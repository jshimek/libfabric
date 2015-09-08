/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gnix.h"
#include "gnix_nic.h"
#include "gnix_vc.h"
#include "gnix_ep.h"
#include "gnix_mr.h"
#include "gnix_cm_nic.h"
#include "gnix_mbox_allocator.h"
#include "gnix_cntr.h"

#include <gni_pub.h>

static int __gnix_atomic_fab_req_complete(void *arg)
{
	struct gnix_fab_req *req = (struct gnix_fab_req *) arg;
	struct gnix_fid_ep *ep = req->gnix_ep;
	int rc;
	struct gnix_fid_cntr *cntr = NULL;

	/* more transaction needed for request? */

	if (req->flags & FI_COMPLETION) {
		rc = _gnix_cq_add_event(ep->send_cq, req->user_context,
					req->flags, req->len,
					(void *)req->loc_addr,
					req->imm, req->msg.tag);
		if (rc) {
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cq_add_event() failed: %d\n", rc);
		}
	}

	if ((req->type == GNIX_FAB_RQ_ATOMIC) &&
	    ep->write_cntr)
		cntr = ep->write_cntr;

	if ((req->type == GNIX_FAB_RQ_ATOMICF) &&
	    ep->read_cntr)
		cntr = ep->read_cntr;

	if (cntr) {
		rc = _gnix_cntr_inc(cntr);
		if (rc)
			GNIX_WARN(FI_LOG_CQ,
				  "_gnix_cntr_inc() failed: %d\n", rc);
	}

	atomic_dec(&req->vc->outstanding_tx_reqs);


	/* We could have requests waiting for TXDs or FI_FENCE operations.
	 * Schedule this VC to push any such TXs. */
	_gnix_vc_schedule_tx(req->vc);

	_gnix_fr_free(ep, req);

	return FI_SUCCESS;
}

static int __gnix_atomic_txd_complete(void *arg)
{
	struct gnix_tx_descriptor *txd = (struct gnix_tx_descriptor *)arg;

	/* Progress fabric operation in the fab_req completer.  Can we call
	 * fab_req->completer_fn directly from __gnix_tx_progress? */
	return txd->req->completer_fn(txd->req->completer_data);
}

int _gnix_atomic_post_req(void *data)
{
	struct gnix_fab_req *fab_req = (struct gnix_fab_req *) data;
	struct gnix_fid_ep *ep = fab_req->gnix_ep;
	struct gnix_nic *nic = ep->nic;
	struct gnix_fid_mem_desc *loc_md;
	struct gnix_tx_descriptor *txd;
	gni_mem_handle_t mdh;
	gni_return_t status;
	int rc;

	rc = _gnix_nic_tx_alloc(nic, &txd);
	if (rc) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_nic_tx_alloc() failed: %d\n",
			 rc);
		return -FI_EAGAIN;

	txd->completer_fn = __gnix_atomic_txd_complete;
	txd->req = fab_req;

	_gnix_convert_key_to_mhdl_no_crc(
		(gnix_mr_key_t *) &fab_req->atm.rem_mr_key,
		&mdh);

	loc_md = (struct gnix_fid_mem_desc *)fab_req->loc_md;

	txd->gni_desc.type = GNI_POST_AMO;
	txd->gni_desc.cq_mode = GNI_CQMODE_GLOBAL_EVENT | /* Check Flags */
				GNI_CQMODE_REMOTE_EVENT;
	txd->gni_desc.dlvr_mode = GNI_DLVMODE_PERFORMANCE;
	txd->gni_desc.local_addr = (uint64_t)fab_req->loc_addr;
	if (loc_md)
		txd->gni_desc.local_mem_hndl = loc_md->mem_hndl;

	txd->gni_desc.remote_addr = (uint64_t)fab_req->atm.rem_addr;
	txd->gni_desc.remote_mem_hndl = mdh;
	txd->gni_desc.length = fab_req->len;
	txd->gni_desc.src_cq_hndl = nic->tx_cq;
	txd->gni_desc.amo_cmd = fab_req->atm.amo_cmd;
	{
		gni_mem_handle_t *tl_mdh = &txd->gni_desc.local_mem_hndl;
		gni_mem_handle_t *tr_mdh = &txd->gni_desc.remote_mem_hndl;

		GNIX_INFO(FI_LOG_EP_DATA, "la: %llx ra: %llx len: %d\n",
			  txd->gni_desc.local_addr, txd->gni_desc.remote_addr,
			  txd->gni_desc.length);
		GNIX_INFO(FI_LOG_EP_DATA,
			  "lmdh: %llx:%llx rmdh: %llx:%llx key: %llx\n",
			  *(uint64_t *)tl_mdh, *(((uint64_t *)tl_mdh) + 1),
			  *(uint64_t *)tr_mdh, *(((uint64_t *)tr_mdh) + 1),
			  fab_req->atm.rem_mr_key);
	}

	fastlock_acquire(&nic->lock);
	status = GNI_PostFma(fab_req->vc->gni_ep, &txd->gni_desc);
	fastlock_release(&nic->lock);

	if (status != GNI_RC_SUCCESS) {
		_gnix_nic_tx_free(nic, txd);
		GNIX_INFO(FI_LOG_EP_DATA, "GNI_Post*() failed: %s\n",
			  gni_err_str[status]);
	}

	return gnixu_to_fi_errno(status);
}
ssize_t _gnix_atomic(struct gnix_fid_ep *ep, const void *buf,
		const struct fi_ioc *iov, const struct fi_ioc *comparev,
		struct fi_ioc *resultv, size_t count, size_t compare_count,
		size_t result_count, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, const void *compare,
		void *result, void *desc, void *compare_desc,
		void *result_desc, fi_addr_t dest_addr,
		const struct fi_atomic_msg *msg, uint64_t flags, void *context)
{
	if (!ep)
		return -FI_EINVAL;
	return -FI_EINVAL;
}
/*
ssize_t _gnix_atomic(struct gnix_fid_ep *ep,
			const struct fi_msg_atomic *msg,
			const struct fi_ioc *comparev, void ** compare_desc,
			size_t compare_count, struct fi_ioc *resultv,
			void **result_desc, size_t result_count, uint64_t flags)
{

	struct gnix_vc *vc;
	struct gnix_fab_req *req;
	struct
*/
