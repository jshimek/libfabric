/*
 * Copyright (c) 2015 Cray Inc.  All rights reserved.
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

#ifndef _GNIX_ATOMIC_H_
#define _GNIX_ATOMIC_H_

ssize_t _gnix_atomic(struct gnix_fid_ep *ep, const void *buf,
		const struct fi_ioc *iov, const struct fi_ioc *comparev,
		struct fi_ioc *resultv, size_t count, size_t compare_count,
		size_t result_count, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, const void *compare,
		void *result, void *desc, void *compare_desc,
		void *result_desc, fi_addr_t dest_addr,
		const struct fi_atomic_msg *msg, uint64_t flags, void *context);

int __gnix_atomic_writevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count);

int __gnix_atomic_readwritevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count);

int __gnix_atomic_compwritevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count);
#endif /* _GNIX_ATOMIC_H_ */
