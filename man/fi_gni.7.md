---
layout: page
title: fi_gni(7)
tagline: Libfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

The GNI Fabric Provider

# OVERVIEW

The GNI provider runs on Cray XC (TM) systems utilizing the user-space
Generic Network Interface (uGNI) which provides low-level access to
the Aries interconnect.  The Aries interconnect is designed for
low-latency one-sided messaging and also includes direct hardware
support for common atomic operations and optimized collectives.

# REQUIREMENTS

The GNI provider runs on Cray XC systems running CLE 5.2 UP04 or higher
using gcc version 4.9 or higher.

# SUPPORTED FEATURES

The GNI provider supports the following features defined for the
libfabric API:

*Endpoint types*
: The provider supports the *FI_EP_RDM* and *FI_EP_DGRAM* endpoint types.

*Address vectors*
: The provider implements both the *FI_AV_MAP* and *FI_AV_TABLE*
  address vector types.

*Memory registration modes*
: The provider implements the *FI_MR_BASIC* memory registration mode.

*Data transfer operations*

: The following data transfer interfaces are supported for all
  endpoint types: *FI_ATOMIC*, *FI_MSG*, *FI_RMA*, *FI_TAGGED*.  See
  DATA TRANSFER OPERATIONS below for more details.

*Completion events*
: The GNI provider supports *FI_CQ_FORMAT_CONTEXT*, *FI_CQ_FORMAT_MSG*,
  *FI_CQ_FORMAT_DATA* and *FI_CQ_FORMAT_TAGGED* with wait objects of type
  *FI_WAIT_NONE*, *FI_WAIT_FD*, and *FI_WAIT_MUTEX_COND*.

*Modes*
: The GNI provider does not require any operation modes.

*Progress*

: For both control and data progress, the GNI provider supports both
  *FI_PROGRESS_AUTO* and *FI_PROGRESS_MANUAL*, with a default set to
  *FI_PROGRESS_AUTO*.

*Additional Features*
: The GNI provider also supports the following capabilities and features:
- *FI_MULTI_RECV*
- *FI_SOURCE*
- *FI_FENCE*
- *FI_RM_ENABLED*
- *FABRIC_DIRECT* compilation mode

# DATA TRANSFER OPERATIONS

## FI_ATOMIC

Currently, the GNI provider only supports atomic operations supported
directly by the Aries NIC.  These include operations on 32- and
64-bit, signed and unsigned integer and floating point values.
Specifically,

### Basic (fi_atomic, etc.)
- *FI_MIN*, *FI_MAX* (no unsigned)
- *FI_SUM* (no 64-bit floating point)
- *FI_BOR*, *FI_BAND*, *FI_BXOR* (no floating point)
- *FI_ATOMIC_WRITE*

### Fetching (fi_fetch_atomic, etc.)
- All of the basic operations as above
- FI_ATOMIC_READ

### Comparison (fi_compare_atomic, etc.)
- FI_CSWAP
- FI_MSWAP

## FI_MSG

All *FI_MSG* operations are supported.

## FI_RMA

All *FI_RMA* operations are supported.

## FI_TAGGED

All *FI_TAGGED* operations are supported except `fi_tinjectdata`.

# GNI EXTENSIONS

The GNI provider exposes low-level tuning parameters via a domain and
endpoint `fi_open_ops` interface named *FI_GNI_DOMAIN_OPS_1* and
*FI_GNI_EP_OPS_1*.  The flags parameter is currently ignored.  The
fi_open_ops function takes a `struct fi_gni_ops_domain` or a
`struct fi_gni_ops_ep` parameter respectively and populates it with
the following:

```c
struct fi_gni_ops_domain {
	int (*set_val)(struct fid *fid, dom_ops_val_t t, void *val);
	int (*get_val)(struct fid *fid, dom_ops_val_t t, void *val);
	int (*flush_cache)(struct fid *fid);
};

struct fi_gni_ops_ep {
	int (*set_val)(struct fid *fid, dom_ops_val_t t, void *val);
	int (*get_val)(struct fid *fid, dom_ops_val_t t, void *val);
        size_t (*native_amo)(struct fid_ep *ep, const void *buf,
                             size_t count,void *desc,
                             fi_addr_t dest_addr, uint64_t addr,
                             uint64_t key, enum fi_datatype datatype,
                             enum gnix_fab_req_type req_type,
                             void *context);
};
```

The `set_val` function sets the value of a given parameter; the
`get_val` function returns the current value.  For
*FI_GNI_DOMAIN_OPS_1*, the currently supported values are:

*GNI_MSG_RENDEZVOUS_THRESHOLD*
: Threshold message size at which a rendezvous protocol is used for
  *FI_MSG* data transfers.  The value is of type uint32_t.

*GNI_RMA_RDMA_THRESHOLD*
: Threshold message size at which RDMA is used for *FI_RMA* data
  transfers.  The value is of type uint32_t.

*GNI_CONN_TABLE_INITIAL_SIZE*
: Initial size of the internal table data structure used to manage
  connections.  The value is of type uint32_t.

*GNI_CONN_TABLE_MAX_SIZE*
: Maximum size of the internal table data structure used to manage
  connections.  The value is of type uint32_t.

*GNI_CONN_TABLE_STEP_SIZE*
: Step size for increasing the size of the internal table data
  structure used to manage internal GNI connections.  The value is of
  type uint32_t.

*GNI_VC_ID_TABLE_CAPACITY*
: Size of the virtual channel (VC) table used for managing remote
  connections.  The value is of type uint32_t.

*GNI_MBOX_PAGE_SIZE*
: Page size for GNI SMSG mailbox allocations.  The value is of type
  uint32_t.

*GNI_MBOX_NUM_PER_SLAB*
: Number of GNI SMSG mailboxes per allocation slab.  The value is of
  type uint32_t.

*GNI_MBOX_MAX_CREDIT*
: Maximum number of credits per GNI SMSG mailbox.  The value is of
  type uint32_t.

*GNI_MBOX_MSG_MAX_SIZE*
: Maximum size of GNI SMSG messages.  The value is of type uint32_t.

*GNI_RX_CQ_SIZE*
: Recommended GNI receive CQ size.  The value is of type uint32_t.

*GNI_TX_CQ_SIZE*
: Recommended GNI transmit CQ size.  The value is of type uint32_t.

*GNI_MAX_RETRANSMITS*
: Maximum number of message retransmits before failure.  The value is
  of type uint32_t.

*GNI_MR_CACHE_LAZY_DEREG*
: Enable or disable lazy deregistration of memory.  The value is of
  type int32_t.

*GNI_MR_CACHE*
: Select the type of cache that the domain will use. Valid choices are
  the following: 'internal', 'udreg', or 'none'. 'internal' refers to the GNI
  provider internal registration cache. 'udreg' refers to a user level dreg
  library based cache. Lastly, 'none' refers to device direct registration
  without a provider cache.

*GNI_MR_HARD_REG_LIMIT*
: Maximum number of registrations. Applies only to the GNI provider cache. The value is of type int32_t (-1 for no limit).

*GNI_MR_SOFT_REG_LIMIT*
: Soft cap on the registration limit. Applies only to the GNI provider cache. The value is of type int32_t (-1 for no limit).

*GNI_MR_HARD_STALE_REG_LIMIT*
: Maximum number of stale registrations to be held in cache. This applies to  the GNI provider cache and the udreg cache. The value is of type int32_t (-1 for no limit for the GNI provider cache and udreg cache values must be greater than 0).

*GNI_MR_UDREG_LIMIT*
: Maximum number of registrations. Applies only to the udreg cache. The value is of type int32_t. The value must be greater than 0.

*GNI_XPMEM_ENABLE*
: Enable or disable use of XPMEM for on node messages using the GNI provider internal rendezvous protocol.  The value is of type bool.

The `flush_cache` function allows the user to flush any stale registration
cache entries from the cache. This has the effect of removing registrations
from the cache that have been deregistered with the provider, but still
exist in case that they may be reused in the near future. Flushing the stale
registrations forces hardware-level deregistration of the stale memory
registrations and frees any memory related to those stale registrations. Only
the provider-level registration struct is freed, not the user buffer
associated with the registration.
The parameter for `flush_cache` is a struct fid pointer to a fi_domain. The
memory registration cache is tied to the domain, so issuing a `flush_cache` to
the domain will flush the registration cache of the domain.

The `flush_cache` function allows the user to flush any stale registration
cache entries from the cache. This has the effect of removing registrations
from the cache that have been deregistered with the provider, but still
exist in case that they may be reused in the near future. Flushing the stale
registrations forces hardware-level deregistration of the stale memory
registrations and frees any memory related to those stale registrations. Only
the provider-level registration struct is freed, not the user buffer
associated with the registration.
The parameter for `flush_cache` is a struct fid pointer to a fi_domain. The
memory registration cache is tied to the domain, so issuing a `flush_cache` to
the domain will flush the registration cache of the domain.

For *FI_GNI_EP_OPS_1*, the currently supported values are:
*GNI_HASH_TAG_IMPL*
: Use a hashlist for the tag list implementation.  The value is of type uint32_t.

The `native_amo` function allows the user to call GNI native atomics
that are not implemented in the libfabric API.
The parameters for native_amo are the same as the fi_atomic function
but adds the following parameter:

*enum gnix_fab_req_type req_type*
: The req_type's supported with this call are GNIX_FAB_RQ_NAMO_AX
 (AND and XOR), and GNIX_FAB_RQ_NAMO_AX_S (AND and XOR 32 bit),
GNIX_FAB_RQ_NAMO_FAX (Fetch AND and XOR) and GNIX_FAB_RQ_NAMO_FAX_S
 (Fetch AND and XOR 32 bit).

# SEE ALSO

[`fabric`(7)](fabric.7.html),
[`fi_open_ops`(3)](fi_open_ops.3.html),
[`fi_provider`(7)](fi_provider.7.html),
[`fi_getinfo`(3)](fi_getinfo.3.html)
[`fi_atomic`(3)](fi_atomic.3.html)

For more information on uGNI, see *Using the GNI and DMAPP APIs*
(S-2446-3103, Cray Inc.).  For more information on the GNI provider,
see *An Implementation of OFI libfabric in Support of Multithreaded
PGAS Solutions* (PGAS '15).

