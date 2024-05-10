/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * RDMA-based Disaggregated Persistent Memory Pool Implementation
 *
 * Disaggregated Memory SpinLock
 *
 * Hohai University
 */

#ifndef ETHANE_DMLOCKTAB_H
#define ETHANE_DMLOCKTAB_H

#include "dmpool.h"

typedef struct dmlocktab dmlocktab_t;

dmlocktab_t *dmlocktab_init(dmcontext_t *ctx, int nr_locks_order);
int dmlock_acquire(dmlocktab_t *locktab, uint64_t oid);
int dmlock_release(dmlocktab_t *locktab, uint64_t oid);

#endif //ETHANE_DMLOCKTAB_H
