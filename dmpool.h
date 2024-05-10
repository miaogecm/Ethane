/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * RDMA-based Disaggregated Persistent Memory Pool Implementation
 *
 * The memory pool supports:
 * (1) Memory READ/WRITE/ATOMIC interfaces
 * (2) RPC interfaces
 * (3) On-device memory allocation
 *
 * Hohai University
 */

#ifndef ETHANE_DMPOOL_H
#define ETHANE_DMPOOL_H

#include <stdint.h>
#include <stdlib.h>
#include <zookeeper/zookeeper.h>

#define DMPOOL_GLOBAL

typedef struct dmpool dmpool_t;
typedef struct dmcontext dmcontext_t;
typedef unsigned long dmflag_t;
typedef unsigned long dmptr_t;
typedef size_t (*dmcallback_t)(void *ctx, void *rv, const void *data, void *aux);

#define DMFLAG_FENCE  0x1
#define DMFLAG_ATOMIC 0x2
#define DMFLAG_ACK    0x4
#define DMFLAG_INLINE 0x8

/*
 * Memory Buffers
 * Currently, we have two types of memory buffers:
 * (1) Persistent memory region
 * (2) On-chip memory region
 */
#define DM_NR_MR_TYPES  2
#define DM_PMEM_MR      0
#define DM_CMEM_MR      1

#define DM_ZK_PREFIX  "/dmpool/"

/*
 * 64bit addr =
 *      1bit memory region type (0: persistent memory; 1: on-chip memory) +
 *      15bit memory node id +
 *      48bit offset/address in the corresponding memory region
 */
#define DMPTR_MR_TYPE(p)         ((int) ((p) >> 63) & 0x1)
#define DMPTR_MN_ID(p)           ((int) ((p) >> 48) & 0x7fff)
#define DMPTR_OFF(p)             ((unsigned long) ((p) & 0xffffffffffff))
#define DMPTR_MK_PM(mn_id, off)  (((dmptr_t) (mn_id) << 48) | (off))
#define DMPTR_MK_CM(mn_id, off)  (((dmptr_t) (1) << 63) | ((dmptr_t) (mn_id) << 48) | (off))

/*
 * Memory Nodes
 */

_Noreturn void dm_daemon(zhandle_t *zh, void *mem_buf, size_t size, size_t cmem_size, dmcallback_t cb, void *aux);

void *dm_get_ptr(void *ctx, dmptr_t remote_addr);

/*
 * Compute Nodes
 */

struct cn_context;
struct cli_context;

dmpool_t *dm_init(zhandle_t *zh);

dmcontext_t *dm_create_context(dmpool_t *pool, size_t local_buf_size);
int dm_destroy_context(dmcontext_t *ctx);

void dm_mark(dmcontext_t *ctx);
void *dm_push(dmcontext_t *ctx, const void *data, size_t size);
void dm_pop(dmcontext_t *ctx);
void *dm_reg_local_buf(dmcontext_t *ctx, void *buf, size_t size);
void dm_local_buf_switch_default(dmcontext_t *ctx);
void dm_local_buf_switch(dmcontext_t *ctx, void *mr);

int dm_copy_from_remote(dmcontext_t *ctx, void *dst, dmptr_t src, size_t size, dmflag_t flag);
int dm_copy_to_remote(dmcontext_t *ctx, dmptr_t dst, const void *src, size_t size, dmflag_t flag);
int dm_cas(dmcontext_t *ctx, dmptr_t dst, void *src, void *old, size_t size, dmflag_t flag);
int dm_faa(dmcontext_t *ctx, dmptr_t ptr, void *add_old, size_t size, dmflag_t flag);

int dm_flush(dmcontext_t *ctx, dmptr_t addr, dmflag_t flag);

int dm_set_ack_all(dmcontext_t *ctx);
int dm_barrier(dmcontext_t *ctx);
int dm_wait_ack_(dmcontext_t *ctx, int nr, const char *file, const char *func, int line);
struct coro *dm_get_ack_coro(dmcontext_t *ctx);

#define dm_wait_ack(ctx, nr)            dm_wait_ack_((ctx), (nr), __FILE__, __func__, __LINE__)

#define dm_data(ctx, x)                 ({ typeof(x) _x = (x); dm_push((ctx), &_x, sizeof(_x)); })
#define dm_param(ctx, x)                dm_data((ctx), (x)), sizeof(typeof(x))
#define dm_write(ctx, addr, x, flag)    dm_copy_to_remote(ctx, (addr), dm_param(ctx, x), (flag))
#define dm_read(ctx, ptr, addr, flag)   ({ (ptr) = dm_push((ctx), NULL, sizeof(*(ptr))); \
                                           dm_copy_from_remote(ctx, (ptr), (addr), sizeof(*(ptr)), (flag)); })

int dm_rpc(dmcontext_t *ctx, dmptr_t addr, void *data, size_t size);
const void *dm_get_rv(dmcontext_t *ctx);

int dm_get_cn_id(dmcontext_t *ctx);
int dm_get_cli_id(dmcontext_t *ctx);
int dm_get_nr_mns(dmpool_t *pool);
void dm_get_mns(dmpool_t *pool, int *ids);
int dm_get_nr_cns(dmpool_t *pool);
void dm_get_cns(dmpool_t *pool, int *ids);

dmpool_t *dm_get_pool(dmcontext_t *ctx);

#endif //ETHANE_DMPOOL_H
