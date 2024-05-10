/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Disaggregated Persistent Memory Management
 *
 * Hohai University
 */

#ifndef ETHANE_DMM_H
#define ETHANE_DMM_H

#include <stdbool.h>

#include "dmpool.h"

typedef struct dmm_mn  dmm_mn_t;
typedef struct dmm_cn  dmm_cn_t;
typedef struct dmm_cli dmm_cli_t;

#define DMPTR_NULL          ((dmptr_t) 0)
#define DMPTR_DUMMY(mn_id)  ((dmptr_t) DMPTR_MK_PM((mn_id), 1))

/* Memory Nodes */

dmm_mn_t *dmm_mn_init(void *mem_buf, size_t size);

size_t dmm_cb(dmm_mn_t *dmm, void *rv, const void *pr);

/* Compute Nodes */

dmm_cn_t *dmm_cn_init(dmpool_t *pool);
dmm_cli_t *dmm_cli_init(dmm_cn_t *dmm_cn, dmcontext_t *ctx, size_t init_pool_size);

dmptr_t dmm_balloc(dmm_cli_t *dmm, size_t size, size_t align, dmptr_t locality_hint);
void dmm_bfree(dmm_cli_t *dmm, dmptr_t ptr, size_t size);
void dmm_bzero(dmm_cli_t *dmm, dmptr_t addr, size_t size, bool mn_side);
void dmm_bclear(dmm_cn_t *dmm, dmcontext_t *ctx);

int dmm_get_interleave_nr(dmm_cli_t *dmm);
void dmm_balloc_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size, size_t align);
void dmm_bfree_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size);
void dmm_bzero_interleaved(dmm_cli_t *dmm, const dmptr_t *addrs, size_t size, bool mn_side);
dmptr_t dmm_get_ptr_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size, size_t off);
size_t dmm_get_strip_size(dmm_cli_t *dmm, size_t size);

int dmm_get_isolated_mn_id(dmm_cli_t *dmm, int i);

#endif //ETHANE_DMM_H
