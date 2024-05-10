/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Remote File System
 *
 * Hohai University
 */

#ifndef ETHANE_SHAREDFS_H
#define ETHANE_SHAREDFS_H

#include "dmlocktab.h"
#include "ethane.h"
#include "dmpool.h"
#include "dmm.h"

typedef struct sharedfs sharedfs_t;

typedef struct sharedfs_ns_update_record {
    const char *full_path;
    struct ethane_dentry *dentry;
    bool is_create;
} sharedfs_ns_update_record_t;

#define SHAREDFS_ZERO_BLK_ADDR      ((dmptr_t) (0x1000))

/*
 * The caller should guarantee that these records are **ORDERED**
 * by <remote_dentry_addr, loff>.
 */
typedef struct sharedfs_bm_update_record {
    dmptr_t dentry_remote_addr;
    size_t loff, size;
    dmptr_t blk_remote_addr;
} sharedfs_bm_update_record_t;

dmptr_t sharedfs_create(dmcontext_t *ctx, dmm_cli_t *dmm, int nr_internal_node_sizes, int *internal_node_nr_blks,
                        size_t ns_kv_size, size_t bm_kv_size, int nr_shards);
sharedfs_t *sharedfs_init(dmcontext_t *ctx, dmm_cli_t *dmm, dmlocktab_t *locktab,
                          dmptr_t sharedfs_info_remote_addr, int nr_max_outstanding_updates);

/* sharedfs Read Functions */

/*
 * This function lookup each prefix of @full_path, and save each prefix path's corresponding
 * file info to @files. For non-existing prefix, the corresponding file info's remote_file
 * field is set to DMPTR_NULL.
 *
 * The initial value of each @file's remote_file field should be DMPTR_NULL. If cached, then
 * you can set it to the corresponding address. sharedfs will skip the lookup of cached prefix.
 */
int sharedfs_ns_lookup_dentries(sharedfs_t *rfs, const char *full_path, struct ethane_dentry **dentries);
int sharedfs_ns_get_dentry(sharedfs_t *rfs, dmptr_t remote_dentry_addr, struct ethane_dentry *dentry, size_t filename_read_len);

int sharedfs_bm_get_extent(sharedfs_t *rfs, dmptr_t *remote_addr, size_t *size,
                           struct ethane_dentry *dentry, size_t off);

/* sharedfs Batch Update Functions */

int sharedfs_ns_update_batch(sharedfs_t *rfs, int nr_updates, sharedfs_ns_update_record_t *updates);
int sharedfs_bm_update_batch(sharedfs_t *rfs, int nr_updates, sharedfs_bm_update_record_t *updates);

int sharedfs_dump(sharedfs_t *rfs);

#endif //ETHANE_SHAREDFS_H
