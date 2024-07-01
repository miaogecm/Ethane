/*
 *   CacheFS is a coherent, scalable compute-node-side cache layer
 * for ETHANE. For every FS client, it provides a partial FS view
 * of the global namespace. It caches the latest / hottest FS data.
 *   The coherence between CacheFSes of different compute-nodes is
 * guaranteed via the shared log.
 *
 *   CacheFS contains 2 parts:
 * (1) namespace cache: It maps full path to file's remote pointer
 *     and attributes. "Tombstone" items are used to indicate the
 *     negative lookup result (removed file).
 *     The namespace cache is organized as a hash table. (ns cache)
 * (3) block mapping cache: It maps <file remote pointer, offset> to
 *     its corresponding data block's remote pointer and block size.
 *     The file mapping cache is organized as an AVL-based interval
 *     tree. (bm cache)
 *
 */

#ifndef ETHANE_CACHEFS_H
#define ETHANE_CACHEFS_H

#include <sys/stat.h>

#include "dmpool.h"
#include "dmm.h"
#include "logger.h"

typedef struct cachefs cachefs_t;
typedef struct cachefs_ctx cachefs_ctx_t;
typedef struct cachefs_blk cachefs_blk_t;

struct cachefs_ctx {
    uid_t uid;
    gid_t gid;
};

struct cachefs_blk {
    dmptr_t blk_remote_addr;
    size_t size;
};

struct sharedfs;

cachefs_t *cachefs_init(struct dmcontext *dmcontext, struct dmm_cli *dmm, struct sharedfs *rfs,
                        size_t max_nsc_size, size_t nsc_size_high_watermark,
                        size_t max_bmc_size, size_t bmc_size_high_watermark);

void cachefs_clean(cachefs_t *cfs);

int cachefs_prefetch_metadata(cachefs_t *cfs, const char *path);
int cachefs_mkdir(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, mode_t mode, dmptr_t remote_file,
                  size_t version);
int cachefs_rmdir(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, size_t version);
int cachefs_unlink(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, size_t version);
int cachefs_create(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, mode_t mode, dmptr_t remote_file,
                   struct ethane_open_file *file, size_t version);
int cachefs_chmod(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, mode_t mode, size_t version);
int cachefs_chown(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, uid_t uid, gid_t gid,
                  size_t version);

int cachefs_open(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, struct ethane_open_file *file);
int cachefs_close(cachefs_t *cfs, cachefs_ctx_t *ctx, struct ethane_open_file *file);
int cachefs_getattr(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, struct stat *stbuf);

int cachefs_truncate(cachefs_t *cfs, cachefs_ctx_t *ctx,
                     const char *path, dmptr_t remote_dentry_addr, size_t size, size_t version);

long cachefs_write(cachefs_t* cfs, cachefs_ctx_t* ctx,
                   const char* path, dmptr_t remote_dentry_addr, size_t off, const cachefs_blk_t* blk,
                   size_t version);

long cachefs_append(cachefs_t* cfs, cachefs_ctx_t* ctx,
                    const char* path, dmptr_t remote_dentry_addr, const cachefs_blk_t* blk, size_t version);

long cachefs_read(cachefs_t* cfs, cachefs_ctx_t* ctx,
                  const char* path, dmptr_t remote_dentry_addr, cachefs_blk_t* blks, size_t off, size_t size);

bool cachefs_reached_high_watermark(cachefs_t *cfs);
bool cachefs_reached_max_size(cachefs_t *cfs);

int cachefs_checkpoint(cachefs_t *cfs);

void cachefs_set_version(cachefs_t *cfs, size_t version);

void cachefs_dump(cachefs_t *cfs);

#endif //ETHANE_CACHEFS_H
