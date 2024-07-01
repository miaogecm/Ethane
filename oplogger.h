#ifndef ETHANE_OPLOGGER_H
#define ETHANE_OPLOGGER_H

#include <stdlib.h>
#include <stdint.h>

#include "ethane.h"
#include "logger.h"

#define OP_RESULT_UNDETERMINED      0x0000000000000000ul
#define OP_RESULT_DO_UPDATE         0xfffffffffffffffeul
#define OP_RESULT_CANCELED          0xfffffffffffffffful

typedef struct oplogger oplogger_t;
typedef struct oplogger_ctx oplogger_ctx_t;

typedef int (*oplogger_replay_cb_t)(oplogger_t *, oplogger_ctx_t *, void *, size_t);

struct oplogger_ctx {
    /* You should initialize these fields: */
    oplogger_t *oplogger;

    uid_t uid;
    gid_t gid;

    int nr_shards, shard;

    oplogger_replay_cb_t replay_cb;
    void *replay_ctx;

    bool wait_check;

    void *priv;

    /* You may not initialize these fields. */

    size_t target_tail;
};

oplogger_t *oplogger_init(logger_t *logger, dmcontext_t *dmcontext, struct cachefs *cfs);
void oplogger_clean(oplogger_t *oplogger);

long oplogger_snapshot_begin(oplogger_t *oplogger, oplogger_ctx_t *ctx);
void oplogger_snapshot_end(oplogger_t *oplogger, oplogger_ctx_t *ctx, long old_v);

dmptr_t
oplogger_mkdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode, dmptr_t dentry_remote_addr);
dmptr_t oplogger_rmdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path);
dmptr_t oplogger_unlink(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path);
dmptr_t
oplogger_create(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode, dmptr_t dentry_remote_addr);
dmptr_t oplogger_chmod(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode);
dmptr_t oplogger_chown(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, uid_t uid, gid_t gid);
dmptr_t oplogger_write(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry,
                       dmptr_t blk_remote_addr, size_t size, off_t offset);
dmptr_t oplogger_append(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry,
                        dmptr_t blk_remote_addr, size_t size);
dmptr_t oplogger_truncate(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry, size_t size);
size_t oplogger_get_version(oplogger_t *oplogger, oplogger_ctx_t *ctx);

int oplogger_set_result_async(oplogger_t *oplogger, dmptr_t log_remote_addr, uint64_t result);
uint64_t oplogger_get_result(oplogger_t* oplogger, dmptr_t log_remote_addr);
size_t oplogger_get_next_replay_from(oplogger_t *oplogger, oplogger_ctx_t *ctx);

/* path == NULL means replay all */
int oplogger_replay_all(oplogger_t *oplogger, oplogger_ctx_t *ctx, bool force, int off);
int oplogger_replay_getattr(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_mkdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_rmdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_unlink(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_create(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_chmod(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_chown(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_write(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_read(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_open(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_append(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);
int oplogger_replay_truncate(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off);

bool oplogger_filter(void *ctx, logger_fgprt_t fgprt, size_t pos);

#endif //ETHANE_OPLOGGER_H
