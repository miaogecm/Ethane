/*
 * Copyright 2023 Regents of Nanjing University of Aeronautics and Astronautics and 
 * Hohai University, Miao Cai <miaocai@nuaa.edu.cn> and Junru Shen <jrshen@hhu.edu.cn>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>

#include "oplogger.h"
#include "coro.h"

#include "cachefs.h"
#include "tabhash.h"
#include "logger.h"
#include "trace.h"
#include "debug.h"

#define OPLOGGER_BUF_SIZE       8192

#define MAX_FGPRT       (1 << (sizeof(logger_fgprt_t) * 8))

enum op_type {
    OP_MKDIR = 0,
    OP_RMDIR,
    OP_UNLINK,
    OP_CREATE,
    OP_CHMOD,
    OP_CHOWN,
    OP_WRITE,
    OP_APPEND,
    OP_TRUNCATE
};

struct oplogger {
    dmcontext_t *dmcontext;

    logger_t *logger;
    cachefs_t *cfs;
    TAB_hash hf;

    char buf[OPLOGGER_BUF_SIZE];

    /*
     * If skip_table[f]=P, we know that for every log with
     * pos p < P and dependent f, it has been replayed.
     */
    size_t skip_table[MAX_FGPRT];

    size_t head;
};

struct oplog {
    uint64_t op;
    uint64_t result;
    uint16_t uid, gid;
};

struct oplog_mkdir {
    struct oplog opl;
    dmptr_t dentry_remote_addr;
    mode_t mode;
    char path[];
};

struct oplog_rmdir {
    struct oplog opl;
    char path[];
};

struct oplog_unlink {
    struct oplog opl;
    char path[];
};

struct oplog_create {
    struct oplog opl;
    dmptr_t dentry_remote_addr;
    mode_t mode;
    char path[];
};

struct oplog_chmod {
    struct oplog opl;
    mode_t mode;
    char path[];
};

struct oplog_chown {
    struct oplog opl;
    uint16_t uid, gid;
    char path[];
};

struct oplog_write {
    struct oplog opl;
    dmptr_t remote_dentry_addr;
    size_t size;
    off_t offset;
    dmptr_t blk_remote_addr;
    char path[];
};

struct oplog_append {
    struct oplog opl;
    dmptr_t remote_dentry_addr;
    size_t size;
    dmptr_t blk_remote_addr;
    char path[];
};

struct oplog_truncate {
    struct oplog opl;
    dmptr_t remote_dentry_addr;
    size_t size;
    char path[];
};

oplogger_t *oplogger_init(logger_t *logger, dmcontext_t *ctx, struct cachefs *cfs) {
    oplogger_t *oplogger;
    TAB_generator gen;

    oplogger = calloc(1, sizeof(*oplogger));
    if (unlikely(!oplogger)) {
        goto out;
    }

    oplogger->dmcontext = ctx;

    oplogger->logger = logger;
    oplogger->cfs = cfs;

    oplogger->head = logger_get_head(logger);

    /* TODO: persistent generator */
    TAB_init_generator(&gen, TAB_DEFAULT_SEED);
    TAB_init_hash(&oplogger->hf, &gen, 3);

out:
    return oplogger;
}

void oplogger_clean(oplogger_t *oplogger) {
    pr_debug("clean oplogger state");
    oplogger->head = logger_get_head(oplogger->logger);
    memset(oplogger->skip_table, 0, sizeof(oplogger->skip_table));
}

static inline void init_op(struct oplog *op, oplogger_ctx_t *ctx, enum op_type type, uint64_t init_res) {
    op->op = type;
    op->result = init_res;
    op->uid = ctx->uid;
    op->gid = ctx->gid;
}

long oplogger_snapshot_begin(oplogger_t *oplogger, oplogger_ctx_t *ctx) {
    return logger_get_tail_begin(oplogger->logger, &ctx->target_tail);
}

void oplogger_snapshot_end(oplogger_t *oplogger, oplogger_ctx_t *ctx, long old_v) {
    logger_get_tail_end(oplogger->logger, &ctx->target_tail, old_v);
}

static inline logger_fgprt_t fold_to_fgprt(uint64_t hash) {
    uint16_t a, b, c, d;
    a = (uint16_t) ((hash >> 48) & 0xffff);
    b = (uint16_t) ((hash >> 32) & 0xffff);
    c = (uint16_t) ((hash >> 16) & 0xffff);
    d = (uint16_t) (hash         & 0xffff);
    return a ^ b ^ c ^ d;
}

static inline logger_fgprt_t calc_path_fgprt(oplogger_t *oplogger, const char *path) {
    uint64_t h = TAB_finalize(&oplogger->hf, TAB_process(&oplogger->hf, (const uint8_t *) path, strlen(path), 0));
    return fold_to_fgprt(h);
}

static inline logger_fgprt_t calc_path_len_fgprt(oplogger_t *oplogger, const char *path, size_t len) {
    uint64_t h = TAB_finalize(&oplogger->hf, TAB_process(&oplogger->hf, (const uint8_t *) path, len, 0));
    return fold_to_fgprt(h);
}

static inline logger_fgprt_t calc_path_parent_fgprt(oplogger_t *oplogger, const char *path) {
    const char *last_slash = strrchr(path, '/');
    uint64_t h = TAB_finalize(&oplogger->hf, TAB_process(&oplogger->hf, (const uint8_t *) path, last_slash - path, 0));
    return fold_to_fgprt(h);
}

static inline void
oplog_tracepoint(oplogger_t *oplogger, trace_lop_op_type_t log_op_type, struct oplog *oplog, size_t log_pos) {
    int cli_id = dm_get_cli_id(oplogger->dmcontext);

    switch (oplog->op) {
        case OP_MKDIR: {
            struct oplog_mkdir *op = (struct oplog_mkdir *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_MKDIR, log_pos, op->path);
            break;
        }

        case OP_RMDIR: {
            struct oplog_rmdir *op = (struct oplog_rmdir *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_RMDIR, log_pos, op->path);
            break;
        }

        case OP_UNLINK: {
            struct oplog_unlink *op = (struct oplog_unlink *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_UNLINK, log_pos, op->path);
            break;
        }

        case OP_CREATE: {
            struct oplog_create *op = (struct oplog_create *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_CREATE, log_pos, op->path);
            break;
        }

        case OP_CHMOD: {
            struct oplog_chmod *op = (struct oplog_chmod *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_CHMOD, log_pos, op->path);
            break;
        }

        case OP_CHOWN: {
            struct oplog_chown *op = (struct oplog_chown *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_CHOWN, log_pos, op->path);
            break;
        }

        case OP_WRITE: {
            struct oplog_write *op = (struct oplog_write *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_WRITE, log_pos, op->path);
            break;
        }

        case OP_APPEND: {
            struct oplog_append *op = (struct oplog_append *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_APPEND, log_pos, op->path);
            break;
        }

        case OP_TRUNCATE: {
            struct oplog_truncate *op = (struct oplog_truncate *) oplog;
            tracepoint_sample(ethane, log_op, cli_id, log_op_type, TRACE_OP_TRUNCATE, log_pos, op->path);
            break;
        }
    }
}

dmptr_t
oplogger_mkdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode, dmptr_t dentry_remote_addr) {
    struct oplog_mkdir *oplog = (struct oplog_mkdir *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_parent_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_MKDIR, OP_RESULT_UNDETERMINED);
    oplog->dentry_remote_addr = dentry_remote_addr;
    oplog->mode = mode;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_mkdir) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_rmdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path) {
    struct oplog_rmdir *oplog = (struct oplog_rmdir *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_parent_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_RMDIR, OP_RESULT_UNDETERMINED);
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_rmdir) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_unlink(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path) {
    struct oplog_unlink *oplog = (struct oplog_unlink *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_parent_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_UNLINK, OP_RESULT_UNDETERMINED);
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_unlink) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t
oplogger_create(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode, dmptr_t dentry_remote_addr) {
    struct oplog_create *oplog = (struct oplog_create *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_parent_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_CREATE, OP_RESULT_UNDETERMINED);
    oplog->dentry_remote_addr = dentry_remote_addr;
    oplog->mode = mode;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_create) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_chmod(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, mode_t mode) {
    struct oplog_chmod *oplog = (struct oplog_chmod *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_CHMOD, OP_RESULT_UNDETERMINED);
    oplog->mode = mode;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_chmod) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_chown(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, uid_t uid, gid_t gid) {
    struct oplog_chown *oplog = (struct oplog_chown *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_CHOWN, OP_RESULT_UNDETERMINED);
    oplog->uid = uid;
    oplog->gid = gid;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_chown) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_write(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry,
                       dmptr_t blk_remote_addr, size_t size, off_t offset) {
    struct oplog_write *oplog = (struct oplog_write *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_WRITE, OP_RESULT_DO_UPDATE);
    oplog->remote_dentry_addr = dentry;
    oplog->size = size;
    oplog->offset = offset;
    oplog->blk_remote_addr = blk_remote_addr;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_write) + strlen(path) + 1, fgprt, 1);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_append(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry,
                        dmptr_t blk_remote_addr, size_t size) {
    struct oplog_append *oplog = (struct oplog_append *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_APPEND, OP_RESULT_DO_UPDATE);
    oplog->remote_dentry_addr = dentry;
    oplog->size = size;
    oplog->blk_remote_addr = blk_remote_addr;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_append) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

dmptr_t oplogger_truncate(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, dmptr_t dentry, size_t size) {
    struct oplog_truncate *oplog = (struct oplog_truncate *) oplogger->buf;
    logger_fgprt_t fgprt = calc_path_fgprt(oplogger, path);
    dmptr_t ret;
    init_op((struct oplog *) oplog, ctx, OP_TRUNCATE, OP_RESULT_DO_UPDATE);
    oplog->remote_dentry_addr = dentry;
    oplog->size = size;
    strcpy(oplog->path, path);
    ret = logger_get_tail_and_append(oplogger->logger, &ctx->target_tail, oplog,
                                     sizeof(struct oplog_truncate) + strlen(path) + 1, fgprt, 0);
    oplog_tracepoint(oplogger, TRACE_LOG_OP_APPEND, (struct oplog *) oplog, ctx->target_tail);
    return ret;
}

size_t oplogger_get_version(oplogger_t *oplogger, oplogger_ctx_t *ctx) {
    return ctx->target_tail;
}

int oplogger_set_result_async(oplogger_t *oplogger, dmptr_t log_remote_addr, uint64_t result) {
    int ret;
    dm_mark(oplogger->dmcontext);
    ret = dm_write(oplogger->dmcontext, log_remote_addr + offsetof(struct oplog, result), result, 0);
    dm_barrier(oplogger->dmcontext);
    dm_pop(oplogger->dmcontext);
    pr_debug("set result async: log=%lx result=%lx", log_remote_addr, result);
    return ret;
}

uint64_t oplogger_get_result(oplogger_t* oplogger, dmptr_t log_remote_addr) {
    uint64_t *result, ret;

    dm_mark(oplogger->dmcontext);

    ret = dm_read(oplogger->dmcontext, result, log_remote_addr + offsetof(struct oplog, result), DMFLAG_ACK);
    if (unlikely(ret)) {
        goto out;
    }

    ret = dm_wait_ack(oplogger->dmcontext, 1);
    if (unlikely(ret)) {
        goto out;
    }

    ret = *result;

    //pr_debug("get result: log=%lx result=%lx", log_remote_addr, ret);

out:
    dm_pop(oplogger->dmcontext);
    return ret;
}

enum replay_dep_type {
    DEP_PARENT_PREFIX,
    DEP_PREFIX,
};

static int *get_deps(oplogger_t *oplogger, int *nr_deps, const char *path, enum replay_dep_type dep_type) {
    const char *component, *next;
    int *deps, i = 0, len;
    size_t pre_size;

    switch (dep_type) {
        case DEP_PARENT_PREFIX:
            *nr_deps = ethane_get_dir_depth(path) - 1;
            break;

        case DEP_PREFIX:
            *nr_deps = ethane_get_dir_depth(path);
            break;

        default:
            ethane_assert(0);
    }

    deps = calloc(*nr_deps, sizeof(*deps));
    if (unlikely(!deps)) {
        goto out;
    }

    ETHANE_ITER_COMPONENTS(path, component, next, len) {
        pre_size = component + len - path;

        if (i >= *nr_deps) {
            break;
        }

        deps[i++] = calc_path_len_fgprt(oplogger, path, pre_size);
    }

out:
    return deps;
}

static int log_replay(oplogger_t *oplogger, struct oplog *oplog, size_t log_pos, dmptr_t log_remote_addr,
                      bool wait_result) {
    cachefs_ctx_t ctx = { .uid = oplog->uid, .gid = oplog->gid };
    int retry_cnt = 0;

    oplog_tracepoint(oplogger, TRACE_LOG_OP_REPLAY, oplog, log_pos);

    if (wait_result) {
        for (; oplog->result == OP_RESULT_UNDETERMINED; retry_cnt++) {
            coro_delay(20);
            oplog->result = oplogger_get_result(oplogger, log_remote_addr);
            if (unlikely((retry_cnt + 1) % 200000 == 0)) {
                pr_err("wait op result timeout, log=%lx, retry_cnt=%d", log_remote_addr, retry_cnt);
            }
        }
        pr_debug("wait check, retry %d times", retry_cnt);
    }

    switch (oplog->op) {
        case OP_MKDIR: {
            struct oplog_mkdir *op = (struct oplog_mkdir *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_mkdir(oplogger->cfs, &ctx, op->path, &oplog->result, op->mode, op->dentry_remote_addr,
                                 log_pos);
        }

        case OP_RMDIR: {
            struct oplog_rmdir *op = (struct oplog_rmdir *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_rmdir(oplogger->cfs, &ctx, op->path, &oplog->result, log_pos);
        }

        case OP_UNLINK: {
            struct oplog_unlink *op = (struct oplog_unlink *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_unlink(oplogger->cfs, &ctx, op->path, &oplog->result, log_pos);
        }

        case OP_CREATE: {
            struct oplog_create *op = (struct oplog_create *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_create(oplogger->cfs, &ctx, op->path, &oplog->result, op->mode,
                                  op->dentry_remote_addr, NULL, log_pos);
        }

        case OP_CHMOD: {
            struct oplog_chmod *op = (struct oplog_chmod *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_chmod(oplogger->cfs, &ctx, op->path, &oplog->result, op->mode, log_pos);
        }

        case OP_CHOWN: {
            struct oplog_chown *op = (struct oplog_chown *) oplog;
            if (unlikely(op->opl.result == OP_RESULT_CANCELED)) {
                return 0;
            }
            return cachefs_chown(oplogger->cfs, &ctx, op->path, &oplog->result, op->uid, op->gid, log_pos);
        }

        case OP_WRITE: {
            struct oplog_write *op = (struct oplog_write *) oplog;
            cachefs_blk_t blk = { .size = op->size, .blk_remote_addr = op->blk_remote_addr };
            size_t ret = cachefs_write(oplogger->cfs, &ctx, op->path, op->remote_dentry_addr, op->offset, &blk,
                                       log_pos);
            return IS_ERR(ret) ? PTR_ERR(ret) : 0;
        }

        case OP_APPEND: {
            struct oplog_append *op = (struct oplog_append *) oplog;
            cachefs_blk_t blk = { .size = op->size, .blk_remote_addr = op->blk_remote_addr };
            size_t ret = cachefs_append(oplogger->cfs, &ctx, op->path, op->remote_dentry_addr, &blk, log_pos);
            return IS_ERR(ret) ? PTR_ERR(ret) : 0;
        }

        case OP_TRUNCATE: {
            struct oplog_truncate *op = (struct oplog_truncate *) oplog;
            return cachefs_truncate(oplogger->cfs, &ctx, op->path, op->remote_dentry_addr, op->size, log_pos);
        }

        default:
            ethane_assert(0);
    }
}

static int log_ingest(void *log_data, void *ctx, size_t log_pos, size_t log_remote_addr) {
    oplogger_ctx_t *c = (oplogger_ctx_t *) ctx;
    struct oplog *oplog = log_data;
    int ret;
    ret = log_replay(c->oplogger, oplog, log_pos, log_remote_addr, c->wait_check);
    if (c->replay_cb) {
        c->replay_cb(c->oplogger, c, c->replay_ctx, log_pos);
    }
    return ret;
}

struct filter_ctx {
    oplogger_ctx_t *oplogger_ctx;
    int nr_deps, *deps;
};

size_t oplogger_get_next_replay_from(oplogger_t *oplogger, oplogger_ctx_t *ctx) {
    return max(oplogger->skip_table[0], oplogger->head);
}

static int
do_replay(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, enum replay_dep_type dep_type, bool force,
          int off) {
    size_t replay_from, replay_tail;
    int *deps, nr_deps, ret = 0, i;
    struct filter_ctx filter_ctx;

    cachefs_set_version(oplogger->cfs, logger_get_head(oplogger->logger));

    if (path) {
        deps = get_deps(oplogger, &nr_deps, path, dep_type);
        if (unlikely(!deps)) {
            ret = -ENOMEM;
            goto out;
        }

        ethane_assert(nr_deps > 0);

        replay_from = oplogger->skip_table[deps[0]];
        pr_debug("%s deps[0]=%d, replay from %lu", path, deps[0], replay_from);
        for (i = 1; i < nr_deps; i++) {
            replay_from = min(replay_from, oplogger->skip_table[deps[i]]);
            pr_debug("%s deps[%d]=%d, replay from %lu", path, i, deps[i], replay_from);
        }
    } else {
        /* we have to replay all */
        deps = NULL;
        nr_deps = 0;

        replay_from = oplogger->skip_table[0];
    }

    replay_from = max(replay_from, oplogger->head);

    if (ctx->target_tail > replay_from) {
        pr_debug("replay range [%lu, %lu) (%s)", replay_from, ctx->target_tail, path ? path : "<all paths>");
    }

    filter_ctx.oplogger_ctx = ctx;
    filter_ctx.deps = deps;
    filter_ctx.nr_deps = nr_deps;

    do {
        replay_tail = logger_read(oplogger->logger, log_ingest, replay_from, ctx->target_tail, &filter_ctx, ctx);
        replay_from = replay_tail;
        if (coro_current()) {
            coro_yield();
        }
    } while (force && replay_tail < ctx->target_tail);

    if (path) {
        for (i = 0; i < nr_deps; i++) {
            oplogger->skip_table[deps[i]] = replay_tail + off;
            pr_debug("update skip_table[%d] = %lu", deps[i], replay_tail + off);
        }
    } else {
        oplogger->skip_table[0] = replay_tail + off;
    }

    free(deps);

out:
    return ret;
}

int oplogger_replay_all(oplogger_t *oplogger, oplogger_ctx_t *ctx, bool force, int off) {
    return do_replay(oplogger, ctx, NULL, 0, force, off);
}

int oplogger_replay_getattr(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_mkdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PARENT_PREFIX, force, off);
}

int oplogger_replay_rmdir(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_unlink(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PARENT_PREFIX, force, off);
}

int oplogger_replay_create(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PARENT_PREFIX, force, off);
}

int oplogger_replay_chmod(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_chown(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_write(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_read(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_open(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_append(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

int oplogger_replay_truncate(oplogger_t *oplogger, oplogger_ctx_t *ctx, const char *path, bool force, int off) {
    return do_replay(oplogger, ctx, path, DEP_PREFIX, force, off);
}

bool oplogger_filter(void *ctx, logger_fgprt_t fgprt, size_t pos) {
    struct filter_ctx *dep_ctx = (struct filter_ctx *) ctx;
    oplogger_ctx_t *c = dep_ctx->oplogger_ctx;
    size_t *skip_table;
    int i;

    if (c->nr_shards && (fgprt % c->nr_shards != c->shard)) {
        return false;
    }

    if (!dep_ctx->deps) {
        return true;
    }

    skip_table = dep_ctx->oplogger_ctx->oplogger->skip_table;
    if (pos < skip_table[fgprt]) {
        return false;
    }

    for (i = 0; i < dep_ctx->nr_deps; i++) {
        if (dep_ctx->deps[i] == fgprt) {
            return true;
        }
    }

    return false;
}
