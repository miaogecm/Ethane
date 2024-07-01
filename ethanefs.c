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
 * ETHANE User-Space Library
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <prom.h>
#include <promhttp.h>

#include "trace.h"
#include "config.h"

#include "coro.h"
#include "dmlocktab.h"

#include "debug.h"
#include "ethanefs.h"

#include <fcntl.h>

#include "dmpool.h"
#include "dmm.h"
#include "bench.h"

#include "sharedfs.h"
#include "cachefs.h"
#include "logger.h"
#include "oplogger.h"

#define CHECK_CHKPT_VER_INTERVAL_US     100000

#define CHKPT_GC_INTERVAL   1024

#define STAT_REQ_INTERVAL   32

#define REQ_LAT_HIST_BUCKETS   16, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 100.0, 125.0, 150.0, 175.0, 200.0, 250.0, 300.0, 400.0

#define MAX_READ_NR_EXTS    128

int debug_mode = 0;

struct ethanefs {
    dmpool_t *pool;
    dmm_cn_t *dmm;

    zhandle_t *zh;

    struct MHD_Daemon *prom_daemon;
};

struct ethanefs_cli {
    ethanefs_t *fs;

    dmcontext_t *ctx;
    dmm_cli_t *dmm;

    sharedfs_t *rfs;
    logger_t *logger;

    cachefs_t *cfs;

    oplogger_t *oplogger;

    dmlocktab_t *locktab;

    uid_t uid;
    gid_t gid;

    int nr_ops;

    dmptr_t chkpt_ver_remote_addr;

    char path[PATH_MAX];
    size_t cwd_len;

    char label[64];
};

static prom_histogram_t *prom_req_lat;
static prom_histogram_t *prom_req_log_insert_lat;
static prom_histogram_t *prom_req_cfs_prefetch_lat;
static prom_histogram_t *prom_req_log_replay_lat;
static prom_histogram_t *prom_req_log_fetch_lat;
static prom_histogram_t *prom_req_log_read_lat;
static prom_histogram_t *prom_req_cfs_lat;
static prom_histogram_t *prom_req_nr_read_logs;

static void ethanefs_cli_init_global() {
    prom_req_lat = prom_histogram_new("ethanefs_req_lat",
                                       "Request latency",
                                       prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                       1, (const char *[]) { "cli_id" });
    prom_req_log_insert_lat = prom_histogram_new("ethanefs_req_log_insert_lat",
                                                  "Request latency (log insert)",
                                                  prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                                  1, (const char *[]) { "cli_id" });
    prom_req_cfs_prefetch_lat = prom_histogram_new("ethanefs_req_cfs_prefetch_lat",
                                                    "Request latency (cfs prefetch)",
                                                    prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                                    1, (const char *[]) { "cli_id" });
    prom_req_log_replay_lat = prom_histogram_new("ethanefs_req_log_replay_lat",
                                                   "Request latency (log replay)",
                                                   prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                                   1, (const char *[]) { "cli_id" });
    prom_req_log_fetch_lat = prom_histogram_new("ethanefs_req_log_fetch_lat",
                                                  "Request latency (log fetch)",
                                                  prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                                  1, (const char *[]) { "cli_id" });
    prom_req_log_read_lat = prom_histogram_new("ethanefs_req_log_read_lat",
                                                 "Request latency (log read)",
                                                 prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                                 1, (const char *[]) { "cli_id" });
    prom_req_cfs_lat = prom_histogram_new("ethanefs_req_cfs_lat",
                                            "Request latency (cfs)",
                                            prom_histogram_buckets_new(REQ_LAT_HIST_BUCKETS),
                                            1, (const char *[]) { "cli_id" });
    prom_req_nr_read_logs = prom_histogram_new("ethanefs_req_nr_read_logs",
                                                 "Number of read logs",
                                                 prom_histogram_buckets_linear(1, 1, 10),
                                                 1, (const char *[]) { "cli_id" });

    prom_collector_registry_must_register_metric(prom_req_lat);
    prom_collector_registry_must_register_metric(prom_req_log_insert_lat);
    prom_collector_registry_must_register_metric(prom_req_cfs_prefetch_lat);
    prom_collector_registry_must_register_metric(prom_req_log_replay_lat);
    prom_collector_registry_must_register_metric(prom_req_log_fetch_lat);
    prom_collector_registry_must_register_metric(prom_req_log_read_lat);
    prom_collector_registry_must_register_metric(prom_req_cfs_lat);
    prom_collector_registry_must_register_metric(prom_req_nr_read_logs);
}

void ethanefs_logger_init_global();
void ethanefs_kv_init_global();

ethanefs_t *ethanefs_init(zhandle_t *zh, int prom_daemon_port) {
    ethanefs_t *fs;

    fs = calloc(1, sizeof(ethanefs_t));
    if (unlikely(!fs)) {
        goto out;
    }

    fs->zh = zh;
    fs->pool = dm_init(fs->zh);
    fs->dmm = dmm_cn_init(fs->pool);

    prom_collector_registry_default_init();
    promhttp_set_active_collector_registry(NULL);

    if (prom_daemon_port) {
        fs->prom_daemon = promhttp_start_daemon(MHD_USE_SELECT_INTERNALLY, prom_daemon_port, NULL, NULL);
        if (unlikely(!fs->prom_daemon)) {
            pr_err("start prometheus daemon failed");
            fs = ERR_PTR(-EINVAL);
            goto out;
        }
    }

    ethanefs_cli_init_global();
    ethanefs_logger_init_global();
    ethanefs_kv_init_global();

out:
    return fs;
}

ethanefs_cli_t *ethanefs_cli_init(ethanefs_t *fs, struct ethane_cli_config *config) {
    struct ethane_super *super;
    ethanefs_cli_t *cli;
    dmm_cli_t *dmm_ctx;
    dmcontext_t *ctx;
    int ret;

    /* create disaggregated memory pool */
    ctx = dm_create_context(fs->pool, config->net.local_buf_size_mb * 1024 * 1024);

    /* create disaggregated memory manager */
    dmm_ctx = dmm_cli_init(fs->dmm, ctx, config->dmm.pmem_initial_alloc_size_mb * 1024 * 1024);

    /* create ethanefs client */
    cli = calloc(1, sizeof(ethanefs_cli_t));
    if (unlikely(!cli)) {
        cli = ERR_PTR(-ENOMEM);
        goto out;
    }

    cli->fs = fs;

    cli->ctx = ctx;
    cli->dmm = dmm_ctx;

    /* read super block */
    super = dm_push(ctx, NULL, sizeof(struct ethane_super));
    ret = dm_copy_from_remote(ctx, super, ETHANE_SB_REMOTE_ADDR, sizeof(struct ethane_super), DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        cli = ERR_PTR(ret);
        goto out;
    }

    /* wait */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(IS_ERR(ret))) {
        cli = ERR_PTR(ret);
        goto out;
    }

    /* init lock table */
    cli->locktab = dmlocktab_init(ctx, config->lock.nr_locks_order);
    if (unlikely(!cli->locktab)) {
        cli = ERR_PTR(-ENOMEM);
        goto out;
    }

    /* init sharedfs */
    cli->rfs = sharedfs_init(ctx, dmm_ctx, cli->locktab,
                             super->sharedfs_remote_addr, config->sharedfs.nr_max_outstanding_updates);
    if (unlikely(IS_ERR(cli->rfs))) {
        cli = ERR_PTR(PTR_ERR(cli->rfs));
        goto out;
    }

    /* create logger */
    cli->logger = logger_init(ctx, dmm_ctx, super->logger_remote_addr, oplogger_filter,
                              config->logger.local_log_region_size_mb * 1024 * 1024,
                              config->logger.log_read_batch_size, config->logger.global_shm_path);
    if (unlikely(IS_ERR(cli->logger))) {
        cli = ERR_PTR(PTR_ERR(cli->logger));
        goto out;
    }

    /* init cacheFS */
    cli->cfs = cachefs_init(ctx, dmm_ctx, cli->rfs,
                            config->cachefs.namespace_cache_size_max_mb * 1024 * 1024,
                            config->cachefs.namespace_cache_size_high_watermark_mb * 1024 * 1024,
                            config->cachefs.block_mapping_cache_size_max_mb * 1024 * 1024,
                            config->cachefs.block_mapping_cache_size_high_watermark_mb * 1024 * 1024);
    if (unlikely(IS_ERR(cli->cfs))) {
        cli = ERR_PTR(PTR_ERR(cli->cfs));
        goto out;
    }

    /* init oplogger */
    cli->oplogger = oplogger_init(cli->logger, cli->ctx, cli->cfs);
    if (unlikely(IS_ERR(cli->oplogger))) {
        cli = ERR_PTR(PTR_ERR(cli->oplogger));
        goto out;
    }

    cli->chkpt_ver_remote_addr = ETHANE_SB_REMOTE_ADDR + offsetof(struct ethane_super, chkpt_ver);

    sprintf(cli->label, "cli%06d", dm_get_cli_id(ctx));

    cli->cwd_len = 0;

out:
    return cli;
}

void ethanefs_set_user(ethanefs_cli_t *cli, uid_t uid, gid_t gid) {
    cli->uid = uid;
    cli->gid = gid;
}

void ethanefs_clean_cli(ethanefs_cli_t *cli) {
    pr_info("clean cli %d", ethanefs_get_cli_id(cli));
    cachefs_clean(cli->cfs);
    oplogger_clean(cli->oplogger);
}

int ethanefs_format(zhandle_t *zh, struct ethane_fs_config *config) {
    dmptr_t sharedfs_remote_addr, logger_remote_addr;
    struct ethane_super *super;
    dmm_cli_t *dmm_ctx;
    dmcontext_t *ctx;
    dmpool_t *pool;
    dmm_cn_t *dmm;
    int ret;

    /* create disaggregated memory pool */
    pool = dm_init(zh);
    ctx = dm_create_context(pool, 1024 * 1024ul);

    /* create disaggregated memory manager */
    dmm = dmm_cn_init(pool);

    /* clear blocks */
    dmm_bclear(dmm, ctx);

    dmm_ctx = dmm_cli_init(dmm, ctx, config->dmm.pmem_initial_alloc_size_mb * 1024 * 1024);

    /* create sharedfs */
    sharedfs_remote_addr = sharedfs_create(ctx, dmm_ctx,
                                           config->sharedfs.interval_node_nr_blks_count,
                                           config->sharedfs.interval_node_nr_blks,
                                           config->sharedfs.namespace_kv_size_mb * 1024 * 1024,
                                           config->sharedfs.block_mapping_kv_size_mb * 1024 * 1024,
                                           config->sharedfs.kv_nr_shards);

    /* create logger */
    logger_remote_addr = logger_create(ctx, dmm_ctx,
                                       config->logger.max_nr_logs, config->logger.arena_nr_logs);

    /* fill super */
    super = dm_push(ctx, NULL, sizeof(struct ethane_super));
    super->magic = 0xaabbccddbeefdead;
    super->sharedfs_remote_addr = sharedfs_remote_addr;
    super->logger_remote_addr = logger_remote_addr;
    super->chkpt_ver = 0;

    /* write super */
    ret = dm_copy_to_remote(ctx, ETHANE_SB_REMOTE_ADDR, super, sizeof(struct ethane_super), DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    /* wait */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static inline void get_oplogger_ctx(ethanefs_cli_t *cli, oplogger_t *oplogger, oplogger_ctx_t *oplogger_ctx) {
    memset(oplogger_ctx, 0, sizeof(*oplogger_ctx));

    oplogger_ctx->oplogger = oplogger;

    oplogger_ctx->uid = cli->uid;
    oplogger_ctx->gid = cli->gid;

    oplogger_ctx->nr_shards = 0;
    oplogger_ctx->shard = 0;

    oplogger_ctx->replay_cb = NULL;

    oplogger_ctx->wait_check = false;
}

static inline void set_oplogger_wait_check(ethanefs_cli_t *cli, oplogger_ctx_t *oplogger_ctx, bool wait_check) {
    oplogger_ctx->wait_check = wait_check;
}

static inline void set_oplogger_private_data(ethanefs_cli_t *cli, oplogger_ctx_t *oplogger_ctx, void *priv) {
    oplogger_ctx->priv = priv;
}

static inline void set_oplogger_shard(ethanefs_cli_t *cli, oplogger_ctx_t *oplogger_ctx, int nr_shards, int shard) {
    oplogger_ctx->nr_shards = nr_shards;
    oplogger_ctx->shard = shard;
}

static inline void set_replay_cb(ethanefs_cli_t *cli, oplogger_ctx_t *oplogger_ctx,
                                 oplogger_replay_cb_t replay_cb, void *replay_ctx) {
    oplogger_ctx->replay_cb = replay_cb;
    oplogger_ctx->replay_ctx = replay_ctx;
}

static inline void get_cachefs_ctx(ethanefs_cli_t *cli, cachefs_ctx_t *cachefs_ctx) {
    cachefs_ctx->uid = cli->uid;
    cachefs_ctx->gid = cli->gid;
}

static inline dmptr_t alloc_dentry(ethanefs_cli_t *cli) {
    dmm_cli_t *dmm_th = cli->dmm;
    dmptr_t addr;
    addr = dmm_balloc(dmm_th, DENTRY_SIZE, DENTRY_SIZE, DMPTR_NULL);
    if (unlikely(IS_ERR(addr))) {
        pr_err("alloc dentry page failed: %ld", PTR_ERR(addr));
    }
    return addr;
}

static inline int read_data(ethanefs_cli_t *cli, void *user_buf, size_t read_size, cachefs_blk_t *blks) {
    dmcontext_t *ctx = cli->ctx;
    void *buf;
    int ret;

    /* FIXME: */
    ethane_assert(read_size == blks->size);

    pr_debug("read_data: %p, %zu", user_buf, read_size);

    dm_mark(cli->ctx);

    buf = dm_push(ctx, NULL, read_size);

    ret = dm_copy_from_remote(ctx, buf, blks->blk_remote_addr, read_size, DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    /* wait */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    memcpy(user_buf, buf, read_size);

out:
    dm_pop(cli->ctx);
    return ret;
}

static dmptr_t alloc_and_write_data(ethanefs_cli_t *cli, size_t size, const char *data) {
    dmm_cli_t *dmm_th = cli->dmm;
    dmptr_t remote_addr;
    void *buf;
    int ret;

    dm_mark(cli->ctx);

    remote_addr = dmm_balloc(dmm_th, ALIGN_UP(size, BLK_SIZE), BLK_SIZE, 0);
    if (unlikely(IS_ERR(remote_addr))) {
        pr_err("failed to alloc data block: %ld", PTR_ERR(remote_addr));
        ret = PTR_ERR(remote_addr);
        goto out;
    }

    pr_debug("alloc and write data: remote_addr=%lx@%d size=%lu", remote_addr, DMPTR_MN_ID(remote_addr), size);

    buf = dm_push(cli->ctx, data, size);

    ret = dm_copy_to_remote(cli->ctx, remote_addr, buf, size, 0);
    if (unlikely(IS_ERR(ret))) {
        remote_addr = ret;
        goto out;
    }

    ret = dm_flush(cli->ctx, remote_addr, DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        remote_addr = ret;
        goto out;
    }

    /* We do not wait for ACK here, wait after dlog append to gain more parallelism. */

out:
    dm_pop(cli->ctx);
    return remote_addr;
}

static void check_cachefs_full(ethanefs_cli_t *cli) {
    if (!cachefs_reached_max_size(cli->cfs)) {
        return;
    }

    pr_err("cacheFS full (reached max size), force clean...");
    ethanefs_clean_cli(cli);
}

static const char *get_path(ethanefs_cli_t *cli, const char *path) {
    if (path[0] != '/') {
        strcpy(cli->path + cli->cwd_len, "/");
        strcat(cli->path + cli->cwd_len, path);
        path = cli->path;
    }
    pr_debug("get_path: %s (cwd: %.*s)", path, (int) cli->cwd_len, cli->path);
    return path;
}

int ethanefs_getattr(ethanefs_cli_t *cli, const char *path, struct stat *stbuf) {
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    long old_v;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    old_v = oplogger_snapshot_begin(cli->oplogger, &oplogger_ctx);

    ret = oplogger_replay_getattr(cli->oplogger, &oplogger_ctx, path, false, 0);
    if (unlikely(ret < 0)) {
        goto out;
    }

    oplogger_snapshot_end(cli->oplogger, &oplogger_ctx, old_v);

    ret = oplogger_replay_getattr(cli->oplogger, &oplogger_ctx, path, false, 0);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_getattr(cli->cfs, &cachefs_ctx, path, stbuf);

out:
    return ret;
}

int ethanefs_mkdir(ethanefs_cli_t *cli, const char *path, mode_t mode) {
    long log_insert_duration, log_replay_duration, cfs_prefetch_duration, cfs_duration, duration;
    long log_read_duration, log_fetch_duration;
    uint64_t result = OP_RESULT_UNDETERMINED;
    struct bench_timer timer, op_timer;
    dmptr_t dentry_remote_addr, log;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    int ret, nr_read_logs;
    size_t ver;

    path = get_path(cli, path);

    bench_timer_start(&op_timer);

    nr_read_logs = logger_get_nr_read_logs(cli->logger);
    log_fetch_duration = logger_get_fetch_duration(cli->logger);
    log_read_duration = logger_get_read_duration(cli->logger);

    check_cachefs_full(cli);

    dentry_remote_addr = alloc_dentry(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    bench_timer_start(&timer);

    /* append log */
    log = oplogger_mkdir(cli->oplogger, &oplogger_ctx, path, mode, dentry_remote_addr);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    log_insert_duration = bench_timer_end(&timer);

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    bench_timer_start(&timer);

    cachefs_prefetch_metadata(cli->cfs, path);

    cfs_prefetch_duration = bench_timer_end(&timer);

    bench_timer_start(&timer);

    /* replay until the newly appended log */
    ret = oplogger_replay_mkdir(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    log_replay_duration = bench_timer_end(&timer);

    bench_timer_start(&timer);

    /* perform the actual operation */
    ret = cachefs_mkdir(cli->cfs, &cachefs_ctx, path, &result, mode, dentry_remote_addr, ver);

    cfs_duration = bench_timer_end(&timer);

    /* change result async */
    oplogger_set_result_async(cli->oplogger, log, result);

    duration = bench_timer_end(&op_timer);

    nr_read_logs = logger_get_nr_read_logs(cli->logger) - nr_read_logs;
    log_fetch_duration = logger_get_fetch_duration(cli->logger) - log_fetch_duration;
    log_read_duration = logger_get_read_duration(cli->logger) - log_read_duration;

    tracepoint_sample(ethane, op_latency, dm_get_cli_id(cli->ctx), TRACE_OP_MKDIR,
                      log_insert_duration, log_replay_duration, cfs_prefetch_duration, cfs_duration, duration);

    cli->nr_ops++;
    if (cli->nr_ops % STAT_REQ_INTERVAL == 0) {
        prom_histogram_observe(prom_req_lat, (double) duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_log_insert_lat, (double) log_insert_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_cfs_prefetch_lat, (double) cfs_prefetch_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_log_replay_lat, (double) log_replay_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_log_fetch_lat, (double) log_fetch_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_log_read_lat, (double) log_read_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_cfs_lat, (double) cfs_duration / 1000, (const char *[]) { cli->label });
        prom_histogram_observe(prom_req_nr_read_logs, (double) nr_read_logs, (const char *[]) { cli->label });
    }

out:
    return ret;
}

int ethanefs_rmdir(ethanefs_cli_t *cli, const char *path) {
    uint64_t result = OP_RESULT_UNDETERMINED;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log;
    size_t ver;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_rmdir(cli->oplogger, &oplogger_ctx, path);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_rmdir(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_rmdir(cli->cfs, &cachefs_ctx, path, &result, ver);

    /* change result async */
    oplogger_set_result_async(cli->oplogger, log, result);

out:
    return ret;
}

int ethanefs_unlink(ethanefs_cli_t *cli, const char *path) {
    uint64_t result = OP_RESULT_UNDETERMINED;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log;
    size_t ver;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_unlink(cli->oplogger, &oplogger_ctx, path);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_unlink(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_unlink(cli->cfs, &cachefs_ctx, path, &result, ver);

    /* change result async */
    oplogger_set_result_async(cli->oplogger, log, result);

out:
    return ret;
}

struct ethanefs_open_file {
    struct ethane_open_file open_file;
};

ethanefs_open_file_t *ethanefs_create(ethanefs_cli_t *cli, const char *path, mode_t mode) {
    uint64_t result = OP_RESULT_UNDETERMINED;
    dmptr_t dentry_remote_addr, log;
    struct ethane_open_file *file;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    ethanefs_open_file_t *of;
    size_t ver;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    dentry_remote_addr = alloc_dentry(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_create(cli->oplogger, &oplogger_ctx, path, mode, dentry_remote_addr);
    if (unlikely(IS_ERR(log))) {
        of = ERR_PTR(PTR_ERR(log));
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_create(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        of = ERR_PTR(ret);
        goto out;
    }

    /* create open file */
    file = malloc(sizeof(struct ethane_open_file) + strlen(path) + 1);

    /* perform the actual operation */
    ret = cachefs_create(cli->cfs, &cachefs_ctx, path, &result, mode, dentry_remote_addr, file, ver);
    if (unlikely(ret < 0)) {
        of = ERR_PTR(ret);
        goto out;
    }

    if (!ret) {
        of = (ethanefs_open_file_t *) file;
    } else {
        free(file);
        of = ERR_PTR(ret);
    }

    /* change result async */
    oplogger_set_result_async(cli->oplogger, log, result);

out:
    return of;
}

ethanefs_open_file_t *ethanefs_open(ethanefs_cli_t *cli, const char *path) {
    struct ethane_open_file *file;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    ethanefs_open_file_t *of;
    long old_v;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* create open file */
    file = malloc(sizeof(struct ethane_open_file) + strlen(path) + 1);

    old_v = oplogger_snapshot_begin(cli->oplogger, &oplogger_ctx);

    ret = oplogger_replay_read(cli->oplogger, &oplogger_ctx, path, false, 0);
    if (unlikely(ret < 0)) {
        of = ERR_PTR(ret);
        goto out;
    }

    oplogger_snapshot_end(cli->oplogger, &oplogger_ctx, old_v);

    ret = oplogger_replay_open(cli->oplogger, &oplogger_ctx, path, false, 0);
    if (unlikely(ret < 0)) {
        of = ERR_PTR(ret);
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_open(cli->cfs, &cachefs_ctx, path, file);
    if (unlikely(ret < 0)) {
        of = ERR_PTR(ret);
        goto out;
    }

    if (!ret) {
        of = (ethanefs_open_file_t *) file;
    } else {
        free(file);
        of = ERR_PTR(ret);
    }

out:
    return of;
}

int ethanefs_close(ethanefs_cli_t *cli, ethanefs_open_file_t *file) {
    free(file);
    return 0;
}

long ethanefs_read(ethanefs_cli_t *cli, ethanefs_open_file_t *file, char *buf, size_t size, off_t off) {
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    cachefs_blk_t blk;
    long read_size;
    long old_v;
    int ret;

    /* FIXME: */
    if (size != IO_SIZE || off % IO_SIZE != 0) {
        pr_err("only support io size %d, and off(=%lu) must be multipler of it!", IO_SIZE, off);
        abort();
    }

    pr_debug("use open file: path=%s dentry=%lx", file->open_file.full_path, file->open_file.remote_dentry_addr);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    old_v = oplogger_snapshot_begin(cli->oplogger, &oplogger_ctx);

    ret = oplogger_replay_read(cli->oplogger, &oplogger_ctx, file->open_file.full_path, false, 0);
    if (unlikely(ret < 0)) {
        read_size = ret;
        goto out;
    }

    oplogger_snapshot_end(cli->oplogger, &oplogger_ctx, old_v);

    ret = oplogger_replay_read(cli->oplogger, &oplogger_ctx, file->open_file.full_path, false, 0);
    if (unlikely(ret < 0)) {
        read_size = ret;
        goto out;
    }

    /* perform the actual operation */
    read_size = cachefs_read(cli->cfs, &cachefs_ctx, file->open_file.full_path,
                             file->open_file.remote_dentry_addr, &blk, off, size);
    if (unlikely(IS_ERR(read_size))) {
        goto out;
    }

    /* read data */
    ret = read_data(cli, buf, read_size, &blk);
    if (unlikely(IS_ERR(ret))) {
        read_size = ret;
        goto out;
    }

out:
    return read_size;
}

long ethanefs_write(ethanefs_cli_t *cli, ethanefs_open_file_t *file, const char *buf, size_t size, off_t off) {
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log, remote_addr;
    cachefs_blk_t blk;
    long write_size;
    size_t ver;
    int ret;

    /* FIXME: */
    if (size != IO_SIZE || off % IO_SIZE != 0) {
        pr_err("only support io size %d, and off(=%lu) must be multipler of it!", IO_SIZE, off);
        abort();
    }

    pr_debug("use open file: path=%s dentry=%lx", file->open_file.full_path, file->open_file.remote_dentry_addr);

    check_cachefs_full(cli);

    remote_addr = alloc_and_write_data(cli, size, buf);
    blk.blk_remote_addr = remote_addr;
    blk.size = size;

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_write(cli->oplogger, &oplogger_ctx,
                         file->open_file.full_path, file->open_file.remote_dentry_addr, remote_addr, size, off);
    if (unlikely(IS_ERR(log))) {
        write_size = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_write(cli->oplogger, &oplogger_ctx, file->open_file.full_path, true, 1);
    if (unlikely(ret < 0)) {
        write_size = ret;
        goto out;
    }

    /* perform the actual operation */
    write_size = cachefs_write(cli->cfs, &cachefs_ctx,
                               file->open_file.full_path, file->open_file.remote_dentry_addr, off, &blk, ver);

out:
    return write_size;
}

int ethanefs_truncate(ethanefs_cli_t *cli, ethanefs_open_file_t *file, off_t size) {
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log;
    size_t ver;
    int ret;

    /* FIXME: */
    if (size % IO_SIZE != 0) {
        pr_err("only support io size %d, and size(=%lu) must be multipler of it!", IO_SIZE, size);
        abort();
    }

    pr_debug("use open file: path=%s dentry=%lx", file->open_file.full_path, file->open_file.remote_dentry_addr);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_truncate(cli->oplogger, &oplogger_ctx,
                            file->open_file.full_path, file->open_file.remote_dentry_addr, size);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_truncate(cli->oplogger, &oplogger_ctx, file->open_file.full_path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_truncate(cli->cfs, &cachefs_ctx,
                           file->open_file.full_path, file->open_file.remote_dentry_addr, size, ver);

out:
    return ret;
}

int ethanefs_chmod(ethanefs_cli_t *cli, const char *path, mode_t mode) {
    uint64_t result = OP_RESULT_UNDETERMINED;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log;
    size_t ver;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_chmod(cli->oplogger, &oplogger_ctx, path, mode);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_chmod(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_chmod(cli->cfs, &cachefs_ctx, path, &result, mode, ver);

    oplogger_set_result_async(oplogger_ctx.oplogger, log, result);

out:
    return ret;
}

int ethanefs_chown(ethanefs_cli_t *cli, const char *path, uid_t uid, gid_t gid) {
    uint64_t result = OP_RESULT_UNDETERMINED;
    oplogger_ctx_t oplogger_ctx;
    cachefs_ctx_t cachefs_ctx;
    dmptr_t log;
    size_t ver;
    int ret;

    path = get_path(cli, path);

    check_cachefs_full(cli);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);
    get_cachefs_ctx(cli, &cachefs_ctx);

    /* append log */
    log = oplogger_chown(cli->oplogger, &oplogger_ctx, path, uid, gid);
    if (unlikely(IS_ERR(log))) {
        ret = PTR_ERR(log);
        goto out;
    }

    /* get current system version */
    ver = oplogger_get_version(cli->oplogger, &oplogger_ctx);

    /* replay until the newly appended log */
    ret = oplogger_replay_chown(cli->oplogger, &oplogger_ctx, path, true, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* perform the actual operation */
    ret = cachefs_chown(cli->cfs, &cachefs_ctx, path, &result, uid, gid, ver);

    oplogger_set_result_async(oplogger_ctx.oplogger, log, result);

out:
    return ret;
}

int ethanefs_get_cli_id(ethanefs_cli_t *cli) {
    return dm_get_cli_id(cli->ctx);
}

static long get_chkpt_ver(ethanefs_cli_t *cli) {
    long *chkpt_ver, ret;

    ret = dm_read(cli->ctx, chkpt_ver, cli->chkpt_ver_remote_addr, DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    /* wait */
    ret = dm_wait_ack(cli->ctx, 1);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    ret = *chkpt_ver;

out:
    return ret;
}

static int increase_chkpt_ver(ethanefs_cli_t *cli) {
    void *add_old_buf;
    int ret = 0;

    add_old_buf = dm_push(cli->ctx, NULL, sizeof(long));
    if (unlikely(!add_old_buf)) {
        ret = -ENOMEM;
        goto out;
    }

    *(long *) add_old_buf = 1;

    ret = dm_faa(cli->ctx, cli->chkpt_ver_remote_addr, add_old_buf, sizeof(long), DMFLAG_ACK);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    ret = dm_wait_ack(cli->ctx, 1);
    if (unlikely(IS_ERR(ret))) {
        goto out;
    }

    pr_info("->%ld+1", *(long *) add_old_buf);

out:
    return ret;
}

void ethanefs_force_checkpoint(ethanefs_cli_t *cli) {
    int ret;
    ret = increase_chkpt_ver(cli);
    if (unlikely(ret < 0)) {
        pr_err("increase_chkpt_ver failed: %d", ret);
        exit(1);
    }
}

void ethanefs_dump_cli(ethanefs_cli_t *cli) {
    cachefs_dump(cli->cfs);
}

void ethanefs_dump_remote(ethanefs_cli_t *cli) {
    sharedfs_dump(cli->rfs);
}

struct replay_ctx {
    long nr_replayed;

    struct bench_timer timer_this_round;
    long nr_replayed_this_round;

    int shard;

    long chkpt_ver, chkpt_ver_remote;
};

static void check_gc(oplogger_ctx_t *oplogger_ctx, struct replay_ctx *replay_ctx, bool replay) {
    ethanefs_cli_t *cli = oplogger_ctx->priv;
    long duration;

    if ((replay && replay_ctx->nr_replayed % CHKPT_GC_INTERVAL == 0) ||
        cachefs_reached_high_watermark(cli->cfs) ||
        replay_ctx->chkpt_ver != replay_ctx->chkpt_ver_remote) {
        pr_info("run checkpointing...");

        replay_ctx->chkpt_ver = replay_ctx->chkpt_ver_remote;

        cachefs_checkpoint(cli->cfs);

        logger_set_gc_head_async(cli->logger, oplogger_ctx->shard,
                                 oplogger_get_next_replay_from(oplogger_ctx->oplogger, oplogger_ctx));

        duration = bench_timer_end(&replay_ctx->timer_this_round);
        tracepoint_sample(ethane, log_checkpoint,
                   dm_get_cli_id(cli->ctx), replay_ctx->shard, replay_ctx->nr_replayed_this_round, duration);

        replay_ctx->nr_replayed_this_round = 0;
        bench_timer_start(&replay_ctx->timer_this_round);
    }
}

static int replay_cb(oplogger_t *oplogger, oplogger_ctx_t *oplogger_ctx, void *replay_ctx_, size_t log_pos) {
    struct replay_ctx *replay_ctx = replay_ctx_;

    replay_ctx->nr_replayed++;
    replay_ctx->nr_replayed_this_round++;

    check_gc(oplogger_ctx, replay_ctx, true);

    return 0;
}

_Noreturn void ethanefs_logger_cache_fetcher_loop(ethanefs_cli_t *cli, ethanefs_logd_config_t *config) {
    pr_info("logger GC invoked, nr_shards=%d", config->checkpoint.nr_shards);
    logger_launch_gc(cli->logger, config->checkpoint.nr_shards);
    logger_cache_fetcher_loop(cli->logger);
}

_Noreturn void ethanefs_checkpoint_loop(ethanefs_cli_t *cli, ethanefs_logd_config_t *config) {
    struct replay_ctx replay_ctx = { 0 };
    zhandle_t *zh = cli->fs->zh;
    oplogger_ctx_t oplogger_ctx;
    struct bench_timer timer;
    int ret, shard;
    char path[256];
    long duration;

    sprintf(path, DM_ZK_PREFIX "checkpoint_clis/shard");
    ret = zoo_create(zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL | ZOO_SEQUENCE, path, sizeof(path));
    if (unlikely(ret != ZOK)) {
        fprintf(stderr, "zoo_create failed: %d", ret);
        exit(1);
    }
    shard = atoi(path + strlen(DM_ZK_PREFIX "checkpoint_clis/shard"));
    pr_info("checkpoint shard: %d started", shard);

    get_oplogger_ctx(cli, cli->oplogger, &oplogger_ctx);

    set_oplogger_shard(cli, &oplogger_ctx, config->checkpoint.nr_shards, shard);
    set_replay_cb(cli, &oplogger_ctx, replay_cb, &replay_ctx);
    set_oplogger_wait_check(cli, &oplogger_ctx, true);
    set_oplogger_private_data(cli, &oplogger_ctx, cli);

    replay_ctx.shard = shard;

    bench_timer_start(&replay_ctx.timer_this_round);
    bench_timer_start(&timer);

    for (;;) {
        oplogger_snapshot_begin(cli->oplogger, &oplogger_ctx);

        ret = oplogger_replay_all(cli->oplogger, &oplogger_ctx, false, 0);
        if (unlikely(ret < 0)) {
            fprintf(stderr, "oplogger_replay_all failed: %d", ret);
            exit(1);
        }

        duration = bench_timer_end(&timer);
        if (duration >= CHECK_CHKPT_VER_INTERVAL_US * 1000) {
            replay_ctx.chkpt_ver_remote = get_chkpt_ver(cli);
            check_gc(&oplogger_ctx, &replay_ctx, false);
            bench_timer_start(&timer);
        }
    }
}

static inline void *huge_page_alloc(size_t size) {
    void *addr = mmap(NULL, size,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    return addr != MAP_FAILED ? addr : NULL;
}

static size_t rpc_cb(void *ctx, void *rv, const void *data, void *aux) {
    size_t size;

    /* Handle DMM callbacks */
    size = dmm_cb(aux, rv, data);
    if (!IS_ERR(size)) {
        return size;
    }

    /* Handle logger callbacks */
    size = logger_cb(ctx, rv, data);
    if (!IS_ERR(size)) {
        return size;
    }

    return -EINVAL;
}

static void *map_file(const char *path, size_t size) {
    void *addr;
    int fd;

    fd = open(path, O_RDWR, 0644);
    if (unlikely(fd < 0)) {
        fprintf(stderr, "open %s failed: %d", path, errno);
        exit(1);
    }

    addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (unlikely(addr == MAP_FAILED)) {
        fprintf(stderr, "mmap %s failed: %d", path, errno);
        exit(1);
    }

    return addr;
}

_Noreturn void ethanefs_mem_daemon(zhandle_t *zh, ethanefs_memd_config_t *config) {
    dmm_mn_t *dmm;
    void *mem_buf;

    mem_buf = map_file(config->pmem_pool_file, config->pmem_pool_size_mb * 1024 * 1024);
    if (unlikely(!mem_buf)) {
        fprintf(stderr, "map_file failed");
        exit(1);
    }

    dmm = dmm_mn_init(mem_buf, config->pmem_pool_size_mb * 1024 * 1024);
    if (unlikely(!dmm)) {
        fprintf(stderr, "dmm_mn_init failed");
        exit(1);
    }

    dm_daemon(zh, mem_buf, config->pmem_pool_size_mb * 1024 * 1024, config->cmem_pool_size_kb * 1024, rpc_cb, dmm);
}

void ethanefs_bind_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if ((sched_setaffinity(0, sizeof(cpu_set_t), &mask)) != 0) {
        perror("bind cpu failed");
        exit(1);
    }
}

void ethanefs_wait_enable(zhandle_t *zh) {
    while (zoo_exists(zh, "/ethane_ctl/enable", 0, NULL) != ZOK) {
        usleep(1000);
    }
}

void ethanefs_post_ready(zhandle_t *zh) {
    char path[256];
    int id;
    if (zoo_create(zh, "/ethane_ctl/ready/ready", NULL, -1, &ZOO_OPEN_ACL_UNSAFE,
                   ZOO_EPHEMERAL | ZOO_SEQUENCE, path, 256) != ZOK) {
        pr_err("failed to post ready");
    }
    id = atoi(path + strlen("/ethane_ctl/ready/ready"));
    pr_info("post ready: %d", id);
}

const char *ethanefs_get_hostname() {
    static char hostname[512] = { 0 };
    static bool set = false;
    if (unlikely(!set)) {
        gethostname(hostname, sizeof(hostname));
        set = true;
    }
    return hostname;
}

const char *ethanefs_get_threadname() {
    static __thread char threadname[16] = { 0 };
    static __thread bool set = false;
    if (unlikely(!set)) {
        pthread_getname_np(pthread_self(), threadname, sizeof(threadname));
        set = true;
    }
    return threadname;
}

int ethanefs_chdir(ethanefs_cli_t *cli, const char *path) {
    if (path[0] == '/') {
        if (path[1] != '\0') {
            strcpy(cli->path, path);
            cli->cwd_len = strlen(path);
        } else {
            cli->cwd_len = 0;
        }
    } else {
        strcat(cli->path, "/");
        strcat(cli->path, path);
        cli->cwd_len += strlen(path) + 1;
    }
    pr_debug("chdir: %.*s", (int) cli->cwd_len, cli->path);
    return 0;
}

int ethanefs_getcwd(ethanefs_cli_t *cli, char *path) {
    strncpy(path, cli->path, cli->cwd_len);
    return 0;
}

const char *ethanefs_get_full_path(ethanefs_cli_t *cli, ethanefs_open_file_t *fh) {
    return fh->open_file.full_path;
}

void ethanefs_set_debug(int mode) {
    pr_info("debug mode: %d", mode);
    debug_mode = mode;
}

void ethanefs_test_remote_path_walk(ethanefs_cli_t *cli, const char *path) {
    static __thread struct ethane_dentry **dentries = NULL;
    int depth = ethane_get_dir_depth(path), i;
    if (unlikely(!dentries)) {
        dentries = malloc(depth * sizeof(*dentries));
        for (i = 0; i < depth; i++) {
            dentries[i]= calloc(1, sizeof(*dentries[i]));
        }
    }
    sharedfs_ns_lookup_dentries(cli->rfs, path, dentries);
}
