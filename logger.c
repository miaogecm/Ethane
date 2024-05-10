/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * DPM-friendly Shared Log optimized for Concurrency and Persistence
 *
 * Hohai University
 */

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "logger.h"

#include <prom_collector_registry.h>
#include <prom_histogram.h>

#include "trace.h"
#include "debug.h"
#include "list.h"
#include "rand.h"

#define META_ADDR(logger, field)     ((logger)->meta_remote_addr + offsetof(struct logger_meta, field))

#define MAX_NR_GC_SHARDS        1024

#define STAT_INSERT_INTERVAL   32

#define LAT_HIST_BUCKETS   16, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 100.0, 125.0, 150.0, 175.0, 200.0, 250.0, 300.0, 400.0

//#define BREAKDOWN_LOG_READ_DURATION

struct log_ptr {
    union {
        struct {
            logger_fgprt_t fgprt;
            uint16_t cli_id: 12;
            uint16_t len: 9;
            uint32_t off: 27;
        } __packed;

        uint64_t val;
    } __packed;
} __packed;

struct logger_meta {
    size_t mlog_tail;
    size_t mlog_head;
};

struct logger_info {
    struct logger_meta meta;
    int arena_nr_logs;
    int max_nr_logs;
    dmptr_t mlogs_remote_addr;
    dmptr_t dlogs_remote_addrs[MAX_NR_CLIS];
    size_t gc_heads[MAX_NR_GC_SHARDS];
};

struct logger_global {
    size_t size;
    size_t mlog_cache_tail;
    size_t mlog_cache_head;
    long range_version;
    struct log_ptr mlog_cache[];
};

struct logger {
    dmcontext_t *ctx;
    dmm_cli_t *dmm;

    const char *shm_path;
    struct logger_global *global;

    logger_filter_t filter;

    /* Logger metadata (volatile) */
    dmptr_t meta_remote_addr;
    dmptr_t lo_arrs_remote_addr;
    dmptr_t gc_heads_remote_addr;

    dmptr_t mlogs_remote_addr, local_dlogs_remote_addr;
    dmptr_t *dlogs_remote_addrs;

    size_t local_dlog_tail;

    size_t local_log_region_size;
    int log_read_batch_size;

    int max_nr_logs;
    int arena_nr_logs;

    unsigned int seed;

    int nr_read_logs;
    int nr_inserts;

    int clis_with_task[MAX_NR_CLIS];
    struct list_head local_log_read_tasks[MAX_NR_CLIS];

    long log_fetch_duration, log_read_duration;

    char label[64];
};

struct logger_mn {
    dmm_mn_t *dmm;
    void *ctx;

    struct logger_info *info;

    struct log_ptr *mlogs;
};

static prom_histogram_t *prom_nr_cas;
static prom_histogram_t *prom_mlog_duration_cas;
static prom_histogram_t *prom_dlog_duration_append;

void ethanefs_logger_init_global() {
    prom_nr_cas = prom_histogram_new("ethanefs_logger_nr_cas",
                                      "Logger CAS num",
                                      prom_histogram_buckets_linear(1.0, 1.0, 20),
                                      1, (const char *[]) { "cli_id" });
    prom_mlog_duration_cas = prom_histogram_new("ethanefs_logger_mlog_duration_cas",
                                               "Logger mlog CAS duration",
                                               prom_histogram_buckets_new(LAT_HIST_BUCKETS),
                                               1, (const char *[]) { "cli_id" });
    prom_dlog_duration_append = prom_histogram_new("ethanefs_logger_dlog_duration_append",
                                               "Logger dlog append duration",
                                               prom_histogram_buckets_new(LAT_HIST_BUCKETS),
                                               1, (const char *[]) { "cli_id" });

    prom_collector_registry_must_register_metric(prom_nr_cas);
    prom_collector_registry_must_register_metric(prom_mlog_duration_cas);
    prom_collector_registry_must_register_metric(prom_dlog_duration_append);
}

static inline struct logger_global *get_logger_global(const char *shm_path, int max_nr_logs) {
    struct logger_global *global;
    int fd, ret;
    size_t size;

    size = ALIGN_UP(sizeof(struct logger_global) + max_nr_logs * sizeof(struct log_ptr), PAGE_SIZE);

    fd = open(shm_path, O_RDWR | O_CREAT, 0666);

    ret = ftruncate(fd, size);
    if (unlikely(ret < 0)) {
        pr_err("ftruncate failed when get_logger_global: %s", strerror(errno));
        return ERR_PTR(-errno);
    }

    /* TODO: use HUGETLB FS instead of /dev/shm */
    global = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (unlikely(global == MAP_FAILED)) {
        pr_err("mmap failed when get_logger_global: %s", strerror(errno));
        return ERR_PTR(-errno);
    }

    global->size = size;

    return global;
}

dmptr_t logger_create(dmcontext_t *ctx, dmm_cli_t *dmm, int max_nr_logs, int arena_nr_logs) {
    dmptr_t logger_remote_addr;
    struct logger_info *info;
    int ret;

    dm_mark(ctx);

    info = dm_push(ctx, NULL, sizeof(*info));
    if (unlikely(!info)) {
        logger_remote_addr = -ENOMEM;
        goto out;
    }

    memset(info, 0, sizeof(*info));

    info->max_nr_logs = max_nr_logs;
    info->arena_nr_logs = arena_nr_logs;

    info->mlogs_remote_addr = dmm_balloc(dmm, max_nr_logs * sizeof(struct log_ptr), BLK_SIZE,
                                      DMPTR_DUMMY(dmm_get_isolated_mn_id(dmm, 0)));
    if (unlikely(IS_ERR(info->mlogs_remote_addr))) {
        logger_remote_addr = PTR_ERR(info->mlogs_remote_addr);
        goto out;
    }

    dmm_bzero(dmm, info->mlogs_remote_addr, max_nr_logs * sizeof(struct log_ptr), true);

    logger_remote_addr = dmm_balloc(dmm, sizeof(*info), BLK_SIZE,
                                    DMPTR_DUMMY(dmm_get_isolated_mn_id(dmm, 0)));
    if (unlikely(IS_ERR(logger_remote_addr))) {
        goto out;
    }

    ret = dm_copy_to_remote(ctx, logger_remote_addr, info, sizeof(*info), 0);
    if (unlikely(ret < 0)) {
        logger_remote_addr = ret;
        goto out;
    }

    ret = dm_flush(ctx, logger_remote_addr, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        logger_remote_addr = ret;
        goto out;
    }

    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        logger_remote_addr = ret;
        goto out;
    }

    pr_info("created, mlogs addr = %lu, at MN %d", info->mlogs_remote_addr, DMPTR_MN_ID(info->mlogs_remote_addr));

out:
    dm_pop(ctx);
    return logger_remote_addr;
}

logger_t *logger_init(dmcontext_t *ctx, dmm_cli_t *dmm, dmptr_t logger_info, logger_filter_t filter,
                      size_t local_log_region_size, int log_read_batch_size, const char *shm_path) {
    struct logger_info *info;
    logger_t *logger;
    size_t off;
    int ret, i;

    dm_mark(ctx);

    info = dm_push(ctx, NULL, sizeof(*info));
    if (unlikely(!info)) {
        logger = ERR_PTR(-ENOMEM);
        goto out;
    }

    /* read logger info */
    ret = dm_copy_from_remote(ctx, info, logger_info, sizeof(*info), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        logger = ERR_PTR(ret);
        goto out;
    }

    /* wait for copy-in to complete */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        logger = ERR_PTR(ret);
        goto out;
    }

    logger = calloc(1, sizeof(*logger));
    if (unlikely(!logger)) {
        logger = ERR_PTR(-ENOMEM);
        goto out;
    }

    logger->ctx = ctx;
    logger->dmm = dmm;
    logger->filter = filter;
    logger->meta_remote_addr = logger_info;
    logger->lo_arrs_remote_addr = logger_info + offsetof(struct logger_info, dlogs_remote_addrs);
    logger->gc_heads_remote_addr = logger_info + offsetof(struct logger_info, gc_heads);
    logger->mlogs_remote_addr = info->mlogs_remote_addr;

    logger->local_log_region_size = local_log_region_size;
    logger->log_read_batch_size = log_read_batch_size;

    logger->max_nr_logs = info->max_nr_logs;
    logger->arena_nr_logs = info->arena_nr_logs;

    logger->shm_path = shm_path;
    logger->global = get_logger_global(shm_path, info->max_nr_logs);
    if (unlikely(IS_ERR(logger->global))) {
        logger = ERR_PTR(PTR_ERR(logger->global));
        goto out;
    }

    logger->local_dlog_tail = 0;
    logger->local_dlogs_remote_addr = info->dlogs_remote_addrs[dm_get_cli_id(ctx)];
    if (unlikely(logger->local_dlogs_remote_addr == DMPTR_NULL)) {
        /* allocate dlogs array */
        logger->local_dlogs_remote_addr = dmm_balloc(dmm, local_log_region_size, BLK_SIZE, 0);
        if (unlikely(IS_ERR(logger->local_dlogs_remote_addr))) {
            logger = ERR_PTR(PTR_ERR(logger->local_dlogs_remote_addr));
            goto out;
        }

        /* write dlogs array address to logger info */
        off = logger_info + offsetof(struct logger_info, dlogs_remote_addrs) + dm_get_cli_id(ctx) * sizeof(dmptr_t);
        ret = dm_write(ctx, off, logger->local_dlogs_remote_addr, DMFLAG_ACK);
        if (unlikely(ret < 0)) {
            logger = ERR_PTR(ret);
            goto out;
        }

        /* wait for write to complete */
        ret = dm_wait_ack(ctx, 1);
        if (unlikely(ret < 0)) {
            logger = ERR_PTR(ret);
            goto out;
        }

        /* update logger info */
        info->dlogs_remote_addrs[dm_get_cli_id(ctx)] = logger->local_dlogs_remote_addr;
    }

    logger->dlogs_remote_addrs = calloc(1, MAX_NR_CLIS * sizeof(dmptr_t));
    if (unlikely(!logger->dlogs_remote_addrs)) {
        logger = ERR_PTR(-ENOMEM);
        goto out;
    }
    memcpy(logger->dlogs_remote_addrs, info->dlogs_remote_addrs, MAX_NR_CLIS * sizeof(dmptr_t));

    logger->seed = get_rand_seed();

    for (i = 0; i < MAX_NR_CLIS; i++) {
        INIT_LIST_HEAD(&logger->local_log_read_tasks[i]);
    }

    sprintf(logger->label, "cli%06d", dm_get_cli_id(ctx));

out:
    dm_pop(ctx);
    return logger;
}

static inline long go_cache_barrier_begin(logger_t *logger) {
    return READ_ONCE(logger->global->range_version);
}

static inline void go_cache_barrier_end(logger_t *logger, long old_v) {
    while (READ_ONCE(logger->global->range_version) == old_v) {
        cpu_relax();
    }
}

static inline void go_cache_barrier(logger_t *logger) {
    long old_v = go_cache_barrier_begin(logger);
    go_cache_barrier_end(logger, old_v);
}

long logger_get_tail_begin(logger_t *logger, size_t *tail) {
    *tail = logger->global->mlog_cache_tail;
    return go_cache_barrier_begin(logger);
}

void logger_get_tail_end(logger_t *logger, size_t *tail, long old_v) {
    go_cache_barrier_end(logger, old_v);
    *tail = logger->global->mlog_cache_tail;
}

static dmptr_t append_dlog(logger_t *logger, const void *data, size_t len, int nack) {
    int ret, client;
    dmptr_t addr;
    size_t xlen;
    void *buf;

    xlen = ALIGN_UP(len, CACHELINE_SIZE);

    if (unlikely(logger->local_dlog_tail + xlen > logger->local_log_region_size)) {
        pr_err("local log region full!!!");
        addr = -ENOMEM;
        goto out;
    }

    client = dm_get_cli_id(logger->ctx);

    addr = logger->dlogs_remote_addrs[client] + logger->local_dlog_tail;

    /* copy to local write buffer */
    buf = dm_push(logger->ctx, NULL, xlen);
    if (unlikely(!buf)) {
        addr = -ENOMEM;
        goto out;
    }
    memcpy(buf, data, len);

    /* write to local order array */
    ret = dm_copy_to_remote(logger->ctx, addr, buf, xlen, 0);
    if (unlikely(ret < 0)) {
        addr = ret;
        goto out;
    }

    /* flush write (ensure persistency) */
    ret = dm_flush(logger->ctx, addr, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        addr = ret;
        goto out;
    }

    /* wait for flush to complete */
    ret = dm_wait_ack(logger->ctx, 1 + nack);
    if (unlikely(ret < 0)) {
        addr = ret;
        goto out;
    }

    logger->local_dlog_tail = ALIGN_UP(logger->local_dlog_tail + len, CACHELINE_SIZE);

out:
    return addr;
}

static int find_candidate_slots_in_arena(logger_t *logger, size_t *candidates, size_t arena_start) {
    struct logger_global *global = logger->global;
    struct log_ptr ptr;
    int nr = 0;
    size_t pos;

    /* all empty slots can be our candidates */
    for (pos = arena_start; pos < arena_start + logger->arena_nr_logs; pos++) {
        ptr = READ_ONCE(global->mlog_cache[pos]);
        if (!ptr.len) {
            candidates[nr++] = pos;
        }
    }

    return nr;
}

static size_t choose_slot_in_arena(logger_t *logger, size_t arena_start) {
    size_t candidates[logger->arena_nr_logs];
    int chosen, nr_candidates;

    /* get candidate slots in arena */
    nr_candidates = find_candidate_slots_in_arena(logger, candidates, arena_start);

    if (unlikely(!nr_candidates)) {
        return -ENOMEM;
    }

    /* random choose candidate */
    chosen = rand_r(&logger->seed) % nr_candidates;

    return candidates[chosen];
}

dmptr_t logger_get_tail_and_append(logger_t *logger, size_t *tail,
                                   const void *data, size_t len, logger_fgprt_t fgprt, int nack) {
    size_t tail_arena_start, tail_arena_end = 0, tail_arena_end_old;
    struct log_ptr new_log_ptr, empty = { 0 }, *old, *src;
    long duration, lo_duration, go_duration = 0;
    struct bench_timer time, lo_time, go_time;
    int ret, nr_candidates, nr_cas = 0;
    dmptr_t data_addr, log_ptr_addr;
    size_t pos;

    bench_timer_start(&time);

    dm_mark(logger->ctx);

    bench_timer_start(&lo_time);

    /* append to local order array */
    data_addr = append_dlog(logger, data, len, nack);
    if (unlikely(IS_ERR(data_addr))) {
        goto out;
    }

    lo_duration = bench_timer_end(&lo_time);

    /* prepare new log ptr */
    new_log_ptr.val = 0;
    new_log_ptr.cli_id = dm_get_cli_id(logger->ctx);
    new_log_ptr.off = data_addr - logger->dlogs_remote_addrs[new_log_ptr.cli_id];
    new_log_ptr.len = ALIGN_UP(len, CACHELINE_SIZE);
    new_log_ptr.fgprt = fgprt;

    /* contend for position in global order array */

    old = dm_data(logger->ctx, empty);
    src = dm_data(logger->ctx, empty);

retry:
    go_cache_barrier(logger);

    /* get log range and tail arena range */
    tail_arena_start = READ_ONCE(logger->global->mlog_cache_tail);
    tail_arena_end = min(tail_arena_start + logger->arena_nr_logs, logger->max_nr_logs);

    if (unlikely(tail_arena_start >= tail_arena_end)) {
        pr_err("log list full!!!");
        new_log_ptr.val = -ENOMEM;
        goto out;
    }

    /* find empty position in arena */
    //pos = rand_r(&logger->seed) % (tail_arena_end - tail_arena_start) + tail_arena_start;
    pos = choose_slot_in_arena(logger, tail_arena_start);

    bench_timer_start(&go_time);

    /* contend for the position in arena */
    nr_cas++;
    log_ptr_addr = logger->mlogs_remote_addr + pos * sizeof(struct log_ptr);
    *old = empty;
    *src = new_log_ptr;
    ret = dm_cas(logger->ctx, log_ptr_addr, src, old, sizeof(struct log_ptr), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        new_log_ptr.val = ret;
        goto out;
    }

    /* wait for CAS to complete */
    ret = dm_wait_ack(logger->ctx, 1);
    if (unlikely(ret < 0)) {
        new_log_ptr.val = ret;
        goto out;
    }

    go_duration += bench_timer_end(&go_time);

    /* if not succeed, retry */
    if (unlikely(old->len)) {
        goto retry;
    }

    *tail = pos;

    duration = bench_timer_end(&time);
    tracepoint_sample(ethane, log_append, dm_get_cli_id(logger->ctx),
                      nr_cas, pos, DMPTR_MN_ID(log_ptr_addr), DMPTR_MN_ID(data_addr), DMPTR_OFF(data_addr),
                      go_duration, lo_duration, duration);

    if (logger->nr_inserts++ % STAT_INSERT_INTERVAL == 0) {
        prom_histogram_observe(prom_nr_cas, nr_cas, (const char *[]) { logger->label });
        prom_histogram_observe(prom_mlog_duration_cas, go_duration, (const char *[]) { logger->label });
        prom_histogram_observe(prom_dlog_duration_append, lo_duration, (const char *[]) { logger->label });
    }

out:
    dm_pop(logger->ctx);
    return data_addr;
}

static inline int check_dlogs_arr(logger_t *logger, int cli_id) {
    dmptr_t lo_arr = logger->dlogs_remote_addrs[cli_id], *lo_addr;
    int ret = 0;

    if (likely(lo_arr != DMPTR_NULL)) {
        goto out;
    }

    ret = dm_read(logger->ctx, lo_addr, logger->lo_arrs_remote_addr + cli_id * sizeof(dmptr_t), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = dm_wait_ack(logger->ctx, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    logger->dlogs_remote_addrs[cli_id] = *lo_addr;

out:
    return ret;
}

struct cli_local_log_read_task {
    size_t off, size;
    struct list_head node;
    void *buf;
};

static struct log_ptr *fetch_local_logs(logger_t *logger, struct list_head *local_log_read_tasks,
                                        struct log_ptr *mlog_start, struct log_ptr *mlog_end, void *filter_ctx) {
    struct cli_local_log_read_task *last_task, *curr_task, *final_task = NULL;
    struct list_head *cli_local_log_read_tasks;
    int k, i, ret = 0, nr_clis_with_task = 0;
    struct log_ptr *mlog_cur, ptr;

    /* scan log infos and maintain the list */
    for (mlog_cur = mlog_start; mlog_cur < mlog_end; mlog_cur++) {
        ptr = READ_ONCE(*mlog_cur);

        if (unlikely(!ptr.len)) {
            /* encountered empty log position, stop the log read */
            break;
        }

        /* ski  p the log if no dependency */
        if (logger->filter && !logger->filter(filter_ctx, ptr.fgprt, mlog_cur - logger->global->mlog_cache)) {
            pr_debug("op not depend on log %lu (fgprt: %d)", mlog_cur - logger->global->mlog_cache, ptr.fgprt);
            continue;
        }
        pr_debug("op depends on log %lu (fgprt: %d)", mlog_cur - logger->global->mlog_cache, ptr.fgprt);

        ret = check_dlogs_arr(logger, ptr.cli_id);
        if (unlikely(ret < 0)) {
            mlog_cur = ERR_PTR(ret);
            goto out;
        }

        ethane_assert(logger->dlogs_remote_addrs[ptr.cli_id] != DMPTR_NULL);

        cli_local_log_read_tasks = &local_log_read_tasks[ptr.cli_id];

        last_task = list_last_entry(cli_local_log_read_tasks, struct cli_local_log_read_task, node);

        /* can merge with last task */
        if (!list_empty(cli_local_log_read_tasks) && last_task->off + last_task->size == ptr.off) {
            last_task->size += ptr.len;
            pr_debug("read mlog %lu, can merge with last task %p, len=%d",
                     mlog_cur - logger->global->mlog_cache, last_task, ptr.len);
            continue;
        }

        /* empty list or can not merge, allocate new task */
        curr_task = malloc(sizeof(*curr_task));
        if (unlikely(!curr_task)) {
            mlog_cur = ERR_PTR(-ENOMEM);
            goto out;
        }

        if (list_empty(cli_local_log_read_tasks)) {
            logger->clis_with_task[nr_clis_with_task++] = ptr.cli_id;
        }

        curr_task->off = ptr.off;
        curr_task->size = ptr.len;
        INIT_LIST_HEAD(&curr_task->node);
        list_add_tail(&curr_task->node, cli_local_log_read_tasks);

        pr_debug("read mlog %lu, create new task %p, len=%d",
                 mlog_cur - logger->global->mlog_cache, curr_task, ptr.len);

        final_task = curr_task;
    }

    if (unlikely(!final_task)) {
        /* no log to read */
        goto out;
    }

    /* allocate RDMA buffers and issue log read requests */
    for (k = 0; k < nr_clis_with_task; k++) {
        i = logger->clis_with_task[k];

        list_for_each_entry(curr_task, &local_log_read_tasks[i], node) {
            ethane_assert(logger->dlogs_remote_addrs[i] != DMPTR_NULL);

            curr_task->buf = dm_push(logger->ctx, NULL, curr_task->size);
            if (unlikely(!curr_task->buf)) {
                mlog_cur = ERR_PTR(-ENOMEM);
                goto out;
            }

            ret = dm_copy_from_remote(logger->ctx,
                                      curr_task->buf, logger->dlogs_remote_addrs[i] + curr_task->off, curr_task->size, 0);
            if (unlikely(ret < 0)) {
                mlog_cur = ERR_PTR(ret);
                goto out;
            }
        }
    }

    /* wait for copy-in to complete */
    ret = dm_wait_ack(logger->ctx, dm_set_ack_all(logger->ctx));
    if (unlikely(ret < 0)) {
        mlog_cur = ERR_PTR(ret);
        goto out;
    }

out:
    return mlog_cur;
}

int logger_get_nr_read_logs(logger_t *logger) {
    return logger->nr_read_logs;
}

long logger_get_fetch_duration(logger_t *logger) {
    return logger->log_fetch_duration;
}

long logger_get_read_duration(logger_t *logger) {
    return logger->log_read_duration;
}

static int read_logs(logger_t *logger, struct list_head *local_log_read_tasks,
                            struct log_ptr *go_start, struct log_ptr *go_end,
                            logger_reader_t reader, void *reader_ctx) {
    struct list_head *cli_local_log_read_tasks;
    struct cli_local_log_read_task *task;
    struct log_ptr *go_cur, ptr;
    size_t off, len;
    int cli_id;

    for (go_cur = go_start; go_cur < go_end; go_cur++) {
        ptr = READ_ONCE(*go_cur);

        cli_id = ptr.cli_id;
        off = ptr.off;
        len = ptr.len;

        cli_local_log_read_tasks = &local_log_read_tasks[cli_id];
        if (list_empty(cli_local_log_read_tasks)) {
            /* no dependent log to read */
            continue;
        }

        task = list_first_entry(cli_local_log_read_tasks, struct cli_local_log_read_task, node);

        if (off < task->off) {
            /* the log has been skipped */
            ethane_assert(off + len <= task->off);
            continue;
        }

        pr_debug("mlog %lu within task %p range, len=%lu, task size=%lu, off=%lu",
                 go_cur - logger->global->mlog_cache, task, len, task->size, task->off);

        if (len > task->size) {
            pr_err("len=%lu size=%lu", len, task->size);
        }

        ethane_assert(off == task->off);
        ethane_assert(len <= task->size);

        /* read the log */
        reader(task->buf, reader_ctx, go_cur - logger->global->mlog_cache,
            logger->dlogs_remote_addrs[cli_id] + off);
        logger->nr_read_logs++;

        /* update task */
        task->off += len;
        task->size -= len;
        task->buf += len;

        /* if the task is done, free it */
        if (!task->size) {
            list_del(&task->node);
            free(task);
        }
    }
}

/*
 * Read logs from @head to @tail. Return the position of first "hole" before @tail, or @tail if no hole.
 * NOTE THAT The logger reading will stop at the first "hole" between @head and @tail.
 */
size_t
logger_read(logger_t *logger, logger_reader_t reader, size_t head, size_t tail, void *filter_ctx, void *reader_ctx) {
    struct list_head *local_log_read_tasks = logger->local_log_read_tasks;
    struct log_ptr *go_start, *go_end, *go_real_end;
    struct logger_global *global = logger->global;
    struct bench_timer timer;

    /* read local logs in a batched manner */
    go_start = global->mlog_cache + head;
    do {
        go_end = min(global->mlog_cache + tail, go_start + logger->log_read_batch_size);

        dm_mark(logger->ctx);

        /* use RDMA to fetch local logs */
#ifdef BREAKDOWN_LOG_READ_DURATION
        bench_timer_start(&timer);
#endif
        go_real_end = fetch_local_logs(logger, local_log_read_tasks, go_start, go_end, filter_ctx);
#ifdef BREAKDOWN_LOG_READ_DURATION
        logger->log_fetch_duration += bench_timer_end(&timer);
#endif

        /* read these logs */
#ifdef BREAKDOWN_LOG_READ_DURATION
        bench_timer_start(&timer);
#endif
        read_logs(logger, local_log_read_tasks, go_start, go_real_end, reader, reader_ctx);
#ifdef BREAKDOWN_LOG_READ_DURATION
        logger->log_read_duration += bench_timer_end(&timer);
#endif

        dm_pop(logger->ctx);

        /* if we encountered empty log position before, stop the log read */
        if (unlikely(go_real_end < go_end)) {
            go_end = go_real_end;
            break;
        }

        go_start = go_end;
    } while (go_end < global->mlog_cache + tail);

    return go_end - global->mlog_cache;
}

int logger_set_gc_head_async(logger_t *logger, int shard, size_t gc_head) {
    int ret;
    dm_mark(logger->ctx);
    ret = dm_write(logger->ctx, logger->gc_heads_remote_addr + shard * sizeof(size_t), gc_head, 0);
    ret = dm_barrier(logger->ctx);
    dm_pop(logger->ctx);
    pr_debug("shard:%d gc_head:%lu", shard, gc_head);
    return ret;
}

_Noreturn void logger_cache_fetcher_loop(logger_t *logger) {
    struct logger_global *global = logger->global;
    struct logger_meta meta, *next_meta;
    dmptr_t start_addr, end_addr;
    struct bench_timer time;
    size_t tail = 0;
    long duration;
    void *mr;
    int ret;

    next_meta = dm_push(logger->ctx, NULL, sizeof(meta));

    mr = dm_reg_local_buf(logger->ctx, global, global->size);

    /* read the logger metadata */
    ret = dm_copy_from_remote(logger->ctx, next_meta, logger->meta_remote_addr, sizeof(*next_meta), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        exit(1);
    }

    /* wait for copy-in to complete */
    ret = dm_wait_ack(logger->ctx, 1);
    if (unlikely(ret < 0)) {
        exit(1);
    }

    for (;;) {
        bench_timer_start(&time);

        meta = *next_meta;

        /* update head and tail pointer */
        global->mlog_cache_head = meta.mlog_head;
        global->mlog_cache_tail = meta.mlog_tail;
        barrier();

        if (meta.mlog_tail <= tail) {
            /* nothing to read */
            goto read_data_done;
        }

        /* get read range */
        start_addr = logger->mlogs_remote_addr + tail * sizeof(struct log_ptr);
        end_addr = logger->mlogs_remote_addr + (meta.mlog_tail + logger->arena_nr_logs - 1) * sizeof(struct log_ptr);

        /* read global order array data */
        dm_local_buf_switch(logger->ctx, mr);
        ret = dm_copy_from_remote(logger->ctx, global->mlog_cache + tail,
                                  start_addr, end_addr - start_addr, 0);
        dm_local_buf_switch_default(logger->ctx);
        if (unlikely(ret < 0)) {
            exit(1);
        }

        tail = meta.mlog_tail;

read_data_done:
        /* read the logger metadata */
        ret = dm_copy_from_remote(logger->ctx, next_meta, logger->meta_remote_addr, sizeof(*next_meta), DMFLAG_ACK);
        if (unlikely(ret < 0)) {
            exit(1);
        }

        /* wait for copy-in to complete */
        ret = dm_wait_ack(logger->ctx, 1);
        if (unlikely(ret < 0)) {
            exit(1);
        }

        duration = bench_timer_end(&time);

        tracepoint_sample(ethane, log_go_read,
                   dm_get_cli_id(logger->ctx), global->range_version,
                   end_addr - start_addr, meta.mlog_head, tail, duration);

        /* increase version */
        WRITE_ONCE(global->range_version, global->range_version + 1);
    }
}

int logger_launch_gc(logger_t *logger, int nr_gc_shards) {
    struct {
        size_t id;
        dmptr_t info_addr;
        int nr_gc_shards;
    } args = {
        .id = LOGGER_GC_RPC_ID,
        .info_addr = logger->meta_remote_addr,
        .nr_gc_shards = nr_gc_shards
    }, *argbuf;
    int ret;
    dm_mark(logger->ctx);
    argbuf = dm_push(logger->ctx, &args, sizeof(args));
    ret = dm_rpc(logger->ctx, logger->meta_remote_addr, argbuf, sizeof(*argbuf));
    dm_pop(logger->ctx);
    return ret;
}

logger_mn_t *logger_mn_init(void *ctx, dmptr_t logger_info) {
    struct logger_info *info;
    logger_mn_t *logger;

    logger = malloc(sizeof(*logger));
    if (unlikely(!logger)) {
        logger = ERR_PTR(-ENOMEM);
        goto out;
    }

    info = dm_get_ptr(ctx, logger_info);
    if (unlikely(!info)) {
        logger = ERR_PTR(-EINVAL);
        pr_err("logger_mn_init: invalid logger_info");
        goto out;
    }

    logger->ctx = ctx;
    logger->info = info;

    logger->mlogs = dm_get_ptr(ctx, info->mlogs_remote_addr);
    if (unlikely(!logger->mlogs)) {
        logger = ERR_PTR(-EINVAL);
        pr_err("invalid mlogsmlogs_remote_addr");
        goto out;
    }

out:
    return logger;
}

_Noreturn void logger_gc_loop(logger_mn_t *logger, int nr_gc_shards) {
    struct logger_info *info = logger->info;
    int gc_head_interval = 128, i;
    size_t min_gc_head, tail = 0;
    struct log_ptr ptr;

    for (i = 0; ; i++) {
        ptr = READ_ONCE(logger->mlogs[tail]);
        if (ptr.len) {
            tail++;
            WRITE_ONCE(info->meta.mlog_tail, tail);
        }

        if (i % gc_head_interval == 0) {
            min_gc_head = info->gc_heads[0];
            for (int i = 1; i < nr_gc_shards; i++) {
                if (info->gc_heads[i] < min_gc_head) {
                    min_gc_head = info->gc_heads[i];
                }
            }

            if (min_gc_head > info->meta.mlog_head) {
                /* GC logs before head */
                WRITE_ONCE(info->meta.mlog_head, min_gc_head);
                pr_debug("change head to %lu, current range: [%lu, %lu)", min_gc_head, min_gc_head, tail);
            }
        }
    }
}

struct gc_worker_arg {
    logger_mn_t *logger;
    int nr_gc_shards;
};

static void *logger_gc_worker(void *arg) {
    struct gc_worker_arg *gc_worker_arg = arg;
    logger_gc_loop(gc_worker_arg->logger, gc_worker_arg->nr_gc_shards);
}

/* TODO: Remove this global variable */
bool gc_worker_started = false;

size_t logger_cb(void *ctx, void *rv, const void *pr) {
    struct gc_worker_arg *arg;
    pthread_t gc_worker;
    logger_mn_t *logger;
    dmptr_t info_addr;
    int nr_gc_shards;

    if (gc_worker_started) {
        return 0;
    }

    if (*(size_t *) pr != LOGGER_GC_RPC_ID) {
        return -EINVAL;
    }

    gc_worker_started = true;

    info_addr = *(dmptr_t *) (pr + sizeof(size_t));
    nr_gc_shards = *(int *) (pr + sizeof(size_t) + sizeof(dmptr_t));

    if (!dm_get_ptr(ctx, info_addr)) {
        pr_err("logger_cb: invalid info_addr: wrong target MN");
        return -EINVAL;
    }

    logger = logger_mn_init(ctx, info_addr);
    if (IS_ERR(logger)) {
        pr_err("logger_cb: logger_mn_init failed");
        return -EINVAL;
    }

    pr_info("Logger GC worker started: nr_gc_shards=%d, info=%p", nr_gc_shards, logger->info);

    arg = malloc(sizeof(struct gc_worker_arg));
    arg->logger = logger;
    arg->nr_gc_shards = nr_gc_shards;
    pthread_create(&gc_worker, NULL, logger_gc_worker, arg);

    return 0;
}

size_t logger_get_head(logger_t *logger) {
    return READ_ONCE(logger->global->mlog_cache_head);
}
