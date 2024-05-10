/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * DPM-friendly Shared Log optimized for Concurrency and Persistence
 *
 * Hohai University
 */

#ifndef ETHANE_LOGGER_H
#define ETHANE_LOGGER_H

#include <stdlib.h>

#include "ethane.h"
#include "dmpool.h"
#include "dmm.h"

#define LOGGER_GC_RPC_ID    8

typedef struct logger logger_t;
typedef struct logger_mn logger_mn_t;

typedef uint16_t logger_fgprt_t;
typedef bool (*logger_filter_t)(void *ctx, logger_fgprt_t fgprt, size_t pos);

typedef int (*logger_reader_t)(void *log_data, void *ctx, size_t log_pos, dmptr_t log_remote_addr);

/* compute node side logger functions */

dmptr_t logger_create(dmcontext_t *ctx, dmm_cli_t *dmm, int max_nr_logs, int arena_nr_logs);
logger_t *logger_init(dmcontext_t *ctx, dmm_cli_t *dmm, dmptr_t logger_info, logger_filter_t filter,
                      size_t local_log_region_size, int log_read_batch_size, const char *shm_path);
long logger_get_tail_begin(logger_t *logger, size_t *tail);
void logger_get_tail_end(logger_t *logger, size_t *tail, long old_v);
size_t logger_get_head(logger_t *logger);
dmptr_t logger_get_tail_and_append(logger_t *logger, size_t *tail,
                                   const void *data, size_t len, logger_fgprt_t fgprt, int nack);
size_t logger_read(logger_t *logger, logger_reader_t reader, size_t head, size_t tail, void *dep_ctx, void *reader_ctx);
int logger_set_gc_head_async(logger_t *logger, int shard, size_t gc_head);
_Noreturn void logger_cache_fetcher_loop(logger_t *logger);
int logger_launch_gc(logger_t *logger, int nr_gc_shards);

int logger_get_nr_read_logs(logger_t *logger);
long logger_get_fetch_duration(logger_t *logger);
long logger_get_read_duration(logger_t *logger);

/* memory node side logger functions */

logger_mn_t *logger_mn_init(void *ctx, dmptr_t logger_info);
_Noreturn void logger_gc_loop(logger_mn_t *logger, int nr_gc_shards);
size_t logger_cb(void *ctx, void *rv, const void *pr);

#endif //ETHANE_LOGGER_H
