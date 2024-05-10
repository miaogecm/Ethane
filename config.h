/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Configuration Parser
 *
 * Hohai University
 */

#ifndef ETHANE_CONFIG_H
#define ETHANE_CONFIG_H

#include <unistd.h>
#include <stdlib.h>

/*
 * Global (per-file-system) Configuration
 */

struct ethane_fs_dmm_config {
    size_t pmem_initial_alloc_size_mb;
};

struct ethane_fs_sharedfs_config {
    size_t namespace_kv_size_mb;
    size_t block_mapping_kv_size_mb;
    int *interval_node_nr_blks;
    int interval_node_nr_blks_count;
    int kv_nr_shards;
};

struct ethane_fs_logger_config {
    int arena_nr_logs;
    int max_nr_logs;
};

struct ethane_fs_config {
    struct ethane_fs_dmm_config dmm;
    struct ethane_fs_sharedfs_config sharedfs;
    struct ethane_fs_logger_config logger;
};

/*
 * Memory Daemon (memd) Configuration
 */

struct ethane_memd_config {
    const char *pmem_pool_file;
    size_t pmem_pool_size_mb;
    size_t cmem_pool_size_kb;
};

/*
 * Client Configuration
 */

struct ethane_cli_net_config {
    size_t local_buf_size_mb;
};

struct ethane_cli_dmm_config {
    size_t pmem_initial_alloc_size_mb;
};

struct ethane_cli_cachefs_config {
    size_t namespace_cache_size_max_mb;
    size_t namespace_cache_size_high_watermark_mb;
    size_t block_mapping_cache_size_max_mb;
    size_t block_mapping_cache_size_high_watermark_mb;
};

struct ethane_cli_sharedfs_config {
    int nr_max_outstanding_updates;
};

struct ethane_cli_logger_config {
    const char *global_shm_path;
    size_t local_log_region_size_mb;
    int log_read_batch_size;
};

struct ethane_cli_lock_config {
    int nr_locks_order;
};

/*
 * Tracing Configuration
 */

struct ethane_cli_trace_config {
    int log_append_trace_interval;
    int log_replay_trace_interval;
    int op_latency_trace_interval;
    int throughput_trace_interval;
};

struct ethane_cli_config {
    struct ethane_cli_net_config net;
    struct ethane_cli_dmm_config dmm;
    struct ethane_cli_cachefs_config cachefs;
    struct ethane_cli_sharedfs_config sharedfs;
    struct ethane_cli_logger_config logger;
    struct ethane_cli_lock_config lock;
    struct ethane_cli_trace_config trace;
};

/*
 * Log Daemon Configuration
 */

struct ethane_logd_checkpoint_config {
    int nr_shards;
};

struct ethane_logd_config {
    struct ethane_logd_checkpoint_config checkpoint;
};

#endif //ETHANE_CONFIG_H
