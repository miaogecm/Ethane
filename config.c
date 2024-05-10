/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Configuration Parser
 *
 * Hohai University
 */

#include <cyaml/cyaml.h>
#include <errno.h>

#include "ethanefs.h"
#include "ethane.h"
#include "config.h"

static const cyaml_schema_field_t ethane_fs_dmm_config_schema[] = {
    CYAML_FIELD_UINT(
        "pmem_initial_alloc_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_dmm_config, pmem_initial_alloc_size_mb),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t internal_node_nr_blks_schema = {
    CYAML_VALUE_INT(CYAML_FLAG_DEFAULT, int)
};

static const cyaml_schema_field_t ethane_fs_sharedfs_config_schema[] = {
    CYAML_FIELD_UINT(
        "namespace_kv_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_sharedfs_config, namespace_kv_size_mb),
    CYAML_FIELD_UINT(
        "block_mapping_kv_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_sharedfs_config, block_mapping_kv_size_mb),
    CYAML_FIELD_SEQUENCE(
        "interval_node_nr_blks",
        CYAML_FLAG_POINTER,
        struct ethane_fs_sharedfs_config, interval_node_nr_blks,
        &internal_node_nr_blks_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "kv_nr_shards",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_sharedfs_config, kv_nr_shards),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_fs_logger_config_schema[] = {
    CYAML_FIELD_UINT(
        "arena_nr_logs",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_logger_config, arena_nr_logs),
    CYAML_FIELD_UINT(
        "max_nr_logs",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_logger_config, max_nr_logs),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_fs_config_schema[] = {
    CYAML_FIELD_MAPPING(
        "dmm",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_config, dmm,
        ethane_fs_dmm_config_schema),
    CYAML_FIELD_MAPPING(
        "sharedfs",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_config, sharedfs,
        ethane_fs_sharedfs_config_schema),
    CYAML_FIELD_MAPPING(
        "logger",
        CYAML_FLAG_DEFAULT,
        struct ethane_fs_config, logger,
        ethane_fs_logger_config_schema),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_memd_config_schema[] = {
    CYAML_FIELD_STRING_PTR(
        "pmem_pool_file",
        CYAML_FLAG_POINTER,
        struct ethane_memd_config, pmem_pool_file,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "pmem_pool_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_memd_config, pmem_pool_size_mb),
    CYAML_FIELD_UINT(
        "cmem_pool_size_kb",
        CYAML_FLAG_DEFAULT,
        struct ethane_memd_config, cmem_pool_size_kb),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_net_config_schema[] = {
    CYAML_FIELD_UINT(
        "local_buf_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_net_config, local_buf_size_mb),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_dmm_config_schema[] = {
    CYAML_FIELD_UINT(
        "pmem_initial_alloc_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_dmm_config, pmem_initial_alloc_size_mb),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_cachefs_config_schema[] = {
    CYAML_FIELD_UINT(
        "namespace_cache_size_max_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_cachefs_config, namespace_cache_size_max_mb),
    CYAML_FIELD_UINT(
        "namespace_cache_size_high_watermark_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_cachefs_config, namespace_cache_size_high_watermark_mb),
    CYAML_FIELD_UINT(
        "block_mapping_cache_size_max_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_cachefs_config, block_mapping_cache_size_max_mb),
    CYAML_FIELD_UINT(
        "block_mapping_cache_size_high_watermark_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_cachefs_config, block_mapping_cache_size_high_watermark_mb),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_sharedfs_config_schema[] = {
    CYAML_FIELD_UINT(
        "nr_max_outstanding_updates",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_sharedfs_config, nr_max_outstanding_updates),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_logger_config_schema[] = {
    CYAML_FIELD_STRING_PTR(
        "global_shm_path",
        CYAML_FLAG_POINTER,
        struct ethane_cli_logger_config, global_shm_path,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "local_log_region_size_mb",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_logger_config, local_log_region_size_mb),
    CYAML_FIELD_UINT(
        "log_read_batch_size",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_logger_config, log_read_batch_size),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_lock_config_schema[] = {
    CYAML_FIELD_UINT(
        "nr_locks_order",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_lock_config, nr_locks_order),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_cli_config_schema[] = {
    CYAML_FIELD_MAPPING(
        "net",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, net,
        ethane_cli_net_config_schema),
    CYAML_FIELD_MAPPING(
        "dmm",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, dmm,
        ethane_cli_dmm_config_schema),
    CYAML_FIELD_MAPPING(
        "cachefs",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, cachefs,
        ethane_cli_cachefs_config_schema),
    CYAML_FIELD_MAPPING(
        "sharedfs",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, sharedfs,
        ethane_cli_sharedfs_config_schema),
    CYAML_FIELD_MAPPING(
        "logger",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, logger,
        ethane_cli_logger_config_schema),
    CYAML_FIELD_MAPPING(
        "lock",
        CYAML_FLAG_DEFAULT,
        struct ethane_cli_config, lock,
        ethane_cli_lock_config_schema),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_logd_checkpoint_config_schema[] = {
    CYAML_FIELD_UINT(
        "nr_shards",
        CYAML_FLAG_DEFAULT,
        struct ethane_logd_checkpoint_config, nr_shards),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t ethane_logd_config_schema[] = {
    CYAML_FIELD_MAPPING(
        "checkpoint",
        CYAML_FLAG_DEFAULT,
        struct ethane_logd_config, checkpoint,
        ethane_logd_checkpoint_config_schema),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t ethane_fs_config_value = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ethane_fs_config, ethane_fs_config_schema)
};

static const cyaml_schema_value_t ethane_memd_config_value = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ethane_memd_config, ethane_memd_config_schema)
};

static const cyaml_schema_value_t ethane_cli_config_value = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ethane_cli_config, ethane_cli_config_schema)
};

static const cyaml_schema_value_t ethane_logd_config_value = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ethane_logd_config, ethane_logd_config_schema)
};

ethanefs_fs_config_t *ethanefs_config_parse_fs(const char *yaml_path) {
    ethanefs_fs_config_t *fs_config;
    cyaml_config_t config = {
            .log_level = CYAML_LOG_WARNING,
            .log_fn = cyaml_log,
            .mem_fn = cyaml_mem,
    };
    cyaml_err_t err;

    err = cyaml_load_file(yaml_path, &config, &ethane_fs_config_value, (void **) &fs_config, NULL);
    if (unlikely(err != CYAML_OK)) {
        return ERR_PTR(-EINVAL);
    }

    return fs_config;
}

ethanefs_memd_config_t *ethanefs_config_parse_memd(const char *yaml_path) {
    ethanefs_memd_config_t *memd_config;
    cyaml_config_t config = {
            .log_level = CYAML_LOG_WARNING,
            .log_fn = cyaml_log,
            .mem_fn = cyaml_mem,
    };
    cyaml_err_t err;

    err = cyaml_load_file(yaml_path, &config, &ethane_memd_config_value, (void **) &memd_config, NULL);
    if (unlikely(err != CYAML_OK)) {
        return ERR_PTR(-EINVAL);
    }

    return memd_config;
}

ethanefs_cli_config_t *ethanefs_config_parse_cli(const char *yaml_path) {
    ethanefs_cli_config_t *cli_config;
    cyaml_config_t config = {
            .log_level = CYAML_LOG_WARNING,
            .log_fn = cyaml_log,
            .mem_fn = cyaml_mem,
    };
    cyaml_err_t err;

    err = cyaml_load_file(yaml_path, &config, &ethane_cli_config_value, (void **) &cli_config, NULL);
    if (unlikely(err != CYAML_OK)) {
        return ERR_PTR(-EINVAL);
    }

    return cli_config;
}

ethanefs_logd_config_t *ethanefs_config_parse_logd(const char *yaml_path) {
    ethanefs_logd_config_t *logd_config;
    cyaml_config_t config = {
            .log_level = CYAML_LOG_WARNING,
            .log_fn = cyaml_log,
            .mem_fn = cyaml_mem,
    };
    cyaml_err_t err;

    err = cyaml_load_file(yaml_path, &config, &ethane_logd_config_value, (void **) &logd_config, NULL);
    if (unlikely(err != CYAML_OK)) {
        return ERR_PTR(-EINVAL);
    }

    return logd_config;
}
