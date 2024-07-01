/*
 * ETHANE Tracing Subsystem
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ethane

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "trace.h"

#if !defined(ETHANE_TRACE_H)

#include <stdlib.h>
#include <time.h>

#include "rand.h"

extern __thread unsigned int _trace_seed;

typedef enum {
    TRACE_LOG_OP_APPEND = 0,
    TRACE_LOG_OP_REPLAY = 1
} trace_lop_op_type_t;

typedef enum {
    TRACE_OP_MKDIR = 0,
    TRACE_OP_RMDIR = 1,
    TRACE_OP_CREATE = 2,
    TRACE_OP_UNLINK = 3,
    TRACE_OP_CHMOD = 4,
    TRACE_OP_CHOWN = 5,
    TRACE_OP_WRITE = 6,
    TRACE_OP_READ = 7,
    TRACE_OP_TRUNCATE = 8,
    TRACE_OP_APPEND = 9,
    TRACE_OP_READDIR = 10
} trace_op_class_t;

typedef enum {
    TRACE_KV_OP_PUT = 0,
    TRACE_KV_OP_GET = 1,
    TRACE_KV_OP_UPD = 2
} trace_kv_op_class_t;

static int _trace_rand() {
    if (_trace_seed == -1) {
        _trace_seed = get_rand_seed();
    }
    return rand_r(&_trace_seed) % 1048576;
}

static int _trace_get_prob(const char *env_name) {
    char *env = getenv(env_name);
    if (env == NULL) {
        return 0;
    }
    return atoi(env);
}

#define _trace_prob(provider, name) \
    (_trace_prob_##provider##_##name != -1 \
        ? _trace_prob_##provider##_##name \
        : (_trace_prob_##provider##_##name = _trace_get_prob("trace_prob_" #provider "_" #name)))

#define _trace_active(provider, name) \
    (_trace_prob(provider, name) != 0 && _trace_rand() < _trace_prob(provider, name))

#define tracepoint_sample(provider, name, ...) do { \
    if (_trace_active(provider, name)) { \
        tracepoint(provider, name, __VA_ARGS__); \
    } \
} while (0)

extern int _trace_prob_ethane_log_append;
extern int _trace_prob_ethane_log_op;
extern int _trace_prob_ethane_log_go_read;
extern int _trace_prob_ethane_log_checkpoint;
extern int _trace_prob_ethane_op_latency;
extern int _trace_prob_ethane_throughput;
extern int _trace_prob_ethane_kv_op;
extern int _trace_prob_ethane_kv_put_at;
extern int _trace_prob_ethane_rdma_read;
extern int _trace_prob_ethane_rdma_write;

#endif

#if !defined(ETHANE_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define ETHANE_TRACE_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    ethane,
    log_append,
    TP_ARGS(
        int, cli_id,
        int, nr_cas,
        int, pos,
        int, go_mn,
        int, lo_mn,
        size_t, lo_off,
        long, go_duration,
        long, lo_duration,
        long, duration
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, nr_cas, nr_cas)
        ctf_integer(int, pos, pos)
        ctf_integer(int, go_mn, go_mn)
        ctf_integer(int, lo_mn, lo_mn)
        ctf_integer(size_t, lo_off, lo_off)
        ctf_integer(long, go_duration, go_duration)
        ctf_integer(long, lo_duration, lo_duration)
        ctf_integer(long, duration, duration)
    )
)

TRACEPOINT_EVENT(
    ethane,
    log_checkpoint,
    TP_ARGS(
        int, cli_id,
        int, shard,
        int, nr_logs,
        long, duration
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, shard, shard)
        ctf_integer(int, nr_logs, nr_logs)
        ctf_integer(long, duration, duration)
    )
)

TRACEPOINT_EVENT(
    ethane,
    log_go_read,
    TP_ARGS(
        int, cli_id,
        int, version,
        int, nr_log_ptrs_read,
        size_t, head,
        size_t, tail,
        long, duration
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, version, version)
        ctf_integer(int, nr_log_ptrs_read, nr_log_ptrs_read)
        ctf_integer(size_t, head, head)
        ctf_integer(size_t, tail, tail)
        ctf_integer(long, duration, duration)
    )
)

TRACEPOINT_ENUM(
    ethane,
    log_op_type,
    TP_ENUM_VALUES(
        ctf_enum_value("APPEND", TRACE_LOG_OP_APPEND)
        ctf_enum_value("REPLAY", TRACE_LOG_OP_REPLAY)
    )
)

TRACEPOINT_ENUM(
    ethane,
    op_class,
    TP_ENUM_VALUES(
        ctf_enum_value("MKDIR", TRACE_OP_MKDIR)
        ctf_enum_value("RMDIR", TRACE_OP_RMDIR)
        ctf_enum_value("CREATE", TRACE_OP_CREATE)
        ctf_enum_value("UNLINK", TRACE_OP_UNLINK)
        ctf_enum_value("CHMOD", TRACE_OP_CHMOD)
        ctf_enum_value("CHOWN", TRACE_OP_CHOWN)
        ctf_enum_value("WRITE", TRACE_OP_WRITE)
        ctf_enum_value("READ", TRACE_OP_READ)
        ctf_enum_value("TRUNCATE", TRACE_OP_TRUNCATE)
        ctf_enum_value("APPEND", TRACE_OP_APPEND)
        ctf_enum_value("READDIR", TRACE_OP_READDIR)
    )
)

TRACEPOINT_EVENT(
    ethane,
    log_op,
    TP_ARGS(
        int, cli_id,
        int, log_op_type,
        int, op_class,
        int, log_pos,
        const char *, path
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_enum(ethane, log_op_type, int, log_op_type, log_op_type)
        ctf_enum(ethane, op_class, int, op_class, op_class)
        ctf_integer(int, log_pos, log_pos)
        ctf_string(path, path)
    )
)

TRACEPOINT_EVENT(
    ethane,
    op_latency,
    TP_ARGS(
        int, cli_id,
        int, op_class,
        long, log_insert_duration,
        long, log_replay_duration,
        long, cachefs_duration,
        long, cachefs_prefetch_duration,
        long, duration
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_enum(ethane, op_class, int, op_class, op_class)
        ctf_integer(long, log_insert_duration, log_insert_duration)
        ctf_integer(long, log_replay_duration, log_replay_duration)
        ctf_integer(long, cachefs_duration, cachefs_duration)
        ctf_integer(long, cachefs_prefetch_duration, cachefs_prefetch_duration)
        ctf_integer(long, duration, duration)
    )
)

TRACEPOINT_ENUM(
    ethane,
    kv_op_class,
    TP_ENUM_VALUES(
        ctf_enum_value("PUT", TRACE_KV_OP_PUT)
        ctf_enum_value("GET", TRACE_KV_OP_GET)
        ctf_enum_value("UPD", TRACE_KV_OP_UPD)
    )
)

TRACEPOINT_EVENT(
    ethane,
    kv_op,
    TP_ARGS(
        int, cli_id,
        int, shard,
        int, kv_op_class,
        const char *, key,
        int, pos0,
        int, pos1
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, shard, shard)
        ctf_enum(ethane, kv_op_class, int, kv_op_class, kv_op_class)
        ctf_string(key, key)
        ctf_integer(int, pos0, pos0)
        ctf_integer(int, pos1, pos1)
    )
)

TRACEPOINT_EVENT(
    ethane,
    kv_put_at,
    TP_ARGS(
        int, cli_id,
        int, shard,
        const char *, key,
        int, dst_ht,
        int, dst_pos,
        int, pair_pos
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, shard, shard)
        ctf_string(key, key)
        ctf_integer(int, dst_ht, dst_ht)
        ctf_integer(int, dst_pos, dst_pos)
        ctf_integer(int, pair_pos, pair_pos)
    )
)

TRACEPOINT_EVENT(
    ethane,
    rdma_write,
    TP_ARGS(
        int, cli_id,
        int, dst_mn_id,
        size_t, dst_off,
        unsigned long, src,
        size_t, len,
        const uint8_t *, data
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, dst_mn_id, dst_mn_id)
        ctf_integer(size_t, dst_off, dst_off)
        ctf_integer(unsigned long, src, src)
        ctf_integer(size_t, len, len)
        ctf_sequence(uint8_t, data, data, size_t, len)
    )
)

TRACEPOINT_EVENT(
    ethane,
    rdma_read,
    TP_ARGS(
        int, cli_id,
        int, src_mn_id,
        size_t, src_off,
        unsigned long, dst,
        size_t, len
    ),
    TP_FIELDS(
        ctf_integer(int, cli_id, cli_id)
        ctf_integer(int, src_mn_id, src_mn_id)
        ctf_integer(size_t, src_off, src_off)
        ctf_integer(unsigned long, dst, dst)
        ctf_integer(size_t, len, len)
    )
)

#endif //ETHANE_TRACE_H

#include <lttng/tracepoint-event.h>
