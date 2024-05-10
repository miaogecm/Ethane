/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * ETHANE Tracing Subsystem
 *
 * Hohai University
 */

#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE

#include "trace.h"

__thread unsigned int _trace_seed = -1;

int _trace_prob_ethane_log_append = -1;
int _trace_prob_ethane_log_op = -1;
int _trace_prob_ethane_log_go_read = -1;
int _trace_prob_ethane_log_checkpoint = -1;
int _trace_prob_ethane_op_latency = -1;
int _trace_prob_ethane_throughput = -1;
int _trace_prob_ethane_kv_op = -1;
int _trace_prob_ethane_kv_put_at = -1;
int _trace_prob_ethane_rdma_read = -1;
int _trace_prob_ethane_rdma_write = -1;
