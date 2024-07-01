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
 * ETHANE Tracing Subsystem
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
