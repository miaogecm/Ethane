#!/bin/bash

TRACE_PATH=/root/dpmfs_trace

trap 'echo "Killing $PIDS..."; kill $PIDS; exit' SIGINT

source utils/common.sh

cluster_init

# make preparations
for node in $(cat conf/all_nodes.txt); do
  ssh $node stdbuf -oL /bin/bash << EOF &
cd ~/DPMFS/scripts
modprobe msr
./utils/disable_ht.sh
./utils/change_turbo.sh disable
./utils/raise_cpufreq.sh
../cmake-build-debug/ddio
lttng destroy --all --no-wait
mkdir -p $TRACE_PATH
rm -rf ${TRACE_PATH:?}/trace
lttng create dpmfs_trace --output=$TRACE_PATH/trace
lttng enable-event -u ethane:rdma_write
lttng enable-event -u ethane:rdma_read
lttng start
EOF
done
wait
pr_info "preparations done"

# start memory daemons (node0,node1,node3,node4), node4 should be the last one
cluster_clear_ready
for node in node0 node1 node3; do
  ssh -tt $node PS1='' stdbuf -oL /bin/bash << EOF &
cd ~/DPMFS/scripts
../cmake-build-debug/memd -z 10.0.2.140:2181 -c conf/memd.yaml
EOF
  PIDS="$PIDS $!"
done
cluster_wait_ready 3
ssh -tt node4 PS1='' stdbuf -oL /bin/bash << EOF &
cd ~/DPMFS/scripts
../cmake-build-debug/memd -z 10.0.2.140:2181 -c conf/memd.yaml
EOF
  PIDS="$PIDS $!"
cluster_wait_ready 4
pr_info "mn init done"

# format FS
../cmake-build-debug/format -z 10.0.2.140:2181 -t conf/fs.yaml
pr_info "fs format done"

# start log daemons
for node in $(cat conf/compute_nodes.txt); do
  if [ "$node" != "node3" ]; then
    NR_CHKPTS=0
  else
    NR_CHKPTS=0
  fi
  ssh -tt $node PS1='' stdbuf -oL /bin/bash << EOF &
rm -rf /dev/shm/ethane-log
cd ~/DPMFS/scripts
#export trace_prob_ethane_rdma_write=1048576
../cmake-build-debug/logd -z 10.0.2.140:2181 -c conf/logd.yaml -t conf/logd_cli.yaml -n $NR_CHKPTS -g true
EOF
  PIDS="$PIDS $!"
done

pr_info "ethanefs init done"

wait
