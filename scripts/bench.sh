#!/bin/bash

TRACE_PATH=/root/dpmfs_trace

NR_THREADS=1
NR_COROS_PER_THREAD=1
NR_CLIS=$(($NR_THREADS * $NR_COROS_PER_THREAD))

trap 'echo "Killing $PIDS..."; kill $PIDS; exit' SIGINT

source utils/common.sh

cluster_clear_ready
for node in $(cat conf/compute_nodes.txt); do
  ssh -tt $node PS1='' stdbuf -oL /bin/bash << EOF &
cd ~/DPMFS/scripts
../cmake-build-debug/launch -t conf/cli.yaml -z 10.0.2.140:2181 -n $NR_THREADS -c $NR_COROS_PER_THREAD -l ../cmake-build-debug/libbench.so
EOF
  PIDS="$PIDS $!"
done
cluster_wait_ready $NR_CLIS

cluster_enable

wait
