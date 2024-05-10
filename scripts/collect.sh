#!/bin/bash

source utils/common.sh

TRACE_PATH=/root/dpmfs_trace

pr_info "stopping trace"
pssh -h conf/all_nodes.txt -i "lttng destroy --all"

pr_info "compressing trace"
pssh -h conf/all_nodes.txt -i "cd $TRACE_PATH && tar -czf trace.tar.gz trace"

pr_info "downloading traces"
mkdir -p ./traces
rm -rf ./traces/*
for node in $(cat conf/all_nodes.txt); do
  scp $node:$TRACE_PATH/trace.tar.gz ./traces/$node.tar.gz &
done
wait

pr_info "decompressing traces"
for node in $(cat conf/all_nodes.txt); do
    echo Decompressing trace data from $node...
    mkdir -p ./traces/$node
    (tar -xzf ./traces/$node.tar.gz -C ./traces/$node; rm ./traces/$node.tar.gz) &
done
wait

pr_info "collect trace done"
