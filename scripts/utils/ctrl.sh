#!/bin/bash

# usage:
# toggle_debug.sh logd/memd/... signal

if [ $# -ne 2 ]; then
    echo "usage: $0 logd/memd/... signal"
    exit 1
fi

pssh -h ./conf/all_nodes.txt -i "kill -$2 \$(pidof $1)"
