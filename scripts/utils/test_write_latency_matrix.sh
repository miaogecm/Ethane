#!/bin/bash

# Test write latency matrix

NODES=(
    "(node0 192.168.1.1)"
    "(node1 192.168.1.2)"
    "(node2 192.168.1.3)"
    "(node3 192.168.1.4)"
)

DEV=mlx5_2

for ((i=0; i<${#NODES[@]}; i++)); do
    for ((j=0; j<${#NODES[@]}; j++)); do
        if [ $i -ne $j ]; then
            eval "a1=${NODES[$i]}"
            eval "a2=${NODES[$j]}"

            # j as server, i as client
            ssh ${a2[0]} "ib_write_lat -d ${DEV} > /dev/null" &
            output=$(ssh ${a1[0]} "sleep 10 && ib_write_lat -d ${DEV} ${a2[1]}")

            # get latency
            latency=$(echo "$output" | awk 'BEGIN{header=0}{if ($6 == "t_avg[usec]") {header=1;} else if (header==1) {print $6;exit}}')

            echo "Write latency from ${a1[0]} to ${a2[0]}: $latency us"
        fi
    done
done
