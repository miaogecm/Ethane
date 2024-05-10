#!/bin/bash

THREADS=$(ps -e -T | grep ethane | awk '{print $2}')
NR_THREADS=$(ps -e -T | grep ethane | awk '{print $2}' | wc -l)
CPU=0
TIDS=""

cset shield -r

cset shield -k on -c 0-$((NR_THREADS-1))

for tid in $THREADS; do
    thread=$(cat /proc/$tid/comm)
    TIDS="$TIDS,$tid"
done
TIDS=${TIDS:1}
echo Moving $TIDS into cset...
cset shield -s --pid $TIDS

echo TOTAL: $NR_THREADS
for tid in $THREADS; do
    thread=$(cat /proc/$tid/comm)
    echo FOUND: $thread[$tid]

    taskset -pc $CPU $tid

    TIDS="$TIDS,$tid"
    CPU=$((CPU+1))
done

echo TOTAL: $NR_THREADS
for tid in $THREADS; do
    thread=$(cat /proc/$tid/comm)
    echo CPU of $thread[$tid]: $(taskset -pc $tid)
done

echo Done.
