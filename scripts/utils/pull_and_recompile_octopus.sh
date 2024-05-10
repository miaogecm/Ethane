#!/bin/bash

echo Press any key to continue pull and recompile...
read -n 1 -s

pssh -h ./conf/all_nodes.txt -P -i "cd ~/DPMFS/evaluation/fs/octopus/cmake-build-debug && git pull && make clean && make -j"
