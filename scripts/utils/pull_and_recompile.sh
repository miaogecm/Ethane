#!/bin/bash

echo Press any key to continue pull and recompile...
read -n 1 -s

pssh -h ./conf/all_nodes.txt "cd ~/DPMFS/cmake-build-debug && git pull thu master && make -j"
