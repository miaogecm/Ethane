#!/bin/bash

CMD="cd ~/DPMFS/cmake-build-debug && export CC=clang-10 && export CXX=clang-10 && rm -r ./* && cmake ../ -DCMAKE_BUILD_TYPE=$* && make -j8"

pssh -h conf/all_nodes.txt -P -i "$CMD"
