#!/bin/bash

source ./ssh.sh "$(cat all_nodes.txt)"

tmux rename-window "dmfs"
tmux send-keys "cd ~/DPMFS/evaluation/fs/octopus/cmake-build-debug && ./dmfs" ENTER
