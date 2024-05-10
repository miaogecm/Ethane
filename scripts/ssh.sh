#!/bin/bash
# ssh-multi
# D.Kovalov
# Based on http://linuxpixies.blogspot.jp/2011/06/tmux-copy-mode-and-how-to-control.html

# a script to ssh multiple servers over multiple tmux panes


starttmux() {
    if [ -z "$HOSTS" ]; then
       echo -n "Please provide of list of hosts separated by spaces [ENTER]: "
       read HOSTS
    fi

    local hosts=( $HOSTS )

    tmux new-window "ssh -R 6666:127.0.0.1:8889 ${hosts[0]}"
    unset hosts[0];
    for i in "${hosts[@]}"; do
        tmux split-window -h  "ssh -R 6666:127.0.0.1:8889 $i"
        tmux select-layout tiled > /dev/null
    done
    tmux select-pane -t 0
    tmux set-window-option synchronize-panes on > /dev/null

    tmux send-keys "ulimit -c unlimited" ENTER
}

if [ -z "$1" ]; then
    HOSTS=$(cat conf/all_nodes.txt)
else
    HOSTS=$1
fi

starttmux
