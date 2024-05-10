#!/bin/bash

ZK_CLI="/usr/share/zookeeper/bin/zkCli.sh"

pr_info() {
  echo -e "\e[32m$1\e[0m"
}

pr_err() {
  echo -e "\e[31m$1\e[0m"
}

pr_warn() {
  echo -e "\e[33m$1\e[0m"
}

cluster_init() {
  $ZK_CLI <<EOF > /dev/null
rmr /dmpool
rmr /dmpool
rmr /ethane_ctl
rmr /ethane_ctl

create /dmpool ""
create /dmpool/clients ""
create /dmpool/memory_nodes ""
create /dmpool/compute_nodes ""
create /dmpool/checkpoint_clis ""

create /ethane_ctl ""
create /ethane_ctl/ready ""
EOF

  pr_info "zk init done"
}

cluster_enable() {
  $ZK_CLI create /ethane_ctl/enable "" > /dev/null
  pr_info "cluster enabled"
}

cluster_disable() {
  $ZK_CLI delete /ethane_ctl/enable > /dev/null
  pr_info "cluster disabled"
}

cluster_clear_ready() {
  $ZK_CLI <<EOF > /dev/null
rmr /ethane_ctl/ready
create /ethane_ctl/ready ""
EOF
}

cluster_wait_ready() {
  id=$(printf "%010d" $(($1-1)))
  while [ ! -n "$($ZK_CLI get /ethane_ctl/ready/ready$id 2>&1 | grep ctime)" ]; do
    sleep 1
  done
}
