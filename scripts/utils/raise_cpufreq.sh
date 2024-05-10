#!/bin/bash

source utils/common.sh

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
systemctl stop ondemand
systemctl restart cpufrequtils

cpupower idle-set --disable-by-latency 0 > /dev/null

pr_info "[$(hostname)] cpu freq raised"
