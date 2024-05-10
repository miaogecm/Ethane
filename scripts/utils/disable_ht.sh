#!/bin/bash

source utils/common.sh

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo off > /sys/devices/system/cpu/smt/control
pr_info "[$(hostname)] ht disabled"
