#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

ETHANE_DIR=$(pwd)/..
TMP_DIR=$ETHANE_DIR/scripts/tmp

mkdir -p $TMP_DIR

cd $TMP_DIR || exit

echo Installing MLNX OFED drivers...

wget https://content.mellanox.com/ofed/MLNX_OFED-4.9-5.1.0.0/MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu18.04-x86_64.tgz
tar -xvf MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu18.04-x86_64.tgz
cd MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu18.04-x86_64 || exit

./mlnxofedinstall  --force
/etc/init.d/openibd restart
/etc/init.d/opensmd restart

echo Installing Libraries...

apt-get install -y gcc g++ emacs vim cmake tmux zsh cpufrequtils msr-tools cpuset numactl \
                   linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
                   zookeeper libzookeeper-mt-dev \
                   lttng-tools lttng-modules-dkms babeltrace liblttng-ust-dev \
                   libyaml-dev

git clone https://github.com/tlsa/libcyaml.git
cd libcyaml || exit
export PREFIX=/usr
make && make install VARIANT=release

modprobe msr

echo /proj/dpmfs-PG0/core > /proc/sys/kernel/core_pattern

echo Building Ethane...

cd $ETHANE_DIR || exit

git submodule update --init --recursive

mkdir -p cmake-build-debug
cd cmake-build-debug || exit

cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j

echo Setting up zsh...

cd $ETHANE_DIR/scripts

sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

cp ./zshrc ~/.zshrc

chsh -s $(which zsh)

echo Cleaning up...

rm -rf $TMP_DIR
