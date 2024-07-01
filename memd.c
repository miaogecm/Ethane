/*
 * Copyright 2023 Regents of Nanjing University of Aeronautics and Astronautics and 
 * Hohai University, Miao Cai <miaocai@nuaa.edu.cn> and Junru Shen <jrshen@hhu.edu.cn>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Memory Daemon (memd) Running at Memory Node
 */

#define _GNU_SOURCE

#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <unistd.h>

#include "ethanefs.h"
#include "ethane.h"
#include "debug.h"

#include "third_party/argparse/argparse.h"

int main(int argc, const char **argv) {
    const char *zookeeper_ip = "localhost:2181";
    const char *memd_config_path = NULL;
    ethanefs_memd_config_t *config;
    zhandle_t *zh;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('z', "zookeeper", &zookeeper_ip, "ZooKeeper server IP address and port"),
        OPT_STRING('c', "config", &memd_config_path, "Memory Daemon (memd) config file path"),
        OPT_END(),
    };
    struct argparse argparse;

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nmemd", "\nMemory Daemon (memd) for ETHANE");
    argparse_parse(&argparse, argc, argv);

    if (unlikely(!memd_config_path)) {
        pr_err("memd config file not specified");
        return -1;
    }

    zoo_set_debug_level(0);

    zh = zookeeper_init(zookeeper_ip, NULL, 100000, NULL, NULL, 0);
    if (unlikely(!zh)) {
        pr_err("failed to connect to ZooKeeper server");
        return -1;
    }

    config = ethanefs_config_parse_memd(memd_config_path);
    if (unlikely(IS_ERR(config))) {
        pr_err("failed to parse memd config file");
        return -1;
    }

    pthread_setname_np(pthread_self(), "ethane-md");

    reg_debug_sig_handler();

    ethanefs_mem_daemon(zh, config);
}
