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
 * An easy-to-use FS launcher
 */

#define _GNU_SOURCE

#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <asm/unistd_64.h>

#include "ethanefs.h"
#include "ethane.h"
#include "bench.h"
#include "debug.h"
#include "coro.h"

#include "third_party/argparse/argparse.h"

#define STARTUP_SEC     16

typedef void (*worker_fn_t)(ethanefs_cli_t *cli);

static worker_fn_t get_worker_fn(const char *library_path) {
    void *handle;
    worker_fn_t worker_fn;

    handle = dlopen(library_path, RTLD_LAZY);
    if (unlikely(!handle)) {
        pr_err("failed to load worker library: %s", dlerror());
        exit(-1);
    }

    worker_fn = dlsym(handle, "worker_fn");
    if (unlikely(!worker_fn)) {
        pr_err("failed to load worker function: %s", dlerror());
        exit(-1);
    }

    return worker_fn;
}

static ethanefs_cli_t *create_cli(ethanefs_t *fs, const char *cli_conf_path, unsigned uid, unsigned gid) {
    ethanefs_cli_config_t *config;
    ethanefs_cli_t *cli;

    config = ethanefs_config_parse_cli(cli_conf_path);
    if (unlikely(IS_ERR(config))) {
        pr_err("failed to parse client config file: %s",
               strerror((int) -PTR_ERR(config)));
        exit(-1);
    }

    cli = ethanefs_cli_init(fs, config);
    if (unlikely(IS_ERR(cli))) {
        pr_err("failed to initialize client: %s",
               strerror((int) -PTR_ERR(cli)));
        exit(-1);
    }

    ethanefs_set_user(cli, uid, gid);

    return cli;
}

struct run_arg {
    ethanefs_t *fs;
    const char *cli_conf_path;
    unsigned uid, gid;
    worker_fn_t fn;
    int nr_coros;
    zhandle_t *zh;
};

static void *run_worker(void *arg) {
    struct run_arg *run_arg = arg;
    ethanefs_cli_t **clis;
    char thr_name[64];
    int i;

    coro_thread_init();

    clis = malloc(sizeof(ethanefs_cli_t *) * run_arg->nr_coros);
    if (unlikely(!clis)) {
        pr_err("failed to allocate memory for clients");
        exit(-1);
    }

    for (i = 0; i < run_arg->nr_coros; i++) {
        pr_info("%ld: Creating client %d..", syscall(__NR_gettid), i);
        clis[i] = create_cli(run_arg->fs, run_arg->cli_conf_path, run_arg->uid, run_arg->gid);
    }

    sprintf(thr_name, "ethane-wk-%d", ethanefs_get_cli_id(clis[0]));

    pthread_setname_np(pthread_self(), thr_name);

    ethanefs_post_ready(run_arg->zh);
    ethanefs_wait_enable(run_arg->zh);

    for (i = 0; i < run_arg->nr_coros; i++) {
        coro_create(run_arg->fn, clis[i]);
    }

    coro_sched();

    return NULL;
}

/* create client workers */
static void launch_clis(ethanefs_t *fs, zhandle_t *zh, const char *cli_conf_path, int nr_workers, int nr_coros,
                        unsigned uid, unsigned gid, worker_fn_t fn) {
    struct run_arg *args;
    pthread_t *workers;
    int i;

    workers = malloc(sizeof(pthread_t) * nr_workers);
    if (unlikely(!workers)) {
        pr_err("failed to allocate memory for workers");
        exit(-1);
    }

    args = malloc(sizeof(struct run_arg) * nr_workers);
    if (unlikely(!args)) {
        pr_err("failed to allocate memory for workers");
        exit(-1);
    }

    for (i = 0; i < nr_workers; i++) {
        args[i].fs = fs;
        args[i].cli_conf_path = cli_conf_path;
        args[i].uid = uid;
        args[i].gid = gid;
        args[i].fn = fn;
        args[i].nr_coros = nr_coros;
        args[i].zh = zh;

        pthread_create(&workers[i], NULL, run_worker, &args[i]);
    }

    for (i = 0; i < nr_workers; i++) {
        pthread_join(workers[i], NULL);
    }
}

int main(int argc, const char **argv) {
    const char *zookeeper_ip = "localhost:2181";
    const char *cli_config_path = NULL;
    int nr_workers = 4, nr_coros = 4;
    const char *library_path = NULL;
    unsigned uid = 0, gid = 0;
    worker_fn_t fn;
    ethanefs_t *fs;
    zhandle_t *zh;

    struct argparse_option options[] = {
        OPT_HELP(),

        OPT_STRING('t', "cli-conf", &cli_config_path, "path to client config file"),
        OPT_STRING('z', "zookeeper-ip", &zookeeper_ip, "zookeeper server ip (and port)"),
        OPT_INTEGER('n', "nr-workers", &nr_workers, "number of worker threads"),
        OPT_INTEGER('c', "nr-coros", &nr_coros, "number of coroutines per worker thread"),
        OPT_INTEGER('u', "uid", &uid, "user id"),
        OPT_INTEGER('g', "gid", &gid, "group id"),
        OPT_STRING('l', "lib", &library_path, "worker library path"),

        OPT_END(),
    };
    struct argparse argparse;

    bench_timer_init_freq();

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nlogd", "\nETHANE Launcher");
    argparse_parse(&argparse, argc, argv);

    if (unlikely(!cli_config_path)) {
        pr_err("client config file not specified");
        return -1;
    }

    if (unlikely(!library_path)) {
        pr_err("worker library not specified");
        return -1;
    }

    fn = get_worker_fn(library_path);

    zoo_set_debug_level(0);

    zh = zookeeper_init(zookeeper_ip, NULL, 100000, NULL, NULL, 0);
    if (unlikely(!zh)) {
        pr_err("failed to connect to ZooKeeper server");
        return -1;
    }

    reg_debug_sig_handler();

    fs = ethanefs_init(zh, 8080);

    launch_clis(fs, zh, cli_config_path, nr_workers, nr_coros, uid, gid, fn);

    return 0;
}
