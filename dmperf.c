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
 * Profiling Remote Memory Access
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

#include "ethane.h"
#include "ethanefs.h"
#include "debug.h"
#include "bench.h"
#include "rand.h"
#include "dmpool.h"
#include "third_party/argparse/argparse.h"

struct worker_arg {
    dmpool_t *pool;
    zhandle_t *zh;
    int id;
};

static void *run_dmperf(void *arg) {
    struct worker_arg *warg = arg;
    dmpool_t *pool = warg->pool;
    int ret, i, repeat = 100000;
    struct bench_timer time;
    unsigned long elapsed;
    char *src, name[64];
    dmcontext_t *ctx;
    unsigned seed;

    seed = get_rand_seed();

    sprintf(name, "ethane-pf-%d", warg->id);
    pthread_setname_np(pthread_self(), name);

    ethanefs_wait_enable(warg->zh);

    ctx = dm_create_context(pool, 1024 * 1024);
    if (unlikely(IS_ERR(ctx))) {
        pr_err("failed to create context: %s", strerror((int) -PTR_ERR(ctx)));
        exit(-1);
    }

    src = dm_push(ctx, NULL, 4096);

    elapsed = 0;

    for (i = 0; i < repeat; i++) {
#if 1
        ret = dm_cas(ctx, DMPTR_MK_PM(3, 4096), src, src, 8, DMFLAG_ACK);
        if (unlikely(ret)) {
            pr_err("failed to copy data to remote: %s", strerror(ret));
            exit(-1);
        }
#endif

#if 0
        ret = dm_copy_to_remote(ctx, DMPTR_MK_PM(0, 4096), src, i == 0 ? 4096 : 64, 0);
        if (unlikely(ret)) {
            pr_err("failed to copy data to remote: %s",
                   strerror(ret));
            exit(-1);
        }

        dm_mark(ctx);
        ret = dm_flush(ctx, DMPTR_MK_PM(0, 4096), DMFLAG_ACK);
        dm_pop(ctx);
#endif

        bench_timer_start(&time);

        ret = dm_wait_ack(ctx, 1);
        if (unlikely(ret)) {
            pr_err("failed to wait for ack: %s",
                   strerror(ret));
            exit(-1);
        }

        elapsed += bench_timer_end(&time);
    }
    printf("avg.elapsed: %lu ns", elapsed / repeat);

    return NULL;
}

int main(int argc, const char *argv[]) {
    const char *zookeeper_host = "localhost:2181";
    struct worker_arg *wargs;
    int nr_workers = 1, i;
    dmpool_t *pool;
    zhandle_t *zh;

    struct argparse_option options[] = {
        OPT_HELP(),

        OPT_STRING('z', "zookeeper-host", &zookeeper_host, "zookeeper server host (IP and port)"),
        OPT_INTEGER('w', "nr-workers", &nr_workers, "number of workers"),

        OPT_END(),
    };
    struct argparse argparse;

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nlogd", "\ndmperf");
    argparse_parse(&argparse, argc, argv);

    zoo_set_debug_level(0);

    zh = zookeeper_init(zookeeper_host, NULL, 100000, NULL, NULL, 0);
    if (unlikely(!zh)) {
        pr_err("failed to connect to ZooKeeper server");
        return -1;
    }

    pool = dm_init(zh);
    if (unlikely(IS_ERR(pool))) {
        pr_err("failed to initialize memory pool: %s",
               strerror((int) -PTR_ERR(pool)));
        exit(-1);
    }

    wargs = malloc(sizeof(struct worker_arg) * nr_workers);

    for (i = 0; i < nr_workers; i++) {
        pthread_t tid;

        wargs[i].pool = pool;
        wargs[i].zh = zh;
        wargs[i].id = i;

        pthread_create(&tid, NULL, run_dmperf, &wargs[i]);
    }

    for (;;);
}
