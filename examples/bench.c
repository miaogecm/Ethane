#include <coro.h>
#include <dmpool.h>
#include <syscall.h>
#include <unistd.h>

#include "ethanefs.h"
#include "bench.h"

#include <debug.h>

#include "examples/random.h"
#include "rand.h"
#include "ethane.h"

#define SHOW_THROUGHPUT_INTERVAL         10

#define DELAY_US   0

#define K 224

#define SET_WORKER_FN(fn)      void worker_fn(ethanefs_cli_t *) __attribute__((alias(#fn)))

static void inject_throttling_delay(long delay_us) {
    struct bench_timer timer;
    if (delay_us == 0) {
        return;
    }
    bench_timer_start(&timer);
    while (bench_timer_end(&timer) < delay_us * 1000) {
        coro_yield();
    }
}

static void mkdir_recur(ethanefs_cli_t *cli, const char *path, bool verbose, bool force) {
    char buf[256];
    char *p, *q;
    int ret;

    strcpy(buf, path);
    p = buf;
    while ((q = strchr(p + 1, '/')) != NULL) {
        *q = '\0';
        ret = ethanefs_mkdir(cli, buf, 0777);
        if (ret && force) {
            pr_err("mkdir %s failed: %s", buf, strerror(-ret));
            exit(1);
        }
        if (verbose) {
            pr_info("mkdir %s done: %s", buf, strerror(-ret));
        }
        *q = '/';
        p = q;
    }
}

static void bench_private(ethanefs_cli_t *cli) {
    struct bench_timer timer;
    long elapsed_ns = 0;
    unsigned int seed;
    char path[256];
    int i, ret, id;

    seed = get_rand_seed();

    id = ethanefs_get_cli_id(cli);

    sprintf(path, "/ethane-%d", id);
    ret = ethanefs_mkdir(cli, path, 0777);
    if (ret) {
        printf("%d: create failed: %d\n", id, ret);
        exit(1);
    }

    bench_timer_start(&timer);

    for (i = 0; i < 160000; i++) {
        inject_throttling_delay(DELAY_US);

        sprintf(path, "/ethane-%d/dir-%d", id, i);
        ret = ethanefs_mkdir(cli, path, 0666);
        if (ret) {
            printf("%d: create failed: %d\n", id, ret);
            exit(1);
        }

        if ((i + 1) % SHOW_THROUGHPUT_INTERVAL == 0) {
            elapsed_ns += bench_timer_end(&timer);
            printf("%d: %lu op/s (%d)\n", id, (i + 1) * 1000000000L / elapsed_ns, i + 1);
            bench_timer_start(&timer);
        }
    }

    printf("%d: done\n", id);
}

static void bench_path_walk(ethanefs_cli_t *cli) {
    const char *target = "/linux/tools/testing/selftests/rcutorture/formal/srcu-cbmc/empty_includes/uapi/linux";
    if (!strcmp(ethanefs_get_hostname(), "node140")) {
        mkdir_recur(cli, target, true,true);
        ethanefs_dump_cli(cli);
        sleep(10);
        ethanefs_dump_remote(cli);
    }
    ethanefs_force_checkpoint(cli);
}

static void bench_skewed_path_walk(ethanefs_cli_t *cli) {
    struct bench_timer timer;
    long id, elapsed_ns;
    struct stat buf;
    char path[256];
    int i, ret;
    int err = 0;

    init_seed();

    init_zipf_generator(0, 10000);

    elapsed_ns = 0;

    bench_timer_start(&timer);

    for (i = 0; ; i++) {
        //id = zipf_next() % 200000;
        id = uniform_next() % 200000;

        sprintf(path, "/a/f%06ld/a1/a2/a3/a4/a5/a6/a7/a8", id);
        ret = ethanefs_getattr(cli, path, &buf);
        if (ret) {
            //pr_err("%d: stat failed: %d (%s)", ethanefs_get_cli_id(cli), ret, path);
            err++;
        }

        if ((i + 1) % SHOW_THROUGHPUT_INTERVAL == 0) {
            elapsed_ns += bench_timer_end(&timer);
            pr_info("%lu op/s (%d) err=%d", (i + 1) * 1000000000L / elapsed_ns, i + 1, err);
            bench_timer_start(&timer);
        }
    }
}

static void bench_io_write(ethanefs_cli_t *cli) {
    const int nr_ios = 2560;

    ethanefs_open_file_t *fh;
    struct bench_timer timer;
    long elapsed_ns;
    char path[256];
    void *buf;
    long ret;
    int i;

    elapsed_ns = 0;

    bench_timer_start(&timer);

    buf = malloc(IO_SIZE);
    strcpy(buf, "teststring");

    sprintf(path, "/cli-%d", ethanefs_get_cli_id(cli));
    fh = ethanefs_create(cli, path, 0777);
    ethane_assert(!IS_ERR(fh));
    ret = ethanefs_truncate(cli, fh, IO_SIZE);
    ethane_assert(!ret);

    pr_info("bench_io: use IO size: %lu, file: %s, nr_ios: %d", IO_SIZE, path, nr_ios);

    for (i = 0; i < nr_ios; i++) {
        ret = ethanefs_write(cli, fh, buf, IO_SIZE, 0);
        ethane_assert(ret == IO_SIZE);

        if ((i + 1) % SHOW_THROUGHPUT_INTERVAL == 0) {
            elapsed_ns += bench_timer_end(&timer);
            pr_info("%lu IOPS (%d)", (i + 1) * 1000000000L / elapsed_ns, i + 1);
            bench_timer_start(&timer);
        }
    }
}

static void bench_io_read(ethanefs_cli_t *cli) {
    const int nr_ios = 1048576;

    ethanefs_open_file_t *fh;
    struct bench_timer timer;
    long elapsed_ns;
    char path[256];
    void *buf;
    long ret;
    int i;

    elapsed_ns = 0;

    bench_timer_start(&timer);

    buf = malloc(IO_SIZE * nr_ios);
    strcpy(buf, "teststring");

    sprintf(path, "/a");
    fh = ethanefs_open(cli, path);
    ethane_assert(!IS_ERR(fh));

    pr_info("bench_io: use IO size: %lu, file: %s, nr_ios: %d", IO_SIZE, path, nr_ios);

    for (i = 0; i < nr_ios; i++) {
        ret = ethanefs_read(cli, fh, buf, IO_SIZE, i * IO_SIZE);
        if (!ret) {
            pr_err("ret err: %s", strerror(-ret));
        }

        if ((i + 1) % SHOW_THROUGHPUT_INTERVAL == 0) {
            elapsed_ns += bench_timer_end(&timer);
            pr_info("%lu IOPS (%d)", (i + 1) * 1000000000L / elapsed_ns, i + 1);
            bench_timer_start(&timer);
        }
    }
}

static void bench_path_walk_lat(ethanefs_cli_t *cli) {
    //const char *target = "/linux/tools/testing/selftests/rcutorture/formal/srcu-cbmc/empty_includes/uapi/linux";
    const char *target = "/linux/tools";
    struct bench_timer timer;
    long elapsed_ns;
    struct stat buf;
    int cnt = 0;
    bench_timer_start(&timer);
    mkdir_recur(cli, target, true,false);
    while (true) {
        cnt++;
        ethanefs_test_remote_path_walk(cli, target);
        elapsed_ns = bench_timer_end(&timer);
        if (elapsed_ns > 3000000000ul) {
            printf("%lu IOPS\n", cnt * 1000000000ul / elapsed_ns);
            bench_timer_start(&timer);
            cnt = 0;
        }
    }
}

SET_WORKER_FN(bench_private);
