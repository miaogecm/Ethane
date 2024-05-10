/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Logger Daemon (logd)
 * (1) Log checkpointing
 * (2) Log global order array fetching
 *
 * Hohai University
 */

#define _GNU_SOURCE

#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "ethanefs.h"
#include "ethane.h"
#include "debug.h"

#include "third_party/argparse/argparse.h"

static ethanefs_cli_t *chkpt_worker_clis[MAX_NR_CLIS];
static int nr_chkpt_workers;

static ethanefs_cli_t *create_cli(ethanefs_t *fs, const char *cli_conf_path) {
    ethanefs_cli_config_t *config;
    ethanefs_cli_t *cli;

    config = ethanefs_config_parse_cli(cli_conf_path);
    if (unlikely(IS_ERR(config))) {
        pr_err("failed to parse client config file: %s\n",
               strerror((int) -PTR_ERR(config)));
        exit(-1);
    }

    cli = ethanefs_cli_init(fs, config);
    if (unlikely(IS_ERR(cli))) {
        pr_err("failed to initialize client: %s\n",
               strerror((int) -PTR_ERR(cli)));
        exit(-1);
    }

    /* TODO: set user */
    ethanefs_set_user(cli, 0, 0);

    return cli;
}

static inline void start_chkpt_loop(ethanefs_cli_t *cli, const char *logd_conf_path) {
    ethanefs_logd_config_t *config;

    config = ethanefs_config_parse_logd(logd_conf_path);
    if (unlikely(IS_ERR(config))) {
        pr_err("failed to parse logd config file: %s\n",
               strerror((int) -PTR_ERR(config)));
        exit(-1);
    }

    ethanefs_checkpoint_loop(cli, config);
}

struct chkpt_arg {
    ethanefs_t *fs;
    const char *cli_conf_path;
    const char *logd_conf_path;
    int id;
};

static void *chkpt_worker(void *arg) {
    struct chkpt_arg *chkpt_arg = arg;
    ethanefs_cli_t *cli;
    char name[64];

    cli = create_cli(chkpt_arg->fs, chkpt_arg->cli_conf_path);

    chkpt_worker_clis[chkpt_arg->id] = cli;

    sprintf(name, "ethane-ck-%d", ethanefs_get_cli_id(cli));
    pthread_setname_np(pthread_self(), name);

    start_chkpt_loop(cli, chkpt_arg->logd_conf_path);

    return NULL;
}

static void dump_chkpt_cli(int signo) {
    int i;
    for (i = 0; i < nr_chkpt_workers; i++) {
        if (!chkpt_worker_clis[i]) {
            return;
        }
        pr_emph("dump chkpt cli %d", ethanefs_get_cli_id(chkpt_worker_clis[i]));
        ethanefs_dump_cli(chkpt_worker_clis[i]);
    }
}

/* create chkpt workers */
static void launch_chkpt_clis(ethanefs_t *fs, const char *cli_conf_path, const char *logd_conf_path, int nr_clis) {
    struct chkpt_arg *args;
    pthread_t *workers;
    int i;

    workers = malloc(sizeof(pthread_t) * nr_clis);
    if (unlikely(!workers)) {
        pr_err("failed to allocate memory for workers\n");
        exit(-1);
    }

    args = malloc(sizeof(struct chkpt_arg) * nr_clis);
    if (unlikely(!args)) {
        pr_err("failed to allocate memory for workers\n");
        exit(-1);
    }

    for (i = 0; i < nr_clis; i++) {
        args[i].id = i;
        args[i].fs = fs;
        args[i].cli_conf_path = cli_conf_path;
        args[i].logd_conf_path = logd_conf_path;

        pthread_create(&workers[i], NULL, chkpt_worker, &args[i]);
    }

    nr_chkpt_workers = nr_clis;
}

struct go_arg {
    ethanefs_t *fs;
    const char *cli_conf_path;
    ethanefs_logd_config_t *logd_conf;
};

static void *go_fetcher_worker(void *arg) {
    struct go_arg *go_arg = arg;
    ethanefs_cli_t *cli;

    pthread_setname_np(pthread_self(), "ethane-go");

    cli = create_cli(go_arg->fs, go_arg->cli_conf_path);

    ethanefs_logger_cache_fetcher_loop(cli, go_arg->logd_conf);

    //return NULL;
}

static void launch_go_fetcher(ethanefs_t *fs, const char *cli_conf_path, const char *logd_conf_path) {
    struct go_arg *arg;
    pthread_t worker;

    arg = malloc(sizeof(struct go_arg));
    if (unlikely(!arg)) {
        pr_err("failed to allocate memory for workers\n");
        exit(-1);
    }

    arg->fs = fs;
    arg->cli_conf_path = cli_conf_path;

    arg->logd_conf = ethanefs_config_parse_logd(logd_conf_path);
    if (unlikely(IS_ERR(arg->logd_conf))) {
        pr_err("failed to parse logd config file: %s\n",
               strerror((int) -PTR_ERR(arg->logd_conf)));
        exit(-1);
    }

    pthread_create(&worker, NULL, go_fetcher_worker, arg);
}

int main(int argc, const char **argv) {
    const char *zookeeper_ip = "localhost:2181";
    const char *logd_config_path = NULL;
    const char *cli_config_path = NULL;
    int start_go_fetcher = true;
    int nr_chkpt_clis = 4;
    ethanefs_t *fs;
    zhandle_t *zh;

    struct argparse_option options[] = {
        OPT_HELP(),

        OPT_STRING('t', "cli-conf", &cli_config_path, "path to client config file"),
        OPT_STRING('c', "logd-conf", &logd_config_path, "path to logd config file"),
        OPT_STRING('z', "zookeeper-ip", &zookeeper_ip, "zookeeper server ip (and port)"),

        OPT_GROUP("Checkpointer options"),
        OPT_INTEGER('n', "nr-clis", &nr_chkpt_clis, "number of checkpointing clients"),

        OPT_GROUP("Global order array fetching options"),
        OPT_BOOLEAN('g', "go-fetcher", &start_go_fetcher, "start global order array fetching"),

        OPT_END(),
    };
    struct argparse argparse;

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nlogd", "\nLog Daemon (logd) for ETHANE");
    argparse_parse(&argparse, argc, argv);

    if (unlikely(!cli_config_path)) {
        pr_err("client config file not specified");
        return -1;
    }

    if (unlikely(!logd_config_path)) {
        pr_err("logd config file not specified");
        return -1;
    }

    zoo_set_debug_level(0);

    zh = zookeeper_init(zookeeper_ip, NULL, 100000, NULL, NULL, 0);
    if (unlikely(!zh)) {
        pr_err("failed to connect to ZooKeeper server\n");
        return -1;
    }

    reg_debug_sig_handler();

    fs = ethanefs_init(zh, 0);

    if (nr_chkpt_clis) {
        signal(SIGUSR1, dump_chkpt_cli);
        pr_info("registered dump chkpt cli sighandler (SIGUSR1)");

        launch_chkpt_clis(fs, cli_config_path, logd_config_path, nr_chkpt_clis);
    }

    if (start_go_fetcher) {
        launch_go_fetcher(fs, cli_config_path, logd_config_path);
    }

    /* TODO: wait for all threads to exit */
    for (;;);
}
