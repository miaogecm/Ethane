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
 * Ethane shell
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

static void parse_cmds(ethanefs_cli_t **clis, FILE *in, FILE *out, bool verbose) {
    char cmd[256], path[1024], data[IO_SIZE];
    ethanefs_open_file_t *fh;
    ethanefs_cli_t *cli;
    int use_cli = 0;
    size_t size;
    long ret;

    for (;;) {
        cli = clis[use_cli];

        if (verbose) {
            printf("eshell> ");
            fflush(stdout);
        }

        if (fscanf(in, "%s", cmd) == EOF) {
            break;
        }

        if (strcmp(cmd, "exit") == 0) {
            printf("bye\n");
            break;
        }

        if (strcmp(cmd, "help") == 0) {
            printf("exit\thelp\tmkdir\tcreate\n");
            printf("trunc\tdump\trmdir\trm\n");
            printf("access\twrite\tread\tflush\n");
            printf("stat\tswitch\tcd\tpwd\n");
            printf("debug");
            continue;
        }

        if (strcmp(cmd, "mkdir") == 0) {
            fscanf(in, "%s", path);
            ret = ethanefs_mkdir(cli, path, 0755);
            if (ret || verbose) {
                printf("mkdir: %s\n", ret ? strerror(-ret) : "ok");
            }
            fprintf(out, "mkdir %s\n", path);
            continue;
        }

        if (strcmp(cmd, "create") == 0) {
            fscanf(in, "%s", path);
            fh = ethanefs_create(cli, path, 0755);
            if (IS_ERR(fh) || verbose) {
                printf("create: %s\n", IS_ERR(fh) ? strerror(-PTR_ERR(fh)) : "ok");
            }
            if (!IS_ERR(fh)) {
                ethanefs_close(cli, fh);
            }
            fprintf(out, "create %s\n", path);
            continue;
        }

        if (strcmp(cmd, "trunc") == 0 || strcmp(cmd, "truncate") == 0) {
            fscanf(in, "%s %lu", path, &size);
            fh = ethanefs_open(cli, path);
            if (IS_ERR(fh)) {
                ret = PTR_ERR(fh);
            } else {
                ret = ethanefs_truncate(cli, fh, size);
            }
            if (IS_ERR(fh) || verbose) {
                printf("trunc: %s\n", ret ? strerror(-ret) : "ok");
            }
            if (!IS_ERR(fh)) {
                ethanefs_close(cli, fh);
            }
            fprintf(out, "trunc %s %lu\n", path, size);
            continue;
        }

        if (strcmp(cmd, "dump") == 0) {
            ethanefs_dump_cli(cli);
            ethanefs_dump_remote(cli);
            fprintf(out, "dump\n");
            continue;
        }

        if (strcmp(cmd, "rmdir") == 0) {
            fscanf(in, "%s", path);
            ret = ethanefs_rmdir(cli, path);
            if (ret || verbose) {
                printf("rmdir: %s\n", ret ? strerror(-ret) : "ok");
            }
            fprintf(out, "rmdir %s\n", path);
            continue;
        }

        if (strcmp(cmd, "rm") == 0) {
            fscanf(in, "%s", path);
            ret = ethanefs_unlink(cli, path);
            if (ret || verbose) {
                printf("rm: %s\n", ret ? strerror(-ret) : "ok");
            }
            fprintf(out, "rm %s\n", path);
            continue;
        }

        if (strcmp(cmd, "access") == 0) {
            fscanf(in, "%s", path);
            fh = ethanefs_open(cli, path);
            if (ret || verbose) {
                printf("access: %s\n", IS_ERR(fh) ? strerror(-PTR_ERR(fh)) : "ok");
            }
            if (!IS_ERR(fh)) {
                ethanefs_close(cli, fh);
            }
            fprintf(out, "access %s\n", path);
            continue;
        }

        if (strcmp(cmd, "write") == 0) {
            size_t off, size;
            fscanf(in, "%s %lu %lu %s", path, &off, &size, data);
            size = ALIGN_UP(size, IO_SIZE);
            fh = ethanefs_open(cli, path);
            if (IS_ERR(fh)) {
                ret = PTR_ERR(fh);
            } else {
                for (off = 0; off < size; off += IO_SIZE) {
                    ret = ethanefs_write(cli, fh, data, sizeof(data), off);
                    if (ret < 0) {
                        break;
                    }
                }
                if (ret < 0 || verbose) {
                    printf("write: %s\n", ret < 0 ? strerror(-ret) : "ok");
                }
            }
            if (!IS_ERR(fh)) {
                ethanefs_close(cli, fh);
            }
            fprintf(out, "write %s %lu %s\n", path, off, data);
            continue;
        }

        if (strcmp(cmd, "read") == 0) {
            size_t off;
            fscanf(in, "%s %lu", path, &off);
            fh = ethanefs_open(cli, path);
            if (IS_ERR(fh)) {
                ret = PTR_ERR(fh);
            } else {
                ret = ethanefs_read(cli, fh, data, sizeof(data), off);
            }
            if (ret < 0 || verbose) {
                printf("read: %s\n", ret < 0 ? strerror(-ret) : data);
            }
            if (!IS_ERR(fh)) {
                ethanefs_close(cli, fh);
            }
            fprintf(out, "read %s %lu\n", path, off);
            continue;
        }

        if (strcmp(cmd, "flush") == 0) {
            ethanefs_force_checkpoint(cli);
            fprintf(out, "flush\n");
            continue;
        }

        if (strcmp(cmd, "stat") == 0) {
            struct stat stat;
            fscanf(in, "%s", path);
            ret = ethanefs_getattr(cli, path, &stat);
            if (ret || verbose) {
                printf("stat: %s\n", ret ? strerror(-ret) : "ok");
            }
            fprintf(out, "stat %s\n", path);
            continue;
        }

        if (strcmp(cmd, "switch") == 0) {
            fscanf(in, "%d", &use_cli);
            if (verbose) {
                printf("use cli: %d(%p)\n", use_cli, clis[use_cli]);
            }
            fprintf(out, "switch %d\n", use_cli);
            continue;
        }

        if (strcmp(cmd, "cd") == 0) {
            fscanf(in, "%s", path);
            ethanefs_chdir(cli, path);
            if (verbose) {
                printf("cd: %s\n", path);
            }
            fprintf(out, "cd %s\n", path);
            continue;
        }

        if (strcmp(cmd, "pwd") == 0) {
            ethanefs_getcwd(cli, path);
            printf("pwd: %s\n", path);
            fprintf(out, "pwd %s\n", path);
            continue;
        }

        if (strcmp(cmd, "debug") == 0) {
            int mode;
            fscanf(in, "%s", cmd);
            mode = strcmp(cmd, "on") == 0;
            ethanefs_set_debug(mode);
            continue;
        }

        printf("invalid command\n");
    }
}

int main(int argc, const char **argv) {
    const char *zookeeper_ip = "10.0.2.140:2181";
    const char *cli_config_path = NULL;
    const char *batch_file = NULL;
    unsigned uid = 0, gid = 0;
    ethanefs_cli_t **clis;
    int nr_clis = 4, i;
    FILE *in, *out;
    ethanefs_t *fs;
    zhandle_t *zh;

    struct argparse_option options[] = {
        OPT_HELP(),

        OPT_STRING('t', "cli-conf", &cli_config_path, "path to client config file"),
        OPT_STRING('z', "zookeeper-ip", &zookeeper_ip, "zookeeper server ip (and port)"),
        OPT_INTEGER('u', "uid", &uid, "user id"),
        OPT_INTEGER('g', "gid", &gid, "group id"),
        OPT_STRING('b', "batch-file", &batch_file, "batch file"),
        OPT_INTEGER('n', "num-clis", &nr_clis, "number of clis"),

        OPT_END(),
    };
    struct argparse argparse;

    bench_timer_init_freq();

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, "\nlogd", "\nETHANE eshell");
    argparse_parse(&argparse, argc, argv);

    if (unlikely(!cli_config_path)) {
        pr_err("client config file not specified");
        return -1;
    }

    zoo_set_debug_level(0);

    zh = zookeeper_init(zookeeper_ip, NULL, 100000, NULL, NULL, 0);
    if (unlikely(!zh)) {
        pr_err("failed to connect to ZooKeeper server");
        return -1;
    }

    reg_debug_sig_handler();

    fs = ethanefs_init(zh, 0);

    clis = malloc(sizeof(ethanefs_cli_t *) * nr_clis);
    for (i = 0; i < nr_clis; i++) {
        clis[i] = create_cli(fs, cli_config_path, uid, gid);
        pr_info("created client %d:%p", i, clis[i]);
    }

    if (batch_file) {
        in = fopen(batch_file, "r");
    } else {
        in = stdin;
        printf("Welcome to ethane eshell\n");
    }

    out = fopen("./batch_file", "w");

    parse_cmds(clis, in, out, batch_file == NULL);

    free(clis);

    fclose(out);

    return 0;
}
