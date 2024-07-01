/*
 * ETHANE User-Space Library
 */

#ifndef ETHANE_LIB_H
#define ETHANE_LIB_H

#include <sys/stat.h>
#include <stdbool.h>
#include <stdlib.h>
#include <zookeeper/zookeeper.h>

typedef struct ethanefs ethanefs_t;
typedef struct ethanefs_cli ethanefs_cli_t;
typedef struct ethanefs_open_file ethanefs_open_file_t;

typedef struct ethane_fs_config ethanefs_fs_config_t;
typedef struct ethane_memd_config ethanefs_memd_config_t;
typedef struct ethane_logd_config ethanefs_logd_config_t;
typedef struct ethane_cli_config ethanefs_cli_config_t;

/* Memory Node Functions */

_Noreturn void ethanefs_mem_daemon(zhandle_t *zh, ethanefs_memd_config_t *config);

/* Compute Node Functions */

int ethanefs_format(zhandle_t *zh, ethanefs_fs_config_t *config);
ethanefs_t *ethanefs_init(zhandle_t *zh, int prom_daemon_port);
ethanefs_cli_t *ethanefs_cli_init(ethanefs_t *fs, struct ethane_cli_config *config);

void ethanefs_set_user(ethanefs_cli_t *cli, uid_t uid, gid_t gid);

int ethanefs_getattr(ethanefs_cli_t *cli, const char *path, struct stat *stbuf);
int ethanefs_mkdir(ethanefs_cli_t *cli, const char *path, mode_t mode);
int ethanefs_rmdir(ethanefs_cli_t *cli, const char *path);
int ethanefs_unlink(ethanefs_cli_t *cli, const char *path);
ethanefs_open_file_t *ethanefs_create(ethanefs_cli_t *cli, const char *path, mode_t mode);
ethanefs_open_file_t *ethanefs_open(ethanefs_cli_t *cli, const char *path);
int ethanefs_close(ethanefs_cli_t *cli, ethanefs_open_file_t *file);
long ethanefs_read(ethanefs_cli_t *cli, ethanefs_open_file_t *file, char *buf, size_t size, off_t off);
long ethanefs_write(ethanefs_cli_t *cli, ethanefs_open_file_t *file, const char *buf, size_t size, off_t off);
int ethanefs_truncate(ethanefs_cli_t *cli, ethanefs_open_file_t *file, off_t size);
int ethanefs_chmod(ethanefs_cli_t *cli, const char *path, mode_t mode);
int ethanefs_chown(ethanefs_cli_t *cli, const char *path, uid_t uid, gid_t gid);

int ethanefs_get_cli_id(ethanefs_cli_t *cli);

_Noreturn void ethanefs_logger_cache_fetcher_loop(ethanefs_cli_t *cli, ethanefs_logd_config_t *config);
_Noreturn void ethanefs_checkpoint_loop(ethanefs_cli_t *cli, ethanefs_logd_config_t *config);

ethanefs_fs_config_t *ethanefs_config_parse_fs(const char *yaml_path);
ethanefs_memd_config_t *ethanefs_config_parse_memd(const char *yaml_path);
ethanefs_cli_config_t *ethanefs_config_parse_cli(const char *yaml_path);
ethanefs_logd_config_t *ethanefs_config_parse_logd(const char *yaml_path);

void ethanefs_bind_to_cpu(int cpu);
void ethanefs_post_ready(zhandle_t *zh);
void ethanefs_wait_enable(zhandle_t *zh);

void ethanefs_force_checkpoint(ethanefs_cli_t *cli);

void ethanefs_clean_cli(ethanefs_cli_t *cli);

void ethanefs_dump_cli(ethanefs_cli_t *cli);
void ethanefs_dump_remote(ethanefs_cli_t *cli);

int ethanefs_chdir(ethanefs_cli_t *cli, const char *path);
int ethanefs_getcwd(ethanefs_cli_t *cli, char *path);

const char *ethanefs_get_full_path(ethanefs_cli_t *cli, ethanefs_open_file_t *fh);

void ethanefs_set_debug(int mode);

void ethanefs_test_remote_path_walk(ethanefs_cli_t *cli, const char *path);

#endif //ETHANE_LIB_H
