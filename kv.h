/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Data-Plane Key-Value Interface
 * The data-plane key-value supports:
 * (1) Concurrent read/write
 * (2) Concurrent writes **across** shards
 * (3) Non-concurrent writes **within** a shard
 * (read=get, write=put/del)
 *
 * You should guarantee that values are unique!
 *
 * Hohai University
 */

#ifndef ETHANE_KV_H
#define ETHANE_KV_H

#include <stdlib.h>

#include "ethane.h"
#include "dmpool.h"
#include "dmm.h"

#include "coro.h"

#define KV_NR_POSSIBLE_VALS 2

typedef struct kv kv_t;
typedef struct {
    const char *key;
    size_t key_len;

    union {
        /* For get batch approx */
        void *possible_vals[KV_NR_POSSIBLE_VALS];

        /* For put */
        void *val;

        /* For update */
        void *upd_ctx;
    };

    int err;
} kv_vec_item_t;
typedef int (*kv_scanner_t)(void *priv, const void *val);

dmptr_t kv_create(dmcontext_t *ctx, dmm_cli_t *dmm, size_t size, size_t val_len, int nr_shards);
kv_t *kv_init(const char *name, dmcontext_t *ctx, dmm_cli_t *dmm, dmlocktab_t *locktab,
              dmptr_t kv_info_remote_addr, int nr_max_outstanding_reqs);

int kv_get_batch_approx(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec);

/* You should guarantee that these keys are NON-EXISTENT!! */
int kv_put_batch(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec);

/*
 * Update(/Delete)
 *
 * The return value of updater:
 * (1) ERR_PTR(-EINVAL): This entry is not our target.
 * (2) NULL: Delete this entry.
 * (3) Other valid pointers: The new value of this entry.
 */
int kv_upd_batch(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec, void *(*updater)(void *, void *));

int kv_scan(kv_t *kv, kv_scanner_t scanner, void *priv);

#define pr_debug_lookup_vec(vec, vec_len) \
    do { \
        for (int _i = 0; _i < (vec_len); ++_i) { \
            pr_debug("lvec[%d]: key=%.*s, val=%p/%p", _i, (int) (vec)[_i].key_len, (vec)[_i].key, \
                     (vec)[_i].possible_vals[0], (vec)[_i].possible_vals[1]); \
        } \
    } while (0)

#endif //ETHANE_KV_H
