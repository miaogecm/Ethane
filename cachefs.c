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
 */

/*
 *   CacheFS is a coherent, scalable compute-node-side cache layer
 * for ETHANE. For every FS client, it provides a partial FS view
 * of the global namespace. It caches the latest / hottest FS data.
 *   The coherence between CacheFSes of different compute-nodes is
 * guaranteed via the shared log.
 *
 *   CacheFS contains 2 parts:
 * (1) namespace cache: It maps full path/remote dentry pointer
 *     to file's remote pointer and attributes. "Tombstone" items
 *     are used to indicate the negative lookup result (removed file).
 *     The namespace cache is organized as a hash table. (ns cache)
 * (3) block mapping cache: It maps <file remote pointer, offset> to
 *     its corresponding data block's remote pointer and block size.
 *     The file mapping cache is organized as an AVL-based interval
 *     tree. (bm cache)
 */

#include <sys/stat.h>
#include <errno.h>
#include <math.h>

#include "sharedfs.h"
#include "cachefs.h"
#include "debug.h"

#include <unistd.h>
#include <asm/unistd_64.h>

#include "oplogger.h"
#include "tabhash.h"
#include "list.h"
#include "avl.h"

#define NSC_BUCKET_MAX_LEN      4

struct lru_bucket {
    struct list_head head;
    int count;
};

struct ns_cache {
    struct lru_bucket *buckets;
    TAB_hash hf;
    int count;
    size_t version;
    int nr_ent_max, nr_ent_high_watermark;
    int nr_buckets, bucket_len_high_watermark;
};

struct ns_entry {
    struct list_head node;
    struct ethane_dentry dentry;
    size_t version;
    bool is_create;
    char full_path[];
};

struct bm_cache {
    struct avl_tree tree;
    struct bm_entry *clock_hand;
    size_t version;
    int nr_ent_max, nr_ent_high_watermark;
};

struct bm_entry {
    struct avl_node node;
    dmptr_t remote_dentry;
    size_t off, size;
    dmptr_t blk_remote_addr;
    size_t version;
    /* We use CLOCK psuedo-LRU cache eviction algorithm for BMC. */
    bool ref;
};

struct cachefs {
    sharedfs_t *rfs;

    struct ns_cache nsc;
    struct bm_cache bmc;

    /*
     * Entries BEFORE this version are considered as "stale"
     * and can be evicted.
     */
    size_t version;
};

void cachefs_set_version(cachefs_t *cfs, size_t version) {
    cfs->version = version;
    cfs->nsc.version = cfs->bmc.version = version;
    if (cfs->version != version) {
        pr_debug("cachefs set version to %lu", version);
    }
}

/*
 * Cache maintenance functions
 * (Data structure level)
 */

/* Namespace Cache */

static inline bool nsc_entry_evictable(struct ns_cache *cache, struct ns_entry *entry) {
    return entry->version < cache->version;
}

static inline int nsc_remove(struct ns_cache *cache, struct ns_entry *entry);

static inline int nsc_entry_evict(struct ns_cache *cache, struct lru_bucket *bucket, int nr) {
    struct ns_entry *entry, *tmp;
    int nr_evicted = 0;

    list_for_each_entry_safe_reverse(entry, tmp, &bucket->head, node) {
        if (!nsc_entry_evictable(cache, entry)) {
            continue;
        }

        nsc_remove(cache, entry);
        free(entry);

        if (++nr_evicted == nr) {
            goto out;
        }
    }

out:
    return nr_evicted;
}

static inline size_t full_path_hash(struct ns_cache *cache, const char *full_path, size_t len) {
    return TAB_finalize(&cache->hf, TAB_process(&cache->hf, (const uint8_t *) full_path, len, 0));
}

static inline void nsc_lru_update(struct lru_bucket *bucket, struct ns_entry *entry) {
    /* move to LRU list head */
    list_move(&entry->node, &bucket->head);
}

static inline void nsc_lru_add(struct ns_cache *cache, struct lru_bucket *bucket, struct ns_entry *entry) {
    int nr_evict;

    if (bucket->count >= cache->bucket_len_high_watermark) {
        /* evict entries from LRU list */
        nr_evict = bucket->count + 1 - cache->bucket_len_high_watermark;
        nr_evict = nsc_entry_evict(cache, bucket, nr_evict);
        bucket->count -= nr_evict;
        cache->count -= nr_evict;
    }

    /* add to LRU list head */
    INIT_LIST_HEAD(&entry->node);
    list_add(&entry->node, &bucket->head);
    bucket->count++;

    cache->count++;
}

static inline void nsc_lru_del(struct ns_cache *cache, struct lru_bucket *bucket, struct ns_entry *entry) {
    list_del(&entry->node);
    bucket->count--;

    cache->count--;
}

static inline struct ns_entry *nsc_lookup(struct ns_cache *cache, const char *full_path, size_t len) {
    struct lru_bucket *bucket;
    struct ns_entry *entry;

    bucket = &cache->buckets[full_path_hash(cache, full_path, len) % cache->nr_buckets];
    list_for_each_entry(entry, &bucket->head, node) {
        if (strlen(entry->full_path) == len && strncmp(entry->full_path, full_path, len) == 0) {
            nsc_lru_update(bucket, entry);
            goto out;
        }
    }

    entry = NULL;

out:
    return entry;
}

static inline int nsc_insert(struct ns_cache *cache, struct ns_entry *entry) {
    int bucketn = full_path_hash(cache, entry->full_path, strlen(entry->full_path)) % cache->nr_buckets;
    struct lru_bucket *bucket;
    bucket = &cache->buckets[bucketn];
    nsc_lru_add(cache, bucket, entry);
    pr_debug("bucket: %d; dentry: %lx(%s); path: %s; create: %d",
             bucketn, entry->dentry.remote_addr, get_de_ty_str(entry->dentry.type),
             entry->full_path, entry->is_create);
    return 0;
}

static inline int nsc_remove(struct ns_cache *cache, struct ns_entry *entry) {
    int bucketn = full_path_hash(cache, entry->full_path, strlen(entry->full_path)) % cache->nr_buckets;
    struct lru_bucket *bucket;
    bucket = &cache->buckets[bucketn];
    nsc_lru_del(cache, bucket, entry);
    pr_debug("bucket: %d; dentry: %lx(%s); path: %s; create: %d",
             bucketn, entry->dentry.remote_addr, get_de_ty_str(entry->dentry.type),
             entry->full_path, entry->is_create);
    return 0;
}

/* Block Mapping Cache */

static inline bool bmc_entry_evictable(struct bm_cache *cache, struct bm_entry *entry) {
    return entry->version < cache->version;
}

static inline struct bm_entry *bmc_lookup(struct bm_cache *cache, dmptr_t remote_dentry, size_t off) {
    struct bm_entry query = { .remote_dentry = remote_dentry, .off = off }, *entry;

    pr_debug("lookup extent: dentry=%lx off=%lu", remote_dentry, off);

    /* find the last interval that <= off */
    entry = avl_tree_nearest(&cache->tree, &query);
    if (unlikely(entry && entry->off > off)) {
        entry = avl_tree_prev(&cache->tree, entry);
    }

    /* ensure @off is within range */
    if (likely(entry)) {
        pr_debug("found entry: dentry=%lx off=%lu size=%lu, check validity",
                 entry->remote_dentry, entry->off, entry->size);

        if (unlikely(off >= entry->off + entry->size)) {
            entry = NULL;
        } else {
            /* set the reference flag for LRU */
            entry->ref = true;
        }
    }

    return entry;
}

static inline int bmc_remove(struct bm_cache *cache, struct bm_entry *entry);

static inline bool bmc_evict(struct bm_cache *bmc, int nr) {
    struct bm_entry *victim, *start;
    int i;

    for (i = 0; i < nr; i++) {
        if (unlikely(!bmc->clock_hand)) {
            bmc->clock_hand = avl_tree_first(&bmc->tree);
        }

        start = bmc->clock_hand;

        while (bmc->clock_hand->ref || !bmc_entry_evictable(bmc, bmc->clock_hand)) {
            bmc->clock_hand->ref = false;
            bmc->clock_hand = avl_tree_next(&bmc->tree, bmc->clock_hand);
            if (unlikely(!bmc->clock_hand)) {
                bmc->clock_hand = avl_tree_first(&bmc->tree);
            }
            if (bmc->clock_hand == start) {
                /* we have tried our best, but no entries can be evicted so far */
                return false;
            }
        }

        victim = bmc->clock_hand;

        bmc->clock_hand = avl_tree_next(&bmc->tree, bmc->clock_hand);

        bmc_remove(bmc, victim);

        pr_debug("evicted entry: dentry=%lx off=%lu size=%lu", victim->remote_dentry, victim->off, victim->size);
    }

    return true;
}

/*
 * adjust entry's prev and next entry to remove intersection part with entry
 */
static inline int bmc_insert_new(struct bm_cache *cache, struct bm_entry *entry) {
    struct bm_entry *nearest, *prev = NULL, *next = NULL, *add;
    int ret = 0;

    pr_debug("insert new block: dentry=%lx off=%lu size=%lu", entry->remote_dentry, entry->off, entry->size);

    /* do eviction if necessary */
    if (cache->tree.count >= cache->nr_ent_high_watermark) {
        bmc_evict(cache, (int) (cache->tree.count - cache->nr_ent_high_watermark + 1));
    }

    /* get pred and succ */
    nearest = avl_tree_nearest(&cache->tree, entry);
    if (nearest) {
        if (unlikely(nearest->off > entry->off)) {
            prev = avl_tree_prev(&cache->tree, nearest);
            next = nearest;
        } else {
            prev = nearest;
            next = avl_tree_next(&cache->tree, nearest);
        }
    }

    if (prev && prev->remote_dentry != entry->remote_dentry) {
        prev = NULL;
    }
    if (next && next->remote_dentry != entry->remote_dentry) {
        next = NULL;
    }

    if (prev) {
        pr_debug("has prev: dentry=%lx off=%lu size=%lu", prev->remote_dentry, prev->off, prev->size);
    }
    if (next) {
        pr_debug("has next: dentry=%lx off=%lu size=%lu", next->remote_dentry, next->off, next->size);
    }

    /* remove prev's intersection part with entry */
    if (prev && prev->off + prev->size > entry->off) {
        /* prev completely covers entry */
        if (prev->off + prev->size > entry->off + entry->size) {
            add = calloc(1, sizeof(*add));
            if (unlikely(!add)) {
                ret = -ENOMEM;
                goto out;
            }

            add->remote_dentry = prev->remote_dentry;
            add->off = entry->off + entry->size;
            add->size = prev->off + prev->size - add->off;
            add->blk_remote_addr = prev->blk_remote_addr;
            add->version = prev->version;
            avl_tree_add(&cache->tree, add);

            pr_debug("prev completely covers entry, add right part dentry=%lx off=%lu size=%lu",
                     add->remote_dentry, add->off, add->size);
        }

        prev->size = entry->off - prev->off;
        pr_debug("prev -> dentry=%lx off=%lu size=%lu", prev->remote_dentry, prev->off, prev->size);

        if (!prev->size) {
            pr_debug("prev is completely covered by entry, remove prev");
            avl_tree_remove(&cache->tree, prev);
            free(prev);
        }
    }

    /* remove next's intersection part with entry */
    if (next && next->off < entry->off + entry->size) {
        /* has intersection */
        if (next->off + next->size > entry->off + entry->size) {
            /* next is partially covered by entry */
            next->off = entry->off + entry->size;
            next->size -= entry->size;

            pr_debug("next -> dentry=%lx off=%lu size=%lu", next->remote_dentry, next->off, next->size);
        } else {
            /* next is completely covered by entry */
            avl_tree_remove(&cache->tree, next);
            free(next);

            pr_debug("next is completely covered by entry, remove next");
        }
    }

    /* write interval */
    entry->ref = true;
    avl_tree_add(&cache->tree, entry);

out:
    return ret;
}

/* adjust entry itself to remove intersection part with prev and next */
static inline int bmc_insert_old(struct bm_cache *cache, struct bm_entry *entry) {
    struct bm_entry *nearest, *prev = NULL, *next = NULL, *add;
    int ret = 0;

    pr_debug("insert old block: dentry=%lx off=%lu size=%lu", entry->remote_dentry, entry->off, entry->size);

    /* do eviction if necessary */
    if (cache->tree.count >= cache->nr_ent_max) {
        bmc_evict(cache, (int) (cache->tree.count - cache->nr_ent_max + 1));
    }

    /* get pred and succ */
    nearest = avl_tree_nearest(&cache->tree, entry);
    if (nearest) {
        if (unlikely(nearest->off > entry->off)) {
            prev = avl_tree_prev(&cache->tree, nearest);
            next = nearest;
        } else {
            prev = nearest;
            next = avl_tree_next(&cache->tree, nearest);
        }
    }

    if (prev && prev->remote_dentry != entry->remote_dentry) {
        prev = NULL;
    }
    if (next && next->remote_dentry != entry->remote_dentry) {
        next = NULL;
    }

    if (prev) {
        pr_debug("has prev: dentry=%lx off=%lu size=%lu", prev->remote_dentry, prev->off, prev->size);
    }
    if (next) {
        pr_debug("has next: dentry=%lx off=%lu size=%lu", next->remote_dentry, next->off, next->size);
    }

    /* remove entry's intersection part with prev */
    if (prev && prev->off + prev->size > entry->off) {
        /* has intersection */
        if (prev->off + prev->size >= entry->off + entry->size) {
            /* prev completely covers entry */
            pr_debug("prev completely covers entry, remove entry");
            free(entry);
            goto out;
        }

        /* prev partially covers entry */
        entry->size -= prev->off + prev->size - entry->off;
        entry->off = prev->off + prev->size;
        ethane_assert(entry->size > 0);
    }

    /* remove entry's intersection part with next */
    if (next && next->off < entry->off + entry->size) {
        if (next->off + next->size < entry->off + entry->size) {
            /* next is completely covered by entry */
            add = calloc(1, sizeof(*add));
            if (unlikely(!add)) {
                ret = -ENOMEM;
                goto out;
            }

            add->remote_dentry = entry->remote_dentry;
            add->off = next->off + next->size;
            add->size = entry->off + entry->size - add->off;
            add->blk_remote_addr = next->blk_remote_addr;
            add->version = entry->version;
            avl_tree_add(&cache->tree, add);

            pr_debug("next completely covered by entry, add right part dentry=%lx off=%lu size=%lu",
                     add->remote_dentry, add->off, add->size);
        }

        entry->size = next->off - entry->off;
        ethane_assert(entry->size > 0);
    }

    avl_tree_add(&cache->tree, entry);
    pr_debug("entry -> dentry=%lx off=%lu size=%lu", entry->remote_dentry, entry->off, entry->size);

out:
    return ret;
}

static inline int bmc_remove(struct bm_cache *cache, struct bm_entry *entry) {
    avl_tree_remove(&cache->tree, entry);
    free(entry);
    return 0;
}

static int fetch_path_prefixes_to_cache(cachefs_t *cfs, const char *path,
                                        struct ns_entry **parent_ent, struct ns_entry **ent) {
    struct ns_cache *nsc = &cfs->nsc;
    struct ethane_dentry **dentries;
    int len, depth, ret = 0, i = 0;
    const char *component, *next;
    dmptr_t parent = DMPTR_NULL;
    bool need_remote = false;
    struct ns_entry *entry;
    size_t prefix_len;

    depth = ethane_get_dir_depth(path);

    dentries = calloc(depth, sizeof(struct ethane_dentry *));
    if (unlikely(!dentries)) {
        ret = -ENOMEM;
        goto out;
    }

    pr_debug("fetch path prefixes to cache, path=%s", path);

    ETHANE_ITER_COMPONENTS(path, component, next, len) {
        prefix_len = component + len - path;

        if ((entry = nsc_lookup(nsc, path, prefix_len))) {
            dentries[i] = &entry->dentry;

            pr_debug("component %d (%.*s) found in cache", i, (int) prefix_len, path);
        } else {
            entry = calloc(1, sizeof(*entry) + prefix_len + 1);
            if (unlikely(!entry)) {
                ret = -ENOMEM;
                goto out_free;
            }
            dentries[i] = &entry->dentry;

            entry->dentry.type = ETHANE_DENTRY_TOMBSTONE;
            entry->version = 0;
            strncpy(entry->full_path, path, prefix_len);
            entry->full_path[prefix_len] = '\0';
            nsc_insert(nsc, entry);

            need_remote = true;

            pr_debug("component %d (%.*s) not present in cache, need_remote", i, (int) prefix_len, path);
        }

        i++;
    }

    if (need_remote) {
        ret = sharedfs_ns_lookup_dentries(cfs->rfs, path, dentries);
        if (unlikely(ret < 0)) {
            goto out_free;
        }
    }

    i = 0;

    ETHANE_ITER_COMPONENTS(path, component, next, len) {
        prefix_len = component + len - path;

        entry = container_of(dentries[i], struct ns_entry, dentry);

        if (dentries[i]->remote_addr == DMPTR_NULL) {
            /* Non-existent file */
            entry->dentry.type = ETHANE_DENTRY_TOMBSTONE;
            pr_debug("component %d (%.*s) is a tombstone", i, (int) prefix_len, path);
        }

        ethane_assert(!dentries[i]->parent || dentries[i]->parent == parent);
        dentries[i]->parent = parent;
        parent = dentries[i]->remote_addr;

        i++;
    }

    ethane_assert(depth > 0);
    if (ent) {
        *ent = container_of(dentries[depth - 1], struct ns_entry, dentry);
    }
    if (parent_ent) {
        *parent_ent = depth > 1 ? container_of(dentries[depth - 2], struct ns_entry, dentry) : NULL;
    }

out_free:
    free(dentries);

out:
    return ret;
}

enum perm_action {
    PERM_R,
    PERM_W,
    PERM_EX
};

/*
 * We assume that UID/GID are synced across CNs
 */
static int check_permission(cachefs_ctx_t *ctx, struct ethane_perm *perm, enum perm_action action) {
    if (perm->owner.uid == ctx->uid) {
        /* Owner */
        switch (action) {
            case PERM_R:
                return (perm->mode & S_IRUSR) ? 0 : -EACCES;
            case PERM_W:
                return (perm->mode & S_IWUSR) ? 0 : -EACCES;
            case PERM_EX:
                return (perm->mode & S_IXUSR) ? 0 : -EACCES;
        }
    } else if (perm->owner.gid == ctx->gid) {
        /* Group */
        switch (action) {
            case PERM_R:
                return (perm->mode & S_IRGRP) ? 0 : -EACCES;
            case PERM_W:
                return (perm->mode & S_IWGRP) ? 0 : -EACCES;
            case PERM_EX:
                return (perm->mode & S_IXGRP) ? 0 : -EACCES;
        }
    } else {
        /* Others */
        switch (action) {
            case PERM_R:
                return (perm->mode & S_IROTH) ? 0 : -EACCES;
            case PERM_W:
                return (perm->mode & S_IWOTH) ? 0 : -EACCES;
            case PERM_EX:
                return (perm->mode & S_IXOTH) ? 0 : -EACCES;
        }
    }
    ethane_assert(0);
}

static int check_prefix_components(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, enum perm_action last_action) {
    size_t prefix_len, path_len = strlen(path);
    struct ns_entry *entry = NULL;
    const char *component, *next;
    int len, ret;

    /* prefix components (except last one) should exist and be with lookup permission */
    ETHANE_ITER_COMPONENTS(path, component, next, len) {
        prefix_len = component + len - path;

        if (prefix_len == path_len) {
            break;
        }

        if (unlikely(!(entry = nsc_lookup(&cfs->nsc, path, prefix_len)) || entry->dentry.type == ETHANE_DENTRY_TOMBSTONE)) {
            ret = -ENOENT;
            goto out;
        }

        if (unlikely(entry->dentry.type != ETHANE_DENTRY_DIR)) {
            ret = -ENOTDIR;
            goto out;
        }

        ret = check_permission(ctx, &entry->dentry.perm, PERM_EX);
        if (unlikely(ret < 0)) {
            goto out;
        }
    }

    ethane_assert(entry);
    ret = check_permission(ctx, &entry->dentry.perm, last_action);

out:
    return ret;
}

static int do_mkdir(cachefs_t *cfs, const char *path, mode_t mode,
                    dmptr_t remote_dentry, dmptr_t parent_remote_addr, size_t version) {
    struct ethane_dentry *dentry;
    bool need_insert = false;
    struct ns_entry *entry;
    int ret = 0;

    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (!entry) {
        entry = calloc(1, sizeof(*entry) + strlen(path) + 1);
        if (unlikely(!entry)) {
            ret = -ENOMEM;
            goto out;
        }
        need_insert = true;
    }

    dentry = &entry->dentry;
    dentry->type = ETHANE_DENTRY_DIR;
    dentry->remote_addr = remote_dentry;
    dentry->parent = parent_remote_addr;
    dentry->file_size = 0;
    dentry->nr_children = 0;
    dentry->perm.mode = mode;
    /* FIXME: */
    dentry->perm.owner.uid = 0;
    dentry->perm.owner.gid = 0;

    entry->version = version;
    entry->is_create = true;
    strcpy(entry->full_path, path);

    if (need_insert) {
        nsc_insert(&cfs->nsc, entry);
    }

    pr_debug("do_mkdir: %lx (parent: %lx)", remote_dentry, parent_remote_addr);

out:
    return ret;
}

int cachefs_prefetch_metadata(cachefs_t *cfs, const char *path) {
    return fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
}

static struct ns_entry *check_mkdir_and_get_parent(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct bench_timer timer;
    struct ns_entry *parent;
    struct ns_entry *entry;
    int ret;

    bench_timer_start(&timer);

    ret = fetch_path_prefixes_to_cache(cfs, path, &parent, NULL);
    if (unlikely(IS_ERR(ret))) {
        parent = ERR_PTR(ret);
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_W);
    if (unlikely(IS_ERR(ret))) {
        parent = ERR_PTR(ret);
        goto out;
    }

    /* the last component must be non-existent */
    entry = nsc_lookup(&cfs->nsc, path, path_len);
    if (unlikely(entry && entry->dentry.type != ETHANE_DENTRY_TOMBSTONE)) {
        parent = ERR_PTR(-EEXIST);
        goto out;
    }

    ethane_assert(parent);

out:
    return parent;
}

int cachefs_mkdir(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res,
                  mode_t mode, dmptr_t remote_dentry, size_t version) {
    dmptr_t parent_remote_addr;
    struct ns_entry *parent;
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        parent = check_mkdir_and_get_parent(cfs, ctx, path);
        if (unlikely(IS_ERR(parent))) {
            *res = OP_RESULT_CANCELED;
            ret = PTR_ERR(parent);
            goto out;
        }
        *res = parent_remote_addr = parent->dentry.remote_addr;
    } else {
        ethane_assert(*res != OP_RESULT_CANCELED);
        parent_remote_addr = *res;
    }

    ret = do_mkdir(cfs, path, mode, remote_dentry, parent_remote_addr, version);

out:
    return ret;
}

static struct ns_entry *check_rmdir_and_get_ent(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct ns_entry *entry;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        entry = ERR_PTR(ret);
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_W);
    if (unlikely(ret < 0)) {
        entry = ERR_PTR(ret);
        goto out;
    }

    /* the last component must be existent */
    entry = nsc_lookup(&cfs->nsc, path, path_len);
    if (unlikely(!entry || entry->dentry.type == ETHANE_DENTRY_TOMBSTONE)) {
        entry = ERR_PTR(-ENOENT);
        goto out;
    }

    /* the last component must be directory */
    if (unlikely(entry->dentry.type != ETHANE_DENTRY_DIR)) {
        entry = ERR_PTR(-ENOTDIR);
        goto out;
    }

    /* ... and it must be empty */
    if (unlikely(entry->dentry.nr_children > 0)) {
        entry = ERR_PTR(-ENOTEMPTY);
        goto out;
    }

out:
    return entry;
}

static int do_rmdir(cachefs_t *cfs, const char *path, size_t version, dmptr_t dentry_remote_addr) {
    bool need_insert = false;
    struct ns_entry *entry;
    int ret = 0;

    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (!entry) {
        entry = calloc(1, sizeof(*entry) + strlen(path) + 1);
        if (unlikely(!entry)) {
            ret = -ENOMEM;
            goto out;
        }
        need_insert = true;
    }

    entry->dentry.remote_addr = dentry_remote_addr;
    entry->dentry.type = ETHANE_DENTRY_TOMBSTONE;

    entry->is_create = false;
    entry->version = version;

    strcpy(entry->full_path, path);

    if (need_insert) {
        nsc_insert(&cfs->nsc, entry);
    }

    pr_debug("do_rmdir: %s %lx", path, dentry_remote_addr);

out:
    return ret;
}

int cachefs_rmdir(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, size_t version) {
    dmptr_t dentry_remote_addr;
    struct ns_entry *entry;
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        entry = check_rmdir_and_get_ent(cfs, ctx, path);
        if (unlikely(IS_ERR(entry))) {
            *res = OP_RESULT_CANCELED;
            ret = PTR_ERR(entry);
            goto out;
        }
        *res = dentry_remote_addr = entry->dentry.remote_addr;
    } else {
        dentry_remote_addr = *res;
    }

    ethane_assert(*res != OP_RESULT_CANCELED);
    ret = do_rmdir(cfs, path, version, dentry_remote_addr);

out:
    return ret;
}

static struct ns_entry *check_unlink_and_get_ent(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct ns_entry *entry;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        entry = ERR_PTR(ret);
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_W);
    if (unlikely(ret < 0)) {
        entry = ERR_PTR(ret);
        goto out;
    }

    /* the last component must be existent */
    entry = nsc_lookup(&cfs->nsc, path, path_len);
    if (unlikely(!entry || entry->dentry.type == ETHANE_DENTRY_TOMBSTONE)) {
        entry = ERR_PTR(-ENOENT);
        goto out;
    }

    /* the last component must be file */
    if (unlikely(entry->dentry.type != ETHANE_DENTRY_FILE)) {
        entry = ERR_PTR(-EISDIR);
        goto out;
    }

out:
    return entry;
}

static int do_unlink(cachefs_t *cfs, const char *path, size_t version, dmptr_t dentry_remote_addr) {
    bool need_insert = false;
    struct ns_entry *entry;
    int ret = 0;

    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (!entry) {
        entry = calloc(1, sizeof(*entry) + strlen(path) + 1);
        if (unlikely(!entry)) {
            ret = -ENOMEM;
            goto out;
        }
        need_insert = true;
    }

    entry->dentry.remote_addr = dentry_remote_addr;
    entry->dentry.type = ETHANE_DENTRY_TOMBSTONE;

    entry->is_create = false;
    entry->version = version;

    strcpy(entry->full_path, path);

    if (need_insert) {
        nsc_insert(&cfs->nsc, entry);
    }

    pr_debug("do_unlink: %s %lx", path, dentry_remote_addr);

out:
    return ret;
}

int cachefs_unlink(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, size_t version) {
    dmptr_t dentry_remote_addr;
    struct ns_entry *entry;
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        entry = check_unlink_and_get_ent(cfs, ctx, path);
        if (unlikely(IS_ERR(entry))) {
            ret = PTR_ERR(entry);
            *res = OP_RESULT_CANCELED;
            goto out;
        }
        *res = dentry_remote_addr = entry->dentry.remote_addr;
    } else {
        dentry_remote_addr = *res;
    }

    ethane_assert(*res != OP_RESULT_CANCELED);
    ret = do_unlink(cfs, path, version, dentry_remote_addr);

out:
    return ret;
}

static struct ns_entry *check_create_and_get_parent(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct ns_entry *parent;
    struct ns_entry *entry;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, &parent, NULL);
    if (unlikely(ret < 0)) {
        parent = ERR_PTR(ret);
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_W);
    if (unlikely(ret < 0)) {
        parent = ERR_PTR(ret);
        goto out;
    }

    /* the last component must be non-existent */
    entry = nsc_lookup(&cfs->nsc, path, path_len);
    if (unlikely(entry && entry->dentry.type != ETHANE_DENTRY_TOMBSTONE)) {
        parent = ERR_PTR(-EEXIST);
        goto out;
    }

    ethane_assert(parent);

out:
    return parent;
}

static int do_create(cachefs_t *cfs, const char *path, mode_t mode, dmptr_t remote_dentry, dmptr_t parent_remote_addr,
                     struct ethane_open_file *file, size_t version) {
    struct ethane_dentry *dentry;
    bool need_insert = false;
    struct ns_entry *entry;
    int ret = 0;

    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (!entry) {
        entry = calloc(1, sizeof(*entry) + strlen(path) + 1);
        if (unlikely(!entry)) {
            ret = -ENOMEM;
            goto out;
        }
        need_insert = true;
    }

    dentry = &entry->dentry;
    dentry->type = ETHANE_DENTRY_FILE;
    dentry->remote_addr = remote_dentry;
    dentry->parent = parent_remote_addr;
    dentry->file_size = 0;
    dentry->perm.mode = mode;
    /* FIXME: */
    dentry->perm.owner.uid = 0;
    dentry->perm.owner.gid = 0;

    entry->version = version;
    entry->is_create = true;
    strcpy(entry->full_path, path);

    if (need_insert) {
        nsc_insert(&cfs->nsc, entry);
    }

    if (file) {
        file->remote_dentry_addr = remote_dentry;
        strcpy(file->full_path, path);
    }

    pr_debug("do create: %lx (parent: %lx)", remote_dentry, parent_remote_addr);

out:
    return ret;
}

int cachefs_create(cachefs_t *cfs, cachefs_ctx_t *ctx,
                   const char *path, uint64_t *res, mode_t mode, dmptr_t remote_dentry, struct ethane_open_file *file,
                   size_t version) {
    dmptr_t parent_remote_addr;
    struct ns_entry *parent;
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        parent = check_create_and_get_parent(cfs, ctx, path);
        if (unlikely(IS_ERR(parent))) {
            *res = OP_RESULT_CANCELED;
            ret = PTR_ERR(parent);
            goto out;
        }
        *res = parent_remote_addr = parent->dentry.remote_addr;
    } else {
        ethane_assert(*res != OP_RESULT_CANCELED);
        parent_remote_addr = *res;
    }

    ret = do_create(cfs, path, mode, remote_dentry, parent_remote_addr, file, version);

out:
    return ret;
}

static int check_chmod(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct ns_entry *entry;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_EX);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* the last component must be existent */
    if (unlikely(!(entry = nsc_lookup(&cfs->nsc, path, path_len)))) {
        ret = -ENOENT;
        goto out;
    }

    /* ... and have write permission */
    ret = check_permission(ctx, &entry->dentry.perm, PERM_W);

out:
    return ret;
}

static int do_chmod(cachefs_t *cfs, const char *path, mode_t mode, size_t version) {
    struct ns_entry *entry;
    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    entry->dentry.perm.mode = mode;
    entry->version = version;
    return 0;
}

int cachefs_chmod(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, mode_t mode, size_t version) {
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        ret = check_chmod(cfs, ctx, path);
        if (unlikely(ret < 0)) {
            *res = OP_RESULT_CANCELED;
            goto out;
        }
        *res = OP_RESULT_DO_UPDATE;
    }

    ethane_assert(*res != OP_RESULT_CANCELED);
    ret = do_chmod(cfs, path, mode, version);

out:
    return ret;
}

static int check_chown(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path) {
    size_t path_len = strlen(path);
    struct ns_entry *entry;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_EX);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* the last component must be existent */
    if (unlikely(!(entry = nsc_lookup(&cfs->nsc, path, path_len)))) {
        ret = -ENOENT;
        goto out;
    }

    /* ... and have write permission */
    ret = check_permission(ctx, &entry->dentry.perm, PERM_W);

out:
    return ret;
}

static int do_chown(cachefs_t *cfs, const char *path, uid_t uid, gid_t gid, size_t version) {
    struct ns_entry *entry;
    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    entry->dentry.perm.owner.uid = uid;
    entry->dentry.perm.owner.gid = gid;
    entry->version = version;
    return 0;
}

int cachefs_chown(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, uint64_t *res, uid_t uid, gid_t gid,
                  size_t version) {
    int ret;

    if (*res == OP_RESULT_UNDETERMINED) {
        ret = check_chown(cfs, ctx, path);
        if (unlikely(ret < 0)) {
            *res = OP_RESULT_CANCELED;
            goto out;
        }
        *res = OP_RESULT_DO_UPDATE;
    }

    ethane_assert(*res != OP_RESULT_CANCELED);
    ret = do_chown(cfs, path, uid, gid, version);

out:
    return ret;
}

int cachefs_open(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, struct ethane_open_file *file) {
    struct ns_entry *nse;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_EX);
    if (unlikely(ret < 0)) {
        goto out;
    }

    nse = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (unlikely(!nse || nse->dentry.type == ETHANE_DENTRY_TOMBSTONE)) {
        ret = -ENOENT;
        goto out;
    }

    if (unlikely(nse->dentry.type != ETHANE_DENTRY_FILE)) {
        ret = -EISDIR;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_R);
    if (unlikely(ret < 0)) {
        goto out;
    }

    file->remote_dentry_addr = nse->dentry.remote_addr;
    strcpy(file->full_path, path);
    pr_debug("open: %s (%lx)", path, file->remote_dentry_addr);

out:
    return ret;
}

int cachefs_close(cachefs_t *cfs, cachefs_ctx_t *ctx, struct ethane_open_file *file) {
    return 0;
}

int cachefs_getattr(cachefs_t *cfs, cachefs_ctx_t *ctx, const char *path, struct stat *stbuf) {
    struct ns_entry *nse;
    int ret;

    ret = fetch_path_prefixes_to_cache(cfs, path, NULL, NULL);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = check_prefix_components(cfs, ctx, path, PERM_EX);
    if (unlikely(ret < 0)) {
        goto out;
    }

    nse = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (unlikely(!nse || nse->dentry.type == ETHANE_DENTRY_TOMBSTONE)) {
        ret = -ENOENT;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_R);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* TODO: fill more fields */
    stbuf->st_size = (__off_t) nse->dentry.file_size;

out:
    return ret;
}

static inline struct ns_entry *nsc_lookup_by_remote_dentry_addr(cachefs_t *cfs,
                                                                const char *path, dmptr_t remote_dentry_addr) {
    struct ns_entry *entry;
    int ret;

    entry = nsc_lookup(&cfs->nsc, path, strlen(path));
    if (entry) {
        ethane_assert(entry->dentry.type != ETHANE_DENTRY_TOMBSTONE);
        goto out;
    }

    entry = calloc(1, sizeof(*entry) + strlen(path) + 1);
    if (unlikely(!entry)) {
        entry = ERR_PTR(-ENOMEM);
        goto out;
    }

    entry->version = 0;
    strcpy(entry->full_path, path);

    ret = sharedfs_ns_get_dentry(cfs->rfs, remote_dentry_addr, &entry->dentry, 0);
    if (unlikely(ret < 0)) {
        free(entry);
        entry = ERR_PTR(ret);
        goto out;
    }

out:
    pr_debug("nsc_lookup_by_remote_dentry_addr: %lx %s", remote_dentry_addr, path);
    return entry;
}

int cachefs_truncate(cachefs_t *cfs, cachefs_ctx_t *ctx,
                     const char *path, dmptr_t remote_dentry_addr, size_t size, size_t version) {
    struct ns_entry *nse;
    int ret;

    nse = nsc_lookup_by_remote_dentry_addr(cfs, path, remote_dentry_addr);
    if (unlikely(IS_ERR(nse))) {
        ret = PTR_ERR(nse);
        goto out;
    }

    if (unlikely(nse->dentry.type != ETHANE_DENTRY_FILE)) {
        ret = -EISDIR;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_W);
    if (unlikely(ret < 0)) {
        goto out;
    }

    nse->dentry.file_size = size;

    nse->version = version;

out:
    return ret;
}

long cachefs_write(cachefs_t* cfs, cachefs_ctx_t* ctx,
                   const char* path, dmptr_t remote_dentry_addr, size_t off, const cachefs_blk_t* blk,
                   size_t version) {
    struct ns_entry *nse;
    struct bm_entry *bme;
    long write_size;
    int ret;

    nse = nsc_lookup_by_remote_dentry_addr(cfs, path, remote_dentry_addr);
    if (unlikely(IS_ERR(nse))) {
        write_size = PTR_ERR(nse);
        goto out;
    }

    if (unlikely(nse->dentry.type != ETHANE_DENTRY_FILE)) {
        write_size = -EISDIR;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_W);
    if (unlikely(ret < 0)) {
        write_size = ret;
        goto out;
    }

    write_size = min(nse->dentry.file_size, blk->size);

    /* FIXME: */
    if (write_size != IO_SIZE || off % IO_SIZE != 0) {
        pr_err("only support io size %lu, and off(=%lu) must be multipler of it!", IO_SIZE, off);
        abort();
    }

    bme = calloc(1, sizeof(*bme));
    if (unlikely(!bme)) {
        write_size = -ENOMEM;
        goto out;
    }

    bme->off = off;
    bme->size = write_size;
    bme->remote_dentry = nse->dentry.remote_addr;
    bme->blk_remote_addr = blk->blk_remote_addr;

    bme->version = version;

    bmc_insert_new(&cfs->bmc, bme);

out:
    return write_size;
}

long cachefs_append(cachefs_t* cfs, cachefs_ctx_t* ctx,
                    const char* path, dmptr_t remote_dentry_addr, const cachefs_blk_t* blk, size_t version) {
    struct ns_entry *nse;
    struct bm_entry *bme;
    long write_size;
    int ret;

    nse = nsc_lookup_by_remote_dentry_addr(cfs, path, remote_dentry_addr);
    if (unlikely(IS_ERR(nse))) {
        write_size = PTR_ERR(nse);
        goto out;
    }

    if (unlikely(nse->dentry.type != ETHANE_DENTRY_FILE)) {
        write_size = -EISDIR;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_W);
    if (unlikely(ret < 0)) {
        write_size = ret;
        goto out;
    }

    write_size = blk->size;

    bme = calloc(1, sizeof(*bme));
    if (unlikely(!bme)) {
        write_size = -ENOMEM;
        goto out;
    }

    bme->off = nse->dentry.file_size;
    bme->size = write_size;
    bme->remote_dentry = nse->dentry.remote_addr;
    bme->blk_remote_addr = blk->blk_remote_addr;

    bme->version = version;

    bmc_insert_new(&cfs->bmc, bme);

    nse->dentry.file_size += write_size;

out:
    return write_size;
}

static struct bm_entry *get_extent(cachefs_t *cfs, struct ethane_dentry *dentry, size_t off) {
    dmptr_t remote_blk_addr;
    struct bm_entry *entry;
    size_t size;
    int ret;

retry:
    entry = bmc_lookup(&cfs->bmc, dentry->remote_addr, off);
    if (entry) {
        pr_debug("get_extent: hit in cache dentry=%lx off=%lu size=%lu", dentry->remote_addr, off, entry->size);
        goto out;
    }

    ret = sharedfs_bm_get_extent(cfs->rfs, &remote_blk_addr, &size, dentry, off);
    if (unlikely(ret)) {
        pr_debug("no bm found");
        goto out;
    }

    entry = calloc(1, sizeof(*entry));
    if (unlikely(!entry)) {
        goto out;
    }

    entry->off = off;
    entry->size = size;
    entry->remote_dentry = dentry->remote_addr;
    entry->blk_remote_addr = remote_blk_addr;

    entry->version = 0;

    bmc_insert_old(&cfs->bmc, entry);
    goto retry;

out:
    return entry;
}

long cachefs_read(cachefs_t* cfs, cachefs_ctx_t* ctx,
                  const char* path, dmptr_t remote_dentry_addr, cachefs_blk_t* blks, size_t off, size_t size) {
    size_t blk_size, end;
    struct ns_entry *nse;
    struct bm_entry *bme;
    long read_size = 0;
    int ret;

    nse = nsc_lookup_by_remote_dentry_addr(cfs, path, remote_dentry_addr);
    if (unlikely(IS_ERR(nse))) {
        ret = PTR_ERR(nse);
        goto out;
    }

    if (unlikely(nse->dentry.type != ETHANE_DENTRY_FILE)) {
        read_size = -EISDIR;
        goto out;
    }

    ret = check_permission(ctx, &nse->dentry.perm, PERM_R);
    if (unlikely(ret < 0)) {
        read_size = ret;
        goto out;
    }

    end = min(off + size, nse->dentry.file_size);

    while (off < end) {
        bme = get_extent(cfs, &nse->dentry, off);
        if (unlikely(!bme)) {
            read_size = -ENOMEM;
            goto out;
        }

        blk_size = min(bme->size, end - off);

        ethane_assert(blk_size > 0);

        blks->blk_remote_addr = bme->blk_remote_addr + (off - bme->off);
        blks->size = bme->off + bme->size - off;

        pr_debug("read range [%lx, %lx) (blk: %lx, size: %lx)", off, off + blk_size, blks->blk_remote_addr, blks->size);

        off = bme->off + bme->size;
        read_size += blk_size;
        blks++;
    }

out:
    return read_size;
}

static inline int count_ns_entries(cachefs_t *cfs) {
    struct ns_entry *entry;
    int i, count = 0;
    for (i = 0; i < cfs->nsc.nr_buckets; i++) {
        list_for_each_entry(entry, &cfs->nsc.buckets[i].head, node) {
            count++;
        }
    }
    return count;
}

static inline int count_bm_entries(cachefs_t *cfs) {
    struct avl_tree *tree = &cfs->bmc.tree;
    struct bm_entry *entry;
    int count = 0;
    for (entry = avl_tree_first(tree); entry; entry = avl_tree_next(tree, entry)) {
        count++;
    }
    return count;
}

static void clear_ns_cache(cachefs_t *cfs) {
    struct ns_entry *entry, *tmp;
    int i;

    for (i = 0; i < cfs->nsc.nr_buckets; i++) {
        list_for_each_entry_safe(entry, tmp, &cfs->nsc.buckets[i].head, node) {
            list_del(&entry->node);
            free(entry);
        }
    }

    cfs->nsc.count = 0;
}

static void clear_bm_cache(cachefs_t *cfs) {
    struct avl_tree *tree = &cfs->bmc.tree;
    struct bm_entry *entry, *tmp;

    for (entry = avl_tree_first(tree); entry; entry = tmp) {
        tmp = avl_tree_next(tree, entry);
        avl_tree_remove(tree, entry);
        free(entry);
    }

    cfs->bmc.clock_hand = NULL;
}

static sharedfs_ns_update_record_t *get_ns_update_records(cachefs_t *cfs, int *nr_records) {
    sharedfs_ns_update_record_t *records, *record;
    struct ns_entry *entry;
    int i, count;

    count = count_ns_entries(cfs);
    records = calloc(count, sizeof(*records));
    if (unlikely(!records)) {
        goto out;
    }

    *nr_records = 0;

    for (i = 0; i < cfs->nsc.nr_buckets; i++) {
        list_for_each_entry(entry, &cfs->nsc.buckets[i].head, node) {
            if (entry->version < cfs->nsc.version) {
                continue;
            }

            record = &records[(*nr_records)++];
            record->full_path = entry->full_path;
            record->dentry = &entry->dentry;
            record->is_create = entry->is_create;
        }
    }

out:
    return records;
}

static sharedfs_bm_update_record_t *get_bm_update_records(cachefs_t *cfs, int *nr_records) {
    sharedfs_bm_update_record_t *records, *record;
    struct avl_tree *tree = &cfs->bmc.tree;
    struct bm_entry *entry;
    int count;

    count = count_bm_entries(cfs);
    records = calloc(count, sizeof(*records));
    if (unlikely(!records)) {
        goto out;
    }

    *nr_records = 0;

    for (entry = avl_tree_first(tree); entry; entry = avl_tree_next(tree, entry)) {
        if (entry->version < cfs->bmc.version) {
            continue;
        }

        record = &records[(*nr_records)++];
        record->dentry_remote_addr = entry->remote_dentry;
        record->loff = entry->off;
        record->size = entry->size;
        record->blk_remote_addr = entry->blk_remote_addr;
    }

out:
    return records;
}

bool cachefs_reached_high_watermark(cachefs_t *cfs) {
    return cfs->nsc.count >= cfs->nsc.nr_ent_high_watermark
           || cfs->bmc.tree.count >= cfs->bmc.nr_ent_high_watermark;
}

bool cachefs_reached_max_size(cachefs_t *cfs) {
    return cfs->nsc.count >= cfs->nsc.nr_ent_max
           || cfs->bmc.tree.count >= cfs->bmc.nr_ent_max;
}

int cachefs_checkpoint(cachefs_t *cfs) {
    sharedfs_ns_update_record_t *ns_records;
    sharedfs_bm_update_record_t *bm_records;
    int nr_records, ret = 0;

    if (debug_mode) {
        pr_debug("dump before chkpt");
        cachefs_dump(cfs);
    }

    ns_records = get_ns_update_records(cfs, &nr_records);
    if (unlikely(!ns_records)) {
        ret = -ENOMEM;
        goto out;
    }
    sharedfs_ns_update_batch(cfs->rfs, nr_records, ns_records);
    free(ns_records);

    bm_records = get_bm_update_records(cfs, &nr_records);
    if (unlikely(!bm_records)) {
        ret = -ENOMEM;
        goto out;
    }
    sharedfs_bm_update_batch(cfs->rfs, nr_records, bm_records);
    free(bm_records);

    clear_ns_cache(cfs);
    clear_bm_cache(cfs);

out:
    return ret;
}

static int bm_entry_cmp(const void *a, const void *b) {
    const struct bm_entry *ea = a, *eb = b;

    if (ea->remote_dentry < eb->remote_dentry) {
        return -1;
    }

    if (ea->remote_dentry > eb->remote_dentry) {
        return 1;
    }

    if (ea->off < eb->off) {
        return -1;
    }

    if (ea->off > eb->off) {
        return 1;
    }

    return 0;
}

cachefs_t *cachefs_init(struct dmcontext *dmcontext, struct dmm_cli *dmm, struct sharedfs *rfs,
                        size_t max_nsc_size, size_t nsc_size_high_watermark,
                        size_t max_bmc_size, size_t bmc_size_high_watermark) {
    TAB_generator gen;
    cachefs_t *cfs;
    int i;

    cfs = calloc(1, sizeof(*cfs));
    if (unlikely(!cfs)) {
        goto out;
    }

    TAB_init_generator(&gen, TAB_DEFAULT_SEED);
    TAB_init_hash(&cfs->nsc.hf, &gen, 0);
    cfs->nsc.nr_ent_high_watermark = (int) (nsc_size_high_watermark / sizeof(struct ns_entry));
    cfs->nsc.nr_ent_max = (int) (max_nsc_size / sizeof(struct ns_entry));
    cfs->nsc.nr_buckets = cfs->nsc.nr_ent_max / NSC_BUCKET_MAX_LEN;
    cfs->nsc.bucket_len_high_watermark = (int) round(NSC_BUCKET_MAX_LEN
                                                     * cfs->nsc.nr_ent_high_watermark
                                                     / cfs->nsc.nr_ent_max);
    cfs->nsc.buckets = calloc(cfs->nsc.nr_buckets, sizeof(*cfs->nsc.buckets));
    if (unlikely(!cfs->nsc.buckets)) {
        free(cfs);
        cfs = NULL;
        goto out;
    }
    for (i = 0; i < cfs->nsc.nr_buckets; i++) {
        INIT_LIST_HEAD(&cfs->nsc.buckets[i].head);
    }
#if 0
    printf("CacheFS namespace cache:\n");
    printf("  nr_buckets: %d\n", cfs->nsc.nr_buckets);
    printf("  bucket_len_max: %d\n", NSC_BUCKET_MAX_LEN);
    printf("  bucket_len_high_watermark: %d\n", cfs->nsc.bucket_len_high_watermark);
    printf("  nr_ent_max: %d\n", cfs->nsc.nr_ent_max);
    printf("  nr_ent_high_watermark: %d\n", cfs->nsc.nr_ent_high_watermark);
#endif

    avl_tree_init(&cfs->bmc.tree, bm_entry_cmp, sizeof(struct bm_entry), offsetof(struct bm_entry, node));
    cfs->bmc.clock_hand = NULL;
    cfs->bmc.nr_ent_max = (int) (max_bmc_size / sizeof(struct bm_entry));
    cfs->bmc.nr_ent_high_watermark = (int) (bmc_size_high_watermark / sizeof(struct bm_entry));
#if 0
    printf("CacheFS block mapping cache:\n");
    printf("  nr_ent_max: %d\n", cfs->bmc.nr_ent_max);
    printf("  nr_ent_high_watermark: %d\n", cfs->bmc.nr_ent_high_watermark);
#endif

    cfs->rfs = rfs;

    pr_info("init done: nbuck=%d,buckmaxlen=%d,buckhwlen=%d,nsentmaxn=%d,nsenthwn=%d,bmentmaxn=%d,bmenthwn=%d",
            cfs->nsc.nr_buckets, NSC_BUCKET_MAX_LEN, cfs->nsc.bucket_len_high_watermark,
            cfs->nsc.nr_ent_max, cfs->nsc.nr_ent_high_watermark,
            cfs->bmc.nr_ent_max, cfs->bmc.nr_ent_high_watermark);

out:
    return cfs;
}

void cachefs_dump(cachefs_t *cfs) {
    struct ns_entry *nse;
    struct bm_entry *bme;
    int i;

    pr_info("cachefs dump");

    pr_info("namespace cache (%d entries):", count_ns_entries(cfs));
    for (i = 0; i < cfs->nsc.nr_buckets; i++) {
        list_for_each_entry(nse, &cfs->nsc.buckets[i].head, node) {
            pr_info("[nsc] bucket: %i; dentry: %lx(%s); path: %s; parent: %lx; create: %d; evictable: %d; sz: %lu;",
                    i, nse->dentry.remote_addr, get_de_ty_str(nse->dentry.type),
                    nse->full_path, nse->dentry.parent, nse->is_create, nsc_entry_evictable(&cfs->nsc, nse),
                    nse->dentry.file_size);
        }
    }

    pr_info("block mapping cache (%d entries):", count_bm_entries(cfs));
    for (bme = avl_tree_first(&cfs->bmc.tree); bme; bme = avl_tree_next(&cfs->bmc.tree, bme)) {
        pr_info("[bmc] dentry: %lx; off: %lu; size: %lu; blk: %lx; evictable: %d;",
                bme->remote_dentry, bme->off, bme->size, bme->blk_remote_addr, bmc_entry_evictable(&cfs->bmc, bme));
    }
}

void cachefs_clean(cachefs_t *cfs) {
    pr_debug("clean nsc");
    clear_ns_cache(cfs);
    pr_debug("clean bmc");
    clear_bm_cache(cfs);
}
