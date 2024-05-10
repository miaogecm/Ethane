/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Remote File System
 *
 * Hohai University
 */

#include <errno.h>

#include "dmlocktab.h"
#include "sharedfs.h"

#include "debug.h"

#include "config.h"
#include "kv.h"

struct sharedfs_info {
    dmptr_t ns_root;

    dmptr_t ns_kv_remote_addr;
    dmptr_t bm_kv_remote_addr;

    int nr_interval_node_sizes;
    int interval_node_nr_blks[MAX_NR_INTERVAL_NODE_BLKN];
};

struct sharedfs {
    dmcontext_t *ctx;
    dmm_cli_t *dmm;

    /* Namespace KV */
    kv_t *ns_kv;
    dmptr_t ns_root;

    /* Block Mapping KV */
    kv_t *bm_kv;

    int nr_interval_node_sizes;
    int *interval_node_nr_blks;

    int nr_max_outstanding_updates;
};

struct ns_kv_val {
    dmptr_t dentry_remote_addr;
    dmptr_t parent;
    size_t filename_len;
};

struct ns_lookup_component {
    struct ns_kv_val possible_vals[KV_NR_POSSIBLE_VALS];
    struct ethane_dentry *possible_dentries[KV_NR_POSSIBLE_VALS];
    kv_vec_item_t *vec;
};

struct bm_extent {
    dmptr_t dentry_remote_addr;
    dmptr_t blk_remote_addr;
    int start_blkn, nr_blks;
};

struct bm_data_section_key {
    dmptr_t dentry_remote_addr;
    int start_blkn, nr_blks;
};

struct bm_data_section {
    struct bm_extent ext;
};

static dmptr_t create_ns_root(dmcontext_t *ctx, dmm_cli_t *dmm) {
    struct ethane_dentry *root;
    dmptr_t root_remote_addr;
    int ret;

    root_remote_addr = dmm_balloc(dmm, BLK_SIZE, BLK_SIZE, 0);
    if (unlikely(IS_ERR(root_remote_addr))) {
        goto out;
    }

    root = dm_push(ctx, NULL, sizeof(*root) + 1);
    if (unlikely(!root)) {
        root_remote_addr = -ENOMEM;
        goto out;
    }

    root->remote_addr = root_remote_addr;
    root->filename[0] = '\0';
    root->type = ETHANE_DENTRY_DIR;
    root->nr_children = 0;
    root->perm.mode = 0755;
    root->perm.owner.uid = 0;
    root->perm.owner.gid = 0;

    ret = dm_copy_to_remote(ctx, root_remote_addr, root, sizeof(*root) + 1, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        root_remote_addr = ret;
        goto out;
    }

    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        root_remote_addr = ret;
        goto out;
    }

out:
    return root_remote_addr;
}

dmptr_t sharedfs_create(dmcontext_t *ctx, dmm_cli_t *dmm,
                        int nr_internal_node_sizes, int *internal_node_nr_blks,
                        size_t ns_kv_size, size_t bm_kv_size,
                        int nr_shards) {
    struct sharedfs_info *info;
    dmptr_t remote_addr;
    int ret;

    dm_mark(ctx);

    remote_addr = dmm_balloc(dmm, sizeof(*info), BLK_SIZE, 0);
    if (unlikely(IS_ERR(remote_addr))) {
        goto out;
    }

    info = dm_push(ctx, NULL, sizeof(*info));
    if (unlikely(!info)) {
        remote_addr = -ENOMEM;
        goto out;
    }

    info->ns_root = create_ns_root(ctx, dmm);
    if (unlikely(IS_ERR(info->ns_root))) {
        remote_addr = info->ns_root;
        goto out;
    }

    info->ns_kv_remote_addr = kv_create(ctx, dmm, ns_kv_size, sizeof(struct ns_kv_val), nr_shards);
    if (unlikely(IS_ERR(info->ns_kv_remote_addr))) {
        remote_addr = info->ns_kv_remote_addr;
        goto out;
    }

    info->bm_kv_remote_addr = kv_create(ctx, dmm, bm_kv_size, sizeof(struct bm_extent), nr_shards);
    if (unlikely(IS_ERR(info->bm_kv_remote_addr))) {
        remote_addr = info->bm_kv_remote_addr;
        goto out;
    }

    info->nr_interval_node_sizes = nr_internal_node_sizes;
    memcpy(info->interval_node_nr_blks, internal_node_nr_blks, sizeof(*internal_node_nr_blks) * nr_internal_node_sizes);

    ret = dm_copy_to_remote(ctx, remote_addr, info, sizeof(*info), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        remote_addr = ret;
        goto out;
    }

    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        remote_addr = ret;
        goto out;
    }

out:
    dm_pop(ctx);
    return remote_addr;
}

sharedfs_t *sharedfs_init(dmcontext_t *ctx, dmm_cli_t *dmm, dmlocktab_t *locktab,
                          dmptr_t sharedfs_info_remote_addr, int nr_max_outstanding_updates) {
    struct sharedfs_info *info;
    sharedfs_t *sfs;
    int ret;

    dm_mark(ctx);

    info = dm_push(ctx, NULL, sizeof(*info));
    if (unlikely(!info)) {
        sfs = ERR_PTR(-ENOMEM);
        goto out;
    }

    ret = dm_copy_from_remote(ctx, info, sharedfs_info_remote_addr, sizeof(*info), DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        sfs = ERR_PTR(ret);
        goto out;
    }

    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        sfs = ERR_PTR(ret);
        goto out;
    }

    sfs = calloc(1, sizeof(*sfs));
    if (unlikely(!sfs)) {
        sfs = ERR_PTR(-ENOMEM);
        goto out;
    }

    sfs->ctx = ctx;
    sfs->dmm = dmm;

    sfs->ns_root = info->ns_root;

    sfs->ns_kv = kv_init("ns", ctx, dmm, locktab, info->ns_kv_remote_addr, nr_max_outstanding_updates);
    if (unlikely(IS_ERR(sfs->ns_kv))) {
        free(sfs);
        sfs = ERR_PTR(sfs->ns_kv);
        goto out;
    }

    sfs->bm_kv = kv_init("bm", ctx, dmm, locktab, info->bm_kv_remote_addr, nr_max_outstanding_updates);
    if (unlikely(IS_ERR(sfs->bm_kv))) {
        free(sfs);
        sfs = ERR_PTR(sfs->bm_kv);
        goto out;
    }

    sfs->nr_interval_node_sizes = info->nr_interval_node_sizes;
    sfs->interval_node_nr_blks = malloc(sizeof(*sfs->interval_node_nr_blks) * info->nr_interval_node_sizes);
    if (unlikely(!sfs->interval_node_nr_blks)) {
        free(sfs);
        sfs = ERR_PTR(-ENOMEM);
        goto out;
    }
    memcpy(sfs->interval_node_nr_blks, info->interval_node_nr_blks,
           sizeof(*info->interval_node_nr_blks) * info->nr_interval_node_sizes);

    sfs->nr_max_outstanding_updates = nr_max_outstanding_updates;

    pr_info("init done");

out:
    dm_pop(ctx);
    return sfs;
}

static int get_possible_dentry_ptrs(sharedfs_t *sfs, struct ns_lookup_component *components,
                                    const char *full_path, struct ethane_dentry **dentries) {
    struct ns_kv_val ns_root_val = { .dentry_remote_addr = sfs->ns_root };
    int dir_depth, len, nr_match, vec_len, ret = 0, i, j;
    struct ns_lookup_component *curr = components;
    struct ethane_dentry **de = dentries;
    kv_vec_item_t *vec, *lookup_vec;
    const char *component, *next;
    dmptr_t addr;

    dm_mark(sfs->ctx);

    pr_debug("get_possible_dentry_ptrs: %s", full_path);

    dir_depth = ethane_get_dir_depth(full_path);

    /* allocate lookup key vector */
    vec = calloc(1, dir_depth * sizeof(kv_vec_item_t));
    if (unlikely(!vec)) {
        ret = -ENOMEM;
        goto out;
    }

    vec_len = 0;
    ETHANE_ITER_COMPONENTS(full_path, component, next, len) {
        addr = (*de)->remote_addr;
        if (addr != DMPTR_NULL) {
            /* already in cacheFS, we save the remote_addr for parent-filtering */
            curr->possible_vals[0].dentry_remote_addr = addr;
            curr->possible_vals[0].filename_len = len;
            curr->possible_vals[0].parent = (*de)->parent;
            curr++;
            de++;

            pr_debug("cached in cachefs: %.*s", (int) len, component);

            continue;
        }
        de++;

        /* not cached, put into lookup vector */
        vec[vec_len].key = full_path;
        vec[vec_len].key_len = component + len - full_path;

        curr->vec = &vec[vec_len++];
        curr++;

        pr_debug("not cached in cachefs: %.*s, ready to remote lookup", (int) len, component);
    }

    /* do lookup */
    lookup_vec = vec;
    if (vec[0].key_len == 0) {
        /* root dentry, we can get its address directly from sharedFS metadata */
        vec[0].possible_vals[0] = &ns_root_val;
        lookup_vec++;
        vec_len--;
    }

    nr_match = kv_get_batch_approx(sfs->ns_kv, vec_len, lookup_vec);
    if (unlikely(nr_match < 0)) {
        ret = -EIO;
        goto out_free;
    }

    /* copy value to ns_lookup_component */
    for (i = 0; i < dir_depth; i++) {
        curr = &components[i];

        if (!curr->vec) {
            continue;
        }

        for (j = 0; j < KV_NR_POSSIBLE_VALS; j++) {
            if (!curr->vec->possible_vals[j]) {
                continue;
            }

            curr->possible_vals[j] = *(struct ns_kv_val *) curr->vec->possible_vals[j];
        }
    }

out_free:
    free(vec);

out:
    dm_pop(sfs->ctx);
    return ret;
}

static void filter_by_parent_ptr(sharedfs_t *sfs, int dir_depth, struct ns_lookup_component *components) {
    dmptr_t possible_parents[KV_NR_POSSIBLE_VALS] = { DMPTR_NULL };
    struct ns_kv_val *possible_val;
    int i, j, k;
    bool match;

    pr_debug("filter_by_parent_ptr");

    for (i = 0; i < dir_depth; i++) {
        if (!components[i].vec) {
            /* this is cached result, must be precise */
            memset(possible_parents, 0, sizeof(possible_parents));
            possible_parents[0] = components[i].possible_vals[0].dentry_remote_addr;
            pr_debug("component %d in cachefs", i);
            continue;
        }

        for (j = 0; j < KV_NR_POSSIBLE_VALS; j++) {
            possible_val = &components[i].possible_vals[j];
            if (possible_val->dentry_remote_addr == DMPTR_NULL) {
                continue;
            }

            match = false;
            for (k = 0; k < KV_NR_POSSIBLE_VALS; k++) {
                if (possible_val->parent == possible_parents[k]) {
                    match = true;
                    break;
                }
                pr_debug("component %d possible value %d parent %d not match, %lx != %lx",
                         i, j, k, possible_val->parent, possible_parents[k]);
            }

            if (!match) {
                components[i].possible_vals[j].dentry_remote_addr = DMPTR_NULL;
                possible_parents[j] = DMPTR_NULL;
                pr_debug("component %d possible value %d not match", i, j);
            } else {
                possible_parents[j] = possible_val->dentry_remote_addr;
                pr_debug("component %d possible value %d match", i, j);
            }
        }
    }
}

static int get_possible_dentries(sharedfs_t *sfs, int dir_depth, struct ns_lookup_component *components) {
    struct ns_kv_val *possible_val;
    size_t read_size;
    int i, j, ret;

    pr_debug("get_possible_dentries");

    for (i = 0; i < dir_depth; i++) {
        for (j = 0; j < KV_NR_POSSIBLE_VALS; j++) {
            possible_val = &components[i].possible_vals[j];
            if (possible_val->dentry_remote_addr == DMPTR_NULL) {
                continue;
            }

            read_size = sizeof(struct ethane_dentry) + possible_val->filename_len + 1;

            components[i].possible_dentries[j] = dm_push(sfs->ctx, NULL, read_size);
            if (unlikely(!components[i].possible_dentries[j])) {
                ret = -ENOMEM;
                goto out;
            }

            ret = dm_copy_from_remote(sfs->ctx, components[i].possible_dentries[j],
                                      possible_val->dentry_remote_addr, read_size, 0);
            if (unlikely(ret < 0)) {
                goto out;
            }
        }
    }

    ret = dm_wait_ack(sfs->ctx, dm_set_ack_all(sfs->ctx));
    if (unlikely(ret < 0)) {
        goto out;
    }

out:
    return ret;
}

static inline void do_pathname_lookup(sharedfs_t *sfs, struct ns_lookup_component *components, const char *full_path,
                                      struct ethane_dentry **dentries) {
    struct ethane_dentry *possible_de;
    const char *component, *next;
    dmptr_t parent = DMPTR_NULL;
    int i, len;
    bool found;

    pr_debug("do_pathname_lookup: %s", full_path);

    ETHANE_ITER_COMPONENTS(full_path, component, next, len) {
        found = false;

        for (i = 0; i < KV_NR_POSSIBLE_VALS; i++) {
            possible_de = components->possible_dentries[i];
            if (!possible_de) {
                continue;
            }

            pr_debug("parent=%lx,expected_parent=%lx,filename=%s,expected_filename=%.*s",
                     components->possible_vals[i].parent, parent, possible_de->filename, (int) len, component);

            if (components->possible_vals[i].parent == parent &&
                strlen(possible_de->filename) == len &&
                !strncmp(possible_de->filename, component, len)) {
                **(dentries++) = *possible_de;
                parent = possible_de->remote_addr;
                found = true;
                pr_debug("match %.*s (%s)", (int) len, component, get_de_ty_str(possible_de->type));
                break;
            }
        }

        if (unlikely(!found)) {
            break;
        }

        components++;
    }
}

int sharedfs_ns_get_dentry(sharedfs_t *sfs, dmptr_t remote_dentry_addr, struct ethane_dentry *dentry,
                           size_t filename_read_len) {
    struct ethane_dentry *de;
    int ret;

    pr_debug("ns_get_dentry: %lx %lu", remote_dentry_addr, sizeof(*de) + filename_read_len);

    dm_mark(sfs->ctx);

    de = dm_push(sfs->ctx, NULL, sizeof(*de) + filename_read_len);

    ret = dm_copy_from_remote(sfs->ctx, de, remote_dentry_addr, sizeof(*de) + filename_read_len, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        goto out;
    }

    ret = dm_wait_ack(sfs->ctx, 1);
    if (unlikely(ret < 0)) {
        goto out;
    }

    memcpy(dentry, de, sizeof(*de) + filename_read_len);

    if (unlikely(remote_dentry_addr != dentry->remote_addr)) {
        pr_err("inconsistent remote entry addr: %lx != %lx", remote_dentry_addr, dentry->remote_addr);
    }

out:
    dm_pop(sfs->ctx);
    return ret;
}

int sharedfs_ns_lookup_dentries(sharedfs_t *sfs, const char *full_path, struct ethane_dentry **dentries) {
    struct ns_lookup_component *components;
    int ret, depth;

    pr_debug("sharedfs_ns_lookup_dentries: %s", full_path);

    depth = ethane_get_dir_depth(full_path);
    components = calloc(1, sizeof(*components) * depth);
    if (unlikely(!components)) {
        ret = -ENOMEM;
        goto out;
    }

    ret = get_possible_dentry_ptrs(sfs, components, full_path, dentries);
    if (unlikely(ret < 0)) {
        goto out_free;
    }

    filter_by_parent_ptr(sfs, depth, components);

    dm_mark(sfs->ctx);

    ret = get_possible_dentries(sfs, depth, components);
    if (unlikely(ret < 0)) {
        goto out_free;
    }

    do_pathname_lookup(sfs, components, full_path, dentries);

    dm_pop(sfs->ctx);

out_free:
    free(components);

out:
    return ret;
}

static int get_extent(sharedfs_t *sfs, struct bm_extent *dst_ext, dmptr_t dentry_remote_addr, int blkn) {
    struct bm_data_section_key keys[sfs->nr_interval_node_sizes];
    kv_vec_item_t vec[sfs->nr_interval_node_sizes];
    struct bm_extent *ext = NULL;
    int i, j, ret;

    dm_mark(sfs->ctx);

    memset(vec, 0, sizeof(vec));

    /* enumerate all the possible interval nodes */
    for (i = 0; i < sfs->nr_interval_node_sizes; i++) {
        keys[i].dentry_remote_addr = dentry_remote_addr;
        keys[i].start_blkn = ALIGN_DOWN(blkn, sfs->interval_node_nr_blks[i]);
        keys[i].nr_blks = sfs->interval_node_nr_blks[i];
        vec[i].key = (const char *) &keys[i];
        vec[i].key_len = sizeof(struct bm_data_section_key);
        pr_debug("get_extent: try[%d]: dentry=%lx blkn=%d nr_blks=%d",
                    i, keys[i].dentry_remote_addr, keys[i].start_blkn, keys[i].nr_blks);
    }

    /* get from data plane KV */
    ret = kv_get_batch_approx(sfs->bm_kv, sfs->nr_interval_node_sizes, vec);
    if (unlikely(ret < 0)) {
        ext = ERR_PTR(ret);
        goto out;
    }

    ret = -ENOMEM;

    /* filter out the possible extents */
    for (i = 0; i < sfs->nr_interval_node_sizes; i++) {
        for (j = 0; j < KV_NR_POSSIBLE_VALS; j++) {
            ext = vec[i].possible_vals[j];
            if (!ext) {
                continue;
            }

            if (ext->dentry_remote_addr == dentry_remote_addr &&
                ext->start_blkn <= blkn && blkn < ext->start_blkn + ext->nr_blks) {
                pr_debug("match ext: dentry=%lx blkn=%d nr_blks=%d",
                         ext->dentry_remote_addr, ext->start_blkn, ext->nr_blks);

                *dst_ext = *ext;

                ret = 0;

                break;
            }

            pr_debug("not match ext: dentry=%lx blkn=%d nr_blks=%d",
                     ext->dentry_remote_addr, ext->start_blkn, ext->nr_blks);
        }
    }

out:
    dm_pop(sfs->ctx);
    return ret;
}

int sharedfs_bm_get_extent(sharedfs_t *sfs, dmptr_t *remote_addr, size_t *size,
                           struct ethane_dentry *dentry, size_t off) {
    int blkn = (int) (off / BLK_SIZE), ret;
    struct bm_extent ext;

    ret = get_extent(sfs, &ext, dentry->remote_addr, blkn);
    if (unlikely(ret < 0)) {
        goto out;
    }

    *remote_addr = ext.blk_remote_addr;
    *size = ext.nr_blks * BLK_SIZE;

out:
    return ret;
}

static void *ns_del_updater(void *del_ctx, void *val) {
    struct ns_kv_val *ns_kv_val = (struct ns_kv_val *) val;
    dmptr_t dentry_remote_addr = (dmptr_t) del_ctx;
    return ns_kv_val->dentry_remote_addr != dentry_remote_addr ? ERR_PTR(-EINVAL) : NULL;
}

int sharedfs_ns_update_batch(sharedfs_t *sfs, int nr_updates, sharedfs_ns_update_record_t *updates) {
    int ret, i, nr_puts = 0, nr_dels = 0, nr_upds;
    sharedfs_ns_update_record_t *update;
    struct ethane_dentry *dentry;
    struct ns_kv_val *vals;
    const char *filename;
    kv_vec_item_t *vec;
    size_t de_size;

    /* A. Deletes */

    vec = calloc(1, nr_updates * sizeof(*vec));
    if (unlikely(!vec)) {
        ret = -ENOMEM;
        goto out;
    }

    /* collect dels */
    for (i = 0; i < nr_updates; i++) {
        if (updates[i].dentry->type == ETHANE_DENTRY_TOMBSTONE && updates[i].dentry->remote_addr) {
            ethane_assert(!updates[i].is_create);
            pr_debug("collected del: %s", updates[i].full_path);
            vec[nr_dels].key = updates[i].full_path;
            vec[nr_dels].key_len = strlen(updates[i].full_path);
            vec[nr_dels].upd_ctx = (void *) updates[i].dentry->remote_addr;
            nr_dels++;
        }
    }

    /* issue dels */
    ret = kv_upd_batch(sfs->ns_kv, nr_dels, vec, ns_del_updater);
    if (unlikely(ret < 0)) {
        goto out_free;
    }

    /* B. Updates (inserts also include here) */
    dm_mark(sfs->ctx);

    nr_upds = 0;

    for (i = 0; i < nr_updates; i++) {
        update = &updates[i];

        /* deletion */
        if (update->dentry->type == ETHANE_DENTRY_TOMBSTONE) {
            continue;
        }

        filename = ethane_get_filename(update->full_path);
        de_size = sizeof(*dentry) + strlen(filename) + 1;
        dentry = dm_push(sfs->ctx, NULL, de_size);
        memcpy(dentry, update->dentry, sizeof(*dentry));
        strcpy(dentry->filename, filename);

        pr_debug("collected upd/ins: %s(%s), de_size=%lu, raddr=%lx, type=%s",
                 update->full_path, filename, de_size, dentry->remote_addr, get_de_ty_str(dentry->type));

        /* update the dentry */
        ret = dm_copy_to_remote(sfs->ctx, update->dentry->remote_addr, dentry, de_size, 0);
        if (unlikely(ret < 0)) {
            goto out_free;
        }

        /* No wait for ack here to gain more parallelism for normal cases. */
        if (++nr_upds % sfs->nr_max_outstanding_updates == 0) {
            ret = dm_wait_ack(sfs->ctx, dm_set_ack_all(sfs->ctx));
            if (unlikely(ret < 0)) {
                goto out_free;
            }

            dm_pop(sfs->ctx);
            dm_mark(sfs->ctx);
        }
    }

    ret = dm_wait_ack(sfs->ctx, dm_set_ack_all(sfs->ctx));
    if (unlikely(ret < 0)) {
        goto out_free;
    }

    dm_pop(sfs->ctx);

    /* C. Inserts */
    vals = malloc(nr_updates * sizeof(*vals));
    if (unlikely(!vals)) {
        ret = -ENOMEM;
        goto out_free;
    }

    /* collect puts */
    for (i = 0; i < nr_updates; i++) {
        update = &updates[i];

        if (!update->is_create) {
            continue;
        }

        ethane_assert(update->dentry->type != ETHANE_DENTRY_TOMBSTONE);

        vals[i].dentry_remote_addr = update->dentry->remote_addr;
        vals[i].filename_len = strlen(ethane_get_filename(update->full_path));
        vals[i].parent = update->dentry->parent;
        ethane_assert(update->dentry->parent != DMPTR_NULL);

        pr_debug("collected insert %s, dentry: %lx, parent: %lx",
                 update->full_path, vals[i].dentry_remote_addr, vals[i].parent);

        vec[nr_puts].key = update->full_path;
        vec[nr_puts].key_len = strlen(update->full_path);
        vec[nr_puts].val = &vals[i];

        nr_puts++;
    }

    /* issue puts */
    ret = kv_put_batch(sfs->ns_kv, nr_puts, vec);
    if (unlikely(ret < 0)) {
        goto out_free;
    }

    free(vals);

out_free:
    free(vec);

out:
    return ret;
}

static void *bm_updater(void *upd_ctx, void *val) {
    sharedfs_bm_update_record_t *upd = (sharedfs_bm_update_record_t *) upd_ctx;
    struct bm_extent *ext = (struct bm_extent *) val;

    if (ext->dentry_remote_addr == upd->dentry_remote_addr && ext->start_blkn == upd->loff / BLK_SIZE) {
        pr_debug("bm update: dentry=%lx blkn=%lx old_blk=%lx new_blk=%lx",
                 upd->dentry_remote_addr, upd->loff / BLK_SIZE,
                 ext->blk_remote_addr, upd->blk_remote_addr);
        ext->blk_remote_addr = upd->blk_remote_addr;
        return ext;
    }

    return ERR_PTR(-EINVAL);
}

int sharedfs_bm_update_batch(sharedfs_t *sfs, int nr_updates, sharedfs_bm_update_record_t *updates) {
    kv_vec_item_t vec[nr_updates], new_vec[nr_updates];
    struct bm_data_section_key keys[nr_updates];
    struct bm_data_section vals[nr_updates];
    int i, ret, cnt;

    memset(vec, 0, sizeof(vec));
    memset(new_vec, 0, sizeof(new_vec));

    /* enumerate all the possible interval nodes */
    for (i = 0; i < nr_updates; i++) {
        keys[i].dentry_remote_addr = updates[i].dentry_remote_addr;
        keys[i].start_blkn = (int) (updates[i].loff / BLK_SIZE);
        /* FIXME: */
        ethane_assert(updates[i].size == IO_SIZE && updates[i].loff % IO_SIZE == 0);
        keys[i].nr_blks = IO_SIZE / BLK_SIZE;
        vec[i].key = (const char *) &keys[i];
        vec[i].key_len = sizeof(struct bm_data_section_key);
        vec[i].upd_ctx = &updates[i];
    }

    /* try update */
    ret = kv_upd_batch(sfs->bm_kv, nr_updates, vec, bm_updater);
    if (unlikely(ret < 0)) {
        goto out;
    }

    /* process new entries */
    cnt = 0;

    for (i = 0; i < nr_updates; i++) {
        if (vec[i].err != -ENOENT) {
            continue;
        }

        vals[i].ext.dentry_remote_addr = updates[i].dentry_remote_addr;
        vals[i].ext.start_blkn = (int) (updates[i].loff / BLK_SIZE);
        vals[i].ext.nr_blks = IO_SIZE / BLK_SIZE;
        vals[i].ext.blk_remote_addr = updates[i].blk_remote_addr;
        vec[i].val = &vals[i];
        new_vec[cnt++] = vec[i];

        pr_debug("bm insert: dentry=%lx blkn=%lx blk=%lx", updates[i].dentry_remote_addr,
                 updates[i].loff / BLK_SIZE, updates[i].blk_remote_addr);
    }

    ret = kv_put_batch(sfs->bm_kv, cnt, new_vec);
    if (unlikely(ret < 0)) {
        goto out;
    }

out:
    return ret;
}

static int ns_dump(void *priv, const void *val) {
    struct ns_kv_val *v = (struct ns_kv_val *) val;
    struct ethane_dentry *de;
    sharedfs_t *rfs = priv;
    int ret;

    de = malloc(sizeof(*de) + v->filename_len);
    if (unlikely(!de)) {
        ret = -ENOMEM;
        goto out;
    }

    ret = sharedfs_ns_get_dentry(rfs, v->dentry_remote_addr, de, v->filename_len);
    if (unlikely(ret < 0)) {
        goto out;
    }

    pr_info("de dentry: %lx(%s); filename: %.*s; size: %lu; parent: %lx",
            v->dentry_remote_addr, get_de_ty_str(de->type),
            (int) v->filename_len, de->filename, de->file_size, v->parent);

    free(de);

out:
    return ret;
}

static int bm_dump(void *priv, const void *val) {
    struct bm_data_section *v = (struct bm_data_section *) val;
    pr_info("bm dentry: %lx; start_blkn: %d; nr_blks: %d; blk: %lx",
            v->ext.dentry_remote_addr, v->ext.start_blkn, v->ext.nr_blks, v->ext.blk_remote_addr);
    return 0;
}

int sharedfs_dump(sharedfs_t *rfs) {
    int ret;

    pr_info("scan ns kv");
    ret = kv_scan(rfs->ns_kv, ns_dump, rfs);
    if (unlikely(ret < 0)) {
        goto out;
    }

    pr_info("scan bm kv");
    ret = kv_scan(rfs->bm_kv, bm_dump, rfs);
    if (unlikely(ret < 0)) {
        goto out;
    }

out:
    return ret;
}
