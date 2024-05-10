/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Data-Plane Key-Value Interface
 * The data-plane key-value supports:
 * (1) Concurrent read/write
 * (2) Concurrent writes **across** shards
 * (3) Non-concurrent writes **within** a shard
 * (read=get, write=put/(get+del))
 *
 * Hohai University
 */

#include <errno.h>

#include "dmlocktab.h"
#include "tabhash.h"
#include "trace.h"
#include "debug.h"
#include "coro.h"
#include "rand.h"
#include "kv.h"

#include <prom_collector_registry.h>
#include <prom_histogram.h>

#define DUMP_SHOW_PROGRESS_INTERVAL_US      2000000

#define STAT_GET_INTERVAL   32

#define LAT_HIST_BUCKETS   16, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 100.0, 125.0, 150.0, 175.0, 200.0, 250.0, 300.0, 400.0

struct slot_hdr {
    bool used : 1;
    int ver : 31;
    /* Position in another hash table */
    uint32_t pair_pos;
};

struct kv_info {
    size_t ht_nr_ents;
    size_t val_len;
    int nr_shards;
    TAB_hash hf[2];
    TAB_hash shard_hf;
    dmptr_t ht[];
};

struct kv {
    dmcontext_t *ctx;
    dmm_cli_t *dmm;
    dmlocktab_t *locktab;

    /* Hash tables and hash functions */
    dmptr_t *ht[2];
    TAB_hash hf[2];
    TAB_hash shard_hf;

    size_t ht_nr_ents;
    size_t val_len;
    size_t slot_len;
    int interleave_nr;

    int nr_shards;

    size_t ht_nr_ents_per_shard;

    unsigned int rnd_seed;

    int nr_max_outstanding_reqs;

    int nr_get_reqs;

    char label[64];
};

dmptr_t kv_create(dmcontext_t *ctx, dmm_cli_t *dmm, size_t size, size_t val_len, int nr_shards) {
    size_t ht_nr_ents, slot_len, info_size;
    dmptr_t kv_info_remote_addr, *ht;
    struct kv_info *info;
    TAB_generator gen;
    int i, ret;

    info_size = sizeof(*info) + 2 * dmm_get_interleave_nr(dmm) * sizeof(dmptr_t);

    info = dm_push(ctx, NULL, info_size);
    if (unlikely(!info)) {
        kv_info_remote_addr = PTR_ERR(-ENOMEM);
        goto out;
    }

    info->val_len = val_len;
    info->nr_shards = nr_shards;

    slot_len = val_len + sizeof(struct slot_hdr);
    ht_nr_ents = DIV_ROUND_UP(size, slot_len) / 2;
    info->ht_nr_ents = ht_nr_ents;

    ethane_assert(ht_nr_ents % nr_shards == 0);

    /* TODO: handle cacheline-unaligned case */
    ethane_assert(slot_len % 64 == 0 || 64 % slot_len == 0);

    /* alloc and clear hash table blocks */
    for (i = 0; i < 2; i++) {
        ht = info->ht + i * dmm_get_interleave_nr(dmm);
        dmm_balloc_interleaved(dmm, ht, ht_nr_ents * slot_len, 0);
        dmm_bzero_interleaved(dmm, ht, ht_nr_ents * slot_len, true);
    }

    /* init two (nearly) independent hash functions */
    TAB_init_generator(&gen, TAB_DEFAULT_SEED);
    for (i = 0; i < 2; i++) {
        TAB_init_hash(&info->hf[i], &gen, i);
    }
    TAB_init_hash(&info->shard_hf, &gen, 2);

    /* allocate kv_info page */
    kv_info_remote_addr = dmm_balloc(dmm, ALIGN_UP(info_size, BLK_SIZE), BLK_SIZE, 0);
    if (unlikely(IS_ERR(kv_info_remote_addr))) {
        goto out;
    }

    /* write back */
    ret = dm_copy_to_remote(ctx, kv_info_remote_addr, info, info_size, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        kv_info_remote_addr = ret;
        goto out;
    }

    /* wait for data write completion */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        kv_info_remote_addr = ret;
        goto out;
    }

    pr_info("created");

out:
    return kv_info_remote_addr;
}

static prom_histogram_t *prom_get_latency;

void ethanefs_kv_init_global() {
    prom_get_latency = prom_histogram_new("ethanefs_kv_get_latency",
                                          "ethanefs_kv_get_latency",
                                          prom_histogram_buckets_new(LAT_HIST_BUCKETS),
                                          1, (const char *[]) { "cli_id" });

    prom_collector_registry_must_register_metric(prom_get_latency);
}

kv_t *kv_init(const char *name, dmcontext_t *ctx, dmm_cli_t *dmm, dmlocktab_t *locktab,
              dmptr_t kv_info_remote_addr, int nr_max_outstanding_reqs) {
    struct kv_info *info;
    size_t info_size;
    int i, ret;
    kv_t *kv;

    info_size = sizeof(*info) + 2 * dmm_get_interleave_nr(dmm) * sizeof(dmptr_t);

    info = dm_push(ctx, NULL, info_size);
    if (unlikely(!info)) {
        return NULL;
    }

    /* read kv_info page */
    ret = dm_copy_from_remote(ctx, info, kv_info_remote_addr, info_size, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        return NULL;
    }

    /* wait for data read completion */
    ret = dm_wait_ack(ctx, 1);
    if (unlikely(ret < 0)) {
        return NULL;
    }

    kv = calloc(1, sizeof(kv_t));
    if (unlikely(!kv)) {
        return NULL;
    }

    kv->ctx = ctx;
    kv->dmm = dmm;
    kv->locktab = locktab;
    kv->ht_nr_ents = info->ht_nr_ents;
    kv->val_len = info->val_len;
    kv->slot_len = kv->val_len + sizeof(struct slot_hdr);
    memcpy(kv->hf, info->hf, sizeof(info->hf));
    memcpy(&kv->shard_hf, &info->shard_hf, sizeof(info->shard_hf));

    /* allocate hash tables in an interleaved manner (to gain parallelism) */
    kv->interleave_nr = dmm_get_interleave_nr(dmm);

    for (i = 0; i < 2; i++) {
        kv->ht[i] = malloc(kv->interleave_nr * sizeof(dmptr_t));
        if (unlikely(!kv->ht[i])) {
            return NULL;
        }

        memcpy(kv->ht[i], info->ht + i * kv->interleave_nr, kv->interleave_nr * sizeof(dmptr_t));
    }

    kv->nr_shards = info->nr_shards;

    ethane_assert(kv->ht_nr_ents % kv->nr_shards == 0);
    kv->ht_nr_ents_per_shard = kv->ht_nr_ents / kv->nr_shards;

    kv->nr_max_outstanding_reqs = nr_max_outstanding_reqs;

    kv->rnd_seed = get_rand_seed();

    sprintf(kv->label, "cli%06d", dm_get_cli_id(ctx));

    pr_info("init done: kv=%s,entn=%lu,shardn=%d", name, kv->ht_nr_ents, kv->nr_shards);

    return kv;
}

static inline uint32_t get_pos_by_hash(kv_t *kv, uint64_t hash) {
    return hash % kv->ht_nr_ents_per_shard;
}

static inline dmptr_t loc_by_pos(kv_t *kv, dmptr_t *ht, uint32_t pos, int shard) {
    size_t start, off;
    start = shard * kv->ht_nr_ents_per_shard * kv->slot_len;
    off = pos * kv->slot_len;
    return dmm_get_ptr_interleaved(kv->dmm, ht, kv->ht_nr_ents * kv->slot_len, start + off);
}

static inline int get_key_shard(kv_t *kv, const char *key, size_t key_len) {
    uint64_t hash;
    hash = TAB_finalize(&kv->shard_hf, TAB_process(&kv->shard_hf, (const uint8_t *) key, key_len, 0));
    return (int) (hash % kv->nr_shards);
}

static int kv_put_at(kv_t *kv, int dst_ht, uint32_t dst_pos, uint32_t pair_pos,
                     const char *root_key, const void *val, int shard) {
    struct slot_hdr *dst_slot_hdr, new_dst_slot_hdr;
    uint32_t dst_pair_slot_pos;
    dmptr_t dst_slot_addr;
    int ret, cli_id;
    void *buf;

    dst_slot_hdr = buf = dm_push(kv->ctx, NULL, kv->slot_len);
    if (unlikely(!buf)) {
        ret = -ENOMEM;
        goto out;
    }

    dst_slot_addr = loc_by_pos(kv, kv->ht[dst_ht], dst_pos, shard);

    /* read the original slot */
    ret = dm_copy_from_remote(kv->ctx, dst_slot_hdr, dst_slot_addr, kv->slot_len, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        pr_err("kv_put: failed to read data");
        goto out;
    }

    /* wait for data read completion */
    ret = dm_wait_ack(kv->ctx, 1);
    if (unlikely(ret < 0)) {
        pr_err("kv_put: failed to wait for data read completion");
        goto out;
    }

    /* kick out if used */
    if (unlikely(dst_slot_hdr->used)) {
        dst_pair_slot_pos = dst_slot_hdr->pair_pos;

        ret = kv_put_at(kv, 1 - dst_ht, dst_pair_slot_pos, dst_pos, root_key, dst_slot_hdr + 1, shard);
        if (unlikely(ret < 0)) {
            pr_err("kv_put: failed to put data");
            goto out;
        }
    }

    /* prepare new slot hdr */
    new_dst_slot_hdr.used = true;
    new_dst_slot_hdr.ver = dst_slot_hdr->ver + 1;
    new_dst_slot_hdr.pair_pos = pair_pos;

    memcpy(buf, &new_dst_slot_hdr, sizeof(new_dst_slot_hdr));
    memcpy(buf + sizeof(new_dst_slot_hdr), val, kv->val_len);

    /* atomic put */
    ret = dm_copy_to_remote(kv->ctx, dst_slot_addr, buf, kv->slot_len, DMFLAG_ACK);
    if (unlikely(ret < 0)) {
        pr_err("kv_put: failed to write data");
        goto out;
    }

    /* wait for data write completion */
    ret = dm_wait_ack(kv->ctx, 1);
    if (unlikely(ret < 0)) {
        pr_err("kv_put: failed to wait for data write completion");
        goto out;
    }

    cli_id = dm_get_cli_id(kv->ctx);
    tracepoint_sample(ethane, kv_put_at, cli_id, shard, root_key, dst_ht, dst_pos, pair_pos);

out:
    return ret;
}

static int kv_put_single(kv_t *kv, kv_vec_item_t *item) {
    int i, dst_ht, shard, ret, cli_id;
    uint32_t poses[2];
    const char *key;
    const void *val;
    size_t key_len;
    char *dup;

    key = item->key;
    key_len = item->key_len;
    val = item->val;

    dup = strndup(key, key_len);

    shard = get_key_shard(kv, key, key_len);

    /* compute hashes and poses */
    for (i = 0; i < KV_NR_POSSIBLE_VALS; i++) {
        poses[i] = get_pos_by_hash(kv, TAB_finalize(&kv->hf[i],
                                                    TAB_process(&kv->hf[i], (const uint8_t *) key, key_len, 0)));
    }

    /* choose dst table */
    dst_ht = rand_r(&kv->rnd_seed) % 2;

    dmlock_acquire(kv->locktab, shard);

    /* put into dst table */
    ret = kv_put_at(kv, dst_ht, poses[dst_ht], poses[1 - dst_ht], dup, val, shard);
    if (unlikely(ret < 0)) {
        pr_err("kv_put: failed to put data");
        goto out;
    }

    dmlock_release(kv->locktab, shard);

    item->err = 0;

    cli_id = dm_get_cli_id(kv->ctx);
    tracepoint_sample(ethane, kv_op, cli_id, shard, TRACE_KV_OP_PUT, dup, poses[0], poses[1]);

out:
    free(dup);
    return ret;
}

int kv_put_batch(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec) {
    int i, ret = 0;
    for (i = 0; i < vec_len; i++) {
        ret = kv_put_single(kv, kv_vec + i);
        if (unlikely(ret < 0)) {
            goto out;
        }
    }
out:
    return ret;
}

static int kv_upd_single(kv_t *kv, kv_vec_item_t *item, void *(*updater)(void *, void *)) {
    dmptr_t hdr_addr, addrs[2], poses[2];
    int ret, shard, i, cli_id;
    struct slot_hdr *hdr[2];
    const char *key;
    size_t key_len;
    uint64_t hash;
    void *update;
    char *dup;

    key = item->key;
    key_len = item->key_len;

    shard = get_key_shard(kv, key, key_len);

    pr_debug("kv_upd: shard=%d key=%.*s", shard, (int) key_len, key);

    /* Hash calculation */
    for (i = 0; i < 2; i++) {
        hash = TAB_finalize(&kv->hf[i],
                            TAB_process(&kv->hf[i], (const uint8_t *) key, key_len, 0));
        poses[i] = get_pos_by_hash(kv, hash);
        addrs[i] = loc_by_pos(kv, kv->ht[i], poses[i], shard);
    }

    dmlock_acquire(kv->locktab, shard);

    for (i = 0; i < 2; i++) {
        hdr[i] = dm_push(kv->ctx, NULL, kv->slot_len);
        if (unlikely(!hdr[i])) {
            ret = -ENOMEM;
            goto out;
        }

        ret = dm_copy_from_remote(kv->ctx, hdr[i], addrs[i], kv->slot_len, 0);
        if (unlikely(ret < 0)) {
            goto out;
        }
    }

    ret = dm_wait_ack(kv->ctx, dm_set_ack_all(kv->ctx));
    if (unlikely(ret < 0)) {
        goto out;
    }

    item->err = -ENOENT;

    for (i = 0; i < 2; i++) {
        if (!hdr[i]->used) {
            continue;
        }

        hdr_addr = addrs[i];

        update = updater(item->upd_ctx, hdr[i] + 1);
        if (update == ERR_PTR(-EINVAL)) {
            pr_debug("kv_upd: %d not match", i);
            continue;
        }

        if (!update) {
             /* do delete (clear the slot header word) */
            ret = dm_write(kv->ctx, hdr_addr, (struct slot_hdr) { .used = false }, DMFLAG_ACK);
            pr_debug("kv_upd: %d do delete", i);
        } else {
            /* do update */
            ret = dm_copy_to_remote(kv->ctx, hdr_addr + sizeof(struct slot_hdr), hdr[i] + 1, kv->val_len, DMFLAG_ACK);
            pr_debug("kv_upd: %d do update", i);
        }
        if (unlikely(ret < 0)) {
            pr_err("kv_del: failed to delete data");
            goto out;
        }

        /* wait for data write completion */
        ret = dm_wait_ack(kv->ctx, 1);
        if (unlikely(ret < 0)) {
            pr_err("kv_del: failed to wait for data write completion");
            goto out;
        }

        item->err = 0;

        break;
    }

    dmlock_release(kv->locktab, shard);

    cli_id = dm_get_cli_id(kv->ctx);
    dup = strndup(key, key_len);
    tracepoint_sample(ethane, kv_op, cli_id, shard, TRACE_KV_OP_UPD, dup, poses[0], poses[1]);
    free(dup);

out:
    return ret;
}

int kv_upd_batch(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec, void *(*updater)(void *, void *)) {
    int i, ret = 0;
    for (i = 0; i < vec_len; i++) {
        ret = kv_upd_single(kv, kv_vec + i, updater);
        if (unlikely(ret < 0)) {
            goto out;
        }
    }
out:
    return ret;
}

static int do_kv_get_batch_approx(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec) {
    struct slot_hdr *hdr1[vec_len][2], *hdr2[vec_len][2];
    int i, j, shard, ret = 0, valid_cnt = 0, rnd;
    dmptr_t addrs[vec_len][2];
    bool valid[vec_len];
    kv_vec_item_t *item;
    uint64_t hash;

    /* It's caller's responsibility to mark and pop buffer! */

    memset(valid, 0, sizeof(valid));

    /* Hash calculation */
    for (i = 0; i < vec_len; i++) {
        item = &kv_vec[i];

        for (j = 0; j < 2; j++) {
            hash = TAB_finalize(&kv->hf[j],
                                TAB_process(&kv->hf[j], (const uint8_t *) item->key, item->key_len, 0));
            shard = get_key_shard(kv, item->key, item->key_len);
            addrs[i][j] = loc_by_pos(kv, kv->ht[j], get_pos_by_hash(kv, hash), shard);

            pr_debug("vec[%d]: HT%d: hash=%lu shard=%d hdr_addr=%lx", i, j, hash, shard, addrs[i][j]);
        }
    }

    /*
     * Repeat until no version mismatch.
     */
    for (rnd = 0; valid_cnt < vec_len; rnd++) {
        pr_debug("rnd %d", rnd);

        /* Issue the first read */
        for (i = 0; i < vec_len; i++) {
            if (valid[i]) {
                continue;
            }

            item = &kv_vec[i];

            for (j = 0; j < 2; j++) {
                hdr1[i][j] = dm_push(kv->ctx, NULL, kv->slot_len);

                item->possible_vals[j] = hdr1[i][j] + 1;

                ret = dm_copy_from_remote(kv->ctx, hdr1[i][j], addrs[i][j], kv->slot_len, 0);
                if (unlikely(ret < 0)) {
                    goto out;
                }

                pr_debug("vec[%d] get from HT[%d], hdr_remote_addr=%lx", i, j, addrs[i][j]);
            }
        }

        ret = dm_wait_ack(kv->ctx, dm_set_ack_all(kv->ctx));
        if (unlikely(ret < 0)) {
            goto out;
        }

        /* Issue the second read */
        for (i = 0; i < vec_len; i++) {
            if (valid[i]) {
                continue;
            }

            for (j = 0; j < 2; j++) {
                hdr2[i][j] = dm_push(kv->ctx, NULL, sizeof(struct slot_hdr));

                ret = dm_copy_from_remote(kv->ctx, hdr2[i][j], addrs[i][j], sizeof(struct slot_hdr), 0);
                if (unlikely(ret < 0)) {
                    goto out;
                }
            }
        }

        ret = dm_wait_ack(kv->ctx, dm_set_ack_all(kv->ctx));
        if (unlikely(ret < 0)) {
            goto out;
        }

        /* Check version match */
        for (i = 0; i < vec_len; i++) {
            if (valid[i]) {
                continue;
            }

            /*
             * The version checking mechanism is used to ensure that no concurrent modifications
             * between reading two slots of a key. It works as follows:
             * (1) Read two slots, and their version number u1, u2
             * (2) Read version number again v1, v2
             * If u1 == v1 && u2 == v2, it's guaranteed that no concurrent modifications to these
             * slots.
             */
            if (hdr1[i][0]->ver == hdr2[i][0]->ver && hdr1[i][1]->ver == hdr2[i][1]->ver) {
                valid[i] = true;
                valid_cnt++;
            } else {
                pr_debug("version mismatch: vec[%d] hdr1[0]=%d hdr2[0]=%d hdr1[1]=%d hdr2[1]=%d",
                         i, hdr1[i][0]->ver, hdr2[i][0]->ver, hdr1[i][1]->ver, hdr2[i][1]->ver);
            }
        }
    }

    /* filter out those empty slots */
    for (i = 0; i < vec_len; i++) {
        if (!(((unsigned long *) kv_vec[i].possible_vals[1])[-1])) {
            kv_vec[i].possible_vals[1] = NULL;
        }
        if (!(((unsigned long *) kv_vec[i].possible_vals[0])[-1])) {
            kv_vec[i].possible_vals[0] = kv_vec[i].possible_vals[1];
        }
        kv_vec[i].err = 0;
    }

out:
    return ret;
}

int kv_get_batch_approx(kv_t *kv, int vec_len, kv_vec_item_t *kv_vec) {
    int nr_batches, batch_vec_len, i, ret = 0, err;
    struct bench_timer timer;
    long duration;

    pr_debug("kv_get start, vec_len=%d", vec_len);
    pr_debug_lookup_vec(kv_vec, vec_len);

    bench_timer_start(&timer);

    nr_batches = ALIGN_UP(vec_len, kv->nr_max_outstanding_reqs) / kv->nr_max_outstanding_reqs;

    for (i = 0; i < nr_batches; i++) {
        batch_vec_len = min(vec_len, kv->nr_max_outstanding_reqs);

        err = do_kv_get_batch_approx(kv, batch_vec_len, kv_vec);
        if (unlikely(err < 0)) {
            ret = err;
        }

        vec_len -= batch_vec_len;
        kv_vec += batch_vec_len;
    }

    duration = bench_timer_end(&timer);
    if (kv->nr_get_reqs++ % STAT_GET_INTERVAL == 0) {
        prom_histogram_observe(prom_get_latency, duration / 1000.0, (const char *[]) { kv->label });
    }

    return ret;
}

static int kv_scan_range(kv_t *kv, dmptr_t start, size_t size, kv_scanner_t scanner, void *priv, int ht) {
    size_t read_size = 1024 * 1024ul, nr_slots, off, cur_read_size;
    struct bench_timer timer;
    struct slot_hdr *hdr;
    int ret = 0;
    void *buf;

    dm_mark(kv->ctx);

    ethane_assert(size % kv->slot_len == 0);
    ethane_assert(read_size % kv->slot_len == 0);

    buf = dm_push(kv->ctx, NULL, read_size);
    if (unlikely(!buf)) {
        ret = -ENOMEM;
        goto out;
    }

    bench_timer_start(&timer);

    for (off = 0; off < size; off += read_size) {
        cur_read_size = min(read_size, size - off);
        nr_slots = cur_read_size / kv->slot_len;

        ret = dm_copy_from_remote(kv->ctx, buf, start + off, cur_read_size, DMFLAG_ACK);
        if (unlikely(ret < 0)) {
            goto out;
        }

        ret = dm_wait_ack(kv->ctx, 1);
        if (unlikely(ret < 0)) {
            goto out;
        }

        for (int i = 0; i < nr_slots; i++) {
            hdr = buf + i * kv->slot_len;
            if (!hdr->used) {
                continue;
            }

            pr_debug("ht[%d]:%lx", ht, start + off + i * kv->slot_len);

            ret = scanner(priv, hdr + 1);
            if (unlikely(ret)) {
                goto out;
            }
        }

        if (bench_timer_end(&timer) > DUMP_SHOW_PROGRESS_INTERVAL_US * 1000) {
            pr_info("%lu/%lu MB", off / 1024 / 1024, size / 1024 / 1024);
            bench_timer_start(&timer);
        }
    }

out:
    dm_pop(kv->ctx);
    return ret;
}

int kv_scan(kv_t *kv, kv_scanner_t scanner, void *priv) {
    size_t strip_size = dmm_get_strip_size(kv->dmm, kv->ht_nr_ents * kv->slot_len);
    int i, j, ret = 0;
    dmptr_t ht;

    for (i = 0; i < 2; i++) {
        for (j = 0; j < dmm_get_interleave_nr(kv->dmm); j++) {
            pr_info("scanning ht=%d,mn=%d", i, j);
            pr_info("start");
            ht = kv->ht[i][j];
            ret = kv_scan_range(kv, ht, strip_size, scanner, priv, i);
            if (unlikely(ret)) {
                goto out;
            }
        }
    }

out:
    return ret;
}
