/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Disaggregated Persistent Memory Management
 *
 * Hohai University
 */

#include <errno.h>
#include <string.h>

#include "ethane.h"
#include "debug.h"
#include "rand.h"
#include "dmm.h"

#include "avl.h"

#define DMM_BALLOC_RPC_ID    1
#define DMM_BFREE_RPC_ID     2
#define DMM_BZERO_RPC_ID     3
#define DMM_BCLEAR_RPC_ID    4

#define DMM_NR_ISOLATE_MNS   1

struct dmm_mn {
    void *mem_buf;
    size_t size;

    size_t used;
};

struct dmm_cn {
    int *mn_ids, nr_mns;
};

struct free_blk {
    /* [start_addr, end_addr) */
    dmptr_t start_addr, end_addr;
    struct avl_node node;
};

struct free_blk_list {
    int mn_id;

    struct avl_tree free_blks;
    struct free_blk *curr_blk;
};

struct dmm_cli {
    struct dmm_cn *dmm_cn;

    int nr_free_blk_lists;
    struct free_blk_list *free_blk_lists;

    dmcontext_t *ctx;

    unsigned int seed;
};

dmm_mn_t *dmm_mn_init(void *mem_buf, size_t size) {
    dmm_mn_t *dmm;

    dmm = malloc(sizeof(dmm_mn_t));
    if (unlikely(!dmm)) {
        pr_err("dmm_mn_init: cannot allocate dmm struct");
        goto out;
    }

    dmm->mem_buf = mem_buf;
    dmm->size = size;
    dmm->used = BLK_SIZE;

out:
    return dmm;
}

/* FIXME: the MN-side allocator is too naive... */
static size_t do_mn_balloc(dmm_mn_t *dmm, size_t size) {
    size_t offset;

    if (unlikely(dmm->used + size > dmm->size)) {
        pr_err("do_mn_balloc: out of memory");
        return -ENOMEM;
    }

    offset = dmm->used;
    dmm->used += size;

    return offset;
}

static void do_mn_bclear(dmm_mn_t *dmm) {
    dmm->used = BLK_SIZE;
}

static void do_mn_bfree(dmm_mn_t *dmm, dmptr_t addr, size_t size) {
    /* FIXME: TBD */
}

static void do_mn_bzero(dmm_mn_t *dmm, dmptr_t addr, size_t size) {
    memset_nt(dmm->mem_buf + DMPTR_OFF(addr), 0, size);
}

size_t dmm_cb(dmm_mn_t *dmm, void *rv, const void *pr) {
    const size_t *args;
    size_t off;

    args = pr;

    switch (args[0]) {
        case DMM_BALLOC_RPC_ID:
            off = do_mn_balloc(dmm, args[1]);
            memcpy(rv, &off, sizeof(off));
            return sizeof(off);

        case DMM_BFREE_RPC_ID:
            do_mn_bfree(dmm, args[1], args[2]);
            return 0;

        case DMM_BZERO_RPC_ID:
            do_mn_bzero(dmm, args[1], args[2]);
            return 0;

        case DMM_BCLEAR_RPC_ID:
            do_mn_bclear(dmm);
            return 0;

        default:
            break;
    }

    return -EINVAL;
}

dmm_cn_t *dmm_cn_init(dmpool_t *pool) {
    dmm_cn_t *dmm;

    dmm = malloc(sizeof(dmm_cn_t));
    if (unlikely(!dmm)) {
        pr_err("cannot allocate dmm_cn_t");
        return NULL;
    }

    dmm->nr_mns = dm_get_nr_mns(pool);
    dmm->mn_ids = malloc(sizeof(int) * dmm->nr_mns);
    if (unlikely(!dmm->mn_ids)) {
        pr_err("cannot allocate mn_ids");
        free(dmm);
        return NULL;
    }
    dm_get_mns(pool, dmm->mn_ids);

    return dmm;
}

static int cmp_free_blk(const void *a, const void *b) {
    const struct free_blk *fa = a, *fb = b;
    if (fa->start_addr < fb->start_addr) {
        return -1;
    } else if (fa->start_addr > fb->start_addr) {
        return 1;
    } else {
        return 0;
    }
}

static dmptr_t mn_balloc(dmm_cli_t *dmm, int mn_id, size_t size) {
    size_t *args, off;
    int ret;

    args = dm_push(dmm->ctx, NULL, 2 * sizeof(size_t));
    args[0] = DMM_BALLOC_RPC_ID;
    args[1] = size;

    ret = dm_rpc(dmm->ctx, DMPTR_DUMMY(mn_id), args, 2 * sizeof(size_t));
    if (unlikely(ret < 0)) {
        pr_err("dm_rpc failed");
        return ret;
    }
    off = *(size_t *) dm_get_rv(dmm->ctx);

    return DMPTR_MK_PM(mn_id, off);
}

static void mn_bfree(dmm_cli_t *dmm, dmptr_t ptr, size_t size) {
    size_t *args;
    int ret;

    args = dm_push(dmm->ctx, NULL, 3 * sizeof(size_t));
    args[0] = DMM_BFREE_RPC_ID;
    args[1] = ptr;
    args[2] = size;

    ret = dm_rpc(dmm->ctx, ptr, args, 3 * sizeof(size_t));
    if (unlikely(ret < 0)) {
        pr_err("dm_rpc failed");
    }
}

static void mn_bclear(dmm_cn_t *dmm, dmcontext_t *ctx) {
    size_t *args;
    int ret, i;

    args = dm_push(ctx, NULL, 1 * sizeof(size_t));
    args[0] = DMM_BCLEAR_RPC_ID;

    for (i = 0; i < dmm->nr_mns; i++) {
        pr_info("clearing blocks at memory node %d", dmm->mn_ids[i]);
        ret = dm_rpc(ctx, DMPTR_DUMMY(dmm->mn_ids[i]), args, 1 * sizeof(size_t));
        if (unlikely(ret < 0)) {
            pr_err("dmm_bclear: dm_rpc failed");
        }
    }
}

static void mn_bzero(dmm_cli_t *dmm, dmptr_t ptr, size_t size) {
    size_t *args;
    int ret;

    args = dm_push(dmm->ctx, NULL, 3 * sizeof(size_t));
    args[0] = DMM_BZERO_RPC_ID;
    args[1] = ptr;
    args[2] = size;

    ret = dm_rpc(dmm->ctx, ptr, args, 3 * sizeof(size_t));
    if (unlikely(ret < 0)) {
        pr_err("dm_rpc failed");
    }
}

/*
 * TODO: The allocation implementation is too naive
 */
dmm_cli_t *dmm_cli_init(dmm_cn_t *dmm_cn, dmcontext_t *ctx, size_t init_pool_size) {
    size_t pool_size_per_mn = init_pool_size / dmm_cn->nr_mns;
    struct free_blk *initial_free_blk;
    struct free_blk_list *list;
    dmm_cli_t *dmm;
    int i;

    dmm = malloc(sizeof(dmm_cli_t));
    if (unlikely(!dmm)) {
        pr_err("dmm_cli_init: cannot allocate dmm_cli_t");
        return NULL;
    }

    dmm->dmm_cn = dmm_cn;
    dmm->ctx = ctx;

    dmm->nr_free_blk_lists = dmm_cn->nr_mns;
    dmm->free_blk_lists = malloc(sizeof(struct free_blk_list) * dmm_cn->nr_mns);
    if (unlikely(!dmm->free_blk_lists)) {
        pr_err("dmm_cli_init: cannot allocate free_blk_lists");
        return NULL;
    }
    for (i = 0; i < dmm_cn->nr_mns; i++) {
        list = &dmm->free_blk_lists[i];

        list->mn_id = dmm_cn->mn_ids[i];

        avl_tree_init(&list->free_blks, cmp_free_blk, sizeof(struct free_blk), offsetof(struct free_blk, node));

        initial_free_blk = malloc(sizeof(struct free_blk));
        if (unlikely(!initial_free_blk)) {
            pr_err("dmm_mn_init: cannot allocate initial free block");
            return NULL;
        }
        initial_free_blk->start_addr = mn_balloc(dmm, dmm_cn->mn_ids[i], pool_size_per_mn);
        initial_free_blk->end_addr = initial_free_blk->start_addr + pool_size_per_mn;
        avl_tree_add(&list->free_blks, initial_free_blk);

        list->curr_blk = initial_free_blk;
    }

    dmm->seed = get_rand_seed();

    return dmm;
}

static inline dmptr_t balloc_from(struct free_blk_list *list, dmptr_t new_start, size_t size, struct free_blk *blk) {
    dmptr_t new_end = new_start + size;
    struct free_blk *right_blk;

    if (new_start == blk->start_addr && new_end == blk->end_addr) {
        /* case 1: allocate the whole block */
        list->curr_blk = avl_tree_next(&list->free_blks, blk);
        avl_tree_remove(&list->free_blks, blk);
        free(blk);
        goto out;
    }

    if (new_start == blk->start_addr) {
        /* case 2: allocate from the start of the block, but not the whole block */
        blk->start_addr = new_end;
        goto out;
    }

    if (new_end == blk->end_addr) {
        /* case 3: allocate from the end of the block, but not the whole block */
        blk->end_addr = new_start;
        goto out;
    }

    /* case 4: allocate from the middle of the block, split the block */
    right_blk = malloc(sizeof(struct free_blk));
    if (unlikely(!right_blk)) {
        pr_err("balloc_from: cannot allocate right free block");
        new_start = -ENOMEM;
        goto out;
    }
    right_blk->start_addr = new_end;
    right_blk->end_addr = blk->end_addr;
    blk->end_addr = new_start;
    avl_tree_add(&list->free_blks, right_blk);

out:
    return new_start;
}

static dmptr_t do_balloc(struct free_blk_list *list, size_t size, size_t align) {
    struct free_blk *blk;
    dmptr_t start;

    if (unlikely(!list->curr_blk)) {
        goto fail;
    }

    blk = list->curr_blk;
    do {
        start = (blk->start_addr + align - 1) & ~(align - 1);

        if (blk->end_addr >= start + size) {
            return balloc_from(list, start, size, blk);
        }

        blk = avl_tree_next(&list->free_blks, blk);
        if (unlikely(!blk)) {
            blk = avl_tree_first(&list->free_blks);
        }
    } while (blk != list->curr_blk);

fail:
    return -ENOMEM;
}

/* TODO: implement the power of two load balancing */
static inline struct free_blk_list *auto_choose_list(dmm_cli_t *dmm) {
    /* Note that we do not choose isolated MNs automatically. */
    int chosen = rand_r(&dmm->seed) % (dmm->nr_free_blk_lists - DMM_NR_ISOLATE_MNS);
    return &dmm->free_blk_lists[chosen];
}

static inline struct free_blk_list *get_list(dmm_cli_t *dmm, int mn_id) {
    struct free_blk_list *list;
    for (int i = 0; i < dmm->nr_free_blk_lists; i++) {
        list = &dmm->free_blk_lists[i];
        if (list->mn_id == mn_id) {
            return list;
        }
    }
    return NULL;
}

dmptr_t dmm_balloc(dmm_cli_t *dmm, size_t size, size_t align, dmptr_t locality_hint) {
    struct free_blk_list *list;
    if (!align) {
        align = BLK_SIZE;
    }
    if (locality_hint) {
        list = get_list(dmm, DMPTR_MN_ID(locality_hint));
    } else {
        list = auto_choose_list(dmm);
    }
    return do_balloc(list, size, align);
}

static inline void find_neighbour_free_blks(struct free_blk_list *list,
                                            struct free_blk **prev, struct free_blk **next,
                                            dmptr_t start_addr, dmptr_t end_addr) {
    struct free_blk blk = { .start_addr = start_addr, .end_addr = end_addr };
    struct free_blk *nearest = avl_tree_nearest(&list->free_blks, &blk);

    if (unlikely(!nearest)) {
        *prev = *next = NULL;
        return;
    }

    if (nearest->start_addr < start_addr) {
        *prev = nearest;
        *next = avl_tree_next(&list->free_blks, nearest);
    } else {
        *prev = avl_tree_prev(&list->free_blks, nearest);
        *next = nearest;
    }

    if (*prev) {
        ethane_assert((*prev)->end_addr <= start_addr);
    }
    if (*next) {
        ethane_assert((*next)->start_addr >= end_addr);
    }
}

static void do_bfree(struct free_blk_list *list, dmptr_t addr, size_t size) {
    struct free_blk *prev, *next;

    find_neighbour_free_blks(list, &prev, &next, addr, addr + size);

    if ((prev && prev->end_addr == addr) && (next && next->start_addr == addr + size)) {
        /* case 1: merge with both prev and next */
        prev->end_addr = next->end_addr;
        if (unlikely(next == list->curr_blk)) {
            list->curr_blk = prev;
        }
        avl_tree_remove(&list->free_blks, next);
        free(next);
        return;
    }

    if (prev && prev->end_addr == addr) {
        /* case 2: merge with prev */
        prev->end_addr += size;
        return;
    }

    if (next && next->start_addr == addr + size) {
        /* case 3: merge with next */
        next->start_addr -= size;
        return;
    }

    /* case 4: no merge */
    struct free_blk *new_blk = malloc(sizeof(struct free_blk));
    new_blk->start_addr = addr;
    new_blk->end_addr = addr + size;
    avl_tree_add(&list->free_blks, new_blk);
}

void dmm_bfree(dmm_cli_t *dmm, dmptr_t addr, size_t size) {
    struct free_blk_list *list = get_list(dmm, addr);
    ethane_assert(list);
    do_bfree(list, addr, size);
}

void dmm_bzero(dmm_cli_t *dmm, dmptr_t addr, size_t size, bool mn_side) {
    if (mn_side) {
        mn_bzero(dmm, addr, size);
    } else {
        /* FIXME: CLIENT-side bzero not implemented! */
        pr_err("CLIENT-side bzero not implemented!");
    }
}

void dmm_bclear(dmm_cn_t *dmm, dmcontext_t *ctx) {
    mn_bclear(dmm, ctx);
}

int dmm_get_interleave_nr(dmm_cli_t *dmm) {
    return dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS;
}

void dmm_balloc_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size, size_t align) {
    int nr_mns = dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS, i;
    size_t size_per_mn = ALIGN_UP(DIV_ROUND_UP(size, nr_mns), PAGE_SIZE);
    for (i = 0; i < nr_mns; i++) {
        addrs[i] = dmm_balloc(dmm, size_per_mn, align, DMPTR_DUMMY(i));
    }
}

void dmm_bfree_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size) {
    int nr_mns = dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS, i;
    size_t size_per_mn = ALIGN_UP(DIV_ROUND_UP(size, nr_mns), PAGE_SIZE);
    for (i = 0; i < nr_mns; i++) {
        dmm_bfree(dmm, addrs[i], size_per_mn);
    }
}

void dmm_bzero_interleaved(dmm_cli_t *dmm, const dmptr_t *addrs, size_t size, bool mn_side) {
    int nr_mns = dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS, i;
    size_t size_per_mn = ALIGN_UP(DIV_ROUND_UP(size, nr_mns), PAGE_SIZE);
    for (i = 0; i < nr_mns; i++) {
        dmm_bzero(dmm, addrs[i], size_per_mn, mn_side);
    }
}

dmptr_t dmm_get_ptr_interleaved(dmm_cli_t *dmm, dmptr_t *addrs, size_t size, size_t off) {
    int nr_mns = dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS;
    size_t size_per_mn = ALIGN_UP(DIV_ROUND_UP(size, nr_mns), PAGE_SIZE);
    return addrs[off / size_per_mn] + off % size_per_mn;
}

size_t dmm_get_strip_size(dmm_cli_t *dmm, size_t size) {
    return ALIGN_UP(DIV_ROUND_UP(size, dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS), PAGE_SIZE);
}

int dmm_get_isolated_mn_id(dmm_cli_t *dmm, int i) {
    return i + dmm->dmm_cn->nr_mns - DMM_NR_ISOLATE_MNS;
}
