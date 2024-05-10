/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * RDMA-based Disaggregated Persistent Memory Pool Implementation
 *
 * Disaggregated Memory SpinLock
 *
 * Hohai University
 */

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include "dmlocktab.h"

#include "debug.h"

#include "dmpool.h"
#include "ethane.h"
#include "bench.h"
#include "hash.h"

#define LOCK_ARR_OFF_PER_MN     0

#define LOCK_ACQ_TIMEOUT_US     8000000

struct dmlocktab {
    dmcontext_t *ctx;

    int nr_locks_order;
    int nr_locks;
};

struct dmlock {
    union {
        struct {
            int next_ticket;
            int now_serving;
        };

        uint64_t val;
    };
};

dmlocktab_t *dmlocktab_init(dmcontext_t *ctx, int nr_locks_order) {
    dmlocktab_t *locktab;

    locktab = malloc(sizeof(dmlocktab_t));
    if (unlikely(!locktab)) {
        goto out;
    }

    locktab->ctx = ctx;
    locktab->nr_locks_order = nr_locks_order;
    locktab->nr_locks = 1 << nr_locks_order;

out:
    return locktab;
}

static inline dmptr_t get_lock_addr(dmlocktab_t *locktab, uint64_t oid) {
    int nr_mns, mn_id;
    size_t off;

    oid = hash_long(oid, locktab->nr_locks_order);

    nr_mns = dm_get_nr_mns(dm_get_pool(locktab->ctx));
    mn_id = (int) (oid % nr_mns);
    off = (oid / nr_mns) * sizeof(uint64_t);

    return DMPTR_MK_CM(mn_id, LOCK_ARR_OFF_PER_MN + off);
}

int dmlock_acquire(dmlocktab_t *locktab, uint64_t oid) {
    struct bench_timer timer;
    struct dmlock *lock;
    int ret, my_ticket;
    dmptr_t lock_addr;

    lock_addr = get_lock_addr(locktab, oid);

    lock = dm_push(locktab->ctx, NULL, sizeof(*lock));

    /* 1. get next ticket */
    lock->val = 0;
    lock->next_ticket = 1;
    ret = dm_faa(locktab->ctx, lock_addr, lock, sizeof(*lock), DMFLAG_ACK);
    if (unlikely(ret)) {
        goto out;
    }

    ret = dm_wait_ack(locktab->ctx, 1);
    if (unlikely(ret)) {
        goto out;
    }

    /* TODO: check overflow */
    ethane_assert(lock->next_ticket < (1 << 30));
    my_ticket = lock->next_ticket;

    bench_timer_start(&timer);

    /* 2. wait for now serving */
    do {
        if (bench_timer_end(&timer) > LOCK_ACQ_TIMEOUT_US * 1000ul) {
            pr_warn("wait for lock %lx too long (exceeding %lf secs), %d/%d",
                    lock_addr, LOCK_ACQ_TIMEOUT_US / 1000000.0, lock->now_serving, my_ticket);
            dump_stack();
            bench_timer_start(&timer);
        }

        ret = dm_copy_from_remote(locktab->ctx, lock, lock_addr, sizeof(*lock), DMFLAG_ACK);
        if (unlikely(ret)) {
            goto out;
        }

        ret = dm_wait_ack(locktab->ctx, 1);
        if (unlikely(ret)) {
            goto out;
        }
    } while (lock->now_serving != my_ticket);

    pr_debug("acquired lock %lx", lock_addr);

out:
    return ret;
}

int dmlock_release(dmlocktab_t *locktab, uint64_t oid) {
    struct dmlock *lock;
    dmptr_t lock_addr;
    int ret;

    lock_addr = get_lock_addr(locktab, oid);

    lock = dm_push(locktab->ctx, NULL, sizeof(*lock));

    /* 1. increment now serving */
    lock->val = 0;
    lock->now_serving = 1;
    ret = dm_faa(locktab->ctx, lock_addr, lock, sizeof(*lock), DMFLAG_ACK);
    if (unlikely(ret)) {
        goto out;
    }

    ret = dm_wait_ack(locktab->ctx, 1);
    if (unlikely(ret)) {
        goto out;
    }

    pr_debug("released lock %lx", lock_addr);

out:
    return ret;
}
