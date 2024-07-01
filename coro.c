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
 * Coroutine Library based on libaco
 */

#include <stdbool.h>

#include "ethane.h"
#include "debug.h"
#include "coro.h"

#include "list.h"

#include "dmpool.h"

//#define CO_SLICE_STAT
#define CO_STACK_SIZE       (16 * 1024)
#define CO_MAX_SLICE_US     10

typedef struct coroset coroset_t;

struct coroset {
    struct list_head running_list;
    aco_t *main_co;

    union {
        /* round-robin scheduler state */
        struct {
            coro_t *sched_head;

#ifdef CO_SLICE_STAT
            unsigned long sum_slice_ns;
            int nr_slices;
#endif
        };
    };

    /* starts from 1 */
    int curr_id;

    bool (*sched)(coroset_t *coroset);
    void *sched_arg;
};

struct coro {
    /* coroutine ID starts from 1 */
    int id;
    aco_t *co;
    coro_fn_t fn;
    void *arg;
    struct list_head list;

    const char *yield_from_file, *yield_from_func;
    int yield_from_line;
};

static void fp() {
    coro_t *coro = aco_get_arg();
    coro->fn(coro->arg);
    aco_exit();
}

static __thread coroset_t *thread_coroset = NULL;

static bool coroset_sched_rr(coroset_t *coroset);

static coroset_t *coroset_create(bool (*sched)(coroset_t *), void *sched_arg) {
    coroset_t *coroset;

    coroset = calloc(1, sizeof(coroset_t));
    if (unlikely(!coroset)) {
        goto out;
    }

    INIT_LIST_HEAD(&coroset->running_list);

    coroset->main_co = aco_create(NULL, NULL, 0, NULL, NULL);
    ethane_assert(coroset->main_co);

    coroset->curr_id = 1;

    coroset->sched = sched;
    coroset->sched_arg = sched_arg;

out:
    return coroset;
}

void coro_thread_init() {
    thread_coroset = coroset_create(coroset_sched_rr, NULL);
    if (unlikely(!thread_coroset)) {
        pr_err("coroset_create failed");
        return;
    }
    aco_thread_init(NULL);
}

coro_t *coro_create(coro_fn_t fn, void *arg) {
    aco_share_stack_t *stack;
    coro_t *coro;

    coro = calloc(1, sizeof(coro_t));
    if (unlikely(!coro)) {
        goto out;
    }

    stack = aco_share_stack_new(CO_STACK_SIZE);
    coro->co = aco_create(thread_coroset->main_co, stack, 0, fp, coro);
    ethane_assert(coro->co);
    coro->arg = arg;
    coro->fn = fn;
    coro->id = thread_coroset->curr_id++;

    list_add_tail(&coro->list, &thread_coroset->running_list);

out:
    return coro;
}

bool coro_terminated(coro_t *coro) {
    return coro->co->is_end;
}

void coro_destroy(coro_t *coro) {
    list_del(&coro->list);
    aco_destroy(coro->co);
    free(coro);
}

static bool coroset_sched_rr(coroset_t *coroset) {
    struct bench_timer timer;
    const char *file, *func;
    unsigned long slice_ns;
    coro_t *coro;
    int line;

    if (unlikely(list_empty(&coroset->running_list))) {
        return false;
    }

    if (unlikely(!coroset->sched_head)) {
        coroset->sched_head = list_first_entry(&coroset->running_list, coro_t, list);
    }

    coro = coroset->sched_head;
    coroset->sched_head = list_next_entry(coro, list);
    if (unlikely(&coroset->sched_head->list == &coroset->running_list)) {
        coroset->sched_head = list_first_entry(&coroset->running_list, coro_t, list);
    }

    file = coro->yield_from_file;
    func = coro->yield_from_func;
    line = coro->yield_from_line;

    bench_timer_start(&timer);

    aco_resume(coro->co);

#ifdef CO_SLICE_STAT
    slice_ns = bench_timer_end(&timer);

    coroset->sum_slice_ns += slice_ns;
    coroset->nr_slices++;

    if (unlikely(slice_ns > CO_MAX_SLICE_US * 1000)) {
        pr_warn("coro %d slice %lu ns (avg: %lu ns from %d)"
                " from %s:%s:%d"
                " to %s:%s:%d",
                 coro->id, slice_ns,
                 coroset->sum_slice_ns / coroset->nr_slices, coroset->nr_slices,
                 file, func, line,
                 coro->yield_from_file, coro->yield_from_func, coro->yield_from_line);
    }
#endif

    if (coro_terminated(coro)) {
        /* remove from running list */
        list_del(&coro->list);

        if (list_empty(&coroset->running_list)) {
            coroset->sched_head = NULL;
        }
    }

    return true;
}

static bool coroset_sched(coroset_t *coroset) {
    return coroset->sched(coroset);
}

void coro_sched() {
    while (coroset_sched(thread_coroset));
}

void coro_yield_(const char *file, const char *func, int line) {
    coro_t *coro = coro_current();
    ethane_assert(coro);
    coro->yield_from_file = file;
    coro->yield_from_func = func;
    coro->yield_from_line = line;
    aco_yield();
}

coro_t *coro_current() {
    aco_t *co = aco_get_co();
    if (!co || aco_is_main_co(co)) {
        return NULL;
    }
    return co->arg;
}

void coro_delay(long delay_us) {
    struct bench_timer timer;
    if (delay_us == 0) {
        return;
    }
    bench_timer_start(&timer);
    if (coro_current()) {
        while (bench_timer_end(&timer) < delay_us * 1000) {
            coro_yield();
        }
    } else {
        while (bench_timer_end(&timer) < delay_us * 1000) {
            cpu_relax();
        }
    }
}
