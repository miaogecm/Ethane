/*
 * Disaggregated Persistent Memory File System (ETHANE)
 *
 * Coroutine Library based on libaco
 *
 * Hohai University
 */

#ifndef ETHANE_CORO_H
#define ETHANE_CORO_H

#include <stdbool.h>

#include "third_party/libaco/aco.h"

typedef struct coro coro_t;
typedef void (*coro_fn_t)(void *);

void coro_thread_init();

coro_t *coro_create(coro_fn_t fn, void *arg);
void coro_sched();
void coro_destroy(coro_t *coro);
void coro_yield_(const char *file, const char *func, int line);
coro_t *coro_current();
bool coro_terminated(coro_t *coro);

#define coro_yield()  coro_yield_(__FILE__, __func__, __LINE__)

void coro_delay(long delay_us);

#endif //ETHANE_CORO_H
