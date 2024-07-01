#ifndef ETHANE_BENCH_H
#define ETHANE_BENCH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int tsc_khz;

struct bench_timer {
    uint64_t start_tsc;
};

static uint64_t get_tsc() {
    uint32_t a, d;
    __asm __volatile("rdtscp" : "=a"(a), "=d"(d) : : "%rcx");
    return ((uint64_t)a) | (((uint64_t)d) << 32);
}

void bench_timer_init_freq();

static void bench_timer_start(struct bench_timer *timer) {
    if (!tsc_khz) {
        fprintf(stderr, "bench timer: TSC_KHZ not initialized\n");
        exit(1);
    }
    timer->start_tsc = get_tsc();
}

/* unit: ns */
static long bench_timer_end(struct bench_timer *timer) {
    uint64_t end_tsc = get_tsc();
    return (end_tsc - timer->start_tsc) * 1000000 / tsc_khz;
}

#endif //ETHANE_BENCH_H
