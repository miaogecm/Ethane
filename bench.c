/*
* Disaggregated Persistent Memory File System (ETHANE)
 *
 * Benchmark Utility
 *
 * Hohai University
 */

#include "bench.h"

#include <stdio.h>
#include <stdlib.h>

#include "debug.h"

int tsc_khz = 0;

static void get_tsc_khz() {
    FILE *fp;
    fp = popen("gdb /dev/null /proc/kcore -ex 'x/uw 0x'$(grep '\\<tsc_khz\\>' /proc/kallsyms | cut -d' ' -f1) -batch 2>/dev/null | tail -n 1 | cut -f2", "r");
    fscanf(fp, "%d", &tsc_khz);
    pclose(fp);
}

void bench_timer_init_freq() {
    get_tsc_khz();
    pr_info("bench timer: TSC_KHZ=%d", tsc_khz);
}
