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
 * Benchmark Utility
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
