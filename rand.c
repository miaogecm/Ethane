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
 * Random Generator
 */

#include "debug.h"
#include "rand.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

unsigned int get_rand_seed() {
    unsigned int seed;
    int fd, err;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        pr_err("open /dev/urandom failed");
        exit(EXIT_FAILURE);
    }

    err = read(fd, &seed, sizeof(seed));
    if (err < 0) {
        pr_err("read /dev/urandom failed");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return seed;
}
