/*
* Disaggregated Persistent Memory File System (ETHANE)
 *
 * Random Generator
 *
 * Hohai University
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
