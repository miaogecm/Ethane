#ifndef ETHANE_ETHANE_H
#define ETHANE_ETHANE_H

#include <sched.h>
#include <string.h>
#include <time.h>
#include <bits/cpu-set.h>

#include "dmpool.h"
#include "bench.h"

#define ETHANE_SB_REMOTE_ADDR    0

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define ERR_PTR(x)      ((void *)(long)(x))
#define PTR_ERR(x)      ((long)(x))
#define IS_ERR(x)       ((unsigned long)(x) >= (unsigned long)-4095)

#define ALIGN_UP(x, a)          (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a)        ((x) & ~((a) - 1))
#define PTR_ALIGN_UP(x, a)      ((typeof(x))ALIGN_UP((unsigned long)(x), (a)))
#define PTR_ALIGN_DOWN(x, a)    ((typeof(x))ALIGN_DOWN((unsigned long)(x), (a)))
#define DIV_ROUND_UP(n, d)      (((n) + (d) - 1) / (d))

#define PAGE_SIZE       4096

#define BLK_SIZE        4096

#define DENTRY_SIZE     512

/* FIXME: We assume a fixed IO SIZE of simplified implementation. */
/* Must be multipler of BLK_SIZE */
//#define IO_SIZE         (32 * BLK_SIZE)
//#define IO_SIZE         (1024ul * BLK_SIZE)
//#define IO_SIZE         (16 * 1024ul)
#define IO_SIZE         (256 * 1024ul)

#define MAX_NR_MNS                  16
#define MAX_NR_CLIS                 4096
#define MAX_NR_INTERVAL_NODE_BLKN   16

#define max(x, y)       ((x) > (y) ? (x) : (y))
#define min(x, y)       ((x) < (y) ? (x) : (y))

#define __packed        __attribute__((packed))

#define READ_ONCE(x)        (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, y)    (*(volatile typeof(x) *)&(x) = (y))
#define CAS(x, old, new)    __sync_bool_compare_and_swap(&(x), (old), (new))
#define FAA(x, v)           __sync_fetch_and_add(&(x), (v))

#define cpu_relax()         asm volatile("pause\n": : :"memory")

#define CACHELINE_SIZE      64

#define barrier()           asm volatile("" ::: "memory")

static __always_inline void __read_once_size(const volatile void *p, void *res, int size) {
    switch (size) {
        case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;
        case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;
        case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;
        case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;
        default:
            barrier();
        __builtin_memcpy(res, (const void *)p, size);
        barrier();
    }
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size) {
    switch (size) {
        case 1: *(volatile uint8_t *)p = *(uint8_t *)res; break;
        case 2: *(volatile uint16_t *)p = *(uint16_t *)res; break;
        case 4: *(volatile uint32_t *)p = *(uint32_t *)res; break;
        case 8: *(volatile uint64_t *)p = *(uint64_t *)res; break;
        default:
            barrier();
        __builtin_memcpy((void *)p, (const void *)res, size);
        barrier();
    }
}

#define WRITE_ONCE(x, val) \
({							\
union { typeof(x) __val; char __c[1]; } __u =	\
{ .__val = (typeof(x)) (val) }; \
__write_once_size(&(x), __u.__c, sizeof(x));	\
__u.__val;					\
})

#define READ_ONCE(x)						\
({									\
union { typeof(x) __val; char __c[1]; } __u;			\
__read_once_size(&(x), __u.__c, sizeof(x));		\
__u.__val;							\
})

typedef enum {
    ETHANE_DENTRY_FILE,
    ETHANE_DENTRY_DIR,
    ETHANE_DENTRY_TOMBSTONE
} ethane_de_type_t;

struct ethane_open_file {
    dmptr_t remote_dentry_addr;
    char full_path[];
};

struct ethane {
    struct dmcontext *dmcontext;
    struct dmm_th *dmm;
    struct cachefs *cfs;
    struct oplogger *oplogger;
    struct coroset *coroset;
};

struct ethane_perm {
    struct {
        uint16_t uid;
        uint16_t gid;
    } owner;

    mode_t mode;
};

struct ethane_dentry {
    ethane_de_type_t type;

    dmptr_t remote_addr;
    dmptr_t parent;

    struct ethane_perm perm;

    size_t file_size;

    /* only for ETHANE_DENTRY_DIR */
    int nr_children;

    char filename[0];
};

struct ethane_super {
    unsigned long magic;

    dmptr_t logger_remote_addr;
    dmptr_t sharedfs_remote_addr;

    long chkpt_ver;
};

static const char *get_de_ty_str(ethane_de_type_t type) {
    switch (type) {
        case ETHANE_DENTRY_FILE:
            return "file";
        case ETHANE_DENTRY_DIR:
            return "dir";
        case ETHANE_DENTRY_TOMBSTONE:
            return "tombstone";
        default:
            return "unknown";
    }
}

static const char *get_component(const char *full_path, int *len) {
    const char *start, *end;
    start = end = full_path;
    while (*end && *end != '/') {
        end++;
    }
    *len = (int) (end - start);
    return *end == '/' ? end + 1 : NULL;
}

#define ETHANE_ITER_COMPONENTS(path, component, next, len) \
    for ((component) = (path); (component) && ((next) = get_component((component), &(len)), 1); (component) = (next))

static int ethane_get_dir_depth(const char *full_path) {
    const char *component, *next;
    int len, depth = 0;
    ETHANE_ITER_COMPONENTS(full_path, component, next, len) {
        depth++;
    }
    return depth;
}

static const char *ethane_get_filename(const char *full_path) {
    const char *component, *next;
    int len;
    ETHANE_ITER_COMPONENTS(full_path, component, next, len) {
        if (!next) {
            return component;
        }
    }
    return NULL;
}

static void memset_nt(void *dest, uint32_t dword, size_t length) {
    uint64_t qword = ((uint64_t) dword << 32) | dword;
    uint64_t dummy1, dummy2;

    asm volatile ("movl %%edx,%%ecx\n"
                  "andl $63,%%edx\n"
                  "shrl $6,%%ecx\n"
                  "jz 9f\n"
                  "1:      movnti %%rax,(%%rdi)\n"
                  "2:      movnti %%rax,1*8(%%rdi)\n"
                  "3:      movnti %%rax,2*8(%%rdi)\n"
                  "4:      movnti %%rax,3*8(%%rdi)\n"
                  "5:      movnti %%rax,4*8(%%rdi)\n"
                  "8:      movnti %%rax,5*8(%%rdi)\n"
                  "7:      movnti %%rax,6*8(%%rdi)\n"
                  "8:      movnti %%rax,7*8(%%rdi)\n"
                  "leaq 64(%%rdi),%%rdi\n"
                  "decl %%ecx\n"
                  "jnz 1b\n"
                  "9:     movl %%edx,%%ecx\n"
                  "andl $7,%%edx\n"
                  "shrl $3,%%ecx\n"
                  "jz 11f\n"
                  "10:     movnti %%rax,(%%rdi)\n"
                  "leaq 8(%%rdi),%%rdi\n"
                  "decl %%ecx\n"
                  "jnz 10b\n"
                  "11:     movl %%edx,%%ecx\n"
                  "shrl $2,%%ecx\n"
                  "jz 12f\n"
                  "movnti %%eax,(%%rdi)\n"
                  "12:\n"
    : "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
}

static char *get_hex_str(const void *buf, size_t len) {
    char *hex;
    int i;
    len = min(len, 16);
    hex = malloc(len * 3 + 1);
    for (i = 0; i < len; i++) {
        sprintf(hex + i * 3, "%02x ", ((unsigned char *) buf)[i]);
    }
    return hex;
}

#endif //ETHANE_ETHANE_H
