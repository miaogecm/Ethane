/*
 * Debug Facilities
 */

#ifndef ETHANE_DEBUG_H
#define ETHANE_DEBUG_H

#include <backtrace.h>
#include <backtrace-supported.h>
#include <signal.h>

#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int debug_mode;

#define COLOR_BLACK         "\033[0;30m"
#define COLOR_RED           "\033[0;31m"
#define COLOR_GREEN         "\033[0;32m"
#define COLOR_YELLOW        "\033[0;33m"
#define COLOR_BLUE          "\033[0;34m"
#define COLOR_MAGENTA       "\033[0;35m"
#define COLOR_CYAN          "\033[0;36m"
#define COLOR_WHITE         "\033[0;37m"
#define COLOR_GRAY          "\033[0;90m"
#define COLOR_DEFAULT       "\033[0;39m"

#define COLOR_BOLD_BLACK    "\033[1;30m"
#define COLOR_BOLD_RED      "\033[1;31m"
#define COLOR_BOLD_GREEN    "\033[1;32m"
#define COLOR_BOLD_YELLOW   "\033[1;33m"
#define COLOR_BOLD_BLUE     "\033[1;34m"
#define COLOR_BOLD_MAGENTA  "\033[1;35m"
#define COLOR_BOLD_CYAN     "\033[1;36m"
#define COLOR_BOLD_WHITE    "\033[1;37m"
#define COLOR_BOLD_DEFAULT  "\033[1;39m"

#define PT_RESET            "\033[0m"
#define PT_BOLD             "\033[1m"
#define PT_UNDERLINE        "\033[4m"
#define PT_BLINKING         "\033[5m"
#define PT_INVERSE          "\033[7m"

#define CURSOR_PREV_LINE    "\033[A\033[K"

#define PR_PREFIX                   COLOR_GRAY "[ethane:%s:%d (%s:%ld:%s)] " COLOR_DEFAULT
#define PR_PREFIX_FMT               __func__, __LINE__, ethanefs_get_hostname(), \
                                    syscall(SYS_gettid), ethanefs_get_threadname()
#define pr_color(color, fmt, ...)   printf(PR_PREFIX color fmt COLOR_DEFAULT "\n", PR_PREFIX_FMT, ##__VA_ARGS__)
#define pr_info(fmt, ...)           pr_color(COLOR_GREEN, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)           pr_color(COLOR_MAGENTA, fmt, ##__VA_ARGS__)
#define pr_emph(fmt, ...)           pr_color(COLOR_YELLOW, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)            do { pr_color(COLOR_RED, fmt, ##__VA_ARGS__); dump_stack(); } while (0)
#define pr_debug(fmt, ...)          do { if (__builtin_expect(debug_mode, 0)) pr_color(COLOR_BLUE, fmt, ##__VA_ARGS__); } while (0)

#define ethane_assert(cond)         do { if (!(cond)) { pr_warn("assertion failed: %s", #cond); abort(); } } while (0)

const char *ethanefs_get_hostname();
const char *ethanefs_get_threadname();

static void bt_err_cb(void *data, const char *msg, int errnum) {
    pr_warn("err %s (%d)", msg, errnum);
}

static int bt_full_cb(void *data, uintptr_t pc, const char *filename, int lineno, const char *function) {
    pr_info(PT_UNDERLINE "%s" PT_RESET " [%s(%d)]", function, filename, lineno);
    return 0;
}

static void dump_stack() {
    struct backtrace_state *state = backtrace_create_state(NULL, BACKTRACE_SUPPORTS_THREADS, bt_err_cb, NULL);
    pr_info(PT_BOLD "========== dump stack ==========" PT_RESET);
    backtrace_full(state, 0, bt_full_cb, bt_err_cb, NULL);
}

static void err_sig_handler(int sig) {
    pr_err("[!!!] program received signal %s", strsignal(sig));
    exit(1);
}

static void toggle_dbg_sig_handler(int sig) {
    pr_info("toggle debug mode, change to %s", debug_mode ? "off" : "on");
    debug_mode = !debug_mode;
}

static void reg_debug_sig_handler() {
    signal(SIGSEGV, err_sig_handler);
    signal(SIGTRAP, err_sig_handler);
    signal(SIGABRT, err_sig_handler);
    signal(SIGILL, err_sig_handler);
    signal(SIGFPE, err_sig_handler);
    signal(SIGBUS, err_sig_handler);
    signal(SIGUSR2, toggle_dbg_sig_handler);
}

#endif //ETHANE_DEBUG_H
