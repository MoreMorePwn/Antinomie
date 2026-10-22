// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// main.c — options, module registry, result lines and the scorecard.
//
// Built with -DSINGLE_MODULE="name" the program is that one stress sample
// (ant-<name>); without it, it is ant-torture with every module.
#include "torture.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const struct module modules[] = {
    {"syscall-flood", "cheap syscalls on every CPU: transport, TRL, shedding", module_syscall_flood},
    {"long-run", "steady mixed activity for minutes: long-session recording, quota", module_long_run},
    {"object-capture", "buffers from 1 byte to MiBs: captured objects, packs", module_object_capture},
    {"terminal-flood", "long lines, ANSI, UTF-8, binary: terminal drain and scrollback", module_terminal_flood},
    {"process-tree", "wide, deep, threaded and orphaned processes: process tree", module_process_tree},
    {"unkillable", "ignores SIGTERM with setsid and daemon children: Stop/Kill run", module_unkillable},
    {"file-churn", "thousands of file changes: Files tab and recovered files", module_file_churn},
    {"network-storm", "connects, UDP, DNS flood, IPv6: network capture and IDS input", module_network_storm},
    {"async-io", "io_uring with many requests in flight: async observation", module_async_io},
    {"decoder-zoo", "rare syscalls with odd arguments: argument decoders", module_decoder_zoo},
    {"crash-core", "large heap then a crash: core on exit and memory dumps", module_crash_core},
    {"memory-tricks", "RWX, memfd exec, mprotect flips: suspicious memory, YARA memory", module_memory_tricks},
    {"detect-yara", "markers in the binary, a dropped file and memory: YARA targets", module_detect_yara},
    {"detect-sigma", "command lines, file names and connects Sigma rules describe", module_detect_sigma},
    {"detect-ids", "network traffic the bundled IDS rules match", module_detect_ids},
    {"argv-env", "huge and odd argument vectors and environments: CommandLine", module_argv_env},
    {"timing", "instant exits and pre-acknowledgement bursts: run start", module_timing},
};
#define MODULE_COUNT (sizeof modules / sizeof modules[0])

static struct {
    const char *what;
    unsigned long long amount;
} counters[64];
static size_t counter_len;
static unsigned passes, limits, unavailables, failures;

long scaled(const struct options *options, long light)
{
    static const long factor[] = {1, 4, 16};
    return light * factor[options->level];
}

int seconds(const struct options *options, int light, int heavy, int extreme)
{
    if (options->duration > 0)
        return options->duration;
    return options->level == LEVEL_LIGHT ? light : options->level == LEVEL_HEAVY ? heavy : extreme;
}

double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void line(const char *tag, const char *module, const char *fmt, va_list args)
{
    printf("%-11s %-15s ", tag, module);
    vprintf(fmt, args);
    putchar('\n');
    fflush(stdout);
}

#define RESULT(fn, tag, counter)                                                                   \
    void fn(const char *module, const char *fmt, ...)                                              \
    {                                                                                              \
        va_list args;                                                                              \
        va_start(args, fmt);                                                                       \
        line(tag, module, fmt, args);                                                              \
        va_end(args);                                                                              \
        counter++;                                                                                 \
    }
RESULT(pass, "PASS", passes)
RESULT(limit, "LIMIT", limits)
RESULT(unavailable, "UNAVAILABLE", unavailables)
RESULT(fail, "FAIL", failures)

void note(const char *module, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    line("NOTE", module, fmt, args);
    va_end(args);
}

int need_root(const struct options *options, const char *module, const char *what)
{
    if (options->root)
        return 1;
    printf("WARNING     %-15s not root: skipping %s; run as root to include it\n", module, what);
    fflush(stdout);
    unavailables++;
    return 0;
}

void count(const char *what, unsigned long long amount)
{
    for (size_t i = 0; i < counter_len; i++) {
        if (strcmp(counters[i].what, what) == 0) {
            counters[i].amount += amount;
            return;
        }
    }
    if (counter_len < sizeof counters / sizeof counters[0]) {
        counters[counter_len].what = what;
        counters[counter_len++].amount = amount;
    }
}

int write_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    const char *cursor = data;
    while (len > 0) {
        ssize_t written = write(fd, cursor, len);
        if (written <= 0) {
            close(fd);
            return -1;
        }
        cursor += written;
        len -= (size_t)written;
    }
    return close(fd);
}

int run_wait(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, 1);
            dup2(null, 2);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void remove_tree(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) {
        unlink(path);
        return;
    }
    struct dirent *entry;
    char child[4096];
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        snprintf(child, sizeof child, "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            remove_tree(child);
        else
            unlink(child);
    }
    closedir(dir);
    rmdir(path);
}

int default_gateway(char *address, size_t size)
{
    FILE *routes = fopen("/proc/net/route", "r");
    if (!routes)
        return -1;
    char row[256];
    int found = -1;
    while (fgets(row, sizeof row, routes)) {
        char name[64];
        unsigned destination, gateway;
        if (sscanf(row, "%63s %x %x", name, &destination, &gateway) == 3 && destination == 0 &&
            gateway != 0) {
            snprintf(address, size, "%u.%u.%u.%u", gateway & 255, gateway >> 8 & 255,
                     gateway >> 16 & 255, gateway >> 24);
            found = 0;
            break;
        }
    }
    fclose(routes);
    return found;
}

int first_nameserver(char *address, size_t size)
{
    FILE *resolv = fopen("/etc/resolv.conf", "r");
    if (!resolv)
        return -1;
    char row[256];
    int found = -1;
    while (fgets(row, sizeof row, resolv)) {
        char server[64];
        if (sscanf(row, "nameserver %63s", server) == 1 && strchr(server, '.') &&
            strncmp(server, "127.", 4) != 0) {
            snprintf(address, size, "%s", server);
            found = 0;
            break;
        }
    }
    fclose(resolv);
    return found;
}

static void usage(const char *self)
{
    printf("usage: %s [--level light|heavy|extreme] [--duration SECONDS] [--public]\n"
           "          [--keep] [--workdir DIR]%s\n\n",
           self,
#ifdef SINGLE_MODULE
           ""
#else
           " [--all | --only a,b,...] [--parallel] [--list]"
#endif
    );
    printf("Benign and bounded: at most %d processes, %llu MiB of memory, %llu MiB of disk\n"
           "and %d seconds of maximum syscall load per module. Parts that need root warn\n"
           "and are skipped when run unprivileged.\n",
           CAP_PROCESSES, CAP_MEMORY_BYTES >> 20, CAP_DISK_BYTES >> 20, CAP_FLOOD_SECONDS);
}

static int run_module(const struct module *module, const struct options *base)
{
    struct options options = *base;
    char template[] = "/tmp/antinomie-torture-XXXXXX";
    if (!base->workdir[0]) {
        if (!mkdtemp(template)) {
            fail(module->name, "work directory: %s", strerror(errno));
            return 1;
        }
        snprintf(options.workdir, sizeof options.workdir, "%s", template);
    } else {
        int len = snprintf(options.workdir, sizeof options.workdir, "%.200s/%s", base->workdir,
                           module->name);
        if (len < 0 || (size_t)len >= sizeof options.workdir) {
            fail(module->name, "work directory path too long");
            return 1;
        }
        mkdir(options.workdir, 0700);
    }
    printf("== %s: %s (level %s, work %s)\n", module->name, module->summary,
           options.level == LEVEL_LIGHT ? "light" : options.level == LEVEL_HEAVY ? "heavy" : "extreme",
           options.workdir);
    fflush(stdout);
    double started = now();
    int status = module->run(&options);
    printf("== %s: done in %.1f s\n", module->name, now() - started);
    fflush(stdout);
    if (!options.keep)
        remove_tree(options.workdir);
    return status;
}

static void scorecard(void)
{
    printf("\n== scorecard: %u pass, %u limit, %u unavailable, %u fail\n", passes, limits,
           unavailables, failures);
    for (size_t i = 0; i < counter_len; i++)
        printf("   %-34s %llu\n", counters[i].what, counters[i].amount);
    fflush(stdout);
}

// Child roles some modules re-execute the program into.
int child_role(int argc, char **argv);

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--child") == 0)
        return child_role(argc, argv);
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct options options = {.level = LEVEL_LIGHT, .root = geteuid() == 0};
    const char *only = NULL;
    int all = 0, parallel = 0;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "--level") && i + 1 < argc) {
            const char *value = argv[++i];
            if (!strcmp(value, "light"))
                options.level = LEVEL_LIGHT;
            else if (!strcmp(value, "heavy"))
                options.level = LEVEL_HEAVY;
            else if (!strcmp(value, "extreme"))
                options.level = LEVEL_EXTREME;
            else {
                usage(argv[0]);
                return 2;
            }
        } else if (!strcmp(arg, "--duration") && i + 1 < argc) {
            options.duration = atoi(argv[++i]);
        } else if (!strcmp(arg, "--public")) {
            options.public_network = 1;
        } else if (!strcmp(arg, "--keep")) {
            options.keep = 1;
        } else if (!strcmp(arg, "--workdir") && i + 1 < argc) {
            snprintf(options.workdir, sizeof options.workdir, "%s", argv[++i]);
#ifndef SINGLE_MODULE
        } else if (!strcmp(arg, "--all")) {
            all = 1;
        } else if (!strcmp(arg, "--only") && i + 1 < argc) {
            only = argv[++i];
        } else if (!strcmp(arg, "--parallel")) {
            parallel = 1;
        } else if (!strcmp(arg, "--list")) {
            for (size_t m = 0; m < MODULE_COUNT; m++)
                printf("%-15s %s\n", modules[m].name, modules[m].summary);
            return 0;
#endif
        } else {
            usage(argv[0]);
            return !strcmp(arg, "--help") || !strcmp(arg, "-h") ? 0 : 2;
        }
    }
    if (!options.root)
        printf("WARNING     %-15s not root: parts that need root are skipped and reported\n",
               "all");
    int status = 0;
#ifdef SINGLE_MODULE
    (void)only;
    (void)all;
    (void)parallel;
    for (size_t m = 0; m < MODULE_COUNT; m++)
        if (!strcmp(modules[m].name, SINGLE_MODULE))
            status = run_module(&modules[m], &options);
#else
    if (!all && !only) {
        usage(argv[0]);
        printf("\nModules (--list): pass --all or --only.\n");
        return 2;
    }
    pid_t children[MODULE_COUNT];
    size_t running = 0;
    for (size_t m = 0; m < MODULE_COUNT; m++) {
        if (only) {
            const char *hit = strstr(only, modules[m].name);
            size_t len = strlen(modules[m].name);
            if (!hit || (hit != only && hit[-1] != ',') || (hit[len] && hit[len] != ','))
                continue;
        }
        if (parallel) {
            pid_t pid = fork();
            if (pid == 0) {
                int child = run_module(&modules[m], &options);
                scorecard();
                _exit(child);
            }
            if (pid > 0)
                children[running++] = pid;
        } else {
            status |= run_module(&modules[m], &options);
        }
    }
    for (size_t i = 0; i < running; i++) {
        int child;
        if (waitpid(children[i], &child, 0) > 0 && !(WIFEXITED(child) && WEXITSTATUS(child) == 0))
            status = 1;
    }
#endif
    scorecard();
    return status || failures ? 1 : 0;
}
