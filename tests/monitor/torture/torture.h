// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// torture.h — shared core of the Antinomie stress samples.
//
// Every module pushes one monitored feature as far as its level allows. All
// work is benign, bounded by the caps below and removed afterwards; a module
// that needs root warns and skips that part when run unprivileged.
#ifndef ANTINOMIE_TORTURE_H
#define ANTINOMIE_TORTURE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Hard caps, whatever the level asks for.
#define CAP_PROCESSES 20000
#define CAP_MEMORY_BYTES (512ULL << 20)
#define CAP_DISK_BYTES (2ULL << 30)
#define CAP_FLOOD_SECONDS 30

enum level { LEVEL_LIGHT, LEVEL_HEAVY, LEVEL_EXTREME };

struct options {
    enum level level;
    // Seconds; 0 means the module's default for its level.
    int duration;
    // Network modules may contact public hosts.
    int public_network;
    // Directory the module works in; removed afterwards unless --keep.
    char workdir[256];
    int keep;
    int root;
};

struct module {
    const char *name;
    const char *summary;
    int (*run)(const struct options *options);
};

// Scale a light-level count by the level: x1, x4, x16.
long scaled(const struct options *options, long light);
// The module's duration: --duration, else light/heavy/extreme defaults.
int seconds(const struct options *options, int light, int heavy, int extreme);
double now(void);

// One result line: PASS, LIMIT (a cap stopped it), UNAVAILABLE or FAIL.
void pass(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void limit(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void unavailable(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void fail(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void note(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
// Prints a warning and returns 0 when the process is not root.
int need_root(const struct options *options, const char *module, const char *what);

// Counters added to the final scorecard.
void count(const char *what, unsigned long long amount);

int write_file(const char *path, const void *data, size_t len, mode_t mode);
// Run argv and wait; returns the exit status or -1.
int run_wait(char *const argv[]);
// Remove a directory tree (used for cleanup).
void remove_tree(const char *path);
// The guest's default gateway and first nameserver, as dotted quads.
int default_gateway(char *address, size_t size);
int first_nameserver(char *address, size_t size);

// Inert strings that public YARA-Forge Core rules match (indicators.c).
size_t executable_indicator_count(void);
char *dropped_indicator_text(size_t *len);
char *memory_indicator_text(void);

#define MODULE(id) int module_##id(const struct options *options)

MODULE(syscall_flood);
MODULE(long_run);
MODULE(object_capture);
MODULE(terminal_flood);
MODULE(process_tree);
MODULE(unkillable);
MODULE(file_churn);
MODULE(network_storm);
MODULE(async_io);
MODULE(decoder_zoo);
MODULE(crash_core);
MODULE(memory_tricks);
MODULE(detect_yara);
MODULE(detect_sigma);
MODULE(detect_ids);
MODULE(argv_env);
MODULE(timing);

#endif
