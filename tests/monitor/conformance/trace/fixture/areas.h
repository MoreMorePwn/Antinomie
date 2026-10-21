// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// areas.h — the conformance fixture's areas and shared helpers.
//
// An area exercises one family of system calls. The "user" group runs every
// user area as UID 1000; the "root" group runs the root areas as UID 0. Both
// run in a disposable VM booted for that group alone.
#ifndef ANTINOMIE_CONFORMANCE_AREAS_H
#define ANTINOMIE_CONFORMANCE_AREAS_H

#include "oracle.h"

#include <stddef.h>
#include <stdint.h>

// User areas (files.c, paths.c, events.c, net.c, memory.c, process.c,
// signals.c, ipc.c, async.c, system.c).
void area_file_io(void);
void area_file_meta(void);
void area_paths(void);
void area_xattr_splice(void);
void area_events(void);
void area_net(void);
void area_memory(void);
void area_process(void);
void area_identity(void);
void area_signals(void);
void area_time(void);
void area_futex(void);
void area_ipc(void);
void area_keys(void);
void area_aio(void);
void area_uring(void);
void area_system(void);
void area_recapture(void);
// Root areas (root.c).
void area_root(void);
// Concurrency (threads.c): many threads and processes on every CPU.
void area_threads(void);

// The fixture's private working directory (absolute), created by main.
extern char work_dir[256];
// The fixture's own path (/proc/self/exe resolved), for exec cases.
extern char self_path[256];
// When main() started: static glibc's start-up calls happened before.
extern uint64_t main_t0;

// Fill `len` bytes with a recognizable pattern seeded by `seed`.
void pattern(void *buffer, size_t len, unsigned seed);
// A path inside work_dir: returns a static per-call-site buffer copy.
const char *work_path(char *out, size_t size, const char *name);
// Run `body` in a forked child with its own case numbering; wait for it.
void in_child(unsigned index, const char *what, void (*body)(void *), void *arg);

#endif
