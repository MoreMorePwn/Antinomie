// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// preload-lib.c — the library of the preload-lib scenario, built as a shared
// object and embedded in the samples. Loaded with LD_PRELOAD or LD_AUDIT into
// the preload child, it only says so: one line on standard error and a
// variable the child prints. It hooks nothing.
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void announce(void)
{
    static const char line[] = "preload-lib: library loaded into this process\n";
    setenv("DEMO_PRELOAD_LOADED", "1", 1);
    ssize_t ignored = write(2, line, sizeof line - 1);
    (void)ignored;
}

// LD_AUDIT asks an audit library for the interface version it speaks; any
// non-zero answer the loader knows keeps it loaded. Nothing else is audited.
unsigned int la_version(unsigned int version)
{
    return version;
}
