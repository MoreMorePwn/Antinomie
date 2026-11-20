// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// preload-child.c — the dynamic child of the preload-lib scenario, embedded in
// the samples: it reports whether a preloaded library ran in it, then exits.
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    const char *loaded = getenv("DEMO_PRELOAD_LOADED");
    printf("preload-child: %s\n", loaded ? "library loaded before main" : "no library ran");
    return 0;
}
