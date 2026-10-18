// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// static-zoo.c — one small program built many ways for static analysis:
// stripped or not, PIE or not, each hardening option on or off, static,
// packed with payloads and a high-entropy region, or huge.
//
// build-torture.sh compiles the variants; ZOO_GENERATED pulls in the
// generated payloads, functions, strings and sections.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef ZOO_GENERATED
#include "static-zoo-generated.h"
#endif

// Readable strings for the Strings tab, including ones that look like
// configuration and indicators but are inert.
static const char *const notes[] = {
    "antinomie static zoo sample",
    "http://example.invalid/antinomie/static-zoo",
    "/etc/antinomie/static-zoo.conf",
    "HKEY-style text that is not a registry key",
    "SELECT name FROM static_zoo WHERE inert = 1",
    "-----BEGIN NOT A KEY----- antinomie -----END NOT A KEY-----",
};

static uint32_t checksum(const unsigned char *data, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++)
        hash = (hash ^ data[i]) * 16777619u;
    return hash;
}

int main(int argc, char **argv)
{
    char buffer[64];
    // A fixed-size copy keeps a stack buffer for the canary to protect.
    strncpy(buffer, argc > 1 ? argv[1] : "zoo", sizeof buffer - 1);
    buffer[sizeof buffer - 1] = 0;
    uint32_t hash = checksum((const unsigned char *)buffer, strlen(buffer));
    for (size_t i = 0; i < sizeof notes / sizeof notes[0]; i++)
        hash ^= checksum((const unsigned char *)notes[i], strlen(notes[i]));
#ifdef ZOO_GENERATED
    hash ^= zoo_generated();
#endif
    printf("static zoo %s: checksum %08x\n", buffer, hash);
    return 0;
}
