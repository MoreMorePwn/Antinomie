// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// indicators.c — inert indicator strings that public YARA-Forge Core rules
// look for, so the public ruleset (not a custom one) reports the samples.
//
// The strings are text only: nothing here runs, formats or sends them.
//
//   Target         Rule (YARA-Forge Core)                         Strings
//   executable     CADOSECURITY_Linux_Wiper_SOLOSHRED             all 5 (plain text below)
//                  CADOSECURITY_Linux_Worm_ORCSHRED               4 of 7 (plain text below)
//   dropped file   ESET_Mozi_Killswitch                           all 4, file under 500 KB
//   memory only    ESET_Kobalos_Ssh_Credential_Stealer            the log format string
//
// The dropped-file and memory strings are stored XOR-encoded (key 0x5a) and
// decoded at run time, so the executable does not match those two rules.
// Only ant-detect-yara and ant-torture carry the plain executable strings;
// the other samples must not be reported as a wiper or a worm.
#include "torture.h"

#include <stdlib.h>
#include <string.h>

#define KEY 0x5a

#if !defined(SINGLE_MODULE) || defined(SINGLE_ID_detect_yara)
static const char *volatile const executable_indicators[] = {
    // SOLOSHRED: printenv | grep -i "ora", shred, --no-preserve-root, /dev/dsk, $(ls /)
    "printenv | grep -i \"ora\"",
    "shred",
    "--no-preserve-root",
    "/dev/dsk",
    "$(ls /)",
    // ORCSHRED: is_owner, check_solaris, disown, /var/log/tasks
    "is_owner",
    "check_solaris",
    "disown",
    "/var/log/tasks",
};
#endif

size_t executable_indicator_count(void)
{
#if !defined(SINGLE_MODULE) || defined(SINGLE_ID_detect_yara)
    size_t bytes = 0;
    for (size_t i = 0; i < sizeof executable_indicators / sizeof executable_indicators[0]; i++)
        bytes += strlen(executable_indicators[i]);
    return bytes;
#else
    return 0;
#endif
}

static const unsigned char mozi_1[] = {0x33, 0x2a, 0x2e, 0x3b, 0x38, 0x36, 0x3f, 0x29, 0x7a, 0x77, 0x13, 0x7a, 0x13, 0x14, 0x0a, 0x0f, 0x0e, 0x7a, 0x7a, 0x77, 0x2a, 0x7a, 0x2e, 0x39, 0x2a, 0x7a, 0x77, 0x77, 0x3e, 0x3f, 0x29, 0x2e, 0x33, 0x34, 0x3b, 0x2e, 0x33, 0x35, 0x34, 0x77, 0x2a, 0x35, 0x28, 0x2e, 0x7a, 0x6d, 0x6f, 0x6e, 0x6d, 0x7a, 0x77, 0x30, 0x7a, 0x1e, 0x08, 0x15, 0x0a};
static const unsigned char mozi_2[] = {0x33, 0x2a, 0x2e, 0x3b, 0x38, 0x36, 0x3f, 0x29, 0x7a, 0x77, 0x13, 0x7a, 0x15, 0x0f, 0x0e, 0x0a, 0x0f, 0x0e, 0x7a, 0x77, 0x2a, 0x7a, 0x2e, 0x39, 0x2a, 0x7a, 0x77, 0x77, 0x29, 0x2a, 0x35, 0x28, 0x2e, 0x7a, 0x69, 0x6a, 0x6a, 0x6a, 0x6f, 0x7a, 0x77, 0x30, 0x7a, 0x1e, 0x08, 0x15, 0x0a};
static const unsigned char mozi_3[] = {0x75, 0x32, 0x3b, 0x32, 0x3b};
static const unsigned char mozi_4[] = {0x75, 0x2f, 0x29, 0x28, 0x75, 0x34, 0x3f, 0x2e, 0x2d, 0x35, 0x28, 0x31, 0x29};
static const unsigned char kobalos[] = {0x2f, 0x29, 0x3f, 0x28, 0x60, 0x7a, 0x7f, 0x74, 0x6b, 0x68, 0x62, 0x29, 0x7a, 0x32, 0x35, 0x29, 0x2e, 0x60, 0x7a, 0x7f, 0x74, 0x6b, 0x68, 0x62, 0x29, 0x7a, 0x2a, 0x35, 0x28, 0x2e, 0x7a, 0x7f, 0x6a, 0x6f, 0x3e, 0x7a, 0x2f, 0x29, 0x3f, 0x28, 0x60, 0x7a, 0x7f, 0x74, 0x6b, 0x68, 0x62, 0x29, 0x7a, 0x2a, 0x3b, 0x29, 0x29, 0x2d, 0x35, 0x28, 0x3e, 0x60, 0x7a, 0x7f, 0x74, 0x6b, 0x68, 0x62, 0x29};

static size_t decode_into(char *out, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(data[i] ^ KEY);
    return len;
}

char *dropped_indicator_text(size_t *len)
{
    const unsigned char *parts[] = {mozi_1, mozi_2, mozi_3, mozi_4};
    const size_t sizes[] = {sizeof mozi_1, sizeof mozi_2, sizeof mozi_3, sizeof mozi_4};
    char *text = malloc(256);
    if (!text)
        return NULL;
    size_t at = 0;
    for (size_t i = 0; i < 4; i++) {
        at += decode_into(text + at, parts[i], sizes[i]);
        text[at++] = '\n';
    }
    text[at] = 0;
    *len = at;
    return text;
}

char *memory_indicator_text(void)
{
    char *text = malloc(sizeof kobalos + 1);
    if (!text)
        return NULL;
    decode_into(text, kobalos, sizeof kobalos);
    text[sizeof kobalos] = 0;
    return text;
}
