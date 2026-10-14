// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Temporary 0.6.1 guest resource producer. No shell or guest libraries needed. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/prctl.h>
#include <termios.h>
#include <unistd.h>

static int memory(uint64_t *total, uint64_t *available)
{
    FILE *file = fopen("/proc/meminfo", "re");
    char line[256], unit[8], extra;
    uint64_t value;
    unsigned found = 0, lines = 0;
    if (!file) return errno;
    while (fgets(line, sizeof line, file) && ++lines <= 256) {
        const char *field = NULL;
        unsigned bit = 0;
        if (!strncmp(line, "MemTotal:", 9)) { field = line + 9; bit = 1; }
        if (!strncmp(line, "MemAvailable:", 13)) { field = line + 13; bit = 2; }
        if (!field) continue;
        if ((found & bit) || sscanf(field, " %" SCNu64 " %7s %c", &value, unit, &extra) != 2 || strcmp(unit, "kB") ||
            value > UINT64_MAX / 1024) { fclose(file); return EINVAL; }
        found |= bit;
        if (bit == 1) *total = value * 1024;
        else *available = value * 1024;
    }
    int error = ferror(file) ? EIO : 0;
    fclose(file);
    if (error) return error;
    return found == 3 && *total && *available <= *total ? 0 : EINVAL;
}

int main(int argc, char **argv)
{
    /* The host supplies an opaque, fixed-length ASCII token, never a command. */
    if (argc != 2 || strlen(argv[1]) != 32 || strspn(argv[1], "0123456789abcdef") != 32)
        return 2;
    /* Exact uploaded path; keep no persistent helper file in the guest. */
    if (unlink(argv[0])) return 3;
    char name[16];
    snprintf(name, sizeof name, "%.15s", argv[1]);
    if (prctl(PR_SET_NAME, name, 0, 0, 0)) return 7;
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) == 0) {
        cfmakeraw(&term);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &term)) return 4;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("ANTREADY1 %s\n", argv[1]);
    char input[32];
    size_t used = 0;
    uint64_t previous = 0;
    for (;;) {
        struct pollfd fd = { .fd = STDIN_FILENO, .events = POLLIN };
        /* No host heartbeat for 30s: exit even after an uncertain launch. */
        int ready = poll(&fd, 1, 30000);
        if (ready <= 0 || (fd.revents & (POLLERR | POLLNVAL))) return 0;
        char ch;
        if (read(STDIN_FILENO, &ch, 1) != 1) return 0;
        if (ch != '\n') {
            if (ch < '0' || ch > '9' || used == sizeof input - 1) return 5;
            input[used++] = ch;
            continue;
        }
        input[used] = 0;
        errno = 0;
        char *end;
        uint64_t seq = strtoull(input, &end, 10);
        if (errno || !used || *end || seq <= previous) return 6;
        previous = seq;
        used = 0;
        uint64_t total = 0, available = 0;
        int mem_error = memory(&total, &available);
        struct statvfs disk = {0};
        int disk_error = statvfs("/", &disk) ? errno : 0;
        printf("ANTRES1 %s %" PRIu64 " %d %" PRIu64 " %" PRIu64 " %d %lu %lu %lu %lu\n",
               argv[1], seq, mem_error, total, available, disk_error,
               (unsigned long)disk.f_blocks, (unsigned long)disk.f_bfree,
               (unsigned long)disk.f_bavail, (unsigned long)disk.f_frsize);
    }
}
