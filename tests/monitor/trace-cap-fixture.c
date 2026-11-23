// SPDX-License-Identifier: GPL-3.0-only
/*
 * trace-cap-fixture: a benign program that makes system calls as fast as it
 * can, so a run reaches its recording cap (`[resources] trace_cap_mib`) in
 * seconds (ANT-T0612, tests/monitor/test-auto-trace-cap.py).
 *
 * First it appends one line to an existing file on the guest's disk
 * (--file, else the first of /etc/profile, /etc/inittab and /etc/passwd
 * that exists), so the run has a changed file whose earlier bytes the
 * recording keeps. Then, until it is stopped or --seconds pass,
 * every round makes --getpid getpid() calls and one non-blocking connect()
 * to a random address of TEST-NET-1/2/3 (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24: documentation ranges, never routed) or of 10.0.0.0/8,
 * closed at once. Nothing is read from the network and no payload is sent.
 *
 *     trace-cap-fixture [--seconds N] [--getpid N] [--file PATH] [--no-connect]
 *
 * Build static for the BusyBox guest: gcc -O2 -static -o trace-cap-fixture
 * trace-cap-fixture.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static unsigned long next_random(unsigned long *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static in_addr_t unroutable(unsigned long *state)
{
    static const unsigned char nets[3][3] = {{192, 0, 2}, {198, 51, 100}, {203, 0, 113}};
    unsigned long r = next_random(state);
    unsigned char host = (unsigned char)(1 + r % 254);
    if ((r >> 8) % 4 == 3) {
        return htonl((10u << 24) | (unsigned)((r >> 16) & 0xffffff) | 1u);
    }
    const unsigned char *net = nets[(r >> 8) % 3];
    return htonl(((unsigned)net[0] << 24) | ((unsigned)net[1] << 16) | ((unsigned)net[2] << 8) | host);
}

static void touch_file(const char *path)
{
    /* The first of these that exists on the guest's disk. */
    const char *const choices[] = {path, "/etc/profile", "/etc/inittab", "/etc/passwd"};
    int fd = -1;
    for (unsigned i = 0; i < sizeof choices / sizeof *choices && fd < 0; i++) {
        path = choices[i];
        fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    }
    if (fd < 0) {
        fprintf(stderr, "trace-cap-fixture: no file to change: %s\n", strerror(errno));
        return;
    }
    printf("trace-cap-fixture: changed %s\n", path);
    static const char line[] = "# trace-cap-fixture was here\n";
    if (write(fd, line, sizeof line - 1) < 0) {
        fprintf(stderr, "trace-cap-fixture: write %s: %s\n", path, strerror(errno));
    }
    fsync(fd);
    close(fd);
}

int main(int argc, char **argv)
{
    long seconds = 0;
    long getpids = 64;
    int connects = 1;
    const char *file = "/etc/hostname";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
            seconds = strtol(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--getpid") && i + 1 < argc) {
            getpids = strtol(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--file") && i + 1 < argc) {
            file = argv[++i];
        } else if (!strcmp(argv[i], "--no-connect")) {
            connects = 0;
        } else {
            fprintf(stderr, "usage: %s [--seconds N] [--getpid N] [--file PATH] [--no-connect]\n", argv[0]);
            return 2;
        }
    }
    touch_file(file);
    unsigned long state = (unsigned long)time(NULL) ^ ((unsigned long)getpid() << 16) ^ 0x9e3779b97f4a7c15ul;
    time_t end = seconds > 0 ? time(NULL) + seconds : 0;
    unsigned long rounds = 0;
    for (;;) {
        for (long n = 0; n < getpids; n++) {
            syscall(SYS_getpid);
        }
        if (connects) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd >= 0) {
                struct sockaddr_in to;
                memset(&to, 0, sizeof to);
                to.sin_family = AF_INET;
                to.sin_port = htons((unsigned short)(1024 + next_random(&state) % 60000));
                to.sin_addr.s_addr = unroutable(&state);
                (void)connect(fd, (struct sockaddr *)&to, sizeof to);
                close(fd);
            }
        }
        rounds++;
        if (end && (rounds & 1023) == 0 && time(NULL) >= end) {
            break;
        }
    }
    printf("trace-cap-fixture: %lu rounds\n", rounds);
    return 0;
}
