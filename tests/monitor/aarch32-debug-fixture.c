// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// aarch32-debug-fixture.c — a benign 32-bit ARM (EABI5) program for the guest
// debug engine and the ELF32 process cores of AArch32 tasks on arm64 guests
// (contract revision 21). One function is A32 code, one Thumb code; the main
// loop calls both, so a breakpoint in either is hit.
//
//   aarch32-debug-fixture loop ROUNDS   print "symbols arm=0x.. thumb=0x..", then
//                                       call both ROUNDS times, 50 ms apart
//   aarch32-debug-fixture crash         the same line, then a null store
//                                       (SIGSEGV: an exit core)
//   aarch32-debug-fixture calls         the compat calls the recorder captures by
//                                       their ILP32 layouts (revision 21), made with
//                                       raw system calls so that the 32-bit time
//                                       variants are the ones called; "calls done"
//
// Build: arm-linux-gnueabihf-gcc -static -O1 -o aarch32-debug-fixture aarch32-debug-fixture.c
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

volatile unsigned int counter;

__attribute__((noinline, target("arm"))) void arm_spot(unsigned int value)
{
    counter += value;
    counter ^= value << 1;
}

__attribute__((noinline, target("thumb"))) void thumb_spot(unsigned int value)
{
    counter += value * 3;
    counter ^= value >> 1;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "loop";
    unsigned int rounds = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 10) : 100;
    struct timespec pause = {0, 50 * 1000 * 1000};

    // Thumb function pointers carry bit 0; the address is the instruction's.
    printf("symbols arm=0x%lx thumb=0x%lx counter=0x%lx\n", (unsigned long)arm_spot,
           (unsigned long)thumb_spot & ~1UL, (unsigned long)&counter);
    fflush(stdout);
    if (strcmp(mode, "calls") == 0) {
        struct { int32_t sec, nsec; } nap = {0, 1000000}, left = {0, 0}, now = {0, 0};
        struct { int32_t sec, usec; } tv = {0, 0};
        struct { uint32_t handler, flags, restorer, mask[2]; } act = {0, 0, 0, {0, 0}}, old;
        int pipefd[2], status = 0;
        char text[8] = "compat", back[8], dirents[1024];
        struct iovec out = {text, 6}, in = {back, sizeof back};
        struct pollfd ready;
        uint32_t readable[1] = {0};

        syscall(SYS_nanosleep, &nap, &left);
        syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &nap, &left);
        syscall(SYS_clock_gettime, CLOCK_REALTIME, &now);
        syscall(SYS_clock_getres, CLOCK_MONOTONIC, &now);
        syscall(SYS_gettimeofday, &tv, NULL);
        syscall(SYS_rt_sigaction, SIGUSR1, NULL, &old, 8);
        act.handler = 1;	/* SIG_IGN */
        syscall(SYS_rt_sigaction, SIGUSR2, &act, &old, 8);
        if (pipe(pipefd) == 0) {
            syscall(SYS_writev, pipefd[1], &out, 1);
            ready.fd = pipefd[0];
            ready.events = POLLIN;
            ready.revents = 0;
            syscall(SYS_poll, &ready, 1, 0);
            readable[0] = 1u << pipefd[0];
            tv.sec = 0;
            tv.usec = 0;
            syscall(SYS__newselect, pipefd[0] + 1, readable, NULL, NULL, &tv);
            syscall(SYS_readv, pipefd[0], &in, 1);
        }
        int dir = open(".", O_RDONLY | O_DIRECTORY);
        if (dir >= 0)
            syscall(SYS_getdents, dir, dirents, sizeof dirents);
        pid_t kid = fork();
        if (kid == 0)
            _exit(5);
        syscall(SYS_wait4, kid, &status, 0, NULL);
        printf("calls done\n");
        return 0;
    }
    if (strcmp(mode, "crash") == 0) {
        struct rlimit core = {RLIM_INFINITY, RLIM_INFINITY};

        setrlimit(RLIMIT_CORE, &core);
        arm_spot(1);
        thumb_spot(2);
        *(volatile int *)0 = 1;
        return 3;
    }
    for (unsigned int i = 0; i < rounds; i++) {
        arm_spot(i);
        thumb_spot(i);
        nanosleep(&pause, NULL);
    }
    printf("done %u\n", counter);
    return 0;
}
