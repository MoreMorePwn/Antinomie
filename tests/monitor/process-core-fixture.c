// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Build statically for the disposable BusyBox process-core qualifier. */
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

volatile char core_evidence[] = "Antinomie process core evidence before exit";
static int finish_workers;

static void *worker(void *unused)
{
    (void)unused;
    if (finish_workers) {
        sleep(2);
        const char marker[] = "worker survived leader exit\n";
        write(STDOUT_FILENO, marker, sizeof(marker) - 1);
        return NULL;
    }
    for (;;) sleep(1);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t first, second;
    const char *mode = argc > 1 ? argv[1] : "normal";
    /* Force a private dirty page: evidence must come from the captured memory. */
    core_evidence[0] = 'A';
    finish_workers = !strcmp(mode, "leader-exit");
    if (!strcmp(mode, "thread-exit")) {
        syscall(SYS_exit, 7);
        return 99;
    }
    if (pthread_create(&first, NULL, worker, NULL) ||
        pthread_create(&second, NULL, worker, NULL)) return 99;
    /* Workers reach a stable sleep before the exit rendezvous. */
    usleep(200000);
    if (finish_workers) pthread_exit(NULL);
    if (!strcmp(mode, "crash")) raise(SIGSEGV);
    if (!strcmp(mode, "terminate")) raise(SIGTERM);
    if (!strcmp(mode, "kill")) raise(SIGKILL);
    if (!strcmp(mode, "descendant")) {
        pid_t child = fork();
        if (child < 0) return 99;
        if (!child) { setsid(); _exit(23); }
        int status;
        if (waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 23) return 99;
    }
    if (!strcmp(mode, "wait")) sleep(60);
    if (!strncmp(mode, "live", 4)) {
        /* Alternating resident and untouched pages verifies
         * that the manual writer emits explicit absent extents, not fake data. */
        volatile unsigned char *memory = mmap(NULL, 4 * 1024 * 1024,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) return 99;
        for (size_t page = 0; page < 4 * 1024 * 1024; page += 8192)
            memory[page] = 0x41;
        for (unsigned int tick = 0; tick < 900; tick++) {
            char text[64];
            int len = snprintf(text, sizeof(text), "live tick %u\n", tick);
            if (len <= 0 || write(STDOUT_FILENO, text, len) != len) return 99;
            struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
            if (poll(&input, 1, 100) > 0) {
                char value[32];
                if (read(STDIN_FILENO, value, sizeof(value)) > 0) break;
            }
        }
        munmap((void *)memory, 4 * 1024 * 1024);
    }
    if (!strcmp(mode, "snapshot")) sleep(40);
    if (!strcmp(mode, "large")) {
        volatile unsigned char *memory = malloc(80 * 1024 * 1024);
        if (!memory) return 99;
        for (size_t i = 0; i < 80 * 1024 * 1024; i += 4096) memory[i] = 0x41;
    }
    return core_evidence[0] == 'A' ? 7 : 99;
}
