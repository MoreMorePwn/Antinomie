// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// process.c — process trees, a run that resists stopping, argument vectors,
// and the child roles the program re-executes itself into.
#include "torture.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void sleep_ms(long ms)
{
    struct timespec pause = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&pause, NULL);
}

static int self_path(char *path, size_t size)
{
    ssize_t len = readlink("/proc/self/exe", path, size - 1);
    if (len <= 0)
        return -1;
    path[len] = 0;
    return 0;
}

// ---------------------------------------------------------------- process-tree

static void *tree_thread(void *arg)
{
    long id = (long)arg;
    char name[16];
    snprintf(name, sizeof name, "ant-thread-%ld", id % 1000);
    prctl(PR_SET_NAME, name);
    for (int i = 0; i < 100; i++)
        syscall(SYS_gettid);
    sleep_ms(50);
    return NULL;
}

// A chain: each process forks the next and waits for it.
__attribute__((noreturn)) static void chain(long depth)
{
    for (; depth > 0; depth--) {
        pid_t child = fork();
        if (child == 0)
            continue;
        int status = 0;
        if (child > 0)
            waitpid(child, &status, 0);
        _exit(child > 0 && WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }
    _exit(0);
}

MODULE(process_tree)
{
    const char *name = "process-tree";
    long wide = scaled(options, 300), depth = scaled(options, 50), threads = scaled(options, 32);
    if (wide > CAP_PROCESSES / 2) {
        limit(name, "wide tree capped at %d processes", CAP_PROCESSES / 2);
        wide = CAP_PROCESSES / 2;
    }
    if (depth > 1000)
        depth = 1000;
    // Wide: batches of short-lived children; process ids get reused.
    long made = 0;
    for (long start = 0; start < wide; start += 128) {
        pid_t batch[128];
        int alive = 0;
        for (long i = start; i < wide && i < start + 128; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                prctl(PR_SET_NAME, "ant-wide-child");
                sleep_ms(20);
                _exit(0);
            }
            if (pid > 0)
                batch[alive++] = pid;
        }
        for (int i = 0; i < alive; i++)
            waitpid(batch[i], NULL, 0);
        made += alive;
    }
    pass(name, "wide: %ld children in batches of 128", made);
    // Deep: one chain.
    pid_t root = fork();
    if (root == 0)
        chain(depth);
    int status = 1;
    if (root > 0)
        waitpid(root, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        pass(name, "deep: a chain of %ld processes", depth);
    else
        fail(name, "deep chain of %ld did not complete", depth);
    // Threads, each with its own name.
    pthread_t ids[1024];
    long started = 0;
    for (long i = 0; i < threads && i < 1024; i++)
        if (pthread_create(&ids[started], NULL, tree_thread, (void *)i) == 0)
            started++;
    for (long i = 0; i < started; i++)
        pthread_join(ids[i], NULL);
    pass(name, "threads: %ld named threads", started);
    // Exec chain: one process image replaced again and again.
    char self[4096], hops[16];
    if (self_path(self, sizeof self) == 0) {
        snprintf(hops, sizeof hops, "%ld", scaled(options, 8));
        char *argv[] = {self, "--child", "exec-chain", hops, NULL};
        if (run_wait(argv) == 0)
            pass(name, "exec chain: %s execs in one process", hops);
        else
            fail(name, "exec chain did not complete");
    }
    // Orphans: double forks whose grandchildren are reparented.
    long orphans = scaled(options, 8);
    for (long i = 0; i < orphans; i++) {
        pid_t parent = fork();
        if (parent == 0) {
            if (fork() == 0) {
                prctl(PR_SET_NAME, "ant-orphan");
                sleep_ms(500);
                _exit(0);
            }
            _exit(0);
        }
        if (parent > 0)
            waitpid(parent, NULL, 0);
    }
    pass(name, "orphans: %ld grandchildren outlived their parents", orphans);
    sleep_ms(600);
    count("processes (tree)", (unsigned long long)(made + depth + orphans * 2));
    count("threads", (unsigned long long)started);
    return 0;
}

// ---------------------------------------------------------------- unkillable

static void ignore_term(const char *as)
{
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    prctl(PR_SET_NAME, as);
}

// Waits out the window and 10 s more unless killed, so a process seen as gone
// at the end of the window was ended from outside; it exits on its own later.
static void linger(int seconds)
{
    double end = now() + seconds + 10;
    while (now() < end)
        sleep_ms(200);
    _exit(0);
}

MODULE(unkillable)
{
    const char *name = "unkillable";
    int duration = seconds(options, 30, 120, 600);
#ifdef SINGLE_MODULE
    // As its own program the run's root process resists SIGTERM too.
    ignore_term("ant-unkillable");
#endif
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        fail(name, "pipe: %s", strerror(errno));
        return 1;
    }
    pid_t victim = fork();
    if (victim == 0) {
        close(pipefd[0]);
        ignore_term("ant-stubborn");
        pid_t ids[2] = {0, 0};
        // A child in its own session, outside the run's process group.
        ids[0] = fork();
        if (ids[0] == 0) {
            setsid();
            ignore_term("ant-setsid");
            linger(duration);
        }
        // A daemon: double fork, own session, reparented to init.
        pid_t middle = fork();
        if (middle == 0) {
            setsid();
            pid_t daemon = fork();
            if (daemon == 0) {
                ignore_term("ant-daemon");
                linger(duration);
            }
            if (write(pipefd[1], &daemon, sizeof daemon) < 0)
                _exit(1);
            _exit(0);
        }
        if (middle > 0)
            waitpid(middle, NULL, 0);
        if (write(pipefd[1], &ids[0], sizeof ids[0]) < 0)
            _exit(1);
        close(pipefd[1]);
        linger(duration);
    }
    close(pipefd[1]);
    pid_t daemon = 0, setsid_child = 0;
    if (read(pipefd[0], &daemon, sizeof daemon) != sizeof daemon ||
        read(pipefd[0], &setsid_child, sizeof setsid_child) != sizeof setsid_child) {
        fail(name, "children did not start");
        close(pipefd[0]);
        return 1;
    }
    close(pipefd[0]);
    note(name, "pids: stubborn %d, setsid child %d, daemon %d; all ignore SIGTERM", victim,
         setsid_child, daemon);
    note(name, "Stop or Kill this run in Antinomie within %d s, then compare the survivors", duration);
    double end = now() + duration;
    while (now() < end) {
        sleep_ms(500);
        if (kill(victim, 0) < 0 && kill(setsid_child, 0) < 0 && kill(daemon, 0) < 0)
            break;
    }
    const char *labels[] = {"stubborn", "setsid child", "daemon"};
    pid_t pids[] = {victim, setsid_child, daemon};
    int alive = 0;
    for (int i = 0; i < 3; i++) {
        int running = kill(pids[i], 0) == 0;
        alive += running;
        note(name, "%s %d: %s", labels[i], pids[i], running ? "still running" : "gone");
        if (running)
            kill(pids[i], SIGKILL);
    }
    waitpid(victim, NULL, WNOHANG);
    if (alive)
        pass(name, "%d of 3 processes outlived the window; ended them with SIGKILL", alive);
    else
        pass(name, "all 3 processes were ended from outside within %d s", duration);
    return 0;
}

// ---------------------------------------------------------------- argv-env

MODULE(argv_env)
{
    const char *name = "argv-env";
    char self[4096];
    if (self_path(self, sizeof self) < 0) {
        unavailable(name, "cannot find its own executable");
        return 0;
    }
    long many = scaled(options, 300);
    if (many > 8000)
        many = 8000;
    size_t big = options->level == LEVEL_LIGHT ? 4096 : options->level == LEVEL_HEAVY ? 65536 : 131000;
    long envs = scaled(options, 200);
    size_t total = 0;
    char **argv = calloc((size_t)many + 16, sizeof *argv);
    char **envp = calloc((size_t)envs + 8, sizeof *envp);
    char *large = malloc(big + 1);
    if (!argv || !envp || !large) {
        fail(name, "allocation");
        return 1;
    }
    memset(large, 'L', big);
    large[big] = 0;
    long n = 0;
    argv[n++] = self;
    argv[n++] = "--child";
    argv[n++] = "argv-echo";
    argv[n++] = "";
    argv[n++] = "with spaces and \"quotes\" and 'single'";
    argv[n++] = "new\nline\ttab";
    argv[n++] = "\x01\x02\x1b[31mcontrol\x7f\xc3\xa9\xff";
    argv[n++] = "--flag=value with = signs";
    argv[n++] = large;
    for (long i = 0; i < many; i++) {
        argv[n] = malloc(24);
        snprintf(argv[n], 24, "arg-%05ld", i);
        n++;
    }
    argv[n] = NULL;
    for (long i = 0; argv[i]; i++)
        total += strlen(argv[i]) + 1;
    long e = 0;
    for (long i = 0; i < envs; i++) {
        envp[e] = malloc(64);
        snprintf(envp[e], 64, "ANTINOMIE_ENV_%05ld=value-%ld", i, i * 31);
        total += strlen(envp[e]) + 1;
        e++;
    }
    envp[e++] = "ANTINOMIE_ENV_EMPTY=";
    envp[e++] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    envp[e] = NULL;
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0)
            dup2(null, 1);
        execve(self, argv, envp);
        _exit(errno == E2BIG ? 7 : 127);
    }
    int status = 1;
    if (pid > 0)
        waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        pass(name, "exec with %ld arguments (one of %zu bytes) and %ld variables, %zu bytes", n,
             big, e, total);
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 7)
        limit(name, "the kernel refused %zu bytes of arguments and environment (E2BIG)", total);
    else
        fail(name, "argument exec failed");
    // Past the kernel's limit on purpose: the failed exec is recorded too.
    char *huge = malloc(256 << 10);
    if (huge) {
        memset(huge, 'H', (256 << 10) - 1);
        huge[(256 << 10) - 1] = 0;
        char *over[] = {self, "--child", "argv-echo", huge, NULL};
        pid = fork();
        if (pid == 0) {
            execve(self, over, environ);
            _exit(errno == E2BIG ? 7 : 127);
        }
        if (pid > 0 && waitpid(pid, &status, 0) > 0 && WIFEXITED(status) &&
            WEXITSTATUS(status) == 7)
            pass(name, "a 256 KiB argument was refused with E2BIG, as expected");
        free(huge);
    }
    count("argument bytes", total);
    return 0;
}

// ---------------------------------------------------------------- child roles

int crash_role(const char *kind, long mib);

int child_role(int argc, char **argv)
{
    const char *role = argc > 2 ? argv[2] : "";
    if (!strcmp(role, "instant-exit"))
        return 0;
    if (!strcmp(role, "burst-exit")) {
        for (int i = 0; i < 10000; i++)
            syscall(SYS_getppid);
        return 0;
    }
    if (!strcmp(role, "sleep")) {
        sleep_ms(argc > 3 ? atol(argv[3]) : 100);
        return 0;
    }
    if (!strcmp(role, "argv-echo")) {
        size_t bytes = 0;
        for (int i = 0; i < argc; i++)
            bytes += strlen(argv[i]) + 1;
        printf("argc %d, %zu bytes\n", argc, bytes);
        return 0;
    }
    if (!strcmp(role, "exec-chain")) {
        long hops = argc > 3 ? atol(argv[3]) : 0;
        if (hops <= 0)
            return 0;
        char self[4096], next[24];
        if (self_path(self, sizeof self) < 0)
            return 1;
        snprintf(next, sizeof next, "%ld", hops - 1);
        char *again[] = {self, "--child", "exec-chain", next, NULL};
        execv(self, again);
        return 1;
    }
    if (!strcmp(role, "dns-pcap") && argc > 3) {
        int write_dns_pcap(const char *path);
        return write_dns_pcap(argv[3]);
    }
    if (!strcmp(role, "crash"))
        return crash_role(argc > 3 ? argv[3] : "segv", argc > 4 ? atol(argv[4]) : 32);
    fprintf(stderr, "unknown child role %s\n", role);
    return 2;
}
