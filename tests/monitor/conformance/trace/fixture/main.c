// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// main.c — the syscall trace conformance fixture.
//
//   trace-fixture user|root|threads [AREA...]
//   trace-fixture --exec-target ARG...      (an execve case's new image)
//
// Everything happens in a private directory below /tmp that is removed before
// the final line. The program is safe, offline and time bounded: an alarm
// ends it after 240 seconds. Its last line is
//   ANT_DONE {"group":..,"failures":N}
// and the exit status is 0 only when every case did what it meant to.
#include "areas.h"

#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

char work_dir[256];
char self_path[256];

struct area {
    const char *name;
    const char *group;
    void (*run)(void);
};

static const struct area areas[] = {
    {"file_io", "user", area_file_io},
    {"file_meta", "user", area_file_meta},
    {"paths", "user", area_paths},
    {"xattr_splice", "user", area_xattr_splice},
    {"events", "user", area_events},
    {"net", "user", area_net},
    {"memory", "user", area_memory},
    {"process", "user", area_process},
    {"identity", "user", area_identity},
    {"signals", "user", area_signals},
    {"time", "user", area_time},
    {"futex", "user", area_futex},
    {"ipc", "user", area_ipc},
    {"keys", "user", area_keys},
    {"aio", "user", area_aio},
    {"uring", "user", area_uring},
    {"system", "user", area_system},
    {"root", "root", area_root},
    {"threads", "threads", area_threads},
};
#define AREA_COUNT (sizeof areas / sizeof areas[0])

void pattern(void *buffer, size_t len, unsigned seed)
{
    unsigned char *bytes = buffer;
    static const char text[] = "ANTINOMIE-CONFORMANCE-";
    for (size_t i = 0; i < len; i++)
        bytes[i] = i < sizeof text - 1 ? (unsigned char)text[i]
                                       : (unsigned char)('a' + (i * 7 + seed) % 26);
}

const char *work_path(char *out, size_t size, const char *name)
{
    snprintf(out, size, "%s/%s", work_dir, name);
    return out;
}

void in_child(unsigned index, const char *what, void (*body)(void *), void *arg)
{
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail(what);
        return;
    }
    if (child == 0) {
        ora_child(index);
        body(arg);
        _exit(ora_failures() ? 3 : 0);
    }
    ora_wait(child, what);
}

static void remove_tree(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) {
        unlink(path);
        return;
    }
    struct dirent *entry;
    char child[512];
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        snprintf(child, sizeof child, "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
            chmod(child, 0700);
            remove_tree(child);
        } else {
            unlink(child);
        }
    }
    closedir(dir);
    rmdir(path);
}

static int selected(const struct area *area, const char *group, int argc, char **argv)
{
    if (argc <= 2)
        return !strcmp(area->group, group);
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], area->name))
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--exec-target")) {
        // The new image of an execve case: say so and end with the code its
        // first argument names.
        printf("ANT_EXEC_TARGET argc=%d\n", argc);
        fflush(stdout);
        return argc > 2 ? atoi(argv[2]) : 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: %s user|root|threads [AREA...]\n", argv[0]);
        return 2;
    }
    const char *group = argv[1];
    ora_make_resident();
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(240);
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (len <= 0)
        return 2;
    self_path[len] = 0;
    snprintf(work_dir, sizeof work_dir, "/tmp/ant-conformance-XXXXXX");
    if (!mkdtemp(work_dir) || chdir(work_dir) != 0) {
        perror("work directory");
        return 2;
    }
    group_line("start", group);
    group_line("workdir", work_dir);
    role("main", getpid());
    for (size_t i = 0; i < AREA_COUNT; i++) {
        if (!selected(&areas[i], group, argc, argv))
            continue;
        group_line("area", areas[i].name);
        areas[i].run();
        if (chdir(work_dir) != 0)
            ora_fail("return to the work directory");
    }
    if (chdir("/") != 0)
        ora_fail("leave the work directory");
    remove_tree(work_dir);
    struct stat st;
    if (stat(work_dir, &st) == 0)
        ora_fail("work directory left behind");
    printf("ANT_DONE {\"group\":\"%s\",\"failures\":%u}\n", group, ora_failures());
    fflush(stdout);
    return ora_failures() ? 1 : 0;
}
