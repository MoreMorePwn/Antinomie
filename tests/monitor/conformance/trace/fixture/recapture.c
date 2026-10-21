// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// recapture.c — inputs the recorder reads again at exit (contract section 22).
//
// The recorder copies user memory without faulting. Memory a process has
// mapped but not touched yet is recorded NOT_RESIDENT at the call's entry; the
// call itself faults it in, so the recorder reads it again at exit and marks
// it "at exit", or, after an exec replaced the caller's memory, takes the
// kernel's own copy, marked "kernel copy". Every case here passes memory its
// process has not touched:
//   - a forked child's literals: fork() copies no page-table entries of
//     read-only file mappings, and these children skip ora_make_resident();
//   - an exec's path and vectors, after a successful and a failed exec;
//   - static glibc's start-up readlinkat("/proc/self/exe") of this program;
//   - a file mapping no one has read, written to a file;
//   - a buffer another thread rewrites while the call runs: the mark is what
//     tells such bytes from what the call was given;
//   - memory the call never reads, which stays NOT_RESIDENT and which the
//     recorder leaves unloaded (mincore).
//
// Slots: openat execve readlinkat write mincore (all also covered elsewhere).
#include "areas.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define PAGE 4096

// Fault-around maps the page-cache pages of the 64 KiB aligned window around
// a fault, so a literal shares no window with anything else the program
// reads. Each child that uses it is forked fresh, without its parent's page
// table entries for it.
#define COLD_SIZE 65536
#define COLD_TEXT(i) cold_literals.text[i]
static const struct {
    char text[10][64];
    char pad[COLD_SIZE - 10 * 64];
} cold_literals __attribute__((aligned(COLD_SIZE))) = {.text = {
    "recapture-file",     // 0: openat
    "recapture-exe",      // 1: execve path and argv[0] (a link to this program)
    "--exec-target",      // 2
    "21",                 // 3: the new image's exit code
    "ANT_RECAPTURE=exec", // 4
    "recapture-noexec",   // 5: a file the kernel cannot execute
    "ANT_RECAPTURE=fail", // 6
}};

// What a cold child reports to its parent about an exec that replaced it.
struct exec_slot {
    long pid, tid;
    uint64_t t0;
    long argv, envp;
};

static void cold_child(unsigned index, const char *what, void (*body)(void))
{
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail(what);
        return;
    }
    if (child == 0) {
        ora_child_cold(index);
        body();
        _exit(ora_failures() ? 3 : 0);
    }
    ora_wait(child, what);
}

static void describe_strings(int arg, const char *const vector[])
{
    char key[48];
    for (int i = 0; vector[i]; i++) {
        snprintf(key, sizeof key, "arg%d.string[%d]", arg, i);
        in_key(key, vector[i], strlen(vector[i]) + 1);
    }
}

static void open_child(void)
{
    long fd = CALL("openat.cold_literal", openat, WANT_OK, AT_FDCWD, COLD_TEXT(0), O_RDONLY);
    in_str(1, COLD_TEXT(0));
    want_recapture("arg1.path", "at exit");
    file_fd("OPEN", (int)fd);
    why("a forked child has no page-table entry for its literal; openat faults it in");
    DONE();
    if (fd >= 0)
        close((int)fd);
}

static void failed_exec_child(void)
{
    const char *argv[] = {COLD_TEXT(5), COLD_TEXT(2), NULL};
    const char *envp[] = {COLD_TEXT(6), NULL};
    CALL("execve.cold_failed", execve, ENOEXEC, COLD_TEXT(5), argv, envp);
    in_str(0, COLD_TEXT(5));
    describe_strings(1, argv);
    describe_strings(2, envp);
    want_recapture("arg0.path", "at exit");
    // The entry stops at the first string it cannot read; the exit reads
    // that string and the rest of the vector (pointers too) again.
    want_recapture("arg1.*", "at exit");
    want_recapture("arg2.*", "at exit");
    why("the exec fails after copying its strings, so the caller's memory is there at exit");
    DONE();
}

static struct exec_slot *slot;

static void exec_child(void)
{
    const char *argv[] = {COLD_TEXT(1), COLD_TEXT(2), COLD_TEXT(3), NULL};
    const char *envp[] = {COLD_TEXT(4), NULL};
    slot->pid = getpid();
    slot->tid = syscall(SYS_gettid);
    slot->argv = (long)argv;
    slot->envp = (long)envp;
    slot->t0 = ora_now();
    syscall(SYS_execve, COLD_TEXT(1), argv, envp);
    _exit(99);
}

static void exec_cases(void)
{
    int status = -1;
    pid_t pid;

    if (symlink(self_path, COLD_TEXT(1)) != 0)
        ora_fail("link to the fixture for the recapture exec");
    slot = mmap(NULL, sizeof *slot, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (slot == MAP_FAILED) {
        ora_fail("exec slot");
        return;
    }
    memset(slot, 0, sizeof *slot);
    ora_flush();
    pid = fork();
    if (pid == 0) {
        ora_child_cold(431);
        exec_child();
    }
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        ora_fail("recapture exec child");
    const char *argv[] = {COLD_TEXT(1), COLD_TEXT(2), COLD_TEXT(3), NULL};
    const char *envp[] = {COLD_TEXT(4), NULL};
    remote_begin("execve.cold_literals", "execve", SYS_execve, slot->pid, slot->tid, slot->t0,
                 ora_now(), 3, (long[6]){(long)COLD_TEXT(1), slot->argv, slot->envp}, 0);
    in_str(0, COLD_TEXT(1));
    describe_strings(1, argv);
    describe_strings(2, envp);
    // The exec replaced the caller's memory: the path is the exec's own copy
    // and the strings come from the new image's stack.
    want_recapture("arg0.path", "kernel copy");
    want_recapture("arg1.string*", "kernel copy");
    want_recapture("arg2.string*", "kernel copy");
    why("the new image prints ANT_EXEC_TARGET and exits 21");
    volatile_case();
    DONE();
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 21)
        ora_fail("recapture exec target exit code");
    munmap(slot, sizeof *slot);
    unlink(COLD_TEXT(1));
}

// static glibc reads /proc/self/exe before main() (_dl_non_dynamic_init,
// readlinkat) from a literal no code had read yet.
static void startup_case(void)
{
    remote_begin("readlinkat.static_startup", "readlinkat", SYS_readlinkat, getpid(),
                 syscall(SYS_gettid), 0, main_t0, 4, (long[6]){0}, (long)strlen(self_path));
    args_unchecked(0x3f);
    in_str(1, "/proc/self/exe");
    want_recapture("arg1.path", "at exit");
    why("static glibc's start-up readlinkat; its literal was not resident yet");
    volatile_case();
    DONE();
}

// A file mapping no one has touched in this process: write() faults it in.
static void mapping_case(void)
{
    static unsigned char data[2 * PAGE];
    int in = open("recapture-map", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int out = open("recapture-out", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    pattern(data, sizeof data, 22);
    if (in < 0 || out < 0 || write(in, data, sizeof data) != (ssize_t)sizeof data) {
        ora_fail("recapture mapping files");
        return;
    }
    void *map = mmap(NULL, sizeof data, PROT_READ, MAP_PRIVATE, in, 0);
    if (map == MAP_FAILED) {
        ora_fail("recapture mapping");
        return;
    }
    CALL("write.untouched_mapping", write, WANT_OK, out, map, sizeof data);
    in_buf(1, data, sizeof data);
    want_recapture("arg1.data", "at exit");
    why("the mapping was never read; write() faults it in");
    DONE();
    munmap(map, sizeof data);
    close(in);
    close(out);
    unlink("recapture-map");
    unlink("recapture-out");
}

// Memory the call never reads stays NOT_RESIDENT: /dev/null's write does not
// read its buffer, and the recorder's own reads leave the page unloaded.
static void untouched_case(void)
{
    unsigned char vec[1] = {0xff};
    int null = open("/dev/null", O_WRONLY);
    void *buffer = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (null < 0 || buffer == MAP_FAILED) {
        ora_fail("untouched buffer");
        return;
    }
    CALL("write.never_read", write, WANT_OK, null, buffer, PAGE);
    want_status(1, "in", "NOT_RESIDENT");
    why("/dev/null does not read the buffer, so it is not resident at exit either");
    DONE();
    CALL("mincore.recorder_left_it", mincore, WANT_OK, buffer, PAGE, vec);
    out_buf(2, "\0", 1);
    why("the recorder never loads memory: the page is still not resident");
    DONE();
    munmap(buffer, PAGE);
    close(null);
}

// Another thread rewrites the buffer while write() is blocked half way.
struct race {
    int pipe[2];
    unsigned char *buffer;
    unsigned char got[2 * PAGE];
    int ok;
};

static void *race_thread(void *arg)
{
    struct race *race = arg;
    struct pollfd ready = {.fd = race->pipe[0], .events = POLLIN};
    size_t len = 0;

    // The first page is in the pipe: the writer copied it and waits for room.
    if (poll(&ready, 1, 10000) != 1)
        return NULL;
    memset(race->buffer, 'X', 2 * PAGE);
    while (len < sizeof race->got) {
        ssize_t n = read(race->pipe[0], race->got + len, sizeof race->got - len);
        if (n <= 0)
            return NULL;
        len += (size_t)n;
    }
    race->ok = 1;
    return NULL;
}

static void race_case(void)
{
    static struct race race;
    static unsigned char rewritten[2 * PAGE];
    pthread_t thread;

    race.buffer = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (race.buffer == MAP_FAILED || pipe(race.pipe) != 0 ||
        fcntl(race.pipe[1], F_SETPIPE_SZ, PAGE) != PAGE) {
        ora_fail("recapture race setup");
        return;
    }
    if (pthread_create(&thread, NULL, race_thread, &race) != 0) {
        ora_fail("recapture race thread");
        return;
    }
    memset(rewritten, 'X', sizeof rewritten);
    CALL("write.rewritten_during_call", write, WANT_OK, race.pipe[1], race.buffer, 2 * PAGE);
    // What the recorder read when the call returned, not what it was given.
    in_buf(1, rewritten, sizeof rewritten);
    want_recapture("arg1.data", "at exit");
    why("the buffer was not resident at entry; a second thread rewrote it while the call "
        "blocked on a full pipe, so the bytes read at exit are the new ones");
    DONE();
    pthread_join(thread, NULL);
    // The pipe got zeros for the first page (copied before the rewrite).
    if (!race.ok || race.got[0] != 0 || race.got[PAGE - 1] != 0 || race.got[PAGE] != 'X')
        ora_fail("recapture race: the call did not see the rewrite as expected");
    munmap(race.buffer, 2 * PAGE);
    close(race.pipe[0]);
    close(race.pipe[1]);
}

void area_recapture(void)
{
    int fd = open(COLD_TEXT(0), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    static const unsigned char junk[] = "not an executable\n";
    int noexec = open(COLD_TEXT(5), O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0 || noexec < 0 || write(noexec, junk, sizeof junk) != (ssize_t)sizeof junk)
        ora_fail("recapture files");
    if (fd >= 0)
        close(fd);
    if (noexec >= 0)
        close(noexec);
    startup_case();
    cold_child(421, "recapture openat child", open_child);
    cold_child(422, "recapture failed exec child", failed_exec_child);
    exec_cases();
    mapping_case();
    untouched_case();
    race_case();
    unlink(COLD_TEXT(0));
    unlink(COLD_TEXT(5));
}
