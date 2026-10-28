// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// file_pos.c — where reads and writes happened, and what in-kernel copies
// moved (contract revision 18: file.position and file.copy).
//
// The position of a descriptor is the open file's, shared by every task and
// every descriptor that refers to it, and an O_APPEND write lands at the end
// of the file as it is when the write runs. These cases make the position
// differ from what one process could infer on its own: a write of a forked
// child through the parent's descriptor, a dup, and writers that append to
// one file at the same time. Two processes that write the same range at the
// same time finish in an order their exits need not show: the file's bytes
// say which write the file system applied last, and its write order must say
// the same. The copy cases cover each in-kernel copy, from a
// file (no bytes carried) and from a pipe (the bytes carried; a socket's
// bytes reach a file through a pipe), and each kind of fallocate range.
#include "areas.h"

#include <fcntl.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#define RACERS 4
#define RACE_WRITES 16
#define RECORD 16
#define OVERLAP_ROUNDS 16

static long tid_of_self(void)
{
    return syscall(SYS_gettid);
}

struct shared_fd {
    int fd;
    char block[7];
};

static void child_writes(void *arg)
{
    struct shared_fd *shared = arg;
    // The parent wrote 10 bytes before the fork: the shared position is 10.
    CALL("write.forked_child", write, WANT_OK, shared->fd, shared->block, sizeof shared->block);
    in_buf(1, shared->block, sizeof shared->block);
    file_pos(10, sizeof shared->block);
    why("a forked child writes through the parent's descriptor: the open file's position moves for both");
    DONE();
}

static void shared_position(void)
{
    char data[10], tail[5], back[4];
    pattern(data, sizeof data, 81);
    pattern(tail, sizeof tail, 82);
    long fd = CALL("openat.pos_shared", openat, WANT_OK, AT_FDCWD, "pos-shared",
                   O_CREAT | O_RDWR | O_TRUNC, 0600);
    in_str(1, "pos-shared");
    file_fd("OPEN", (int)fd);
    DONE();
    CALL("write.pos_first", write, WANT_OK, fd, data, sizeof data);
    in_buf(1, data, sizeof data);
    file_pos(0, sizeof data);
    DONE();

    struct shared_fd shared = {.fd = (int)fd};
    pattern(shared.block, sizeof shared.block, 83);
    in_child(800, "forked writer", child_writes, &shared);
    // This process wrote 10 bytes; the file's position is 17 after the child.
    CALL("write.after_child", write, WANT_OK, fd, tail, sizeof tail);
    in_buf(1, tail, sizeof tail);
    file_pos(17, sizeof tail);
    why("the position the child left: 17, not the 10 this process wrote");
    DONE();

    long copy = CALL("dup.pos_shared", dup, WANT_OK, fd);
    DONE();
    CALL("write.through_dup", write, WANT_OK, copy, tail, 3);
    in_buf(1, tail, 3);
    file_pos(22, 3);
    DONE();
    CALL("pread64.pos_explicit", pread64, WANT_OK, fd, back, sizeof back, 2);
    out_buf(1, data + 2, sizeof back);
    file_pos(2, sizeof back);
    DONE();
    struct iovec vec = {.iov_base = back, .iov_len = sizeof back};
    CALL("readv.pos_at_end", readv, WANT_OK, fd, &vec, 1);
    file_pos(25, 0);
    why("the position is at the end of the file: the read moves nothing, and says where");
    DONE();
    CASE("close.pos_dup", close, WANT_OK, copy);
    CASE("close.pos_shared", close, WANT_OK, fd);
}

// One racing writer: what it did, for the parent to report after the race.
struct racer {
    long pid, tid;
    struct {
        uint64_t t0, t1;
        long ret;
        char record[RECORD];
    } writes[RACE_WRITES];
};

struct race {
    volatile int go;
    struct racer racers[RACERS];
};

static void racer_body(struct race *race, int index, int fd)
{
    struct racer *self = &race->racers[index];
    char record[RECORD];
    self->pid = getpid();
    self->tid = tid_of_self();
    while (!race->go)
        ;
    for (int n = 0; n < RACE_WRITES; n++) {
        // Unique, so the parent finds where each one landed.
        memset(record, 0, sizeof record);
        snprintf(record, sizeof record, "racer%d-write%02d", index, n);
        memcpy(self->writes[n].record, record, RECORD);
        self->writes[n].t0 = ora_now();
        self->writes[n].ret = syscall(SYS_write, fd, record, RECORD);
        self->writes[n].t1 = ora_now();
        if (self->writes[n].ret != RECORD)
            _exit(4);
    }
    _exit(0);
}

static void racing_appends(void)
{
    struct race *race = mmap(NULL, sizeof *race, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t children[RACERS];
    char *file;
    if (race == MAP_FAILED) {
        ora_fail("race mmap");
        return;
    }
    memset(race, 0, sizeof *race);
    long fd = CALL("openat.append_race", openat, WANT_OK, AT_FDCWD, "pos-append",
                   O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0600);
    in_str(1, "pos-append");
    file_fd("OPEN", (int)fd);
    DONE();
    ora_flush();
    for (int index = 0; index < RACERS; index++) {
        children[index] = fork();
        if (children[index] == 0) {
            ora_child_cold(810 + index);
            racer_body(race, index, (int)fd);
        }
    }
    race->go = 1;
    for (int index = 0; index < RACERS; index++)
        ora_wait(children[index], "append racer");
    CASE("close.append_race", close, WANT_OK, fd);

    // Where each record landed is where the kernel put it.
    size_t total = (size_t)RACERS * RACE_WRITES * RECORD;
    file = malloc(total);
    int check = open("pos-append", O_RDONLY | O_CLOEXEC);
    if (!file || check < 0 || read(check, file, total) != (ssize_t)total) {
        ora_fail("append race readback");
        free(file);
        if (check >= 0)
            close(check);
        return;
    }
    close(check);
    static char labels[RACERS][RACE_WRITES][48];
    int interleaved = 0;
    for (int index = 0; index < RACERS; index++) {
        struct racer *racer = &race->racers[index];
        long last = -1;
        for (int n = 0; n < RACE_WRITES; n++) {
            long at = -1;
            for (size_t slot = 0; slot < total / RECORD; slot++)
                if (!memcmp(file + slot * RECORD, racer->writes[n].record, RECORD))
                    at = (long)(slot * RECORD);
            if (at < 0) {
                ora_fail("append race record missing");
                continue;
            }
            interleaved |= last >= 0 && at != last + RECORD;
            last = at;
            snprintf(labels[index][n], sizeof labels[index][n], "write.append_race.%d.%02d", index,
                     n);
            remote_begin(labels[index][n], "write", SYS_write, racer->pid, racer->tid,
                         racer->writes[n].t0, racer->writes[n].t1, 3,
                         (long[6]){fd, 0, RECORD}, racer->writes[n].ret);
            args_unchecked(1 << 1);
            in_buf(1, racer->writes[n].record, RECORD);
            file_pos((uint64_t)at, RECORD);
            volatile_case();
            why("O_APPEND writers race: each lands at the end of the file as it was then");
            DONE();
        }
    }
    group_line("append_race", interleaved ? "interleaved" : "serial");
    free(file);
    munmap(race, sizeof *race);
}

// Two processes write the same 16 bytes of one file at once, round after
// round (each round its own range): one write of each pair is applied last.
struct overlap {
    volatile int ready[OVERLAP_ROUNDS][2];
    long pid[2], tid[2];
    struct {
        uint64_t t0, t1;
        long ret;
        char record[RECORD];
    } writes[OVERLAP_ROUNDS][2];
};

static void overlap_body(struct overlap *race, int index, int fd)
{
    race->pid[index] = getpid();
    race->tid[index] = tid_of_self();
    for (int round = 0; round < OVERLAP_ROUNDS; round++) {
        char record[RECORD];
        memset(record, 0, sizeof record);
        snprintf(record, sizeof record, "writer%d-round%02d", index, round);
        memcpy(race->writes[round][index].record, record, RECORD);
        // Both writers start each round together.
        race->ready[round][index] = 1;
        while (!race->ready[round][1 - index])
            sched_yield();
        race->writes[round][index].t0 = ora_now();
        race->writes[round][index].ret =
            syscall(SYS_pwrite64, fd, record, RECORD, (long)round * RECORD);
        race->writes[round][index].t1 = ora_now();
        if (race->writes[round][index].ret != RECORD)
            _exit(4);
    }
    _exit(0);
}

static void overlapping_writers(void)
{
    struct overlap *race = mmap(NULL, sizeof *race, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t children[2];
    char file[OVERLAP_ROUNDS * RECORD];
    if (race == MAP_FAILED) {
        ora_fail("overlap mmap");
        return;
    }
    memset(race, 0, sizeof *race);
    long fd = CALL("openat.overlap_race", openat, WANT_OK, AT_FDCWD, "pos-overlap",
                   O_CREAT | O_RDWR | O_TRUNC, 0600);
    in_str(1, "pos-overlap");
    file_fd("OPEN", (int)fd);
    DONE();
    ora_flush();
    for (int index = 0; index < 2; index++) {
        children[index] = fork();
        if (children[index] == 0) {
            ora_child_cold(820 + index);
            overlap_body(race, index, (int)fd);
        }
    }
    for (int index = 0; index < 2; index++)
        ora_wait(children[index], "overlapping writer");
    if (pread(fd, file, sizeof file, 0) != (ssize_t)sizeof file) {
        ora_fail("overlap readback");
        return;
    }
    CASE("close.overlap_race", close, WANT_OK, fd);

    // The bytes of each round are the write applied last: the other one's
    // write order must be lower.
    static char labels[OVERLAP_ROUNDS][2][48];
    for (int round = 0; round < OVERLAP_ROUNDS; round++)
        for (int index = 0; index < 2; index++)
            snprintf(labels[round][index], sizeof labels[round][index],
                     "pwrite64.overlap_race.%02d.%d", round, index);
    for (int round = 0; round < OVERLAP_ROUNDS; round++) {
        int last = -1;
        for (int index = 0; index < 2; index++)
            if (!memcmp(file + round * RECORD, race->writes[round][index].record, RECORD))
                last = index;
        if (last < 0) {
            ora_fail("overlap round has neither record");
            continue;
        }
        for (int index = 0; index < 2; index++) {
            remote_begin(labels[round][index], "pwrite64", SYS_pwrite64, race->pid[index],
                         race->tid[index], race->writes[round][index].t0,
                         race->writes[round][index].t1, 4,
                         (long[6]){fd, 0, RECORD, (long)round * RECORD},
                         race->writes[round][index].ret);
            args_unchecked(1 << 1);
            in_buf(1, race->writes[round][index].record, RECORD);
            file_pos((uint64_t)round * RECORD, RECORD);
            if (index != last)
                file_written_before(labels[round][last]);
            volatile_case();
            why("two processes write the same range at once: the write order says which "
                "the file system applied last, as the file's bytes do");
            DONE();
        }
    }
    munmap(race, sizeof *race);
}

static void copies(void)
{
    char data[32], back[8];
    int pipes[2], sockets[2];
    pattern(data, sizeof data, 84);
    int src = open("pos-src", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    int dst = open("pos-dst", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (src < 0 || dst < 0 || write(src, data, sizeof data) != sizeof data ||
        lseek(dst, 5, SEEK_SET) != 5 || pipe2(pipes, O_CLOEXEC) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)) {
        ora_fail("copy setup");
        return;
    }

    // From a file: the operands only; the host rebuilds the bytes.
    off_t offset = 3;
    CALL("sendfile.file_to_file", sendfile, WANT_OK, dst, src, &offset, 8);
    file_copy("SENDFILE", src, 3, dst, 5, 8, 0, 0);
    DONE();
    loff_t in_offset = 1, out_offset = 50;
    CALL("copy_file_range.file_to_file", copy_file_range, WANT_OK, src, &in_offset, dst,
         &out_offset, 10, 0);
    file_copy("COPY_RANGE", src, 1, dst, 50, 10, 0, 0);
    DONE();
    loff_t from = 4;
    CALL("splice.file_to_pipe", splice, WANT_OK, src, &from, pipes[1], NULL, 6, 0);
    file_copy("SPLICE", src, 4, pipes[0], -1, 6, 0, 0);
    why("the destination is a pipe: only the source has a position");
    DONE();
    CALL("read.pipe_no_position", read, WANT_OK, pipes[0], back, 6);
    out_buf(1, data + 4, 6);
    file_pos_none();
    DONE();

    // From a pipe: nothing can read the bytes again, so they come along.
    static const char piped[] = "PIPEDATA";
    if (write(pipes[1], piped, 8) != 8) {
        ora_fail("pipe fill");
        return;
    }
    loff_t to = 40;
    CALL("splice.pipe_to_file", splice, WANT_OK, pipes[0], NULL, dst, &to, 8, 0);
    file_copy("SPLICE", pipes[0], -1, dst, 40, 8, 0, 8);
    out_key("file.copy.data", piped, 8);
    DONE();
    static const char socketed[] = "SOCKET";
    if (write(sockets[1], socketed, 6) != 6) {
        ora_fail("socket fill");
        return;
    }
    CALL("sendfile.socket_refused", sendfile, EINVAL, dst, sockets[0], NULL, 6);
    why("sendfile needs a seekable source: a socket's bytes reach a file through a pipe");
    DONE();
    CALL("splice.socket_to_pipe", splice, WANT_OK, sockets[0], NULL, pipes[1], NULL, 6, 0);
    why("between a socket and a pipe: no file, no file.copy");
    DONE();
    // dst's position is 13 after the first sendfile.
    CALL("splice.socket_pipe_to_file", splice, WANT_OK, pipes[0], NULL, dst, NULL, 6, 0);
    file_copy("SPLICE", pipes[0], -1, dst, 13, 6, 0, 6);
    out_key("file.copy.data", socketed, 6);
    DONE();

    // A reflink: ext4 and tmpfs share no extents, so the guest refuses it and
    // records nothing (a copy is recorded only when it succeeded).
    int clone = open("pos-clone", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    CALL("ioctl.ficlone_unsupported", ioctl, WANT_ANY, clone, FICLONE, src);
    why("the guest's file systems have no reflinks; a clone that fails has no file.copy");
    DONE();
    close(clone);

    // Allocations: the range and what it did.
    CALL("fallocate.pos_extend", fallocate, WANT_OK, dst, 0, 100, 50);
    file_copy("FALLOCATE", -1, -1, dst, 100, 50, 0, 0);
    DONE();
    CALL("fallocate.pos_punch", fallocate, WANT_OK, dst, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
         2, 3);
    file_copy("FALLOCATE", -1, -1, dst, 2, 3, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0);
    DONE();
    close(sockets[0]);
    close(sockets[1]);
    close(pipes[0]);
    close(pipes[1]);
    close(src);
    close(dst);
    // Removed here, a few at a time: the guest hashes each file a run deletes
    // through a bounded queue, which a burst at the end could overflow.
    static const char *const names[] = {"pos-shared", "pos-append", "pos-overlap", "pos-src",
                                        "pos-dst",    "pos-clone"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        unlink(names[i]);
        usleep(20000);
    }
}

void area_file_pos(void)
{
    shared_position();
    racing_appends();
    overlapping_writers();
    copies();
}
