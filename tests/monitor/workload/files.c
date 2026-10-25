// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// files.c — file changes at volume: the Files tab, changed-file diffs and
// recovered files.
#include "workload.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

MODULE(file_churn)
{
    const char *name = "file-churn";
    long directories = scaled(options, 10), per_directory = scaled(options, 100) / 4;
    if (per_directory < 25)
        per_directory = 25;
    size_t largest = options->level == LEVEL_EXTREME ? 1 << 20 : 64 << 10;
    unsigned char *data = malloc(largest);
    if (!data) {
        fail(name, "allocation");
        return 1;
    }
    for (size_t i = 0; i < largest; i++)
        data[i] = (unsigned char)(i * 131 + 7);
    unsigned long long operations = 0, bytes = 0;
    int capped = 0;
    char dir[512], path[640], other[640];
    for (long d = 0; d < directories && !capped; d++) {
        snprintf(dir, sizeof dir, "%s/dir-%03ld/nested/deeper", options->workdir, d);
        char partial[512];
        snprintf(partial, sizeof partial, "%s/dir-%03ld", options->workdir, d);
        mkdir(partial, 0700);
        snprintf(partial, sizeof partial, "%s/dir-%03ld/nested", options->workdir, d);
        mkdir(partial, 0700);
        mkdir(dir, 0700);
        operations += 3;
        for (long f = 0; f < per_directory; f++) {
            size_t size = (size_t)(f * 977 % (long)largest) + 1;
            if (bytes + size > CAP_DISK_BYTES) {
                capped = 1;
                break;
            }
            snprintf(path, sizeof path, "%s/file-%04ld.dat", dir, f);
            if (write_file(path, data, size, 0600) == 0)
                bytes += size, operations += 3;
            snprintf(other, sizeof other, "%s/renamed-%04ld.dat", dir, f);
            if (rename(path, other) == 0)
                operations++;
            switch (f % 8) {
            case 0:
                chmod(other, 0640);
                break;
            case 1:
                setxattr(other, "user.antinomie", "workload", 7, 0);
                break;
            case 2:
                truncate(other, (off_t)size / 2);
                break;
            case 3: {
                struct timespec times[2] = {{.tv_sec = 1000000000}, {.tv_sec = 1000000000}};
                utimensat(AT_FDCWD, other, times, 0);
                break;
            }
            case 4:
                snprintf(path, sizeof path, "%s/hardlink-%04ld", dir, f);
                link(other, path);
                break;
            case 5:
                snprintf(path, sizeof path, "%s/symlink-%04ld", dir, f);
                symlink(other, path);
                break;
            case 6: {
                int in = open(other, O_RDONLY | O_CLOEXEC);
                snprintf(path, sizeof path, "%s/copy-%04ld.dat", dir, f);
                int outfd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                if (in >= 0 && outfd >= 0) {
                    ssize_t copied = copy_file_range(in, NULL, outfd, NULL, size, 0);
                    if (copied > 0)
                        bytes += (unsigned long long)copied;
                }
                if (in >= 0)
                    close(in);
                if (outfd >= 0)
                    close(outfd);
                break;
            }
            default:
                unlink(other);
                break;
            }
            operations++;
        }
    }
    if (capped)
        limit(name, "stopped at the %llu MiB disk cap", CAP_DISK_BYTES >> 20);
    pass(name, "%ld directories with %ld files each: %llu operations, %llu bytes", directories,
         per_directory, operations, bytes);
    // Special forms: an unnamed file given a name, a shared mapping written
    // through memory, preallocation, an exchange of two names and sendfile.
    int special = 0;
    int tmp = open(options->workdir, O_TMPFILE | O_RDWR, 0600);
    if (tmp >= 0) {
        if (write(tmp, data, 4096) == 4096) {
            char proc[64];
            snprintf(proc, sizeof proc, "/proc/self/fd/%d", tmp);
            snprintf(path, sizeof path, "%s/was-tmpfile", options->workdir);
            if (linkat(AT_FDCWD, proc, AT_FDCWD, path, AT_SYMLINK_FOLLOW) == 0)
                special++;
        }
        close(tmp);
    }
    snprintf(path, sizeof path, "%s/mapped.dat", options->workdir);
    int mapped = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (mapped >= 0 && ftruncate(mapped, 1 << 20) == 0) {
        unsigned char *view = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_SHARED, mapped, 0);
        if (view != MAP_FAILED) {
            memset(view, 'M', 1 << 20);
            if (msync(view, 1 << 20, MS_SYNC) == 0)
                special++;
            munmap(view, 1 << 20);
        }
        if (fallocate(mapped, 0, 0, 2 << 20) == 0)
            special++;
    }
    snprintf(other, sizeof other, "%s/exchange.dat", options->workdir);
    if (write_file(other, "exchange", 8, 0600) == 0 &&
        renameat2(AT_FDCWD, path, AT_FDCWD, other, RENAME_EXCHANGE) == 0)
        special++;
    if (mapped >= 0) {
        snprintf(path, sizeof path, "%s/sent.dat", options->workdir);
        int sent = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        off_t offset = 0;
        if (sent >= 0 && sendfile(sent, mapped, &offset, 1 << 20) > 0)
            special++;
        if (sent >= 0)
            close(sent);
        close(mapped);
    }
    pass(name, "%d of 5 special forms (O_TMPFILE+linkat, msync, fallocate, RENAME_EXCHANGE, sendfile)",
         special);
    free(data);
    count("file operations", operations);
    count("file bytes written", bytes);
    return 0;
}
