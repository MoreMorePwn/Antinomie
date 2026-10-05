// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    char input[64] = {0}, filename[96], buffer[4096];
    struct stat metadata;
    struct iovec vectors[2];
    pid_t child;
    int fd, status;
    printf("PROBE UID=%u GID=%u ENV=%s\n", getuid(), getgid(), getenv("ANT_PROBE"));
    fflush(stdout);
    snprintf(filename, sizeof(filename), "/tmp/ant-probe-%d", getpid());
    fd = openat(AT_FDCWD, filename, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) return 10;
    memset(buffer, 'A', sizeof(buffer));
    memcpy(buffer, "ANTINOMIE-POINTER-CONTENT", 24);
    vectors[0] = (struct iovec){buffer, 2048};
    vectors[1] = (struct iovec){buffer + 2048, 2048};
    if (writev(fd, vectors, 2) != sizeof(buffer)) return 11;
    if (lseek(fd, 0, SEEK_SET) < 0) return 12;
    memset(buffer, 0, sizeof(buffer));
    if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) return 13;
    if (memcmp(buffer, "ANTINOMIE-POINTER-CONTENT", 24)) return 14;
    if (fstat(fd, &metadata) || metadata.st_size != sizeof(buffer)) return 15;
    errno = 0;
    if (syscall(SYS_write, fd, (void *)1, 64) != -1 || errno != EFAULT) return 16;
    close(fd);
    if (unlink(filename)) return 17;
    child = fork();
    if (child < 0) return 18;
    if (!child) {
        setsid();
        execl("/bin/sh", "sh", "-c", "echo PROBE-DESCENDANT; sleep 1", NULL);
        _exit(19);
    }
    if (waitpid(child, &status, 0) != child || status) return 20;
    child = fork();
    if (child < 0) return 22;
    if (!child) {
        pid_t orphan;
        if (setsid() < 0) _exit(23);
        orphan = fork();
        if (orphan < 0) _exit(24);
        if (orphan) _exit(0);
        sleep(1);
        execl("/bin/sh", "sh", "-c", "echo PROBE-ORPHAN", NULL);
        _exit(25);
    }
    if (waitpid(child, &status, 0) != child || status) return 26;
    sleep(2);
    printf("PROBE READY\n");
    fflush(stdout);
    if (read(STDIN_FILENO, input, sizeof(input) - 1) <= 0) return 21;
    printf("PROBE INPUT=%s", input);
    printf("PROBE PASS\n");
    return 0;
}
