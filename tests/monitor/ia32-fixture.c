// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// ia32-fixture: the same few benign behaviours built twice, as a 32-bit x86
// (gcc -m32 -static) and an x86-64 program, so a check can compare how the
// recorder and Triage see each (tracer-check ia32). It writes, renames and
// removes a file under /tmp, names itself, maps a page and makes it
// executable, connects to a closed local port and sends one datagram there,
// and runs `sh -c "exit 0"` in a child. Nothing leaves the guest.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DIRECTORY "/tmp/ia32-probe"
#define TEXT "ia32 probe text\n"

static int files(void)
{
    struct stat st;
    int fd;

    if (mkdir(DIRECTORY, 0700) != 0)
        return 1;
    fd = open(DIRECTORY "/note.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, TEXT, strlen(TEXT)) != (ssize_t)strlen(TEXT) || close(fd) != 0)
        return 2;
    if (stat(DIRECTORY "/note.txt", &st) != 0 || st.st_size != (off_t)strlen(TEXT))
        return 3;
    if (rename(DIRECTORY "/note.txt", DIRECTORY "/renamed.txt") != 0)
        return 4;
    if (unlink(DIRECTORY "/renamed.txt") != 0 || rmdir(DIRECTORY) != 0)
        return 5;
    return 0;
}

static int network(void)
{
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(9) };
    int stream, datagram;

    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    stream = socket(AF_INET, SOCK_STREAM, 0);
    if (stream < 0)
        return 6;
    // Nothing listens on the discard port: refused.
    if (connect(stream, (struct sockaddr *)&address, sizeof(address)) == 0)
        return 7;
    close(stream);
    datagram = socket(AF_INET, SOCK_DGRAM, 0);
    if (datagram < 0)
        return 8;
    if (sendto(datagram, "probe", 5, 0, (struct sockaddr *)&address, sizeof(address)) != 5)
        return 9;
    close(datagram);
    return 0;
}

static int memory(void)
{
    char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED)
        return 10;
    page[0] = (char)0xc3;
    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0)
        return 11;
    return munmap(page, 4096) != 0 ? 12 : 0;
}

static int child(void)
{
    int status;
    pid_t pid = fork();

    if (pid < 0)
        return 13;
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", "exit 0", (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 14;
    return 0;
}

int main(void)
{
    struct timespec pause = { .tv_nsec = 10 * 1000 * 1000 };
    struct utsname names;
    int code;

    if (prctl(PR_SET_NAME, "ia32probe", 0, 0, 0) != 0 || uname(&names) != 0)
        return 20;
    nanosleep(&pause, NULL);
    if ((code = files()) || (code = network()) || (code = memory()) || (code = child()))
        return code;
    printf("ia32-fixture %d-bit done\n", (int)(sizeof(long) * 8));
    return 0;
}
