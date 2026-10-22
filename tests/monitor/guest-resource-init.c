// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Disposable guest qualification init; never installed in a published base. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define TOKEN "0123456789abcdef0123456789abcdef"

static void stop(int status)
{
    printf("ANTINOMIE_RESOURCE_PROBE %s\n", status ? "FAIL" : "PASS");
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    _exit(status);
}
static void fail(const char *message)
{
    printf("probe failed: %s: %s\n", message, strerror(errno));
    stop(1);
}
int main(void)
{
    alarm(20);
    mkdir("/dev", 0755); mkdir("/root", 0755);
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) fail("mount devtmpfs");
    if (mount("/dev/vda", "/root", "ext4", 0, NULL)) fail("mount disposable root disk");
    mkdir("/root/proc", 0755); mkdir("/root/tmp", 01777);
    if (mount("proc", "/root/proc", "proc", 0, NULL)) fail("mount guest proc");
    int source = open("/probe", O_RDONLY), target = open("/root/tmp/resource-probe", O_CREAT | O_EXCL | O_WRONLY, 0700);
    if (source < 0 || target < 0) fail("copy probe");
    char buffer[4096]; ssize_t count;
    while ((count = read(source, buffer, sizeof buffer)) > 0) {
        if (write(target, buffer, (size_t)count) != count) fail("copy write");
    }
    if (count < 0) fail("copy read");
    close(source); close(target);
    int input[2], output[2];
    if (pipe(input) || pipe(output)) fail("pipes");
    pid_t pid = fork();
    if (pid < 0) fail("fork");
    if (!pid) {
        close(input[1]); close(output[0]);
        if (chroot("/root") || chdir("/")) fail("chroot");
        dup2(input[0], STDIN_FILENO); dup2(output[1], STDOUT_FILENO);
        close(input[0]); close(output[1]);
        execl("/tmp/resource-probe", "/tmp/resource-probe", TOKEN, NULL);
        fail("exec");
    }
    close(input[0]); close(output[1]);
    FILE *stream = fdopen(output[0], "r");
    char line[1024];
    if (!stream || !fgets(line, sizeof line, stream) || strcmp(line, "ANTREADY1 " TOKEN "\n")) fail("ready handshake");
    if (access("/root/tmp/resource-probe", F_OK) == 0) fail("self unlink");
    if (write(input[1], "1\n", 2) != 2 || !fgets(line, sizeof line, stream)) fail("sample");
    printf("guest sample: %s", line);
    char version[16], token[40];
    uint64_t seq, total, available, blocks, free_blocks, allowed, fragment;
    int mem_error, disk_error;
    if (sscanf(line, "%15s %39s %" SCNu64 " %d %" SCNu64 " %" SCNu64 " %d %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
               version, token, &seq, &mem_error, &total, &available, &disk_error,
               &blocks, &free_blocks, &allowed, &fragment) != 11 ||
        strcmp(version, "ANTRES1") || strcmp(token, TOKEN) || seq != 1 || mem_error || disk_error ||
        !total || total >= 512ULL * 1024 * 1024 || available > total || !blocks ||
        free_blocks > blocks || allowed > free_blocks || !fragment) fail("guest capacities");
    close(input[1]); fclose(stream);
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) fail("collector cleanup");
    stop(0);
}
