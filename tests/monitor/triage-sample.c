// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Run only in the disposable sample guest. All file changes stay in a fresh
 * /tmp directory; network destinations are the isolated local fixture server. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned char memory_marker[] = "ANTINOMIE_TRIAGE_FIXTURE_v1";
static int failures;

static void resident_string(char *value)
{
    /* Fault in each literal's page before Antinomie's deliberate nofault reads. */
    volatile char *resident = value;
    for (size_t index = 0; resident[index]; index++) (void)resident[index];
}

static void check(const char *label, int success)
{
    int error = success ? 0 : errno;
    printf("%s %s errno=%d\n", success ? "PASS" : "UNAVAILABLE", label, error);
    if (!success) failures++;
}

static void file_activity(void)
{
    char buffer[256] = {0};
    int fd = open("changed.txt", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) { check("create changed.txt", 0); return; }
    const char initial[] = "original line\nunchanged line\n";
    check("initial write", write(fd, initial, sizeof(initial) - 1) == (ssize_t)sizeof(initial) - 1);
    check("read original bytes", pread(fd, buffer, sizeof(buffer), 0) > 0);
    const char final[] = "MODIFIED line\nunchanged line\nnew line\n";
    check("overwrite bytes", pwrite(fd, final, sizeof(final) - 1, 0) == (ssize_t)sizeof(final) - 1);
    check("truncate", ftruncate(fd, (off_t)sizeof(final) - 1) == 0);
    check("read final bytes", pread(fd, buffer, sizeof(buffer), 0) > 0);
    check("fsync", fsync(fd) == 0);
    /* A non-executable data file exercises setuid-mode observation; never exec it. */
    check("setuid metadata", fchmod(fd, 04600) == 0);
    check("restore mode", fchmod(fd, 0600) == 0);
    int duplicate = dup(fd);
    if (duplicate >= 0) close(duplicate);
    close(fd);

    fd = open("changed.txt", O_RDONLY);
    if (fd >= 0) {
        char first[8], second[64];
        struct iovec parts[] = {{first, sizeof(first)}, {second, sizeof(second)}};
        check("readv", readv(fd, parts, 2) > 0);
        close(fd);
    }
    check("rename", rename("changed.txt", "renamed.txt") == 0);
    check("hard link", link("renamed.txt", "alias.txt") == 0);
    check("symlink", symlink("renamed.txt", "symbolic.txt") == 0);
    check("unlink alias", unlink("alias.txt") == 0);
    fd = open("deleted.txt", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
        const char removed[] = "deleted fixture contents\n";
        (void)write(fd, removed, sizeof(removed) - 1);
        close(fd);
        check("delete file", unlink("deleted.txt") == 0);
    }
    fd = open("missing-file", O_RDONLY);
    check("expected failed open", fd == -1 && errno == ENOENT);
    if (fd >= 0) close(fd);
}

static void *thread_activity(void *unused)
{
    (void)unused;
    int fd = open("thread.txt", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
        const char text[] = "worker thread evidence\n";
        (void)write(fd, text, sizeof(text) - 1);
        close(fd);
    }
    return NULL;
}

static void process_activity(void)
{
    pid_t child = fork();
    if (child == 0) {
        char shell[] = "/bin/sh";
        char name[] = "sh", option[] = "-c";
        char script[] = "printf 'shell child evidence\\n' > shell.txt; "
            "(printf 'grandchild evidence\\n' > grandchild.txt; /bin/sleep 1) & wait";
        char *arguments[] = {name, option, script, NULL};
        for (size_t index = 0; arguments[index]; index++) resident_string(arguments[index]);
        resident_string(shell);
        execv(shell, arguments);
        _exit(127);
    }
    int status = 0;
    check("shell child and grandchild", child > 0 && waitpid(child, &status, 0) == child &&
          WIFEXITED(status) && WEXITSTATUS(status) == 0);
    pthread_t thread;
    int result = pthread_create(&thread, NULL, thread_activity, NULL);
    check("worker thread", result == 0);
    if (result == 0) pthread_join(thread, NULL);
}

static int peer(int type, uint16_t port)
{
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 4};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, "10.0.2.2", &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void network_activity(void)
{
    unsigned char response[4096];
    int fd = peer(SOCK_DGRAM, 53);
    if (fd >= 0) {
        /* triage.test A, answered only by the owned local DNS fixture. */
        const unsigned char query[] = {0x62,0x62,1,0,0,1,0,0,0,0,0,0,
            6,'t','r','i','a','g','e',4,'t','e','s','t',0,0,1,0,1};
        int sent = send(fd, query, sizeof(query), 0) == (ssize_t)sizeof(query);
        ssize_t len = sent ? recv(fd, response, sizeof(response), 0) : -1;
        check("DNS request and response", len >= 12 && response[0] == 0x62 && response[1] == 0x62);
        close(fd);
    } else check("DNS connect", 0);

    fd = peer(SOCK_STREAM, 8080);
    if (fd >= 0) {
        const char request[] = "GET /ANTINOMIE_TRIAGE_FIXTURE_v1 HTTP/1.1\r\n"
            "Host: triage.test\r\nUser-Agent: Antinomie-Triage-Fixture/1\r\nConnection: close\r\n\r\n";
        int sent = send(fd, request, sizeof(request) - 1, MSG_NOSIGNAL) == (ssize_t)sizeof(request) - 1;
        ssize_t len = sent ? recv(fd, response, sizeof(response), 0) : -1;
        check("HTTP request and response", len >= 12 && !memcmp(response, "HTTP/1.1 200", 12));
        while (len > 0) len = recv(fd, response, sizeof(response), 0);
        close(fd);
    } else check("HTTP connect", 0);
}

static void filter_activity(void)
{
    struct bpf_insn code[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    const char license[] = "GPL"; /* Kernel program-type compatibility declaration. */
    union bpf_attr attributes = {0};
    attributes.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attributes.insn_cnt = sizeof(code) / sizeof(code[0]);
    attributes.insns = (uintptr_t)code;
    attributes.license = (uintptr_t)license;
    int program = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attributes, sizeof(attributes));
    check("BPF program load", program >= 0);
    if (program >= 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        check("BPF socket attach", fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF,
              &program, sizeof(program)) == 0);
        if (fd >= 0) close(fd);
        close(program);
    }
    /* Allow-all seccomp creates observable filter telemetry, without blocking
     * operations needed by the fixture or changing any other process. */
    struct sock_filter instructions[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog filter = {.len = 1, .filter = instructions};
    check("no_new_privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    check("seccomp allow-all filter", syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter) == 0);
}

int main(int argc, char **argv)
{
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 1) {
        /* The initial control launch may predate trace membership. A real
         * self-exec provides captured executable identity for the process tree. */
        char path[] = "/tmp/triage-sample", option[] = "--recorded";
        char *arguments[] = {path, option, NULL};
        resident_string(path);
        resident_string(option);
        execv(path, arguments);
        perror("recorded self-exec");
        return 1;
    }
    char directory[] = "/tmp/antinomie-triage-XXXXXX";
    if (!mkdtemp(directory) || chdir(directory)) { perror("sample directory"); return 1; }
    printf("ANTINOMIE TRIAGE SAMPLE pid=%ld directory=%s\n", (long)getpid(), directory);
    memory_marker[0] = 'A';
    void *mapping = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("RWX mapping", mapping != MAP_FAILED);
    if (mapping != MAP_FAILED) memcpy(mapping, (const void *)memory_marker, sizeof(memory_marker));
    file_activity();
    process_activity();
    network_activity();
    filter_activity();
    /* Allow executable acquisition to finish while the root task is still live. */
    sleep(2);
    /* Keep the marker and RWX region resident for core-on-exit capture. */
    printf("TRIAGE SAMPLE DONE unavailable=%d marker=%s\n", failures, (const char *)memory_marker);
    return failures ? 2 : 0;
}
