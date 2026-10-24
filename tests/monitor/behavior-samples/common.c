// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// common.c — file, path and helper-process utilities shared by the scenarios.
//
// The helper processes are the way the samples show the shape of a command
// without running it: sample_spoof() starts this same binary with an argv such as
// {"iptables", "-F"}. The kernel and the trace see an exec with that argument
// vector, and the child does nothing but exit (SAMPLE_NOOP, see main.c). The
// program named in argv[0] is never looked up or run.
#include "samples.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

int sample_write_all(int fd, const void *buffer, size_t length)
{
    const char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

int sample_write_bytes(const char *path, const void *data, size_t length, unsigned mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    int result = sample_write_all(fd, data, length);
    if (close(fd) != 0)
        result = -1;
    return result;
}

int sample_write_text(const char *path, const char *text)
{
    return sample_write_bytes(path, text, strlen(text), 0600);
}

int sample_write_nested(const char *path, const char *text)
{
    char parent[512];
    int length = snprintf(parent, sizeof parent, "%s", path);
    if (length <= 0 || (size_t)length >= sizeof parent)
        return -1;
    char *slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    if (sample_mkdir_p(parent) != 0)
        return -1;
    return sample_write_text(path, text);
}

int sample_path(char *output, size_t cap, const char *base, const char *relative)
{
    int length = snprintf(output, cap, "%s/%s", base, relative);
    if (length < 0 || (size_t)length >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int sample_self_path(char *output, size_t cap)
{
    ssize_t length = readlink("/proc/self/exe", output, cap - 1);
    if (length <= 0)
        return -1;
    output[length] = '\0';
    return 0;
}

int sample_copy_file(const char *from, const char *to, unsigned mode, size_t limit)
{
    int input = open(from, O_RDONLY | O_CLOEXEC);
    if (input < 0)
        return -1;
    int output = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
    if (output < 0) {
        close(input);
        return -1;
    }
    char buffer[65536];
    size_t total = 0;
    ssize_t got;
    int result = 0;
    while ((got = read(input, buffer, sizeof buffer)) > 0) {
        total += (size_t)got;
        if (total > limit || sample_write_all(output, buffer, (size_t)got) != 0) {
            result = -1;
            break;
        }
    }
    if (got < 0)
        result = -1;
    close(input);
    if (close(output) != 0)
        result = -1;
    if (result == 0)
        result = chmod(to, mode) == 0 ? 0 : -1;
    return result;
}

#define SPAWN_WAIT_MS 4000

// Waits for `pid` at most SPAWN_WAIT_MS, then kills that pid and reaps it.
static int wait_bounded(pid_t pid, int limit_ms)
{
    int status = 0;
    for (int waited = 0; waited <= limit_ms; waited += 10) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        if (done < 0 && errno != EINTR)
            return -1;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&pause, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

int sample_spawn_capture(const char *path, char *const argv[], char *const extra_env[],
                      const char *mode, const char *cwd, char *output, size_t cap)
{
    char *environment[256];
    size_t count = 0;
    char marker[64];
    // A NULL mode starts the program as it is (the pinned payloads); any other
    // mode makes this binary exit at once, whatever argv names.
    if (mode)
        snprintf(marker, sizeof marker, "SAMPLE_NOOP=%s", mode);
    for (size_t i = 0; environ && environ[i] && count < 200; i++)
        if (strncmp(environ[i], "SAMPLE_NOOP=", 9) != 0 &&
            strncmp(environ[i], "SAMPLE_MEMFD_CHILD=", 16) != 0)
            environment[count++] = environ[i];
    for (size_t i = 0; extra_env && extra_env[i] && count < 250; i++)
        environment[count++] = extra_env[i];
    if (mode)
        environment[count++] = marker;
    environment[count] = NULL;
    int channel[2] = {-1, -1};
    if (output && cap > 0) {
        output[0] = '\0';
        if (pipe2(channel, O_CLOEXEC) != 0)
            return -1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        if (channel[0] >= 0) {
            close(channel[0]);
            close(channel[1]);
        }
        return -1;
    }
    if (child == 0) {
        if (channel[1] >= 0 && (dup2(channel[1], 1) < 0 || dup2(channel[1], 2) < 0))
            _exit(126);
        if (cwd && chdir(cwd) != 0)
            _exit(126);
        execve(path, argv, environment);
        _exit(127);
    }
    if (channel[1] >= 0)
        close(channel[1]);
    size_t used = 0;
    int status = 0;
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);
    for (;;) {
        // Drain the pipe until it reports end of file, then just wait.
        if (channel[0] >= 0) {
            struct pollfd ready = {.fd = channel[0], .events = POLLIN};
            if (poll(&ready, 1, 10) > 0) {
                char scrap[256];
                ssize_t got = used + 1 < cap ? read(channel[0], output + used, cap - 1 - used)
                                             : read(channel[0], scrap, sizeof scrap);
                if (got > 0 && used + 1 < cap) {
                    used += (size_t)got;
                    output[used] = '\0';
                } else if (got <= 0) {
                    close(channel[0]);
                    channel[0] = -1;
                }
            }
        } else {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
            nanosleep(&pause, NULL);
        }
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) {
            if (channel[0] >= 0) {
                ssize_t got = used + 1 < cap ? read(channel[0], output + used, cap - 1 - used) : 0;
                if (got > 0) {
                    used += (size_t)got;
                    output[used] = '\0';
                }
                close(channel[0]);
            }
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)(now.tv_sec - started.tv_sec) * 1000 +
                       (now.tv_nsec - started.tv_nsec) / 1000000;
        if ((done < 0 && errno != EINTR) || elapsed > SPAWN_WAIT_MS)
            break;
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    if (channel[0] >= 0)
        close(channel[0]);
    return -1;
}

int sample_spawn(const char *path, char *const argv[], char *const extra_env[], const char *mode,
              const char *cwd)
{
    return sample_spawn_capture(path, argv, extra_env, mode, cwd, NULL, 0);
}

int sample_spoof(char *const argv[], char *const extra_env[])
{
    char self[512];
    if (sample_self_path(self, sizeof self) != 0)
        return -1;
    return sample_spawn(self, argv, extra_env, "exit", NULL);
}

int sample_spoof_all(const char *module, const struct spoof *list, size_t count)
{
    int ran = 0;
    for (size_t i = 0; i < count; i++) {
        if (sample_spoof(list[i].argv, NULL) == 0)
            ran++;
        else
            sample_note(module, "could not start the stand-in for %s %s", list[i].argv[0],
                     list[i].argv[1] ? list[i].argv[1] : "");
    }
    return ran;
}

int sample_in_child(int (*body)(void *context), void *context, int limit_ms)
{
    fflush(stdout);
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        int status = body(context);
        fflush(stdout);
        _exit(status & 0xff);
    }
    return wait_bounded(child, limit_ms);
}

int sample_noop(const char *mode)
{
    char self[512];
    const char *target = getenv("SAMPLE_NOOP_OUT");
    if (!target || !*target || sample_self_path(self, sizeof self) != 0)
        return 0;
    if (!strcmp(mode, "selfdelete") && !strcmp(self, target))
        unlink(self);
    else if (!strcmp(mode, "compile") && strcmp(self, target) != 0)
        sample_copy_file(self, target, 0755, 8u << 20);
    return 0;
}

int sample_is_private(const char *address)
{
    struct in_addr parsed;
    if (!address || inet_pton(AF_INET, address, &parsed) != 1)
        return 0;
    uint32_t ip = ntohl(parsed.s_addr);
    return (ip >> 24) == 10 || (ip >> 24) == 127 || (ip >> 20) == 0xac1 || (ip >> 16) == 0xc0a8 ||
           (ip >> 16) == 0xa9fe;
}

// ---- SHA-256 ------------------------------------------------------------------

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t state[8], const unsigned char block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 |
               (uint32_t)block[i * 4 + 2] << 8 | (uint32_t)block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choose + k256[i] + w[i];
        uint32_t s0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sample_sha256_hex(const void *data, size_t length, char output[65])
{
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const unsigned char *bytes = data;
    size_t offset = 0;
    for (; offset + 64 <= length; offset += 64)
        sha256_block(state, bytes + offset);
    unsigned char tail[128];
    size_t rest = length - offset;
    memset(tail, 0, sizeof tail);
    if (rest)
        memcpy(tail, bytes + offset, rest);
    tail[rest] = 0x80;
    size_t total = rest + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)length * 8;
    for (int i = 0; i < 8; i++)
        tail[total - 1 - (size_t)i] = (unsigned char)(bits >> (8 * i));
    for (size_t at = 0; at < total; at += 64)
        sha256_block(state, tail + at);
    for (int i = 0; i < 8; i++)
        snprintf(output + i * 8, 9, "%08x", state[i]);
}
