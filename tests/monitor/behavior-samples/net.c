// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// net.c — bounded sockets, HTTP and DNS for the behavior samples.
#include "samples.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

int sample_dns_port = 53;

void sample_delay(int milliseconds)
{
    if (milliseconds <= 0)
        return;
    if (milliseconds > SAMPLE_MAX_DELAY_MS)
        milliseconds = SAMPLE_MAX_DELAY_MS;
    struct timespec ts = {.tv_sec = milliseconds / 1000,
                          .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

const char *sample_host(const struct options *options)
{
    return options->host ? options->host : SAMPLE_REMOTE_ADDR;
}

int sample_port(const struct options *options, int fallback)
{
    return options->port > 0 ? options->port : fallback;
}

int sample_mkdir_p(const char *path)
{
    char copy[512];
    int length = snprintf(copy, sizeof copy, "%s", path);
    if (length <= 0 || (size_t)length >= sizeof copy) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct stat info;
    // Only components that are missing are created, so an existing tree
    // produces no failed mkdir calls.
    for (char *cursor = copy + 1;; cursor++) {
        if (*cursor != '/' && *cursor != '\0')
            continue;
        char saved = *cursor;
        *cursor = '\0';
        if (stat(copy, &info) != 0 && mkdir(copy, 0700) != 0 && errno != EEXIST)
            return -1;
        *cursor = saved;
        if (!saved)
            break;
    }
    return stat(path, &info) == 0 && S_ISDIR(info.st_mode) ? 0 : -1;
}

size_t sample_hex(const char *input, char *output, size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    size_t at = 0;
    for (size_t i = 0; input[i] && at + 2 < cap; i++) {
        unsigned char byte = (unsigned char)input[i];
        output[at++] = digits[byte >> 4];
        output[at++] = digits[byte & 15];
    }
    output[at] = 0;
    return at;
}

size_t sample_fingerprint(char *output, size_t cap)
{
    struct utsname info;
    char host[128] = "?";
    if (gethostname(host, sizeof host - 1) != 0)
        strcpy(host, "?");
    host[sizeof host - 1] = 0;
    memset(&info, 0, sizeof info);
    uname(&info);
    snprintf(output, cap, "id=%08x&host=%s&uid=%d&sys=%s&rel=%s&arch=%s",
             (unsigned)(getpid() * 2654435761u ^ (unsigned)time(NULL)), host, (int)getuid(),
             info.sysname, info.release, info.machine);
    return strlen(output);
}

int sample_dial(const char *host, int port, int timeout_ms)
{
    struct sockaddr_in target;
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &target.sin_addr) != 1) {
        // Numeric IPv4 only: a .invalid name cannot resolve anyway, and this
        // keeps the static build independent of glibc's NSS modules.
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int result = connect(fd, (struct sockaddr *)&target, sizeof target);
    if (result < 0 && errno == EINPROGRESS) {
        struct pollfd ready = {.fd = fd, .events = POLLOUT};
        int waited = poll(&ready, 1, timeout_ms);
        if (waited == 0) {
            errno = ETIMEDOUT;
            result = -1;
        } else if (waited < 0) {
            result = -1;
        } else {
            int error = 0;
            socklen_t size = sizeof error;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0) {
                result = 0;
            } else {
                errno = error;
                result = -1;
            }
        }
    }
    if (result == 0 && flags >= 0)
        fcntl(fd, F_SETFL, flags);
    if (result != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int sample_send_all(int fd, const void *buffer, size_t length)
{
    const char *cursor = buffer;
    while (length > 0) {
        ssize_t written = send(fd, cursor, length, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

ssize_t sample_recv_wait(int fd, void *buffer, size_t length, int timeout_ms)
{
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    int waited = poll(&ready, 1, timeout_ms);
    if (waited <= 0)
        return waited;
    return recv(fd, buffer, length, 0);
}

int sample_http_as(const char *host, int port, const char *host_header, const char *method,
                const char *path, const char *body, unsigned long long *received)
{
    size_t body_len = body ? strlen(body) : 0;
    int fd = sample_dial(host, port, 1500);
    if (fd < 0)
        return -1;
    char header[1024];
    int length = snprintf(header, sizeof header,
                          "%s %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "User-Agent: %s\r\n"
                          "Accept: */*\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n\r\n",
                          method, path, host_header, SAMPLE_USER_AGENT, body_len);
    int ok = length > 0 && (size_t)length < sizeof header &&
             sample_send_all(fd, header, (size_t)length) == 0 &&
             (body_len == 0 || sample_send_all(fd, body, body_len) == 0);
    if (ok && received) {
        char sink[4096];
        for (int i = 0; i < 4; i++) {
            ssize_t got = sample_recv_wait(fd, sink, sizeof sink, 400);
            if (got <= 0)
                break;
            *received += (unsigned long long)got;
        }
    }
    close(fd);
    return ok ? 0 : -1;
}

int sample_http_request(const char *host, int port, const char *method, const char *path,
                     const char *body, size_t body_len, unsigned long long *received)
{
    (void)body_len;
    return sample_http_as(host, port, host, method, path, body, received);
}

#define FETCH_HEADER_MAX 1024

ssize_t sample_http_fetch(const char *host, int port, const char *path, unsigned char *body,
                       size_t cap, int *status)
{
    if (status)
        *status = 0;
    int fd = sample_dial(host, port, 1500);
    if (fd < 0)
        return -1;
    char request[1024];
    int length = snprintf(request, sizeof request,
                          "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                          "Accept: */*\r\nConnection: close\r\n\r\n",
                          path, host, SAMPLE_USER_AGENT);
    if (length <= 0 || (size_t)length >= sizeof request ||
        sample_send_all(fd, request, (size_t)length) != 0) {
        close(fd);
        return -1;
    }
    // Peek for the end of the headers, then take exactly the headers: the body
    // is then a read of its own, the way a downloader reads it.
    char head[FETCH_HEADER_MAX + 1];
    size_t head_len = 0;
    for (int attempt = 0; attempt < 40; attempt++) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 100) <= 0)
            continue;
        ssize_t peeked = recv(fd, head, FETCH_HEADER_MAX, MSG_PEEK);
        if (peeked <= 0)
            break;
        head[peeked] = '\0';
        char *end = strstr(head, "\r\n\r\n");
        if (end) {
            head_len = (size_t)(end - head) + 4;
            break;
        }
        if (peeked >= FETCH_HEADER_MAX)
            break;
    }
    if (head_len == 0) {
        close(fd);
        return -1;
    }
    if (recv(fd, head, head_len, MSG_WAITALL) != (ssize_t)head_len) {
        close(fd);
        return -1;
    }
    head[head_len] = '\0';
    int code = 0;
    if (sscanf(head, "HTTP/%*d.%*d %d", &code) != 1)
        code = 0;
    if (status)
        *status = code;
    size_t total = 0;
    while (total < cap) {
        ssize_t got = sample_recv_wait(fd, body + total, cap - total, 400);
        if (got <= 0)
            break;
        total += (size_t)got;
    }
    close(fd);
    return code == 200 ? (ssize_t)total : -1;
}

int sample_touch_port(const char *host, int port)
{
    struct sockaddr_in target;
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &target.sin_addr) != 1)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int result = connect(fd, (struct sockaddr *)&target, sizeof target);
    int started = result == 0 || errno == EINPROGRESS || errno == ECONNREFUSED;
    close(fd);
    return started ? 0 : -1;
}

size_t sample_dns_build(unsigned char *packet, const char *name, uint16_t type, uint16_t id)
{
    size_t length = 0;
    packet[length++] = (unsigned char)(id >> 8);
    packet[length++] = (unsigned char)(id & 255);
    packet[length++] = 0x01; // recursion desired
    packet[length++] = 0x00;
    packet[length++] = 0; // qdcount
    packet[length++] = 1;
    for (int i = 0; i < 6; i++)
        packet[length++] = 0;
    const char *label = name;
    while (*label && length < 480) {
        const char *dot = strchr(label, '.');
        size_t part = dot ? (size_t)(dot - label) : strlen(label);
        if (part > 63)
            part = 63;
        packet[length++] = (unsigned char)part;
        memcpy(packet + length, label, part);
        length += part;
        label += part + (dot ? 1 : 0);
        if (!dot)
            break;
    }
    packet[length++] = 0;
    packet[length++] = (unsigned char)(type >> 8);
    packet[length++] = (unsigned char)(type & 255);
    packet[length++] = 0x00;
    packet[length++] = 0x01; // class IN
    return length;
}

int sample_dns_ask(const char *resolver, const char *name, uint16_t type, int wait_ms)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    // Port 53 needs root for a local sinkhole; --dns-port or SAMPLE_DNS_PORT
    // lets a sinkhole run on an unprivileged port.
    int port = sample_dns_port;
    const char *port_text = getenv("SAMPLE_DNS_PORT");
    if (port == 53 && port_text && *port_text) {
        int parsed = atoi(port_text);
        if (parsed > 0 && parsed < 65536)
            port = parsed;
    }
    server.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, resolver, &server.sin_addr) != 1) {
        close(fd);
        return 0;
    }
    unsigned char packet[512];
    static uint16_t sequence;
    size_t length = sample_dns_build(packet, name, type, (uint16_t)(getpid() * 31u + ++sequence));
    int answered = 0;
    if (sendto(fd, packet, length, 0, (struct sockaddr *)&server, sizeof server) > 0 && wait_ms > 0) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, wait_ms) > 0) {
            unsigned char reply[1500];
            answered = recv(fd, reply, sizeof reply, 0) > 0;
        }
    }
    close(fd);
    return answered;
}
