// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// network.c — network capture volume and traffic for the bundled IDS rules.
//
// Without --public all traffic stays between the guest and its NAT gateway or
// nameserver (it still crosses the virtual network card, so the VM-wide
// capture sees it), plus loopback sockets. --public adds example.com.
#include "torture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void pause_us(long us)
{
    struct timespec ts = {.tv_sec = us / 1000000, .tv_nsec = (us % 1000000) * 1000};
    nanosleep(&ts, NULL);
}

// One DNS question for `name` of `type` to `server`; returns 1 if answered.
static int dns_query(int sock, const struct sockaddr_in *server, const char *name, uint16_t type,
                     uint16_t id, int wait_ms)
{
    unsigned char packet[512];
    size_t len = 0;
    packet[len++] = id >> 8;
    packet[len++] = id & 255;
    packet[len++] = 0x01;
    packet[len++] = 0x00;
    packet[len++] = 0;
    packet[len++] = 1;
    memset(packet + len, 0, 6);
    len += 6;
    const char *label = name;
    while (*label && len < 480) {
        const char *dot = strchr(label, '.');
        size_t part = dot ? (size_t)(dot - label) : strlen(label);
        if (part > 63)
            part = 63;
        packet[len++] = (unsigned char)part;
        memcpy(packet + len, label, part);
        len += part;
        label += part + (dot ? 1 : 0);
        if (!dot)
            break;
    }
    packet[len++] = 0;
    packet[len++] = type >> 8;
    packet[len++] = type & 255;
    packet[len++] = 0;
    packet[len++] = 1;
    if (sendto(sock, packet, len, 0, (const struct sockaddr *)server, sizeof *server) < 0)
        return 0;
    if (wait_ms <= 0)
        return 0;
    struct pollfd ready = {.fd = sock, .events = POLLIN};
    if (poll(&ready, 1, wait_ms) <= 0)
        return 0;
    unsigned char reply[1500];
    return recv(sock, reply, sizeof reply, 0) > 0;
}

// Non-blocking TCP connect; returns 0 connected, 1 refused, -1 otherwise.
static int tcp_try(int family, const char *address, int port, int wait_ms, int *fd_out)
{
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_storage target = {0};
    socklen_t len;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&target;
        v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, address, &v4->sin_addr);
        len = sizeof *v4;
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&target;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)port);
        inet_pton(AF_INET6, address, &v6->sin6_addr);
        len = sizeof *v6;
    }
    int result = -1;
    if (connect(fd, (struct sockaddr *)&target, len) == 0) {
        result = 0;
    } else if (errno == EINPROGRESS) {
        struct pollfd ready = {.fd = fd, .events = POLLOUT};
        if (poll(&ready, 1, wait_ms) > 0) {
            int error = 0;
            socklen_t size = sizeof error;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
            result = error == 0 ? 0 : error == ECONNREFUSED ? 1 : -1;
        }
    } else if (errno == ECONNREFUSED) {
        result = 1;
    }
    if (fd_out && result == 0)
        *fd_out = fd;
    else
        close(fd);
    return result;
}

struct loop_server {
    int listener;
    long clients;
    unsigned long long bytes;
};

static void *serve_loopback(void *arg)
{
    struct loop_server *server = arg;
    char buffer[65536];
    for (long i = 0; i < server->clients; i++) {
        int client = accept(server->listener, NULL, NULL);
        if (client < 0)
            break;
        ssize_t got;
        while ((got = recv(client, buffer, sizeof buffer, 0)) > 0)
            server->bytes += (unsigned long long)got;
        close(client);
    }
    return NULL;
}

// Loopback: socket calls and data, not visible to the VM-wide capture.
static int loopback(const struct options *options, const char *name, int family)
{
    int listener = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        return -1;
    struct sockaddr_storage bound = {0};
    socklen_t len;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&bound;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof *v4;
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bound;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        len = sizeof *v6;
    }
    if (bind(listener, (struct sockaddr *)&bound, len) < 0 || listen(listener, 128) < 0 ||
        getsockname(listener, (struct sockaddr *)&bound, &len) < 0) {
        close(listener);
        return -1;
    }
    int port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&bound)->sin_port
                                       : ((struct sockaddr_in6 *)&bound)->sin6_port);
    struct loop_server server = {.listener = listener, .clients = scaled(options, 25)};
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_loopback, &server) != 0) {
        close(listener);
        return -1;
    }
    static char chunk[65536];
    memset(chunk, 'N', sizeof chunk);
    size_t per_client = (size_t)scaled(options, 256 << 10);
    long connected = 0;
    for (long i = 0; i < server.clients; i++) {
        int fd = -1;
        if (tcp_try(family, family == AF_INET ? "127.0.0.1" : "::1", port, 1000, &fd) != 0)
            continue;
        int flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        for (size_t sent = 0; sent < per_client;) {
            ssize_t n = send(fd, chunk, sizeof chunk, 0);
            if (n <= 0)
                break;
            sent += (size_t)n;
        }
        close(fd);
        connected++;
    }
    shutdown(listener, SHUT_RDWR);
    pthread_join(thread, NULL);
    close(listener);
    pass(name, "loopback %s: %ld connections carried %llu bytes",
         family == AF_INET ? "IPv4" : "IPv6", connected, server.bytes);
    count("loopback bytes", server.bytes);
    return 0;
}

static int http_get(const char *host, const char *path, const char *agent, unsigned long long *bytes)
{
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *found;
    if (getaddrinfo(host, "80", &hints, &found) != 0)
        return -1;
    int fd = socket(found->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct timeval timeout = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    int ok = fd >= 0 && connect(fd, found->ai_addr, found->ai_addrlen) == 0;
    freeaddrinfo(found);
    if (!ok) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    char request[512];
    int len = snprintf(request, sizeof request,
                       "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
                       path, host, agent);
    send(fd, request, (size_t)len, 0);
    char reply[8192];
    ssize_t got;
    while ((got = recv(fd, reply, sizeof reply, 0)) > 0)
        *bytes += (unsigned long long)got;
    close(fd);
    return 0;
}

MODULE(network_storm)
{
    const char *name = "network-storm";
    char gateway[64] = "", nameserver[64] = "";
    int have_gateway = default_gateway(gateway, sizeof gateway) == 0;
    int have_dns = first_nameserver(nameserver, sizeof nameserver) == 0;
    if (have_dns) {
        long queries = scaled(options, 200);
        if (queries > 5000)
            queries = 5000;
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
        inet_pton(AF_INET, nameserver, &server.sin_addr);
        long answered = 0;
        char host[128];
        for (long i = 0; i < queries; i++) {
            snprintf(host, sizeof host, "q%05ld.flood.antinomie-torture.invalid", i);
            answered += dns_query(sock, &server, host, i % 2 ? 28 : 1, (uint16_t)i, i % 50 == 0 ? 200 : 0);
            if (i % 50 == 49)
                pause_us(20000);
        }
        close(sock);
        count("DNS questions", (unsigned long long)queries);
        pass(name, "%ld DNS questions to %s (%ld sampled answers)", queries, nameserver, answered);
    } else {
        unavailable(name, "no IPv4 nameserver in /etc/resolv.conf");
    }
    if (have_gateway) {
        long connects = scaled(options, 100);
        long refused = 0, open_ports = 0;
        for (long i = 0; i < connects; i++) {
            int result = tcp_try(AF_INET, gateway, 1024 + (int)(i * 37 % 60000), 300, NULL);
            refused += result == 1;
            open_ports += result == 0;
        }
        pass(name, "%ld TCP connects to %s: %ld refused, %ld open", connects, gateway, refused,
             open_ports);
        count("TCP connect attempts", (unsigned long long)connects);
        long datagrams = scaled(options, 500);
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in sink = {.sin_family = AF_INET, .sin_port = htons(9)};
        inet_pton(AF_INET, gateway, &sink.sin_addr);
        static char payload[1400];
        memset(payload, 'U', sizeof payload);
        unsigned long long sent = 0;
        for (long i = 0; i < datagrams; i++) {
            size_t size = (size_t)(1 + i * 53 % (long)sizeof payload);
            if (sendto(sock, payload, size, 0, (struct sockaddr *)&sink, sizeof sink) > 0)
                sent += size;
            if (i % 100 == 99)
                pause_us(10000);
        }
        close(sock);
        pass(name, "%ld UDP datagrams, %llu bytes, to %s port 9", datagrams, sent, gateway);
        count("UDP bytes", sent);
    } else {
        unavailable(name, "no default gateway: is the VM's network isolated?");
    }
    loopback(options, name, AF_INET);
    if (loopback(options, name, AF_INET6) < 0)
        unavailable(name, "IPv6 loopback is not available");
    if (options->public_network) {
        unsigned long long bytes = 0;
        long requests = scaled(options, 5), ok = 0;
        for (long i = 0; i < requests; i++)
            ok += http_get("example.com", "/", "AntinomieTorture/1.0", &bytes) == 0;
        pass(name, "%ld of %ld HTTP requests to example.com, %llu bytes", ok, requests, bytes);
    } else {
        note(name, "public hosts not contacted; pass --public to add HTTP to example.com");
    }
    return 0;
}

// ---------------------------------------------------------------- detect-ids

MODULE(detect_ids)
{
    const char *name = "detect-ids";
    char gateway[64] = "", nameserver[64] = "";
    note(name, "add tests/monitor/torture/torture.rules as a custom IDS group, with network capture on");
    if (first_nameserver(nameserver, sizeof nameserver) == 0) {
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
        inet_pton(AF_INET, nameserver, &server.sin_addr);
        long repeats = scaled(options, 3);
        for (long i = 0; i < repeats; i++)
            dns_query(sock, &server, "antinomie-ids-test.invalid", 1, (uint16_t)(0x4100 + i), 300);
        close(sock);
        pass(name, "DNS question for antinomie-ids-test.invalid (sid 9900701), %ld times", repeats);
    } else {
        unavailable(name, "no nameserver for the DNS rule");
    }
    if (default_gateway(gateway, sizeof gateway) == 0) {
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in sink = {.sin_family = AF_INET, .sin_port = htons(9)};
        inet_pton(AF_INET, gateway, &sink.sin_addr);
        const char marker[] = "ANTINOMIE-IDS-UDP-MARKER benign torture payload";
        long repeats = scaled(options, 3);
        for (long i = 0; i < repeats; i++)
            sendto(sock, marker, sizeof marker - 1, 0, (struct sockaddr *)&sink, sizeof sink);
        close(sock);
        pass(name, "UDP marker to %s port 9 (sid 9900702), %ld times", gateway, repeats);
    } else {
        unavailable(name, "no gateway for the UDP rule");
    }
    if (options->public_network) {
        unsigned long long bytes = 0;
        if (http_get("example.com", "/antinomie-ids-test", "AntinomieTorture/1.0 ids-test", &bytes) == 0)
            pass(name, "HTTP user agent AntinomieTorture to example.com (sid 9900703)");
        else
            unavailable(name, "example.com did not answer");
    } else {
        note(name, "the HTTP rule (sid 9900703) needs --public");
    }
    return 0;
}
