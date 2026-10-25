// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// network.c — network capture volume and traffic for the bundled IDS rules.
//
// Without --public all traffic stays between the guest and its NAT gateway or
// nameserver (it still crosses the virtual network card, so the VM-wide
// capture sees it), plus loopback sockets. --public adds example.com.
#include "workload.h"

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

// A DNS question for `name` of `type` with header `flags`; returns its length.
static size_t dns_build(unsigned char *packet, const char *name, uint16_t type, uint16_t id,
                        uint16_t flags)
{
    size_t len = 0;
    packet[len++] = id >> 8;
    packet[len++] = id & 255;
    packet[len++] = flags >> 8;
    packet[len++] = flags & 255;
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
    return len;
}

// One DNS question for `name` of `type` to `server`; returns 1 if answered.
static int dns_query(int sock, const struct sockaddr_in *server, const char *name, uint16_t type,
                     uint16_t id, int wait_ms)
{
    unsigned char packet[512];
    size_t len = dns_build(packet, name, type, id, 0x0100);
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

MODULE(network_load)
{
    const char *name = "network-load";
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
            snprintf(host, sizeof host, "q%05ld.flood.antinomie-workload.invalid", i);
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
            ok += http_get("example.com", "/", "AntinomieWorkload/1.0", &bytes) == 0;
        pass(name, "%ld of %ld HTTP requests to example.com, %llu bytes", ok, requests, bytes);
    } else {
        note(name, "public hosts not contacted; pass --public to add HTTP to example.com");
    }
    return 0;
}

// ---------------------------------------------------------------- detect-ids

// Questions that public Emerging Threats Open rules report by name. They are
// lookups only: nothing connects to these services.
static const struct {
    const char *name;
    unsigned sid;
} et_questions[] = {
    {"api.ipify.org", 2047702},         // External IP lookup (ipify)
    {"tunnel.ngrok.io", 2022642},       // *.ngrok.io
    {"dashboard.ngrok.com", 2022641},   // *.ngrok.com
    {"antinomie.duckdns.org", 2042936}, // dynamic DNS
    {"checkip.dyndns.org", 2043238},    // external IP lookup (dyndns)
    {"transfer.sh", 2034316},           // file transfer service
    {"gateway.discord.com", 2035465},   // Discord
    {"api.telegram.org", 2033966},      // Telegram API
    {"termbin.com", 2050513},           // pastebin-like
    {"ip-api.io", 2039045},             // external IP lookup (ip-api)
};

// Odd questions that public rules report: two Suricata built-in DNS event
// rules, and an over-long name that Emerging Threats Open reports as a large
// query. The resolver only rejects them. (Checked with Suricata 8: a response
// sent as a request and a cut-short question raise no event, so they are not
// sent.)
static size_t malformed_dns(unsigned kind, unsigned char *packet, unsigned *sid)
{
    switch (kind) {
    case 0: // Z flag set
        *sid = 2240006;
        return dns_build(packet, "antinomie-z-flag.invalid", 1, 0x5a01, 0x0140);
    case 1: // opcode 15
        *sid = 2240007;
        return dns_build(packet, "antinomie-opcode.invalid", 1, 0x5a02, 0x7900);
    default: { // a name longer than 255 bytes
        *sid = 2013075;
        char name[400];
        size_t at = 0;
        for (int label = 0; label < 5; label++) {
            memset(name + at, 'a' + label, 60);
            at += 60;
            name[at++] = '.';
        }
        memcpy(name + at, "invalid", 8);
        return dns_build(packet, name, 1, 0x5a05, 0x0100);
    }
    }
}

#define MALFORMED_KINDS 3

MODULE(detect_ids)
{
    const char *name = "detect-ids";
    note(name, "install Emerging Threats Open and Suricata built-in in the Rule manager, "
               "with network capture on");
    char nameserver[64] = "";
    if (first_nameserver(nameserver, sizeof nameserver) == 0) {
        int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
        inet_pton(AF_INET, nameserver, &server.sin_addr);
        long repeats = scaled(options, 1);
        size_t total = sizeof et_questions / sizeof et_questions[0];
        for (long round = 0; round < repeats; round++)
            for (size_t i = 0; i < total; i++)
                dns_query(sock, &server, et_questions[i].name, 1, (uint16_t)(0x4100 + i), 300);
        for (size_t i = 0; i < total; i++)
            note(name, "ET Open sid %u: DNS question %s", et_questions[i].sid, et_questions[i].name);
        pass(name, "%zu ET Open DNS questions to %s, %ld time(s) each", total, nameserver, repeats);
        unsigned char packet[512];
        for (unsigned kind = 0; kind < MALFORMED_KINDS; kind++) {
            unsigned sid;
            size_t len = malformed_dns(kind, packet, &sid);
            sendto(sock, packet, len, 0, (struct sockaddr *)&server, sizeof server);
            note(name, "%s sid %u: odd DNS question %u", sid < 2240000 ? "ET Open" : "Suricata built-in",
                 sid, kind + 1);
        }
        pass(name, "%d odd DNS questions (Z flag, opcode 15, a 300-byte name)", MALFORMED_KINDS);
        close(sock);
    } else {
        unavailable(name, "no IPv4 nameserver in /etc/resolv.conf");
    }
    if (options->public_network) {
        unsigned long long bytes = 0;
        int ipify = http_get("api.ipify.org", "/", "curl/8.5.0", &bytes) == 0;
        int icanhazip = http_get("icanhazip.com", "/", "curl/8.5.0", &bytes) == 0;
        if (ipify)
            pass(name, "HTTP to api.ipify.org (ET Open sid 2029622)");
        if (icanhazip)
            pass(name, "HTTP to icanhazip.com (ET Open sid 2017398)");
        if (!ipify || !icanhazip)
            unavailable(name, "a public HTTP lookup did not answer");
    } else {
        note(name, "the HTTP rules (sids 2029622, 2017398) need --public");
    }
    return 0;
}

// The exact DNS questions above, as a capture from 10.0.2.15 to 10.0.2.3,
// for checking the rules against Suricata without a VM.
int write_dns_pcap(const char *path)
{
    FILE *out = fopen(path, "wb");
    if (!out)
        return 1;
    const uint32_t header[] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
    fwrite(header, sizeof header, 1, out);
    unsigned char payload[512], frame[600];
    for (unsigned n = 0; n < sizeof et_questions / sizeof et_questions[0] + MALFORMED_KINDS; n++) {
        size_t len;
        unsigned sid;
        if (n < sizeof et_questions / sizeof et_questions[0])
            len = dns_build(payload, et_questions[n].name, 1, (uint16_t)(0x4100 + n), 0x0100);
        else
            len = malformed_dns(n - (unsigned)(sizeof et_questions / sizeof et_questions[0]), payload,
                                &sid);
        static const unsigned char ethernet[] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02, 0x52, 0x54,
                                                 0x00, 0x12, 0x34, 0x56, 0x08, 0x00};
        size_t at = 0;
        memcpy(frame, ethernet, sizeof ethernet);
        at += sizeof ethernet;
        size_t ip_len = 20 + 8 + len;
        unsigned char ip[20] = {0x45, 0, (unsigned char)(ip_len >> 8), (unsigned char)ip_len,
                                0, (unsigned char)n, 0x40, 0, 64, 17, 0, 0, 10, 0, 2, 15, 10, 0, 2, 3};
        uint32_t sum = 0;
        for (int i = 0; i < 20; i += 2)
            sum += (uint32_t)(ip[i] << 8 | ip[i + 1]);
        while (sum >> 16)
            sum = (sum & 0xffff) + (sum >> 16);
        ip[10] = (unsigned char)(~sum >> 8);
        ip[11] = (unsigned char)~sum;
        memcpy(frame + at, ip, 20);
        at += 20;
        uint16_t sport = 40000; // one socket sends them all, as the module does
        unsigned char udp[8] = {(unsigned char)(sport >> 8), (unsigned char)sport, 0, 53,
                                (unsigned char)((8 + len) >> 8), (unsigned char)(8 + len), 0, 0};
        memcpy(frame + at, udp, 8);
        at += 8;
        memcpy(frame + at, payload, len);
        at += len;
        const uint32_t record[] = {1700000000u + n, 0, (uint32_t)at, (uint32_t)at};
        fwrite(record, sizeof record, 1, out);
        fwrite(frame, at, 1, out);
    }
    return fclose(out) != 0;
}
