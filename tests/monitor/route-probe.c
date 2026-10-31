/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest probe for the network routes: what a program in the VM reaches on
 * the route of its run. It is launched as the sample (a run) and prints one
 * line per fact:
 *
 *   ROUTE <key> <value>
 *
 *   route-probe NAME PORT [IP]
 *
 * net.gateway and net.resolv (the lease), dns.NAME (an A query to the first
 * nameserver of resolv.conf), then one plain HTTP GET of "/" with the Host
 * NAME to the address the name resolved to, or to IP when the name did not
 * resolve: http.status is the response's status line or why there is none,
 * http.via the X-Route-Fake header a local fake answers with. meta.status is
 * the answer of 169.254.169.254 (a cloud profile's metadata service; only
 * the Routed gateway has one). "ROUTE-END" ends the output.
 *
 * The program sends nothing but these requests: it is a benign check that a
 * route carries traffic, or does not.
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/route-probe.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void line(const char *key, const char *value)
{
	char clean[300];
	size_t i, n = 0;

	for (i = 0; value && value[i] && n < sizeof(clean) - 1; i++) {
		unsigned char c = value[i];

		clean[n++] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : (c < 0x20 || c > 0x7e) ? '?' : c;
	}
	clean[n] = 0;
	printf("ROUTE %s %s\n", key, clean);
	fflush(stdout);
}

static void timeouts(int fd, int seconds)
{
	struct timeval tv = { .tv_sec = seconds };

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* The first nameserver of resolv.conf, or "" when there is none. */
static void nameserver(char *out, size_t size)
{
	char buf[128], server[64] = "";
	FILE *f = fopen("/etc/resolv.conf", "r");

	while (f && fgets(buf, sizeof(buf), f)) {
		buf[strcspn(buf, "\n")] = 0;
		line("net.resolv", buf);
		if (!server[0])
			sscanf(buf, "nameserver %63s", server);
	}
	if (f)
		fclose(f);
	snprintf(out, size, "%s", server);
}

static void gateway(void)
{
	char buf[256];
	FILE *f = fopen("/proc/net/route", "r");
	int seen = 0;

	while (f && fgets(buf, sizeof(buf), f)) {
		char iface[32];
		unsigned long dest, gw;

		if (sscanf(buf, "%31s %lx %lx", iface, &dest, &gw) == 3 && dest == 0 && gw) {
			struct in_addr a = { .s_addr = (in_addr_t)gw };

			line("net.gateway", inet_ntoa(a));
			seen = 1;
		}
	}
	if (f)
		fclose(f);
	if (!seen)
		line("net.gateway", "(none)");
}

/* An A query for name to server; the first answer's address in out, or 0. */
static int dns_lookup(const char *server, const char *name, char *out, size_t size)
{
	unsigned char q[300] = { 0x52, 0x54, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }, a[512];
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53) };
	const char *label = name;
	char key[160];
	size_t n = 12, i;
	ssize_t got;
	int fd;

	snprintf(key, sizeof(key), "dns.%s", name);
	if (!server[0] || inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
		line(key, "(no nameserver)");
		return 0;
	}
	while (*label && n + 70 < sizeof(q)) {
		const char *dot = strchr(label, '.');
		size_t len = dot ? (size_t)(dot - label) : strlen(label);

		if (len == 0 || len > 63)
			break;
		q[n++] = (unsigned char)len;
		memcpy(q + n, label, len);
		n += len;
		label += len + (dot ? 1 : 0);
		if (!dot)
			break;
	}
	q[n++] = 0;
	q[n++] = 0;
	q[n++] = 1;
	q[n++] = 0;
	q[n++] = 1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		line(key, "(no socket)");
		return 0;
	}
	timeouts(fd, 4);
	sendto(fd, q, n, 0, (struct sockaddr *)&sa, sizeof(sa));
	got = recv(fd, a, sizeof(a), 0);
	close(fd);
	if (got < (ssize_t)n + 16 || (a[3] & 0x0f) || !a[7]) {
		line(key, "(no answer)");
		return 0;
	}
	/* The last record of the answer is the A record (after any CNAME). */
	i = (size_t)got - 4;
	snprintf(out, size, "%u.%u.%u.%u", a[i], a[i + 1], a[i + 2], a[i + 3]);
	line(key, out);
	return 1;
}

/* One HTTP GET of "/" to ip:port with Host host; prints <prefix>.status and,
 * when a fake answered, <prefix>.via. */
static void http_get(const char *prefix, const char *ip, int port, const char *host)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	char request[512], response[4096], key[64];
	size_t used = 0;
	ssize_t got;
	int fd;

	snprintf(key, sizeof(key), "%s.status", prefix);
	if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
		line(key, "(no address)");
		return;
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		line(key, "(no socket)");
		return;
	}
	timeouts(fd, 6);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		line(key, "(no connection)");
		close(fd);
		return;
	}
	snprintf(request, sizeof(request),
		 "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: antinomie-route-probe\r\n"
		 "Connection: close\r\n\r\n",
		 host);
	if (write(fd, request, strlen(request)) < 0) {
		line(key, "(send failed)");
		close(fd);
		return;
	}
	while (used + 1 < sizeof(response) &&
	       (got = read(fd, response + used, sizeof(response) - 1 - used)) > 0)
		used += (size_t)got;
	response[used] = 0;
	close(fd);
	if (!used) {
		line(key, "(no answer)");
		return;
	}
	{
		char status[128];
		const char *via = strstr(response, "X-Route-Fake: ");

		snprintf(status, sizeof(status), "%.*s", (int)strcspn(response, "\r\n"), response);
		line(key, status);
		if (via) {
			char fake[64];

			snprintf(key, sizeof(key), "%s.via", prefix);
			via += strlen("X-Route-Fake: ");
			snprintf(fake, sizeof(fake), "%.*s", (int)strcspn(via, "\r\n"), via);
			line(key, fake);
		}
	}
}

int main(int argc, char **argv)
{
	char server[64], address[64] = "";
	int port;

	if (argc < 3) {
		fprintf(stderr, "usage: route-probe NAME PORT [IP]\n");
		return 2;
	}
	port = atoi(argv[2]);
	gateway();
	nameserver(server, sizeof(server));
	if (!dns_lookup(server, argv[1], address, sizeof(address)) && argc > 3)
		snprintf(address, sizeof(address), "%s", argv[3]);
	http_get("http", address, port, argv[1]);
	http_get("meta", "169.254.169.254", 80, "169.254.169.254");
	printf("ROUTE-END\n");
	fflush(stdout);
	return 0;
}
