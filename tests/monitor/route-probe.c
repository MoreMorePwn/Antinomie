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
 * Started with a dash, it is the egress filter's probe instead: plain TCP
 * connects (no data but a byte to keep a connection alive) to an address the
 * route's local fake proxy answers for, one line per result:
 *
 *   route-probe -p IP PORT...           one connect per port: port.P open|refused|...
 *   route-probe -l IP PORT COUNT GAP    COUNT connects in a row, GAP ms apart:
 *                                       loop.open, loop.refused, loop.second (opened
 *                                       within the first second), loop.ms, loop.slowest
 *                                       (ms), loop.trace (o/r/x per connect), loop.every20
 *                                       (ms after every 20th)
 *   route-probe -d NET FIRST COUNT PORT GAP
 *                                       COUNT distinct addresses NET.FIRST..: dist.open,
 *                                       dist.refused, dist.first_refused, then
 *                                       dist.repeat (the first address again)
 *   route-probe -o IP PORT COUNT GAP    COUNT connections held open at once:
 *                                       open.open, open.refused
 *   route-probe -b IP PORT COUNT        COUNT connects started together (a browser's
 *                                       first burst): burst.open, burst.refused
 *   route-probe -t IP PORT SECONDS      one connection kept alive up to SECONDS:
 *                                       held.ms and held.end, then after.connect and
 *                                       after.dns (a lookup of example.com)
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/route-probe.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void number(const char *key, long value)
{
	char text[32];

	snprintf(text, sizeof(text), "%ld", value);
	line(key, text);
}

static void pause_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };

	if (ms > 0)
		nanosleep(&ts, NULL);
}

/* One blocking connect; the open socket in *out (or -1), the result in words. */
static const char *connect_to(const char *ip, int port, int *out)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	*out = -1;
	if (fd < 0)
		return "no-socket";
	if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
		close(fd);
		return "no-address";
	}
	timeouts(fd, 6);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		*out = fd;
		return "open";
	}
	close(fd);
	switch (errno) {
	case ECONNREFUSED:
		return "refused";
	case EINPROGRESS:
	case ETIMEDOUT:
	case EAGAIN:
		return "timeout";
	case ECONNRESET:
		return "reset";
	default:
		return "error";
	}
}

static int try_once(const char *ip, int port)
{
	int fd;
	const char *got = connect_to(ip, port, &fd);

	if (fd >= 0)
		close(fd);
	return !strcmp(got, "open") ? 1 : !strcmp(got, "refused") ? 0 : -1;
}

static void ports(int argc, char **argv)
{
	char key[32];
	int i, fd;

	for (i = 3; i < argc; i++) {
		const char *got = connect_to(argv[2], atoi(argv[i]), &fd);

		if (fd >= 0)
			close(fd);
		snprintf(key, sizeof(key), "port.%d", atoi(argv[i]));
		line(key, got);
	}
}

static void loop(const char *ip, int port, int count, long gap)
{
	long start = now_ms(), open = 0, refused = 0, other = 0, second = 0, slowest = 0;
	char trace[256], at[256] = "";
	int i;

	for (i = 0; i < count; i++) {
		long before = now_ms();
		int got = try_once(ip, port);

		if (now_ms() - before > slowest)
			slowest = now_ms() - before;
		if (i < (int)sizeof(trace) - 1)
			trace[i] = got == 1 ? 'o' : got == 0 ? 'r' : 'x';
		if (i % 20 == 19 && strlen(at) < sizeof(at) - 12)
			snprintf(at + strlen(at), sizeof(at) - strlen(at), "%ld ", now_ms() - start);
		if (got == 1) {
			open++;
			second += now_ms() - start < 1000;
		} else if (got == 0) {
			refused++;
		} else {
			other++;
		}
		pause_ms(gap);
	}
	trace[i < (int)sizeof(trace) - 1 ? i : (int)sizeof(trace) - 1] = 0;
	number("loop.open", open);
	number("loop.refused", refused);
	number("loop.other", other);
	number("loop.second", second);
	number("loop.ms", now_ms() - start);
	number("loop.slowest", slowest);
	line("loop.trace", trace);
	line("loop.every20", at);
}

static void distinct(const char *net, int first, int count, int port, long gap)
{
	char ip[64];
	long open = 0, refused = 0, other = 0, first_refused = -1;
	int i;

	for (i = 0; i < count; i++) {
		int got;

		snprintf(ip, sizeof(ip), "%s.%d", net, first + i);
		got = try_once(ip, port);
		if (got == 1) {
			open++;
		} else if (got == 0) {
			refused++;
			if (first_refused < 0)
				first_refused = i;
		} else {
			other++;
		}
		pause_ms(gap);
	}
	number("dist.open", open);
	number("dist.refused", refused);
	number("dist.other", other);
	number("dist.first_refused", first_refused);
	snprintf(ip, sizeof(ip), "%s.%d", net, first);
	line("dist.repeat", try_once(ip, port) == 1 ? "open" : "not open");
}

static void hold_open(const char *ip, int port, int count, long gap)
{
	static int fds[1024];
	long open = 0, refused = 0, other = 0;
	int i, n = 0;

	for (i = 0; i < count && n < 1024; i++) {
		int fd;
		const char *got = connect_to(ip, port, &fd);

		if (fd >= 0)
			fds[n++] = fd;
		if (!strcmp(got, "open"))
			open++;
		else if (!strcmp(got, "refused"))
			refused++;
		else
			other++;
		pause_ms(gap);
	}
	number("open.open", open);
	number("open.refused", refused);
	number("open.other", other);
	while (n > 0)
		close(fds[--n]);
}

static void burst(const char *ip, int port, int count)
{
	static struct pollfd fds[512];
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	long open = 0, refused = 0, other = 0, start = now_ms();
	int i, n = 0, left;

	if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
		line("burst.open", "(no address)");
		return;
	}
	for (i = 0; i < count && i < 512; i++) {
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

		if (fd < 0) {
			other++;
			continue;
		}
		if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 || errno == EINPROGRESS) {
			fds[n].fd = fd;
			fds[n++].events = POLLOUT;
		} else {
			refused += errno == ECONNREFUSED;
			other += errno != ECONNREFUSED;
			close(fd);
		}
	}
	left = n;
	while (left > 0 && now_ms() - start < 8000) {
		if (poll(fds, n, 500) <= 0)
			continue;
		for (i = 0; i < n; i++) {
			int error = 0;
			socklen_t size = sizeof(error);

			if (fds[i].fd < 0 || !fds[i].revents)
				continue;
			getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &error, &size);
			if (!error)
				open++;
			else if (error == ECONNREFUSED)
				refused++;
			else
				other++;
			close(fds[i].fd);
			fds[i].fd = -1;
			left--;
		}
	}
	number("burst.open", open);
	number("burst.refused", refused);
	number("burst.other", other + left);
	number("burst.ms", now_ms() - start);
}

static void held(const char *ip, int port, long seconds)
{
	char server[64], address[64];
	long start = now_ms();
	const char *end = "kept";
	int fd;
	const char *got = connect_to(ip, port, &fd);

	line("held.connect", got);
	if (fd < 0)
		return;
	while (now_ms() - start < seconds * 1000) {
		char byte;
		ssize_t r;

		if (send(fd, "x", 1, MSG_NOSIGNAL) < 0) {
			end = errno == ECONNRESET ? "reset" : errno == EPIPE ? "closed" : "error";
			break;
		}
		r = recv(fd, &byte, 1, MSG_DONTWAIT);
		if (r == 0) {
			end = "closed";
			break;
		}
		if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			end = errno == ECONNRESET ? "reset" : "error";
			break;
		}
		pause_ms(1000);
	}
	number("held.ms", now_ms() - start);
	line("held.end", end);
	close(fd);
	got = connect_to(ip, port, &fd);
	if (fd >= 0)
		close(fd);
	line("after.connect", got);
	nameserver(server, sizeof(server));
	if (!dns_lookup(server, "example.com", address, sizeof(address)))
		line("after.dns", "(no answer)");
	else
		line("after.dns", address);
}

/* The egress filter's probe (a first argument with a dash). */
static int filter_probe(int argc, char **argv)
{
	const char *mode = argv[1];

	if (argc < 4)
		return 2;
	if (!strcmp(mode, "-p"))
		ports(argc, argv);
	else if (!strcmp(mode, "-l") && argc >= 6)
		loop(argv[2], atoi(argv[3]), atoi(argv[4]), atol(argv[5]));
	else if (!strcmp(mode, "-d") && argc >= 7)
		distinct(argv[2], atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atol(argv[6]));
	else if (!strcmp(mode, "-o") && argc >= 6)
		hold_open(argv[2], atoi(argv[3]), atoi(argv[4]), atol(argv[5]));
	else if (!strcmp(mode, "-b") && argc >= 5)
		burst(argv[2], atoi(argv[3]), atoi(argv[4]));
	else if (!strcmp(mode, "-t") && argc >= 5)
		held(argv[2], atoi(argv[3]), atol(argv[4]));
	else
		return 2;
	printf("ROUTE-END\n");
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	char server[64], address[64] = "";
	int port;

	if (argc < 3) {
		fprintf(stderr, "usage: route-probe NAME PORT [IP]\n");
		return 2;
	}
	if (argv[1][0] == '-')
		return filter_probe(argc, argv);
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
