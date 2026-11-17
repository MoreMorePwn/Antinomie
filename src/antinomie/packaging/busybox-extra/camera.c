// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/*
 * The stand-in for a camera's or DVR's vendor program in Antinomie's BusyBox
 * camera base (profile busybox-extra). Real devices run one large program as
 * root that serves the web interface on 80, RTSP on 554 and the maker's own
 * protocol on a vendor port; IoT bots look for it, kill it and take its ports.
 * This program only holds those ports and answers like a device that wants a
 * login: a login page on 80, OPTIONS and "401 Unauthorized" on 554, and
 * silence on the vendor port. It contains no camera code, records nothing,
 * starts nothing and reads no file.
 *
 * It is freestanding (no C library): a few system calls through each
 * architecture's own instruction, so the kit builds it with the cross
 * compiler alone and the binary is the same for every build host's libraries.
 * CAMERA_VENDOR_PORT (the device profile's) is set when it is compiled.
 */
#include <stddef.h>
#include <stdint.h>

#ifndef CAMERA_VENDOR_PORT
#define CAMERA_VENDOR_PORT 37777
#endif

#if defined(__x86_64__)
enum { SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_socket = 41, SYS_accept4 = 288,
       SYS_sendto = 44, SYS_bind = 49, SYS_listen = 50, SYS_setsockopt = 54,
       SYS_exit_group = 231, SYS_ppoll = 271 };

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall"
			 : "=a"(ret)
			 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
			 : "rcx", "r11", "memory");
	return ret;
}

__asm__(".text\n.globl _start\n_start:\n\txor %ebp, %ebp\n\tand $-16, %rsp\n"
	"\tcall camera_main\n\thlt\n");
#elif defined(__aarch64__)
enum { SYS_read = 63, SYS_write = 64, SYS_close = 57, SYS_socket = 198, SYS_accept4 = 242,
       SYS_sendto = 206, SYS_bind = 200, SYS_listen = 201, SYS_setsockopt = 208,
       SYS_exit_group = 94, SYS_ppoll = 73 };

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;
	__asm__ volatile("svc 0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory");
	return x0;
}

__asm__(".text\n.globl _start\n_start:\n\tmov x29, #0\n\tmov x30, #0\n\tbl camera_main\n"
	"\tb .\n");
#else
#error "no system call glue for this architecture yet"
#endif

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define POLLIN 1
#define MSG_NOSIGNAL 0x4000

struct sockaddr_in4 {
	uint16_t family;
	uint16_t port;
	uint32_t address;
	uint8_t zero[8];
};

struct poll_fd {
	int fd;
	short events;
	short revents;
};

struct time_spec {
	long seconds;
	long nanoseconds;
};

/* The compiler may still call these for structure copies. */
void *memset(void *target, int value, size_t length)
{
	unsigned char *byte = target;
	while (length--)
		*byte++ = (unsigned char)value;
	return target;
}

void *memcpy(void *target, const void *source, size_t length)
{
	unsigned char *to = target;
	const unsigned char *from = source;
	while (length--)
		*to++ = *from++;
	return target;
}

static size_t text_length(const char *text)
{
	size_t length = 0;
	while (text[length])
		length++;
	return length;
}

static void send_all(int fd, const char *data, size_t length)
{
	while (length) {
		long sent = sys6(SYS_sendto, fd, (long)data, (long)length, MSG_NOSIGNAL, 0, 0);
		if (sent <= 0)
			return;
		data += sent;
		length -= (size_t)sent;
	}
}

static void send_text(int fd, const char *text)
{
	send_all(fd, text, text_length(text));
}

static int listener(uint16_t port)
{
	int one = 1;
	struct sockaddr_in4 address;
	long fd = sys6(SYS_socket, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0, 0, 0, 0);
	if (fd < 0)
		return -1;
	memset(&address, 0, sizeof(address));
	address.family = AF_INET;
	address.port = (uint16_t)((port >> 8) | (port << 8));
	sys6(SYS_setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, (long)&one, sizeof(one), 0);
	if (sys6(SYS_bind, fd, (long)&address, sizeof(address), 0, 0, 0) < 0 ||
	    sys6(SYS_listen, fd, 16, 0, 0, 0, 0) < 0) {
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		return -1;
	}
	return (int)fd;
}

/* What a client sent within a few seconds (a request line and headers). */
static long read_request(int fd, char *buffer, size_t size)
{
	struct poll_fd wait = { fd, POLLIN, 0 };
	struct time_spec limit = { 3, 0 };
	long length;
	if (sys6(SYS_ppoll, (long)&wait, 1, (long)&limit, 0, 8, 0) <= 0)
		return 0;
	length = sys6(SYS_read, fd, (long)buffer, (long)size - 1, 0, 0, 0);
	if (length < 0)
		length = 0;
	buffer[length] = 0;
	return length;
}

static const char login_page[] =
	"<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>WEB SERVICE</title></head>\n"
	"<body><form method=\"post\" action=\"/RPC2_Login\">\n"
	"<p><label>Username <input name=\"username\" autocomplete=\"off\"></label></p>\n"
	"<p><label>Password <input type=\"password\" name=\"password\"></label></p>\n"
	"<p><button type=\"submit\">Login</button></p>\n</form></body></html>\n";

static void answer_web(int fd, const char *request)
{
	char header[160];
	const char *head = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
			   "Content-Length: ";
	size_t length = sizeof(login_page) - 1, used = text_length(head), digits = 0;
	char number[12];
	(void)request;
	memcpy(header, head, used);
	do {
		number[digits++] = (char)('0' + length % 10);
		length /= 10;
	} while (length);
	while (digits)
		header[used++] = number[--digits];
	memcpy(header + used, "\r\n\r\n", 4);
	send_all(fd, header, used + 4);
	send_all(fd, login_page, sizeof(login_page) - 1);
}

static int starts_with(const char *text, const char *prefix)
{
	while (*prefix)
		if (*text++ != *prefix++)
			return 0;
	return 1;
}

/* The CSeq header's value, copied into sequence (empty when there is none). */
static void cseq(const char *request, char *sequence, size_t size)
{
	size_t used = 0;
	for (; *request; request++) {
		if (starts_with(request, "CSeq:") || starts_with(request, "Cseq:")) {
			request += 5;
			while (*request == ' ')
				request++;
			while (*request >= '0' && *request <= '9' && used + 1 < size)
				sequence[used++] = *request++;
			break;
		}
	}
	sequence[used] = 0;
}

static void answer_rtsp(int fd, const char *request)
{
	char sequence[12];
	cseq(request, sequence, sizeof(sequence));
	if (starts_with(request, "OPTIONS")) {
		send_text(fd, "RTSP/1.0 200 OK\r\nCSeq: ");
		send_text(fd, sequence);
		send_text(fd, "\r\nPublic: OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, "
			      "TEARDOWN, SET_PARAMETER, GET_PARAMETER\r\n\r\n");
		return;
	}
	send_text(fd, "RTSP/1.0 401 Unauthorized\r\nCSeq: ");
	send_text(fd, sequence);
	send_text(fd, "\r\nWWW-Authenticate: Digest realm=\"Login to DVR\", "
		      "nonce=\"0c9d7a91e5f3b2a4\"\r\n\r\n");
}

void camera_main(void)
{
	static const uint16_t ports[3] = { 80, 554, CAMERA_VENDOR_PORT };
	struct poll_fd waits[3];
	char request[2048];
	int index;
	for (index = 0; index < 3; index++) {
		waits[index].fd = listener(ports[index]);
		waits[index].events = POLLIN;
		waits[index].revents = 0;
	}
	for (;;) {
		if (sys6(SYS_ppoll, (long)waits, 3, 0, 0, 8, 0) <= 0)
			continue;
		for (index = 0; index < 3; index++) {
			long client;
			if (waits[index].fd < 0 || !(waits[index].revents & POLLIN))
				continue;
			client = sys6(SYS_accept4, waits[index].fd, 0, 0, SOCK_CLOEXEC, 0, 0);
			if (client < 0)
				continue;
			read_request((int)client, request, sizeof(request));
			if (index == 0)
				answer_web((int)client, request);
			else if (index == 1)
				answer_rtsp((int)client, request);
			/* The vendor protocol is binary and needs a login first:
			 * nothing is said until the client gives up. */
			sys6(SYS_close, client, 0, 0, 0, 0, 0);
		}
	}
	sys6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
}
