/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest fixture for the stop, reconnect and process-core qualifications
 * (examples/audit-check.rs). Static, POSIX only. One mode per run:
 *
 *   ignore-term    ignores SIGTERM and sleeps (the sample STOP_RUN must still end)
 *   handle-term    handles SIGTERM, prints "TERM handled" and exits 0
 *   tree           root ignores SIGTERM and starts five more processes: a child
 *                  that ignores it, a setsid() child that ignores it, a child
 *                  that handles it, a child that uses default handling and a
 *                  grandchild of a double fork that ignores it
 *   ticks [N]      prints "tick I" every 100 ms for N ticks (default 600), then
 *                  exits 7; the reconnect qualification
 *   heap MIB TOUCH allocates MIB MiB; TOUCH is "all" (every page written),
 *                  "sparse" (every 64th page) or "none" (only the first page);
 *                  prints "HEAP READY" then waits
 *   heap-exit MIB TOUCH
 *                  as heap, but exits 7 on its own after "HEAP READY"
 *   heap-crash MIB TOUCH
 *                  as heap, but raises SIGSEGV after "HEAP READY"
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/audit-fixture.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void say(const char *text)
{
	size_t length = strlen(text);

	if (write(STDOUT_FILENO, text, length) < 0)
		_exit(98);
}

static void on_term(int signal_number)
{
	(void)signal_number;
	say("TERM handled\n");
	_exit(0);
}

static void set_term(void (*handler)(int))
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = handler;
	sigaction(SIGTERM, &action, NULL);
}

static void nap(long milliseconds)
{
	struct timespec pause = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };

	nanosleep(&pause, NULL);
}

static void forever(void)
{
	for (;;)
		nap(200);
}

static void child(const char *kind)
{
	char line[96];

	if (!strcmp(kind, "ignore") || !strcmp(kind, "session") || !strcmp(kind, "grandchild"))
		set_term(SIG_IGN);
	else if (!strcmp(kind, "handle"))
		set_term(on_term);
	if (!strcmp(kind, "session"))
		setsid();
	snprintf(line, sizeof(line), "CHILD %s pid %d\n", kind, getpid());
	say(line);
	forever();
}

static void tree(void)
{
	char line[96];

	set_term(SIG_IGN);
	if (!fork())
		child("ignore");
	if (!fork())
		child("session");
	if (!fork())
		child("handle");
	if (!fork())
		child("default");
	if (!fork()) {
		/* Double fork: the intermediate exits, the grandchild is orphaned. */
		if (!fork())
			child("grandchild");
		_exit(0);
	}
	nap(500);
	snprintf(line, sizeof(line), "TREE READY root %d\n", getpid());
	say(line);
	forever();
}

static void heap(const char *mode, unsigned long mib, const char *touch)
{
	size_t size = (size_t)mib << 20, offset;
	volatile unsigned char *memory;

	memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (memory == MAP_FAILED) {
		say("HEAP FAILED\n");
		_exit(99);
	}
	if (!strcmp(touch, "all"))
		for (offset = 0; offset < size; offset += 4096)
			memory[offset] = (unsigned char)(offset >> 12) | 1;
	else if (!strcmp(touch, "sparse"))
		for (offset = 0; offset < size; offset += 64 * 4096)
			memory[offset] = 0x41;
	else
		memory[0] = 0x41;
	say("HEAP READY\n");
	if (!strcmp(mode, "heap-exit"))
		_exit(7);
	if (!strcmp(mode, "heap-crash"))
		raise(SIGSEGV);
	forever();
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ticks";
	char line[64];
	long ticks, tick;

	if (!strcmp(mode, "ignore-term")) {
		set_term(SIG_IGN);
		say("IGNORE READY\n");
		forever();
	} else if (!strcmp(mode, "handle-term")) {
		set_term(on_term);
		say("HANDLE READY\n");
		forever();
	} else if (!strcmp(mode, "tree")) {
		tree();
	} else if (!strcmp(mode, "ticks")) {
		ticks = argc > 2 ? atol(argv[2]) : 600;
		for (tick = 0; tick < ticks; tick++) {
			snprintf(line, sizeof(line), "tick %ld\n", tick);
			say(line);
			nap(100);
		}
		return 7;
	} else if (!strncmp(mode, "heap", 4) && argc > 3) {
		heap(mode, strtoul(argv[2], NULL, 0), argv[3]);
	}
	say("usage: see source\n");
	return 2;
}
