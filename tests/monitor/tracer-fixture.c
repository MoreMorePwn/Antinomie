/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest fixture for the written-file and launched-image hashes and for Triage
 * across a transport reconnect (examples/tracer-check.rs). Static, plain
 * system calls. One mode per run; every mode prints "TRACER DONE" just before
 * it exits 0 on its own.
 *
 * File contents are pattern(SEED, SIZE): byte i = (i * 31 + SEED) & 0xff, so
 * the checker computes the SHA-256 the guest must report without reading the
 * guest. Every file lives under /tmp/tracer/ (created fresh).
 *
 *   writes   the cases below, one after another, each printing "CASE name":
 *     new        create /tmp/tracer/new (100000 bytes, seed 1), close
 *     two        open /tmp/tracer/two twice, write through the first and close
 *                it, then write through the second (seed 2, 4096 + 4096
 *                bytes) and close it: one hash, after the second close
 *     child      create /tmp/tracer/child (seed 3, 8192), fork; the parent
 *                closes its descriptor, the child writes and exits with it
 *                open: the hash comes with the child's exit
 *     exit       done by the last child: /tmp/tracer/exit (seed 4, 5000) is
 *                written and the child exits without closing it
 *     big        /tmp/tracer/big, 17 MiB (seed 5): over the 16 MiB limit
 *     proc       write /proc/self/comm: a pseudo filesystem, no record
 *     rdwr       open the existing /tmp/tracer/new read-write, read, close
 *                (opened for writing: hashed again, same digest)
 *     renamed    write /tmp/tracer/before (seed 6, 3000), rename it to
 *                /tmp/tracer/after, then close
 *     unlinked   write /tmp/tracer/gone (seed 7, 2000), unlink it, then close
 *                (no name left: nlink 0)
 *     dropper    copy this program to /tmp/tracer/dropped, close, exec it in
 *                a child with mode "exit0" (the exec hash may be CACHED)
 *     memfd      memfd_create, write (seed 8, 6000), close
 *     burst      6 files of 15 MiB (seed 9) written and closed, each hashed;
 *                then each is reopened, its first byte rewritten ('X') and
 *                closed, back to back: six 15 MiB jobs at once are more than
 *                the 64 MiB the guest queues, so some are refused (BUDGET)
 *     changed    write /tmp/tracer/changed (seed 10, 12 MiB), close, and at
 *                once rewrite its first page: the hash may report CHANGED
 *   slow N     write /tmp/tracer/slow-K (seed 20 + K, 4096) every second for
 *              N seconds, keeping /tmp/tracer/long open across all of them
 *              (one 512-byte write per second, seed 11) and closing it last,
 *              so a reconnect in the middle splits one file's story; each
 *              second also sends a DNS query for tick-K.tracer.test to the
 *              NAT resolver 10.0.2.3 (no answer is needed)
 *   versions   one file per case under /tmp/tracer-v/, where a version
 *              that does not survive is the one that matters:
 *     payload    v1 decoy (seed 31, 6000), closed; overwritten (truncated)
 *                with v2, a copy of this program, chmod 0755, executed in a
 *                child (mode exit0); overwritten with v3 (seed 33, 3000) and
 *                deleted
 *     data       v1 (seed 41, 4096), closed; v2 (seed 42, 4096) through a
 *                truncating open, read back whole on its own descriptor;
 *                then truncated to 0
 *     partial    seed 51, 16384, then pwrite seed 52 at 4096 (512 bytes) and
 *                seed 53 at 15000 (100 bytes)
 *     append     three O_APPEND writes of 1000 bytes (seed 61)
 *     renamed    target v1 (seed 71, 2000); target.new v2 (seed 72, 2500),
 *                renamed over target, then target read back
 *     mapped     8192 bytes through a shared writable mapping (seed 81),
 *                msync, munmap
 *     shared     two processes write one file: the child bytes 0..4096
 *                (seed 91), the parent 4096..8192 (seed 92)
 *   exit0      prints and exits (the dropped copy's mode)
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/tracer-fixture.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DIR_PATH "/tmp/tracer"

static void say(const char *text)
{
	if (write(STDOUT_FILENO, text, strlen(text)) < 0)
		_exit(98);
}

static void fail(const char *what)
{
	char line[256];

	snprintf(line, sizeof(line), "TRACER FAIL %s errno %d\n", what, errno);
	say(line);
	_exit(1);
}

static void nap(long milliseconds)
{
	struct timespec pause = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };

	nanosleep(&pause, NULL);
}

/* Write SIZE pattern bytes of SEED, starting at pattern offset FROM. */
static void pattern_write(int fd, unsigned seed, size_t from, size_t size)
{
	static unsigned char chunk[65536];
	size_t done = 0;

	while (done < size) {
		size_t count = size - done < sizeof(chunk) ? size - done : sizeof(chunk);
		size_t i;

		for (i = 0; i < count; i++)
			chunk[i] = (unsigned char)(((from + done + i) * 31 + seed) & 0xff);
		if (write(fd, chunk, count) != (ssize_t)count)
			fail("write");
		done += count;
	}
}

static int create(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

	if (fd < 0)
		fail(path);
	return fd;
}

static void make_file(const char *path, unsigned seed, size_t size)
{
	int fd = create(path);

	pattern_write(fd, seed, 0, size);
	if (close(fd))
		fail("close");
}

static void fresh_dir(void)
{
	char name[64];
	int i;

	static const char *const names[] = { "new", "two", "child", "exit", "big", "before",
		"after", "gone", "dropped", "changed", "long" };
	for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
		snprintf(name, sizeof(name), DIR_PATH "/%s", names[i]);
		unlink(name);
	}
	for (i = 0; i < 64; i++) {
		snprintf(name, sizeof(name), DIR_PATH "/burst-%d", i);
		unlink(name);
		snprintf(name, sizeof(name), DIR_PATH "/slow-%d", i);
		unlink(name);
	}
	if (mkdir(DIR_PATH, 0755) && errno != EEXIST)
		fail("mkdir");
}

static void wait_child(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("child");
}

static void copy_self(const char *to)
{
	unsigned char buffer[65536];
	int in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC), out;
	ssize_t count;

	if (in < 0)
		fail("self");
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (out < 0)
		fail(to);
	while ((count = read(in, buffer, sizeof(buffer))) > 0)
		if (write(out, buffer, count) != count)
			fail("copy");
	close(in);
	if (close(out))
		fail("close copy");
}

static void writes(void)
{
	char name[64];
	pid_t child;
	int a, b, i;

	fresh_dir();

	say("CASE new\n");
	make_file(DIR_PATH "/new", 1, 100000);

	say("CASE two\n");
	a = create(DIR_PATH "/two");
	b = open(DIR_PATH "/two", O_WRONLY | O_CLOEXEC);
	if (b < 0)
		fail("two");
	pattern_write(a, 2, 0, 4096);
	close(a);
	if (lseek(b, 4096, SEEK_SET) != 4096)
		fail("seek");
	pattern_write(b, 2, 4096, 4096);
	close(b);

	say("CASE child\n");
	a = create(DIR_PATH "/child");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		nap(100);
		pattern_write(a, 3, 0, 8192);
		_exit(0);
	}
	close(a);
	wait_child(child);

	say("CASE exit\n");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		/* A path on this stack page: a forked child has not faulted in the
		 * program's read-only data, which the tracer does not fault. */
		snprintf(name, sizeof(name), "%s/exit", DIR_PATH);
		a = create(name);
		pattern_write(a, 4, 0, 5000);
		_exit(0);
	}
	wait_child(child);

	say("CASE big\n");
	make_file(DIR_PATH "/big", 5, 17u << 20);

	say("CASE proc\n");
	a = open("/proc/self/comm", O_WRONLY | O_CLOEXEC);
	if (a < 0 || write(a, "tracer-fixture", 14) != 14)
		fail("comm");
	close(a);

	say("CASE rdwr\n");
	a = open(DIR_PATH "/new", O_RDWR | O_CLOEXEC);
	if (a < 0 || read(a, name, sizeof(name)) != sizeof(name))
		fail("rdwr");
	close(a);

	say("CASE renamed\n");
	a = create(DIR_PATH "/before");
	pattern_write(a, 6, 0, 3000);
	if (rename(DIR_PATH "/before", DIR_PATH "/after"))
		fail("rename");
	close(a);

	say("CASE unlinked\n");
	a = create(DIR_PATH "/gone");
	pattern_write(a, 7, 0, 2000);
	if (unlink(DIR_PATH "/gone"))
		fail("unlink");
	close(a);

	say("CASE dropper\n");
	copy_self(DIR_PATH "/dropped");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		char path[64], mode[8];
		char *argv[] = { path, mode, NULL };
		char *envp[] = { NULL };

		snprintf(path, sizeof(path), "%s/dropped", DIR_PATH);
		snprintf(mode, sizeof(mode), "exit0");

		execve(argv[0], argv, envp);
		_exit(97);
	}
	wait_child(child);

	say("CASE memfd\n");
	a = (int)syscall(SYS_memfd_create, "tracer", 0);
	if (a < 0)
		fail("memfd");
	pattern_write(a, 8, 0, 6000);
	close(a);

	say("CASE burst\n");
	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), DIR_PATH "/burst-%d", i);
		make_file(name, 9, 15u << 20);
	}
	nap(2000);
	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), DIR_PATH "/burst-%d", i);
		a = open(name, O_WRONLY | O_CLOEXEC);
		if (a < 0 || pwrite(a, "X", 1, 0) != 1)
			fail("burst");
		close(a);
	}
	/* The queue drains before the next case. */
	nap(2000);

	say("CASE changed\n");
	make_file(DIR_PATH "/changed", 10, 12u << 20);
	a = open(DIR_PATH "/changed", O_WRONLY | O_CLOEXEC);
	if (a < 0)
		fail("changed");
	pattern_write(a, 99, 0, 4096);
	close(a);

	/* Let the guest's hash worker finish before the run ends. */
	nap(1500);
	say("TRACER DONE\n");
}

#define VERSIONS_PATH "/tmp/tracer-v"

/* Read a whole file through its own descriptor (the run's read of it). */
static void read_back(const char *path, size_t size)
{
	static unsigned char buffer[65536];
	size_t done = 0;
	ssize_t count;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		fail(path);
	while (done < size && (count = read(fd, buffer, sizeof(buffer))) > 0)
		done += (size_t)count;
	if (done != size)
		fail("read back");
	close(fd);
}

static void versions(void)
{
	static const char *const names[] = { "payload", "data", "partial", "append", "target",
		"target.new", "mapped", "shared" };
	unsigned char *map;
	char path[64];
	pid_t child;
	int fd, i;

	for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
		snprintf(path, sizeof(path), VERSIONS_PATH "/%s", names[i]);
		unlink(path);
	}
	if (mkdir(VERSIONS_PATH, 0755) && errno != EEXIST)
		fail("mkdir");

	say("CASE payload\n");
	make_file(VERSIONS_PATH "/payload", 31, 6000);
	copy_self(VERSIONS_PATH "/payload");
	if (chmod(VERSIONS_PATH "/payload", 0755))
		fail("chmod");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		char run[64], mode[8];
		char *argv[] = { run, mode, NULL };
		char *envp[] = { NULL };

		snprintf(run, sizeof(run), "%s/payload", VERSIONS_PATH);
		snprintf(mode, sizeof(mode), "exit0");
		execve(argv[0], argv, envp);
		_exit(97);
	}
	wait_child(child);
	make_file(VERSIONS_PATH "/payload", 33, 3000);
	if (unlink(VERSIONS_PATH "/payload"))
		fail("unlink payload");

	say("CASE data\n");
	make_file(VERSIONS_PATH "/data", 41, 4096);
	make_file(VERSIONS_PATH "/data", 42, 4096);
	read_back(VERSIONS_PATH "/data", 4096);
	if (truncate(VERSIONS_PATH "/data", 0))
		fail("truncate");

	say("CASE partial\n");
	make_file(VERSIONS_PATH "/partial", 51, 16384);
	fd = open(VERSIONS_PATH "/partial", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		fail("partial");
	if (lseek(fd, 4096, SEEK_SET) != 4096)
		fail("seek");
	pattern_write(fd, 52, 4096, 512);
	{
		unsigned char tail[100];

		for (i = 0; i < 100; i++)
			tail[i] = (unsigned char)(((15000 + i) * 31 + 53) & 0xff);
		if (pwrite(fd, tail, sizeof(tail), 15000) != (ssize_t)sizeof(tail))
			fail("pwrite");
	}
	close(fd);

	say("CASE append\n");
	for (i = 0; i < 3; i++) {
		fd = open(VERSIONS_PATH "/append", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
		if (fd < 0)
			fail("append");
		pattern_write(fd, 61, (size_t)i * 1000, 1000);
		close(fd);
	}

	say("CASE renamed\n");
	make_file(VERSIONS_PATH "/target", 71, 2000);
	make_file(VERSIONS_PATH "/target.new", 72, 2500);
	if (rename(VERSIONS_PATH "/target.new", VERSIONS_PATH "/target"))
		fail("rename over");
	read_back(VERSIONS_PATH "/target", 2500);

	say("CASE mapped\n");
	fd = open(VERSIONS_PATH "/mapped", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0 || ftruncate(fd, 8192))
		fail("mapped");
	map = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		fail("mmap");
	for (i = 0; i < 8192; i++)
		map[i] = (unsigned char)((i * 31 + 81) & 0xff);
	if (msync(map, 8192, MS_SYNC) || munmap(map, 8192))
		fail("msync");
	close(fd);

	say("CASE shared\n");
	fd = create(VERSIONS_PATH "/shared");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		unsigned char half[4096];

		for (i = 0; i < 4096; i++)
			half[i] = (unsigned char)((i * 31 + 91) & 0xff);
		if (pwrite(fd, half, sizeof(half), 0) != (ssize_t)sizeof(half))
			_exit(1);
		_exit(0);
	}
	{
		unsigned char half[4096];

		for (i = 0; i < 4096; i++)
			half[i] = (unsigned char)(((4096 + i) * 31 + 92) & 0xff);
		if (pwrite(fd, half, sizeof(half), 4096) != (ssize_t)sizeof(half))
			fail("shared");
	}
	wait_child(child);
	close(fd);

	/* Let the guest's hash worker finish before the run ends. */
	nap(1500);
	say("TRACER DONE\n");
}

/* One DNS query (A, recursion desired) for tick-INDEX.tracer.test. */
static void dns_query(int index)
{
	unsigned char packet[64];
	char label[16];
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(53) };
	size_t at = 12, length;
	int fd;

	memset(packet, 0, sizeof(packet));
	packet[0] = 0x7a;
	packet[1] = (unsigned char)index;
	packet[2] = 0x01;
	packet[5] = 1;
	length = (size_t)snprintf(label, sizeof(label), "tick-%d", index);
	packet[at++] = (unsigned char)length;
	memcpy(packet + at, label, length);
	at += length;
	packet[at++] = 6;
	memcpy(packet + at, "tracer", 6);
	at += 6;
	packet[at++] = 4;
	memcpy(packet + at, "test", 4);
	at += 4;
	packet[at++] = 0;
	packet[at + 1] = 1;
	packet[at + 3] = 1;
	at += 4;
	inet_pton(AF_INET, "10.0.2.3", &to.sin_addr);
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;
	sendto(fd, packet, at, 0, (struct sockaddr *)&to, sizeof(to));
	close(fd);
}

static void slow(int seconds)
{
	char name[64];
	int fd, i;

	fresh_dir();
	fd = create(DIR_PATH "/long");
	for (i = 0; i < seconds && i < 64; i++) {
		snprintf(name, sizeof(name), DIR_PATH "/slow-%d", i);
		make_file(name, 20 + i, 4096);
		pattern_write(fd, 11, (size_t)i * 512, 512);
		dns_query(i);
		printf("TICK %d\n", i);
		fflush(stdout);
		nap(1000);
	}
	close(fd);
	nap(500);
	say("TRACER DONE\n");
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "writes"))
		writes();
	else if (argc >= 3 && !strcmp(argv[1], "slow"))
		slow(atoi(argv[2]));
	else if (argc >= 2 && !strcmp(argv[1], "versions"))
		versions();
	else if (argc >= 2 && !strcmp(argv[1], "exit0"))
		say("TRACER DONE\n");
	else {
		say("usage: tracer-fixture writes|slow N|versions|exit0\n");
		return 2;
	}
	return 0;
}
