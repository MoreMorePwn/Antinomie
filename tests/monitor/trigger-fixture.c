/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest fixture for the dump trigger (ANT-T0426): a benign program that does
 * what the High rule persistence.cron reads, then stays alive so its core can
 * be taken.
 *
 *   trigger-fixture NAME [SECONDS]
 *
 * It creates /etc/cron.d (when missing) and writes /etc/cron.d/NAME holding a
 * comment and an entry that runs /bin/true, prints "TRIGGER-FIXTURE wrote
 * /etc/cron.d/NAME", sleeps SECONDS (default 15) and exits 0. Built for every
 * ABI a check runs: x86-64, aarch64, and the 32-bit ones (i386, AArch32), so
 * the live judge is seen to fire on each.
 *
 *   trigger-fixture --dropexec MODE [SECONDS]
 *
 * The dropper case (ANT-T0591): it writes a copy of itself to /tmp/.ntmrun.PID,
 * makes it executable and executes it, which is what execution.dropped_exec
 * reads. MODE says who does it: "spawn" and "spawnlong" (this process; the executed copy then
 * starts a helper with vfork at once and waits for it, 1.5 s or 6 s), "threads" (this process, after starting three
 * more threads, so the exec ends them), "plain" (this process execs), "fork" (a forked
 * child does) or "vfork" (a vfork child does, sharing this process's memory).
 * The executed copy (--dropped) fills a buffer with a marker only it writes at
 * run time, prints "TRIGGER-FIXTURE dropped image running", sleeps SECONDS
 * (default 15) and exits 0. A core of it names the dropped file, a core of
 * the dropper does not.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

/* Written at run time by the executed copy only, so no other image holds it. */
static char marker[64];

static int dropped(unsigned seconds, int spawn)
{
	static const char part[] = "DROPPED-IMAGE";

	snprintf(marker, sizeof(marker), "%s-%s-%u", part, "LIVE", seconds);
	printf("TRIGGER-FIXTURE dropped image running (%s)\n", marker);
	fflush(stdout);
	if (spawn) {
		/* Starts a helper at once, as a dropper starts its payload: the
		 * helper shares this process's memory while this one waits. */
		pid_t helper = vfork();

		if (helper == 0) {
			/* 1 (spawn): a short wait, then the helper starts a program,
			 * which ends the sharing. 2 (spawnlong): it outlasts the
			 * host's retries. */
			char *const none[] = {(char *)"/bin/true", NULL};

			usleep(spawn == 2 ? 6000000 : 1500000);
			if (spawn == 1)
				execve("/bin/true", none, none);
			_exit(0);
		}
		if (helper > 0)
			waitpid(helper, NULL, 0);
		/* In spawnlong it then persists: the next match, once the helper is
		 * done (spawn waits for its retried core instead). */
		if (spawn == 2) {
			int fd;

			if (mkdir("/etc/cron.d", 0755) != 0 && errno != EEXIST)
				perror("mkdir");
			fd = open("/etc/cron.d/antinomie-dropped", O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd >= 0) {
				if (write(fd, "* * * * * root /bin/true\n", 25) < 0)
					perror("write");
				close(fd);
			}
		}
	}
	sleep(seconds);
	return marker[0] == 'D' ? 0 : 1;
}

static void *idle(void *unused)
{
	(void)unused;
	for (;;)
		sleep(60);
	return NULL;
}

/* Copy this program to /tmp/.ntmrun.PID, make it executable and run it. */
static void drop_and_exec(const char *seconds, int spawn)
{
	char target[64], block[4096];
	char *const args[] = {target, (char *)"--dropped", (char *)seconds,
			      (char *)(spawn == 2 ? "spawnlong" : spawn ? "spawn" : ""), NULL};
	char *const env[] = {NULL};
	ssize_t got;
	int in, out;

	snprintf(target, sizeof(target), "/tmp/.ntmrun.%d", (int)getpid());
	in = open("/proc/self/exe", O_RDONLY);
	out = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (in < 0 || out < 0) {
		perror("open");
		_exit(1);
	}
	while ((got = read(in, block, sizeof(block))) > 0)
		if (write(out, block, (size_t)got) != got) {
			perror("write");
			_exit(1);
		}
	/* A dropper is megabytes: the exec reads a file that takes a while. */
	memset(block, 0, sizeof(block));
	for (got = 0; got < 1024; got++)
		if (write(out, block, sizeof(block)) != (ssize_t)sizeof(block)) {
			perror("pad");
			_exit(1);
		}
	close(in);
	close(out);
	if (chmod(target, 0755) != 0) {
		perror("chmod");
		_exit(1);
	}
	execve(target, args, env);
	perror("execve");
	_exit(1);
}

int main(int argc, char **argv)
{
	static const char entry[] = "# antinomie trigger fixture\n* * * * * root /bin/true\n";
	char path[256];
	unsigned seconds = 15;
	int fd;

	if (argc > 1 && strcmp(argv[1], "--dropped") == 0)
		return dropped(argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 15,
			       argc > 3 ? (strcmp(argv[3], "spawnlong") == 0 ? 2 : strcmp(argv[3], "spawn") == 0) : 0);
	if (argc > 2 && strcmp(argv[1], "--dropexec") == 0) {
		const char *mode = argv[2], *secs = argc > 3 ? argv[3] : "15";
		int status, spawn = strcmp(mode, "spawnlong") == 0 ? 2 : strcmp(mode, "spawn") == 0;
		pid_t child;

		if (strcmp(mode, "threads") == 0) {
			/* A multi-threaded program execs from its leader: the guest
			 * ends the other threads inside the exec. */
			pthread_t thread;
			int count;

			for (count = 0; count < 3; count++)
				if (pthread_create(&thread, NULL, idle, NULL) != 0)
					return 1;
			usleep(200000);
			drop_and_exec(secs, spawn);
		}
		if (strcmp(mode, "plain") == 0 || spawn)
			drop_and_exec(secs, spawn);
		child = strcmp(mode, "vfork") == 0 ? vfork() : fork();
		if (child == 0)
			drop_and_exec(secs, spawn);
		if (child < 0)
			return 1;
		waitpid(child, &status, 0);
		return 0;
	}
	if (argc < 2 || strchr(argv[1], '/') || strlen(argv[1]) > 64) {
		fprintf(stderr, "usage: trigger-fixture NAME [SECONDS]\n");
		return 2;
	}
	if (argc > 2)
		seconds = (unsigned)strtoul(argv[2], NULL, 10);
	if (mkdir("/etc/cron.d", 0755) != 0 && errno != EEXIST) {
		perror("mkdir /etc/cron.d");
		return 1;
	}
	snprintf(path, sizeof(path), "/etc/cron.d/%s", argv[1]);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (write(fd, entry, sizeof(entry) - 1) != (ssize_t)(sizeof(entry) - 1)) {
		perror("write");
		close(fd);
		return 1;
	}
	close(fd);
	printf("TRIGGER-FIXTURE wrote %s\n", path);
	fflush(stdout);
	sleep(seconds);
	return 0;
}
