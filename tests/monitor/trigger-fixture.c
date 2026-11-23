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
 *
 *   trigger-fixture --selfscan SECONDS DELAY_MS
 *
 * The daemon case (ANT-T0596): it forks, the child forks again, and both
 * parents exit at once, as a daemon starts. The grandchild waits DELAY_MS
 * after the middle process said it is exiting (with the dump trigger's core
 * on, the guest holds an exiting process for longer than that), then looks
 * for a running copy of itself, as a sample that will not run twice does:
 * another process whose /proc/PID/exe is its own image (the /proc listing,
 * and both parents by number). A copy found: "selfscan found PID", exit 3.
 * None: it checks that the middle process was in fact still there (its
 * getppid() still names it while /proc and kill(pid, 0) no longer find it,
 * which only a hidden exiting process looks like); if so, "selfscan alone,
 * parent hidden", it writes /etc/cron.d/antinomie-selfscan (persistence.cron)
 * and sleeps SECONDS; if not, the hold was over before it looked and the
 * case proves nothing: "selfscan no hold seen", exit 4.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
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

static void selfscan_say(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
	fflush(stdout);
}

/* Whether process pid runs the image at self (its exe link names it). */
static int runs_image(long pid, const char *self)
{
	char link[64], target[512];
	ssize_t got;

	snprintf(link, sizeof(link), "/proc/%ld/exe", pid);
	got = readlink(link, target, sizeof(target) - 1);
	if (got <= 0)
		return 0;
	target[got] = '\0';
	return strcmp(target, self) == 0;
}

/* Another running copy of this program, by the /proc listing, or 0. */
static long copy_listed(const char *self)
{
	struct dirent *entry;
	long found = 0, pid;
	char *end;
	DIR *proc = opendir("/proc");

	if (!proc)
		return -1;
	while (!found && (entry = readdir(proc))) {
		pid = strtol(entry->d_name, &end, 10);
		if (*end || pid <= 0 || pid == (long)getpid())
			continue;
		if (runs_image(pid, self))
			found = pid;
	}
	closedir(proc);
	return found;
}

static int selfscan(unsigned seconds, unsigned delay_ms)
{
	static const char entry[] = "# antinomie trigger fixture\n* * * * * root /bin/true\n";
	struct timespec delay = {delay_ms / 1000, (long)(delay_ms % 1000) * 1000000L};
	char self[512], proc_path[64], said;
	pid_t first = getpid(), middle, child;
	ssize_t got = readlink("/proc/self/exe", self, sizeof(self) - 1);
	int pipefd[2], fd, hidden;
	long found;

	if (got <= 0 || pipe(pipefd) != 0)
		return 1;
	self[got] = '\0';
	child = fork();
	if (child < 0)
		return 1;
	if (child > 0)
		_exit(0);
	middle = getpid();
	child = fork();
	if (child < 0)
		_exit(1);
	if (child > 0) {
		/* The middle process says it is exiting, then exits. */
		if (write(pipefd[1], "x", 1) != 1)
			_exit(1);
		_exit(0);
	}
	close(pipefd[1]);
	if (read(pipefd[0], &said, 1) != 1)
		return 1;
	close(pipefd[0]);
	setsid();
	nanosleep(&delay, NULL);
	found = copy_listed(self);
	if (!found && runs_image(first, self))
		found = first;
	if (!found && runs_image(middle, self))
		found = middle;
	/* A parent that has exited reparents this process: getppid() still
	 * naming it means it is still there, in its exit. */
	snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)middle);
	hidden = getppid() == middle && access(proc_path, F_OK) != 0 &&
		 kill(middle, 0) != 0 && errno == ESRCH;
	if (found) {
		selfscan_say("TRIGGER-FIXTURE selfscan found %ld (first %d, middle %d)", found,
			     (int)first, (int)middle);
		return 3;
	}
	if (!hidden) {
		selfscan_say("TRIGGER-FIXTURE selfscan no hold seen (parent %d, middle %d)",
			     (int)getppid(), (int)middle);
		return 4;
	}
	selfscan_say("TRIGGER-FIXTURE selfscan alone, parent hidden (first %d, middle %d)",
		     (int)first, (int)middle);
	if (mkdir("/etc/cron.d", 0755) != 0 && errno != EEXIST)
		perror("mkdir /etc/cron.d");
	fd = open("/etc/cron.d/antinomie-selfscan", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		if (write(fd, entry, sizeof(entry) - 1) < 0)
			perror("write");
		close(fd);
	}
	sleep(seconds);
	return 0;
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
	if (argc > 3 && strcmp(argv[1], "--selfscan") == 0)
		return selfscan((unsigned)strtoul(argv[2], NULL, 10),
				(unsigned)strtoul(argv[3], NULL, 10));
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
