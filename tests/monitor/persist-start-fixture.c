// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// persist-start-fixture.c: a benign program that installs persistence and
// exits at once, the way RotaJakiro or Skidmap do (ANT-T0608), to check
// Start persistence. Run as root in a guest, it:
//
//   * copies itself to /tmp/persist-start-copy;
//   * writes an init script, /etc/init.d/persist-start-fixture, whose
//     `start` runs the copy in the background ("init");
//   * writes a cron line, /etc/cron.d/persist-start-fixture, that runs the
//     copy every minute ("cron"; BusyBox crond does not read /etc/cron.d, so
//     only Antinomie's start runs it);
//   * prints PERSIST FIXTURE INSTALLED and exits 0.
//
// The copy, started with `--beat <how>`, does only harmless things: every
// 2 s for at most 20 min it rewrites /tmp/persist-start-<how>.beat with a
// counter. It prints nothing (a boot gives it no terminal).
//
// With Start persistence on, the run is held after the tree's end and the
// recording shows both copies writing their beat files until the run time;
// with it off, the run ends at once and its notes say the persistence was
// installed but not started.
//
// `--clean` removes everything it wrote.
//
// Build: gcc -static -O2 -Wall -Wextra -o persist-start-fixture persist-start-fixture.c
//   (aarch64-linux-gnu-gcc for an arm64 base).
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define COPY "/tmp/persist-start-copy"
#define INIT "/etc/init.d/persist-start-fixture"
#define CRON "/etc/cron.d/persist-start-fixture"

static int write_text(const char *path, const char *text, mode_t bits)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, bits);
	if (fd < 0) {
		printf("%s: %s\n", path, strerror(errno));
		return -1;
	}
	size_t len = strlen(text);
	ssize_t done = write(fd, text, len);
	close(fd);
	if (done != (ssize_t)len) {
		printf("%s: short write\n", path);
		return -1;
	}
	chmod(path, bits);
	return 0;
}

static int copy_self(void)
{
	int in = open("/proc/self/exe", O_RDONLY);
	if (in < 0) {
		printf("/proc/self/exe: %s\n", strerror(errno));
		return -1;
	}
	unlink(COPY);
	int out = open(COPY, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (out < 0) {
		printf("%s: %s\n", COPY, strerror(errno));
		close(in);
		return -1;
	}
	char buf[65536];
	ssize_t got;
	while ((got = read(in, buf, sizeof buf)) > 0) {
		if (write(out, buf, (size_t)got) != got) {
			printf("%s: short write\n", COPY);
			got = -1;
			break;
		}
	}
	close(in);
	close(out);
	return got < 0 ? -1 : 0;
}

static int beat(const char *how)
{
	char path[128];
	if (strlen(how) > 16 || strchr(how, '/') != NULL)
		return 2;
	snprintf(path, sizeof path, "/tmp/persist-start-%s.beat", how);
	for (int count = 1; count <= 600; count++) {
		char text[64];
		snprintf(text, sizeof text, "%s %d\n", how, count);
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd >= 0) {
			if (write(fd, text, strlen(text)) < 0) {
				/* nothing to do: the next beat tries again */
			}
			close(fd);
		}
		struct timespec pause = {2, 0};
		nanosleep(&pause, NULL);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--beat") == 0)
		return beat(argv[2]);
	if (argc == 2 && strcmp(argv[1], "--clean") == 0) {
		unlink(INIT);
		unlink(CRON);
		unlink(COPY);
		unlink("/tmp/persist-start-init.beat");
		unlink("/tmp/persist-start-cron.beat");
		puts("PERSIST FIXTURE CLEANED");
		return 0;
	}
	mkdir("/etc/init.d", 0755);
	mkdir("/etc/cron.d", 0755);
	if (copy_self() || write_text(INIT,
				      "#!/bin/sh\n"
				      "case \"$1\" in\n"
				      "start) " COPY " --beat init & ;;\n"
				      "esac\n"
				      "exit 0\n",
				      0755) ||
	    write_text(CRON, "* * * * * root " COPY " --beat cron\n", 0644)) {
		puts("PERSIST FIXTURE FAILED");
		return 1;
	}
	puts("PERSIST FIXTURE INSTALLED");
	return 0;
}
