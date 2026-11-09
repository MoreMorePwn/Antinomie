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
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	static const char entry[] = "# antinomie trigger fixture\n* * * * * root /bin/true\n";
	char path[256];
	unsigned seconds = 15;
	int fd;

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
