// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// cron-probe.c — a benign program that installs cron persistence the way an
// IoT bot does (ANT-T0558): it writes a script that only leaves a marker
// file, a root crontab line that runs it every minute
// (/var/spool/cron/crontabs/root) and BusyBox crond's update note
// (cron.update, as `crontab` writes it), then waits for the base's crond to
// run the script. Triage should report persistence.cron. Prints CRON PROBE
// PASS once the marker exists, or FAIL after about two and a half minutes.
//
// Build: gcc -static -O2 -Wall -Wextra -o cron-probe cron-probe.c
//   (aarch64-linux-gnu-gcc for an arm64 base). Run as root in a guest.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_text(const char *path, const char *text, const char *mode, mode_t bits)
{
	FILE *file = fopen(path, mode);
	if (file == NULL) {
		printf("%s: %s\n", path, strerror(errno));
		return -1;
	}
	fputs(text, file);
	fclose(file);
	chmod(path, bits);
	return 0;
}

int main(void)
{
	const char *marker = "/tmp/cron-probe.ran";
	unlink(marker);
	if (write_text("/tmp/cron-probe.sh", "#!/bin/sh\necho ran > /tmp/cron-probe.ran\n", "w",
		       0755) || write_text("/var/spool/cron/crontabs/root",
					   "* * * * * /tmp/cron-probe.sh\n", "a", 0600) ||
	    write_text("/var/spool/cron/crontabs/cron.update", "root\n", "a", 0600)) {
		puts("CRON PROBE FAIL");
		return 1;
	}
	puts("crontab written; waiting for crond");
	fflush(stdout);
	for (int second = 0; second < 150; second++) {
		if (access(marker, F_OK) == 0) {
			printf("the script ran after about %d s\nCRON PROBE PASS\n", second);
			return 0;
		}
		sleep(1);
	}
	puts("the script did not run\nCRON PROBE FAIL");
	return 1;
}
