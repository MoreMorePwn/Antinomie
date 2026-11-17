// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// watchdog-probe.c — a benign program that does what Mirai does to a device's
// watchdog first (ANT-T0558): open /dev/watchdog (or /dev/misc/watchdog),
// turn it off with WDIOC_SETOPTIONS(WDIOS_DISABLECARD), read its timeout and
// close it with the magic character, so the device does not reboot. On the
// BusyBox camera base the watchdog is softdog. Triage should report
// evasion.watchdog_disable. Prints WATCHDOG PROBE PASS or FAIL.
//
// Build: gcc -static -O2 -Wall -Wextra -o watchdog-probe watchdog-probe.c
//   (aarch64-linux-gnu-gcc for an arm64 base). Run as root in a guest.
#include <errno.h>
#include <fcntl.h>
#include <linux/watchdog.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
	const char *paths[] = { "/dev/watchdog", "/dev/misc/watchdog" };
	int fd = -1, off = WDIOS_DISABLECARD, timeout = 0;
	unsigned i;

	for (i = 0; i < 2 && fd < 0; i++) {
		fd = open(paths[i], O_RDWR);
		printf("open %s: %s\n", paths[i], fd < 0 ? strerror(errno) : "ok");
	}
	if (fd < 0) {
		puts("WATCHDOG PROBE FAIL");
		return 1;
	}
	int disabled = ioctl(fd, WDIOC_SETOPTIONS, &off);
	printf("WDIOC_SETOPTIONS(WDIOS_DISABLECARD): %s\n", disabled ? strerror(errno) : "ok");
	if (ioctl(fd, WDIOC_GETTIMEOUT, &timeout) == 0)
		printf("timeout %d s\n", timeout);
	if (write(fd, "V", 1) != 1)
		printf("magic close: %s\n", strerror(errno));
	close(fd);
	puts(disabled ? "WATCHDOG PROBE FAIL" : "WATCHDOG PROBE PASS");
	return disabled != 0;
}
