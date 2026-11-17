// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// flash-probe.c — a benign program that reads the device's flash layout and
// overwrites one partition, as a bot that wipes or replaces firmware does
// (ANT-T0558): it prints /proc/mtd, finds the "kernel" partition, erases its
// first erase block (MEMERASE) and writes a marker there, then reads it back.
// On the BusyBox camera base the flash is a RAM disk behind block2mtd, so
// nothing survives a reboot. Triage should report impact.block_device_write.
// Prints FLASH PROBE PASS or FAIL.
//
// Build: gcc -static -O2 -Wall -Wextra -o flash-probe flash-probe.c
//   (aarch64-linux-gnu-gcc for an arm64 base). Run as root in a guest.
#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
	char line[256], device[32] = "", name[64];
	unsigned size, erase;
	int partitions = 0;
	FILE *table = fopen("/proc/mtd", "r");

	if (table == NULL) {
		printf("/proc/mtd: %s\nFLASH PROBE FAIL\n", strerror(errno));
		return 1;
	}
	while (fgets(line, sizeof(line), table)) {
		fputs(line, stdout);
		int index;
		if (sscanf(line, "mtd%d: %x %x \"%63[^\"]\"", &index, &size, &erase, name) == 4) {
			partitions++;
			if (strcmp(name, "kernel") == 0)
				snprintf(device, sizeof(device), "/dev/mtd%d", index);
		}
	}
	fclose(table);
	if (partitions < 4 || device[0] == 0) {
		puts("no kernel partition\nFLASH PROBE FAIL");
		return 1;
	}
	int fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("open %s: %s\nFLASH PROBE FAIL\n", device, strerror(errno));
		return 1;
	}
	struct mtd_info_user info;
	if (ioctl(fd, MEMGETINFO, &info) != 0) {
		printf("MEMGETINFO: %s\nFLASH PROBE FAIL\n", strerror(errno));
		return 1;
	}
	struct erase_info_user block = { 0, info.erasesize };
	int erased = ioctl(fd, MEMERASE, &block);
	printf("MEMERASE %s first %u bytes: %s\n", device, info.erasesize,
	       erased ? strerror(errno) : "ok");
	const char marker[] = "antinomie flash probe";
	ssize_t written = pwrite(fd, marker, sizeof(marker), 0);
	char back[sizeof(marker)] = "";
	ssize_t got = pread(fd, back, sizeof(back), 0);
	close(fd);
	int ok = !erased && written == (ssize_t)sizeof(marker) && got == written &&
		 memcmp(back, marker, sizeof(marker)) == 0;
	printf("write %zd, read back %s\n", written, ok ? "the marker" : "something else");
	puts(ok ? "FLASH PROBE PASS" : "FLASH PROBE FAIL");
	return !ok;
}
