/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest fixture for the non-resident core policy (contract revision 22,
 * ANT-T0343): a benign program whose address space has pages that are mapped
 * and hold data but are not in memory when a core is taken.
 *
 *   nonresident-core-fixture DIR [PAGES]
 *
 * It writes DIR/nonresident-data (PAGES pages, default 256, each starting with
 * "page N"), maps it private and read-only, reads every page, then asks the
 * kernel to reclaim them (MADV_PAGEOUT: clean file pages leave memory and the
 * page cache), prints "NONRESIDENT READY <address> <pages>" and sleeps until
 * killed or for 300 s. A core taken with the resident-only policy has those
 * pages missing; one taken with the non-resident policy reads them back in.
 * It removes its file at the start of its next run; nothing else is touched.
 *
 * Build: gcc -static -O1 -o nonresident-core-fixture nonresident-core-fixture.c
 *        aarch64-linux-gnu-gcc -static -O1 -o nonresident-core-fixture-a64 nonresident-core-fixture.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	unsigned long pages = 256, i;
	char path[512], *data, *map;
	volatile char sum = 0;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: nonresident-core-fixture DIR [PAGES]\n");
		return 2;
	}
	if (argc > 2)
		pages = strtoul(argv[2], NULL, 10);
	if (!pages || pages > 65536)
		return 2;
	snprintf(path, sizeof(path), "%s/nonresident-data", argv[1]);
	unlink(path);
	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	data = calloc(1, page);
	if (!data)
		return 1;
	for (i = 0; i < pages; i++) {
		snprintf(data, page, "page %lu", i);
		if (write(fd, data, page) != page) {
			perror("write");
			return 1;
		}
	}
	fsync(fd);
	map = mmap(NULL, pages * page, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	close(fd);
	for (i = 0; i < pages; i++)
		sum += map[i * page];
	if (madvise(map, pages * page, MADV_PAGEOUT) != 0)
		perror("madvise");
	printf("NONRESIDENT READY %p %lu\n", (void *)map, pages);
	fflush(stdout);
	sleep(300);
	return sum == 42;
}
