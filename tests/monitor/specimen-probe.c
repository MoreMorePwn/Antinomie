/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/* A ~95 MiB static program for the specimen-check VM check: its read-only
 * table is initialized, so the file itself is that big (over the 64 MiB an
 * older guest keeps for static analysis, under revision 19's 128 MiB). It
 * prints one line and exits. */
#include <stdio.h>

static const unsigned char table[95u << 20] = { 1, 2, 3, 4 };

int main(int argc, char **argv)
{
	(void)argv;
	printf("SPECIMEN-PROBE %u\n", table[argc % 4]);
	return 0;
}
