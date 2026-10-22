/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	printf("ANTINOMIE-STATIC-PROBE uid=%lu marker=%s\n",
	       (unsigned long)getuid(), argc > 1 ? argv[1] : "none");
	fflush(stdout);
	return 0;
}
