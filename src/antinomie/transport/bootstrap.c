// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/antinomie.h>
#include "abi.h"

static bool reserved;
static u64 bootstrap_gpa = ANT_BOOT_GPA;

static int __init ant_boot_gpa_param(char *value)
{
	u64 gpa;
	if (!value || kstrtoull(value, 0, &gpa) || (gpa & (ANT_BOOT_SIZE - 1)) ||
	    gpa < 0x100000 || gpa > U64_MAX - ANT_BOOT_SIZE)
		return -EINVAL;
	bootstrap_gpa = gpa;
	return 0;
}
early_param("antinomie_boot_gpa", ant_boot_gpa_param);

void __init ant_bootstrap_reserve(void)
{
	if (memblock_is_region_memory(bootstrap_gpa, ANT_BOOT_SIZE) &&
	    !memblock_is_region_reserved(bootstrap_gpa, ANT_BOOT_SIZE) &&
	    !memblock_reserve(bootstrap_gpa, ANT_BOOT_SIZE))
		reserved = true;
}

bool ant_bootstrap_reserved(void)
{
	return reserved;
}

u64 ant_bootstrap_gpa(void)
{
	return bootstrap_gpa;
}
