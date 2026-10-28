/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest probe for the stealth profile: the checks a sample makes to tell a
 * VM, a sandbox or Antinomie itself from a real machine. It is launched as
 * the sample (a run, never part of the base) and prints one line per check:
 *
 *   STEALTH <verdict> <key> <value>
 *
 * verdict: pass (looks like a real machine), fail (a giveaway), info (no
 * verdict: recorded for the table), skip (not readable for this user).
 * The checks reimplement systemd-detect-virt (CPUID, DMI vendors, the SMBIOS
 * VM bit), virt-what (DMI, cpuinfo, block and PCI vendors, fw_cfg) and the
 * Linux side of pafish (user and host names, uptime, resources, rdtsc around
 * cpuid, sleep skew), plus what is particular to Antinomie: its kernel
 * command line options, build string, symbols, worker thread names and the
 * shape of the launched process. "STEALTH-END" ends the output.
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/stealth-probe.c
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cpuid.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <x86intrin.h>

#define VALUE_MAX 240

static void report(const char *verdict, const char *key, const char *value)
{
	char clean[VALUE_MAX + 1];
	size_t i, n = 0;

	for (i = 0; value && value[i] && n < VALUE_MAX; i++) {
		unsigned char c = value[i];

		clean[n++] = (c == '\n' || c == '\t') ? ' ' : (c < 0x20 || c > 0x7e) ? '?' : c;
	}
	while (n && clean[n - 1] == ' ')
		n--;
	clean[n] = 0;
	printf("STEALTH %s %s %s\n", verdict, key, n ? clean : "-");
}

static void reportf(const char *verdict, const char *key, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

static void reportf(const char *verdict, const char *key, const char *format, ...)
{
	char text[1024];
	va_list args;

	va_start(args, format);
	vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	report(verdict, key, text);
}

/* The first line of a file, without its newline; -1 when unreadable. */
static int read_line(const char *path, char *out, size_t size)
{
	FILE *file = fopen(path, "r");

	if (!file)
		return -1;
	if (!fgets(out, size, file))
		out[0] = 0;
	fclose(file);
	out[strcspn(out, "\n")] = 0;
	return 0;
}

/* A whole (small) file; returns its length or -1. */
static ssize_t read_all(const char *path, char *out, size_t size)
{
	ssize_t total = 0, got;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	while ((size_t)total + 1 < size && (got = read(fd, out + total, size - 1 - total)) > 0)
		total += got;
	close(fd);
	out[total] = 0;
	return total;
}

static int contains_ci(const char *text, const char *needle)
{
	return strcasestr(text, needle) != NULL;
}

/* Strings that name a hypervisor, an emulator or this sandbox. */
static const char *const vm_words[] = {
	"qemu", "kvm", "bochs", "bxpc", "vmware", "virtualbox", "vbox", "innotek", "xen",
	"bhyve", "parallels", "hyper-v", "microsoft corporation virtual", "openstack",
	"kubevirt", "red hat", "standard pc", "virtual machine", "virtual disk", "msft",
	"antinomie", NULL
};

static const char *vm_word(const char *text)
{
	int i;

	for (i = 0; vm_words[i]; i++)
		if (contains_ci(text, vm_words[i]))
			return vm_words[i];
	return NULL;
}

static int antinomie_word(const char *text)
{
	return contains_ci(text, "antinomie");
}

/* --- CPUID ------------------------------------------------------------ */

static void check_cpuid(void)
{
	unsigned int a, b, c, d, regs[12];
	char vendor[13], hv[13], brand[49];
	int i;

	__cpuid(0, a, b, c, d);
	memcpy(vendor, &b, 4);
	memcpy(vendor + 4, &d, 4);
	memcpy(vendor + 8, &c, 4);
	vendor[12] = 0;
	report("info", "cpuid.vendor", vendor);
	__cpuid(1, a, b, c, d);
	reportf(c & (1u << 31) ? "fail" : "pass", "cpuid.hypervisor-bit", "%u", c >> 31);
	__cpuid(0x40000000, a, b, c, d);
	memcpy(hv, &b, 4);
	memcpy(hv + 4, &c, 4);
	memcpy(hv + 8, &d, 4);
	hv[12] = 0;
	for (i = 0; i < 12; i++)
		if (!hv[i] || !isprint((unsigned char)hv[i]))
			hv[i] = '.';
	{
		static const char *const known[] = { "KVMKVMKVM", "TCGTCGTCGTCG", "Microsoft Hv",
			"VMwareVMware", "XenVMMXenVMM", "VBoxVBoxVBox", "bhyve bhyve", " lrpepyh  vr",
			"ACRNACRNACRN", "QNXQVMBSQG", NULL };
		const char *match = NULL;

		for (i = 0; known[i]; i++)
			if (!strncmp(hv, known[i], strlen(known[i])))
				match = known[i];
		reportf(match ? "fail" : "pass", "cpuid.hypervisor-leaf", "0x40000000 max %#x vendor \"%s\"",
			a, hv);
	}
	__cpuid(0x80000000, a, b, c, d);
	if (a >= 0x80000004) {
		for (i = 0; i < 3; i++)
			__cpuid(0x80000002 + i, regs[i * 4], regs[i * 4 + 1], regs[i * 4 + 2],
				regs[i * 4 + 3]);
		memcpy(brand, regs, 48);
		brand[48] = 0;
		report(vm_word(brand) || contains_ci(brand, "virtual") ? "fail" : "pass", "cpuid.brand",
		       brand);
	} else {
		report("fail", "cpuid.brand", "no brand string leaves");
	}
}

/* --- Timing (pafish rdtsc checks, sleep skew) ---------------------------- */

static int cmp_u64(const void *x, const void *y)
{
	uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;

	return a < b ? -1 : a > b;
}

static uint64_t now_ns(clockid_t clock)
{
	struct timespec ts;

	clock_gettime(clock, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void check_timing(void)
{
	enum { N = 201 };
	uint64_t plain[N], vmexit[N], t0, t1, m0, m1, tsc_hz, slept_tsc, slept_mono;
	unsigned int a, b, c, d;
	struct timespec half = { 0, 500000000 };
	double skew;
	int i;

	for (i = 0; i < N; i++) {
		t0 = __rdtsc();
		t1 = __rdtsc();
		plain[i] = t1 - t0;
		t0 = __rdtsc();
		__cpuid(0, a, b, c, d);
		t1 = __rdtsc();
		vmexit[i] = t1 - t0;
	}
	(void)a; (void)b; (void)c; (void)d;
	qsort(plain, N, sizeof(plain[0]), cmp_u64);
	qsort(vmexit, N, sizeof(vmexit[0]), cmp_u64);
	/* pafish: rdtsc twice averages over 750 cycles, or rdtsc around cpuid
	 * over 1000, on a VM; bare metal is tens and about 100-250. */
	reportf(plain[N / 2] > 750 ? "fail" : "pass", "timing.rdtsc-delta", "median %llu cycles",
		(unsigned long long)plain[N / 2]);
	reportf(vmexit[N / 2] > 1000 ? "fail" : "pass", "timing.rdtsc-cpuid", "median %llu cycles (min %llu)",
		(unsigned long long)vmexit[N / 2], (unsigned long long)vmexit[0]);
	/* The TSC rate from a 100 ms busy wait, then a 500 ms sleep timed twice. */
	m0 = now_ns(CLOCK_MONOTONIC);
	t0 = __rdtsc();
	while (now_ns(CLOCK_MONOTONIC) - m0 < 100000000ull)
		;
	m1 = now_ns(CLOCK_MONOTONIC);
	t1 = __rdtsc();
	tsc_hz = (t1 - t0) * 1000000000ull / (m1 - m0);
	m0 = now_ns(CLOCK_MONOTONIC);
	t0 = __rdtsc();
	nanosleep(&half, NULL);
	t1 = __rdtsc();
	m1 = now_ns(CLOCK_MONOTONIC);
	slept_mono = m1 - m0;
	slept_tsc = (t1 - t0) * 1000000000ull / (tsc_hz ? tsc_hz : 1);
	skew = ((double)slept_tsc - (double)slept_mono) / (double)slept_mono * 100.0;
	reportf(slept_mono < 500000000ull || skew > 2.0 || skew < -2.0 ? "fail" : "pass", "timing.sleep-skew",
		"500 ms sleep: monotonic %.1f ms, tsc %.1f ms (%+.2f%%), tsc %.0f MHz",
		slept_mono / 1e6, slept_tsc / 1e6, skew, tsc_hz / 1e6);
}

/* --- DMI / SMBIOS -------------------------------------------------------- */

static void check_dmi(void)
{
	static const char *const fields[] = {
		"sys_vendor", "product_name", "product_version", "product_family", "product_sku",
		"board_vendor", "board_name", "bios_vendor", "bios_version", "bios_date",
		"chassis_vendor", "chassis_type", "product_serial", "product_uuid", "board_serial",
		NULL
	};
	char path[96], value[256];
	int i;

	for (i = 0; fields[i]; i++) {
		char key[64];

		snprintf(path, sizeof(path), "/sys/class/dmi/id/%s", fields[i]);
		snprintf(key, sizeof(key), "dmi.%s", fields[i]);
		if (read_line(path, value, sizeof(value)) < 0) {
			report(errno == EACCES ? "skip" : "fail", key, strerror(errno));
			continue;
		}
		if (!strcmp(fields[i], "chassis_type"))
			report(!strcmp(value, "1") || !strcmp(value, "2") ? "fail" : "pass", key, value);
		else
			report(vm_word(value) ? "fail" : "pass", key, value);
	}
}

/* The raw SMBIOS table (root only): the BIOS VM bit and QEMU's own strings. */
static void check_smbios_raw(void)
{
	static unsigned char table[65536];
	ssize_t len = read_all("/sys/firmware/dmi/tables/DMI", (char *)table, sizeof(table));
	ssize_t at = 0;
	char found[512] = "";
	int vm_bit = -1, types = 0, oem_strings = -1;

	if (len < 0) {
		report(errno == EACCES ? "skip" : "fail", "smbios.vm-bit", strerror(errno));
		report(errno == EACCES ? "skip" : "fail", "smbios.strings", strerror(errno));
		return;
	}
	while (at + 4 <= len) {
		unsigned char type = table[at], length = table[at + 1];
		ssize_t end;

		if (length < 4 || at + length > len)
			break;
		types++;
		/* Type 0 byte 0x13: BIOS characteristics extension byte 2, bit 4
		 * "system is a virtual machine" (systemd-detect-virt reads it). */
		if (type == 0 && length > 0x13)
			vm_bit = (table[at + 0x13] >> 4) & 1;
		/* Type 11: OEM strings, which PC firmware fills and QEMU leaves out. */
		if (type == 11 && length > 4)
			oem_strings = table[at + 4];
		/* The string set: NUL-terminated strings, ended by one more NUL;
		 * a structure without strings has two NULs. */
		end = at + length;
		if (end + 1 < len && !table[end] && !table[end + 1]) {
			end += 2;
		} else {
			while (end < len && table[end]) {
				const char *text = (const char *)table + end;
				size_t text_len = strnlen(text, len - end);

				if (vm_word(text) && strlen(found) + text_len + 8 < sizeof(found))
					snprintf(found + strlen(found), sizeof(found) - strlen(found),
						 "%st%u:%s", *found ? ", " : "", type, text);
				end += text_len + 1;
			}
			end++;
		}
		at = end;
		if (type == 127)
			break;
	}
	reportf(vm_bit == 1 ? "fail" : "pass", "smbios.vm-bit", "%d (%d structures)", vm_bit, types);
	report(*found ? "fail" : "pass", "smbios.strings", *found ? found : "none naming a VM");
	if (oem_strings < 0)
		report("fail", "smbios.oem-strings", "no type 11 structure");
	else
		reportf("pass", "smbios.oem-strings", "%d strings", oem_strings);
}

/* ACPI tables (root only): OEM IDs and QEMU devices in the DSDT. */
static void check_acpi(void)
{
	static char data[1 << 20];
	char list[512] = "", path[128], found[512] = "", oem_found[512] = "";
	struct dirent *entry;
	DIR *dir = opendir("/sys/firmware/acpi/tables");
	int denied = 0;

	if (dir) {
		while ((entry = readdir(dir))) {
			ssize_t len;

			if (entry->d_name[0] == '.' || entry->d_type == DT_DIR)
				continue;
			snprintf(path, sizeof(path), "/sys/firmware/acpi/tables/%.64s", entry->d_name);
			len = read_all(path, data, sizeof(data));
			if (len < 0) {
				denied = 1;
				continue;
			}
			if (len >= 36) {
				char oem[16];

				snprintf(oem, sizeof(oem), "%.6s/%.8s", data + 10, data + 16);
				if (strlen(list) + strlen(entry->d_name) + strlen(oem) + 4 < sizeof(list))
					snprintf(list + strlen(list), sizeof(list) - strlen(list), "%s%s=%s",
						 *list ? " " : "", entry->d_name, oem);
				/* BOCHS/BXPC from QEMU, INTEL/EDK2 from OVMF (BGRT). */
				if ((vm_word(oem) || contains_ci(oem, "BOCHS") || contains_ci(oem, "EDK2")) &&
				    strlen(oem_found) + 40 < sizeof(oem_found))
					snprintf(oem_found + strlen(oem_found),
						 sizeof(oem_found) - strlen(oem_found), "%s%s OEM %s",
						 *oem_found ? ", " : "", entry->d_name, oem);
			}
			{
				static const char *const devices[] = { "QEMU0002", "QEMU0001", "FWCF",
					"BOCHS", "BXPC", "VMBUS", "VBOX", NULL };
				int i;

				for (i = 0; devices[i]; i++)
					if (memmem(data, len, devices[i], strlen(devices[i])) &&
					    strlen(found) + 40 < sizeof(found))
						snprintf(found + strlen(found), sizeof(found) - strlen(found),
							 "%s%s has %s", *found ? ", " : "", entry->d_name,
							 devices[i]);
			}
		}
		closedir(dir);
	}
	if (!dir || (denied && !*list)) {
		report("skip", "acpi.oem-ids", dir ? "permission denied" : strerror(errno));
		report("skip", "acpi.tables", dir ? "permission denied" : strerror(errno));
	} else {
		/* The header's OEM and table IDs (BOCHS/BXPC by default). */
		report(*oem_found ? "fail" : "pass", "acpi.oem-ids", *oem_found ? oem_found : list);
		/* The creator ID and the DSDT's devices. */
		report(*found ? "fail" : "pass", "acpi.tables", *found ? found : "no VM names");
	}
	/* Enumerated ACPI devices are world-readable. */
	found[0] = 0;
	dir = opendir("/sys/bus/acpi/devices");
	if (dir) {
		while ((entry = readdir(dir)))
			if ((!strncmp(entry->d_name, "QEMU", 4) || !strncmp(entry->d_name, "VMBUS", 5)) &&
			    strlen(found) + strlen(entry->d_name) + 2 < sizeof(found))
				snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s%s",
					 *found ? " " : "", entry->d_name);
		closedir(dir);
	}
	report(*found ? "fail" : "pass", "acpi.devices", *found ? found : "none named QEMU");
}

/* --- QEMU fw_cfg --------------------------------------------------------- */

static void check_fw_cfg(void)
{
	struct stat st;
	char sig[5] = "";
	int i;

	report(stat("/sys/firmware/qemu_fw_cfg", &st) ? "pass" : "fail", "fwcfg.sysfs",
	       stat("/sys/firmware/qemu_fw_cfg", &st) ? "absent" : "present");
	/* The I/O ports: selector 0 (signature) at 0x510, data at 0x511. */
	if (ioperm(0x510, 2, 1)) {
		report("skip", "fwcfg.ioport", strerror(errno));
		return;
	}
	outw(0, 0x510);
	for (i = 0; i < 4; i++) {
		unsigned char c = inb(0x511);

		sig[i] = isprint(c) ? c : '.';
	}
	ioperm(0x510, 2, 0);
	reportf(!strcmp(sig, "QEMU") ? "fail" : "pass", "fwcfg.ioport", "signature \"%s\"", sig);
}

/* --- Devices ------------------------------------------------------------- */

static void check_pci(void)
{
	struct dirent *entry;
	DIR *dir = opendir("/sys/bus/pci/devices");
	static const char vm_vendors[] = "0x1af4 0x1b36 0x1234 0x15ad 0x80ee";
	char path[160], vendor[16], device[16], sub[16], found[1024] = "", subs[1024] = "";
	int total = 0, sub_vm = 0;

	if (!dir) {
		report("info", "pci.vendors", "no PCI bus");
		return;
	}
	while ((entry = readdir(dir))) {
		if (entry->d_name[0] == '.')
			continue;
		total++;
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%.64s/vendor", entry->d_name);
		if (read_line(path, vendor, sizeof(vendor)))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%.64s/device", entry->d_name);
		if (read_line(path, device, sizeof(device)))
			device[0] = 0;
		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%.64s/subsystem_vendor", entry->d_name);
		if (read_line(path, sub, sizeof(sub)))
			sub[0] = 0;
		/* 1af4 Red Hat (virtio), 1b36 Red Hat (QEMU), 1234 Bochs display,
		 * 15ad VMware, 80ee VirtualBox. */
		if (strstr(vm_vendors, vendor) && strlen(found) + 48 < sizeof(found))
			snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s%s %s:%s",
				 *found ? ", " : "", entry->d_name + 5, vendor + 2, device + 2);
		/* The subsystem: q35 gives every device QEMU's 1af4:1100. */
		if (*sub && strstr(vm_vendors, sub))
			sub_vm++;
		else if (*sub && strlen(subs) + 40 < sizeof(subs))
			snprintf(subs + strlen(subs), sizeof(subs) - strlen(subs), "%s%s sub %s",
				 *subs ? ", " : "", entry->d_name + 5, sub + 2);
	}
	closedir(dir);
	reportf(*found ? "fail" : "pass", "pci.vendors", "%d devices; VM vendors: %s", total,
		*found ? found : "none");
	reportf(sub_vm ? "fail" : "pass", "pci.subsystems", "%d of %d with a VM subsystem vendor; others: %s",
		sub_vm, total, *subs ? subs : "none");
}

static void check_virtio(void)
{
	struct dirent *entry;
	DIR *dir = opendir("/sys/bus/virtio/devices");
	int count = 0;

	if (dir) {
		while ((entry = readdir(dir)))
			if (entry->d_name[0] != '.')
				count++;
		closedir(dir);
	}
	reportf(count ? "fail" : "pass", "virtio.devices", "%d", count);
}

static void check_block(void)
{
	struct dirent *entry;
	DIR *dir = opendir("/sys/block");
	char path[160], value[128], list[512] = "";
	int bad = 0, small = 0;

	if (!dir)
		return;
	while ((entry = readdir(dir))) {
		unsigned long long sectors = 0;
		char model[64] = "", vendor[64] = "";

		if (entry->d_name[0] == '.' || !strncmp(entry->d_name, "loop", 4) ||
		    !strncmp(entry->d_name, "ram", 3))
			continue;
		snprintf(path, sizeof(path), "/sys/block/%.64s/size", entry->d_name);
		if (!read_line(path, value, sizeof(value)))
			sectors = strtoull(value, NULL, 10);
		snprintf(path, sizeof(path), "/sys/block/%.64s/device/model", entry->d_name);
		read_line(path, model, sizeof(model));
		snprintf(path, sizeof(path), "/sys/block/%.64s/device/vendor", entry->d_name);
		read_line(path, vendor, sizeof(vendor));
		if (!strncmp(entry->d_name, "vd", 2) || vm_word(model) || vm_word(vendor) ||
		    !strcmp(vendor, "0x1af4"))
			bad = 1;
		if (strncmp(entry->d_name, "sr", 2) && sectors && sectors * 512 < 60ull << 30)
			small = 1;
		if (strlen(list) + 96 < sizeof(list))
			snprintf(list + strlen(list), sizeof(list) - strlen(list), "%s%s %.1f GiB %s %s",
				 *list ? ", " : "", entry->d_name, sectors * 512.0 / (1 << 30), vendor,
				 model);
	}
	closedir(dir);
	report(bad ? "fail" : "pass", "block.devices", list);
	report(small ? "fail" : "pass", "block.disk-size", small ? "a disk under 60 GiB (pafish)" : "every disk 60 GiB or more");
	/* NVMe controllers: model, firmware and subsystem name (QEMU's say so). */
	dir = opendir("/sys/class/nvme");
	if (dir) {
		char nvme[512] = "";
		int qemu = 0;

		while ((entry = readdir(dir))) {
			char model[64] = "", firmware[32] = "", nqn[256] = "";

			if (entry->d_name[0] == '.')
				continue;
			snprintf(path, sizeof(path), "/sys/class/nvme/%.32s/model", entry->d_name);
			read_line(path, model, sizeof(model));
			snprintf(path, sizeof(path), "/sys/class/nvme/%.32s/firmware_rev", entry->d_name);
			read_line(path, firmware, sizeof(firmware));
			snprintf(path, sizeof(path), "/sys/class/nvme/%.32s/subsysnqn", entry->d_name);
			read_line(path, nqn, sizeof(nqn));
			qemu |= vm_word(model) || vm_word(nqn);
			if (strlen(nvme) + 160 < sizeof(nvme))
				snprintf(nvme + strlen(nvme), sizeof(nvme) - strlen(nvme),
					 "%s%s model %.40s firmware %.8s nqn %.80s", *nvme ? ", " : "",
					 entry->d_name, model, firmware, nqn);
		}
		closedir(dir);
		if (*nvme)
			report(qemu ? "fail" : "pass", "block.nvme", nvme);
	}
	if (!read_line("/sys/block/sda/queue/rotational", value, sizeof(value))) {
		char wwid[128] = "";

		read_line("/sys/block/sda/device/wwid", wwid, sizeof(wwid));
		reportf("info", "block.sata", "sda rotational %s wwid %s", value, *wwid ? wwid : "-");
	}
}

static void check_net(void)
{
	static const char *const ouis[] = { "52:54:00", "08:00:27", "00:0c:29", "00:50:56",
		"00:05:69", "00:1c:14", "00:16:3e", "00:1c:42", "00:15:5d", "0a:00:27", NULL };
	struct dirent *entry;
	DIR *dir = opendir("/sys/class/net");
	char path[160], mac[32], driver[256], list[512] = "";
	int bad = 0, i;

	if (!dir)
		return;
	while ((entry = readdir(dir))) {
		ssize_t n;
		const char *name;

		if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo"))
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%.64s/address", entry->d_name);
		if (read_line(path, mac, sizeof(mac)))
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%.64s/device/driver", entry->d_name);
		n = readlink(path, driver, sizeof(driver) - 1);
		driver[n > 0 ? n : 0] = 0;
		name = strrchr(driver, '/') ? strrchr(driver, '/') + 1 : driver;
		for (i = 0; ouis[i]; i++)
			if (!strncasecmp(mac, ouis[i], 8))
				bad = 1;
		if (!strcmp(name, "virtio_net"))
			bad = 1;
		if (strlen(list) + 64 < sizeof(list))
			snprintf(list + strlen(list), sizeof(list) - strlen(list), "%s%.32s %s %.32s",
				 *list ? ", " : "", entry->d_name, mac, name);
	}
	closedir(dir);
	report(bad ? "fail" : *list ? "pass" : "info", "net.mac", *list ? list : "no network card");
}

/* QEMU's (and VirtualBox's) user networking: 10.0.2.15, gateway 10.0.2.2,
 * DNS 10.0.2.3; the guest's own address too. */
static void check_net_addresses(void)
{
	static char text[8192];
	char gateway[32] = "none", dns[64] = "none", address[32] = "none", *line;
	int qemu = 0;

	if (read_all("/proc/net/route", text, sizeof(text)) >= 0) {
		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
			char name[32];
			unsigned int destination, via;

			if (sscanf(line, "%31s %x %x", name, &destination, &via) == 3 && !destination) {
				snprintf(gateway, sizeof(gateway), "%u.%u.%u.%u", via & 0xff, (via >> 8) & 0xff,
					 (via >> 16) & 0xff, via >> 24);
				qemu |= (via & 0xffffff) == 0x02000a;
			}
		}
	}
	if (read_all("/etc/resolv.conf", text, sizeof(text)) >= 0) {
		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n"))
			if (sscanf(line, "nameserver %63s", dns) == 1) {
				qemu |= !strncmp(dns, "10.0.2.", 7);
				break;
			}
	}
	{
		struct ifaddrs *list, *item;

		if (!getifaddrs(&list)) {
			for (item = list; item; item = item->ifa_next) {
				struct sockaddr_in *in = (struct sockaddr_in *)item->ifa_addr;

				if (!in || in->sin_family != AF_INET || !strcmp(item->ifa_name, "lo"))
					continue;
				inet_ntop(AF_INET, &in->sin_addr, address, sizeof(address));
				qemu |= !strncmp(address, "10.0.2.", 7);
				break;
			}
			freeifaddrs(list);
		}
	}
	reportf(qemu ? "fail" : "pass", "net.addresses", "address %s, gateway %s, nameserver %s",
		address, gateway, dns);
}

static void check_devices_misc(void)
{
	static char text[65536];
	char value[256], found[512] = "";
	char *line;

	if (read_all("/proc/bus/input/devices", text, sizeof(text)) >= 0) {
		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n"))
			if (!strncmp(line, "N: Name=", 8) && vm_word(line) &&
			    strlen(found) + strlen(line) + 2 < sizeof(found))
				snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s%s",
					 *found ? ", " : "", line + 8);
		report(*found ? "fail" : "pass", "input.names", *found ? found : "no VM names");
	}
	if (read_all("/proc/fb", text, sizeof(text)) >= 0) {
		report(contains_ci(text, "virtio") || contains_ci(text, "bochs") ||
		       contains_ci(text, "qxl") || contains_ci(text, "vmwgfx") ? "fail" : "pass",
		       "display.fb", text);
	}
	if (!read_line("/sys/devices/system/clocksource/clocksource0/current_clocksource", value,
		       sizeof(value)))
		report(contains_ci(value, "kvm") || contains_ci(value, "hyperv") ||
		       contains_ci(value, "xen") ? "fail" : "pass", "clock.source", value);
	if (read_all("/proc/cpuinfo", text, sizeof(text)) >= 0) {
		char *flags = strstr(text, "\nflags");
		char *model = strstr(text, "model name");

		if (flags) {
			char *end = strchr(flags + 1, '\n');

			if (end)
				*end = 0;
			report(strstr(flags, " hypervisor") ? "fail" : "pass", "cpuinfo.flags",
			       strstr(flags, " hypervisor") ? "hypervisor flag set" : "no hypervisor flag");
		}
		if (model) {
			char *end = strchr(model, '\n');

			if (end)
				*end = 0;
			report(vm_word(model) ? "fail" : "pass", "cpuinfo.model", strchr(model, ':') ? strchr(model, ':') + 2 : model);
		}
	}
	if (read_all("/proc/scsi/scsi", text, sizeof(text)) >= 0)
		report(vm_word(text) ? "fail" : "pass", "scsi.models", text);
}

/* --- Kernel identity ----------------------------------------------------- */

static void check_kernel(void)
{
	static char text[1 << 16];
	struct utsname u;
	char value[1024];

	if (read_line("/proc/cmdline", value, sizeof(value)) == 0)
		report(contains_ci(value, "antinomie") ? "fail" : "pass", "kernel.cmdline", value);
	if (read_line("/proc/version", value, sizeof(value)) == 0) {
		/* Distribution kernels name their build service; anything else is a
		 * kernel someone built on their own machine. */
		int distro = strstr(value, "@lists.debian.org") || strstr(value, "buildd@") ||
			     strstr(value, "@ubuntu") || strstr(value, "mockbuild@") ||
			     strstr(value, "@build") || strstr(value, "@archlinux");

		report(antinomie_word(value) || !distro ? "fail" : "pass", "kernel.version", value);
	}
	uname(&u);
	reportf(antinomie_word(u.version) || antinomie_word(u.release) ? "fail" : "info", "kernel.uname",
		"%s %s %s %s %s", u.sysname, u.nodename, u.release, u.version, u.machine);
	report(read_all("/proc/config.gz", text, 16) >= 0 ? "fail" : "pass", "kernel.config-gz",
	       read_all("/proc/config.gz", text, 16) >= 0 ? "present" : "absent");
	if (!read_line("/proc/sys/kernel/tainted", value, sizeof(value)))
		report(strcmp(value, "0") ? "info" : "pass", "kernel.tainted", value);
}

static int antinomie_symbol(const char *name)
{
	return !strncmp(name, "ant_", 4) || !strncmp(name, "__ant_", 6) ||
	       !strncmp(name, "antc_", 5) || antinomie_word(name) || strstr(name, "_ant_");
}

static void check_kallsyms(void)
{
	FILE *file = fopen("/proc/kallsyms", "r");
	char line[512], sample[512] = "";
	unsigned long total = 0, hits = 0, zero = 0;

	if (!file) {
		report("skip", "kallsyms.antinomie", strerror(errno));
		return;
	}
	while (fgets(line, sizeof(line), file)) {
		char address[32], type[4], name[256];

		if (sscanf(line, "%31s %3s %255s", address, type, name) != 3)
			continue;
		total++;
		if (strspn(address, "0") == strlen(address))
			zero++;
		if (antinomie_symbol(name)) {
			hits++;
			if (strncmp(name, "__pfx_", 6))
				printf("STEALTH-DETAIL kallsyms %s %s\n", type, name);
			if (strlen(sample) + strlen(name) + 2 < 200)
				snprintf(sample + strlen(sample), sizeof(sample) - strlen(sample), "%s%s",
					 *sample ? " " : "", name);
		}
	}
	fclose(file);
	reportf(hits ? "fail" : "pass", "kallsyms.antinomie", "%lu of %lu symbols%s%s%s", hits, total,
		zero == total ? " (addresses hidden)" : "", hits ? ": " : "", sample);
}

static void check_modules(void)
{
	static char text[1 << 16];
	ssize_t len = read_all("/proc/modules", text, sizeof(text));
	struct dirent *entry;
	DIR *dir;
	char found[256] = "";
	int lines = 0, i;

	if (len >= 0)
		for (i = 0; i < len; i++)
			lines += text[i] == '\n';
	report(len >= 0 && antinomie_word(text) ? "fail" : "info", "modules.loaded",
	       len < 0 ? "no /proc/modules" : lines ? "some loaded" : "none loaded (all built in)");
	dir = opendir("/sys/module");
	if (dir) {
		while ((entry = readdir(dir)))
			if ((antinomie_word(entry->d_name) || !strncmp(entry->d_name, "ant_", 4)) &&
			    strlen(found) + strlen(entry->d_name) + 2 < sizeof(found))
				snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s%s",
					 *found ? " " : "", entry->d_name);
		closedir(dir);
		report(*found ? "fail" : "pass", "modules.sysfs", *found ? found : "no antinomie entry");
	}
}

/* Kernel log: readable by root, or by anyone without dmesg_restrict. */
static void check_dmesg(void)
{
	static char text[1 << 20];
	char found[512] = "", restrict_value[16] = "?";
	int len = klogctl(10, NULL, 0), hits = 0, vm = 0;
	char *line;

	read_line("/proc/sys/kernel/dmesg_restrict", restrict_value, sizeof(restrict_value));
	if (len <= 0)
		len = 1 << 20;
	len = klogctl(3, text, len < (int)sizeof(text) - 1 ? len : (int)sizeof(text) - 1);
	if (len < 0) {
		reportf("skip", "dmesg.antinomie", "%s (dmesg_restrict %s)", strerror(errno), restrict_value);
		return;
	}
	text[len] = 0;
	for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
		int ours = antinomie_word(line);
		int virt = !ours && (vm_word(line) || contains_ci(line, "hypervisor") ||
				     contains_ci(line, "virtio"));

		if (ours)
			hits++;
		if (virt)
			vm++;
		if ((ours || virt) && hits + vm <= 80)
			printf("STEALTH-DETAIL dmesg %.200s\n", line);
		if ((ours || (virt && hits == 0)) && strlen(found) + 80 < sizeof(found))
			snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s[%.70s]",
				 *found ? " " : "", line);
	}
	reportf(hits ? "fail" : "pass", "dmesg.antinomie", "%d line(s) (dmesg_restrict %s)", hits,
		restrict_value);
	reportf(vm ? "fail" : "pass", "dmesg.vm", "%d line(s) naming a VM or virtio: %s", vm, found);
}

/* A recorder name in BTF: antinomie anywhere, or a name starting with ant_ or
 * antc_ after any underscores (ant_task, __ant_x, ANT_X), in any case. Stock
 * vmlinux BTF has none; stock wireless modules have ant_* fields, but no
 * wireless driver loads in these VMs. */
static int btf_recorder_name(const char *name)
{
	const char *p = name + strspn(name, "_");

	return contains_ci(name, "antinomie") || !strncasecmp(p, "ant_", 4) ||
	       !strncasecmp(p, "antc_", 5);
}

/* Scan one BTF file's string table (the names its types use) for recorder
 * names; -1 when unreadable or not BTF, else the number of hits. */
static long btf_scan(const char *path, char *buf, size_t size, unsigned long *strings,
		     char *sample, size_t sample_size)
{
	ssize_t len = read_all(path, buf, size);
	uint32_t hdr_len, str_off, str_len;
	uint16_t magic;
	long hits = 0;
	size_t at, end;

	if (len < 24)
		return -1;
	memcpy(&magic, buf, 2);
	memcpy(&hdr_len, buf + 4, 4);
	memcpy(&str_off, buf + 16, 4);
	memcpy(&str_len, buf + 20, 4);
	if (magic != 0xeb9f || (size_t)hdr_len + str_off + str_len > (size_t)len)
		return -1;
	at = (size_t)hdr_len + str_off;
	end = at + str_len;
	buf[end - (end > at)] = 0;
	while (at < end) {
		const char *name = buf + at;

		(*strings)++;
		if (*name && btf_recorder_name(name)) {
			hits++;
			if (hits <= 40)
				printf("STEALTH-DETAIL btf %s %s\n", path, name);
			if (strlen(sample) + strlen(name) + 2 < sample_size)
				snprintf(sample + strlen(sample), sample_size - strlen(sample), "%s%s",
					 *sample ? " " : "", name);
		}
		at += strlen(name) + 1;
	}
	return hits;
}

/* The kernel's BTF: Debian's kernel has it (systemd's bpf-restrict-fs and
 * eBPF tools need it), so missing is a giveaway, and so is any recorder name
 * in it or in a module's. */
static void check_btf(void)
{
	static char buf[32 << 20];
	char sample[256] = "", path[300];
	unsigned long strings = 0, modules = 0;
	long hits, module_hits = 0, found;
	struct dirent *entry;
	DIR *dir;

	hits = btf_scan("/sys/kernel/btf/vmlinux", buf, sizeof(buf), &strings, sample, sizeof(sample));
	if (hits < 0)
		report("fail", "kernel.btf", "no /sys/kernel/btf/vmlinux (Debian's kernel has it)");
	else
		reportf(hits ? "fail" : "pass", "kernel.btf", "present, %lu names, %ld of the recorder%s%s",
			strings, hits, hits ? ": " : "", sample);
	dir = opendir("/sys/kernel/btf");
	if (!dir)
		return;
	*sample = 0;
	while ((entry = readdir(dir))) {
		unsigned long ignored = 0;

		if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "vmlinux"))
			continue;
		snprintf(path, sizeof(path), "/sys/kernel/btf/%s", entry->d_name);
		found = btf_scan(path, buf, sizeof(buf), &ignored, sample, sizeof(sample));
		modules++;
		if (found > 0)
			module_hits += found;
	}
	closedir(dir);
	reportf(module_hits ? "fail" : "pass", "kernel.btf.modules",
		"%lu loaded module(s) with BTF, %ld recorder name(s)%s%s", modules, module_hits,
		module_hits ? ": " : "", sample);
}

/* Tracing interfaces a root sample can mount. */
static void check_tracing(void)
{
	static char text[1 << 16];
	char dir[] = "/tmp/.stp-XXXXXX";
	struct stat st;
	int mounted = 0;

	if (stat("/sys/kernel/tracing/available_events", &st)) {
		if (!mkdtemp(dir)) {
			report("skip", "tracing.functions", strerror(errno));
			return;
		}
		if (mount("tracefs", dir, "tracefs", 0, NULL)) {
			reportf("skip", "tracing.functions", "mount tracefs: %s", strerror(errno));
			rmdir(dir);
			return;
		}
		mounted = 1;
	}
	{
		char path[96];
		ssize_t len;

		snprintf(path, sizeof(path), "%s/available_filter_functions",
			 mounted ? dir : "/sys/kernel/tracing");
		len = read_all(path, text, sizeof(text));
		if (len < 0)
			report("pass", "tracing.functions", "no function tracer");
		else
			report(strstr(text, "ant_") ? "fail" : "pass", "tracing.functions",
			       strstr(text, "ant_") ? "ant_ functions listed" : "no ant_ functions");
		snprintf(path, sizeof(path), "%s/available_events", mounted ? dir : "/sys/kernel/tracing");
		len = read_all(path, text, sizeof(text));
		report(len >= 0 && antinomie_word(text) ? "fail" : "pass", "tracing.events",
		       len >= 0 && antinomie_word(text) ? "antinomie events" : "no antinomie events");
	}
	if (mounted) {
		umount(dir);
		rmdir(dir);
	}
}

static void check_iomem(void)
{
	static char text[1 << 16];
	char found[512] = "";
	const char *files[] = { "/proc/iomem", "/proc/ioports", NULL };
	int i, zeros = 1;

	for (i = 0; files[i]; i++) {
		char *line;

		if (read_all(files[i], text, sizeof(text)) < 0)
			continue;
		if (strstr(text, "-") && !strstr(text, "00000000-00000000"))
			zeros = 0;
		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n"))
			if ((vm_word(line) || contains_ci(line, "fw_cfg") || contains_ci(line, "virtio")) &&
			    strlen(found) + 60 < sizeof(found))
				snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s[%.50s]",
					 *found ? " " : "", line + strspn(line, " "));
	}
	reportf(*found ? "fail" : "pass", "iomem.names", "%s%s", *found ? found : "no VM names",
		zeros ? " (addresses hidden)" : "");
}

/* --- Processes and the launched program ---------------------------------- */

static int stat_fields(const char *pid, char *comm, size_t comm_size, long *ppid, long *pgrp,
		       long *session, long *tty, long *tpgid)
{
	char path[64], text[1024], *close_paren;

	snprintf(path, sizeof(path), "/proc/%s/stat", pid);
	if (read_all(path, text, sizeof(text)) <= 0)
		return -1;
	close_paren = strrchr(text, ')');
	if (!close_paren || !strchr(text, '('))
		return -1;
	snprintf(comm, comm_size, "%.*s", (int)(close_paren - strchr(text, '(') - 1), strchr(text, '(') + 1);
	return sscanf(close_paren + 2, "%*c %ld %ld %ld %ld %ld", ppid, pgrp, session, tty, tpgid) == 5 ? 0 : -1;
}

static void add_word(char *list, size_t size, const char *word)
{
	char padded[96];

	snprintf(padded, sizeof(padded), " %.90s ", word);
	if (*list) {
		char haystack[2048];

		snprintf(haystack, sizeof(haystack), " %s ", list);
		if (strstr(haystack, padded))
			return;
	}
	if (strlen(list) + strlen(word) + 2 < size)
		snprintf(list + strlen(list), size - strlen(list), "%s%s", *list ? " " : "", word);
}

/* One pass over /proc; the names a sample would grep for. */
static void scan_processes(char *ours, size_t ours_size, char *queues, size_t queues_size, int *total,
			   int *kthreads)
{
	struct dirent *entry;
	DIR *dir = opendir("/proc");
	char comm[80], path[64], cmd[256];

	*total = *kthreads = 0;
	if (!dir)
		return;
	while ((entry = readdir(dir))) {
		long ppid, pgrp, session, tty, tpgid;
		ssize_t n;
		char *dash;

		if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
			continue;
		if (stat_fields(entry->d_name, comm, sizeof(comm), &ppid, &pgrp, &session, &tty, &tpgid))
			continue;
		(*total)++;
		if (ppid == 2 || !strcmp(entry->d_name, "2"))
			(*kthreads)++;
		snprintf(path, sizeof(path), "/proc/%.20s/cmdline", entry->d_name);
		n = read_all(path, cmd, sizeof(cmd));
		for (ssize_t i = 0; i + 1 < n; i++)
			if (!cmd[i])
				cmd[i] = ' ';
		if (antinomie_word(comm) || !strncasecmp(comm, "ant_", 4) || (n > 0 && antinomie_word(cmd)))
			add_word(ours, ours_size, comm);
		/* A worker shows the queue of its last work: kworker/uN:M-name,
		 * or kworker/uN:M+name while it runs it. */
		if (!strncmp(comm, "kworker/", 8) && (dash = strpbrk(comm + 8, "-+")) && dash[1] &&
		    strncmp(comm + 8, "R-", 2))
			add_word(queues, queues_size, dash + 1);
	}
	closedir(dir);
}

static void check_processes(void)
{
	char ours[512] = "", queues[1024] = "";
	int total = 0, kthreads = 0, i;
	struct timespec pause = { 0, 100000000 };

	/* Workers change names with every work item: watch for four seconds,
	 * long enough for the host's once-a-second polls. */
	for (i = 0; i < 40; i++) {
		scan_processes(ours, sizeof(ours), queues, sizeof(queues), &total, &kthreads);
		nanosleep(&pause, NULL);
	}
	report(*ours ? "fail" : "pass", "proc.comm-antinomie", *ours ? ours : "none");
	reportf("info", "proc.count", "%d processes, %d kernel threads", total, kthreads);
	printf("STEALTH-DETAIL worker queues seen: %s\n", queues);
	report(contains_ci(queues, "antinomie") ? "fail" : "pass", "proc.kworker-names",
	       contains_ci(queues, "antinomie") ? queues : "no antinomie queue in 4 s of worker names");
}

static void check_self(void)
{
	char comm[64], parent_comm[64] = "?", pid_text[24], ppid_text[24], tty_name[64] = "", value[256];
	long ppid, pgrp, session, tty, tpgid, pp, pg, se, tt, tp;
	pid_t pid = getpid();
	int leader_alive, ctty;
	ssize_t n;

	snprintf(pid_text, sizeof(pid_text), "%d", pid);
	if (stat_fields(pid_text, comm, sizeof(comm), &ppid, &pgrp, &session, &tty, &tpgid)) {
		report("fail", "self.stat", "unreadable");
		return;
	}
	snprintf(ppid_text, sizeof(ppid_text), "%ld", ppid);
	stat_fields(ppid_text, parent_comm, sizeof(parent_comm), &pp, &pg, &se, &tt, &tp);
	reportf(ppid == 2 || !strcmp(parent_comm, "kthreadd") || ppid == 0 ? "fail" : ppid == 1 ? "info" : "pass",
		"self.parent", "PPid %ld (%s)", ppid, parent_comm);
	n = readlink("/proc/self/fd/0", tty_name, sizeof(tty_name) - 1);
	tty_name[n > 0 ? n : 0] = 0;
	ctty = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (ctty >= 0)
		close(ctty);
	leader_alive = session != pid && session > 0 && kill((pid_t)session, 0) == 0;
	/* A program started from a shell: its own process group in the
	 * shell's session, foreground on the shell's terminal. sid == pid is a
	 * session leader (a login shell or a setsid daemon); a session whose
	 * leader is gone is an orphan of a closed terminal. */
	reportf(session == pid ? "fail" : leader_alive ? "pass" : "info", "self.session",
		"pid %d sid %ld pgid %ld tty_nr %ld tpgid %ld stdin %s, /dev/tty %s, session leader %s",
		pid, session, pgrp, tty, tpgid, tty_name, ctty >= 0 ? "opens" : "does not open",
		session == pid ? "is itself" : leader_alive ? "alive" : "gone");
	{
		extern char **environ;
		char keys[512] = "";
		char **env;

		for (env = environ; *env; env++) {
			size_t len = strcspn(*env, "=");

			if (strlen(keys) + len + 2 < sizeof(keys))
				snprintf(keys + strlen(keys), sizeof(keys) - strlen(keys), "%s%.*s",
					 *keys ? " " : "", (int)len, *env);
		}
		report(getenv("HOME") && getenv("PATH") ? "pass" : "info", "self.environment", keys);
	}
	if (read_all("/proc/self/status", value, sizeof(value)) >= 0) {
		static char status[4096];

		read_all("/proc/self/status", status, sizeof(status));
		{
			char *tracer = strstr(status, "TracerPid:");
			char *seccomp = strstr(status, "Seccomp:");
			long traced = tracer ? strtol(tracer + 10, NULL, 10) : -1;
			long filter = seccomp ? strtol(seccomp + 8, NULL, 10) : -1;

			reportf(traced || filter > 0 ? "fail" : "pass", "self.tracer",
				"TracerPid %ld Seccomp %ld", traced, filter);
		}
	}
	{
		char exe[256];

		n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
		exe[n > 0 ? n : 0] = 0;
		report("info", "self.path", exe);
	}
}

/* --- Recorder residency -------------------------------------------------- */

/* The recorder copies a call's memory without faulting, at entry and again at
 * exit (contract section 22). A page the call itself never reads must still
 * be out of the page tables afterwards: mincore() would show a sample any
 * page the recorder loaded.
 */
static void check_residency(void)
{
	long page = sysconf(_SC_PAGESIZE);
	unsigned char vec = 0xff;
	int null = open("/dev/null", O_WRONLY);
	void *buffer = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (null < 0 || buffer == MAP_FAILED) {
		report("info", "recorder.residency", "setup failed");
	} else if (write(null, buffer, page) != page || mincore(buffer, page, &vec)) {
		report("info", "recorder.residency", "write or mincore failed");
	} else {
		reportf(vec & 1 ? "fail" : "pass", "recorder.residency",
			"an untouched page given to write(/dev/null) is %s afterwards",
			vec & 1 ? "resident" : "not resident");
	}
	if (buffer != MAP_FAILED)
		munmap(buffer, page);
	if (null >= 0)
		close(null);
}

/* --- Base defaults ------------------------------------------------------- */

static int sandbox_name(const char *name)
{
	static const char *const names[] = { "localhost", "(none)", "sandbox", "antinomie", "analyst",
		"analysis", "malware", "virus", "sample", "cuckoo", "test", "vm", "qemu", "kvm",
		"user-pc", NULL };
	int i;

	for (i = 0; names[i]; i++)
		if (!strcasecmp(name, names[i]) || (strlen(names[i]) > 4 && contains_ci(name, names[i])))
			return 1;
	return 0;
}

static void check_base(void)
{
	static char text[1 << 16];
	char host[256] = "", file[256] = "", found[256] = "", label[17] = "";
	struct statvfs fs;
	char *line;
	double uptime = 0;
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned long long mem_kib = 0;
	FILE *meminfo;

	gethostname(host, sizeof(host));
	report(sandbox_name(host) ? "fail" : "pass", "base.hostname", host);
	if (!read_line("/etc/hostname", file, sizeof(file)))
		report(sandbox_name(file) ? "fail" : "pass", "base.etc-hostname", file);
	if (read_all("/etc/passwd", text, sizeof(text)) >= 0) {
		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
			char *colon = strchr(line, ':');
			char *uid_field;
			long uid;

			if (!colon)
				continue;
			*colon = 0;
			uid_field = strchr(colon + 1, ':');
			uid = uid_field ? strtol(uid_field + 1, NULL, 10) : -1;
			if ((uid == 0 || uid >= 1000) && uid != 65534 && strlen(found) + strlen(line) + 2 < sizeof(found))
				snprintf(found + strlen(found), sizeof(found) - strlen(found), "%s%s",
					 *found ? " " : "", line);
		}
		{
			int bad = 0;
			char copy[256], *word;

			snprintf(copy, sizeof(copy), "%s", found);
			for (word = strtok(copy, " "); word; word = strtok(NULL, " "))
				if (strcmp(word, "root") && sandbox_name(word))
					bad = 1;
			report(bad ? "fail" : "pass", "base.users", found);
		}
	}
	/* The root filesystem's ext4 label, from its superblock (root only). */
	if (read_all("/proc/mounts", text, sizeof(text)) >= 0) {
		char device[128] = "", type[32] = "";

		for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
			char dev[128], dir[128], fstype[32];

			if (sscanf(line, "%127s %127s %31s", dev, dir, fstype) == 3 && !strcmp(dir, "/") &&
			    strcmp(dev, "rootfs")) {
				snprintf(device, sizeof(device), "%s", dev);
				snprintf(type, sizeof(type), "%s", fstype);
			}
		}
		reportf(!strncmp(device, "/dev/vd", 7) ? "fail" : "pass", "base.root-device", "%s %s", device, type);
		if (*device) {
			int fd = open(device, O_RDONLY | O_CLOEXEC);

			if (fd < 0) {
				report("skip", "base.fs-label", strerror(errno));
			} else {
				if (pread(fd, label, 16, 1024 + 0x78) != 16)
					label[0] = 0;
				close(fd);
				label[16] = 0;
				report(sandbox_name(label) || antinomie_word(label) ? "fail" : "pass",
				       "base.fs-label", *label ? label : "(none)");
			}
		}
	}
	if (!read_line("/proc/uptime", text, 64))
		uptime = strtod(text, NULL);
	reportf(uptime < 600 ? "fail" : "pass", "base.uptime", "%.0f s", uptime);
	meminfo = fopen("/proc/meminfo", "r");
	if (meminfo) {
		if (fscanf(meminfo, "MemTotal: %llu", &mem_kib) != 1)
			mem_kib = 0;
		fclose(meminfo);
	}
	reportf(cpus < 2 ? "fail" : "pass", "base.cpus", "%ld", cpus);
	reportf(mem_kib < (2ull << 20) ? "fail" : "pass", "base.memory", "%llu MiB", mem_kib >> 10);
	if (!statvfs("/", &fs))
		reportf("info", "base.root-size", "%.1f GiB", (double)fs.f_blocks * fs.f_frsize / (1 << 30));
}

/* --- Firmware and CPU topology ----------------------------------------- */

static void check_firmware(void)
{
	struct stat st;
	ssize_t len;

	if (stat("/sys/firmware/efi", &st)) {
		/* A current PC boots UEFI; SeaBIOS boots leave no EFI tables. */
		report("fail", "firmware.type", "BIOS (no /sys/firmware/efi)");
		return;
	}
	report("pass", "firmware.type", "UEFI");
	/* The EFI system table's firmware vendor, as the kernel logs it at boot
	 * ("efi: EFI v2.7 by <vendor>"; the log is root's). */
	{
		static char log[1 << 20];
		int size = klogctl(3, log, sizeof(log) - 1);
		char *line, vendor[96] = "";

		if (size < 0) {
			report("skip", "firmware.vendor", strerror(errno));
		} else {
			log[size] = 0;
			line = strstr(log, "efi: EFI v");
			if (line && (line = strstr(line, " by ")))
				sscanf(line + 4, "%95[^\n]", vendor);
			report(!*vendor ? "info" : contains_ci(vendor, "EDK") || vm_word(vendor) ? "fail" : "pass",
			       "firmware.vendor", *vendor ? vendor : "not in the kernel log");
		}
	}
	/* Secure Boot's state, when efivarfs is mounted (any user reads it). */
	if (stat("/sys/firmware/efi/efivars", &st)) {
		report("info", "firmware.secure-boot", "no efivars");
	} else {
		char data[8];

		len = read_all("/sys/firmware/efi/efivars/"
			       "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", data, sizeof(data));
		if (len >= 5)
			reportf("info", "firmware.secure-boot", "%s", data[4] ? "on" : "off");
		else
			report("info", "firmware.secure-boot", "efivarfs not mounted");
	}
}

static void check_topology(void)
{
	char siblings[64] = "", cache[32] = "";

	if (!read_line("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", siblings,
		       sizeof(siblings)))
		reportf("info", "cpu.threads", "cpu0 siblings %s (%s)", siblings,
			strpbrk(siblings, ",-") ? "two threads per core" : "one thread per core");
	if (read_line("/sys/devices/system/cpu/cpu0/cache/index3/size", cache, sizeof(cache)))
		report("fail", "cpu.l3-cache", "none");
	else
		report("pass", "cpu.l3-cache", cache);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("STEALTH-BEGIN uid %d euid %d\n", getuid(), geteuid());
	(void)argc;
	(void)argv;
	check_self();
	check_residency();
	check_cpuid();
	check_topology();
	check_firmware();
	check_dmi();
	check_smbios_raw();
	check_acpi();
	check_fw_cfg();
	check_pci();
	check_virtio();
	check_block();
	check_net();
	check_net_addresses();
	check_devices_misc();
	check_kernel();
	check_kallsyms();
	check_modules();
	check_dmesg();
	check_btf();
	check_tracing();
	check_iomem();
	check_processes();
	check_base();
	check_timing();
	printf("STEALTH-END\n");
	return 0;
}
