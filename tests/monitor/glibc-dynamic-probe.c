// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// glibc-dynamic-probe.c — a benign program linked against glibc's shared
// libraries, for the BusyBox bases' glibc runtime (ANT-T0556 A51). It starts
// only when the base has the loader its PT_INTERP names, then uses each
// library the base ships: libm (cos), a thread (libpthread's symbols, in libc
// since 2.34), dlopen and dlsym (libdl's), clock_gettime (librt's), res_init
// (libresolv), the user database through name services (getpwuid), the C
// library's version, and dlopen of each stub library an older program names
// (libpthread.so.0 ... libnss_dns.so.2: a linker of glibc 2.34 or later no
// longer records them in DT_NEEDED). One line per check, then GLIBC PROBE PASS or
// GLIBC PROBE FAIL.
//
// Build (DT_NEEDED on every library, not only those the linker keeps):
//   gcc -O2 -Wall -Wextra -o glibc-dynamic-probe glibc-dynamic-probe.c
//       -Wl,--no-as-needed -lm -lpthread -ldl -lrt -lresolv   (one line)
//   aarch64-linux-gnu-gcc ... (the same flags) for an arm64 base.
// The program needs symbol versions no newer than the base's glibc (2.41):
// check with `readelf -V`.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <resolv.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	failures += !ok;
}

static void *worker(void *arg)
{
	*(int *)arg = 42;
	return NULL;
}

int main(int argc, char **argv)
{
	volatile double angle = argc - 1;
	int value = 0;
	pthread_t thread;
	struct timespec now;
	void *libm;

	(void)argv;
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("glibc %s\n", gnu_get_libc_version());
	check("libm cos(0) == 1", cos(angle) == 1.0);
	check("thread ran", pthread_create(&thread, NULL, worker, &value) == 0 &&
				    pthread_join(thread, NULL) == 0 && value == 42);
	libm = dlopen("libm.so.6", RTLD_NOW);
	check("dlopen libm.so.6", libm != NULL && dlsym(libm, "sin") != NULL);
	check("clock_gettime", clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	check("res_init", res_init() == 0);
	struct passwd *root = getpwuid(0);
	check("getpwuid(0) is root", root != NULL && root->pw_name[0] == 'r');
	static const char *const stubs[] = {"libpthread.so.0", "libdl.so.2",	 "librt.so.1",
					    "libutil.so.1",	"libanl.so.1",	 "libnss_files.so.2",
					    "libnss_dns.so.2"};
	for (unsigned i = 0; i < sizeof(stubs) / sizeof(stubs[0]); i++) {
		char what[64];
		snprintf(what, sizeof(what), "dlopen %s", stubs[i]);
		check(what, dlopen(stubs[i], RTLD_NOW) != NULL);
	}
	puts(failures ? "GLIBC PROBE FAIL" : "GLIBC PROBE PASS");
	return failures != 0;
}
