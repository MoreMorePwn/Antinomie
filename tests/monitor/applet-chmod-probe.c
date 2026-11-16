// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// applet-chmod-probe.c — a benign program that does what Mirai's killer did
// to a BusyBox base (ANT-T0556 A26): chmod 0000 on /bin/reboot, /bin/halt,
// /bin/poweroff and /bin/netstat, then runs a shell (`sh -c true`, the way
// the sample ran its persistence), a shell that runs an applet inside itself
// (`sh -c 'cp ... && cat ...'`) and an applet directly (/bin/ls). On the r22
// BusyBox base the applets were links to /bin/busybox, so the chmod made
// BusyBox itself unrunnable and every later exec failed with EACCES.
// One line per check, then CHMOD PROBE PASS or CHMOD PROBE FAIL.
//
// Build: gcc -static -O2 -Wall -Wextra -o applet-chmod-probe applet-chmod-probe.c
//   (aarch64-linux-gnu-gcc for an arm64 base). Run as root in a disposable
//   guest only: it leaves those four tools unrunnable.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static int run(char *const argv[])
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		/* Their output is not the probe's. */
		if (freopen("/dev/null", "w", stdout) == NULL)
			_exit(125);
		execv(argv[0], argv);
		_exit(126 + (errno == ENOENT));
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static void check(const char *what, int code)
{
	printf("%s %s (exit %d)\n", code == 0 ? "ok  " : "FAIL", what, code);
	failures += code != 0;
}

int main(void)
{
	static const char *const tools[] = {"/bin/reboot", "/bin/halt", "/bin/poweroff",
					    "/bin/netstat"};
	char *const shell[] = {"/bin/sh", "-c", "true", NULL};
	char *const applets[] = {"/bin/sh", "-c",
				 "cp /etc/passwd /tmp/.probe && cat /tmp/.probe && rm /tmp/.probe",
				 NULL};
	char *const direct[] = {"/bin/ls", "/", NULL};
	struct stat busybox;

	setvbuf(stdout, NULL, _IOLBF, 0);
	for (unsigned i = 0; i < sizeof(tools) / sizeof(tools[0]); i++)
		printf("chmod 0000 %s: %s\n", tools[i],
		       chmod(tools[i], 0) == 0 ? "done" : strerror(errno));
	check("sh -c true", run(shell));
	check("sh runs cp and cat", run(applets));
	check("/bin/ls runs", run(direct));
	if (stat("/bin/busybox", &busybox) == 0)
		printf("/bin/busybox mode %04o\n", busybox.st_mode & 07777);
	puts(failures ? "CHMOD PROBE FAIL" : "CHMOD PROBE PASS");
	return failures != 0;
}
