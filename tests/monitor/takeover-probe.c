// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// takeover-probe.c — a benign program that does what Mirai's killer does to a
// device's telnet service (ANT-T0558): it finds the socket listening on TCP 23
// in /proc/net/tcp, finds the process holding that socket under /proc/*/fd,
// kills it (SIGKILL) and binds and listens on port 23 itself for a few
// seconds. On the BusyBox camera base the victim is BusyBox telnetd. Triage
// should report impact.service_takeover. Prints TAKEOVER PROBE PASS or FAIL.
//
// Build: gcc -static -O2 -Wall -Wextra -o takeover-probe takeover-probe.c
//   (aarch64-linux-gnu-gcc for an arm64 base). Run as root in a disposable
//   guest only: telnet stays down until the guest restarts.
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 23

static unsigned long listening_inode(void)
{
	char line[512];
	unsigned long inode = 0;
	FILE *table = fopen("/proc/net/tcp", "r");
	if (table == NULL)
		return 0;
	while (fgets(line, sizeof(line), table)) {
		unsigned local_port, state;
		unsigned long found;
		if (sscanf(line, " %*d: %*x:%x %*x:%*x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
			   &local_port, &state, &found) == 3 &&
		    local_port == PORT && state == 0x0a)
			inode = found;
	}
	fclose(table);
	return inode;
}

static int holder(unsigned long inode)
{
	char wanted[64], path[300], target[64];
	struct dirent *process;
	DIR *proc = opendir("/proc");
	snprintf(wanted, sizeof(wanted), "socket:[%lu]", inode);
	while (proc && (process = readdir(proc))) {
		int pid = atoi(process->d_name);
		if (pid <= 1 || pid == getpid())
			continue;
		snprintf(path, sizeof(path), "/proc/%d/fd", pid);
		DIR *fds = opendir(path);
		struct dirent *fd;
		while (fds && (fd = readdir(fds))) {
			snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, fd->d_name);
			ssize_t length = readlink(path, target, sizeof(target) - 1);
			if (length > 0) {
				target[length] = 0;
				if (strcmp(target, wanted) == 0) {
					closedir(fds);
					closedir(proc);
					return pid;
				}
			}
		}
		if (fds)
			closedir(fds);
	}
	if (proc)
		closedir(proc);
	return 0;
}

int main(void)
{
	unsigned long inode = listening_inode();
	int pid = inode ? holder(inode) : 0;
	printf("port %d socket inode %lu held by pid %d\n", PORT, inode, pid);
	if (pid <= 0 || kill(pid, SIGKILL) != 0) {
		printf("kill: %s\nTAKEOVER PROBE FAIL\n", pid > 0 ? strerror(errno) : "no holder");
		return 1;
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1, bound = -1;
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	/* The killed listener's socket closes as the process exits. */
	for (int attempt = 0; attempt < 50 && bound != 0; attempt++) {
		bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
		if (bound != 0)
			usleep(100000);
	}
	if (bound != 0 || listen(fd, 1) != 0) {
		printf("bind/listen: %s\nTAKEOVER PROBE FAIL\n", strerror(errno));
		return 1;
	}
	printf("killed pid %d and listening on %d\n", pid, PORT);
	sleep(3);
	close(fd);
	puts("TAKEOVER PROBE PASS");
	return 0;
}
