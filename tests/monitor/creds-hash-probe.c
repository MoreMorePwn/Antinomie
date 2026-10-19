/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest probe for the kernel tracer's credential and file-hash records.
 * Static, no libc features beyond POSIX. Run as root (uid 0) from a launched
 * run; it does the following and prints one marker line for each step.
 *
 *   - writes /tmp/ant-a (100000 bytes, byte i = (i*31+7)&0xff) and deletes it;
 *   - writes /tmp/ant-big (17 MiB, over the 16 MiB hash limit) and deletes it;
 *   - copies itself to /tmp/ant-child and /tmp/ant-suid (mode 4755) and execs
 *     the first, a small binary whose hash is the probe's own;
 *   - in a child: setfsuid, capset, setresgid, setresuid down to uid 1000,
 *     creates and deletes /tmp/ant-user as uid 1000, then execs the setuid
 *     copy, which runs with euid 0;
 *   - sets its login uid with /proc/self/loginuid;
 *   - after the copy is 40 ms old, execs /tmp/ant-child twice more (the second
 *     digest may be served from the guest's cache, flag CACHED);
 *   - writes 60 files of 256 KiB and deletes them back to back, so the guest's
 *     16-job queue overflows and the dropped requests are recorded;
 *   - removes its files and reports processes and directory entries that
 *     appeared in the guest while it ran (there must be none but its own).
 *
 * Build: cc -static -O2 -Wall -Wextra -Werror tests/monitor/creds-hash-probe.c
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_NAMES 4096
#define NAME_LEN 96

struct names {
	char item[MAX_NAMES][NAME_LEN];
	int count;
};

static void say(const char *text)
{
	dprintf(1, "%s\n", text);
}

static int write_file(const char *path, size_t size, int pattern, mode_t mode)
{
	unsigned char chunk[4096];
	size_t done = 0, i;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

	if (fd < 0)
		return -1;
	if (!pattern) {
		if (ftruncate(fd, size) < 0)
			return close(fd), -1;
		return close(fd);
	}
	while (done < size) {
		size_t n = size - done < sizeof(chunk) ? size - done : sizeof(chunk);

		for (i = 0; i < n; i++)
			chunk[i] = (unsigned char)(((done + i) * 31 + 7) & 0xff);
		if (write(fd, chunk, n) != (ssize_t)n)
			return close(fd), -1;
		done += n;
	}
	return close(fd);
}

static int copy_self(const char *dest, mode_t mode)
{
	char buffer[65536];
	ssize_t n;
	int in = open("/proc/self/exe", O_RDONLY);
	int out = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (in < 0 || out < 0)
		return -1;
	while ((n = read(in, buffer, sizeof(buffer))) > 0)
		if (write(out, buffer, n) != n)
			return -1;
	close(in);
	close(out);
	return chmod(dest, mode);
}

static void list_dir(const char *dir, const char *prefix, struct names *out)
{
	struct dirent *entry;
	DIR *handle = opendir(dir);

	if (!handle)
		return;
	while ((entry = readdir(handle)) && out->count < MAX_NAMES) {
		if (entry->d_name[0] == '.' && (!entry->d_name[1] || entry->d_name[1] == '.'))
			continue;
		snprintf(out->item[out->count++], NAME_LEN, "%.20s%.60s", prefix, entry->d_name);
	}
	closedir(handle);
}

static void list_processes(struct names *out)
{
	struct dirent *entry;
	DIR *handle = opendir("/proc");
	char path[64], comm[32];

	if (!handle)
		return;
	while ((entry = readdir(handle)) && out->count < MAX_NAMES) {
		FILE *file;

		if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
			continue;
		snprintf(path, sizeof(path), "/proc/%.20s/comm", entry->d_name);
		file = fopen(path, "r");
		if (!file)
			continue;
		if (!fgets(comm, sizeof(comm), file))
			comm[0] = 0;
		fclose(file);
		comm[strcspn(comm, "\n")] = 0;
		snprintf(out->item[out->count++], NAME_LEN, "%.20s:%.40s", entry->d_name, comm);
	}
	closedir(handle);
}

static void snapshot(struct names *processes, struct names *files)
{
	processes->count = files->count = 0;
	list_processes(processes);
	list_dir("/", "/", files);
	list_dir("/tmp", "/tmp/", files);
	list_dir("/dev", "/dev/", files);
	list_dir("/run", "/run/", files);
	list_dir("/var/tmp", "/var/tmp/", files);
}

static int has(const struct names *set, const char *name)
{
	int i;

	for (i = 0; i < set->count; i++)
		if (!strcmp(set->item[i], name))
			return 1;
	return 0;
}

static void report_new(const char *kind, const struct names *before, const struct names *after)
{
	char line[128];
	int i, found = 0;

	for (i = 0; i < after->count; i++)
		if (!has(before, after->item[i])) {
			snprintf(line, sizeof(line), "NEW %s %s", kind, after->item[i]);
			say(line);
			found++;
		}
	snprintf(line, sizeof(line), "NEW %s total %d", kind, found);
	say(line);
}

static void child_ids(void)
{
	uid_t r, e, s;
	gid_t gr, ge, gs;
	char line[128];

	getresuid(&r, &e, &s);
	getresgid(&gr, &ge, &gs);
	snprintf(line, sizeof(line), "CHILD ids pid %d uid %u/%u/%u gid %u/%u/%u", getpid(), r, e, s, gr, ge, gs);
	say(line);
}

static void drop_and_exec(void)
{
	struct { unsigned int version; int pid; } header = { 0x20080522, 0 };
	struct { unsigned int effective, permitted, inheritable; } data[2];
	char line[96];

	setfsuid(1000);
	/* Drop CAP_SYS_PTRACE (19) from the effective set only. */
	syscall(SYS_capget, &header, data);
	data[0].effective &= ~(1U << 19);
	header.version = 0x20080522;
	snprintf(line, sizeof(line), "CAPSET %ld", syscall(SYS_capset, &header, data));
	say(line);
	if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
		say("DROP failed");
	if (write_file("/tmp/ant-user", 4096, 1, 0644) == 0 && unlink("/tmp/ant-user") == 0)
		say("USER FILE deleted as 1000");
	execl("/tmp/ant-suid", "/tmp/ant-suid", "--child", (char *)NULL);
	say("EXEC suid failed");
	_exit(1);
}

int main(int argc, char **argv)
{
	struct names processes_before, processes_after, files_before, files_after;
	char line[128];
	pid_t pid;
	int status, fd, i;
	long long ctime_s = 0;
	long ctime_ns = 0;

	if (argc > 1 && !strcmp(argv[1], "--child")) {
		child_ids();
		return 0;
	}
	snapshot(&processes_before, &files_before);
	snprintf(line, sizeof(line), "PARENT pid %d uid %d", getpid(), getuid());
	say(line);

	fd = open("/proc/self/loginuid", O_WRONLY);
	snprintf(line, sizeof(line), "LOGINUID write %zd", fd < 0 ? (ssize_t)-1 : write(fd, "1000", 4));
	say(line);
	if (fd >= 0)
		close(fd);

	snprintf(line, sizeof(line), "DELETE a %d", write_file("/tmp/ant-a", 100000, 1, 0644) == 0 ? unlink("/tmp/ant-a") : -1);
	say(line);
	snprintf(line, sizeof(line), "DELETE big %d", write_file("/tmp/ant-big", 17u << 20, 0, 0644) == 0 ? unlink("/tmp/ant-big") : -1);
	say(line);

	if (copy_self("/tmp/ant-child", 0755) || copy_self("/tmp/ant-suid", 04755)) {
		say("COPY failed");
		return 1;
	}
	pid = fork();
	if (!pid) {
		execl("/tmp/ant-child", "/tmp/ant-child", "--child", (char *)NULL);
		_exit(1);
	}
	waitpid(pid, &status, 0);
	/* Watch the copy's change time while it ages: the tracer's own reads must
	 * never move it. */
	for (i = 0; i < 8; i++) {
		struct stat st;

		usleep(5000);
		if (!stat("/tmp/ant-child", &st) && (i == 0 || st.st_ctim.tv_nsec != ctime_ns || st.st_ctim.tv_sec != ctime_s)) {
			snprintf(line, sizeof(line), "WATCH ant-child ctime %lld.%09ld step %d", (long long)st.st_ctim.tv_sec, st.st_ctim.tv_nsec, i);
			say(line);
		}
		ctime_s = st.st_ctim.tv_sec;
		ctime_ns = st.st_ctim.tv_nsec;
	}
	for (i = 0; i < 2; i++) {
		pid = fork();
		if (!pid) {
			execl("/tmp/ant-child", "/tmp/ant-child", "--child", (char *)NULL);
			_exit(1);
		}
		waitpid(pid, &status, 0);
		{
			struct stat st;

			if (!stat("/tmp/ant-child", &st)) {
				snprintf(line, sizeof(line), "WATCH ant-child after exec %d ctime %lld.%09ld", i, (long long)st.st_ctim.tv_sec, st.st_ctim.tv_nsec);
				say(line);
			}
		}
	}
	pid = fork();
	if (!pid)
		drop_and_exec();
	waitpid(pid, &status, 0);
	snprintf(line, sizeof(line), "SUID child status %d", WEXITSTATUS(status));
	say(line);

	unlink("/tmp/ant-child");
	unlink("/tmp/ant-suid");
	for (i = 0; i < 60; i++) {
		snprintf(line, sizeof(line), "/tmp/ant-burst-%d", i);
		if (write_file(line, 256 * 1024, 1, 0644))
			say("BURST write failed");
	}
	for (i = 0; i < 60; i++) {
		snprintf(line, sizeof(line), "/tmp/ant-burst-%d", i);
		unlink(line);
	}
	say("BURST done");
	snapshot(&processes_after, &files_after);
	report_new("process", &processes_before, &processes_after);
	report_new("file", &files_before, &files_after);
	say("TEST DONE");
	return 0;
}
