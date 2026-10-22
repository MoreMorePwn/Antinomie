/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int commands[2][2], gate[2];
static pthread_barrier_t ready;

static void marker(const char *kind, long value)
{
	printf("OBS %s pid=%ld tid=%ld value=%ld\n", kind,
	       (long)getpid(), syscall(SYS_gettid), value);
	fflush(stdout);
	usleep(20000);
}

static int read_byte(int fd, char *byte)
{
	ssize_t count;

	do {
		count = read(fd, byte, 1);
	} while (count < 0 && errno == EINTR);
	return count == 1;
}

static void *worker(void *argument)
{
	long index = (long)argument;
	char name[16], byte;

	snprintf(name, sizeof(name), "obs-worker%ld", index);
	prctl(PR_SET_NAME, name);
	marker("THREAD", index);
	pthread_barrier_wait(&ready);
	while (read_byte(commands[index][0], &byte)) {
		if (byte == 'q')
			break;
		if (byte == 'b') {
			marker("BLOCK", gate[0]);
			if (!read_byte(gate[0], &byte))
				break;
			marker("TAIL", index);
		} else {
			marker("THREAD-PULSE", index);
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t threads[2];
	int existing_pipe[2], status;
	pid_t existing, child;
	char byte;
	long index;

	if (argc == 2) {
		prctl(PR_SET_NAME, "obs-future");
		marker("FUTURE", 0);
		return 0;
	}
	prctl(PR_SET_NAME, "obs-main");
	if (pipe(existing_pipe) || pipe(gate) || pipe(commands[0]) ||
	    pipe(commands[1]))
		return 2;
	existing = fork();
	if (existing < 0)
		return 2;
	if (!existing) {
		prctl(PR_SET_NAME, "obs-existing");
		while (read_byte(existing_pipe[0], &byte) && byte != 'q')
			marker("EXISTING", 0);
		_exit(0);
	}
	if (pthread_barrier_init(&ready, NULL, 3))
		return 2;
	for (index = 0; index < 2; index++)
		if (pthread_create(&threads[index], NULL, worker, (void *)index))
			return 2;
	pthread_barrier_wait(&ready);
	marker("READY", existing);
	while (read_byte(STDIN_FILENO, &byte)) {
		switch (byte) {
		case 't':
			if (write(commands[0][1], "t", 1) != 1 ||
			    write(commands[1][1], "t", 1) != 1)
				return 2;
			break;
		case 'b':
			if (write(commands[0][1], "b", 1) != 1)
				return 2;
			break;
		case 'u':
			if (write(gate[1], "u", 1) != 1)
				return 2;
			break;
		case 'e':
			if (write(existing_pipe[1], "e", 1) != 1)
				return 2;
			break;
		case 'f':
			child = fork();
			if (child < 0)
				return 2;
			if (!child) {
				execl(argv[0], argv[0], "--child", NULL);
				_exit(3);
			}
			if (waitpid(child, &status, 0) != child || status)
				return 2;
			break;
		case 'q':
			for (index = 0; index < 2; index++) {
				if (write(commands[index][1], "q", 1) != 1)
					return 2;
				pthread_join(threads[index], NULL);
			}
			if (write(existing_pipe[1], "q", 1) != 1)
				return 2;
			waitpid(existing, &status, 0);
			marker("DONE", 0);
			return 0;
		default:
			continue;
		}
		marker("ACK", byte);
	}
	return 0;
}
