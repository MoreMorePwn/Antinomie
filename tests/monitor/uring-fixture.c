/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
/*
 * Guest fixture for the io_uring run-status qualification
 * (examples/uring-check.rs). Static, raw io_uring system calls, no liburing.
 * One mode per run. Every mode prints "URING READY" once its ring works and
 * "URING DONE" just before it ends on its own.
 *
 *   pairs [ROUNDS]   linked write/read pairs forced onto io-wq workers (so the
 *                    ring has iou-wrk threads), then exit 3
 *   cancel           an endless pipe read on a worker, then its cancellation
 *                    through the ring, then exit 4
 *   drain            requests that can never finish are left pending on
 *                    worker threads and the process exits 5 with them
 *   sqpoll           a ring with a kernel submission thread, writes through it,
 *                    then exit 6 with the thread alive
 *   threads          the leader starts a thread that owns the ring and leaves
 *                    with pthread_exit; the thread exits the whole process 9
 *                    from a non-leader thread after its workers finished
 *   crash            workers exist, then SIGSEGV
 *   hold             pending requests on workers, then sleeps (Stop target)
 *   hold-ignore      as hold, ignoring SIGTERM (Stop must escalate to SIGKILL)
 *   files            io_uring file operations for the Triage file index: openat,
 *                    write, read, fsync, ftruncate, renameat, unlinkat, close, a
 *                    rename and a hard link of one file, then exit 0
 *   syncfiles        the same story with plain system calls: create, rename,
 *                    hard-link, write through the other name, unlink one name,
 *                    then a new file under the first name; exit 0
 *   aio              a file written and read through io_submit, exit 0
 *   script FILE      writes an executable "#!/bin/sh" script to FILE and runs it
 *
 * Build: cc -static -O2 -pthread -Wall -Wextra -Werror tests/monitor/uring-fixture.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/io_uring.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct ring {
	int fd;
	unsigned entries;
	unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
	unsigned *cq_head, *cq_tail, *cq_mask;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	unsigned *sq_flags;
	unsigned pending;
};

static void say(const char *text)
{
	if (write(STDOUT_FILENO, text, strlen(text)) < 0)
		_exit(98);
}

static void nap(long milliseconds)
{
	struct timespec pause = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };

	nanosleep(&pause, NULL);
}

static int ring_open(struct ring *ring, unsigned entries, unsigned flags)
{
	struct io_uring_params params;
	size_t sq_size, cq_size;
	unsigned char *sq, *cq;

	memset(&params, 0, sizeof(params));
	params.flags = flags;
	ring->fd = (int)syscall(__NR_io_uring_setup, entries, &params);
	if (ring->fd < 0)
		return -1;
	ring->entries = params.sq_entries;
	sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
	cq_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
	if (cq_size > sq_size)
		sq_size = cq_size;
	sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd,
		  IORING_OFF_SQ_RING);
	if (sq == MAP_FAILED)
		return -1;
	cq = sq;
	ring->sqes = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe),
			  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring->fd,
			  IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED)
		return -1;
	ring->sq_head = (unsigned *)(sq + params.sq_off.head);
	ring->sq_tail = (unsigned *)(sq + params.sq_off.tail);
	ring->sq_mask = (unsigned *)(sq + params.sq_off.ring_mask);
	ring->sq_array = (unsigned *)(sq + params.sq_off.array);
	ring->sq_flags = (unsigned *)(sq + params.sq_off.flags);
	ring->cq_head = (unsigned *)(cq + params.cq_off.head);
	ring->cq_tail = (unsigned *)(cq + params.cq_off.tail);
	ring->cq_mask = (unsigned *)(cq + params.cq_off.ring_mask);
	ring->cqes = (struct io_uring_cqe *)(cq + params.cq_off.cqes);
	ring->pending = 0;
	return 0;
}

static struct io_uring_sqe *ring_next(struct ring *ring)
{
	unsigned tail = *ring->sq_tail;
	unsigned index = tail & *ring->sq_mask;
	struct io_uring_sqe *sqe;

	if (tail - __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE) >= ring->entries)
		return NULL;
	sqe = &ring->sqes[index];
	memset(sqe, 0, sizeof(*sqe));
	ring->sq_array[index] = index;
	__atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);
	ring->pending++;
	return sqe;
}

/* Submit what was queued and wait for `wait` completions; returns how many
 * completions were reaped.
 */
static long ring_submit(struct ring *ring, unsigned wait, int *errors)
{
	unsigned submit = ring->pending, head;
	long reaped = 0;

	ring->pending = 0;
	if (syscall(__NR_io_uring_enter, ring->fd, submit, wait, wait ? IORING_ENTER_GETEVENTS : 0,
		    NULL, 0) < 0)
		return -1;
	head = *ring->cq_head;
	while (head != __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE)) {
		if (ring->cqes[head & *ring->cq_mask].res < 0 && errors)
			(*errors)++;
		head++;
		reaped++;
	}
	__atomic_store_n(ring->cq_head, head, __ATOMIC_RELEASE);
	return reaped;
}

static void queue_rw(struct ring *ring, unsigned char opcode, int fd, void *buffer, unsigned length,
		     unsigned long long offset, unsigned char flags, unsigned long long tag)
{
	struct io_uring_sqe *sqe = ring_next(ring);

	if (!sqe)
		return;
	sqe->opcode = opcode;
	sqe->fd = fd;
	sqe->addr = (unsigned long)buffer;
	sqe->len = length;
	sqe->off = offset;
	sqe->flags = flags;
	sqe->user_data = tag;
}

static char block[4096];

static int scratch_file(void)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), "/tmp/uring-fixture.%d", (int)getpid());
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd >= 0)
		unlink(path);
	memset(block, 'Q', sizeof(block));
	return fd;
}

/* Linked write/read pairs, each forced onto an io-wq worker. */
static int work_pairs(struct ring *ring, int fd, int rounds)
{
	int errors = 0, round;

	for (round = 0; round < rounds; round++) {
		unsigned queued = 0, i;

		for (i = 0; i + 1 < ring->entries && i < 8; i += 2) {
			unsigned long long offset = (unsigned long long)((round * 8 + i) % 64) * 4096;

			queue_rw(ring, IORING_OP_WRITE, fd, block, sizeof(block), offset,
				 IOSQE_ASYNC | IOSQE_IO_LINK, 1);
			queue_rw(ring, IORING_OP_READ, fd, block, sizeof(block), offset,
				 IOSQE_ASYNC, 2);
			queued += 2;
		}
		if (ring_submit(ring, queued, &errors) < 0)
			return -1;
	}
	return errors;
}

static int open_ring(struct ring *ring, unsigned flags)
{
	if (ring_open(ring, 32, flags) < 0) {
		say("URING UNAVAILABLE\n");
		return -1;
	}
	return 0;
}

static int mode_pairs(int rounds)
{
	struct ring ring;
	int fd = scratch_file();

	if (open_ring(&ring, 0) < 0 || fd < 0)
		return 2;
	say("URING READY\n");
	if (work_pairs(&ring, fd, rounds) < 0)
		return 2;
	say("URING DONE\n");
	return 3;
}

static int pipe_read(struct ring *ring, int *pipefd, unsigned long long tag)
{
	static char sink[16];

	if (pipe(pipefd) < 0)
		return -1;
	queue_rw(ring, IORING_OP_READ, pipefd[0], sink, sizeof(sink), 0, IOSQE_ASYNC, tag);
	return 0;
}

static int mode_cancel(void)
{
	struct ring ring;
	struct io_uring_sqe *cancel;
	int pipefd[2];

	if (open_ring(&ring, 0) < 0 || pipe_read(&ring, pipefd, 0xdead) < 0)
		return 2;
	say("URING READY\n");
	if (ring_submit(&ring, 0, NULL) < 0)
		return 2;
	nap(200);
	cancel = ring_next(&ring);
	if (!cancel)
		return 2;
	cancel->opcode = IORING_OP_ASYNC_CANCEL;
	cancel->addr = 0xdead;
	cancel->user_data = 3;
	if (ring_submit(&ring, 2, NULL) < 0)
		return 2;
	say("URING DONE\n");
	return 4;
}

/* Requests that never finish, on worker threads. */
static int pending_reads(struct ring *ring, int count)
{
	int pipes[8][2], i;

	for (i = 0; i < count && i < 8; i++)
		if (pipe_read(ring, pipes[i], 100 + i) < 0)
			return -1;
	return ring_submit(ring, 0, NULL) < 0 ? -1 : 0;
}

static int mode_drain(void)
{
	struct ring ring;

	if (open_ring(&ring, 0) < 0 || pending_reads(&ring, 4) < 0)
		return 2;
	nap(200);
	say("URING READY\n");
	say("URING DONE\n");
	return 5;
}

static int mode_sqpoll(void)
{
	struct ring ring;
	int fd = scratch_file(), tries;

	if (fd < 0 || ring_open(&ring, 32, IORING_SETUP_SQPOLL) < 0) {
		say("URING UNAVAILABLE\n");
		return 2;
	}
	say("URING READY\n");
	queue_rw(&ring, IORING_OP_WRITE, fd, block, sizeof(block), 0, 0, 1);
	queue_rw(&ring, IORING_OP_WRITE, fd, block, sizeof(block), 4096, IOSQE_ASYNC, 2);
	ring.pending = 0;
	for (tries = 0; tries < 200; tries++) {
		if (__atomic_load_n(ring.sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP)
			syscall(__NR_io_uring_enter, ring.fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
		if (*ring.cq_head != __atomic_load_n(ring.cq_tail, __ATOMIC_ACQUIRE))
			break;
		nap(10);
	}
	say("URING DONE\n");
	return 6;
}

static void *ring_thread(void *unused)
{
	struct ring ring;
	int fd = scratch_file();

	(void)unused;
	if (open_ring(&ring, 0) < 0 || fd < 0 || work_pairs(&ring, fd, 4) < 0 ||
	    pending_reads(&ring, 2) < 0)
		_exit(2);
	say("URING READY\n");
	nap(300);
	say("URING DONE\n");
	/* The whole process ends from a thread that is not the leader. */
	exit(9);
	return NULL;
}

static int mode_threads(void)
{
	pthread_t thread;

	if (pthread_create(&thread, NULL, ring_thread, NULL))
		return 2;
	/* The leader leaves alone: the process lives on in the thread. */
	pthread_exit(NULL);
	return 0;
}

static int mode_crash(void)
{
	struct ring ring;
	int fd = scratch_file();
	volatile int *nothing = NULL;

	if (open_ring(&ring, 0) < 0 || fd < 0 || work_pairs(&ring, fd, 2) < 0 ||
	    pending_reads(&ring, 2) < 0)
		return 2;
	say("URING READY\n");
	nap(200);
	*nothing = 1;
	return 0;
}

static void ignore_term(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;
	sigaction(SIGTERM, &action, NULL);
}

static int mode_hold(int ignore)
{
	struct ring ring;
	int fd = scratch_file();

	if (ignore)
		ignore_term();
	if (open_ring(&ring, 0) < 0 || fd < 0 || work_pairs(&ring, fd, 2) < 0 ||
	    pending_reads(&ring, 3) < 0)
		return 2;
	say("URING READY\n");
	for (;;)
		nap(1000);
}

/* A file name the Triage file index can follow, written by native io_uring
 * requests: every request names its path or descriptor.
 */
static int mode_files(void)
{
	static const char first[] = "/tmp/uring-files.a";
	static const char moved[] = "/tmp/uring-files.b";
	static const char linked[] = "/tmp/uring-files.c";
	static char data[] = "uring file contents\n";
	static char back[64];
	struct open_how how;
	struct ring ring;
	int fd, errors = 0;

	unlink(first);
	unlink(moved);
	unlink(linked);
	if (open_ring(&ring, 0) < 0)
		return 2;
	say("URING READY\n");
	memset(&how, 0, sizeof(how));
	how.flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC;
	how.mode = 0600;
	{
		struct io_uring_sqe *sqe = ring_next(&ring);

		sqe->opcode = IORING_OP_OPENAT2;
		sqe->fd = AT_FDCWD;
		sqe->addr = (unsigned long)first;
		sqe->len = sizeof(how);
		sqe->off = (unsigned long)&how;
		sqe->user_data = 10;
	}
	{
		unsigned head = *ring.cq_head;

		if (ring_submit(&ring, 1, &errors) < 1)
			return 2;
		fd = ring.cqes[head & *ring.cq_mask].res;
	}
	if (fd < 0)
		return 2;
	queue_rw(&ring, IORING_OP_WRITE, fd, data, sizeof(data) - 1, 0, 0, 11);
	queue_rw(&ring, IORING_OP_READ, fd, back, sizeof(data) - 1, 0, 0, 12);
	if (ring_submit(&ring, 2, &errors) < 2)
		return 2;
	{
		struct io_uring_sqe *sqe = ring_next(&ring);

		sqe->opcode = IORING_OP_FSYNC;
		sqe->fd = fd;
		sqe->user_data = 13;
		sqe = ring_next(&ring);
		sqe->opcode = IORING_OP_FTRUNCATE;
		sqe->fd = fd;
		sqe->off = 8;
		sqe->user_data = 14;
	}
	if (ring_submit(&ring, 2, &errors) < 2)
		return 2;
	{
		struct io_uring_sqe *sqe = ring_next(&ring);

		sqe->opcode = IORING_OP_RENAMEAT;
		sqe->fd = AT_FDCWD;
		sqe->addr = (unsigned long)first;
		sqe->len = AT_FDCWD;
		sqe->addr2 = (unsigned long)moved;
		sqe->user_data = 15;
	}
	if (ring_submit(&ring, 1, &errors) < 1)
		return 2;
	{
		struct io_uring_sqe *sqe = ring_next(&ring);

		sqe->opcode = IORING_OP_LINKAT;
		sqe->fd = AT_FDCWD;
		sqe->addr = (unsigned long)moved;
		sqe->len = AT_FDCWD;
		sqe->addr2 = (unsigned long)linked;
		sqe->user_data = 16;
	}
	if (ring_submit(&ring, 1, &errors) < 1)
		return 2;
	queue_rw(&ring, IORING_OP_WRITE, fd, data, 4, 0, 0, 17);
	if (ring_submit(&ring, 1, &errors) < 1)
		return 2;
	{
		struct io_uring_sqe *sqe = ring_next(&ring);

		sqe->opcode = IORING_OP_CLOSE;
		sqe->fd = fd;
		sqe->user_data = 18;
		sqe = ring_next(&ring);
		sqe->opcode = IORING_OP_UNLINKAT;
		sqe->fd = AT_FDCWD;
		sqe->addr = (unsigned long)moved;
		sqe->user_data = 19;
		sqe = ring_next(&ring);
		sqe->opcode = IORING_OP_UNLINKAT;
		sqe->fd = AT_FDCWD;
		sqe->addr = (unsigned long)linked;
		sqe->user_data = 20;
	}
	if (ring_submit(&ring, 3, &errors) < 0)
		return 2;
	say(errors ? "URING DONE (errors)\n" : "URING DONE\n");
	return errors ? 1 : 0;
}

static int mode_syncfiles(void)
{
	static const char first[] = "/tmp/sync-files.a";
	static const char moved[] = "/tmp/sync-files.b";
	static const char linked[] = "/tmp/sync-files.c";
	int fd, other;

	unlink(first);
	unlink(moved);
	unlink(linked);
	say("URING READY\n");
	fd = open(first, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "first file\n", 11) != 11)
		return 2;
	if (rename(first, moved) || link(moved, linked))
		return 2;
	other = open(linked, O_RDWR | O_CLOEXEC);
	if (other < 0 || write(other, "+more\n", 6) != 6)
		return 2;
	close(other);
	if (unlink(moved))
		return 2;
	if (write(fd, "x", 1) != 1)
		return 2;
	close(fd);
	/* The first name now means a different file. */
	fd = open(first, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "second\n", 7) != 7)
		return 2;
	close(fd);
	unlink(first);
	unlink(linked);
	say("URING DONE\n");
	return 0;
}

static int mode_aio(void)
{
	static const char path[] = "/tmp/uring-aio.dat";
	static char data[4096];
	aio_context_t context = 0;
	struct iocb write_cb, read_cb, *list[1];
	struct io_event events[2];
	int fd;

	memset(data, 'A', sizeof(data));
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || syscall(__NR_io_setup, 4, &context) < 0)
		return 2;
	say("URING READY\n");
	memset(&write_cb, 0, sizeof(write_cb));
	write_cb.aio_lio_opcode = IOCB_CMD_PWRITE;
	write_cb.aio_fildes = fd;
	write_cb.aio_buf = (unsigned long)data;
	write_cb.aio_nbytes = sizeof(data);
	list[0] = &write_cb;
	if (syscall(__NR_io_submit, context, 1, list) != 1 ||
	    syscall(__NR_io_getevents, context, 1, 1, events, NULL) != 1)
		return 2;
	memset(&read_cb, 0, sizeof(read_cb));
	read_cb.aio_lio_opcode = IOCB_CMD_PREAD;
	read_cb.aio_fildes = fd;
	read_cb.aio_buf = (unsigned long)data;
	read_cb.aio_nbytes = sizeof(data);
	list[0] = &read_cb;
	if (syscall(__NR_io_submit, context, 1, list) != 1 ||
	    syscall(__NR_io_getevents, context, 1, 1, events, NULL) != 1)
		return 2;
	syscall(__NR_io_destroy, context);
	close(fd);
	unlink(path);
	say("URING DONE\n");
	return 0;
}

static int mode_script(const char *path)
{
	static const char body[] = "#!/bin/sh\necho SCRIPT RAN\nexit 0\n";
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	char *const argv[] = { (char *)path, NULL };

	if (fd < 0 || write(fd, body, sizeof(body) - 1) != (ssize_t)(sizeof(body) - 1))
		return 2;
	close(fd);
	say("URING READY\n");
	execv(path, argv);
	return 2;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!strcmp(mode, "pairs"))
		return mode_pairs(argc > 2 ? atoi(argv[2]) : 8);
	if (!strcmp(mode, "cancel"))
		return mode_cancel();
	if (!strcmp(mode, "drain"))
		return mode_drain();
	if (!strcmp(mode, "sqpoll"))
		return mode_sqpoll();
	if (!strcmp(mode, "threads"))
		return mode_threads();
	if (!strcmp(mode, "crash"))
		return mode_crash();
	if (!strcmp(mode, "hold"))
		return mode_hold(0);
	if (!strcmp(mode, "hold-ignore"))
		return mode_hold(1);
	if (!strcmp(mode, "files"))
		return mode_files();
	if (!strcmp(mode, "aio"))
		return mode_aio();
	if (!strcmp(mode, "syncfiles"))
		return mode_syncfiles();
	if (!strcmp(mode, "script") && argc > 2)
		return mode_script(argv[2]);
	say("usage: uring-fixture pairs|cancel|drain|sqpoll|threads|crash|hold|hold-ignore|files|syncfiles|aio|script FILE\n");
	return 64;
}
