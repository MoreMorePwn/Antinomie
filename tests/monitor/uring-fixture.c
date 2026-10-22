/* SPDX-License-Identifier: GPL-3.0-only */
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
 *   regfiles         io_uring OPENAT, WRITEV and READV, WRITE_FIXED and READ_FIXED
 *                    on a registered buffer, a WRITE through a registered file,
 *                    an OPENAT straight into the registered table (a slot, not
 *                    a descriptor) written through that slot, CLOSE and
 *                    UNLINKAT; exit 0
 *   syncfiles        the same story with plain system calls: create, rename,
 *                    hard-link, write through the other name, unlink one name,
 *                    then a new file under the first name; exit 0
 *   aio              a file written and read through io_submit (PWRITE, PREAD,
 *                    PWRITEV, PREADV), exit 0
 *   sqfiles          file work through an SQPOLL ring, whose kernel thread
 *                    submits it: WRITE and FSYNC of a file opened with open,
 *                    UNLINKAT of another; exit 0
 *   morefiles        io_uring FSYNC (data only), SYNC_FILE_RANGE, FSETXATTR,
 *                    SETXATTR, GETXATTR, SPLICE from a pipe into a file and
 *                    from the file into a pipe, UNLINKAT of a directory
 *                    (AT_REMOVEDIR), and rmdir of another; exit 0
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
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
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
	/* Linked: the read runs after the write, not beside it on a worker. */
	queue_rw(&ring, IORING_OP_WRITE, fd, data, sizeof(data) - 1, 0, IOSQE_IO_LINK, 11);
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

/* Submit one queued request, wait for it and return its result. */
static int ring_one(struct ring *ring, int *errors)
{
	unsigned head = *ring->cq_head;

	if (ring_submit(ring, 1, errors) < 1)
		return -1000;
	return ring->cqes[head & *ring->cq_mask].res;
}

static int mode_regfiles(void)
{
	static const char first[] = "/tmp/uring-reg.a";
	static const char direct[] = "/tmp/uring-reg.d";
	static char one[] = "vector one\n", two[] = "vector two\n", back[64];
	static char fixed[4096];
	static const char slot_text[] = "slot write\n", direct_text[] = "direct\n";
	struct iovec parts[2] = { { one, sizeof(one) - 1 }, { two, sizeof(two) - 1 } };
	struct iovec readback[1] = { { back, sizeof(back) } };
	struct iovec registered[1] = { { fixed, sizeof(fixed) } };
	struct io_uring_sqe *sqe;
	struct ring ring;
	int fd, table[2], errors = 0;

	unlink(first);
	unlink(direct);
	if (open_ring(&ring, 0) < 0)
		return 2;
	say("URING READY\n");
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)first;
	sqe->open_flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC;
	sqe->len = 0600;
	fd = ring_one(&ring, &errors);
	if (fd < 0)
		return 2;
	queue_rw(&ring, IORING_OP_WRITEV, fd, parts, 2, 0, 0, 21);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	queue_rw(&ring, IORING_OP_READV, fd, readback, 1, 0, 0, 22);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	/* A registered buffer: WRITE_FIXED and READ_FIXED use buffer 0. */
	memset(fixed, 'F', sizeof(fixed));
	memcpy(fixed, "fixed buffer data", 17);
	if (syscall(__NR_io_uring_register, ring.fd, IORING_REGISTER_BUFFERS, registered, 1) < 0)
		return 2;
	queue_rw(&ring, IORING_OP_WRITE_FIXED, fd, fixed, 17, 64, 0, 23);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	queue_rw(&ring, IORING_OP_READ_FIXED, fd, fixed + 1024, 17, 64, 0, 24);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	/* A registered file table: slot 0 is fd, slot 1 is free. */
	table[0] = fd;
	table[1] = -1;
	if (syscall(__NR_io_uring_register, ring.fd, IORING_REGISTER_FILES, table, 2) < 0)
		return 2;
	queue_rw(&ring, IORING_OP_WRITE, 0, (void *)slot_text, sizeof(slot_text) - 1, 128,
		 IOSQE_FIXED_FILE, 25);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	/* An open straight into slot 1: the result is 0, not a descriptor. */
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)direct;
	sqe->open_flags = O_RDWR | O_CREAT | O_TRUNC;
	sqe->len = 0600;
	sqe->file_index = 2;
	sqe->user_data = 26;
	if (ring_one(&ring, &errors) != 0)
		return 2;
	queue_rw(&ring, IORING_OP_WRITE, 1, (void *)direct_text, sizeof(direct_text) - 1, 0,
		 IOSQE_FIXED_FILE, 27);
	if (ring_one(&ring, &errors) < 0)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_CLOSE;
	sqe->file_index = 2;
	sqe->user_data = 28;
	if (ring_one(&ring, &errors) < 0)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_CLOSE;
	sqe->fd = fd;
	sqe->user_data = 29;
	if (ring_one(&ring, &errors) < 0)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_UNLINKAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)first;
	sqe->user_data = 30;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_UNLINKAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)direct;
	sqe->user_data = 31;
	if (ring_submit(&ring, 2, &errors) < 0)
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
	{
		static char first_half[] = "aio vector one\n", second_half[] = "aio vector two\n";
		static char back[64];
		struct iovec parts[2] = { { first_half, sizeof(first_half) - 1 },
					  { second_half, sizeof(second_half) - 1 } };
		struct iovec readback[1] = { { back, sizeof(back) } };

		memset(&write_cb, 0, sizeof(write_cb));
		write_cb.aio_lio_opcode = IOCB_CMD_PWRITEV;
		write_cb.aio_fildes = fd;
		write_cb.aio_buf = (unsigned long)parts;
		write_cb.aio_nbytes = 2;
		write_cb.aio_offset = sizeof(data);
		list[0] = &write_cb;
		if (syscall(__NR_io_submit, context, 1, list) != 1 ||
		    syscall(__NR_io_getevents, context, 1, 1, events, NULL) != 1)
			return 2;
		memset(&read_cb, 0, sizeof(read_cb));
		read_cb.aio_lio_opcode = IOCB_CMD_PREADV;
		read_cb.aio_fildes = fd;
		read_cb.aio_buf = (unsigned long)readback;
		read_cb.aio_nbytes = 1;
		read_cb.aio_offset = sizeof(data);
		list[0] = &read_cb;
		if (syscall(__NR_io_submit, context, 1, list) != 1 ||
		    syscall(__NR_io_getevents, context, 1, 1, events, NULL) != 1)
			return 2;
	}
	syscall(__NR_io_destroy, context);
	close(fd);
	unlink(path);
	say("URING DONE\n");
	return 0;
}

/* Fill an entry, then publish it: the SQPOLL thread may take it at once. */
static void sq_queue(struct ring *ring, const struct io_uring_sqe *entry)
{
	unsigned tail = *ring->sq_tail, index = tail & *ring->sq_mask;

	ring->sqes[index] = *entry;
	ring->sq_array[index] = index;
	__atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);
}

/* Wait for `count` completions of an SQPOLL ring, waking its thread when it
 * sleeps; returns how many failed, or -1 when they did not all come.
 */
static int sq_wait(struct ring *ring, unsigned count)
{
	unsigned head = *ring->cq_head;
	int tries, errors = 0;

	for (tries = 0; tries < 500 && count; tries++) {
		if (__atomic_load_n(ring->sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP)
			syscall(__NR_io_uring_enter, ring->fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
		while (count && head != __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE)) {
			if (ring->cqes[head & *ring->cq_mask].res < 0)
				errors++;
			head++;
			count--;
		}
		if (count)
			nap(10);
	}
	__atomic_store_n(ring->cq_head, head, __ATOMIC_RELEASE);
	return count ? -1 : errors;
}

static int mode_sqfiles(void)
{
	static const char first[] = "/tmp/uring-sq.a";
	static const char other[] = "/tmp/uring-sq.b";
	static char data[] = "written by the ring thread\n";
	struct io_uring_sqe entry;
	struct ring ring;
	int fd, spare, errors;

	unlink(first);
	unlink(other);
	fd = open(first, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	spare = open(other, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || spare < 0)
		return 2;
	close(spare);
	if (ring_open(&ring, 32, IORING_SETUP_SQPOLL) < 0) {
		say("URING UNAVAILABLE\n");
		return 2;
	}
	say("URING READY\n");
	memset(&entry, 0, sizeof(entry));
	entry.opcode = IORING_OP_WRITE;
	entry.fd = fd;
	entry.addr = (unsigned long)data;
	entry.len = sizeof(data) - 1;
	entry.flags = IOSQE_IO_LINK;
	entry.user_data = 1;
	sq_queue(&ring, &entry);
	memset(&entry, 0, sizeof(entry));
	entry.opcode = IORING_OP_FSYNC;
	entry.fd = fd;
	entry.user_data = 2;
	sq_queue(&ring, &entry);
	errors = sq_wait(&ring, 2);
	if (errors < 0)
		return 2;
	memset(&entry, 0, sizeof(entry));
	entry.opcode = IORING_OP_UNLINKAT;
	entry.fd = AT_FDCWD;
	entry.addr = (unsigned long)other;
	entry.user_data = 3;
	sq_queue(&ring, &entry);
	if (sq_wait(&ring, 1) != 0)
		errors++;
	close(fd);
	unlink(first);
	say(errors ? "URING DONE (errors)\n" : "URING DONE\n");
	return errors ? 1 : 0;
}

static int mode_morefiles(void)
{
	static const char path[] = "/tmp/uring-more.a";
	static const char directory[] = "/tmp/uring-more.d";
	static const char plain_directory[] = "/tmp/uring-more.e";
	static char data[] = "spliced bytes\n";
	static char value[16];
	struct io_uring_sqe *sqe;
	struct ring ring;
	int fd, pipes[2], errors = 0;

	unlink(path);
	rmdir(directory);
	rmdir(plain_directory);
	if (open_ring(&ring, 0) < 0)
		return 2;
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "first\n", 6) != 6 || pipe(pipes) ||
	    mkdir(directory, 0700) || mkdir(plain_directory, 0700))
		return 2;
	say("URING READY\n");
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_FSYNC;
	sqe->fd = fd;
	sqe->fsync_flags = IORING_FSYNC_DATASYNC;
	sqe->user_data = 1;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_SYNC_FILE_RANGE;
	sqe->fd = fd;
	sqe->len = 6;
	sqe->sync_range_flags = 2; /* SYNC_FILE_RANGE_WRITE */
	sqe->user_data = 2;
	if (ring_submit(&ring, 2, &errors) < 2)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_FSETXATTR;
	sqe->fd = fd;
	sqe->addr = (unsigned long)"user.tag";
	sqe->addr2 = (unsigned long)"red";
	sqe->len = 3;
	sqe->user_data = 3;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_SETXATTR;
	sqe->addr = (unsigned long)"user.colour";
	sqe->addr2 = (unsigned long)"blue";
	sqe->addr3 = (unsigned long)path;
	sqe->len = 4;
	sqe->user_data = 4;
	if (ring_submit(&ring, 2, &errors) < 2)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_GETXATTR;
	sqe->addr = (unsigned long)"user.tag";
	sqe->addr2 = (unsigned long)value;
	sqe->addr3 = (unsigned long)path;
	sqe->len = sizeof(value);
	sqe->user_data = 5;
	if (ring_submit(&ring, 1, &errors) < 1)
		return 2;
	/* A pipe into the file at offset 6, then the file into the pipe. */
	if (write(pipes[1], data, sizeof(data) - 1) != (ssize_t)(sizeof(data) - 1))
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_SPLICE;
	sqe->fd = fd;
	sqe->off = 6;
	sqe->splice_off_in = (unsigned long long)-1;
	sqe->splice_fd_in = pipes[0];
	sqe->len = sizeof(data) - 1;
	sqe->user_data = 6;
	if (ring_submit(&ring, 1, &errors) < 1)
		return 2;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_SPLICE;
	sqe->fd = pipes[1];
	sqe->off = (unsigned long long)-1;
	sqe->splice_off_in = 0;
	sqe->splice_fd_in = fd;
	sqe->len = 6;
	sqe->user_data = 7;
	sqe = ring_next(&ring);
	sqe->opcode = IORING_OP_UNLINKAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)directory;
	sqe->unlink_flags = AT_REMOVEDIR;
	sqe->user_data = 8;
	if (ring_submit(&ring, 2, &errors) < 2)
		return 2;
	if (rmdir(plain_directory))
		errors++;
	close(fd);
	unlink(path);
	say(errors ? "URING DONE (errors)\n" : "URING DONE\n");
	return errors ? 1 : 0;
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
	if (!strcmp(mode, "regfiles"))
		return mode_regfiles();
	if (!strcmp(mode, "syncfiles"))
		return mode_syncfiles();
	if (!strcmp(mode, "sqfiles"))
		return mode_sqfiles();
	if (!strcmp(mode, "morefiles"))
		return mode_morefiles();
	if (!strcmp(mode, "script") && argc > 2)
		return mode_script(argv[2]);
	say("usage: uring-fixture pairs|cancel|drain|sqpoll|threads|crash|hold|hold-ignore|files|syncfiles|sqfiles|morefiles|aio|script FILE\n");
	return 64;
}
