// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include "host_api.h"
#include "queue.h"
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct reader {
	struct ant_queue *q;
	void *data;
	__u32 size;
	__u64 tail, seen_head;
	__u64 gpa;
	__u32 cpu_id;
	/* When ant_read_ordered first saw this ring's head message waiting (0:
	 * the ring was empty at its last look). */
	__u64 head_since;
};
struct backing {
	int fd;
	struct stat stat;
};
struct ant_client {
	int cancelled, fatal, health_ms, guest_paused;
	struct ant_boot *boot;
	struct ant_control *control;
	struct ant_region *region;
	struct backing *backings;
	struct ant_memory_region *regions;
	size_t backing_count, region_count;
	__u64 bootstrap_gpa;
	struct reader *readers, replies;
	unsigned count, next;
	/* Ring (cpu id) and wait of the message the last ordered read took. */
	__u32 last_cpu;
	__u64 last_wait_ns;
	enum ant_poll_mode poll_mode;
	unsigned poll_sleep_us, poll_spin_us;
	__u64 session, command_head, command_tail_seen, sequence;
	__u32 abi;
	__u64 guest_hb, guest_changed, heartbeat_at;
	__u64 control_gpa, attachment;
	bool pending, suspended;
};

static __u64 now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (__u64)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void pause_us(unsigned us)
{
	struct timespec t = { .tv_sec = us / 1000000, .tv_nsec = (us % 1000000) * 1000 };
	nanosleep(&t, NULL);
}
static int failed(struct ant_client *c, int error)
{
	if (error == -EPROTO || error == -ESTALE || error == -ETIMEDOUT)
		c->fatal = error;
	return error;
}
static int tick(struct ant_client *c)
{
	__u64 t, hb;
	if (!c) return -EINVAL;
	if (__atomic_load_n(&c->cancelled, __ATOMIC_RELAXED)) return -ECANCELED;
	if (c->pending || c->suspended) return -EINPROGRESS;
	if (c->fatal) return c->fatal;
	if (ANT_ACQ(&c->boot->magic) != ANT_MAGIC || ANT_ACQ(&c->boot->session) != c->session ||
	    ANT_ACQ(&c->control->geometry.magic) != ANT_MAGIC || ANT_ACQ(&c->control->geometry.session) != c->session)
		return failed(c, -ESTALE);
	if (c->abi >= 9 && (ANT_ACQ(&c->boot->owner) != c->attachment ||
	    ANT_ACQ(&c->boot->resume_request) != c->attachment ||
	    ANT_ACQ(&c->boot->resume_ack) != c->attachment)) return failed(c, -ESTALE);
	t = now_ns();
	if (t - c->heartbeat_at >= 10000000ULL) {
		ANT_REL(&c->control->host_heartbeat, t);
		c->heartbeat_at = t;
	}
	hb = ANT_ACQ(&c->control->guest_heartbeat);
	if (hb < c->guest_hb) return failed(c, -ESTALE);
	if (hb != c->guest_hb) { c->guest_hb = hb; c->guest_changed = t; }
	if (!c->guest_paused && t - c->guest_changed > (__u64)c->health_ms * 1000000)
		return failed(c, -ETIMEDOUT);
	if (ANT_ACQ(&c->control->health) & ANT_HEALTH_RING_FAULT)
		return failed(c, -EPROTO);
	return 0;
}

static bool overlap(__u64 a, __u64 as, __u64 b, __u64 bs)
{
	return a < b + bs && b < a + as;
}

static int open_layout(struct ant_client *c, const struct ant_options *o)
{
	__u64 total = 0;
	size_t i, j;
	if (!o->backings || !o->regions || !o->backing_count || o->backing_count > 16 ||
	    !o->region_count || o->region_count > 64 || !o->ram_size)
		return -EINVAL;
	c->backings = calloc(o->backing_count, sizeof(*c->backings));
	if (!c->backings) return -ENOMEM;
	c->backing_count = o->backing_count;
	for (i = 0; i < c->backing_count; i++) c->backings[i].fd = -1;
	c->regions = calloc(o->region_count, sizeof(*c->regions));
	if (!c->regions) return -ENOMEM;
	c->region_count = o->region_count;
	memcpy(c->regions, o->regions, c->region_count * sizeof(*c->regions));
	for (i = 0; i < c->backing_count; i++) {
		struct backing *b = &c->backings[i];
		if (!o->backings[i].path || !o->backings[i].size || o->backings[i].size > INT64_MAX)
			return -EINVAL;
		b->fd = open(o->backings[i].path, O_RDWR | O_CLOEXEC);
		if (b->fd < 0) return -errno;
		if (fstat(b->fd, &b->stat)) return -errno;
		if (!S_ISREG(b->stat.st_mode) || (__u64)b->stat.st_size != o->backings[i].size)
			return -ENOTSUP;
		for (j = 0; j < i; j++)
			if (b->stat.st_dev == c->backings[j].stat.st_dev &&
			    b->stat.st_ino == c->backings[j].stat.st_ino) return -EINVAL;
		if (flock(b->fd, LOCK_EX | LOCK_NB)) return -EBUSY;
	}
	for (i = 0; i < c->region_count; i++) {
		struct ant_memory_region *r = &c->regions[i];
		__u64 backing_size;
		if (!r->size || ((r->gpa | r->size | r->file_offset) & 4095) ||
		    r->gpa > UINT64_MAX - r->size || r->backing_index >= c->backing_count)
			return -EINVAL;
		backing_size = c->backings[r->backing_index].stat.st_size;
		if (r->file_offset > backing_size || r->size > backing_size - r->file_offset ||
		    total > UINT64_MAX - r->size) return -EINVAL;
		total += r->size;
		for (j = 0; j < i; j++) {
			struct ant_memory_region *p = &c->regions[j];
			if (overlap(r->gpa, r->size, p->gpa, p->size)) return -EINVAL;
			if (r->backing_index == p->backing_index &&
			    overlap(r->file_offset, r->size, p->file_offset, p->size)) return -EINVAL;
		}
	}
	return total == o->ram_size ? 0 : -EINVAL;
}

/* A transport allocation must fit wholly in one declared mapping segment. */
static int map_gpa(struct ant_client *c, __u64 gpa, __u64 size, int prot, void **out)
{
	size_t i;
	if (!size || (gpa & 4095) || gpa < 0x100000 || gpa > UINT64_MAX - size)
		return -EPROTO;
	for (i = 0; i < c->region_count; i++) {
		struct ant_memory_region *r = &c->regions[i];
		__u64 offset;
		void *mapping;
		if (gpa < r->gpa || gpa - r->gpa > r->size) continue;
		offset = gpa - r->gpa;
		if (size > r->size - offset) continue;
		mapping = mmap(NULL, size, prot, MAP_SHARED, c->backings[r->backing_index].fd,
			r->file_offset + offset);
		if (mapping == MAP_FAILED) return -errno;
		*out = mapping;
		return 0;
	}
	return -EPROTO;
}

void ant_close(struct ant_client *c)
{
	unsigned i;
	if (!c) return;
	for (i = 0; i < c->count; i++)
		if (c->readers && c->readers[i].data) munmap(c->readers[i].data, c->readers[i].size);
	free(c->readers);
	if (c->region) munmap(c->region, ANT_CONTROL_SIZE);
	if (c->boot) munmap(c->boot, ANT_BOOT_SIZE);
	for (i = 0; i < c->backing_count; i++)
		if (c->backings[i].fd >= 0) close(c->backings[i].fd);
	free(c->backings);
	free(c->regions);
	free(c);
}

int ant_open_pending(const struct ant_options *options, struct ant_client **out)
{
	struct ant_client *c;
	struct ant_boot boot;
	struct ant_geometry geometry;
	struct ant_queue *directory;
	struct ant_queue descriptors[ANT_MAX_CPUS];
	__u64 deadline, expected = 0;
	unsigned i, j;
	int error = -ENOMEM, timeout;
	void *mapping;
	_Static_assert(sizeof(struct ant_message) == 32, "message ABI");
	_Static_assert(sizeof(struct ant_boot) == 256, "bootstrap ABI");
	_Static_assert(offsetof(struct ant_boot, resume_request) == 128, "resume request ABI");
	_Static_assert(offsetof(struct ant_boot, resume_ack) == 192, "resume ack ABI");
	_Static_assert(sizeof(struct ant_queue) == 192, "queue ABI");
	_Static_assert(sizeof(struct ant_geometry) == 64, "geometry ABI");
	_Static_assert(offsetof(struct ant_control, guest_heartbeat) == 64, "guest state ABI");
	_Static_assert(offsetof(struct ant_control, host_heartbeat) == 128, "host state ABI");
	_Static_assert(offsetof(struct ant_region, request_data) == ANT_REQUEST_OFFSET, "request ABI");
	_Static_assert(offsetof(struct ant_region, response_data) == ANT_RESPONSE_OFFSET, "response ABI");
	_Static_assert(offsetof(struct ant_region, directory) == ANT_DIRECTORY_OFFSET, "directory ABI");
	_Static_assert(sizeof(struct ant_region) == ANT_CONTROL_SIZE, "region ABI");
	_Static_assert(offsetof(struct ant_control, requests) == 512, "control ABI");
	if (!out) return -EINVAL;
	*out = NULL;
	if (!options || options->init_timeout_ms < 0 || options->health_timeout_ms < 0 ||
	    options->host_timeout_ms > ANT_HOST_TIMEOUT_MAX_MS ||
	    options->poll_mode < ANT_POLL_SLEEP || options->poll_mode > ANT_POLL_ADAPTIVE ||
	    options->poll_sleep_us > 10000 || options->poll_spin_us > 10000) return -EINVAL;
	c = calloc(1, sizeof(*c));
	if (!c) return -ENOMEM;
	c->health_ms = options->health_timeout_ms ?: 10000;
	c->poll_mode = options->poll_mode;
	c->poll_sleep_us = options->poll_sleep_us ?: 50;
	c->poll_spin_us = options->poll_spin_us ?: 20;
	c->bootstrap_gpa = options->bootstrap_gpa;
	timeout = options->init_timeout_ms ?: 30000;
	error = open_layout(c, options);
	if (error) goto fail;
	error = map_gpa(c, c->bootstrap_gpa, ANT_BOOT_SIZE, PROT_READ | PROT_WRITE, &mapping);
	if (error) goto fail;
	c->boot = mapping;
	deadline = now_ns() + (__u64)timeout * 1000000;
	while (!ANT_ACQ(&c->boot->magic)) {
		if (now_ns() >= deadline) { error = -ETIMEDOUT; goto fail; }
		pause_us(1000);
	}
	memcpy(&boot, c->boot, sizeof(boot));
	error = -EPROTO;
	/* ABI 7 guests (fixed 256 KiB rings, no send wait) remain supported. */
	if (boot.magic != ANT_MAGIC || (boot.version != ANT_ABI && boot.version != 8 && boot.version != 7) || boot.profile != 1 ||
	    !boot.session || boot.control_size != ANT_CONTROL_SIZE ||
	    boot.control_gpa > UINT64_MAX - ANT_CONTROL_SIZE ||
	    overlap(boot.control_gpa, ANT_CONTROL_SIZE, c->bootstrap_gpa, ANT_BOOT_SIZE)) goto fail;
	if (boot.version < 9 && boot.owner) { error = -EALREADY; goto fail; }
	c->session = boot.session;
	c->abi = boot.version;
	c->control_gpa = boot.control_gpa;
	error = map_gpa(c, boot.control_gpa, ANT_CONTROL_SIZE, PROT_READ | PROT_WRITE, &mapping);
	if (error) goto fail;
	c->region = mapping;
	c->control = &c->region->control;
	error = -EPROTO;
	if (ANT_ACQ(&c->control->geometry.magic) != ANT_MAGIC) goto fail;
	memcpy(&geometry, &c->control->geometry, sizeof(geometry));
	if (geometry.magic != ANT_MAGIC || geometry.version != c->abi || geometry.session != c->session ||
	    geometry.size != ANT_CONTROL_SIZE || geometry.max_message_len != ANT_MAX_MESSAGE_LEN ||
	    geometry.max_command_len != ANT_MAX_COMMAND_LEN || geometry.max_result_len != ANT_MAX_RESULT_LEN || !geometry.queue_count ||
	    geometry.queue_count > ANT_MAX_CPUS) goto fail;
	if (c->control->requests.data_gpa != boot.control_gpa + ANT_REQUEST_OFFSET ||
	    c->control->requests.data_size != ANT_COMMAND_RING_SIZE ||
	    c->control->responses.data_gpa != boot.control_gpa + ANT_RESPONSE_OFFSET ||
	    c->control->responses.data_size != ANT_COMMAND_RING_SIZE) goto fail;
	c->count = geometry.queue_count;
	c->readers = calloc(c->count, sizeof(*c->readers));
	if (!c->readers) { error = -ENOMEM; goto fail; }
	directory = c->region->directory;
	for (i = 0; i < c->count; i++) {
		struct ant_queue *d = &descriptors[i];
		memcpy(d, &directory[i], offsetof(struct ant_queue, head));
		__u32 size = d->data_size;
		error = -EPROTO;
		if (size < ANT_TELEMETRY_RING_MIN || size > ANT_TELEMETRY_RING_MAX || (size & (size - 1)) ||
		    (c->abi == 7 && size != ANT_TELEMETRY_RING_MIN) ||
		    (i && size != descriptors[0].data_size) || d->data_gpa > UINT64_MAX - size ||
		    overlap(d->data_gpa, size, c->bootstrap_gpa, ANT_BOOT_SIZE) ||
		    overlap(d->data_gpa, size, boot.control_gpa, ANT_CONTROL_SIZE) ||
		    (i && d->cpu_id <= descriptors[i - 1].cpu_id) ||
		    (c->abi < 9 && ANT_ACQ(&directory[i].tail))) goto fail;
		for (j = 0; j < i; j++)
			if (overlap(d->data_gpa, size, descriptors[j].data_gpa, size)) goto fail;
		error = map_gpa(c, d->data_gpa, size, PROT_READ, &mapping);
		if (error) goto fail;
		c->readers[i].data = mapping;
		c->readers[i].size = size;
		c->readers[i].q = &directory[i];
		c->readers[i].gpa = d->data_gpa;
		c->readers[i].cpu_id = d->cpu_id;
	}
	if (c->abi < 9 && (ANT_ACQ(&c->control->requests.head) || ANT_ACQ(&c->control->requests.tail) ||
	    ANT_ACQ(&c->control->responses.head) || ANT_ACQ(&c->control->responses.tail))) {
		error = -EALREADY; goto fail;
	}
	if (c->abi < 9 && !__atomic_compare_exchange_n(&c->boot->owner, &expected, c->session, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) { error = -EALREADY; goto fail; }
	c->replies.q = &c->control->responses;
	c->replies.data = c->region->response_data;
	ANT_REL(&c->control->host_timeout_ms, options->host_timeout_ms ?: ANT_HOST_TIMEOUT_DEFAULT_MS);
	c->guest_changed = now_ns();
	error = c->abi >= 9 ? ant_resume_begin(c) : tick(c);
	if (error) goto fail;
	*out = c;
	return 0;
fail:
	ant_close(c);
	return error;
}

int ant_init(const struct ant_options *options, struct ant_client **out)
{
	struct ant_resume_report report;
	int error = ant_open_pending(options, out);
	if (error) return error;
	if ((*out)->abi < 9) return 0;
	error = ant_resume_finish(*out, options->init_timeout_ms, &report);
	if (error) { ant_close(*out); *out = NULL; }
	return error;
}

static int validate_resume_layout(struct ant_client *c)
{
	struct ant_boot *b = c->boot;
	struct ant_geometry *g = &c->control->geometry;
	unsigned i;

	if (ANT_ACQ(&b->magic) != ANT_MAGIC || b->version != c->abi ||
	    b->session != c->session || b->control_gpa != c->control_gpa ||
	    b->control_size != ANT_CONTROL_SIZE || b->profile != 1 ||
	    ANT_ACQ(&g->magic) != ANT_MAGIC || g->version != c->abi ||
	    g->session != c->session || g->queue_count != c->count ||
	    g->size != ANT_CONTROL_SIZE || g->max_message_len != ANT_MAX_MESSAGE_LEN ||
	    g->max_command_len != ANT_MAX_COMMAND_LEN || g->max_result_len != ANT_MAX_RESULT_LEN ||
	    c->control->requests.data_gpa != c->control_gpa + ANT_REQUEST_OFFSET ||
	    c->control->requests.data_size != ANT_COMMAND_RING_SIZE ||
	    c->control->responses.data_gpa != c->control_gpa + ANT_RESPONSE_OFFSET ||
	    c->control->responses.data_size != ANT_COMMAND_RING_SIZE) return -ESTALE;
	for (i = 0; i < c->count; i++) {
		struct reader *r = &c->readers[i];
		if (r->q->data_gpa != r->gpa || r->q->data_size != r->size ||
		    r->q->cpu_id != r->cpu_id) return -ESTALE;
	}
	return 0;
}

int ant_resume_begin(struct ant_client *c)
{
	__u64 nonce;
	int error;
	ssize_t got;

	if (!c) return -EINVAL;
	if (c->abi < 9) return -EOPNOTSUPP;
	if (__atomic_load_n(&c->cancelled, __ATOMIC_RELAXED)) return -ECANCELED;
	if (c->pending) return -EINPROGRESS;
	error = validate_resume_layout(c);
	if (error) return failed(c, error);
	do {
		do { got = getrandom(&nonce, sizeof(nonce), 0); } while (got < 0 && errno == EINTR);
		if (got < 0) return -errno;
		if (got != sizeof(nonce)) return -EIO;
	} while (!nonce || nonce == c->attachment || nonce == ANT_ACQ(&c->boot->resume_request) ||
		 nonce == ANT_ACQ(&c->boot->resume_ack) || nonce == ANT_ACQ(&c->boot->owner));
	c->attachment = nonce;
	c->pending = true;
	/* A fresh namespace fences queued and already executing commands; callers
	 * must abandon unresolved results, rather than automatically replay them. */
	ANT_REL(&c->boot->resume_sequence_floor, c->sequence);
	ANT_REL(&c->boot->resume_request, nonce);
	return 0;
}

int ant_suspend_heartbeats(struct ant_client *c)
{
	if (!c) return -EINVAL;
	if (__atomic_load_n(&c->cancelled, __ATOMIC_RELAXED)) return -ECANCELED;
	c->suspended = true;
	return 0;
}

int ant_resume_heartbeats(struct ant_client *c)
{
	int error;
	if (!c) return -EINVAL;
	if (c->pending) return -EINPROGRESS;
	error = validate_resume_layout(c);
	if (error) return failed(c, error);
	c->guest_changed = now_ns();
	c->heartbeat_at = 0;
	c->suspended = false;
	return tick(c);
}

int ant_resume_finish(struct ant_client *c, int timeout_ms, struct ant_resume_report *report)
{
	__u64 deadline, head, tail;
	unsigned i;
	int error;

	if (!c || !report || timeout_ms < 0) return -EINVAL;
	memset(report, 0, sizeof(*report));
	if (c->abi < 9) return -EOPNOTSUPP;
	if (!c->pending) return -EINVAL;
	deadline = now_ns() + (__u64)(timeout_ms ?: 30000) * 1000000;
	for (;;) {
		if (__atomic_load_n(&c->cancelled, __ATOMIC_RELAXED)) return -ECANCELED;
		error = validate_resume_layout(c);
		if (error) return failed(c, error);
		if (ANT_ACQ(&c->boot->resume_request) != c->attachment) return failed(c, -ESTALE);
		if (ANT_ACQ(&c->boot->resume_ack) == c->attachment) break;
		if (now_ns() >= deadline) return -ETIMEDOUT;
		pause_us(1000);
	}
	if (c->boot->resume_status) return failed(c,
		c->boot->resume_status < 0 ? c->boot->resume_status : -EPROTO);
	if (ANT_ACQ(&c->boot->owner) != c->attachment) return failed(c, -ESTALE);
	head = ANT_ACQ(&c->control->requests.head);
	tail = ANT_ACQ(&c->control->requests.tail);
	if ((head & 7) || head != tail) return failed(c, -EPROTO);
	c->command_head = head;
	c->command_tail_seen = tail;
	head = ANT_ACQ(&c->control->responses.head);
	tail = ANT_ACQ(&c->control->responses.tail);
	if ((head & 7) || (tail & 7) || tail > head || head - tail > ANT_COMMAND_RING_SIZE)
		return failed(c, -EPROTO);
	c->replies.tail = head;
	c->replies.seen_head = head;
	ANT_REL(&c->control->responses.tail, head);
	for (i = 0; i < c->count; i++) {
		struct reader *r = &c->readers[i];
		tail = ANT_ACQ(&r->q->tail);
		head = ANT_ACQ(&r->q->head);
		if ((head & 7) || (tail & 7) || tail > head || head - tail > r->size)
			return failed(c, -EPROTO);
		r->tail = tail;
		r->seen_head = head;
		r->head_since = 0;
	}
	c->sequence = c->boot->resume_sequence_ack;
	c->guest_hb = ANT_ACQ(&c->control->guest_heartbeat);
	c->guest_changed = now_ns();
	c->heartbeat_at = 0;
	c->next = 0;
	c->fatal = 0;
	c->pending = false;
	c->suspended = false;
	*report = (struct ant_resume_report){ c->attachment, c->sequence,
		c->boot->discarded_request_bytes, c->boot->discarded_reply_bytes };
	return tick(c);
}

static int peek_telemetry(struct ant_client *c, struct reader *r, struct ant_message *msg)
{
	int error = ant_peek(r->q, r->data, r->size, ANT_MAX_MESSAGE_LEN,
		r->tail, &r->seen_head, msg);
	if (error) return failed(c, error);
	if (msg->opcode) return failed(c, -EPROTO);
	if (msg->id) return failed(c, -EPROTO);
	if (msg->status) return failed(c, -EPROTO);
	return 0;
}

static int peek_replies(struct ant_client *c, struct ant_message *msg)
{
	struct reader *r = &c->replies;
	int error = ant_peek(r->q, r->data, ANT_COMMAND_RING_SIZE, ANT_MAX_RESULT_LEN,
		r->tail, &r->seen_head, msg);
	if (error) return failed(c, error);
	if (!msg->id || msg->id > c->sequence) return failed(c, -EPROTO);
	if (!msg->opcode) return failed(c, -EPROTO);
	if (msg->status > 0) return failed(c, -EPROTO);
	return 0;
}

int ant_poll(struct ant_client *c, int timeout_ms)
{
	__u64 begin = now_ns(), deadline = 0;
#ifdef ANT_BENCH_LEGACY_IDLE
	unsigned idle = 0;
#endif
	if (!c || timeout_ms < -1) return -EINVAL;
	if (timeout_ms >= 0) deadline = begin + (__u64)timeout_ms * 1000000;
	for (;;) {
		struct ant_message msg;
		unsigned i;
		__u64 t, delay_ns;
		bool spin;
		int events = 0, error = tick(c);
		if (error) return error;
		for (i = 0; i < c->count; i++) {
			error = peek_telemetry(c, &c->readers[i], &msg);
			if (!error) events |= ANT_EVENT_TELEMETRY;
			else if (error != -EAGAIN) return error;
		}
		error = peek_replies(c, &msg);
		if (!error) events |= ANT_EVENT_RESULT;
		else if (error != -EAGAIN) return error;
		if (events) return events;
		t = now_ns();
		if (timeout_ms >= 0 && t >= deadline) return 0;
		spin = c->poll_mode == ANT_POLL_BUSY;
		if (c->poll_mode == ANT_POLL_ADAPTIVE && t - begin < (__u64)c->poll_spin_us * 1000)
			spin = true;
#ifdef ANT_BENCH_LEGACY_IDLE
		/* Benchmark-only V6 wait policy; never enabled in the library build. */
		if (idle < 64) idle++;
		spin = idle < 64;
#endif
		if (spin) {
			__asm__ __volatile__("pause");
			continue;
		}
		delay_ns = (__u64)c->poll_sleep_us * 1000;
		if (timeout_ms >= 0 && delay_ns > deadline - t) delay_ns = deadline - t;
		{
			struct timespec delay = { .tv_nsec = delay_ns };
#ifdef ANT_POLL_BENCH
			extern void ant_bench_sleep(__u64 requested, __u64 actual);
			__u64 before = now_ns();
#endif
			nanosleep(&delay, NULL);
#ifdef ANT_POLL_BENCH
			ant_bench_sleep(delay_ns, now_ns() - before);
#endif
		}
	}
}

/* Copy out and consume the head message of reader index, peeked as msg. */
static int take_telemetry(struct ant_client *c, unsigned index, const struct ant_message *msg,
		void *dst, size_t capacity, size_t *payload_len, __u64 now)
{
	struct reader *r = &c->readers[index];
	*payload_len = msg->payload_len;
	if (capacity < msg->payload_len) {
		c->next = index;
		return -ENOBUFS;
	}
	ant_copy_out(r->data, r->size, r->tail + sizeof(*msg), dst, msg->payload_len);
	r->tail += ant_span(msg->payload_len);
	ANT_REL(&r->q->tail, r->tail);
	c->last_cpu = r->cpu_id;
	c->last_wait_ns = now > r->head_since && r->head_since ? now - r->head_since : 0;
	r->head_since = 0;
	c->next = (index + 1) % c->count;
	return 0;
}

int ant_read(struct ant_client *c, void *dst, size_t capacity, size_t *payload_len)
{
	unsigned i;
	int error;
	if (!payload_len || (!dst && capacity)) return -EINVAL;
	*payload_len = 0;
	error = tick(c);
	if (error) return error;
	for (i = 0; i < c->count; i++) {
		unsigned index = (c->next + i) % c->count;
		struct ant_message msg;
		error = peek_telemetry(c, &c->readers[index], &msg);
		if (error == -EAGAIN) continue;
		if (error) return error;
		return take_telemetry(c, index, &msg, dst, capacity, payload_len, 0);
	}
	return -EAGAIN;
}

/* Longest a ring's head waits behind the timestamp order while others are read. */
#define ANT_STARVED_NS 10000000ULL

int ant_read_ordered(struct ant_client *c, void *dst, size_t capacity, size_t *payload_len,
		size_t key_offset)
{
	struct ant_message best_msg, starved_msg;
	unsigned i, best = UINT32_MAX, starved = UINT32_MAX;
	__u64 best_key = 0, now = 0;
	int error;
	if (!payload_len || (!dst && capacity) || key_offset > ANT_MAX_MESSAGE_LEN - 8)
		return -EINVAL;
	*payload_len = 0;
	error = tick(c);
	if (error) return error;
	/* Each ring is in its producer's order; taking the smallest key among the
	 * heads merges the rings in key order. Equal keys go round robin. A key
	 * is when an event began, so the fragments of one long event keep an old
	 * key and would hold every other ring back for as long as it is sent: a
	 * head that has waited ANT_STARVED_NS is taken first (the longest
	 * waiting one), so no ring is kept from the host for longer than that
	 * while another is read. */
	for (i = 0; i < c->count; i++) {
		unsigned index = (c->next + i) % c->count;
		struct reader *r = &c->readers[index];
		struct ant_message msg;
		unsigned char raw[8];
		__u64 key = 0;
		int k;
		error = peek_telemetry(c, r, &msg);
		if (error == -EAGAIN) {
			r->head_since = 0;
			continue;
		}
		if (error) return error;
		if (!now) now = now_ns();
		if (!r->head_since) r->head_since = now;
		if (now - r->head_since >= ANT_STARVED_NS) {
			if (starved == UINT32_MAX || r->head_since < c->readers[starved].head_since) {
				starved = index;
				starved_msg = msg;
			}
			continue;
		}
		if (msg.payload_len >= key_offset + 8) {
			ant_copy_out(r->data, r->size, r->tail + sizeof(msg) + key_offset, raw, 8);
			for (k = 7; k >= 0; k--)
				key = key << 8 | raw[k];
		}
		if (best == UINT32_MAX || key < best_key) {
			best = index;
			best_key = key;
			best_msg = msg;
		}
	}
	if (starved != UINT32_MAX) {
		best = starved;
		best_msg = starved_msg;
	}
	if (best == UINT32_MAX) return -EAGAIN;
	return take_telemetry(c, best, &best_msg, dst, capacity, payload_len, now);
}

int ant_last_read(struct ant_client *c, uint32_t *cpu_id, uint64_t *wait_ns)
{
	if (!c || !cpu_id || !wait_ns) return -EINVAL;
	*cpu_id = c->last_cpu;
	*wait_ns = c->last_wait_ns;
	return 0;
}

int ant_command_send(struct ant_client *c, uint32_t opcode,
		const void *args, size_t payload_len, uint64_t *request_id)
{
	struct ant_message msg = { .payload_len = payload_len, .opcode = opcode };
	int error;
	if (!request_id || !opcode || (!args && payload_len)) return -EINVAL;
	if (payload_len > ANT_MAX_COMMAND_LEN) return -EMSGSIZE;
	error = tick(c);
	if (error) return error;
	if (c->sequence == UINT64_MAX) return -EOVERFLOW;
	error = ant_space(&c->control->requests, ANT_COMMAND_RING_SIZE, c->command_head,
		&c->command_tail_seen, ant_span(payload_len));
	if (error) return failed(c, error);
	msg.id = ++c->sequence;
	ant_publish(&c->control->requests, c->region->request_data, ANT_COMMAND_RING_SIZE,
		&c->command_head, &msg, args);
	*request_id = msg.id;
	return 0;
}

int ant_result_read(struct ant_client *c, uint64_t *id, int32_t *status,
		void *dst, size_t capacity, size_t *payload_len)
{
	struct ant_message msg;
	struct reader *r;
	int error;
	if (!id || !status || !payload_len || (!dst && capacity)) return -EINVAL;
	*payload_len = 0;
	error = tick(c);
	if (error) return error;
	r = &c->replies;
	error = peek_replies(c, &msg);
	if (error) return error;
	*payload_len = msg.payload_len;
	if (capacity < msg.payload_len) return -ENOBUFS;
	ant_copy_out(r->data, ANT_COMMAND_RING_SIZE, r->tail + sizeof(msg), dst, msg.payload_len);
	r->tail += ant_span(msg.payload_len);
	ANT_REL(&r->q->tail, r->tail);
	*id = msg.id;
	*status = msg.status;
	return 0;
}

int ant_get_stats(struct ant_client *c, struct ant_stats *stats)
{
	unsigned i;
	int error;
	if (!stats) return -EINVAL;
	error = tick(c);
	if (error) return error;
	memset(stats, 0, sizeof(*stats));
	for (i = 0; i < c->count; i++) {
		stats->attempted += ANT_ACQ(&c->readers[i].q->attempted);
		stats->dropped += ANT_ACQ(&c->readers[i].q->dropped);
		stats->waits += ANT_ACQ(&c->readers[i].q->waits);
		stats->wait_ns += ANT_ACQ(&c->readers[i].q->wait_ns);
	}
	stats->abi = c->abi;
	stats->ring_size = c->count ? c->readers[0].size : 0;
	stats->send_wait_us = c->abi >= 8 ? ANT_ACQ(&c->control->send_wait_us) : 0;
	stats->queue_count = c->count;
	stats->bad_commands = ANT_ACQ(&c->control->bad_commands);
	stats->reply_stalls = ANT_ACQ(&c->control->reply_stalls);
	stats->health = ANT_ACQ(&c->control->health);
	stats->live = ANT_ACQ(&c->control->live);
	stats->host_timeout_ms = ANT_ACQ(&c->control->applied_host_timeout_ms);
	return 0;
}

int ant_guest_heartbeat(struct ant_client *c, uint64_t *heartbeat)
{
	if (!c || !heartbeat) return -EINVAL;
	if (__atomic_load_n(&c->cancelled, __ATOMIC_RELAXED)) return -ECANCELED;
	*heartbeat = ANT_ACQ(&c->control->guest_heartbeat);
	return 0;
}

void ant_cancel(struct ant_client *c)
{
	if (c) __atomic_store_n(&c->cancelled, 1, __ATOMIC_RELAXED);
}

int ant_get_limits(struct ant_client *c, struct ant_limits *limits)
{
	int error;
	if (!c || !limits) return -EINVAL;
	/* Limits are immutable and do not publish a heartbeat. This query is also
	 * available while a paused incoming guest has not acknowledged resume. */
	error = c->pending ? validate_resume_layout(c) : tick(c);
	if (error) return error;
	*limits = (struct ant_limits){ ANT_MAX_MESSAGE_LEN, ANT_MAX_COMMAND_LEN, ANT_MAX_RESULT_LEN };
	return 0;
}

int ant_set_host_timeout(struct ant_client *c, uint32_t timeout_ms)
{
	int error;
	if (timeout_ms > ANT_HOST_TIMEOUT_MAX_MS) return -EINVAL;
	error = tick(c);
	if (error) return error;
	if (!timeout_ms) timeout_ms = ANT_HOST_TIMEOUT_DEFAULT_MS;
	ANT_REL(&c->control->host_timeout_ms, timeout_ms);
	return 0;
}

int ant_heartbeat(struct ant_client *c)
{
	return tick(c);
}

int ant_set_guest_paused(struct ant_client *c, int paused)
{
	if (!c) return -EINVAL;
	if (c->guest_paused && !paused) {
		c->guest_hb = ANT_ACQ(&c->control->guest_heartbeat);
		c->guest_changed = now_ns();
	}
	c->guest_paused = !!paused;
	return tick(c);
}

int ant_set_send_wait(struct ant_client *c, uint32_t wait_us)
{
	int error;
	if (wait_us > ANT_SEND_WAIT_MAX_US) return -EINVAL;
	error = tick(c);
	if (error) return error;
	if (c->abi < 8) return wait_us ? -EOPNOTSUPP : 0;
	ANT_REL(&c->control->send_wait_us, wait_us);
	return 0;
}
