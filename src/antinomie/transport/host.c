// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include "host_api.h"
#include "queue.h"
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct reader {
	struct ant_queue *q;
	void *data;
	__u32 size;
	__u64 tail, seen_head;
};
struct backing {
	int fd;
	struct stat stat;
};
struct ant_client {
	int cancelled, fatal, health_ms;
	struct ant_boot *boot;
	struct ant_control *control;
	struct ant_region *region;
	struct backing *backings;
	struct ant_memory_region *regions;
	size_t backing_count, region_count;
	__u64 bootstrap_gpa;
	struct reader *readers, replies;
	unsigned count, next;
	enum ant_poll_mode poll_mode;
	unsigned poll_sleep_us, poll_spin_us;
	__u64 session, command_head, command_tail_seen, sequence;
	__u32 abi;
	__u64 guest_hb, guest_changed, heartbeat_at;
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
	if (c->fatal) return c->fatal;
	if (ANT_ACQ(&c->boot->magic) != ANT_MAGIC || ANT_ACQ(&c->boot->session) != c->session ||
	    ANT_ACQ(&c->control->geometry.magic) != ANT_MAGIC || ANT_ACQ(&c->control->geometry.session) != c->session)
		return failed(c, -ESTALE);
	t = now_ns();
	if (t - c->heartbeat_at >= 10000000ULL) {
		ANT_REL(&c->control->host_heartbeat, t);
		c->heartbeat_at = t;
	}
	hb = ANT_ACQ(&c->control->guest_heartbeat);
	if (hb < c->guest_hb) return failed(c, -ESTALE);
	if (hb != c->guest_hb) { c->guest_hb = hb; c->guest_changed = t; }
	if (t - c->guest_changed > (__u64)c->health_ms * 1000000)
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

int ant_init(const struct ant_options *options, struct ant_client **out)
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
	if (boot.magic != ANT_MAGIC || (boot.version != ANT_ABI && boot.version != 7) || boot.profile != 1 ||
	    !boot.session || boot.control_size != ANT_CONTROL_SIZE ||
	    boot.control_gpa > UINT64_MAX - ANT_CONTROL_SIZE ||
	    overlap(boot.control_gpa, ANT_CONTROL_SIZE, c->bootstrap_gpa, ANT_BOOT_SIZE)) goto fail;
	if (boot.owner) { error = -EALREADY; goto fail; }
	c->session = boot.session;
	c->abi = boot.version;
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
		    (i && d->cpu_id <= descriptors[i - 1].cpu_id) || ANT_ACQ(&directory[i].tail)) goto fail;
		for (j = 0; j < i; j++)
			if (overlap(d->data_gpa, size, descriptors[j].data_gpa, size)) goto fail;
		error = map_gpa(c, d->data_gpa, size, PROT_READ, &mapping);
		if (error) goto fail;
		c->readers[i].data = mapping;
		c->readers[i].size = size;
		c->readers[i].q = &directory[i];
	}
	if (ANT_ACQ(&c->control->requests.head) || ANT_ACQ(&c->control->requests.tail) ||
	    ANT_ACQ(&c->control->responses.head) || ANT_ACQ(&c->control->responses.tail)) {
		error = -EALREADY; goto fail;
	}
	if (!__atomic_compare_exchange_n(&c->boot->owner, &expected, c->session, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) { error = -EALREADY; goto fail; }
	c->replies.q = &c->control->responses;
	c->replies.data = c->region->response_data;
	ANT_REL(&c->control->host_timeout_ms, options->host_timeout_ms ?: ANT_HOST_TIMEOUT_DEFAULT_MS);
	c->guest_changed = now_ns();
	error = tick(c);
	if (error) goto fail;
	*out = c;
	return 0;
fail:
	ant_close(c);
	return error;
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
		struct reader *r = &c->readers[index];
		struct ant_message msg;
		error = peek_telemetry(c, r, &msg);
		if (error == -EAGAIN) continue;
		if (error) return error;
		*payload_len = msg.payload_len;
		if (capacity < msg.payload_len) {
			c->next = index;
			return -ENOBUFS;
		}
		ant_copy_out(r->data, r->size, r->tail + sizeof(msg), dst, msg.payload_len);
		r->tail += ant_span(msg.payload_len);
		ANT_REL(&r->q->tail, r->tail);
		c->next = (index + 1) % c->count;
		return 0;
	}
	return -EAGAIN;
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

void ant_cancel(struct ant_client *c)
{
	if (c) __atomic_store_n(&c->cancelled, 1, __ATOMIC_RELAXED);
}

int ant_get_limits(struct ant_client *c, struct ant_limits *limits)
{
	int error;
	if (!limits) return -EINVAL;
	error = tick(c);
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
