// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
#define _GNU_SOURCE
#include "host_api.h"
#include "queue.h"
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Host-side lifecycle checks with a deterministic guest mailbox simulator.
 * These do not replace the actual multi-vCPU kernel/QEMU acceptance run. */
struct fixture {
	char path[64];
	int fd;
	void *ram;
	struct ant_boot *boot;
	struct ant_region *region;
	struct ant_backing backing;
	struct ant_memory_region mapping;
	struct ant_options options;
};

static void setup(struct fixture *f, unsigned abi)
{
	unsigned i;
	memset(f, 0, sizeof(*f));
	strcpy(f->path, "/tmp/antinomie-resume-XXXXXX");
	f->fd = mkstemp(f->path);
	assert(f->fd >= 0 && !ftruncate(f->fd, 8U << 20));
	f->ram = mmap(NULL, 8U << 20, PROT_READ | PROT_WRITE, MAP_SHARED, f->fd, 0);
	assert(f->ram != MAP_FAILED);
	f->boot = (void *)((char *)f->ram + (1U << 20));
	f->region = (void *)((char *)f->ram + (2U << 20));
	*f->boot = (struct ant_boot){ .magic = ANT_MAGIC, .version = abi,
		.session = 12345, .control_gpa = 2U << 20, .control_size = ANT_CONTROL_SIZE, .profile = 1 };
	f->region->control.geometry = (struct ant_geometry){ .magic = ANT_MAGIC,
		.version = abi, .session = 12345, .queue_count = 4,
		.max_message_len = ANT_MAX_MESSAGE_LEN, .max_command_len = ANT_MAX_COMMAND_LEN,
		.size = ANT_CONTROL_SIZE, .max_result_len = ANT_MAX_RESULT_LEN };
	f->region->control.requests.data_gpa = (2U << 20) + ANT_REQUEST_OFFSET;
	f->region->control.requests.data_size = ANT_COMMAND_RING_SIZE;
	f->region->control.responses.data_gpa = (2U << 20) + ANT_RESPONSE_OFFSET;
	f->region->control.responses.data_size = ANT_COMMAND_RING_SIZE;
	f->region->control.guest_heartbeat = 100;
	for (i = 0; i < 4; i++) {
		f->region->directory[i].data_gpa = (4U << 20) + i * ANT_TELEMETRY_RING_MIN;
		f->region->directory[i].data_size = ANT_TELEMETRY_RING_MIN;
		f->region->directory[i].cpu_id = i;
	}
	f->backing = (struct ant_backing){ f->path, 8U << 20 };
	f->mapping = (struct ant_memory_region){ 0, 8U << 20, 0, 0 };
	f->options = (struct ant_options){ .backings = &f->backing, .backing_count = 1,
		.regions = &f->mapping, .region_count = 1, .ram_size = 8U << 20,
		.bootstrap_gpa = 1U << 20, .init_timeout_ms = 20, .health_timeout_ms = 1000 };
}

static void cleanup(struct fixture *f)
{
	assert(!munmap(f->ram, 8U << 20));
	close(f->fd);
	unlink(f->path);
}

static void acknowledge(struct fixture *f)
{
	struct ant_control *c = &f->region->control;
	__u64 cursor = ANT_ACQ(&c->requests.tail), seen = cursor;
	__u64 head = ANT_ACQ(&c->requests.head);
	__u64 floor = ANT_ACQ(&f->boot->resume_sequence_floor);
	if (f->boot->resume_sequence_ack > floor) floor = f->boot->resume_sequence_ack;
	while (cursor != head) {
		struct ant_message message;
		assert(!ant_peek(&c->requests, ANT_PROFILE_LP64, f->region->request_data, ANT_COMMAND_RING_SIZE,
			ANT_MAX_COMMAND_LEN, cursor, &seen, &message));
		if (message.id > floor) floor = message.id;
		cursor += ant_span(message.payload_len);
	}
	f->boot->discarded_request_bytes = head - c->requests.tail;
	f->boot->discarded_reply_bytes = c->responses.head - c->responses.tail;
	f->boot->resume_sequence_ack = floor;
	f->boot->resume_status = 0;
	ANT_REL(&c->requests.tail, head);
	ANT_REL(&f->boot->owner, ANT_ACQ(&f->boot->resume_request));
	ANT_REL(&f->boot->resume_ack, ANT_ACQ(&f->boot->resume_request));
}

static void *ack_thread(void *arg)
{
	struct fixture *f = arg;
	while (!ANT_ACQ(&f->boot->resume_request)) usleep(100);
	acknowledge(f);
	return NULL;
}

static void test_resume(void)
{
	struct fixture f;
	struct ant_client *client, *other = NULL;
	struct ant_resume_report report;
	struct ant_stats stats;
	struct ant_boot saved_boot;
	struct ant_region *saved_region = malloc(sizeof(*saved_region));
	struct ant_message telemetry = { .payload_len = 5 }, reply = { .opcode = 42, .id = 1 };
	pthread_t thread;
	__u64 head = 0;
	uint64_t id, first_attachment, saved_heartbeat;
	char data[8];
	size_t len;
	assert(saved_region);
	setup(&f, 9);
	assert(!pthread_create(&thread, NULL, ack_thread, &f));
	assert(!ant_init(&f.options, &client));
	assert(!pthread_join(thread, NULL));
	first_attachment = f.boot->resume_ack;
	assert(first_attachment && f.boot->owner == first_attachment);
	assert(ant_open_pending(&f.options, &other) == -EBUSY && !other);
	assert(!ant_get_stats(client, &stats) && stats.abi == 9 && stats.queue_count == 4);
	assert(!ant_set_send_wait(client, 1000));
	assert(!ant_suspend_heartbeats(client));
	saved_heartbeat = f.region->control.host_heartbeat;
	assert(ant_heartbeat(client) == -EINPROGRESS);
	assert(f.region->control.host_heartbeat == saved_heartbeat);
	assert(!ant_resume_heartbeats(client));
	/* Queue telemetry, a submitted command and an old reply; none may replay. */
	f.region->directory[0].attempted = 71;
	f.region->directory[0].dropped = 2;
	ant_publish(&f.region->directory[0], ANT_PROFILE_LP64, (char *)f.ram + (4U << 20),
		ANT_TELEMETRY_RING_MIN, &head, &telemetry, "hello");
	assert(!ant_command_send(client, 42, NULL, 0, &id) && id == 1);
	head = 0;
	ant_publish(&f.region->control.responses, ANT_PROFILE_LP64, f.region->response_data,
		ANT_COMMAND_RING_SIZE, &head, &reply, NULL);
	assert(!ant_resume_begin(client));
	assert(ant_command_send(client, 42, NULL, 0, &id) == -EINPROGRESS);
	acknowledge(&f);
	assert(!ant_resume_finish(client, 10, &report));
	assert(report.attachment != first_attachment && report.sequence_floor == 1);
	assert(report.discarded_request_bytes == 32 && report.discarded_reply_bytes == 32);
	assert(!ant_read(client, data, sizeof(data), &len) && len == 5 && !memcmp(data, "hello", 5));
	assert(!ant_get_stats(client, &stats) && stats.attempted == 71 && stats.dropped == 2);
	assert(!ant_command_send(client, 42, NULL, 0, &id) && id == 2);
	/* A rollback restores guest cursors/nonce/heartbeat; recovery is explicit. */
	saved_boot = *f.boot;
	*saved_region = *f.region;
	ANT_REL(&f.region->control.guest_heartbeat, 110);
	assert(!ant_heartbeat(client));
	assert(!ant_resume_begin(client));
	acknowledge(&f);
	assert(!ant_resume_finish(client, 10, &report));
	*f.boot = saved_boot;
	*f.region = *saved_region;
	assert(ant_heartbeat(client) == -ESTALE);
	assert(!ant_resume_begin(client));
	acknowledge(&f);
	assert(!ant_resume_finish(client, 10, &report));
	assert(report.sequence_floor >= 2);
	ant_close(client);
	assert(!ant_open_pending(&f.options, &client));
	acknowledge(&f);
	assert(!ant_resume_finish(client, 10, &report));
	assert(!ant_command_send(client, 42, NULL, 0, &id) && id > 2);
	assert(!ant_resume_begin(client));
	assert(ant_resume_finish(client, 1, &report) == -ETIMEDOUT);
	ant_cancel(client);
	assert(ant_resume_finish(client, 1, &report) == -ECANCELED);
	assert(ant_resume_begin(client) == -ECANCELED);
	ant_close(client);
	cleanup(&f);
	free(saved_region);
}

static void test_geometry(void)
{
	struct fixture f;
	struct ant_client *client;
	struct ant_resume_report report;
	unsigned mutation;
	for (mutation = 0; mutation < 4; mutation++) {
		setup(&f, 9);
		assert(!ant_open_pending(&f.options, &client));
		assert(ant_resume_finish(client, 1, &report) == -ETIMEDOUT);
		/* Explicit reconnect retry continues the existing nonce, rather than
		 * resubmitting commands or changing the attachment request. */
		assert(ant_resume_begin(client) == -EINPROGRESS);
		acknowledge(&f);
		assert(!ant_resume_finish(client, 10, &report));
		switch (mutation) {
		case 0: f.region->directory[0].data_gpa += 4096; break;
		case 1: f.region->directory[0].data_size *= 2; break;
		case 2: f.region->control.geometry.queue_count--; break;
		case 3: f.region->control.geometry.session++; break;
		}
		assert(ant_resume_begin(client) == -ESTALE);
		ant_close(client);
		cleanup(&f);
	}
}

static void test_ack_failure(void)
{
	struct fixture f;
	struct ant_client *client;
	struct ant_resume_report report;
	setup(&f, 9);
	assert(!ant_open_pending(&f.options, &client));
	f.boot->resume_status = -EPROTO;
	ANT_REL(&f.boot->resume_ack, ANT_ACQ(&f.boot->resume_request));
	assert(ant_resume_finish(client, 10, &report) == -EPROTO);
	assert(ant_heartbeat(client) == -EINPROGRESS);
	ant_close(client);
	cleanup(&f);
}

static void test_legacy(unsigned abi)
{
	struct fixture f;
	struct ant_client *client;
	struct ant_resume_report report;
	setup(&f, abi);
	f.options.health_timeout_ms = 10;
	assert(!ant_init(&f.options, &client));
	assert(ant_resume_begin(client) == -EOPNOTSUPP);
	assert(ant_resume_finish(client, 10, &report) == -EOPNOTSUPP);
	assert(!ant_suspend_heartbeats(client));
	assert(ant_heartbeat(client) == -EINPROGRESS);
	usleep(20000);
	assert(!ant_resume_heartbeats(client));
	ANT_REL(&f.region->control.guest_heartbeat, 1);
	assert(ant_heartbeat(client) == -ESTALE);
	assert(ant_resume_heartbeats(client) == -ESTALE);
	ant_close(client);
	assert(ant_init(&f.options, &client) == -EALREADY && !client);
	cleanup(&f);
}

/* Messages keyed by a timestamp in each ring come out merged in key order. */
static void test_ordered_reads(void)
{
	static const struct { unsigned ring; __u64 key; } sent[] = {
		{ 0, 10 }, { 0, 40 }, { 0, 50 }, { 1, 20 }, { 1, 30 }, { 3, 25 },
	};
	static const __u64 order[] = { 0, 10, 20, 25, 30, 40, 50 };
	struct fixture f;
	struct ant_client *client;
	struct ant_message message = { .payload_len = 16 }, short_message = { .payload_len = 1 };
	pthread_t thread;
	__u64 heads[4] = { 0 }, key;
	unsigned char data[16];
	size_t len;
	unsigned i;
	setup(&f, 9);
	assert(!pthread_create(&thread, NULL, ack_thread, &f));
	assert(!ant_init(&f.options, &client));
	assert(!pthread_join(thread, NULL));
	for (i = 0; i < sizeof(sent) / sizeof(sent[0]); i++) {
		memset(data, 0, sizeof(data));
		memcpy(data, &sent[i].key, sizeof(sent[i].key));
		ant_publish(&f.region->directory[sent[i].ring], ANT_PROFILE_LP64,
			(char *)f.ram + (4U << 20) + sent[i].ring * ANT_TELEMETRY_RING_MIN,
			ANT_TELEMETRY_RING_MIN, &heads[sent[i].ring], &message, data);
	}
	/* Too short to hold a key: it orders first. */
	ant_publish(&f.region->directory[2], ANT_PROFILE_LP64, (char *)f.ram + (4U << 20) + 2 * ANT_TELEMETRY_RING_MIN,
		ANT_TELEMETRY_RING_MIN, &heads[2], &short_message, "x");
	for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
		assert(!ant_read_ordered(client, data, sizeof(data), &len, 0));
		key = 0;
		if (len == 16)
			memcpy(&key, data, sizeof(key));
		assert(key == order[i] && (len == 16 || (len == 1 && !order[i])));
	}
	assert(ant_read_ordered(client, data, sizeof(data), &len, 0) == -EAGAIN);
	assert(ant_read_ordered(client, data, sizeof(data), &len, ANT_MAX_MESSAGE_LEN) == -EINVAL);
	ant_close(client);
	cleanup(&f);
}

/* ABI 10 with POS32 (a 32-bit guest): only the low words of positions,
 * nonces and counters travel. Positions start just below 2^32, so the first
 * message wraps both the ring and the 32-bit position. */
static void test_pos32(void)
{
	struct fixture f;
	struct ant_client *client;
	struct ant_stats stats;
	struct ant_message telemetry = { .payload_len = 5 };
	pthread_t thread;
	__u64 head = 0xfffffff0ULL;
	uint64_t id;
	size_t len;
	char data[8];
	static const unsigned rejected[][2] = { { 10, ANT_PROFILE_POS32 }, { 9, 3 }, { 11, 1 } };
	unsigned i;

	for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
		setup(&f, rejected[i][0]);
		f.boot->profile = rejected[i][1];
		assert(ant_init(&f.options, &client) == -EPROTO);
		cleanup(&f);
	}
	setup(&f, ANT_ABI_WIRE_LE);
	f.boot->profile = ANT_PROFILE_LP64 | ANT_PROFILE_POS32;
	f.region->directory[0].head = f.region->directory[0].tail = head;
	f.region->control.requests.head = f.region->control.requests.tail = 0xfffffff8ULL;
	assert(!pthread_create(&thread, NULL, ack_thread, &f));
	assert(!ant_init(&f.options, &client));
	assert(!pthread_join(thread, NULL));
	/* The nonce is a 32-bit value; the high word of every moving field stays zero. */
	assert(f.boot->owner && f.boot->owner <= UINT32_MAX);
	assert(!ant_heartbeat(client) && f.region->control.host_heartbeat <= UINT32_MAX);
	f.region->directory[0].attempted = 0x100000007ULL;	/* only the low word counts */
	ant_publish(&f.region->directory[0], ANT_PROFILE_LP64 | ANT_PROFILE_POS32,
		(char *)f.ram + (4U << 20), ANT_TELEMETRY_RING_MIN, &head, &telemetry, "hello");
	assert(head == 0x100000018ULL && f.region->directory[0].head == 0x18);
	assert(!ant_read(client, data, sizeof(data), &len) && len == 5 && !memcmp(data, "hello", 5));
	assert(f.region->directory[0].tail == 0x18);
	assert(ant_read(client, data, sizeof(data), &len) == -EAGAIN);
	assert(!ant_get_stats(client, &stats) && stats.abi == ANT_ABI_WIRE_LE && stats.attempted == 7);
	assert(!ant_command_send(client, 42, "x", 1, &id) && id == 1);
	assert(f.region->control.requests.head == 0x20);
	ant_close(client);
	cleanup(&f);
}

int main(void)
{
	test_pos32();
	test_ordered_reads();
	test_resume();
	test_geometry();
	test_ack_failure();
	test_legacy(7);
	test_legacy(8);
	puts("TRANSPORT RECONNECT PASS (host simulator)");
	return 0;
}
