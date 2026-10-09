/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#ifndef ANTINOMIE_HOST_API_H
#define ANTINOMIE_HOST_API_H
#include <stddef.h>
#include <stdint.h>

struct ant_client;
/* All sizes/offsets are bytes. Layout is immutable for the client lifetime. */
struct ant_backing {
	const char *path;
	uint64_t size;
};
struct ant_memory_region {
	uint64_t gpa, size, file_offset;
	uint32_t backing_index;
};
enum ant_poll_mode {
	ANT_POLL_SLEEP, ANT_POLL_BUSY, ANT_POLL_ADAPTIVE,
};
struct ant_options {
	const struct ant_backing *backings;
	size_t backing_count;
	const struct ant_memory_region *regions;
	size_t region_count;
	uint64_t ram_size, bootstrap_gpa;
	int init_timeout_ms; /* Positive; zero selects 30 seconds. */
	int health_timeout_ms; /* Positive; zero selects 10 seconds. */
	uint32_t host_timeout_ms; /* Guest watchdog: 1..60000; zero selects 250 ms. */
	enum ant_poll_mode poll_mode; /* Zero selects consistent sleeping. */
	uint32_t poll_sleep_us; /* 1..10000; zero selects 50 us. */
	uint32_t poll_spin_us; /* Adaptive only: 1..10000; zero selects 20 us. */
};
enum { ANT_EVENT_TELEMETRY = 1, ANT_EVENT_RESULT = 2 };
struct ant_stats {
	uint64_t attempted, dropped, bad_commands, reply_stalls;
	uint32_t health, queue_count, live, host_timeout_ms;
	/* ABI 8: sends that waited for room, their total wait, the per-CPU ring
	 * size and the published send wait (ABI 7 guests: 0, 0, 256 KiB, 0). */
	uint64_t waits, wait_ns;
	uint32_t abi, ring_size, send_wait_us, reserved;
};
struct ant_limits { size_t max_message_len, max_command_len, max_result_len; };

/* One owning thread per client. Different clients are independent.
 * Every function returns zero/success, an event mask, or negative errno.
 * A client owns one boot session; close does not clear queues or allow reattach.
 */
int ant_init(const struct ant_options *options, struct ant_client **out_client);
void ant_close(struct ant_client *client);
int ant_poll(struct ant_client *client, int timeout_ms);
int ant_read(struct ant_client *client, void *dst, size_t capacity, size_t *payload_len);
int ant_command_send(struct ant_client *client, uint32_t opcode,
		const void *args, size_t payload_len, uint64_t *request_id);
int ant_result_read(struct ant_client *client, uint64_t *request_id,
		int32_t *command_status, void *dst, size_t capacity, size_t *payload_len);
int ant_get_stats(struct ant_client *client, struct ant_stats *stats);
int ant_get_limits(struct ant_client *client, struct ant_limits *limits);
/* Local configuration publication, not acknowledgement of guest application. */
int ant_set_host_timeout(struct ant_client *client, uint32_t timeout_ms);
/* How long (0..10000000 us) a guest send may wait for room in a full ring
 * instead of dropping; 0 drops at once. ABI 7 guests: -EOPNOTSUPP unless 0. */
int ant_set_send_wait(struct ant_client *client, uint32_t wait_us);
/* Only this function may run concurrently with the owner; cancellation is sticky.
 * Join the owner before ant_close. No calls, including cancel, may race close.
 */
void ant_cancel(struct ant_client *client);
#endif
