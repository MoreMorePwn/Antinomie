/* SPDX-License-Identifier: GPL-3.0-only */
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
struct ant_resume_report {
	uint64_t attachment, sequence_floor;
	uint64_t discarded_request_bytes, discarded_reply_bytes;
};

/* One owning thread per client. Different clients are independent.
 * Every function returns zero/success, an event mask, or negative errno.
 * ABI 7/8 own one cold boot; close does not permit their reattachment. ABI 9
 * attaches with a fresh guest-acknowledged nonce while holding backing locks.
 */
int ant_init(const struct ant_options *options, struct ant_client **out_client);
/* Map/validate/lock and publish ABI 9 resume, without waiting for a paused
 * guest. Legacy guests attach normally. Finish ABI 9 before ordinary calls. */
int ant_open_pending(const struct ant_options *options, struct ant_client **out_client);
/* Sole owner only; no normal calls between begin and finish. Does not replay
 * commands. In-flight side effects have unknown outcomes after reconnect.
 * ABI 7/8: -EOPNOTSUPP. Cancel remains sticky. Layout/session must match. */
int ant_resume_begin(struct ant_client *client);
/* timeout_ms: 0 selects 30 seconds; negative is invalid. A timeout leaves the
 * handle pending; close it or finish later, never retry abandoned commands.
 * Preserves telemetry rings/counters; reports discarded command queue bytes. */
int ant_resume_finish(struct ant_client *client, int timeout_ms,
		struct ant_resume_report *report);
/* Explicit QMP pause lifecycle: block ordinary calls (and their RAM writes),
 * then resume liveness observation without allowing heartbeat rollback or
 * legacy reattachment. Sole owner only. Resume may fail on stale geometry. */
int ant_suspend_heartbeats(struct ant_client *client);
int ant_resume_heartbeats(struct ant_client *client);
void ant_close(struct ant_client *client);
int ant_poll(struct ant_client *client, int timeout_ms);
int ant_read(struct ant_client *client, void *dst, size_t capacity, size_t *payload_len);
/* As ant_read, but from the ring whose head message has the smallest
 * little-endian u64 at payload offset key_offset (a payload too short for it
 * counts as 0): rings whose messages carry a key that grows along each ring,
 * such as a timestamp, are read merged in key order. */
int ant_read_ordered(struct ant_client *client, void *dst, size_t capacity,
		size_t *payload_len, size_t key_offset);
int ant_command_send(struct ant_client *client, uint32_t opcode,
		const void *args, size_t payload_len, uint64_t *request_id);
int ant_result_read(struct ant_client *client, uint64_t *request_id,
		int32_t *command_status, void *dst, size_t capacity, size_t *payload_len);
int ant_get_stats(struct ant_client *client, struct ant_stats *stats);
/* Immutable limits may also be queried on a pending attachment. */
int ant_get_limits(struct ant_client *client, struct ant_limits *limits);
/* Local configuration publication, not acknowledgement of guest application. */
int ant_set_host_timeout(struct ant_client *client, uint32_t timeout_ms);
/* Refresh the host heartbeat and check the guest, like any other call, for an
 * owner that is busy elsewhere (for example waiting on its disk). */
int ant_heartbeat(struct ant_client *client);
/* The guest is paused on purpose (QEMU writing a memory dump): its heartbeat
 * is not expected to move, so the guest liveness check is suspended. Resuming
 * (paused = 0) restarts the liveness window from now. */
int ant_set_guest_paused(struct ant_client *client, int paused);
/* How long (0..10000000 us) a guest send may wait for room in a full ring
 * instead of dropping; 0 drops at once. ABI 7 guests: -EOPNOTSUPP unless 0. */
int ant_set_send_wait(struct ant_client *client, uint32_t wait_us);
/* Only this function may run concurrently with the owner; cancellation is sticky.
 * Join the owner before ant_close. No calls, including cancel, may race close.
 */
void ant_cancel(struct ant_client *client);
#endif
