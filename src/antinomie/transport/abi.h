/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#ifndef ANTINOMIE_TRANSPORT_ABI_H
#define ANTINOMIE_TRANSPORT_ABI_H
#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/antinomie_boot.h>
#else
#include "bootstrap_layout.h"
#endif

/* Wire profile: x86-64, little endian. Memory translation is supplied by host. */
#define ANT_MAGIC 0x354e5441U
#define ANT_ABI 7U
#define ANT_MAX_CPUS 256U
#define ANT_CONTROL_SIZE 1048576U
#define ANT_REQUEST_OFFSET 4096U
#define ANT_RESPONSE_OFFSET (ANT_REQUEST_OFFSET + ANT_COMMAND_RING_SIZE)
#define ANT_DIRECTORY_OFFSET (ANT_RESPONSE_OFFSET + ANT_COMMAND_RING_SIZE)
#define ANT_COMMAND_RING_SIZE 262144U
#define ANT_TELEMETRY_RING_SIZE 262144U
#define ANT_MAX_MESSAGE_LEN (ANT_TELEMETRY_RING_SIZE - 32U)
#define ANT_MAX_COMMAND_LEN 16352U
#define ANT_MAX_RESULT_LEN 16352U
#define ANT_POLL_MS 10U
#define ANT_HOST_TIMEOUT_DEFAULT_MS 250U
#define ANT_HOST_TIMEOUT_MAX_MS 60000U
#define ANT_HEALTH_OVERFLOW 1U
#define ANT_HEALTH_BAD_COMMAND 2U
#define ANT_HEALTH_REPLY_FULL 4U
#define ANT_HEALTH_RING_FAULT 8U
#define ANT_HEALTH_HOST_STALE 16U
#define ANT_HEALTH_BAD_CONFIG 32U

struct ant_boot {
	__u32 magic, version;
	__u64 session, control_gpa;
	__u32 control_size, profile;
	__u8 pad[32];
	__u64 owner;
	__u8 owner_pad[56];
} __attribute__((aligned(64)));

/* Descriptor, producer and consumer each occupy their own cache line. */
struct ant_queue {
	__u64 data_gpa;
	__u32 data_size, cpu_id;
	__u8 descriptor_pad[48];
	__u64 head, attempted, dropped;
	__u32 fault;
	__u8 producer_pad[36];
	__u64 tail;
	__u8 consumer_pad[56];
} __attribute__((aligned(64)));

struct ant_geometry {
	__u32 magic, version;
	__u64 session;
	__u32 queue_count, max_message_len, max_command_len, size, max_result_len;
	__u8 geometry_pad[28];
};

struct ant_control {
	struct ant_geometry geometry;
	__u64 guest_heartbeat, bad_commands, reply_stalls;
	__u32 health, live;
	__u32 applied_host_timeout_ms;
	__u8 guest_pad[28];
	__u64 host_heartbeat;
	__u32 host_timeout_ms;
	__u8 host_pad[316];
	struct ant_queue requests, responses;
} __attribute__((aligned(64)));

struct ant_region {
	struct ant_control control;
	__u8 control_pad[ANT_REQUEST_OFFSET - sizeof(struct ant_control)];
	__u8 request_data[ANT_COMMAND_RING_SIZE];
	__u8 response_data[ANT_COMMAND_RING_SIZE];
	struct ant_queue directory[ANT_MAX_CPUS];
	__u8 allocation_pad[ANT_CONTROL_SIZE - ANT_DIRECTORY_OFFSET -
		ANT_MAX_CPUS * sizeof(struct ant_queue)];
};

/* All queues carry complete length-delimited messages, aligned to eight bytes. */
struct ant_message {
	__u32 payload_len, opcode;
	__u64 id;
	__s32 status;
	__u32 flags;
	__u64 reserved;
};
#endif
