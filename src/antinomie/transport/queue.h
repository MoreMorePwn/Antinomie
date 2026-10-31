/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#ifndef ANTINOMIE_QUEUE_H
#define ANTINOMIE_QUEUE_H
#include "abi.h"
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/barrier.h>
#include <asm/byteorder.h>
#define ANT_ACQ(p) virt_load_acquire(p)
#define ANT_REL(p, v) virt_store_release(p, v)
#define ANT_LE32(v) le32_to_cpu((__force __le32)(v))
#define ANT_TO_LE32(v) ((__force __u32)cpu_to_le32(v))
#else
#include <errno.h>
#include <string.h>
#define ANT_ACQ(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ANT_REL(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
/* The host is little endian (x86-64 only). */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little-endian host");
#define ANT_LE32(v) (v)
#define ANT_TO_LE32(v) (v)
#endif

/* A queue position of a ring with this profile (abi.h). With POS32 only the
 * low word travels: the reader widens it next to a position it knows, the
 * peer's being at most a ring's size behind (below) or ahead of (above) it. */
static inline __u64 ant_pos_acquire(__u64 *field, __u32 profile, __u64 known, int above)
{
	__u32 low;

	if (!(profile & ANT_PROFILE_POS32))
		return ANT_ACQ(field);
	low = ANT_LE32(ANT_ACQ((__u32 *)field));
	return above ? known + (__u32)(low - (__u32)known) : known - (__u32)((__u32)known - low);
}

static inline void ant_pos_release(__u64 *field, __u32 profile, __u64 pos)
{
	if (profile & ANT_PROFILE_POS32)
		ANT_REL((__u32 *)field, ANT_TO_LE32((__u32)pos));
	else
		ANT_REL(field, pos);
}

/* Message headers are little endian on the wire: a no-op but on a big-endian
 * guest. */
static inline void ant_message_wire(struct ant_message *msg)
{
#if defined(__KERNEL__) && defined(__BIG_ENDIAN)
	msg->payload_len = (__force __u32)cpu_to_le32(msg->payload_len);
	msg->opcode = (__force __u32)cpu_to_le32(msg->opcode);
	msg->id = (__force __u64)cpu_to_le64(msg->id);
	msg->status = (__force __s32)cpu_to_le32(msg->status);
	msg->flags = (__force __u32)cpu_to_le32(msg->flags);
	msg->reserved = (__force __u64)cpu_to_le64(msg->reserved);
#else
	(void)msg;
#endif
}

static inline __u64 ant_span(__u32 payload_len)
{
	return (sizeof(struct ant_message) + (__u64)payload_len + 7) & ~7ULL;
}

static inline void ant_copy_in(void *ring, __u32 size, __u64 pos,
			       const void *src, __u32 payload_len)
{
	__u32 off = pos & (size - 1), first = size - off;
	if (first > payload_len) first = payload_len;
	if (first) memcpy((char *)ring + off, src, first);
	if (payload_len > first) memcpy(ring, (const char *)src + first, payload_len - first);
}

static inline void ant_copy_out(const void *ring, __u32 size, __u64 pos,
				void *dst, __u32 payload_len)
{
	__u32 off = pos & (size - 1), first = size - off;
	if (first > payload_len) first = payload_len;
	if (first) memcpy(dst, (const char *)ring + off, first);
	if (payload_len > first) memcpy((char *)dst + first, ring, payload_len - first);
}

/* Private counters are authoritative; never accept a peer-written geometry. */
static inline int ant_space(struct ant_queue *q, __u32 profile, __u32 size, __u64 head,
			    __u64 *cached_tail, __u64 span)
{
	__u64 tail = ant_pos_acquire(&q->tail, profile, head, 0);
	if ((tail & 7) || (head & 7) || tail < *cached_tail || tail > head || head - tail > size)
		return -EPROTO;
	*cached_tail = tail;
	if (head > (~0ULL) - span) return -EOVERFLOW;
	return span <= size - (head - tail) ? 0 : -ENOSPC;
}

static inline void ant_publish(struct ant_queue *q, __u32 profile, void *ring, __u32 size,
			       __u64 *head, const struct ant_message *msg, const void *data)
{
	__u64 zero = 0, span = ant_span(msg->payload_len);
#if defined(__KERNEL__) && defined(__BIG_ENDIAN)
	struct ant_message wire = *msg;

	ant_message_wire(&wire);
	ant_copy_in(ring, size, *head, &wire, sizeof(wire));
#else
	ant_copy_in(ring, size, *head, msg, sizeof(*msg));
#endif
	ant_copy_in(ring, size, *head + sizeof(*msg), data, msg->payload_len);
	ant_copy_in(ring, size, *head + sizeof(*msg) + msg->payload_len, &zero,
		    span - sizeof(*msg) - msg->payload_len);
	*head += span;
	ant_pos_release(&q->head, profile, *head);
}

static inline int ant_peek(struct ant_queue *q, __u32 profile, const void *ring, __u32 size,
			   __u32 limit, __u64 tail, __u64 *seen_head,
			   struct ant_message *msg)
{
	__u64 head = ant_pos_acquire(&q->head, profile, tail, 1);
	if ((head & 7) || (tail & 7) || head < *seen_head || head < tail || head - tail > size) return -EPROTO;
	*seen_head = head;
	if (head == tail) return -EAGAIN;
	if (head - tail < sizeof(*msg)) return -EPROTO;
	ant_copy_out(ring, size, tail, msg, sizeof(*msg));
	ant_message_wire(msg);
	if (msg->payload_len > limit || msg->flags || msg->reserved ||
	    ant_span(msg->payload_len) > head - tail) return -EPROTO;
	return 0;
}
#endif
