/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ANTINOMIE_QUEUE_H
#define ANTINOMIE_QUEUE_H
#include "abi.h"
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/barrier.h>
#define ANT_ACQ(p) virt_load_acquire(p)
#define ANT_REL(p, v) virt_store_release(p, v)
#else
#include <errno.h>
#include <string.h>
#define ANT_ACQ(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ANT_REL(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#endif

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
static inline int ant_space(struct ant_queue *q, __u32 size, __u64 head,
			    __u64 *cached_tail, __u64 span)
{
	__u64 tail = ANT_ACQ(&q->tail);
	if ((tail & 7) || (head & 7) || tail < *cached_tail || tail > head || head - tail > size)
		return -EPROTO;
	*cached_tail = tail;
	if (head > (~0ULL) - span) return -EOVERFLOW;
	return span <= size - (head - tail) ? 0 : -ENOSPC;
}

static inline void ant_publish(struct ant_queue *q, void *ring, __u32 size,
			       __u64 *head, const struct ant_message *msg, const void *data)
{
	__u64 zero = 0, span = ant_span(msg->payload_len);
	ant_copy_in(ring, size, *head, msg, sizeof(*msg));
	ant_copy_in(ring, size, *head + sizeof(*msg), data, msg->payload_len);
	ant_copy_in(ring, size, *head + sizeof(*msg) + msg->payload_len, &zero,
		    span - sizeof(*msg) - msg->payload_len);
	*head += span;
	ANT_REL(&q->head, *head);
}

static inline int ant_peek(struct ant_queue *q, const void *ring, __u32 size,
			   __u32 limit, __u64 tail, __u64 *seen_head,
			   struct ant_message *msg)
{
	__u64 head = ANT_ACQ(&q->head);
	if ((head & 7) || (tail & 7) || head < *seen_head || head < tail || head - tail > size) return -EPROTO;
	*seen_head = head;
	if (head == tail) return -EAGAIN;
	if (head - tail < sizeof(*msg)) return -EPROTO;
	ant_copy_out(ring, size, tail, msg, sizeof(*msg));
	if (msg->payload_len > limit || msg->flags || msg->reserved ||
	    ant_span(msg->payload_len) > head - tail) return -EPROTO;
	return 0;
}
#endif
