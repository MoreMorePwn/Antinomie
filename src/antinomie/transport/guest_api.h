/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ANTINOMIE_GUEST_API_H
#define ANTINOMIE_GUEST_API_H
#include <linux/types.h>

/* Task context only. data is valid kernel memory; copied before return.
 * Zero means local acceptance, not delivery. No allocation or sleep on send.
 * A full ring returns -ENOSPC at once, unless the host set a send wait: then
 * the sender spins, preemption off, until room appears, the wait ends or the
 * host stops being live. A zero-length message is valid. Maximum payload
 * length is the smallest ring capacity minus framing (ANT_MAX_MESSAGE_LEN).
 */
int ant_send(const void *data, size_t payload_len);
/* Bytes in each CPU's telemetry ring (antinomie_ring_kib=, or smaller when
 * the requested size could not be allocated at boot). */
u32 ant_ring_size(void);
/* Bytes free in the telemetry ring of the CPU the caller runs on, as of the
 * consumer's last published tail; U32_MAX when sends would fail regardless.
 * Advisory: a caller that can sleep uses it to pace bulk publication.
 */
u32 ant_send_room(void);
/* Whether a send that finds its ring full waits for the host (it set a send
 * wait and is live) instead of failing at once. Advisory, like ant_send_room.
 */
bool ant_send_waits(void);

/* Handlers run in sleepable worker context. No recursive registration changes.
 * reply is transport-owned, valid only during the callback.
 * Set reply_len on success; return zero or a negative errno.
 */
typedef int (*ant_command_handler)(const void *args, size_t args_len,
		void *reply, size_t capacity, size_t *reply_len, void *context);
int ant_register_command(u32 opcode, ant_command_handler handler, void *context);
int ant_unregister_command(u32 opcode);

/* Architecture integration only; consumers must not call these. */
void ant_bootstrap_reserve(void);
bool ant_bootstrap_reserved(void);
u64 ant_bootstrap_gpa(void);
#endif
