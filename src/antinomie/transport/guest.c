// SPDX-License-Identifier: GPL-2.0-only
#include <linux/antinomie.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/sched/clock.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "queue.h"
#include "process_core.h"
#include "debug.h"

/* The longest a sender that may not sleep spins for room in a full ring, whatever
 * wait the host asked for: it holds a CPU, and with interrupts off a spin of
 * milliseconds is a hard-lockup report. A sender that may sleep waits for the
 * host's full allowance.
 */
#define ANT_SEND_ATOMIC_WAIT_US 200U

/* The transport this guest announces (abi.h). A 64-bit little-endian guest
 * announces ABI 9 and every word below is a native access, exactly as before
 * ABI 10 existed. Any other guest announces ABI 10: every field little endian
 * and, on a 32-bit guest (POS32), each moving 64-bit word (position,
 * heartbeat, nonce, sequence, counter: MOV_*) carried as its low 32 bits.
 * W64 is a 64-bit value written once before the boot block is published.
 */
#if BITS_PER_LONG == 64 && defined(__LITTLE_ENDIAN)
#define ANT_GUEST_ABI ANT_ABI
#define ANT_GUEST_PROFILE ANT_PROFILE_LP64
#define MOV_ACQ(p) ANT_ACQ(p)
#define MOV_REL(p, v) ANT_REL(p, v)
#define MOV_READ(p) READ_ONCE(*(p))
#define MOV_ONCE(p, v) WRITE_ONCE(*(p), v)
#define MOV_GET(p) (*(p))
#define MOV_SET(p, v) (*(p) = (v))
#define MOV_INC(p) ((*(p))++)
#define W64_SET(p, v) (*(p) = (v))
#define W64_GET(p) (*(p))
#define W32_ACQ(p) ANT_ACQ(p)
#define W32_READ(p) READ_ONCE(*(p))
#define W32_ONCE(p, v) WRITE_ONCE(*(p), v)
#define W32_GET(p) (*(p))
#define W32_SET(p, v) (*(p) = (v))
#define W32_OR(p, v) (*(p) |= (v))
#else
#define ANT_GUEST_ABI ANT_ABI_WIRE_LE
#if BITS_PER_LONG == 32
#define ANT_GUEST_PROFILE (ANT_PROFILE_LP64 | ANT_PROFILE_POS32)
#define MOV_WORD(p) ((u32 *)(p))
#define MOV_ACQ(p) ((u64)le32_to_cpu((__force __le32)ANT_ACQ(MOV_WORD(p))))
#define MOV_REL(p, v) ANT_REL(MOV_WORD(p), (__force u32)cpu_to_le32((u32)(v)))
#define MOV_READ(p) ((u64)le32_to_cpu((__force __le32)READ_ONCE(*MOV_WORD(p))))
#define MOV_ONCE(p, v) WRITE_ONCE(*MOV_WORD(p), (__force u32)cpu_to_le32((u32)(v)))
#else
#define ANT_GUEST_PROFILE ANT_PROFILE_LP64
#define MOV_ACQ(p) le64_to_cpu((__force __le64)ANT_ACQ(p))
#define MOV_REL(p, v) ANT_REL(p, (__force u64)cpu_to_le64(v))
#define MOV_READ(p) le64_to_cpu((__force __le64)READ_ONCE(*(p)))
#define MOV_ONCE(p, v) WRITE_ONCE(*(p), (__force u64)cpu_to_le64(v))
#endif
#define MOV_GET(p) MOV_READ(p)
#define MOV_SET(p, v) MOV_ONCE(p, v)
#define MOV_INC(p) MOV_SET(p, MOV_GET(p) + 1)
#define W64_SET(p, v) (*(p) = (__force u64)cpu_to_le64(v))
#define W64_GET(p) le64_to_cpu((__force __le64)*(p))
#define W32_ACQ(p) le32_to_cpu((__force __le32)ANT_ACQ(p))
#define W32_READ(p) le32_to_cpu((__force __le32)READ_ONCE(*(p)))
#define W32_ONCE(p, v) WRITE_ONCE(*(p), (__force u32)cpu_to_le32(v))
#define W32_GET(p) le32_to_cpu((__force __le32)*(p))
#define W32_SET(p, v) (*(p) = (__force u32)cpu_to_le32(v))
#define W32_OR(p, v) W32_SET(p, W32_GET(p) | (v))
#endif

struct ant_cpu {
	struct page *pages;
	void *data;
};
/* One per CPU, used with preemption off. A sender that must wait for room
 * takes a turn (next_ticket) and stays on its CPU until serving reaches it.
 * Allocated at setup (alloc_percpu), not in the static per-CPU section: a
 * static one would move every later per-CPU variable of the kernel (their
 * offsets are in its BTF).
 */
struct ant_producer {
	u64 head, cached_tail, attempted, dropped, waits, wait_ns;
	u32 index, next_ticket, serving;
	bool fault;
};
static struct ant_producer __percpu *producers;
static struct ant_cpu *cpus;
static struct ant_control *control;
static struct ant_queue *directory;
static struct ant_region *region;
static struct ant_boot *boot;
static u32 queue_count;
static u32 ring_size = ANT_TELEMETRY_RING_DEFAULT;
static bool ready, broken;
static struct workqueue_struct *worker;
static void control_tick(struct work_struct *work);
static DECLARE_DELAYED_WORK(control_work, control_tick);

struct ant_handler {
	u32 opcode;
	ant_command_handler fn;
	void *context;
};
static struct ant_handler handlers[64];
static DECLARE_RWSEM(handler_lock);
static u8 command_args[ANT_MAX_COMMAND_LEN], command_result[ANT_MAX_RESULT_LEN];
static u64 last_request_id;
static u64 request_tail, request_head_seen, response_head, response_tail_seen;
static u64 last_heartbeat;
static unsigned long host_seen;
static bool host_attached;

/* Only the ordered control worker writes command cursors and the ack. The
 * host holds all RAM backing file locks and publishes no commands until ack.
 * This deliberately does not touch any per-CPU telemetry producer state.
 */
static bool service_resume(void)
{
	u64 nonce = MOV_ACQ(&boot->resume_request);
	u64 cursor, seen, head, reply_tail, floor;
	int error = 0;

	if (!nonce || nonce == MOV_ACQ(&boot->resume_ack))
		return false;
	/* Fence acknowledgment waits until manual acquisition owns no parks.
	 * Completed immutable evidence remains retained across reattachment.
	 */
	if (!ant_manual_fence() || !ant_debug_fence())
		return true;
	floor = max(last_request_id, MOV_ACQ(&boot->resume_sequence_floor));
	cursor = request_tail;
	seen = request_head_seen;
	head = ant_pos_acquire(&control->requests.head, ANT_GUEST_PROFILE, cursor, 1);
	reply_tail = ant_pos_acquire(&control->responses.tail, ANT_GUEST_PROFILE, response_head, 0);
	if (broken || (head & 7) || head < cursor || head - cursor > ANT_COMMAND_RING_SIZE ||
	    (reply_tail & 7) || reply_tail > response_head ||
	    response_head - reply_tail > ANT_COMMAND_RING_SIZE) {
		error = -EPROTO;
		goto acknowledge;
	}
	while (cursor != head) {
		struct ant_message req;

		error = ant_peek(&control->requests, ANT_GUEST_PROFILE, region->request_data,
			ANT_COMMAND_RING_SIZE, ANT_MAX_COMMAND_LEN, cursor, &seen, &req);
		if (error || !req.id || !req.opcode || req.status) {
			error = -EPROTO;
			goto acknowledge;
		}
		floor = max(floor, req.id);
		cursor += ant_span(req.payload_len);
	}
	MOV_SET(&boot->discarded_request_bytes, head - request_tail);
	MOV_SET(&boot->discarded_reply_bytes, response_head - reply_tail);
	request_tail = head;
	request_head_seen = head;
	last_request_id = floor;
	ant_pos_release(&control->requests.tail, ANT_GUEST_PROFILE, request_tail);
	/* A new heartbeat establishes liveness independently of rolled-back time. */
	host_seen = jiffies;
	last_heartbeat = MOV_ACQ(&control->host_heartbeat);
	host_attached = true;
	MOV_REL(&boot->owner, nonce);
acknowledge:
	if (error) {
		broken = true;
		W32_OR(&control->health, ANT_HEALTH_RING_FAULT);
		MOV_SET(&boot->discarded_request_bytes, 0);
		MOV_SET(&boot->discarded_reply_bytes, 0);
	}
	MOV_SET(&boot->resume_sequence_ack, floor);
	W32_SET((u32 *)&boot->resume_status, (u32)error);
	MOV_REL(&boot->resume_ack, nonce);
	return true;
}

/* antinomie_ring_kib=<KiB>: per-CPU telemetry ring size, a power of two. */
static int __init ant_ring_param(char *arg)
{
	u32 kib;

	if (kstrtou32(arg, 0, &kib) || !is_power_of_2(kib) ||
	    kib < ANT_TELEMETRY_RING_MIN / 1024 || kib > ANT_TELEMETRY_RING_MAX / 1024) {
		pr_warn("antinomie: ignoring antinomie_ring_kib=%s\n", arg);
		return 0;
	}
	ring_size = kib * 1024;
	return 0;
}
early_param("antinomie_ring_kib", ant_ring_param);

u32 ant_ring_size(void)
{
	return ring_size;
}

int ant_send(const void *data, size_t payload_len)
{
	struct ant_producer *p;
	struct ant_queue *q;
	struct ant_message msg = { .payload_len = payload_len };
	u64 waited_from = 0, progress_at = 0, tail = 0, now;
	u32 wait_us, ticket = 0;
	bool may_sleep, queued = false;
	int error;

	if (!in_task()) return -EWOULDBLOCK;
	if (payload_len > ANT_MAX_MESSAGE_LEN) return -EMSGSIZE;
	if (!data && payload_len) return -EINVAL;
	if (!smp_load_acquire(&ready)) return -ENOTCONN;
	preempt_disable();
	p = this_cpu_ptr(producers);
	q = &directory[p->index];
	p->attempted++;
	if (p->fault) {
		error = -EPROTO;
		goto drop;
	}
	may_sleep = preempt_count() == 1 && !irqs_disabled() && !rcu_preempt_depth();
	for (;;) {
		/* Room freed while senders wait is theirs, in turn: a sender that
		 * may sleep and finds others waiting queues behind them instead of
		 * taking it. One that may not sleep never queues; it takes room
		 * when there is some. */
		if (!queued && may_sleep && p->serving != p->next_ticket)
			error = -ENOSPC;
		else if (queued && ticket != p->serving)
			error = -ENOSPC;
		else
			error = ant_space(q, ANT_GUEST_PROFILE, ring_size, p->head, &p->cached_tail,
					  ant_span(payload_len));
		if (error != -ENOSPC)
			break;
		/* The host may ask senders to wait for room instead of dropping,
		 * only while it is live and keeps reading this ring: the wait ends
		 * when the host has taken nothing from it for the whole send wait.
		 * A sender that may sleep sleeps on this CPU, so the control worker
		 * and other tasks keep running; one in atomic context spins, and
		 * only briefly. */
		wait_us = min_t(u32, W32_READ(&control->send_wait_us), ANT_SEND_WAIT_MAX_US);
		if (!may_sleep)
			wait_us = min_t(u32, wait_us, ANT_SEND_ATOMIC_WAIT_US);
		now = local_clock();
		if (!waited_from) {
			waited_from = progress_at = now;
			tail = ant_pos_acquire(&q->tail, ANT_GUEST_PROFILE, p->head, 0);
			p->waits++;
		} else if (ant_pos_acquire(&q->tail, ANT_GUEST_PROFILE, p->head, 0) != tail) {
			tail = ant_pos_acquire(&q->tail, ANT_GUEST_PROFILE, p->head, 0);
			progress_at = now;
		}
		if (!wait_us || !W32_READ(&control->live) ||
		    now - progress_at >= (u64)wait_us * NSEC_PER_USEC) {
			/* A queued sender gives up in its turn, so the ones behind it
			 * keep theirs; they see the same dead host or idle ring. */
			if (!queued || ticket == p->serving) {
				error = -ENOSPC;
				break;
			}
		}
		if (may_sleep) {
			if (!queued) {
				/* Stay on this CPU while asleep: the turn is this
				 * ring's. */
				ticket = p->next_ticket++;
				queued = true;
				migrate_disable();
			}
			/* Only our own preempt_disable is held. */
			MOV_ONCE(&q->attempted, p->attempted);
			MOV_ONCE(&q->waits, p->waits);
			preempt_enable();
			usleep_range(50, 100);
			preempt_disable();
			if (p->fault) {
				error = -EPROTO;
				break;
			}
			continue;
		}
		cpu_relax();
	}
	if (queued)
		p->serving++;
	if (waited_from) {
		p->wait_ns += local_clock() - waited_from;
		MOV_ONCE(&q->waits, p->waits);
		MOV_ONCE(&q->wait_ns, p->wait_ns);
	}
	if (error) {
		if (error != -ENOSPC) {
			p->fault = true;
			W32_ONCE(&q->fault, -error);
		}
		goto drop;
	}
	ant_publish(q, ANT_GUEST_PROFILE, cpus[p->index].data, ring_size, &p->head, &msg, data);
	goto out;
drop:
	p->dropped++;
out:
	MOV_ONCE(&q->attempted, p->attempted);
	MOV_ONCE(&q->dropped, p->dropped);
	preempt_enable();
	if (queued)
		migrate_enable();
	return error;
}

u32 ant_send_room(void)
{
	struct ant_producer *p;
	struct ant_queue *q;
	u64 tail;
	u32 room = U32_MAX;

	/* Pairs with the release that publishes the rings at setup. */
	if (!smp_load_acquire(&ready))
		return room;
	preempt_disable();
	p = this_cpu_ptr(producers);
	q = &directory[p->index];
	tail = ant_pos_acquire(&q->tail, ANT_GUEST_PROFILE, p->head, 0);
	if (!p->fault && tail <= p->head && p->head - tail <= ring_size)
		room = ring_size - (p->head - tail);
	preempt_enable();
	return room;
}

bool ant_send_waits(void)
{
	/* Pairs with the release that publishes the rings at setup. */
	return smp_load_acquire(&ready) && W32_READ(&control->send_wait_us) &&
		W32_READ(&control->live);
}

int ant_register_command(u32 opcode, ant_command_handler fn, void *context)
{
	int i, free_slot = -1, error = -ENOSPC;
	if (!opcode || !fn) return -EINVAL;
	if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
	down_write(&handler_lock);
	for (i = 0; i < ARRAY_SIZE(handlers); i++) {
		if (handlers[i].opcode == opcode) {
			error = -EEXIST;
			goto out;
		}
		if (!handlers[i].fn) free_slot = i;
	}
	if (free_slot >= 0) {
		handlers[free_slot] = (struct ant_handler){ opcode, fn, context };
		error = 0;
	}
out:
	up_write(&handler_lock);
	return error;
}

int ant_unregister_command(u32 opcode)
{
	int i, error = -ENOENT;
	if (!opcode) return -EINVAL;
	if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
	down_write(&handler_lock);
	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (handlers[i].opcode == opcode) {
			memset(&handlers[i], 0, sizeof(handlers[i]));
			error = 0;
			break;
		}
	up_write(&handler_lock);
	return error;
}

static int dispatch(const struct ant_message *req, size_t *payload_len)
{
	int i, error = -EOPNOTSUPP;
	down_read(&handler_lock);
	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (handlers[i].fn && handlers[i].opcode == req->opcode) {
			error = handlers[i].fn(command_args, req->payload_len, command_result,
					     ANT_MAX_RESULT_LEN, payload_len, handlers[i].context);
			break;
		}
	up_read(&handler_lock);
	if (*payload_len > ANT_MAX_RESULT_LEN || error > 0) error = -EOVERFLOW;
	if (error) *payload_len = 0;
	return error;
}

static void service_commands(void)
{
	unsigned int budget;
	if (broken) return;
	for (budget = 0; budget < 16; budget++) {
		struct ant_message req, resp = { 0 };
		size_t payload_len = 0;
		int error;

		/* A request arriving during a sleeping handler is fenced before the
		 * next handler. Already executing effects are not retried or undone.
		 */
		if (service_resume())
			return;
		error = ant_peek(&control->requests, ANT_GUEST_PROFILE, region->request_data,
			ANT_COMMAND_RING_SIZE, ANT_MAX_COMMAND_LEN, request_tail, &request_head_seen, &req);
		if (error == -EAGAIN) return;
		if (error) goto fault;
		/* Reserve worst-case result space before invoking any side effect. */
		error = ant_space(&control->responses, ANT_GUEST_PROFILE, ANT_COMMAND_RING_SIZE, response_head,
			&response_tail_seen, ant_span(ANT_MAX_RESULT_LEN));
		if (error == -ENOSPC) {
			MOV_INC(&control->reply_stalls);
			W32_OR(&control->health, ANT_HEALTH_REPLY_FULL);
			return;
		}
		if (error) goto fault;
		ant_copy_out(region->request_data, ANT_COMMAND_RING_SIZE,
			request_tail + sizeof(req), command_args, req.payload_len);
		resp.id = req.id;
		resp.opcode = req.opcode;
		if (!req.id || !req.opcode || req.status) resp.status = -EPROTO;
		else if (req.id <= last_request_id) resp.status = -ESTALE;
		else {
			last_request_id = req.id;
			/* Zero output so a buggy handler cannot expose old kernel bytes. */
			memset(command_result, 0, sizeof(command_result));
			resp.status = dispatch(&req, &payload_len);
			resp.payload_len = payload_len;
		}
		if (resp.status) {
			MOV_INC(&control->bad_commands);
			W32_OR(&control->health, ANT_HEALTH_BAD_COMMAND);
		}
		ant_publish(&control->responses, ANT_GUEST_PROFILE, region->response_data, ANT_COMMAND_RING_SIZE,
			    &response_head, &resp, command_result);
		request_tail += ant_span(req.payload_len);
		ant_pos_release(&control->requests.tail, ANT_GUEST_PROFILE, request_tail);
	}
	return;
fault:
	broken = true;
	W32_OR(&control->health, ANT_HEALTH_RING_FAULT);
}

static void control_tick(struct work_struct *work)
{
	u64 heartbeat = MOV_ACQ(&control->host_heartbeat);
	u32 timeout_ms = W32_ACQ(&control->host_timeout_ms);
	u32 i;
	service_resume();
	if (!timeout_ms) timeout_ms = ANT_HOST_TIMEOUT_DEFAULT_MS;
	if (timeout_ms > ANT_HOST_TIMEOUT_MAX_MS) {
		W32_OR(&control->health, ANT_HEALTH_BAD_CONFIG);
		timeout_ms = W32_GET(&control->applied_host_timeout_ms);
	}
	W32_ONCE(&control->applied_host_timeout_ms, timeout_ms);
	if (heartbeat != last_heartbeat) {
		last_heartbeat = heartbeat;
		host_seen = jiffies;
		host_attached = true;
	}
	W32_SET(&control->live, host_attached && time_before(jiffies, host_seen + msecs_to_jiffies(timeout_ms)));
	if (host_attached && !W32_GET(&control->live)) W32_OR(&control->health, ANT_HEALTH_HOST_STALE);
	for (i = 0; i < queue_count; i++) {
		if (MOV_READ(&directory[i].dropped)) W32_OR(&control->health, ANT_HEALTH_OVERFLOW);
		if (W32_READ(&directory[i].fault)) W32_OR(&control->health, ANT_HEALTH_RING_FAULT);
	}
	service_commands();
	MOV_REL(&control->guest_heartbeat, MOV_GET(&control->guest_heartbeat) + 1);
	/* While a debugger is attached, or a finished process core is being read,
	 * every request is a round trip the user waits for: poll at the next tick
	 * instead of every ANT_POLL_MS.
	 */
	queue_delayed_work(worker, &control_work,
			   ant_debug_active() || ant_core_reading() ?
			   1 : msecs_to_jiffies(ANT_POLL_MS));
}

static int __init ant_guest_init(void)
{
	struct page *pages;
	u32 cpu, index = 0;
	int error = -ENOMEM;
	BUILD_BUG_ON(sizeof(struct ant_queue) != 192);
	BUILD_BUG_ON(sizeof(struct ant_boot) != 256);
	BUILD_BUG_ON(offsetof(struct ant_boot, resume_request) != 128);
	BUILD_BUG_ON(offsetof(struct ant_boot, resume_ack) != 192);
	BUILD_BUG_ON(sizeof(struct ant_geometry) != 64);
	BUILD_BUG_ON(offsetof(struct ant_control, guest_heartbeat) != 64);
	BUILD_BUG_ON(offsetof(struct ant_control, host_heartbeat) != 128);
	BUILD_BUG_ON(offsetof(struct ant_region, request_data) != ANT_REQUEST_OFFSET);
	BUILD_BUG_ON(offsetof(struct ant_region, response_data) != ANT_RESPONSE_OFFSET);
	BUILD_BUG_ON(offsetof(struct ant_region, directory) != ANT_DIRECTORY_OFFSET);
	BUILD_BUG_ON(sizeof(struct ant_region) != ANT_CONTROL_SIZE);
	BUILD_BUG_ON(sizeof(struct ant_message) != 32);
	BUILD_BUG_ON(offsetof(struct ant_control, requests) != 512);
	BUILD_BUG_ON(sizeof(struct ant_control) > ANT_REQUEST_OFFSET);
	BUILD_BUG_ON(ANT_REQUEST_OFFSET + ANT_COMMAND_RING_SIZE > ANT_RESPONSE_OFFSET);
	BUILD_BUG_ON(ANT_RESPONSE_OFFSET + ANT_COMMAND_RING_SIZE > ANT_DIRECTORY_OFFSET);
	BUILD_BUG_ON(ANT_MAX_COMMAND_LEN + sizeof(struct ant_message) > ANT_COMMAND_RING_SIZE);
	BUILD_BUG_ON(ANT_MAX_RESULT_LEN + sizeof(struct ant_message) > ANT_COMMAND_RING_SIZE);
	BUILD_BUG_ON(ANT_DIRECTORY_OFFSET + ANT_MAX_CPUS * sizeof(struct ant_queue) > ANT_CONTROL_SIZE);
	if (!ant_bootstrap_reserved()) return -ENXIO;
	boot = phys_to_virt(ant_bootstrap_gpa());
	memset(boot, 0, ANT_BOOT_SIZE);
	queue_count = num_possible_cpus();
	if (!queue_count || queue_count > ANT_MAX_CPUS) return -E2BIG;
	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(ANT_CONTROL_SIZE));
	if (!pages) return -ENOMEM;
	region = page_address(pages);
	control = &region->control;
	directory = region->directory;
	producers = alloc_percpu(struct ant_producer);
	if (!producers)
		goto free_control;
	cpus = kcalloc(queue_count, sizeof(*cpus), GFP_KERNEL);
	if (!cpus)
		goto free_producers;
	/* Every ring has the same size; when memory is short, try a smaller one. */
retry:
	index = 0;
	for_each_possible_cpu(cpu) {
		cpus[index].pages = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN,
						get_order(ring_size));
		if (!cpus[index].pages) {
			while (index) {
				__free_pages(cpus[--index].pages, get_order(ring_size));
				cpus[index].pages = NULL;
			}
			if (ring_size == ANT_TELEMETRY_RING_MIN)
				goto free_rings;
			ring_size /= 2;
			goto retry;
		}
		cpus[index].data = page_address(cpus[index].pages);
		W64_SET(&directory[index].data_gpa, page_to_phys(cpus[index].pages));
		W32_SET(&directory[index].data_size, ring_size);
		W32_SET(&directory[index].cpu_id, cpu);
		per_cpu_ptr(producers, cpu)->index = index++;
	}
	/*
	 * This worker only polls host commands. It is not a reclaim path,
	 * and a terminal READ reaches n_tty_read, which flushes the ordinary
	 * TTY queue events_unbound. WQ_MEM_RECLAIM makes that flush trip
	 * check_flush_dependency. Flags stay 0 so the worker may complete
	 * the read. The queue stays ordered, so commands, EOF and shutdown
	 * keep one sequence. A worker shows the name of the queue it last ran
	 * work for (kworker/uN:M-name), so it is named like the system's.
	 */
	worker = alloc_ordered_workqueue("events_unbound", 0);
	if (!worker) goto free_rings;
	W32_SET(&control->geometry.version, ANT_GUEST_ABI);
	W64_SET(&control->geometry.session, get_random_u64() ?: 1);
	W32_SET(&control->geometry.size, ANT_CONTROL_SIZE);
	W32_SET(&control->geometry.queue_count, queue_count);
	W32_SET(&control->geometry.max_message_len, ANT_MAX_MESSAGE_LEN);
	W32_SET(&control->geometry.max_command_len, ANT_MAX_COMMAND_LEN);
	W32_SET(&control->geometry.max_result_len, ANT_MAX_RESULT_LEN);
	W32_SET(&control->applied_host_timeout_ms, ANT_HOST_TIMEOUT_DEFAULT_MS);
	W64_SET(&control->requests.data_gpa, page_to_phys(pages) + ANT_REQUEST_OFFSET);
	W32_SET(&control->requests.data_size, ANT_COMMAND_RING_SIZE);
	W64_SET(&control->responses.data_gpa, page_to_phys(pages) + ANT_RESPONSE_OFFSET);
	W32_SET(&control->responses.data_size, ANT_COMMAND_RING_SIZE);
	ANT_REL(&control->geometry.magic, ANT_TO_LE32(ANT_MAGIC));
	W32_SET(&boot->version, ANT_GUEST_ABI);
	W64_SET(&boot->session, W64_GET(&control->geometry.session));
	W64_SET(&boot->control_gpa, page_to_phys(pages));
	W32_SET(&boot->control_size, ANT_CONTROL_SIZE);
	W32_SET(&boot->profile, ANT_GUEST_PROFILE);
	host_seen = jiffies;
	smp_store_release(&ready, true);
	queue_delayed_work(worker, &control_work, 0);
	ANT_REL(&boot->magic, ANT_TO_LE32(ANT_MAGIC));
	return 0;
free_rings:
	for (index = 0; index < queue_count; index++)
		if (cpus[index].pages) __free_pages(cpus[index].pages, get_order(ring_size));
	kfree(cpus);
free_producers:
	free_percpu(producers);
	producers = NULL;
free_control:
	__free_pages(pages, get_order(ANT_CONTROL_SIZE));
	return error;
}
late_initcall(ant_guest_init);
