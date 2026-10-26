// SPDX-License-Identifier: GPL-2.0-only
#include <linux/antinomie.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/export.h>
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

struct ant_cpu {
	struct page *pages;
	void *data;
};
/* One per CPU, used with preemption off. A sender that must wait for room
 * takes a turn (next_ticket) and stays on its CPU until serving reaches it.
 */
struct ant_producer {
	u64 head, cached_tail, attempted, dropped, waits, wait_ns;
	u32 index, next_ticket, serving;
	bool fault;
};
static DEFINE_PER_CPU(struct ant_producer, producers);
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
	u64 nonce = ANT_ACQ(&boot->resume_request);
	u64 cursor, seen, head, reply_tail, floor;
	int error = 0;

	if (!nonce || nonce == ANT_ACQ(&boot->resume_ack))
		return false;
	/* Fence acknowledgment waits until manual acquisition owns no parks.
	 * Completed immutable evidence remains retained across reattachment.
	 */
	if (!ant_manual_fence() || !ant_debug_fence())
		return true;
	floor = max(last_request_id, ANT_ACQ(&boot->resume_sequence_floor));
	cursor = request_tail;
	seen = request_head_seen;
	head = ANT_ACQ(&control->requests.head);
	reply_tail = ANT_ACQ(&control->responses.tail);
	if (broken || (head & 7) || head < cursor || head - cursor > ANT_COMMAND_RING_SIZE ||
	    (reply_tail & 7) || reply_tail > response_head ||
	    response_head - reply_tail > ANT_COMMAND_RING_SIZE) {
		error = -EPROTO;
		goto acknowledge;
	}
	while (cursor != head) {
		struct ant_message req;

		error = ant_peek(&control->requests, region->request_data,
			ANT_COMMAND_RING_SIZE, ANT_MAX_COMMAND_LEN, cursor, &seen, &req);
		if (error || !req.id || !req.opcode || req.status) {
			error = -EPROTO;
			goto acknowledge;
		}
		floor = max(floor, req.id);
		cursor += ant_span(req.payload_len);
	}
	boot->discarded_request_bytes = head - request_tail;
	boot->discarded_reply_bytes = response_head - reply_tail;
	request_tail = head;
	request_head_seen = head;
	last_request_id = floor;
	ANT_REL(&control->requests.tail, request_tail);
	/* A new heartbeat establishes liveness independently of rolled-back time. */
	host_seen = jiffies;
	last_heartbeat = ANT_ACQ(&control->host_heartbeat);
	host_attached = true;
	ANT_REL(&boot->owner, nonce);
acknowledge:
	if (error) {
		broken = true;
		control->health |= ANT_HEALTH_RING_FAULT;
		boot->discarded_request_bytes = 0;
		boot->discarded_reply_bytes = 0;
	}
	boot->resume_sequence_ack = floor;
	boot->resume_status = error;
	ANT_REL(&boot->resume_ack, nonce);
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
EXPORT_SYMBOL_GPL(ant_ring_size);

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
	p = this_cpu_ptr(&producers);
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
			error = ant_space(q, ring_size, p->head, &p->cached_tail,
					  ant_span(payload_len));
		if (error != -ENOSPC)
			break;
		/* The host may ask senders to wait for room instead of dropping,
		 * only while it is live and keeps reading this ring: the wait ends
		 * when the host has taken nothing from it for the whole send wait.
		 * A sender that may sleep sleeps on this CPU, so the control worker
		 * and other tasks keep running; one in atomic context spins, and
		 * only briefly. */
		wait_us = min_t(u32, READ_ONCE(control->send_wait_us), ANT_SEND_WAIT_MAX_US);
		if (!may_sleep)
			wait_us = min_t(u32, wait_us, ANT_SEND_ATOMIC_WAIT_US);
		now = local_clock();
		if (!waited_from) {
			waited_from = progress_at = now;
			tail = ANT_ACQ(&q->tail);
			p->waits++;
		} else if (ANT_ACQ(&q->tail) != tail) {
			tail = ANT_ACQ(&q->tail);
			progress_at = now;
		}
		if (!wait_us || !READ_ONCE(control->live) ||
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
			WRITE_ONCE(q->attempted, p->attempted);
			WRITE_ONCE(q->waits, p->waits);
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
		WRITE_ONCE(q->waits, p->waits);
		WRITE_ONCE(q->wait_ns, p->wait_ns);
	}
	if (error) {
		if (error != -ENOSPC) {
			p->fault = true;
			WRITE_ONCE(q->fault, -error);
		}
		goto drop;
	}
	ant_publish(q, cpus[p->index].data, ring_size, &p->head, &msg, data);
	goto out;
drop:
	p->dropped++;
out:
	WRITE_ONCE(q->attempted, p->attempted);
	WRITE_ONCE(q->dropped, p->dropped);
	preempt_enable();
	if (queued)
		migrate_enable();
	return error;
}
EXPORT_SYMBOL_GPL(ant_send);

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
	p = this_cpu_ptr(&producers);
	q = &directory[p->index];
	tail = ANT_ACQ(&q->tail);
	if (!p->fault && tail <= p->head && p->head - tail <= ring_size)
		room = ring_size - (p->head - tail);
	preempt_enable();
	return room;
}
EXPORT_SYMBOL_GPL(ant_send_room);

bool ant_send_waits(void)
{
	/* Pairs with the release that publishes the rings at setup. */
	return smp_load_acquire(&ready) && READ_ONCE(control->send_wait_us) &&
		READ_ONCE(control->live);
}
EXPORT_SYMBOL_GPL(ant_send_waits);

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
EXPORT_SYMBOL_GPL(ant_register_command);

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
EXPORT_SYMBOL_GPL(ant_unregister_command);

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
		error = ant_peek(&control->requests, region->request_data,
			ANT_COMMAND_RING_SIZE, ANT_MAX_COMMAND_LEN, request_tail, &request_head_seen, &req);
		if (error == -EAGAIN) return;
		if (error) goto fault;
		/* Reserve worst-case result space before invoking any side effect. */
		error = ant_space(&control->responses, ANT_COMMAND_RING_SIZE, response_head,
			&response_tail_seen, ant_span(ANT_MAX_RESULT_LEN));
		if (error == -ENOSPC) {
			control->reply_stalls++;
			control->health |= ANT_HEALTH_REPLY_FULL;
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
			control->bad_commands++;
			control->health |= ANT_HEALTH_BAD_COMMAND;
		}
		ant_publish(&control->responses, region->response_data, ANT_COMMAND_RING_SIZE,
			    &response_head, &resp, command_result);
		request_tail += ant_span(req.payload_len);
		ANT_REL(&control->requests.tail, request_tail);
	}
	return;
fault:
	broken = true;
	control->health |= ANT_HEALTH_RING_FAULT;
}

static void control_tick(struct work_struct *work)
{
	u64 heartbeat = ANT_ACQ(&control->host_heartbeat);
	u32 timeout_ms = ANT_ACQ(&control->host_timeout_ms);
	u32 i;
	service_resume();
	if (!timeout_ms) timeout_ms = ANT_HOST_TIMEOUT_DEFAULT_MS;
	if (timeout_ms > ANT_HOST_TIMEOUT_MAX_MS) {
		control->health |= ANT_HEALTH_BAD_CONFIG;
		timeout_ms = control->applied_host_timeout_ms;
	}
	WRITE_ONCE(control->applied_host_timeout_ms, timeout_ms);
	if (heartbeat != last_heartbeat) {
		last_heartbeat = heartbeat;
		host_seen = jiffies;
		host_attached = true;
	}
	control->live = host_attached && time_before(jiffies, host_seen + msecs_to_jiffies(timeout_ms));
	if (host_attached && !control->live) control->health |= ANT_HEALTH_HOST_STALE;
	for (i = 0; i < queue_count; i++) {
		if (READ_ONCE(directory[i].dropped)) control->health |= ANT_HEALTH_OVERFLOW;
		if (READ_ONCE(directory[i].fault)) control->health |= ANT_HEALTH_RING_FAULT;
	}
	service_commands();
	ANT_REL(&control->guest_heartbeat, control->guest_heartbeat + 1);
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
	cpus = kcalloc(queue_count, sizeof(*cpus), GFP_KERNEL);
	if (!cpus) goto free_control;
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
		directory[index].data_gpa = page_to_phys(cpus[index].pages);
		directory[index].data_size = ring_size;
		directory[index].cpu_id = cpu;
		per_cpu(producers, cpu).index = index++;
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
	control->geometry.version = ANT_ABI;
	control->geometry.session = get_random_u64() ?: 1;
	control->geometry.size = ANT_CONTROL_SIZE;
	control->geometry.queue_count = queue_count;
	control->geometry.max_message_len = ANT_MAX_MESSAGE_LEN;
	control->geometry.max_command_len = ANT_MAX_COMMAND_LEN;
	control->geometry.max_result_len = ANT_MAX_RESULT_LEN;
	control->applied_host_timeout_ms = ANT_HOST_TIMEOUT_DEFAULT_MS;
	control->requests.data_gpa = page_to_phys(pages) + ANT_REQUEST_OFFSET;
	control->requests.data_size = ANT_COMMAND_RING_SIZE;
	control->responses.data_gpa = page_to_phys(pages) + ANT_RESPONSE_OFFSET;
	control->responses.data_size = ANT_COMMAND_RING_SIZE;
	ANT_REL(&control->geometry.magic, ANT_MAGIC);
	boot->version = ANT_ABI;
	boot->session = control->geometry.session;
	boot->control_gpa = page_to_phys(pages);
	boot->control_size = ANT_CONTROL_SIZE;
	boot->profile = 1;
	host_seen = jiffies;
	smp_store_release(&ready, true);
	queue_delayed_work(worker, &control_work, 0);
	ANT_REL(&boot->magic, ANT_MAGIC);
	return 0;
free_rings:
	for (index = 0; index < queue_count; index++)
		if (cpus[index].pages) __free_pages(cpus[index].pages, get_order(ring_size));
	kfree(cpus);
free_control:
	__free_pages(pages, get_order(ANT_CONTROL_SIZE));
	return error;
}
late_initcall(ant_guest_init);
