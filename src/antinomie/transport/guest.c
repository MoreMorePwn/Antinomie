// SPDX-License-Identifier: GPL-2.0-only
#include <linux/antinomie.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "queue.h"

struct ant_cpu {
	struct page *pages;
	void *data;
};
struct ant_producer {
	u64 head, cached_tail, attempted, dropped;
	u32 index;
	bool fault;
};
static DEFINE_PER_CPU(struct ant_producer, producers);
static struct ant_cpu *cpus;
static struct ant_control *control;
static struct ant_queue *directory;
static struct ant_region *region;
static u32 queue_count;
static bool ready, broken;
static struct workqueue_struct *worker;
static void control_tick(struct work_struct *work);
static DECLARE_DELAYED_WORK(control_work, control_tick);

struct ant_handler {
	u32 opcode;
	ant_command_handler fn;
	void *context;
};
static struct ant_handler handlers[32];
static DECLARE_RWSEM(handler_lock);
static u8 command_args[ANT_MAX_COMMAND_LEN], command_result[ANT_MAX_RESULT_LEN];
static u64 last_request_id;
static u64 request_tail, request_head_seen, response_head, response_tail_seen;
static u64 last_heartbeat;
static unsigned long host_seen;
static bool host_attached;

int ant_send(const void *data, size_t payload_len)
{
	struct ant_producer *p;
	struct ant_queue *q;
	struct ant_message msg = { .payload_len = payload_len };
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
	error = ant_space(q, ANT_TELEMETRY_RING_SIZE, p->head, &p->cached_tail, ant_span(payload_len));
	if (error) {
		if (error != -ENOSPC) {
			p->fault = true;
			WRITE_ONCE(q->fault, -error);
		}
		goto drop;
	}
	ant_publish(q, cpus[p->index].data, ANT_TELEMETRY_RING_SIZE, &p->head, &msg, data);
	goto out;
drop:
	p->dropped++;
out:
	WRITE_ONCE(q->attempted, p->attempted);
	WRITE_ONCE(q->dropped, p->dropped);
	preempt_enable();
	return error;
}
EXPORT_SYMBOL_GPL(ant_send);

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
		int error = ant_peek(&control->requests, region->request_data,
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
	queue_delayed_work(worker, &control_work, msecs_to_jiffies(ANT_POLL_MS));
}

static int __init ant_guest_init(void)
{
	struct page *pages;
	struct ant_boot *boot;
	u32 cpu, index = 0;
	int error = -ENOMEM;
	BUILD_BUG_ON(sizeof(struct ant_queue) != 192);
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
	for_each_possible_cpu(cpu) {
		cpus[index].pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(ANT_TELEMETRY_RING_SIZE));
		if (!cpus[index].pages) goto free_rings;
		cpus[index].data = page_address(cpus[index].pages);
		directory[index].data_gpa = page_to_phys(cpus[index].pages);
		directory[index].data_size = ANT_TELEMETRY_RING_SIZE;
		directory[index].cpu_id = cpu;
		per_cpu(producers, cpu).index = index++;
	}
	worker = alloc_ordered_workqueue("antinomie-control", WQ_MEM_RECLAIM);
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
		if (cpus[index].pages) __free_pages(cpus[index].pages, get_order(ANT_TELEMETRY_RING_SIZE));
	kfree(cpus);
free_control:
	__free_pages(pages, get_order(ANT_CONTROL_SIZE));
	return error;
}
late_initcall(ant_guest_init);
