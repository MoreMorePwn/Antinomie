# Antinomie shared-memory transport API (ABI 7)

V7 transport code lives here. The initial monitor and application commands live
in `../monitor/`, with integration probes in `tests/monitor/` at the repository
root. Historical transport-only benchmarks remain in the original project vault.

Host implementation/API and original shared headers (`abi.h`, `queue.h`,
`bootstrap_layout.h`) are MIT licensed, copyright 2026 MikiMiku (MoreMorePwn).
Kernel-only `guest.c`, `bootstrap.c` and `guest_api.h` remain GPL-2.0-only.
See the root [licensing scope](../../../LICENSING.md); licensing changes do
not change the ABI or executable logic.

- `guest_api.h`: kernel feature interface, included as `<linux/antinomie.h>`.
- `host_api.h`: opaque host client interface; compile/link `host.c` (the Rust
  monitor build creates its own `ant_host` static library).
- `guest.c`: per-CPU publication, command registration/dispatch and health worker.
- `host.c`: initialization, mapping, polling, reads, command submission/results.
- `bootstrap.c`: early reservation of a single bootstrap page.
- `abi.h`: private wire layout, typed control region and geometry.
- `bootstrap_layout.h`: shared bootstrap defaults for host, kernel and decompressor.
- `queue.h`: private bounded variable-length SPSC byte queues.

See the [API reference](https://github.com/MoreMorePwn/idk-docs/blob/main/random/Shared%20Memory%20v7%20-%20Bootstrap%20and%20API.md)
for per-field structure tables, per-argument function tables, return values,
limits and unsupported lifecycle operations. The
[diff and walkthrough](https://github.com/MoreMorePwn/idk-docs/blob/main/random/Shared%20Memory%20v7%20-%20Diff%20and%20Walkthrough.md)
shows numbered source excerpts and implementation details.

Code excerpts in those documents carry actual source line numbers. The short
examples below use example-local numbers instead; numbers and `|` are annotations,
not code to compile. Mermaid diagrams remain unnumbered for Obsidian rendering.

## Guest feature

Illustrative usage, example lines 1-3 (not a source-file excerpt):

```c
1 | #include <linux/antinomie.h>
2 |
3 | int result = ant_send(message, message_length);
```

Success means all bytes were copied locally, not delivered or persisted.
No allocation, sleeping, overwrite or partial publication occurs on this path.
It is task-context-only; the caller supplies valid, stable kernel memory.
The maximum payload is the ring capacity minus its 32-byte frame header:
262,112 bytes in the current profile. A full ring returns `-ENOSPC`.

Commands are independent registered callbacks. They receive argument bytes and
a bounded result buffer; they do not manipulate queues or physical addresses.
Registration/unregistration is sleepable, and unregister waits for an active
callback. A callback must not recursively modify registrations.

## Host feature

Illustrative identity-mapped 2 GiB launch configuration, example lines 1-15
(not a source-file excerpt or an assumption made by the API):

```c
 1 | #include "host_api.h"
 2 |
 3 | struct ant_backing backing = { .path = ram_backing_path, .size = 2ULL << 30 };
 4 | struct ant_memory_region memory = { .gpa = 0, .size = 2ULL << 30 };
 5 | struct ant_options options = {
 6 |     .backings = &backing, .backing_count = 1,
 7 |     .regions = &memory, .region_count = 1, .ram_size = 2ULL << 30,
 8 |     .bootstrap_gpa = 0x70000000, .host_timeout_ms = 250,
 9 |     .poll_mode = ANT_POLL_SLEEP, .poll_sleep_us = 50,
10 | };
11 | struct ant_client *client;
12 | int error = ant_init(&options, &client);
13 | /* Check error before using client. */
14 | /* ant_poll -> ant_read; ant_command_send -> ant_result_read. */
15 | /* ant_close(client) after the owning thread has stopped using the handle. */
```

One owner thread per client. Only `ant_cancel` may be called concurrently;
join the owner before close. Different clients/VMs can run concurrently.
Payloads are opaque and exact-length, including embedded zeros and empty messages.
An undersized destination returns `-ENOBUFS` and the required size without
consuming the message. Results use a separate queue and echo request IDs.

ABI 7 retains separate 256 KiB request/result byte rings with independent
16,352-byte argument and result payload limits. Before executing a command,
the guest requires 16 KiB of free result space, not an empty result ring.
Sixteen maximum-sized results can remain unread; smaller results use less space.
The control allocation is 1 MiB. Duplicate/older dispatched command IDs return
`-ESTALE`; cached responses have been removed. New IDs execute even with identical
arguments. Rebuild guest and host together; older ABIs are rejected. See the
[benchmark and verification report](../../../Documentation/Antinomie/random/Shared%20Memory%20v7%20-%20Benchmark%20and%20Source%20Walkthrough.md).

`host_timeout_ms` configures the guest's host-liveness watchdog: zero selects
250 ms; 1..60000 ms are supported. `ant_set_host_timeout()` changes it at runtime;
stats report the guest-applied value. Before the first observed host heartbeat,
the guest is unattached, not stale. This is separate from `health_timeout_ms`,
which configures the host's guest-progress watchdog. No background host thread
refreshes heartbeats; the owner must continue servicing API calls.

Polling defaults to consistent 50 us requested sleeps after empty scans.
Busy PAUSE and adaptive wall-time spinning are optional. `ant_poll(..., -1)`
waits indefinitely by polling, not by a data-arrival interrupt. Scheduling can
extend sleep, timeout and cancellation latency.

## Deployment boundary

The supported wire architecture is x86-64 little endian. The launcher passes
RAM size, regular-file backings, GPA-to-file segments and bootstrap GPA at init.
The host validates and copies the descriptions; GPA need not equal file offset.
At most 16 backings and 64 segments are supported; an individual transport
allocation must fit wholly inside one segment. Backings and topology must remain
stable. File truncation/replacement or live RAM reconfiguration is unsupported.

The guest defaults to bootstrap GPA `0x70000000`; select another valid page with
`antinomie_boot_gpa=<numeric-address>` and pass exactly that GPA to the host.
The decompressor excludes it from KASLR placement and memblock reserves it after
`e820__memblock_setup()`. The page must be usable RAM and not occupied by another
boot artifact. No address discovery uses serial. The boot option remains visible
to guest inspection; this design is not protection from a malicious host/kernel.

The transport does not create test producer threads, sysfs controls or printk
application handlers. The optional test feature does. Build a production kernel
with `CONFIG_ANTINOMIE_TRANSPORT=y` and `CONFIG_ANTINOMIE_TRANSPORT_TEST=n`.
The profile still has an observable memory footprint and a periodic worker;
there is no claim of invisibility to a compromised guest kernel.

Snapshot restore, migration, in-session reconnect and expansion beyond the CPU
set declared possible at boot are unsupported. A client exclusively claims a
boot session; closing does not reset or reclaim that claim. Recovery currently
requires a fresh boot and backing allocation. Never resume an external monitor
against a restored VM snapshot and assume the counters still agree.
