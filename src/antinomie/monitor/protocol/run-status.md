# Run Status Control Contract

Producer/consumer contract, revision 1, 2026-10-06.
The existing V7 transport and application control header remain unchanged.
This defines an additive command; old guests can reject it and the host must
then keep execution status unknown instead of inferring completion from PTY EOF.

## Request

Opcode `ANTC_RUN_STATUS = 0x1016`. Exactly 16 octets, little endian.

| Offset | Type | Meaning |
|---|---|---|
| 0 | u16 | Control version 1 |
| 2 | u16 | Header length 8 |
| 4 | u32 | Flags 0 |
| 8 | u64 | Nonzero launch root task cookie, scoped to this guest boot |

## Success Reply

Exactly 64 octets, little endian. No native struct casts.

| Offset | Type | Meaning |
|---|---|---|
| 0 | u64 | Queried root cookie; must match request |
| 8 | u64 | Monotonic per-run generation; changes on membership/status transitions |
| 16 | u64 | Live task/thread count at the defined kernel task-exit boundary |
| 24 | u64 | Outstanding observed async requests; not a proof that unsupported variants have none |
| 32 | u32 | Flags below |
| 36 | s32 | Raw Linux root wait status, valid only with ROOT_EXITED |
| 40 | u64 | Cumulative async observation/staging/publication losses for this run |
| 48 | u64 | Total tasks created for this run, including the launched root |
| 56 | u64 | Reserved 0 |

| Flag | Value | Meaning |
|---|---|---|
| ROOT_EXITED | 1 | Launched root process's thread group ended and its wait status is recorded; descendants may still run |
| TREE_EXITED | 2 | Live task count reached zero after all counted exit transitions |
| STOP_REQUESTED | 4 | At least one accepted Stop request targeted this run; not termination proof |
| ASYNC_COMPLETE | 8 | Known outstanding async count is zero and no unsupported/incomplete tracking prevents a completion claim |
| OBSERVATION_INCOMPLETE | 16 | Async lifecycle attribution or counting was incomplete; retain explicit completion uncertainty |
| KILL_ESCALATED | 32 | The guest sent SIGKILL to the run after a Stop's grace period because tasks of the run outlived SIGTERM; set once, when the first SIGKILL was issued |

Unknown flag bits (above 32), nonzero reserved data, mismatched root cookie, inconsistent
TREE_EXITED/live count or a regressing generation are protocol errors. ROOT_EXITED
with status zero means normal exit code zero, not unknown. Signal/exit codes use
wait-status decoding; do not display the raw status as the program's exit code.

## Stop and its escalation (revision 17)

`ANTC_STOP_RUN` (0x1015) sends SIGTERM to every task that carries the run's
launch cookie (descendants after root exit, `setsid()` children and orphaned
grandchildren included) and sets STOP_REQUESTED. A task that ignores SIGTERM
used to run on for ever; the guest now ends it itself, without any help from the
host or a process in the guest:

| Rule | Value |
|---|---|
| Grace period | 4000 ms by default. The request may be 24 bytes: `u32 grace_ms` at 16 (0 = default, else 100..30000) and `u32 reserved = 0` at 20. A 16-byte request keeps working and means the default. The host sends the 24-byte form only when `BackendOptions::stop_grace` is set (revision-17 guests only) |
| Escalation | When the grace period ends, SIGKILL goes to every task of the run still alive, and again every 250 ms while tasks remain, at most 20 passes. The repeats catch a fork that raced the first pass |
| A later Stop | Sends SIGTERM again and can only bring the deadline forward |
| Core copy | A process core being copied is not interrupted (SIGKILL would truncate it): the escalation waits for the copy, for at most 15 s past the grace period. A root killed before its exit copy starts has no core, as for any SIGKILL |
| Reporting | KILL_ESCALATED is set with the first SIGKILL, whichever task of the run needed it. The signal that ended the root is in the wait status: `Signaled 9` when the root itself was killed, `Signaled 15` or the program's own exit when it obeyed SIGTERM. A root that handled SIGTERM and exited by itself reports `Exited` while the flag still says another task needed SIGKILL |
| Run state | `Stopped` needs STOP_REQUESTED, TREE_EXITED, no outstanding request and a root that died of a signal; a root that exited normally is `Finished` (ASYNC_COMPLETE and OBSERVATION_INCOMPLETE no longer decide it; see below) |

The work runs on the system unbound workqueue; no thread, workqueue or process
is created in the guest. A task stuck in uninterruptible sleep cannot be killed
by any signal; the run then stays live and the status says so.

## io_uring workers, and what ends a run (revision 17)

An io_uring ring puts kernel threads into the creating process: `iou-wrk-*`
workers and an `iou-sqp-*` submission thread. They are threads of the root's
thread group, appear in its process core, and can be the last to leave it. The
run therefore counts them: they raise `live` and `total` like any thread and
the thread that leaves the group last records the root's wait status, whichever
thread it is. They have no cookie, are not observed, never start the process
core rendezvous and are not signalled by Stop's escalation by cookie (SIGKILL of
the group ends them with the process). An older guest did not count them; when
a worker left last it reported TREE_EXITED without ROOT_EXITED.

What the host takes from a reply:

| Fact | Source | Never inferred from |
|---|---|---|
| The program tree ended | TREE_EXITED with `live == 0` | terminal EOF, a workload marker |
| How the root ended | the wait status with ROOT_EXITED | the same |
| Requests still outstanding | `pending` | the observation flags |
| The observation was complete | no OBSERVATION_INCOMPLETE, loss count 0 | the process having ended |

The run state follows the first three: **Finished** (or **Stopped**, for a
stopped root that died of a signal) is a tree that ended with no request
outstanding, whatever the observation flags say. OBSERVATION_INCOMPLETE and the
loss count are reported next to the state, not folded into it, and apart from
each other:

| Guest says | Host shows |
|---|---|
| Loss count above 0 | Note "Async observation lost N records"; the run is listed under "Runs with async observation loss" (Summary › health), a warning |
| OBSERVATION_INCOMPLETE, count 0 | Note "Uses io_uring: which task submitted each request is not proven (an SQPOLL ring, or a ring another process can write); nothing was lost", information only; not listed as loss |
| Neither | No note |

OBSERVATION_INCOMPLETE is raised for an io_uring request whose entry's writer
is not proven: the SQPOLL thread's submissions, submissions from outside the
ring creator's process, and a ring another process maps (native-schema-slices
14.3). A ring one process maps was written by that process, and its run can
be ASYNC_COMPLETE (guest series 0055); an older guest raised the flag for
every io_uring request, so folding it into the state would have left every
io_uring run `Unknown` for ever. A run saved before the two notes were told
apart has "Async observation loss reported: last guest count N, loss flag B":
with N = 0 it is shown as the attribution note and is not loss.
TREE_EXITED without ROOT_EXITED (an older guest, above) ends the run with the
exit status unknown (`root_status_missing`), never zero. A reply the host cannot
use (a field out of range, an inconsistent live count) is an error naming the
cookie, generation, live, async, flags and total fields it rejected; once the
root's exit is recorded, such a reply no longer clears the status the run has.

## Run identity across a transport reconnect (host)

A transport reconnect seals the recording of the old timeline and continues each
live run in a new one. The run keeps its id, so a selection, an open terminal
and a pending Stop still mean the same run, and Run History lists one record for
it: the newest segment, with a note "Recording continues after a transport
reconnect (recording segment N)" per reconnect naming the boot that holds the
earlier part. The terminal sequence continues instead of restarting. Restoring a
snapshot is a different timeline of the run and still gets a new id.

## Errors and Ownership

| Result | Meaning |
|---|---|
| `-EINVAL` | Invalid header, extent, flags or zero cookie |
| `-ESRCH` | No retained run matches the cookie in this boot |
| Unsupported opcode | Old guest; host displays unknown execution status |
| Other transport/control error | Query failed; do not convert into Finished |

Kernel retains at most 64 launched-run objects until reboot, matching the host's
per-boot launch admission bound. Root initialization admits the object before
execution. Fork/thread membership increments before child wakeup, independently
of telemetry allocation/publication; exit decrements exactly once. Keep the root
wait status when descendants outlive it. Root-process membership follows its
thread group through nonleader exec; leader pthread_exit alone does not end the
process. Its wait status uses the kernel group-exit/group-leader rules when the
last root thread exits. Query snapshots use a defined lock and
reference lifetime, never an unreferenced PID scan.

TREE_EXITED is task completion at the existing exit observation boundary, not
proof that all file/task cleanup, async I/O or telemetry delivery finished.
Run payload recording continues until VM stop in this update, avoiding premature
archive closure; status and archival finalization remain separate. Unknown old
archives and forced VM termination retain distinct states.

Async tracking increments before submission can complete and decrements once on
completion/cancellation. IRQ callbacks never call V7 ant_send directly. Stage
bounded owned records and publish from task context; failed tracking/attribution
sets OBSERVATION_INCOMPLETE and reports losses. Capture or publication loss alone
increments the loss count and reports field gaps; it does not invalidate an
otherwise authoritative final request count. Avoid retaining unchecked user
pointers and mark captures observational. Shared-ring creator identity alone
does not prove the identity of each submitting task.

## Asynchronous Telemetry

Uses the existing ANTT phase 3, field and content-chunk framing, not a new V7
ring or packet version. The host associates auxiliary observations by matching
stream, origin task and known parent invocation. Any surviving `async.*` field
identifies an async observation; incomplete unclassified auxiliary records also
remain visible when identifying fields were lost. Never invent a missing request
ID, stage or system. Known lifecycle-only records do not replace syscall phases.
If both parent Entry/Exit records were lost, a known nonzero invocation remains
visible as an async-only row with explicitly missing phases. Unknown parent
invocations (zero) stay raw-only rather than inventing a syscall association.
Completion worker PID is not the origin identity. Scalar fields are eight-octet
little-endian values; signed results retain their two's-complement bits. CPU and
time record the observation context, not the later deferred publisher's CPU.

| Field | Meaning |
|---|---|
| `async.request_id` | Boot-scoped observer request identity |
| `async.parent_call_id` | Known submitting syscall invocation; zero if not observed |
| `async.stage` | Stage table below |
| `async.result` | Operation result for accepted/rejected/completed stages; observation error for stage 6 |
| `async.final` | Observer retires this request at this record; not independently proof of completion |
| `async.opcode` | Native io_uring/AIO operation selector |
| `async.user_data` | Application-supplied completion correlation value; not an identity guarantee |
| `async.system` | NUL-terminated `io_uring` or `AIO` |
| `async.flags` | Bit 0 payload gap, bit 1 unknown SQE producer, bit 2 retired without observed completion, bit 3 SQE written by a thread of the submitting process (which thread is not known; guest series 0055); upper 32 bits raw CQE flags |
| `async.submission` | Kernel-imported SQE or IOCB descriptor snapshot, native layout named in field metadata |
| `async.payload.direction` | 1 input or 2 output |
| `async.payload.requested_size` | Kernel-imported iterator extent, in bytes |
| `async.payload.result_offset` | Already processed portion, in bytes |
| `async.payload.iov` | Imported native iovec descriptors, when applicable |
| `async.payload.input` / `.output` | Content snapshots, streamed in bounded chunks |
| `async.operand.*` | Known typed imported operands (for example path, open_how, timeout or sockaddr); per-field status/layout determines what was safely observed |

| Stage | Value | Meaning |
|---|---|---|
| Submission | 1 | Observed imported descriptor/input; not acceptance proof |
| Accepted | 2 | Accepted for processing; not completion proof |
| Rejected | 3 | Submission rejected; signed result describes the rejection |
| Completion | 4 | Subsystem result; multishot/partial records may be nonfinal |
| Canceled | 5 | Actual observed completion result `-ECANCELED` |
| Observation Unavailable | 6 | Observer retired without seeing a completion; `-ENODATA` describes observation failure, not the operation result |

Payload supplements may have stage 1 or 4 with `final = 0`; the subsystem's
completion hook publishes finality separately. User content can be copied only
in a safe original address-space context. A retained task reference does not
retain its old memory map. Later ordinary user buffers remain explicitly
`ASYNC_UNOBSERVED` when that context is unavailable; registered pinned-page or
kernel iterators can be observed within their actual lifetime. Capture status,
staging overflow and publication loss must remain visible. Scalar lifecycle
observation alone does not guarantee full asynchronous payload capture.
