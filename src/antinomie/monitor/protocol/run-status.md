# Run Status Control Contract

ANT-T0009 producer/consumer contract, revision 1, 2026-10-06.
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

Unknown flag bits, nonzero reserved data, mismatched root cookie, inconsistent
TREE_EXITED/live count or a regressing generation are protocol errors. ROOT_EXITED
with status zero means normal exit code zero, not unknown. Signal/exit codes use
wait-status decoding; do not display the raw status as the program's exit code.

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
| `async.flags` | Bit 0 payload gap, bit 1 unknown SQE producer, bit 2 retired without observed completion; upper 32 bits raw CQE flags |
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
