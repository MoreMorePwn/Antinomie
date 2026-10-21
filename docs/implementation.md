# Antinomie initial monitoring release

This brief is the shared implementation contract. User authorized implementation
on 2026-10-01. Core workers/review use gpt-6.1-sol; bounded support may use Luna.
The accepted 0.5.0 snapshot/reconnect extension below supersedes the historical
V7-only restriction; older requirements remain recorded for their releases.

## Accepted requirements

### Accepted kernel-native guest resources (0.7.0, ANT-T0084 follow-up)

Contract revision 17 replaces the temporary guest collector with the kernel
`RESOURCES` command (`0x1070`, header-only request, 96-byte reply; layout in
`protocol/control.h`). The guest samples on its own dedicated single-slot
workqueue: the handler returns the latest completed sample and queues a refresh
only when that sample is at least 500 ms old and none is running, so a blocked
statfs never stalls the control worker or queues work; it surfaces as a growing
sample age and `refresh_pending_ms`. Memory is `si_meminfo` MemTotal and
`si_mem_available` MemAvailable (the pinned `meminfo.c` sources, not text
parsing). Storage is `vfs_statfs` on the root of PID 1 in the initial namespace,
resolved at every sample and never held, so a `switch_root` is visible in the
reported device/type/id and no old mount is pinned; sizes use `f_frsize` with
checked arithmetic and distinct total, free and available values.

The host (`kernel_resources.rs`) polls about once a second with one request in
flight and a 4 s deadline. A request is idempotent: nothing is replayed, a late
reply is still owned and recovers the state, a rejected request backs off 2 s
and `EOPNOTSUPP` stops polling. Age is the kernel's sample age plus host time
since the reply; older than 6 s, a late or invalid reply, a blocked refresh,
a paused VM, snapshot or reconnect all mark the reading stale, and a timeline
boundary discards readings and the answer still in flight. Values the kernel
marks invalid are unavailable, never zero. Kernels of revision 11 to 16 keep
the temporary collector described below, unchanged, until their bases are
outdated; a revision-17 kernel never receives the collector upload or exec.

### Accepted debugger, phases 0, 1 and 2 (0.7.0)

The debugger is a ptrace-free, process-scoped engine in the guest kernel
(`kernel/antinomie/debug.c`, one file per architecture, x86-64 first) driven by
control opcodes `0x1080..0x108d` and served to gdb, IDA, Ghidra and radare2 by a
host RSP server (`gdbstub 0.7.10`, MIT/Apache-2.0) on a loopback Unix socket and
an ephemeral 127.0.0.1 port. Contract revision 17 is unchanged: the opcodes are
additive and an older guest answers `-EOPNOTSUPP`. Layouts are in
`protocol/control.h`, semantics, measurements and limits in `protocol/debugger.md`.

* **Stealth.** No helper in the guest and no ptrace: `TracerPid` stays 0, the
  sample's own `PTRACE_TRACEME` succeeds, engine breakpoints and steps raise no
  `SIGTRAP`, the trap flag is hidden, and reads of the sample's own memory through
  `/proc/self/mem` show original bytes while breakpoints are in. A direct load of
  its own code can still see the engine's `0xCC`; hardware breakpoints (phase 2)
  are the stealth tier.
* **Multi-architecture.** Messages carry the ELF `e_machine`; registers travel as
  regset blobs tagged with their ELF note type; `CAPS` reports breakpoint lengths,
  hardware breakpoint and watchpoint counts and hardware single-step; the host
  `DebugBackend` trait is implemented by the kernel engine and is the seam for a
  QEMU-gdbstub backend; the GDB register image, the target description and any UI
  register view are built from one `TargetDescription`.
* **Host.** `Command::DebugAttach { identity }` opens the guest session and the
  server; `Snapshot::debug` carries the endpoints and a ready-to-paste
  `gdb -ex 'target remote 127.0.0.1:PORT'`. The server thread never touches the
  transport: it sends requests, limited to the debug opcodes, to the transport
  thread. (Phase 1 refused a VM snapshot while a debugger was attached; Phase 3
  allows it and re-adopts the sessions, below.) The VM stopping or the app closing
  ends the session and resumes the process.
* **Phase 0 evidence** (real BusyBox VM, KVM, one vCPU): a three-thread process
  stopped without ptrace in 44-55 ms with memory provably frozen; registers (216 B
  general, 512 B FXSAVE) and memory read and written; an `INT3` planted by the
  engine caught 8 of 8 times before the task saw `SIGTRAP` with the instruction
  pointer rewound; single-step advanced `hot+3`, `+7`, `+14` with TF clear in every
  stop and in the word a stepped `PUSHF` stored. Go for phase 1.
* **Phase 1 evidence**: a real `gdb` (17.2) connected, read registers
  (including `fs_base` and `orig_rax`) and memory, set a breakpoint, continued to
  it, stepped, and detached, and the sample then ran to its own exit. Also
  verified with gdb: exit under the debugger reported as "exited normally", `kill`
  ending the process, gdb killed mid-run (the process kept running, a new gdb
  attached, no `SIGTRAP`), and Ctrl-C.
* **Phase 2 evidence** (final BusyBox base, real gdb 17.2): Debug on start stopped
  static, static-pie and dynamic programs at their entry before any user output;
  `info threads` listed every thread and `stepi` moved one; `stepi` over `syscall`
  and `rep movsb` ended on the next instruction; `hbreak`, `watch`, `awatch` fired
  and a fifth `hbreak` was refused cleanly; signals were passed, dropped and
  stepped into handlers; Stop of a debugged run ended it in about 1 s without the
  SIGKILL escalation; a process core completed under a debug stop. A request costs
  4 ms (22 ms in Phase 1). `debug-check p2` repeats all of it.
* **Phase 3** (fork and exec following, non-stop, re-adoption, the panel's
  process and signal controls) is described after the panel.

### Accepted ANT-T0120 configurable process-core size (0.7.0)

The 64 MiB / 5 s ceiling of process cores is configurable. The guest series gains
0039 (limits from guest RAM, chunked buffer, one budget enforcer, `CORE_CAPS`
0x1066, `CORE_STATUS` STORED flag) and 0040 (control worker polls every tick while a
finished core is read). The contract stays at revision 17; an older guest answers
`CORE_CAPS` with `-EOPNOTSUPP` and the host keeps the 64 MiB / 5000 ms contract,
and an older host never sends either request. Host: `core_limits.rs` (limits,
validation messages, reasons), `backend/core_stream.rs` (pipelined reads, host
disk and quota checks), a probe in `session_transport.rs`, budget and deadline
choosers (`core_budget.rs`) in Run program, Dump core and Settings.

* **Decisions**: default budget 256 MiB clamped to the guest; hard cap 1 GiB; the
  guest maximum is half of RAM less 128 MiB (64 MiB to 1 GiB), pool twice that;
  exit cores still allocate 64 MiB when armed; deadline 5 s + 10 ms per MiB up to
  60 s. Buffering stays in the guest (no streaming during capture).
* **Evidence** (BusyBox base, `core-size-check`, torture `crash-core`): light
  33,996,800 bytes and heavy 134,660,096 bytes complete at budget 256 MiB (stack
  and vsyscall pages captured; heavy at 64 MiB is Partial, reason budget, cut at
  67,321,856 of 134,660,096); extreme 524,730,368 bytes complete at the 1 GiB cap
  on a 3 GiB guest; a 335 MiB heap on a 512 MiB guest is Partial, reason guest
  memory, never Complete; a 300 MiB manual core completes its transfer in 13.9 s;
  a deadline of 2 s under software emulation is Partial, reason deadline; a 100 MiB
  recording quota cuts a heavy core at the quota (reason quota); a host disk with
  137 MiB free refuses a 129 MiB core before writing (reason host disk); canceling
  a manual core at 50 % keeps a hashed prefix (reason canceled).
* **Transfer**: 1.2 MiB/s before (guest poll of 10 ms, one read per pass) to
  25-31 MiB/s after (eight reads in flight, joined writes, tick polling).
* **Still true**: a manual core reports Partial with reason coverage when the
  resident-only policy leaves mappings out, as before.

### Accepted in-app debugger panel (0.7.0)

The Debugger window is the minimal in-app UI over the same engine. It does not
connect to the RSP socket: the controller (`debug/ui_control.rs`) runs on the
RSP server thread and drives the same `Debugger` and `DebugBackend`, reaching the
guest through the same `DebugLink` as an external client. Panel data types are in
`debug/view.rs`.

* **Messages.** `Command::DebugUi(DebugRequest { id, sequence, action })` is queued
  (at most 32) for the controller; the answer is `Snapshot::debug_view`, an
  `Arc<DebugView>` replaced as a whole with an increasing `epoch`. The success of a
  `DebugUi` command is not reported (no result is emitted); a refusal is. A
  request that needs a stop names the stop it was made against (`sequence`); the
  controller drops one that does not match the current stop and reports it in the
  view (`handled` says which request ids are answered, `notice` says why one was
  dropped). The panel shows memory windows only when they belong to the stop on
  screen.
* **One controller at a time.** Without an RSP client the panel drives. A client
  that connects takes control: queued panel requests are dropped, the view becomes
  `Controller::Gdb` (no registers or windows, read-only, new requests refused
  with a message), the process is stopped for the client (the server's existing
  behaviour at connect), and the client's session proceeds unchanged. When the
  client leaves the server removes the client's breakpoints and resumes the
  process (unchanged), and the panel reads the state again and drives. The
  panel's breakpoints and the client's share the guest's table with ownership:
  an address stays registered while either holds it, and a client leaving removes
  only its own. Tested with fakes and with a real TCP client
  (`debug::tests::ui_control`).
* **Guest cost.** About 22 ms per request. A stop fetches, in order, the thread
  list, the general register set, 256 bytes of code (up to 48 before the
  instruction pointer), 256 bytes of stack and, if chosen, the memory range: five
  requests (about 110 ms), published after each part. Nothing is read while the
  process runs or is idle at a stop. A running process is polled every 100 ms, one
  that was asked to stop or step every 10 ms. Memory reads are at most 4096 bytes.
  Disassembly decodes the window in the UI thread (`analysis::decode_window`, the
  listing's iced-x86 formatter); instructions before the current one are a guess.
* **Room for phase 2.** `StopReason` has signal, watchpoint and entry variants,
  `BreakpointKind` has hardware and watch kinds (requests for them are refused
  until the guest offers them), `ViewCaps` carries the guest's capabilities, and a
  stop reason is mapped from the engine's `StopKind` in one place.
* **Not in the panel.** Saved process cores (opened read-only in Core dumps, which
  already shows registers, mappings with a hex view and disassembly), memory and
  register writes, step over, and anything that needs phase 2.

### Accepted debugger phase 3: follow, non-stop, re-adoption (0.7.0)

Guest series 0041-0042, contract revision 17 unchanged. The wire (`protocol/control.h`,
`protocol/debugger.md`) adds CONFIG, EVENTS, THREAD_CTL, SESSIONS and BP_LIST, an
ADOPT flag on ATTACH and a `CAPS` extension (flags2: FOLLOW, NONSTOP, ADOPT,
THREAD_HW) that only a host sending the extension sees: an old host with a new
guest, and a new host with an old guest, both keep the Phase 2 behaviour.

* **Engine.** Sessions are a list, one per thread group, over a shared address
  space record (breakpoints, history) that a vfork child shares until its exec.
  A fork parks the child at its first return to user mode with a CHILD event and
  gives the parent a FORK event; a vfork parent sleeps in the kernel, so its stop
  is reported without parking (VFORK, later VFORK_DONE). One-shot events that
  arrive when the state cannot take them are deferred and promoted at the next
  stop or continue, so none is lost or doubled. Exec swaps the address space and
  reports EXEC with the path. Non-stop keeps breakpoints inserted, queues events
  (64, sequence and ack) and stops, steps and continues threads singly.
  Asynchronous exact steps (`syscall`, `rep` strings) no longer plant a temporary
  breakpoint. A new thread installs the hardware breakpoints from its own context.
  `ant_debug_fence()` no longer cancels sessions.
* **Host.** `debug/` has its own RSP implementation (`rsp_packet`, `rsp_client`,
  `rsp_requests`) over a `Debugger` that owns one `Inferior` per process
  (`debugger.rs`, `inferior.rs`). The panel and a gdb client share it: the same
  registry gives each breakpoint its owners, a client leaving removes only its own.
  `ui_follow.rs` holds the panel's fork policy, process list and signal handling
  (`signal_policy.rs` is gdb's default `handle` table). Panel features stay in
  `ui_control.rs` and `view.rs`; the UI crate only draws them.
* **Reconnect and snapshots.** The link is paused around a snapshot, a restore
  or a reconnect (`DebugPause`), then `debug_guest_moved` either refreshes a live
  server (`request_resync`; a restore ends a connected gdb client, a reconnect does
  not) or adopts the guest's sessions into a new server. Snapshots while attached
  are allowed: the guest's session state is bit-exact in a snapshot, a
  breakpoint-time snapshot is a useful thing to keep, and refusing would have
  cost that workflow for no protection once the host can reconcile. A restore that
  reboots the disks ends the session.
* **What a client sees at connect.** A process stopped at a fork or exec the panel
  had not handled is reported by `?` as the fork or exec (gdb follows it before
  `target remote` returns); stops of other threads in non-stop follow as
  notifications after `qSymbol`.
* **The forkbp flake.** `debug-check p2 forkbp` failed under host load with
  "unexpected stop Signal 17". glibc's `fork` blocks every signal around the
  clone; a child that exits before the parent unblocks leaves a queued SIGCHLD,
  which the engine correctly reports (a tracer sees the same). gdb's default for
  SIGCHLD is nostop noprint pass, which the checker did not apply. The checker was
  wrong, the engine right: it now passes the signals gdb's table says are quiet.
  `debug-check p3 sigchld` makes the race deterministic.

### Accepted guest credential and file-hash records (0.7.0)

Revision 17 also gives the tracer two lifecycle records (layouts in
`protocol/control.h`, rules in `native-schema-slices.md` section 18). They are
ordinary phase-3 events with one fixed-structure field, so the ANTT envelope and
ABI 9 are unchanged and a host that does not know them ignores them.

* `lifecycle.creds` is written from `commit_creds()`, the only place a task's
  credentials change, plus the login-uid setter. A task's first traced call
  writes its credentials as they are (START), so a task that was running when
  Capture All began is described too. No change, no record.
* `lifecycle.file_hash` is SHA-256 of the image an exec committed (not a script,
  whose interpreter is hashed and flagged) and of the file an `unlink` removed. The traced
  task pins the dentry and mount and queues a job of about 450 bytes under a
  spinlock; the system unbound workqueue reopens the file with
  `kernel_file_open` (no fsnotify event, no atime update, no file accounting) and
  publishes under the originating call's identity, so the host pairs it with the
  call although it is written later. A 32-entry digest cache keyed by inode, size,
  mtime and ctime covers an exec storm. Budget: 16 MiB per file, 16 queued jobs,
  64 MiB queued bytes, ext4/tmpfs/ramfs only; every refusal is a record with its
  reason and a cumulative loss count rides in every later record.

The host (`kernel_notes.rs`) decodes both; the call pairing, the archive index
(`lifecycle` rows now store a kind; the cached index is rebuilt once) and
`InvocationSummary::kernel_notes` carry them with their call. Triage
(`triage/kernel_records.rs`) follows credentials per task and attaches the ones in effect after
the call to Sysmon-style `User` and `LogonId` and the auditd `uid` family, and
the hash to `process_creation` and `file_delete`. Nothing is derived from a
missing record: `User` is the numeric uid (names since the tracer gaps work
below), `LogonId` is
the audit login uid only when the guest set one, and the Sigma journal is
format 3 (versions 1 and 2 still load). The MD5 digest is not recorded: no rule
in the SigmaHQ Linux pack reads a hash.

### Accepted io_uring run status and Triage file identity (0.7.0)

Guest series 0043 and 0044; the contract stays at revision 17 and every addition is
optional, so an older guest and an older host both keep working.

* **Run status with io_uring workers (0043).** `iou-wrk` and `iou-sqp` threads
  are threads of the process that made the ring, and are in its process core. The
  run did not count them (`ant_monitor_fork_prepare` skipped `PF_USER_WORKER`), so
  when a worker was the last thread out, the leader had already taken the live
  count to zero and nothing recorded the root's wait status: RUN_STATUS said
  TREE_EXITED without ROOT_EXITED, which the host rejected. Evidence from the
  previous base (series 0001-0042) and host: `guest-run` with `ant-torture --only
  async-io --level light` as root on four vCPUs gave, for each of four runs with
  Core Dump on Exit, a complete core but no execution status, state `Unknown`,
  "inconsistent run status reply" and the 30-second completion deadline; one of
  the two runs without a core lost the status the same way, the other kept exit 0
  with `Unknown` (OBSERVATION_INCOMPLETE, below). With a trace added to that
  kernel, RUN_STATUS read `flags 0x12 live 0 total 1`, and the exits were: the
  root thread with `group_dead 0` (so the live count reached zero without a
  root status), then `iou-wrk-<pid>` (or `iou-sqp-<pid>` for SQPOLL) with
  `group_dead 1` and no run to record in. The core rendezvous makes this the
  usual order: `coredump_wait` sends SIGKILL to the workers, which leave io-wq
  (so the root's ring cancellation does not wait for them) and then wait in
  `coredump_task_exit` until the copy ends, while the root goes on with its own
  exit. Without a core the workers usually, not always, leave first. Workers now join the run (live and total
  counts, root status by whichever thread leaves the group last, core published
  unavailable if one is last out of an armed run) but stay unobserved and do not
  start the core rendezvous. The same run without a core ended with the root's
  status, but OBSERVATION_INCOMPLETE (every io_uring request has an unproven
  producer) and `Unknown` state, because the host folded that flag into the
  state. Host (`execution.rs`): the state is the tree ending with nothing
  outstanding; the observation flags stay beside it (`observation_incomplete`,
  `has_async_loss`, the run note); TREE_EXITED without ROOT_EXITED is accepted
  as an old guest's reply (`root_status_missing`, exit status unknown); an
  unusable reply names its fields and no longer clears a recorded root exit
  (`ProgramRun::status_unreadable`).
  `examples/uring-check.rs` with `tests/monitor/uring-fixture.c`: `status` (the
  torture module, linked pairs, cancellation, requests pending at exit, SQPOLL, a
  non-leader root exit, a crash, AIO, each with and without a core, then Stop of
  runs with workers, handled or ignoring SIGTERM), `boots` (the hardest cases on
  fresh boots), `legacy` (an older base: Finished, exit unknown or right).
* **File identity and exec image records (0044).** `lifecycle.file_id` and
  `lifecycle.exec_image`, specified in `protocol/control.h` and
  `native-schema-slices.md` section 20. Hooks: `do_sys_openat2`, `do_renameat2`,
  `do_linkat`, `do_unlinkat` and `exec_binprm` publish in the traced call; the
  io_uring `OPENAT*` hook, a name lookup just before `RENAMEAT`, `LINKAT` and
  `UNLINKAT`, and the issue of a request that acts on an open regular file attach
  the same bytes to the request (`async.operand.file_id`). Those operations run
  on a worker with no traced call, which is why they are request operands.
* **Triage (host).** `triage/async_files.rs` groups the saved asynchronous
  observations by request and writes each file request as the equivalent system
  call, with the submitting call's identity, the path operands as `argN.name`
  fields, the recorded data as `arg1.buf` and the result of its completion; the
  scan feeds those calls through the tracking and classification it already has,
  so Opened, Read, Written, Deleted, Renamed and the detection events need no
  second path. A registered descriptor (`IOSQE_FIXED_FILE`) is not a descriptor
  number: it carries none and is resolved through the file identity. An
  `OPENAT`/`OPENAT2` with a `file_index` installs into the ring's table; its
  result is a slot (or 0), so it is shown as `registered` and never tracked as a
  descriptor of the process (`async_files::direct_descriptor`). A call that
  reaches a file by no descriptor of the run (a registered slot) is named, and
  counted as by descriptor, from the identity of the file it used and the name
  an earlier open or rename gave that identity (`FdState::identity_paths`). The
  guest publishes a request's data in stages, each at its offset in the
  transfer (a vector read fills one segment after another): one stage is the
  call's `arg1.buf`, several are its `arg1.iov[N].data` segments, up to the
  first stage that is missing. `files.rs`
  routes a call to the entry of the file it names by identity (`FileIndex::route`):
  a name seen before for the same inode joins, a name that now holds another inode
  splits the old file off, and the link count turns "deleted" into "name removed
  (N links remain)". Without identity everything is as before: a name is a file.
* **Verification.** Synthetic recordings: unit tests of the request decoding, the
  identity routing, direct-descriptor opens and the interpreter text. Real
  recordings: `uring-check record` (fixture modes `files`, `regfiles` with
  `OPENAT`, `WRITEV`/`READV`, `WRITE_FIXED`/`READ_FIXED`, a registered file and a
  direct-descriptor open, `syncfiles`, `aio` with vectors, `script`, and the
  torture module) then the ignored test `recorded_uring_triage`
  (`triage/uring_qa.rs`), which prints every row it matched and fails on any
  that is missing. `uring-check` status modes boot two vCPUs; `record` boots one
  (see Limits).
* **Limits.** A request that never completed has no result and is shown as a call
  with no exit. Requests that an SQPOLL thread submitted on behalf of the ring's
  creator have no submitting call to attach to, and are not read. Operations that touch no file (sockets, timeouts, polls) are not
  mapped. `SPLICE`, `TEE`, `FSYNC` and extended-attribute requests are not mapped.
  The io_uring rename, link and unlink identity comes from a lookup just before
  the operation, so a name changed in between is identified as it was at the
  lookup. A core of a process whose leader left first is Partial for the
  leader's missing registers, as before. Past 100,000 file requests a scan
  stops reading them and the coverage line says so. On a guest with more than
  one vCPU, a record a worker publishes after a call (an unlink's content hash)
  can be saved ahead of calls made before it, and the archive orders a call by
  its first saved record, so a file's lifecycle can list such a step early
  (found with `uring-check record` on two vCPUs; it predates this work and is
  not changed here).

### Accepted tracer and reconnect gaps (0.7.0)

Guest series 0045; the contract stays at revision 17 and everything is
negotiated: an older guest and an older host keep working, each without the
additions.

* **Negotiation.** `TRACER_CAPS` (0x10a0) is a new optional command: its reply
  lists the optional EXEC flags the guest accepts (`HASH_ROOT` 8, `HASH_WRITES`
  16) and the hashing budget. The host probes it after `CORE_CAPS`
  (`session_transport.rs`, `KernelProbe::Tracer*`), keeps the answer in
  `Snapshot::guest_tracer` and adds the offered flags to every EXEC
  (`control::with_tracer_flags`); -EOPNOTSUPP or an older revision offers
  nothing, so an older guest never sees a flag it would reject with -EINVAL. The
  flags a run was launched with are saved as `tracer_hashing` in its manifest
  and carried across a reconnect in the host checkpoint.
* **Written files (guest).** `__fput()` calls `ant_monitor_close_write()` after
  it put the file's write access; when the inode's writer count is then zero and
  the closing task belongs to a run launched with `HASH_WRITES`, a WRITE job is
  queued exactly like an exec or delete job (references only, `GFP_NOWAIT`, the
  worker on `system_unbound_wq`). The identity is the task's last traced call
  (`ant_monitor_identity_last()`); a task that has already left its run at exit
  finds the run by its root cookie (`ant_run_hashes()`). A refusal decided at the
  close is published by the worker too (`hash_reports`, bounded at 64). The
  record (`antinomie.hash/2`) adds the file's device, inode, generation, mode and
  link count, because the closing call need not name the file. Specification:
  `native-schema-slices.md` section 21.
* **The launched program (guest).** `ant_monitor_launch()` marks the context
  (`launch_exec`) and `ant_monitor_exec()` sends the commit of that exec, which has
  no traced call, to `ant_hash_launch_exec()`: hashed only for `HASH_ROOT`, under
  the launch's identity (call id 0, syscall `U64_MAX`).
* **Host records.** `kernel_notes::file_hash` reads `/2` (`HashKind::Write`,
  `FileHash::file`); `recording::launch_record_cancellable` reads the launch
  event and its notes by the root's key with call id 0, which no call owns
  (`CallReader::lifecycle`).
* **Triage.** The scan reads the launch record once and writes the launched
  program's own `process_creation` first (`normalized::launch`): image and
  command line from the launch, the user from the root's first credentials, the
  launch directory, and `Hashes` from the launch's exec hash; the root is named
  after it in the process tree, so its children's `ParentImage` is known. An
  exec whose path was not captured takes the image the guest recorded for it
  (`exec_image`), or none, never the parent's (`process_tree::observe_processes`).
  For a run with `tracer_hashing`, the `file_event` of a regular file the run
  created waits, keyed by the file's identity, for the WRITE hash of its last
  close and then carries it as `Hashes` (or `HashSkipped`); one still waiting at
  the end says no last close was recorded (`normalized::hold_creations`,
  `flush_creations`). Sysmon has no file-modify event on Linux and Sigma's
  `file_event` is the creation, so a modified existing file has no event to
  carry a hash; its hash is in Files. `files::FileIndex::observe_hashes` puts the
  latest WRITE or DELETE hash of a file into its lifecycle and Details and the
  `file.sha256` filter value.
* **User names.** `guest_names::for_run` reads `/etc/passwd` and `/etc/group`
  from the installed base the run's disk came from (`disk_base_identity`), with
  the sandboxed disk reader, which now opens a standalone qcow2 image itself
  (`disks/reader/qcow2.rs`: v2/v3, no backing file, no encryption or external
  data, zlib clusters; every table offset checked) instead of needing a
  flattened copy, and adds the account the app provisioned (uid and gid 1000).
  Chosen over a recording's reads of `/etc/passwd`, which exist only when the
  program looked a name up and show what the program read; the base is
  immutable, verified at install and read without touching the running VM.
  Limit: users created in the guest after the base was built (by a run or by
  hand) have no name and stay numeric. `User` is the name or the number; auditd
  keeps every id numeric and adds the interpreted `UID`, `EUID`, `SUID`,
  `FSUID`, `GID`… and `AUID` (`unset`, `unknown(N)`) that the enriched format
  appends; the Sigma adapter keeps reading the raw ids (its columns are
  case-insensitive, so the interpreted names are not loaded as columns).
* **A reconnected run, whole.** `recording::run_segments` follows a run's
  segments back from its newest through each boot's `resume-boundary.json`
  (`source_boot_id`, no snapshot), so a snapshot restore, which starts another
  run, is never joined. The scan (`triage/segments.rs`) walks every segment in
  order with one file index, process tree and detection journal (written to the
  newest segment, as before), checks each segment's identity with its own boot,
  takes the start, launch directory and hashing from the first segment and
  completeness from the newest unless an earlier one lost records, and gives the
  packet index every segment's own captures. A file whose operations span a
  boundary gets "reconnected" in its lifecycle and a "transport reconnected ·
  recording segment N" row in its operation timeline; the coverage line says how
  many segments were read.
* **Debugger console.** Checked live (`app/tests/debugger_live.rs`, ignored): the
  app with its backend, a BusyBox VM, the phase-2 fixture, and the console pane
  driven as a person types into it (`Console::type_text`), for GEF, the managed
  portable pwndbg and the host's system pwndbg: attach to a running program and
  Debug on start, registers, memory and the front end's context, a software
  breakpoint reached, two instruction steps, detach, and the pane's Stop, after
  which the program runs on (a debugged-from-start one to its end). Found and
  fixed: a portable pwndbg reads the user's `~/.gdbinit` even with `-nx`, and one
  that sources another pwndbg made the console stop at once ("Detected
  double-loading of Pwndbg"); pwndbg now runs with a private `HOME`
  (`<data>/tools/.console-home`, `XDG_CONFIG_HOME` removed). The pane's Stop is
  `Console::quit()`: a stopped console must say so, or its next draw starts gdb
  again.
* **Verification.** `examples/tracer-check.rs` with `tests/monitor/tracer-fixture.c`
  (`record`: every written-file case, a reconnect with network capture, users
  1000 and 65534; `legacy`: an older base), then the ignored test
  `recorded_tracer_triage` (`triage/tracer_qa.rs`); `debugger_console_live`;
  unit tests of the qcow2 reader, the names, the segments, the launch record,
  the probe and the Triage events. Evidence and numbers are in the task report.
* **Limits.** A file written through an io_uring worker or closed by a process
  outside the run is not hashed; the launched program of a desktop run is the
  shell wrapper. A file opened for writing and not written is hashed at its last
  close all the same. A run's earlier segments must be in the same recording
  folder as its newest.

### Guest conformance suite, part 1: the syscall trace log (0.7.0)

One command boots disposable BusyBox VMs, runs programs that print what they did
and checks what the app recorded and shows against it
(`tests/monitor/conformance/README.md`):

```sh
cargo run --release --locked -j 2 -p antinomie-monitor-core --example conformance -- \
    trace BASE_DIR OUT_DIR [--bless] [--groups …] [--recheck] [--no-render] [--no-build]
```

* **Fixture.** `tests/monitor/conformance/trace/fixture` (static C, one program,
  groups `user`, `root`, `threads`). Every call goes through `CALL()`
  (`oracle.h`): the raw system call with six registers, timed with
  `CLOCK_MONOTONIC`, then one `ANT_EXPECT` JSON line with the arguments, the raw
  result, the bytes behind each pointer argument at entry and exit, deliberate
  capture statuses, the file identity, async requests and why the case is
  shaped as it is. All 375 native slots are exercised, with success, failure and
  decoding variants (about 2,000 cases as UID 1000, 130 as root, 2,240 under
  concurrency). Dangerous calls are refused as UID 1000 or made harmless as root
  in private namespaces and children; every such case says why.
* **Tool.** `examples/conformance` (`main.rs` parts and CLI, `vm.rs` one VM per
  group, `judge.rs` the call-by-call comparison, `trace.rs` the part, `stress.rs`,
  `recording.rs` raw scan and pages, `render.rs`, `matrix.rs`, `golden.rs`). A
  part names its groups and checks their runs; file lifecycle, process tree,
  network and Suspicious activity are later parts of the same structure.
* **Rendering.** The ignored monitor-ui test `conformance_trace_render`
  (`trace/conformance.rs`) renders every call with the Syscall Trace view's own
  code and draws the inspector, and reports raw-value fallbacks; the suite runs
  it through cargo.
* **Strictness.** Any warning or error of any recorded call fails, unless the
  capture contract explains it and `tests/monitor/conformance/trace/gaps.json`
  names it with a reason; so does any gap or unexercised slot not listed there.
  Losses must add up exactly: packets saved = recorder attempted − failed =
  transport taken − dropped = received = persisted; events saved = attempted when
  nothing was lost; calls that show loss and incomplete async requests are bounded
  by the counted failures and observation losses.
* **Host fixes found by the suite.** Field statuses that mean there was nothing
  to copy (NULL_POINTER, ADDRESS_ONLY, NOT_WRITTEN; ASYNC_UNOBSERVED in a call's
  own Entry or Exit and the payload marker of a non-final async record) no longer
  mark a call incomplete, matching the guest recorder; the recorder's own
  incomplete marks are reported only when no field explains them, and precisely
  (lost Entry, failed sends). The per-event "packet sequence gap" warning is gone:
  packet numbers are per task across sync and async events, the END count shows
  loss. `FieldSummary::arg` carries the argument the guest captured a field for,
  and the trace places fields by it. Enumerated arguments are named (fcntl
  commands, arch_prctl codes, ioctl requests by name or `_IOC` encoding, clocks
  including CPU clocks, rlimits, madvise and fadvise advice, address families,
  epoll and SysV IPC commands, scheduling policies, reboot magic and commands,
  and more: `syscalls/selectors.rs`); address lengths are counts, not addresses;
  exec vectors read as lists and an argument with several captured objects says
  so instead of showing its address; MAP_DROPPABLE and memfd_secret's O_CLOEXEC
  have names.
* **Guest fix (series 0051, revision 17 unchanged).** An async request that ends
  with an error has no payload to lose: its final record carries no payload gap
  and no observation loss is counted (a failing io_uring READ or a rejected
  opcode used to flag the run as lossy). The terminal ioctl decoder knows
  TCGETS2/TCSETS2* (glibc's `tcgetattr`) and TIOCGPGRP/TIOCSPGRP/TIOCGSID.
* **Limits.** NOT_RESIDENT is recorded for pages a process has not touched yet
  (static glibc's start-up readlink, a forked child's first literal): the
  no-fault copy is the contract (15.1); a capture at exit would close it and needs
  a contract change. The ioctl argument is decoded for terminal requests only.
  Directory removal publishes no file identity. Rows without an entry point have
  positional argument names.

### Accepted ANT-T0097 host UI performance (0.6.2)

Remove render-time filesystem checks for host chooser availability; resolve
and cache its program asynchronously at startup and explicit capability refresh.
Use the resolved path on invocation. Flatten Explorer's bounded cached tree
only when its data/expansion changes and create widgets only for visible rows,
preserving path identity, paging, file actions and selection.

Backend, archive, chooser and dependency results wake the frontend. Suppress
unchanged idle backend snapshots and replace unconditional 50 ms redraws with
a quiet one-second fallback; active VM polling keeps its existing 50 ms bound.
Individual pending analysis views retain their own timers and input/animation
wakes remain native. Never invoke frontend wake callbacks under snapshot locks.

Tools > UI performance reports actual context renderer/vendor/version and the
last 240 UI update CPU samples, explicitly excluding GPU/presentation latency.
Provide explicit per-launch `--graphics-driver system|d3d12` without changing
global driver settings or forcing GPU selection by default. Measure native
idle/update behavior and render-thread file calls with isolated data directories.
No guest, image, shared-memory ABI, dependency or release-tag change is needed.

### Historical initial requirements

- Linux 6.12.94 existing baseline, BusyBox filesystem; Debian userspace later.
- Native Rust desktop interface without HTML. Separate QEMU display window.
- Initially empty VM list, create named VMs from one base image. Configurable
  CPU count, RAM, disk capacity. Many saved configurations, one running VM.
- Persistent VM disk overlays with explicit confirmed reset to base. User VM
  data lives outside disposable work/ build trees.
- Disconnected network default; explicit NAT enable with warning.
- Host file upload to guest path: overwrite confirmation, separate executable
  option. Never execute automatically after upload.
- Kernel implements control, upload, execution, tracing, and terminal I/O;
  no auxiliary guest control helper, except the explicitly approved temporary
  resource-only collector in ANT-T0084 below, which only revision 11 to 16
  kernels still use (revision 17 samples resources in the kernel). Ordinary init, shell and target programs
  remain userspace processes.
- Launch path, argument list, cwd, environment, UID/GID. Default unprivileged.
- Interactive terminal in host control view, independent of QEMU console.
- Trace only control-launched processes and all descendants, surviving exec,
  double fork, parent exit, CPU migration. Per-task unique identity, not PID only.
- Entry/exit correlation and full semantically defined pointer content. Stream
  large buffers in bounded chunks. Nofault observations may be incomplete.
- Nonblocking drop-new transport; capture and delivery losses remain explicit.
- Save raw telemetry and manifest. Stop saving on quota/full disk, preserve
  earlier data, visibly report persistence failure while continuing collection.
- Closing app: request guest shutdown, continue capture; after configurable
  timeout force power-off; finalize and mark clean/forced recording.
- V7 no snapshot/reconnect. No next transport version. Existing transport API
  is opaque; frontend/backend never manage CPU rings.

## Disks tab: the disks of a stopped VM (0.7.0, phases 1 to 3)

Accepted design: the documentation checkout's "Disks Tab - Implementation
Design" v2, phases 1 to 3 (the dumps are described after the limits below,
phase 3 after them). Host only; no guest kernel change.

**Mechanism.** The VM's qcow2 chain (`snapshots::active_disk`) is flattened by
`qemu-img convert -p -f qcow2 -O raw` into a sparse raw ext4 image,
`<recording dir>/disks/.scratch-<id>/root.ext4` (a scratch image). Progress is
the `(NN.NN/100%)` lines of `-p`; the converter runs under `setpriv
--pdeathsig KILL` so an app crash cannot leave it attached to the chain, and
without `-U`, so QEMU's own image lock is the backstop. After conversion the
size must equal the chain's virtual size and the ext4 magic must be at offset
1080; the superblock `s_state` gives `clean` or `not cleanly unmounted`.
`qemu-img map` (output capped at 64 MiB, falling back to the layers' allocated
sizes) gives the estimate: the sum of extents that are data and not zero, an
upper bound of the sparse output. Free space is `statvfs` of the `disks`
folder against estimate + 64 MiB (the whole logical size when a one-megabyte
probe file shows the folder cannot hold holes).

**Backend (`backend/worker_disks.rs`, `disks/{measure,job}.rs`).** One disk job
at a time (`Worker.disk_job`) holds the lease on its VM's image while
`qemu-img` reads the chain. `Worker::command` first runs `disk_lease_gate`
(`lease()` is a pure function with a test over every command).

| Command | While a job holds this VM's image | While a view of this VM is open |
| --- | --- | --- |
| `Start` | Refused ("being read for the Disks tab") | Allowed; the view is closed after the start |
| `Reset`, `RestoreVmSnapshot`, `CreateVmSnapshot`, `Delete` | Refused | Allowed; the view is closed after success |
| `Duplicate`, `Save` that resizes | Refused | Allowed; the view stays |
| `MeasureDisk`, `OpenCurrentDisk` | Refused ("another disk inspection or dump is still running") | `Open` replaces the view |
| Either, while this VM runs | Refused ("stop the VM before inspecting or dumping its disk") | n/a |

Another VM running does not matter. Scratch folders are swept when the backend
starts and before a new materialization; closing the backend deletes the open
view. `Snapshot` gains `current_disk`, `disk_measure` and `disk_job`; commands
are `MeasureDisk`, `OpenCurrentDisk`, `CloseCurrentDisk`, `DumpDisk`,
`KeepCurrentDiskAsDump`, `CancelDiskJob`.

**Reader (`disks/reader/`).** A second mode of this program, `--disk-reader`
(`worker_main_if_requested`, before CLI parsing like the analysis workers),
under the `sandbox_run` bubblewrap recipe: `--unshare-all --unshare-user
--disable-userns --die-with-parent --new-session --clearenv --cap-drop ALL`,
`--ro-bind /usr`, `--proc`, a 16 MiB `/tmp`, the program at `/worker`, the image
`--ro-bind` at `/image`, the extraction folder `--bind` at `/out`,
`--remount-ro /`, and `prlimit --as=2147483648 --nofile=64 --core=0`. The
protocol is JSON lines (`Probe`, `List`, `Info`, `Find`, `Extract`), one
request in flight, each answer echoing its id, bounded line sizes, typed
`ReadError`. The parent (`Reader`) starts the worker lazily, kills it on a
timeout, an abort or drop, and starts a new one with the next request. Guest
paths are labels: a path must be absolute without `..`, every parent must be a
real directory (a path through a link is refused), links are reported with their
target text and never followed, extraction of a link writes its target as data.
The worker writes `/out/<request id>`; `disks::extract::place` then (in the
parent, after the answer) checks it is a regular file, names it `<n>-<leaf>` with
`host_leaf` (controls, separators and direction overrides replaced, leading dots
dropped, 100 bytes) and seals it with `openat2(NO_SYMLINKS)` and `fchmod 0600`.
Bounds: listing pages of 256 (a directory is read up to 65,536 entries), Find
at most 5,000 matches, 1,000,000 entries, depth 64 and 15 s, hashes up to the
setting (64 MiB), extraction up to the setting (256 MiB; 4 GiB after the user
confirms, with a free-space check), the viewer up to 16 MiB.

**Interface (`disk_view/`).** `Panel::Disks` after Memory (layout version 7 puts
the tab after Memory in saved layouts without changing which tab shows);
`DetailsOf::DiskEntry` for the shared Details dock. The tab keeps two reader
threads (browse; find and extract) so a long find does not block the tree. The
tree is the host explorer's cached-flatten design (shared `PAGE_LEN`,
`DIRECTORY_LIMIT`, `DEPTH_LIMIT`, `tree_lines`, viewport-only rows) over reader
listings. Extract to view uses `DataWindows::open_bytes` (the data viewer);
Static Analysis uses the new `AnalyzeHostFile` command, because `AnalyzeOnly`
reads a guest path from a running VM: `Jobs::submit_host_file` copies the
extracted file into the report's specimen slot and the ordinary isolated
worker, report and quota accounting follow, with its own `Jobs` in the backend
worker so it needs no VM. Settings: `disks.{extract_cap_mib, hash_cap_mib,
hide_dotfiles, numeric_modes}`.

**Limits.** `ext4-view` 1.0.0 exposes no inode numbers or link counts, so
neither is shown and a directory cycle is bounded by the Find depth and entry
limits instead of a visited-inode set. A filesystem other than ext2/3/4 is the
"unsupported filesystem" state. The lease is held by one job per backend; the
view itself holds nothing.

### Disk dumps (phase 2)

**Folder and record (`disks/dump.rs`).** `<recording dir>/disks/<id>/` holds
`root.ext4` and `dump.json` (`DiskDump`: ids, VM, `fs_state`, `started_ms`,
`finished_ms`, `logical_size`, `allocated_size`, `sha256`, the `source` with
its layers, `system`, `imported`, `error`); `extracted/` holds files extracted
from the dump. Every field is `#[serde(default)]`, unknown fields are ignored
and an image format a later version wrote deserializes as `Unsupported` (listed,
not opened), so records move between versions. The image name in a sidecar is
reduced to its last component, so a hand-edited record cannot point outside the
folder. `list` reads `disks/*/dump.json` of every recording directory (not
`.scratch-*`, hidden folders or `extracted`; at most 1 MiB per sidecar), newest
first, one entry per folder.

**Finalization.** `Dump disk` (`Job::dump`): measure, quota and free-space
checks, `disks/<id>/` (0700), `qemu-img convert` into `root.ext4.part`,
`fsync`, size and ext4 magic/state check, rename to `root.ext4`, `fsync` of
the folder, SHA-256 (1 MiB reads of the full logical content, the `Hashing`
stage, cancelable), optional per-layer digests, then `dump.json` written
atomically and the folder synced. Any error or Cancel removes the folder;
a folder without `dump.json` is therefore never a dump. `sweep_partial` (backend
start and before every dump or view) removes folders without a sidecar that
hold nothing but `root.ext4`/`root.ext4.part`, and a stale `.part` in a finished
dump. `Keep as dump` (`Job::keep`) checks the quota ceiling against the view's
allocation, hashes the scratch image in place, then renames
`.scratch-<view>/` to `<id>/` (`promote`; on `EXDEV` it copies the scratch image,
never the chain, with `qemu-img convert -f raw -O raw` and leaves the view on
the scratch image) and writes the sidecar. The view keeps its id and extraction
folder and now reads `disks/<id>/root.ext4` (`CurrentDiskView.kept_as`, `image`);
closing it removes nothing of the dump, and deleting a dump an open view reads
is refused until the view is closed.

**Quota and space.** `JobSpec.quota` is `capture_quota_size`, applied as a
per-dump ceiling to the `qemu-img map` estimate (`DiskMeasure.quota_error`,
shown on the card before the click; the job checks it again). Views are not
bounded by it. The free-space and sparse-support preflight is the phase 1 one.

**Commands.** `DumpDisk` and `KeepCurrentDiskAsDump` carry the two Settings
flags (`disks.dump_hash`, default on; `disks.source_digests`, default off) and
go through the same lease as `OpenCurrentDisk`; `CancelDiskJob` cancels them.
`EvidenceItem::DiskDump { directory }` deletes through `DeleteEvidence`: the
path is canonicalized, must not contain `..` or be a link, must be exactly
`<recording dir>/disks/<id>` of the VM, and must hold a `dump.json`, which is
removed first. Nothing else records a dump, so no other file is rewritten.

**Import and save (`disks/dump.rs`, `disks/export.rs`).** `import` validates a
raw ext4 image: regular file, the superblock magic, a sane block size, a block
count that fits, and a file at least as long as the filesystem; qcow2 and an
MBR boot signature are named as such. It reads only the superblock, writes a
sidecar with `imported: true` and the canonical path, and leaves the file where
it is. `export` runs `qemu-img convert -p -f raw -O raw|qcow2 [-c]` (the source
format is explicit, so the guest's bytes are never probed) into a temporary
file beside the destination, then renames it with mode 0600; it refuses the
image itself, checks free space and can be cancelled.

**Interface.** The entries list is the Current disk row, **Dump disk**,
**Import image…** and the dumps (record filter `disk-dump-history` over the
query engine, context menus). The list is scanned when the recording folders,
a job's presence or `kept_as` change and on Refresh, never per frame. Whether
an imported image moved is checked in the same scan. Verify and Save run on
their own threads and are polled. Settings: `disks.{dump_hash, source_digests}`.

### Checkpoint sources, partitions, diff, content search, qcow2 import (phase 3)

**Sources (`DiskSourceSpec`).** `MeasureDisk`, `OpenCurrentDisk` and `DumpDisk`
carry a source: `Current` (`snapshots::active_disk`), `Checkpoint(id)`
(`snapshots::checkpoint_disk`: the saved, not deleted node's frozen layer,
through the same `owned()` validation and the same "no unfinished snapshot
operation" check, then `validate_disk` of that layer's whole chain against the
pinned base) or `Base` (the VM's pinned `bundle.json` base). They differ only
in the file `qemu-img` starts from, so measure, convert, lease, scratch
folders, Keep as dump and the VM-off rule are the same code. The record
(`DiskSourceKind::{Current, Imported, Checkpoint{id,name}, Base}`) lands in the
view and in `dump.json`; older sidecars read as before. The UI lists the
checkpoints of `Snapshot.vm_snapshot_trees` (which the backend fills at start
and after every snapshot change).

**Partitions (`disks/partition.rs`).** The measure step reads the first 64 KiB
of the guest disk (`qemu-img convert --image-opts` of the byte range, which
always writes its full length) and `partition::parse` decides: an ext
superblock at 1024 means a whole-disk filesystem (the Antinomie bases, no
table); a boot signature with a protective-MBR entry means GPT (header at LBA 1,
at most 128 entries of 128 to 256 bytes inside the probed window; entries whose
range is reversed, outside the usable range or outside the disk are dropped
and counted); otherwise an MBR (four primary entries; an extended entry is
listed as such, its logical partitions are not read). The filesystem of the
first 16 partitions is read (the 512 bytes at partition start + 1024). The
default partition is the GPT Linux root (x86-64 or arm64) that holds ext4, else
the largest ext4 one. The estimate is `qemu-img map --image-opts` over the same
carve, and the conversion is `qemu-img convert --image-opts
driver=raw,offset=…,size=…,file.driver=qcow2,file.file.filename=…` (commas of
the file name doubled), verified against `dd`. A partition that is not ext2/3/4
(or a table with no ext4 partition) is `DiskMeasure::unsupported()`: Open and
Dump are refused with the "unsupported filesystem" sentence. `SaveDiskPartition`
carves any partition to a host file (written as a hidden `.part` beside it,
synced, size-checked, renamed).

**Reference image and diff.** `OpenDiskReference` flattens a source into a
second scratch image beside the open view (`Snapshot.disk_reference`; a new
scratch image does not sweep the view's folder); it is closed with the view, on
the same triggers, and shares the one job slot and the VM-off rule. The UI
reuses an existing reference of the same source. The diff itself is a request of
the sandboxed reader: a reader started with a second image mounted read-only at
`/other` (the "before"; `/image` is the "after") answers `Diff` (`reader/diff.rs`).
Both trees are walked together by name; an entry in one tree only is added or
deleted and its whole subtree with it; kinds that differ are a change of type
and each side's subtree is added or deleted; directories are changed only by
kind, mode or owner; files by size, mode, owner, modification time or link
target, and when only the time differs (equal size) the bytes are compared up
to 64 MiB to tell `Content` from `Time`. Equal metadata means equal: a guest
that sets a file's time back after editing it is not seen (the Triage evidence
or a hash comparison of dumps covers that). A rename is a deletion plus an
addition. Bounds: 20,000 listed entries (totals keep counting), 2,000,000
entries over both trees, 120 s, depth 64, 65,536 entries per directory;
cancelling kills the reader. The UI keeps the results, filters them in a cached
index list (recomputed when the filter or results change) and draws only the
viewport's rows.

**Triage links.** Triage keeps the absolute guest paths of the selected run's
Changed files (`TriageView::changed_paths`, rebuilt when its index is). A diff
row whose path is in the set is marked and its Details offer **Show in Triage ›
Changed files**, which opens the Files section's Changed files tab filtered to
`file.path == "…"`. The diff publishes its non-directory paths through egui's
data store; Triage's Details of a Changed file show a link back that asks the
Disks tab to select the path. Both say what kind of evidence they are (block
evidence versus syscall evidence), never that one confirms the other.

**Content search.** `FindMode::Content` / `ContentAnyCase` (ASCII letters in any
case) in the reader's `Find`: regular files only, never through links, the first
16 MiB of each file, 512 MiB read in all, 60 s, a needle of 2 to 256 bytes, one
hit per file with its offset and a snippet in which every non-printable byte is
a dot. The answer counts files read, bytes read and files read only in part, and
says whether the byte limit or the time ended it. Cancel kills the search reader
(the tree's reader is not touched) and a new one starts with the next search.

**qcow2 import (`disks/job/import.rs`, `disks/sandbox.rs`).** A qcow2 image has
attacker-controlled metadata, so `qemu-img` runs only as `bwrap` (the shared
`sandbox_profile`: every namespace unshared, `/usr` read-only, a private
`/etc/passwd`, a 64 MiB `/tmp`) with the file `--ro-bind` at `/input`, one writable
folder at `/out`, `--remount-ro /`, and `prlimit --as=8 GiB --nofile=64
--core=0`; `qemu-img` must be under `/usr`. Steps: `info --output=json` (refused:
not qcow2, a `backing-filename`, an external `data-file`, encryption, a virtual
size over 2 TiB or none), a free-space check, `convert -f qcow2 -O raw` to a
temporary raw disk (the conversion is watched: the output's allocation may not
pass the free space left, which stops a compressed image that expands), a
partition probe of the raw disk and, for a partitioned image, a second sandboxed
conversion that carves the default ext4 partition, then the same checks as any
dump (size, ext4 magic and state), optional hash, and `dump.json` with
`source.kind = imported`. Even without the pre-check the sandbox cannot see a
backing file outside the image: the host path does not exist in it. The import
job does not hold the VM's chain (`Job::holds_chain` is false), so the VM can run
meanwhile, but it takes the one job slot.

**Reader sandbox.** `disks/reader/client.rs` builds its command line from
`sandbox_profile::apply` (with a private one-line account file from
`disks/sandbox.rs`) and adds only `/worker`, `/image`, `/other` (a diff) and
`/out`, then `prlimit --as=2147483648 --nofile=64 --core=0`.

**Commands.** `MeasureDisk`, `OpenCurrentDisk`, `DumpDisk` (+ `source`,
`partition`), `OpenDiskReference`, `CloseDiskReference`, `SaveDiskPartition`,
`ImportQcow2Disk`; `Snapshot.disk_reference`. `DiskJobPurpose` gains
`Reference`, `Carve` and `Import`. Settings are unchanged.

## Recording quota and pre-acknowledgement telemetry (0.6.2)

The recording quota (Settings, 4 GiB by default) bounds what one VM boot may
save: raw telemetry, assembled objects, terminal journals and screens, analysis
metadata, cores and network captures. The limit is read when the VM starts.

**Reaching the quota** is a boot-wide, permanent condition that stops *new*
data; it never rewrites what is already complete.

| Recording | State when the quota is reached |
| --- | --- |
| Run whose program tree ended and whose terminal is closed | Untouched: no `recording_error`, finalizes normally. A packet of such a run that still arrives is counted and noted once in the run's `notes`. |
| Run still open | Stops saving telemetry, objects and terminal output, keeps everything saved so far, `recording_error` is the quota message. |
| Capture still open | Same as an open run. |
| Closed capture archive | Untouched. |
| Boot unassigned archive | Stops growing; `health.persistence_error` is the quota message. |
| Run or capture started after the quota was reached | Born stopped with the quota message. |

The message names the limit and says that everything saved before is intact.
The frontend reads it in `health.persistence_error`; `storage_dropped_packets`
counts the packets that were not saved. A quota failure of one terminal write
is the same event: it stops every open recording, not only that run. Any other
terminal write failure stops saving for that run only, and the run's first
recorded cause stays the reported one. Raising the quota applies to the next
VM start; a running boot is not resumed.

**One copy of a packet nobody owns.** While a capture that can still save
observes a packet no run owns, that capture's archive is the packet's only
raw copy; the boot's unassigned raw archive skips it. Run-owned packets are
still written to the run archive and, under Capture All, to the capture
archive, because each archive must be readable on its own; the capture's
object store also keeps its own objects. Capture All therefore still costs up
to twice the run's own telemetry while a run is active.

**Pre-acknowledgement buffer.** Telemetry of a launched program can arrive
before the reply to its EXEC command. Such packets wait in a buffer keyed by
root cookie until the reply claims them.

| Rule | Value |
| --- | --- |
| Per-cookie size | 16 MiB (`PreAckLimits::cookie_size`) |
| Size for all cookies | 32 MiB (`PreAckLimits::total_size`) |
| Age limit | 5 s (`PreAckLimits::max_age`); older packets are dropped |
| Cookies tracked | 64; the one quiet longest is forgotten first |
| Never buffered | Cookie 0 and the app's own resource collector |
| On claim | The cookie's entry is removed, so an overflow never outlives it |

A cookie that overflows or ages out only counts its own loss. When that cookie
is claimed the loss becomes an entry in the run's `notes` (a field separate
from `recording_error`, which gates terminal journaling); the lost packets
remain in the boot's raw archives. A cookie nobody claims disappears.

## Recording disk work off the transport thread (0.6.2)

The thread that drains telemetry and serves commands never waits for the
disk. Run, Upload, Stop and snapshots are answered while a recording saturates
the disk.

| Write | Where it happens | Durability |
| --- | --- | --- |
| Small JSON publications (`artifacts.json`, capture summaries, process lists) | A bounded queue drained by one writer thread (`storage/json_queue.rs`) | Published within the disk's latency, not when the call returns. A later value of a path replaces a pending earlier one and is never overwritten by it; a direct write to the same path waits for the queued one first. Queued values are capped at 8 MiB and the queue at 64 MiB / 4,096 paths; direct writes have no cap. |
| Raw packets and object chunks | The recording writer thread (`writer.rs`) | Ordered per archive; payload before the index records that name it. |
| Durability of a stopped boot (fsync of archives, final manifest) | One bounded background flush worker (`recording_flush.rs`) | Done after the guest is told to stop; the boot manifest is written after the archives it lists. |

**Object packs.** Captured buffers of an archive are stored in append-only
segment files `objects/objects-NNNNNN.seg` with an append-only index
`objects/objects.idx`, instead of one file per buffer. A field keeps its
`stream-task-call-phase-seq-object.raw` name; readers look for that file first
(archives made before packing) and otherwise resolve it through the index.
Identical chunks within an archive are stored once. Quota counts the segment
and index bytes actually written.

**Terminal output.** One worker pass reads a run's terminal until it is
empty, up to 4 MiB or 40 ms per run, instead of a single 4 KiB read, so a
chatty program is not throttled to the pass rate.

**Stop.** Guest shutdown is requested before the host makes the recordings
durable, so host disk work does not use up the guest's shutdown time. A
graphical guest gets at least 30 s to shut down (`shutdown_timeout` applies
as configured to console guests) before the VM is forced off.

## VM stealth profiles (0.6.2)

`VmConfig.stealth` (`monitor-core/src/stealth.rs`) holds the identity a VM
shows its guest. A configuration without the field is Transparent, which adds
no launch options, so VMs saved before 0.6.2 launch exactly as they did. New
VMs default to Realistic desktop.

| Entry | QEMU option | Transparent | Realistic |
| --- | --- | --- | --- |
| Machine identity | `-smbios type=1,2,4,17`, `-smbios file=` (type 0 BIOS and type 3 chassis tables written to the runtime directory; the BIOS table lists real characteristics and not QEMU's "virtual machine" bit), `-machine smbios-entry-point-type=64` | QEMU strings, chassis Other | One of eight built-in vendor machines (Dell, HP, Lenovo, Supermicro; Intel and AMD) with random serials and UUID |
| ACPI OEM IDs | `-machine x-oem-id=,x-oem-table-id=` | `BOCHS` / `BXPC` | The machine's vendor IDs |
| CPU | `-cpu host,-hypervisor,kvm=off,pmu=on` (without KVM: `max,model-id=<host CPU name>,-hypervisor`); passthrough replaces the VM's CPU model setting | QEMU model, hypervisor bit, KVM signature | Passthrough, hidden hypervisor bit and KVM signature, performance counters |
| CPU caches | `-cpu host,host-cache-info=on` (passthrough only) | QEMU's cache sizes | The host's cache sizes |
| Topology | `-smp N,sockets=1,cores=N,threads=1` | `-smp N` | One socket of N cores |
| Network card | `-device e1000e\|e1000\|rtl8139\|virtio-net-pci,mac=` | virtio-net, `52:54:00:12:34:56` | e1000e with a random Intel (`3c:fd:fe`) address; a random locally administered address is offered |
| USB | `-machine usb=on` (ICH9 EHCI with UHCI companions at 00:1d) | No USB controller | Present |
| Disk and CD-ROM | `-global virtio-blk-pci.serial=`, `-global ide-cd.model=` | QEMU defaults | A Samsung-style disk serial, an LG DVD model |
| Devices | `-machine vmport=off,hpet=off` | VMware port and HPET present | No VMware port; HPET kept |
| Clock | `-rtc base=localtime` | UTC | UTC (local time is offered for Windows-like guests) |

Hiding the KVM signature makes the guest use its TSC instead of kvm-clock.
On AMD hosts the topology stays cores only (QEMU warns about SMT threads).
The profile is validated before a VM is created, saved or launched: MAC
addresses are six hex pairs and not multicast, identity strings have no
control characters and are at most 64 bytes, ACPI IDs fit their 6 and 8
bytes, and the UUID is in 8-4-4-4-12 form.

**What a profile cannot change.** The root disk stays virtio-blk: the bases'
kernels build AHCI and NVMe as modules and the bootstrap initrd loads none.
The firmware stays SeaBIOS: under OVMF the kernel's EFI stub places the
kernel through firmware allocations that do not know the bootstrap page
(`antinomie_boot_gpa`), so with KASLR the kernel could land on it and the
transport would fail now and then; UEFI needs that page reserved in the EFI
stub first. The pointer stays virtio-tablet (the Antinomie window needs an
absolute pointer, and the USB tablet is named QEMU as well). The RTC stays in
UTC by default because Linux guests read it as UTC; local time would shift
the guest clock and every recorded timestamp. The fw_cfg device, the q35 chipset layout, the
virtio display and VM-exit timing are outside launch options; the Stealth
profile window and the Summary list them under "Still visible". The guest
kernel's own traces are handled in the guest (see "Guest stealth" below). A
snapshot taken with other hardware may not restore after the profile changes.

**Summary.** The VM configuration section of the Summary shows Compute,
Storage and display, and Network and transport cards, and a Stealth profile
card with the preset, the machine identity (machine, chassis, serial,
firmware, ACPI OEM), the CPU, network card and MAC, devices and clock, and
what is still visible. Configure… opens the VM dialog while the VM is
stopped.

**Verified** on QEMU 11 with KVM (AMD host): a Realistic desktop BusyBox
guest reads `LENOVO` / `11JN0047US` / chassis 35 from DMI, has no
hypervisor CPU flag, uses the `tsc` clocksource, sees an Intel 0x8086 e1000e
card with a `3c:fd:fe` address, Intel ICH9 USB controllers (8086:2934-2936,
293a), the host's 16 MiB L3 and a `LENOVO` ACPI OEM ID, and records a
guest-run without loss (3,456 packets, none dropped).

## Guest stealth (0.7.0)

Guest series 0046-0050; contract revision 17 unchanged, every guest change
either invisible to the host or negotiated. What a sample sees from inside the
guest, measured on a BusyBox base with the Realistic desktop profile, and
what the guest kernel and the base now keep from it.

**The check.** `examples/stealth-check.rs measure BUNDLE NEW_DATA_DIR PROBE
[desktop|laptop|server|transparent]` boots one VM (two vCPUs, 2 GiB, isolated
NAT) with that preset, uploads the static `tests/monitor/stealth-probe.c` and
launches it as a run, as root and as uid 1000, after the host's first
resource polls. The probe prints `STEALTH verdict key value` lines (pass: looks
like a real machine; fail: a giveaway; info; skip: not readable for that
user), the check turns them into `ROW` lines and `stealth.md`/`stealth.tsv` in
the data folder and fails when the root run's recording holds fewer than 100
calls (observation must not suffer). The probe reimplements
systemd-detect-virt's VM checks (CPUID leaf 1 and 0x40000000, DMI vendors, the
SMBIOS BIOS "virtual machine" bit), virt-what's (DMI, `/proc/cpuinfo`, block,
SCSI and PCI vendors, fw_cfg sysfs and its I/O port), the Linux side of
pafish (user and host names, uptime, CPU count, memory, disk size, rdtsc twice
and around cpuid, a 500 ms sleep timed by the monotonic clock and the TSC),
the MAC prefix and NAT addresses, and Antinomie's own: `/proc/cmdline`,
`/proc/version`, `uname`, `/proc/config.gz`, `/proc/kallsyms`, `/proc/modules`
and `/sys/module`, the kernel log, BTF and tracefs, `/proc/iomem` and
`/proc/ioports` names, ACPI devices, every process's comm and command line
watched for four seconds (worker names change with every work item), and the
launched program's parent, session, process group, terminal and environment.

**Before → after** (root's verdict; user's where it differs):

| Check | Before | After | How |
| --- | --- | --- | --- |
| `kernel.cmdline` | fail: `… antinomie_ring_kib=1024 antinomie_boot_gpa=0x40000000` | pass: `console=tty0 console=ttyS0 panic=-1` | 0046 |
| `dmesg.antinomie` | fail: the command line twice, readable by users (`dmesg_restrict` 0) | pass: none; root only (`dmesg_restrict` 1) | 0046, build script |
| `kernel.version` | fail: the builder's `user@machine`, build time and time zone | pass: `(debian-kernel@lists.debian.org) … Debian 6.12.94-1 (2026-06-20)` | build script |
| `kallsyms.antinomie` | fail: 365 `ant_*` of 190,666 | pass: none (854 of the recorder's symbols hidden) | 0047 |
| `proc.comm-antinomie`, `proc.kworker-names` | fail: `kworker/u8:N-antinomie-control`, `-antinomie_resources` | pass | 0048 |
| `self.parent` | fail: PPid 2 (kthreadd) | info: PPid 1 (init) | 0050, `SHELL_JOB` |
| `self.session` | fail: sid = pgid = pid (session leader) | info: own process group, foreground, in session `pid - 1` whose leader does not exist | 0050, `SHELL_JOB` |
| `acpi.devices`, `iomem.names` | fail: `QEMU0002:00` in sysfs and `/proc/ioports` | pass (sysfs); `bochs-drm` and `virtio-pci-modern` remain | 0049 |
| `smbios.vm-bit` | fail: set | pass: clear | host, `stealth.rs` |
| `base.hostname`, `base.users`, `base.fs-label` | fail: `localhost`, `analyst`, label `antinomie` | pass: `debian`, `user`, no label | image builders |
| `acpi.tables` (root) | fail: BXPC creator ID, `QEMU0002`/`FWCF` in the DSDT | unchanged | limit |
| `fwcfg.ioport` (root) | fail: signature `QEMU` at port 0x511 | unchanged | limit |
| `pci.vendors` | fail: subsystem vendor 1af4 on every q35 device, Bochs display 1234:1111 | unchanged | limit, launch options |
| `virtio.devices`, `block.devices`, `base.root-device` | fail: virtio disk `vda` | unchanged | follow-up card (SATA/NVMe) |
| `display.fb` | fail: `bochs-drmdrmfb` (or virtio-gpu) | unchanged | limit |
| `net.addresses` | fail: gateway 10.0.2.2, DNS 10.0.2.3 | unchanged | limit, launch options |
| `timing.rdtsc-cpuid` | fail: median about 16,000 cycles | unchanged | limit |
| `base.uptime`, `base.memory`, `block.disk-size` | fail: seconds, 2 GiB, 8 GiB | unchanged | the VM's settings and a fresh boot |
| CPUID, DMI strings, MAC, clocksource, `cpuinfo` | pass (the 0.6.2 profile) | pass | |

Totals with the Realistic desktop preset: 27 of 72 checks gave the VM or
Antinomie away before, 14 after; with this app and the new base the user's
view has no Antinomie name left. The tables, probe outputs and logs of both
measurements are kept with the task report.

**Command line (0046).** `setup_arch()` hands `boot_command_line` to
`ant_cmdline_take()` (`kernel/antinomie/stealth.c`) before it first prints it:
every `antinomie_*` option is cut out (quoting and the order of the others
kept) and applied at once with `parse_early_options()`, so the existing
`early_param()` handlers run as before and nothing later sees the options. The
decompressor reads the original line for its KASLR placement. The host is
unchanged.

**Symbols (0047).** `section_begin.o` and `section_end.o`, linked first and last
in `kernel/antinomie`, put labels at the start and end of its `.text`,
`.rodata`, `.data`, `.bss` and per-CPU sections (`sections.h`; the text labels
are annotated as not being call targets for objtool). `ant_symbol_hidden()`
answers for an address in one of these ranges or an `ant_*` name (the hooks
elsewhere and their `__pfx_`, `__ksymtab_`, `__setup_` and initcall entries).
`/proc/kallsyms` skips those lines for every reader, root too, and
`/proc/<pid>/wchan` shows 0 for them. The kernel's table is complete: oopses,
`%pS`, kprobes, `kallsyms_lookup_name()` and the debugger are unaffected.

**Workers (0048).** The resource refresh is queued on `system_unbound_wq`
(one work item, one refresh in flight); the control (ordered), process-core
and debug queues keep their own ordering and limits and are named
`events_unbound`, the system queue whose worker pool they share.

**ACPI (0049).** `acpi_bus_check_add()` skips devices whose `_HID` starts with
`QEMU` (fw_cfg `QEMU0002`, pvpanic `QEMU0001`). Nothing in the guest uses
fw_cfg after the firmware: SeaBIOS and the linuxboot option ROM read the
kernel, initrd, ACPI and SMBIOS tables through it before the kernel runs, the
BusyBox kernel has no fw_cfg driver, the Debian one's `qemu_fw_cfg` module
has no device left to load for (not run on a Debian base here), and the host uses no fw_cfg device (no vmcoreinfo). The device stays in
QEMU, so its I/O ports 0x510-0x51b still answer `QEMU` to root with `ioperm`.

**Launch shape (0050, negotiated).** EXEC flag `SHELL_JOB` (32), listed in
TRACER_CAPS `exec_flags`; the host asks for it on every launch when the guest
offers it (`control::with_tracer_flags`), alongside the hashing flags (which
alone are saved as the manifest's `tracer_hashing`). `execute()` allocates a
PID before the launch (`alloc_pid()` in the initial namespace, so it is lower
than the program's); in `launch_init()`, after the program took its terminal
as session leader, `launch_as_job()` moves it under tasklist_lock from
kthreadd's children to init's (`real_parent`, `parent`, `exit_signal`
SIGCHLD), moves its session to that PID (`change_pid(PIDTYPE_SID)`) and points
the terminal's session at it. Result: PPid 1, pgid = pid = the terminal's
foreground group, sid = an id no process holds, `/dev/tty` opens, a child can
`setsid()`, the program cannot (it leads a process group, as under a shell's
job control). Init reaps it at exit (BusyBox init and systemd reap any
child). The PID belongs to the session from then on and is freed with its last
member; a launch that fails before frees it like a failed fork's. A real
parent shell is not possible: it would be a process running in the guest for
Antinomie, which the design excludes, so this is the shape of a job whose
terminal shell has exited. An older host never asks and gets kthreadd as
parent; an older guest does not offer the flag.

**Build string and log.** `scripts/build-monitor-kernel.sh` sets
`KBUILD_BUILD_USER`/`HOST` from the pinned package's maintainer
(`debian-kernel`, `lists.debian.org`), `KBUILD_BUILD_VERSION=1`,
`KBUILD_BUILD_TIMESTAMP` from its changelog date and
`KBUILD_BUILD_VERSION_TIMESTAMP="Debian 6.12.94-1 (2026-06-20)"`, as Debian's
`debian/rules.real` does (values in `adapter.conf`: `SOURCE_VERSION`,
`SOURCE_DATE_EPOCH`, `SOURCE_MAINTAINER`); the build becomes reproducible in
time too. The minimal profile disables `LOCALVERSION_AUTO` and builds with
`LOCALVERSION=`, so a git author tree no longer gives `6.12.94-g<commit>`,
and enables `SECURITY_DMESG_RESTRICT` as Debian does. The compiler part of
`/proc/version` is the builder's compiler (Debian's own builder VM has
Debian 13's gcc 14; a host build shows the host's). The release stays
`6.12.94`: Debian's is `6.12.94+deb13-amd64`, and changing it would move the
Debian base's modules and the bundles' `kernel_version`.

**Base defaults.** BusyBox and Debian bases default to the hostname `debian`
(the Debian installer's default), the BusyBox base names uid 1000 `user`
(home `/home/user/`), the Debian account form proposes `user`, and neither
image gives the root filesystem a label (nothing mounts it by label).

**Known limits** (what neither a launch option nor the guest kernel removes
without a cost to observation or a separate design):

* *VM-exit timing.* CPUID, I/O ports and other intercepted instructions exit
  to KVM: rdtsc around cpuid measures about 16,000 cycles on this AMD host
  (bare metal: 100-250). Plain rdtsc and sleep timing look normal.
* *Tracer overhead.* Each traced call of a run writes telemetry; a sample that
  times its own system calls against a baseline sees them slower (see the
  overhead benchmark). The debugger's parked thread shows state `D`, not the
  `t` of a ptrace stop (it waits killable).
* *Root inspection of the guest kernel.* Root can read `/proc/kcore`, place a
  kprobe on a recorder function by name, read `/proc/<pid>/stack`, iterate
  kernel symbols with BPF, or read the original boot command line from the
  boot parameters' memory; the guest kernel is modified and cannot hide that
  from its own root. The Debian kernel profile also keeps Debian's
  `DEBUG_INFO_BTF` (world-readable `/sys/kernel/btf/vmlinux` names every
  function, the recorder's too) and `FUNCTION_TRACER` (root's tracefs lists
  them): not changed here because the Debian kernel was not rebuilt.
* *q35 PCI layout.* QEMU gives every q35 device the Red Hat subsystem vendor
  1af4, and the chipset (ICH9, 8086:29c0 host bridge) is QEMU's choice of a
  2009 platform.
* *QEMU's ACPI tables and fw_cfg.* To root, every table header has the creator
  ID `BXPC`, the DSDT describes `QEMU0002`/`FWCF`, and port 0x511 answers
  `QEMU`; the kernel log (root only now) prints the table headers.
* *Virtio disk and the emulated display.* `vda` with vendor 1af4 (SATA/NVMe is
  the follow-up card); the display is Bochs (`bochs-drm`, 1234:1111) or
  virtio-gpu.
* *NAT addresses.* QEMU user networking gives 10.0.2.15, gateway 10.0.2.2 and
  DNS 10.0.2.3, which VirtualBox shares; the BusyBox base configures them
  statically.
* *A fresh boot.* Uptime is seconds to minutes; the VM's CPU count, memory
  and disk size are its settings (pafish flags under 2 CPUs, 2 GiB, 60 GiB).
* *Environment.* A run gets exactly the environment the user set (by default
  `PATH` and `TERM`), not a login shell's `HOME`, `USER`, `SHELL`, `PWD`.
* *Older bases* keep their command line, build string, symbols, worker names
  and `QEMU0002` until rebuilt, and are launched with kthreadd as parent.

## Detection scanned inputs (0.6.2)

Every detection report records `inputs` (`analysis/detection/inputs.rs`):
one `ScannedInput` per thing the rules were run against, with its kind,
path, display name, size, SHA-256 when known, outcome (`scanned`, `partial`,
`skipped`), the reason for a partial or skipped outcome, and a coverage
detail. The field is `Option`: reports saved before it load as `None` and the
Detection panel says the list was not recorded. At most 10,000 rows are kept
(further inputs count as omitted evidence); the panel draws the first 200.

| Engine | Rows | Detail | Partial or skipped when |
| --- | --- | --- | --- |
| YARA | The executable (the specimen static analysis kept, named after the sample) | — | Its report or bytes cannot be read |
| YARA | The process core and the guest memory dump | Blocks of up to 64 MiB scanned; mapped ranges not captured | Memory scanning is off; the dump cannot be parsed; the time or 512 MiB budget was reached; mapped ranges are missing |
| YARA | Each recovered file under the memory dump's `files/` | — | Recovered-file scanning is off; there are none; the file exceeds 64 MiB / 512 MiB total; it changed during the scan |
| IDS | Each run-owned PCAP segment (its original path, not the scan's snapshot) | Packets | Staging failed; Suricata failed or timed out; the segment was still being captured; the 100 s budget was reached |
| Sigma | The normalized event journal | Events per category | The journal is not ready, has no end record, omits oversized events, does not cover every call, or the scan used a live prefix |

A row's outcome is about the data, while the report's state also covers the
rules: an IDS result is Partial when rules are skipped even if every segment
was scanned. Clicking a row opens the executable in Static Analysis, a PCAP
in Network, the core in Core dumps, the memory dump in Memory, or a
recovered file's folder.

## Accepted ANT-T0091 run triage (0.6.2)

ANT-T0101 reorganizes triage presentation around section navigation,
detector comparison and complementary behavior/network sections. The specimen
name, path and hash are not repeated above the tabs. Detection shows each
rule’s recorded explanation and match location. Local destination addresses
are labeled without a country or organization lookup. Wide peer sections align to the taller content; narrow panes stack.
Properties groups identification, exact hashes and similarity hashes/classifiers; the
shared Details pane uses aligned field/value rows. Summary observation previews
retain existing exact evidence and shared Details navigation. Missing or partial
coverage stays explicit; count and detection semantics do not change. Use the
existing light/dark palettes and bundled fonts. Emphasized labels set those
palette colors explicitly, because egui's strong style follows the active
widget color. No new dependency or external asset. Address enrichment stays
off the render path: the default is local TShark GeoIP, and dig/whois runs
only in the index worker when that setting is selected. Local addresses are
never queried.

ANT-T0099 extends these host-only views with exact operation-time executable
labels, standard-stream/library visibility controls and stable column sorting
before archive pagination. Sorted process lists retain parent/depth fields in
Details; recorded order restores tree indentation. A temporary SQLite spool
bounds sorted query data and retains original evidence identities.

The Properties tab analyzes the selected run's digest-verified retained specimen.
MD5/SHA-1/SHA-256, ssdeep and TLSH are computed in the sandboxed worker with
locked Rust libraries (`fuzzyhash` for ssdeep, `tlsh2` for TLSH), so they need
no installed tool; both were checked against ppdeep and py-tlsh. When TLSH
cannot hash an input (under 50 octets, or too uniform), the field says why.
File type comes from the executable parser; the file and Magika executables run
in the same mandatory offline sandbox. Magika is looked up in the managed tools folder first (`<data-dir>/tools/magika`, mounted read-only at
`/opt/antinomie-tools` as for the analysis worker), then in `/usr/bin` and
`/usr/local/bin`. Tools > Analysis tools installs Magika 1.1.0 from the
official google/magika release (a single Linux x86-64 executable with its model
built in; pinned by URL, size and SHA-256). Missing tools are explicit
unavailable states. vhash and TrID are no longer shown; fields of those names
in an older properties.json are ignored when it is read. No sample/hash lookup,
model download or guest change is introduced. properties.json remains beside
the saved specimen for export. Saved metadata stays readable and is labeled not
reverified when needed. File sizes in the UI read `N bytes (X.Y KB)` with
1024-based units.

Detection has independent YARA, IDS and Sigma jobs. Production rules come from
the Detection rules page under `<data-dir>/rules/`: installed community packs, custom
group revisions and the enabled-rule selection. The manager reads
`https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve/catalog.json`
only when Check or Install/Update is used, and only if
Settings allows outbound catalog access; the Detection rules page offers to allow it
in place and names every host it will contact. Scans do not contact the network.

The catalog has two schemas, both read by `monitor-core/src/ruleset/catalog.rs`.
Schema 1 lists hosted tar.gz archives (`download_url`, `sha256`, `size`) and is
still read so existing installs keep working. Schema 2 lists *sources*; the
bucket holds only `catalog.json`, a README and a NOTICE. When a catalog says
`"schema": 2` it takes precedence. A schema 2 pack entry:

| Field | Meaning |
|---|---|
| `id`, `engine`, `name` | Stable pack id, `yara`/`ids`/`sigma`, display name |
| `homepage`, `license`, `license_url` | The publisher's project, license in words, license text |
| `revision`, `revision_kind` | The pin: a release tag, a commit, or `rolling` |
| `app`, `engine_requirement`, `rules`, `helpers`, `evidence`, `limits` | As schema 1; counts are approximate |
| `sources[]` | `url` (HTTPS), `format` (`file`, `zip`, `tar.gz`), `size`, optional archive `sha256`, `rolling`, `strip`, `paths` (directories holding rules) and `files[]` (`path`, `sha256` of every file kept) |
| `filter` | `copy` (extensions, support files), `yara-forge` (allowed rule licenses, allowed repository licenses, repository to license table) or `sigma` (log sources to keep) |
| `options[]` | Per-install choices, off unless `default`; `include-unlicensed` adds YARA-Forge rules from repositories without a license, with a warning |
| `notices[]` | Terms shown before the download |

```json
{
  "id": "yara-forge-core", "engine": "yara", "name": "YARA-Forge Core",
  "homepage": "https://github.com/YARAHQ/yara-forge",
  "revision": "20261011", "revision_kind": "release",
  "sources": [{
    "url": "https://github.com/YARAHQ/yara-forge/releases/download/20261011/yara-forge-rules-core.zip",
    "format": "zip", "size": 1748575, "sha256": "bf0cc68e…",
    "files": [{"path": "packages/core/yara-rules-core.yar", "sha256": "f871f618…"}]}],
  "filter": {"kind": "yara-forge", "allowed_licenses": ["MIT", "…"],
             "allowed_repository_licenses": ["DRL-1.1", "…"],
             "repository_licenses": {"https://github.com/SEKOIA-IO/Community": {"license": "DRL-1.1"}}},
  "options": [{"id": "include-unlicensed", "default": false, "label": "…", "warning": "…"}]
}
```

`ruleset::install_source` (`source_install.rs`) downloads each source through a
`Fetcher` (`source_fetch.rs`: the system `curl`, HTTPS only, size and time
bounded, cancellable; a redirect may only reach the publisher's own hosts, for
example `github.com` to `codeload.github.com`), reads only the listed files from
the download (`source_archive.rs`), and compares each with its pinned hash. A
pinned source that differs, or lacks a listed file, refuses the install and
leaves the previous selection. A `rolling` source (Emerging Threats, abuse.ch)
records the difference in the pack's provenance instead, because the publisher
updates it in place. Downloaded content is parsed and never executed. The local
filter then runs: the YARA-Forge filter (`source_yara.rs`) splits the package
by source repository, keeps a rule whose own `license` meta starts with an
allowed license or, when it names none, whose repository's license is allowed,
drops repositories without a license unless the `include-unlicensed` option is
on, adds the repository license to kept rules as `antinomie_repo_license` meta,
and drops rules YARA-X cannot compile; the Sigma filter (`source_sigma.rs`)
keeps documents whose log source is listed. The result is indexed like any
pack and registered as a version named `<revision>-<12 hex of the plan digest>`,
where the plan digest covers the pinned inputs, the filter, the chosen options
and `FILTER_REVISION`; the installed pack records its source, hashes and what
the filter removed (`SourceProvenance`), which the Detection rules page, the rule-set
list and each scan's selection manifest show.

`scripts/rules/prepare-catalog.py` generates the catalog from pinned upstream
revisions: it downloads each source into its own directory, hashes every kept
file, counts rules, verifies repository licenses and writes `catalog.json`,
`README.md` and `NOTICE`. `scripts/rules/publish-rules.py` publishes it; a
schema 2 catalog has no archives to upload.

Sigma `network_connection` rules are evaluated from `connect()` calls the
kernel accepted, `accept()` calls (`Initiated` false, the peer as `SourceIp`)
and each UDP peer a socket first sends to (`sendto` with a captured address, or
`connect` on a datagram socket), whose type comes from tracking `socket()`
descriptors. `DestinationHostname` is the name of a DNS answer in the run's
capture for that address, matched by address and, when several names share
one, by time; it is marked inferred. `process_creation` carries
`ParentImage`, `ParentCommandLine` and `ParentProcessId` from the fork or clone
result and the parent's last committed exec, and `CurrentDirectory` from the
launch directory followed through `chdir`/`fchdir` (inferred once a `chdir` has
run, because the join is lexical). `file_event` covers `O_CREAT|O_EXCL`,
`O_CREAT|O_TRUNC` and `creat()` opens, `O_TMPFILE`, `mkdir*`, `mknod*`,
`link*` and `symlink*`; a truncating create counts as new only when the path
was not seen to exist earlier in the run, which is inferred and marked so.
Sigma `process_termination` events come from the task-exit record the trace
attaches to the call a process ended in: one per thread-group leader, with
`Image`, `ProcessId`, `ThreadId` and `User` where known. There is no
`ProcessGuid`, and the exit time travels as the event's time.
Sigma `service: auditd` rules are evaluated against auditd-style records under
the journal category `auditd`: `SYSCALL` (`Syscall`, `a0`..`a3` as hex, `exit`,
`success`, `pid`, `ppid`, `exe`, `comm`), `CWD` (`cwd`), `PROCTITLE` (`proctitle`:
the arguments NUL-joined and hex-encoded, 128 bytes at most; only with a whole
argument vector), `EXECVE` (`argc`, `a0`..`a15` from
the captured argument vector), `PATH` (`name`, `nametype`) and `SOCKADDR`
(`saddr`). The trace has no audit keys, credentials, file modes or inodes, so
those fields are absent and a rule that needs one is reported as not
evaluated. An event's `_inferred` list (event journal format 2; format 1
journals still load) names the fields that came from tracking or correlation,
and a finding says how many of its matched events rely on one. Rules that need
a field the journal lacks, and keyword rules, are still reported as not
evaluated; other services (`syslog`, `sshd`, `cron` and similar) have no events.
Suricata is an optional system
package, listed in App dependencies. pySigma 2.x with its SQLite backend is
the Sigma analysis tool: Tools > Analysis tools creates
`<data-dir>/tools/sigma/venv` with the system Python and installs a
hash-locked set of wheels (`assets/sigma-requirements.txt`, written by
`scripts/rules/lock-sigma.py`); scans use it unless a Sigma Python is set.
A downloaded pack does not install its engine. All execution stays in the
existing mandatory offline sandbox. Results retain sources, versions, the
selection digest, licenses, corpus hashes, coverage, rule-supplied ATT&CK
references and original syscall/packet/byte identities under
triage-detection/{yara,ids,sigma}/report.json. Automatic scanning runs once per
ready input and selection. Missing evidence, a missing engine and “No rules
enabled” stay distinct from a complete scan with zero matches.
Shared Details owns match inspection; byte previews verify the scanned block's
digest, and packet jumps validate the owning run and capture segment.

YARA scans the exact retained specimen; optional targets are declared captured
ELF core/RAM extents and recovered files. Memory blocks are at most 64 MiB,
with 512 MiB total input, explicit gaps and no cross-block completeness claim.
IDS evaluates frozen run-owned PCAP segments independently with bounded
reassembly; encrypted contents, missing segments and cross-segment flow state
are unavailable. General network triage aggregates all owned segments before
filters/sorting/pagination and keeps the capture path with every frame identity.
Sigma uses upstream pySigma conversion, not a second expression implementation.
Its derived JSONL event journal precedes visibility filters and pagination;
unsupported logsources/conditions and missing fields remain explicit. Bounded
argv previews do not supply a complete CommandLine. Rules needing that field
cannot produce positive or negative conclusions from this recording. Windows
event-log rules are incompatible with Linux telemetry; HTTP/DNS is VM-wide.
Complete, partial, unavailable and not-scanned states remain distinct.

Summary is the first/default tab, followed by Properties and Detection. Activity,
file and decoded network counts are collected before visibility filters, queries
and pagination; absent network input is unavailable, not zero. Task identities
include threads and are not labeled as a process count. Rule totals/occurrences
and unique rule-supplied ATT&CK references are cached when reports change. Count
buttons navigate to their corresponding evidence tabs. No vendor consensus,
malware verdict or invented threat score is derived from these counts.

Dedicated PCAPs are selected by identity-matching run artifact ownership, rather
than host-time comparisons against QEMU's potentially shifted capture clock.
Shared captures retain the existing time-window restriction; packet timestamps
are labeled as capture-clock values. A dedicated capture takes priority over a
simultaneous manual capture from the same boot.

The user authorized all 20 triage/history issues from the Notion 0.6.2 list.
Keep this host-only work on release-0.6.2. Triage requires one explicit program
run; capture/all-traces selections must not populate it. Index the selected run's
retained prefix off the UI thread and keep process descendants scoped to that
root. History rows select the same run and open triage; both histories sort by
host start time, newest first, with start time as the leftmost column.

Double-clicks navigate to exact retained evidence. Syscall identity is the
stream/task-cookie/call tuple, because call IDs are per task. Reveal the target
despite existing category filters without overwriting saved preferences. Open
the owned PCAP before selecting a packet's original frame and clear obstructing
packet filters for this explicit navigation.

Opened files: time, path, PID/TID, result, evidence. Read files adds transferred
content with a bounded, ellipsized preview. Changed files groups original-to-final
captured bytes per run and retains an operation timeline. List observed content,
metadata and namespace operations, including failed attempts and shared mapping
observations. Unknown originals, offsets, inode aliases and missing bytes stay
explicit gaps. No host filesystem access is inferred from a guest path.

The Network viewer displays TShark's parse and decodes nothing itself: one
sandboxed single-pass `-T fields` run prints the packet list (Protocol and Info
columns plus the fields the colors and menus need) into a disk-backed row
store, validated and sanitized per row, and the selected frame's details come
from `-T pdml` with byte ranges checked against the frame. Finished captures
cache their rows in `<capture>.pcap.view` keyed by size, mtime and TShark
version; live captures append. Without TShark only raw frames and bytes show.
Known limits: PDML byte ranges for reassembled or decrypted data are relative to
that data and can highlight the wrong frame bytes (only ranges outside the frame
are dropped), and single-pass details omit "reassembled in" links.
Network has IPs, Hosts, HTTP, DNS and Sessions tables with the requested compact columns.
Use recorded packet frame links and TShark's existing decoder. Local GeoIP/ASN
data may enrich destination rows; do not contact an external lookup service.
PCAPs record VM traffic, so time-window correlation does not prove process
ownership. Host-time anchors are receipt estimates with transport latency;
historical start-anchored estimates and unavailable timestamps must be labeled.
New summary timestamps are optional serde fields, preserving older archives.

Remove the requested index/count/coverage essays. Show actionable missing-feature
and incomplete-evidence warnings near the run selector. Preserve the current
native palette, proportional navigation and monospace evidence values; use
resizable columns, horizontal table scrolling and bounded lower detail panes.

ANT-T0093 supersedes the inline lower-pane presentation: every triage entry's
single-click information belongs in the existing shared Details dock panel.
Include suspicious activity, process tree, Opened/Read/Changed files, IPs/Hosts/
HTTP/DNS and BPF decoding/export. Remove row-content hover popups and duplicate
inline inspectors; preserve filter context menus and double-click exact evidence
navigation. Details follows Triage using the existing active/split/detached
panel rules. Changing run/VM clears selection and pending evidence jumps.

## Accepted ANT-T0087 aligned VM status cards (0.6.1)

The ANT-T0087 visual clarification requires equal-height VM Status resource
cards within each responsive row. Render the contents once, measure that row's
tallest card and extend all of its frame backgrounds to the shared height in
the same frame. Apply this to guest pairs and host pairs/triples; single-column
cards retain natural height. Width/data/font changes must not depend on a stale
height cache or clip wrapped notes. Measurements and monitoring stay unchanged.

## Accepted ANT-T0086 upload/picker and collector follow-up (0.6.1)

The latest user clarification supersedes the dialog-tree and immediate-send
portions of ANT-T0082/83: keep the sidebar Explorer tree, fill its pane width,
and align folder/Refresh left using proportional text. Upload has a native file
chooser button and manual path fields, with no second tree. Sidebar Send and Run
only prefills Upload; it does not submit. Opening Upload hides Run program.
Upload and Run retains the matching-success, same-session editable Run handoff.
File-picker callbacks preserve exact paths and reject closed/reopened/pending
dialog choices. Keep native host chooser asynchronous and manual entry usable.

Boot INFO proves kernel control support before userspace has necessarily mounted
the real root and created `/tmp`. For the temporary collector, retry only typed
Upload Begin and Exec ENOENT rejections at two-second intervals within one
60-second readiness window; `/dev/ptmx` can appear after `/tmp` on Debian.
The UMH_WAIT_EXEC rejection proves the helper did not exec. Preserve a committed
upload and token across Exec readiness attempts; never upload it again. Unknown
outcomes, other rejections and transfer failures are never retried. Existing guest images,
kernel and protocol stay unchanged; the producer backlog remains 0.7.0.

## Historical accepted ANT-T0082 upload browser and Run handoff (0.6.1)

User authorized a new release-0.6.1 branch and an Upload file workflow that
chooses a host folder through the filesystem explorer, displays its expandable
filesystem tree and selects a file to upload. Keep manual path entry and plain
Upload. Upload and Run makes the uploaded file executable and, only after the
matching successful upload in the same VM session, opens the editable Run program
window with its guest path. It never executes without the user's Run action.
Overwrite confirmation retains the chosen action; closing cancels the handoff
without claiming to cancel a guest write already submitted. Reuse the existing
single-file guest protocol and 0.6.0 bases; no guest/image/transport changes.

The accepted ANT-T0083 clarification adds a persistent Explorer section below
Base images. Choose its host root independently of the Upload dialog; double-click
a regular file or use right-click Send and Run to submit the existing upload and
success-only Run dialog handoff. Right-click Open Directory opens the containing
host folder (the folder itself for directory entries). Stopped/wrongly selected
VMs and pending uploads cannot admit another send. Folded bases never hide Explorer.

## Accepted ANT-T0084 resource observations and UI repairs (0.6.1)

The user's follow-up requests explicit disconnected-network capture warnings,
loss-counter definitions on hover and repair of growing subwindows, while keeping
the folder Upload and Run workflow. Fix the reproduced Import Base row feedback;
validate floating/detached views at normal and large text sizes. Extend the
existing host resource producer with checked MemAvailable and statvfs used/free
values. Label their host scope and preserve session/retention identity.

The user selected a temporary guest resource collector for 0.6.1, an explicit
resource-only exception to the kernel-only producer contract. Build/embed a
static x86-64 musl executable and use existing Upload/Exec/Input/Read/Signal
controls, without guest packages, shell interpolation or image/kernel changes.
Read guest MemTotal/MemAvailable and statvfs of `/`; label other mounts outside
coverage. Poll every two seconds, bound replies and retain one outstanding
request, validate session/token/sequence and expose unavailable/stale readings.
Self-unlink at launch and exit after 30 seconds without input. Stop/reap before
snapshots and reconnect, never replay uncertain side effects or carry readings
across a timeline. Collector syscalls remain observable in Capture All; this is
not a stealth guarantee. Kernel-native production is deferred to 0.7.0.

## Accepted ANT-T0085 tab dragging and docking feedback (0.6.1)

The user reports unclear/nonworking tab movement and requests the expected
drag shadow. Preserve the native dock tree and saved arrangements. Drag tab
labels directly, show a bounded shadowed title and explicit docking action,
and use one resolver for the highlighted destination and the committed drop.
Pane edges split, centers join, and visible tab headers allow insertion/reorder
with source-index removal accounted for. Show grab/grabbing cursors, focus moved
tabs and update the corresponding Details context on a committed drop. Escape
and missing-release cancellation must not silently detach or move a tab; a lone
tab cannot promise a split into an empty source group. No guest/backend changes.

## Accepted ANT-T0057 manual cores and performance Summary (0.6.0)

User authorized a real Dump core action beside Dump memory and inside Core dumps,
choosing pause/capture/resume of a selected live process. Use validated guest
boot/task/start/TGID identity, a nonfatal bounded guest rendezvous and native ELF
notes, with truthful unavailable memory and independent repeated host captures.
Do not use the exit-core rendezvous, kill the target, replay uncertain acquisition
or add a guest helper. The revision-16 extension retains ABI9 and ordinary
revision-15 exit captures; ANT-T0057 defines its accepted wire and lifecycle.

Summary uses native performance charts/meters with measured QEMU/host values,
per-VM identity, bounded sample history and explicit unknown states. Guest RAM
utilization remains unavailable. Run program gains title dragging while preserving
its initial viewport-limited size and final actions. Other debugger features and
release/base publication remain separate.

## Accepted ANT-T0056 process core and VM Summary update (0.6.0)

User authorized the planned 0.6.0 guest process-core-on-exit backlog and a native
Summary tab immediately before Run History, showing VM status, health and
resources. Unscheduled candidates and a live debugger remain outside this task.
Opt-in core acquisition targets the launched root thread group on native x86-64,
before normal/fatal exit releases its address space. Reuse Linux ELF core notes
and its memory filtering; bound retained guest buffers and host transfers, expose
partial/unavailable results, preserve original exit status and old-base launches.
Acquisition requires guest revision 15; revision-14 snapshot ABI9 is unchanged.
Host timelines never replay acquisition effects across snapshot recovery.

Summary uses owned backend snapshots and per-VM identity guards. Configured guest
vCPU/RAM/disk capacities are separate from QEMU host CPU/resident memory and
available data-volume space. Missing measurements remain unavailable. Existing
layouts gain Summary before Run History without losing custom windows.

The accepted UI follow-up aligns Core dumps with Memory: a resizable capture
list on the left, selected evidence and analysis tabs on the right, and a separate
import dialog. Waiting/unfinished entries, names/tags and lazy inspection remain
available. This changes presentation only; core acquisition/recovery is unchanged.

## Accepted ANT-T0055 host evidence update (0.5.0)

User authorized inspection, completion and release of current 0.5.0, with guest
acquisition work deferred to 0.6.0. Static-analysis priority is result readability.
This extends the existing revision-14 / ABI9 snapshot baseline without changing
the guest contract. Host launch controls optionally own a separate network filter
from before execution through whole-tree exit and queue one post-exit VM RAM dump.
Snapshot/reconnect boundaries split captures into new retained segments.

Evidence labels are bounded sidecars; recorded IDs and paths never change.
Full retained static text/JSON and native Ghidra project exports preserve partial
status, reject unsafe paths and never overwrite existing output. Opening Ghidra
uses an exported working copy. Saved trees and numbered 100-call trace pages read
a bounded snapshot of ongoing archives. Imported process cores use bounded,
file-backed Linux ELF64/x86-64 inspection, thread registers, mappings and on-demand
disassembly; missing pages remain explicit. They are separate from physical RAM.

Isolated networking uses QEMU user networking with restrict=on, no forwarding,
TFTP or SMB. Exact process core capture before exit, all-thread register freezing
and pre-free memory capture require new guest support and remain 0.6.0 backlog.
No guest rebuild is necessary for these host additions; already-built current
0.5.0 bases are reused. The documentation acceptance record is ANT-T0055.

## Ownership

### Accepted ANT-T0042 Update

User authorized local Antinomie 0.3.0 on 2026-10-09 and the usability follow-up
on 2026-10-10. Capture All retains a per-process tree; revision-13 bases use
transport ABI 8 with tunable rings and bounded never-drop waits. Legacy ABI 7
bases remain supported with their original dropping behavior. This supersedes
the initial drop-only/V7 requirement for new bases; no snapshot or reconnect.
Network capture is explicitly started/stopped on a running NAT VM using QMP,
retained separately per boot and capture, and browsed with history, protocol
colors and structured filters. Terminals resize their guest PTYs and retain
bounded scrollback. Details offer numeric copy formats and bounded captured-data
windows; analysis displays ongoing progress. Optional guest-desktop launches
join an already logged-in graphical session using the run's kernel-controlled
process tree. No persistent guest helper or automatic login is introduced.
The task record and resumption contract are ANT-T0042 in the documentation task
directory. Product commits and binaries stay local until the user's testing;
documentation publication is independent of that product-release decision.

### Accepted ANT-T0033 Update

User authorized the native static-analysis workspace redesign on 2026-10-08.
One workspace is the default; selecting a category updates local results and
separate dockable section panes open only on explicit request. Typed available
evidence drives searchable/sortable tables, selected details and bounded read-only
specimen previews. Legacy generic reports remain readable. Acquisition, launch
scope, engine availability, guest controls and V7 remain unchanged. No new analyzer
dependency or guest image build is needed. The revision-1 result contract and
acceptance record are ANT-T0033 in the documentation task directory. Development
and the rebuilt executable stay in feature/static-analysis pending integration.

### Accepted ANT-T0025 Update

User authorized complete static-analysis acquisition/backend and launch setup
on 2026-10-08. Run Program opens launch fields left, opt-in analysis checkboxes
right and a final Run button. Initial executable only; no descendant/later exec
static acquisition. Triage plus optional deep analysis, local/no network default,
exact initial guest exec-file acquisition with bounded wait, failure continues
execution and reports unavailable. Retained reports reopen without rescanning.
The frozen revision-1 implementation contract is in the documentation task
directory, ANT-T0025 - Implementation Contract.md. Application control revision
10 adds optional specimen controls; V7 remains unchanged, revision-9 guests
still launch with explicit analysis unavailable. Resource/isolation/compatibility
limits and engine gaps must be recorded, not presented as complete clean scans.
Development is isolated in feature/static-analysis; preserve concurrent dirty
image-builder work and do not replace the normal executable before integration.

### Accepted ANT-T0012 Update

User authorized saved per-VM guest/window resolution, fullscreen, fit-to-window,
KVM/TCG acceleration and bounded CPU-model choices in New VM/settings. Typed
serde-default launch configuration preserves legacy defaults. Settings apply on
next boot only; global force-TCG/headless overrides retain precedence. Host CPU
requires effective KVM. User approved retaining fixed guest pixels while scaling
the QEMU window. Presets use standard VGA static EDID, built-in Linux Bochs DRM
and video=Virtual-1 mode selection. Fixed/fitted/windowed GTK launches use a
bounded owned-window X11/XWayland initial-size operation; fullscreen/headless
paths need none. Existing x11rb/rustix packages provide safe display operations.
New immutable bundles declare fixed_display capability; legacy hashes and user
disks stay intact. No kernel/transport revision, guest helper or free-form QEMU
arguments. Detailed revision 3 contract is ANT-T0012 in the documentation task
directory.

### Accepted ANT-T0015 Update

User found the Debian Xfce guest did not resemble a VM installed from the Debian
ISO; analysis showed a `virt-builder debian-13` cloud template plus a curated
`--no-install-recommends` package list missing the desktop meta-package and its
recommends. User chose the closest-to-ISO completeness level and to keep guest
integration purged. Install `task-xfce-desktop` with recommendations, move
networking to NetworkManager (dropping the custom `ifupdown`/`dhcpcd` setup),
and grow the immutable base to a 16 GiB whole-disk layout with 16 GiB guest
minimum. `openssh-server`, `qemu-guest-agent`, `spice-vdagent`, `cloud-init`,
`cloud-guest-utils` and `linux-image-*` remain purged; root stays locked, no
ordinary users exist in the base, `/dev/vda` remains the fstab root and the
hostname stays `antinomie`. No kernel, transport or application change; existing
bundles, VM disks and recordings are untouched. Task record is ANT-T0015 in the
documentation task directory.

### Accepted ANT-T0014 Update

User reported that after the absolute-pointer fix the guest showed two cursors
(the guest's software cursor plus the host pointer). The fixed-resolution path
used standard VGA (`-device VGA,edid=...`), which has no hardware cursor, so the
guest X server painted its cursor into the framebuffer. User approved switching
the fixed path to a hardware-cursor GPU. Use
`-vga none -device virtio-gpu-pci,edid=on,xres=W,yres=H`. The connector is a
`DRM_MODE_CONNECTOR_VIRTUAL` named `Virtual-1`, so `video=Virtual-1:WxH` is
retained. This matches the Auto path's virtio-gpu device and gives a single,
VMware-like pointer. Both virtio-gpu and Bochs DRM use the `Virtual-1` virtual
connector, so existing fixed-display bundles whose kernels build
`DRM_VIRTIO_GPU=y` remain compatible. Image/bundle capability checks now require
`DRM_VIRTIO_GPU` and `DRM_VIRTIO_GPU_KMS`. No kernel, transport or user-disk
change. Task record is ANT-T0014 in the documentation task directory.

### Accepted ANT-T0013 Update

User reported the guest mouse pointer stuck at the display center: clicks reached
the guest but motion did not move the cursor. Cause is the QEMU GTK relative
pointer grab; the launch attached only the emulated PS/2 mouse. User approved
attaching an absolute pointing device to all non-headless launches. Use
`-device virtio-tablet-pci` (a self-contained PCI device requiring no USB
controller) so the host pointer is tracked directly and never grabbed. The
existing guest kernel already binds `CONFIG_VIRTIO_INPUT`, so this is a
launch-argument change only: no kernel, transport, bundle or user-disk change.
Headless launches are unaffected. Task record is ANT-T0013 in the documentation
task directory.

### Accepted ANT-T0010 Update

The user authorized full Debian userspace on 2026-10-06, selected Xfce and
requested per-VM credential creation with password-protected sudo. Add Debian13
trixie amd64 alongside BusyBox; retain patched Linux6.12.94, V7, kernel-only
monitoring controls, disconnected default and existing disk/archive identities.

Optional bounded guest-profile bundle metadata distinguishes installed bases,
declares resource minima and credential/display requirements. Legacy bundles
without metadata preserve their old identity. Base import and creation stay
backend-owned; UI only selects values and transient credentials.

Debian New VM requires username/password/confirmation; create UID/GID1000 with
local password login and sudo, root locked, SSH disabled, no autologin. Offline
libguestfs provisioning precedes publication. Passwords must not be serialized
in configuration/preferences/recordings, displayed in Debug, or passed in argv.
A private0600 per-VM username/salted-hash provisioning record can support reset
and duplicate; no plaintext retained. Reset reapplies original credentials and
publishes replacement disk only after provisioning succeeds. Existing VMs are
not automatically converted or modified.

Image build uses authenticated Debian inputs and retains system account file
ownership, package provenance and licenses. Full source task/API/check contract
is `Agents/Tasks/ANT-T0010 - Debian Xfce VM Base.md` in the docs checkout. This
does not complete ANT-T0009's remaining syscall/async semantics.

### Accepted ANT-T0009 Update

The user approved these changes on 2026-10-06. The task record is
`Agents/Tasks/ANT-T0009 - Full Native Syscalls and Dockable Workspace.md` in
the documentation checkout. Earlier 30-syscall requirements remain historical,
not the completion target for this update.

- Cover all 375 named native `common`/`64` syscall slots in Linux 6.12.94.
  Use the pinned syscall table and checked argument/schema inventory; exclude
  x32/i386 from native decoding. Empty/ni entry points and disabled features
  remain explicit. Raw metadata expansion alone is not full pointer decoding.
- Capture asynchronous submissions/completions, including native io_uring/AIO
  observation. Use request and originating-run identities, bounded staging,
  explicit losses and safe callback lifetimes. V7 remains task-context-only
  and unchanged. Unknown multiplexed/device variants retain raw arguments and
  explicit Unsupported decoder status; do not guess pointer extents.
- Add kernel-owned queryable full-tree run status; root wait status is separate
  from surviving descendants and pending async work. Stop acknowledgement still
  means signal requests, not termination. Legacy/unknown state is not Finished.
- VM-scoped Run History replaces the sidebar program list. It displays launch
  path/name, argv, cwd, environment, UID/GID/stable identity and truthful status.
  Double-click selects that run's syscall archive independently of collection.
- Independently chosen disk and recording locations; durable per-VM paths and
  preserved existing data. Folder changes never silently move active files.
- Installed-base dropdown initially labelled Linux 6.12.94; ordinary startup
  must work without disposable build inputs after a verified base import.
- Display captured lengths with units, e.g. Captured bytes (52 bytes). Decode
  argument flags with named masks/enums/composites, raw values and unknown bits.
- VM context actions: Rename, Open Directory, Delete, Duplicate and Settings.
  Duplication requires a stopped source, copies its current disk independently
  with a new identity and omits history. Destructive actions are confirmed.
- Syscall Trace, Run History, Details, Activity and program terminals can detach
  into native windows and dock/merge back. VM list stays fixed; panel movement
  cannot duplicate transport/readers or terminate programs.
- Static syscall exercise ELF and host verifier: safe/reversible disposable
  resources, bounded children/timeouts/cleanup, explicit PASS/FAIL/SKIP and
  incomplete-capture outcomes. Do not execute irreversible guest/host changes.

Implementation is split into checked contracts and family slices, with bounded
kernel/core/UI ownership and an independent review gate. Do not claim the whole
task delivered while native content/async cases remain unimplemented. Existing
archives and per-VM disks are compatibility inputs, not disposable fixtures.

### Accepted ANT-T0008 Update

The user approved these changes on 2026-10-05:

- Each launched program opens a native terminal-only window. Concurrent runs
  are supported within the single running VM. Closing that window leaves the
  program running; it can be reopened and explicitly stopped.
- Main trace pairs entry/exit by stream/task/call identity and shows Time,
  Sequence, TID, CPU, Syscall (number), Return and Info. Missing phases remain
  explicit. Entry/Exit argument trees and captured-object expansion feed a
  separate hexdump/numeric inspector. Never infer uncaptured pointer content.
- Text size is configurable and persisted. Terminal grid uses the same font.
- Default retained data root is `~/antinomie`; VM directories are sanitized
  names plus random identifiers. Existing user VM data/archives are migrated
  by validated publication, never by moving an active VM's backing files.
  User also approved booting migrated VMs with the newly patched kernel;
  existing disk overlays/backing bases and explicit reset-to-base behavior
  remain intact. Record boot bundle and disk base identities separately.
- Each launch retains separate telemetry, launch metadata, terminal output,
  resize history and a final terminal-screen snapshot. This is NOT a QEMU RAM
  snapshot; V7 restore/reconnect remains unsupported. Offline paging must not
  replace active collection or allocate the entire history.
- Application telemetry extends major 1 with minor 1 and a 136-byte header:
  original offsets 0..127 unchanged, root task cookie u64 at offset 128,
  inherited independently of successful lifecycle transmission. Host also
  reads legacy minor 0 / 128-byte headers with explicitly unknown ownership.
- STOP_RUN opcode `0x1015`: version header (8 bytes), root task cookie u64 at
  offset 8, total 16 bytes (or 24 with a `u32 grace_ms`, see
  `protocol/run-status.md`). Signals matching tracked tasks with SIGTERM;
  success means signals issued, not atomic full-tree termination. No matching
  tasks returns `-ESRCH`. After a grace period (4 s by default) the guest sends
  SIGKILL to every task of the run still alive and reports KILL_ESCALATED in
  RUN_STATUS. Existing SIGNAL semantics remain separate.
- PTY EOF/root exit alone do not prove detached descendants finished. Per-run
  recording remains active until VM stop, with that distinction visible.
- Cleanup removes old generated test VM disks/captures only after migration
  validation; kernel author/source trees, build inputs and executable remain.

Core/UI workers freeze public run-addressed types before dependent rendering.
Core owns archive validation/paging and headless terminal persistence; UI uses
owned API values and performs offline disk reads outside the rendering thread.
Existing `vt100 0.15` may be used by core without adding a new external package.
`rusqlite 0.40.2` is approved for bounded disk-backed archive indexing; SQLite
is linked from the system and required upstream notices are retained.
Run/session maps, previews, pages and queues remain bounded; new recording
payloads count against the recording quota and preserve explicit failures.

- Guest worker: kernel author tree work/debian-6.12.94-1-trixie/core, new guest
  protocol header src/antinomie/monitor/protocol/control.h, guest source manifest.
- Host worker: src/antinomie/monitor/crates/monitor-core only, public backend API.
- UI worker: src/antinomie/monitor/crates/monitor-ui only, depends on monitor-core.
- Coordinator: workspace Cargo.toml, build/test/rootfs scripts, integration,
  patch exports, final documentation. Workers must not commit outer repository.
- No nested delegation, no wholesale refactor of transport. Return concise
  changed files / tests / failures / outstanding work. Never invent test results.

## Telemetry protocol

Use existing Syscall Telemetry Plan application protocol 1 (ANTT, 128-byte
little-endian envelope) from the docs vault, carried as opaque V7 messages.
Implement EVENT_BEGIN (120), FIELD_BEGIN (40 + key/layout), FIELD_DATA,
FIELD_END (32), EVENT_END (32); emit lifecycle/health where implemented. Parse
explicit offsets, never native Rust struct casts. Missing begin/end/chunks,
copy faults, decoder gaps, parser limits and persistence failures are explicit.
CPU is metadata. Stream ID + task cookie + call ID identify invocations.

Initial 30 syscall numbers/names for behavioral malware analysis (selected
coverage, not a measured popularity ranking):
0 read, 1 write, 2 open, 3 close, 4 stat, 5 fstat, 9 mmap, 10 mprotect,
11 munmap, 16 ioctl, 19 readv, 20 writev, 41 socket, 42 connect, 43 accept,
44 sendto, 45 recvfrom, 49 bind, 50 listen, 56 clone, 57 fork, 58 vfork,
59 execve, 60 exit, 62 kill, 82 rename, 87 unlink, 231 exit_group,
257 openat, 322 execveat.
Output buffers use actual return bounds and saved entry capacities. Vector
descriptors are entry snapshots. Exec argv/env strings obey kernel ceilings.
Unknown ioctl operations report NO_DECODER, not guessed nested memory layouts.
Lifecycle hooks must follow descendants regardless of selected syscall number.

## Host/control contract

Guest worker establishes protocol/control.h promptly and tells host worker
when ready. Opcodes: 0x1001 upload begin, 0x1002 upload chunk, 0x1003 commit,
0x1004 abort, 0x1010 exec, 0x1011 terminal input, 0x1012 terminal read,
0x1013 terminal resize, 0x1014 signal, 0x1020 recorder stats,
0x1030 shutdown. Explicit little-endian fields, versioned, checked lengths;
results travel in the existing reply queue. Each reply matches request ID.
Persistent health/loss counters queryable even after telemetry loss.

Rust backend runs blocking ant_init/poll/read on one owner thread. It exposes
owned commands and bounded UI snapshots, handles reply matching and telemetry,
and keeps collection/persistence independent of frontend frame rate. Shared
public API types should be established early by host worker for UI worker.

## Verification

Build Rust workspace and kernel. Four-core QEMU integration: bootstrap attach,
upload static test program/shell script, launch with UID/cwd/env, terminal I/O,
entry/exit + buffer bytes, descendant execution, invalid pointers, telemetry
overflow, disk persistence/reset and graceful/forced shutdown. Include CPU/RAM
variants if feasible. Use actual measured results and record unavailable tests.

All final docs in the separate documentation repository. Obsidian
Mermaid. Declarations/arguments/returns in tables; executable source explained
using short excerpts with actual filename/line numbers and prose below. Preserve
unrelated v5 walkthrough edit. Coordinator commits/pushes docs after validation.

## Accepted snapshot and reconnect extension (0.5.0)

The authorized snapshot manager supports disk checkpoints (cold boot recovery)
and full CPU/RAM/device checkpoints (resume recovery), with a branching native
graph. External qcow2 layers are frozen; each branch owns a separate writable
child. A durable manifest and pending-operation journal own active disk selection.
Live disk capture is crash-consistent; full capture pauses CPUs and suspends host
RAM writes. Full recovery requires ABI9 and exact QEMU/config/bundle compatibility.

ABI9 adds a host attachment nonce/guest acknowledgement mailbox independent of
command queues. The guest services it before/between control dispatches, fences
executed and abandoned request IDs, and preserves per-CPU telemetry producers.
The host skips stale replies, reads from restored owned tails and never replays
unresolved side effects. ABI7/8 retain cold attachment and disk checkpoints.

Full restore creates fresh recording IDs/directories, retains restored guest
run/capture cookies, seals old archives and records incomplete boundary tails.
Old recordings and saved ancestors remain immutable. Restore confirmation can
save current state first; failure to save prevents restore. Hidden checkpoints
retain all disk/memory artifacts until confirmed whole-VM deletion. Snapshot-aware
reset/data relocation are guarded until their dependency-safe implementations.
