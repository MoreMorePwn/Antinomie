# Antinomie initial monitoring release

## Current licensing boundary (0.7.0)

Original host application, host transport, scripts, tests and product
documentation use GPL-3.0-only from 0.7.0. The shared kernel headers remain MIT;
kernel implementation and historical patch exports keep their kernel terms.
Imports and separately installed tools/rules retain their own licenses. Earlier
releases and the separate documentation/website repositories retain their
original license scopes. `scripts/check-licenses.py` validates the boundary and
locked dependency license expressions, and records notice-document gaps without
claiming full legal clearance. Release packaging includes that inventory.

This brief is the shared implementation contract. User authorized implementation
on 2026-10-01.
The accepted 0.5.0 snapshot/reconnect extension below supersedes the historical
V7-only restriction; older requirements remain recorded for their releases.

## Accepted requirements

### Accepted kernel-native guest resources (0.7.0)

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
host RSP server on a loopback Unix socket and an ephemeral 127.0.0.1 port. The
server is the project's own implementation of GDB's Remote Serial Protocol
(`debug/rsp_packet.rs` framing, `rsp_client.rs` and `rsp_requests.rs` packet
dispatch, `rsp_server.rs` sockets and threads); no third-party RSP crate is used,
so no gdbstub licence applies. Contract revision 17 is unchanged: the opcodes are
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

### Accepted configurable process-core size (0.7.0)

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
* **Evidence** (BusyBox base, `core-size-check`, workload `core-on-crash`): light
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

The Debugger tab (beside Static analysis) holds the in-app UI over the same engine. It does not
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
* **Breakpoint kinds.** `BreakpointKind` has software, hardware and watch kinds
  (write, read, access); the Breakpoints pane's "Add as" choice makes any of them
  and greys out a kind the guest's `ViewCaps` do not offer (a request for one the
  guest lacks is refused with a notice). A watch covers eight bytes from its
  address, and a read watch is an access watch because the debug registers have no
  read-only mode. `StopReason` has signal, watchpoint and entry variants, and a
  stop reason is mapped from the engine's `StopKind` in one place.
* **Detach and kill** asks for confirmation (a plain, movable window like the
  other confirmations) before it ends the process with SIGKILL; **Detach** does
  not ask, as the process keeps running.
* **Not in the panel.** Saved process cores (opened read-only in Core dumps, which
  already shows registers, mappings with a hex view and disassembly), memory and
  register writes, and step over (Next), Watch…, Mappings, Decompile and "Open in
  GDB" of the mockup, which were not built.

### Accepted gdb console in the Debugger tab (0.7.0)

The tab also runs a gdb front end against the session's loopback port
(`app/debugger/console.rs`, `pty.rs`): GEF (the managed script in the system gdb),
or pwndbg (a system install, else the managed portable copy), chosen in Settings;
it starts with `-nx -q` and `target remote 127.0.0.1:PORT`, with debuginfod off.
The program runs on a pseudo-terminal as its session leader, drawn by the app's
terminal widget. While gdb drives, the panel is read-only (see "One controller at
a time" above). Closing the pane or the session asks gdb to quit, then kills it.

* **Environment.** gdb starts with a cleared environment: only `PATH`, `LANG`,
  `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES` and `TZ` are passed on, plus `TERM` and an
  empty `DEBUGINFOD_URLS`. Its `HOME` is a private folder, `<data>/tools/.console-home`
  (mode 0700), for GEF and pwndbg alike, so no init file or setting of the user's
  own home reaches it and none of theirs is written. The display, D-Bus and
  ssh-agent sockets and `PYTHONPATH` are not inherited.
* **Not sandboxed.** Unlike the analysis workers, the console does not run under
  bubblewrap. Ctrl-C must reach gdb through the terminal, which needs gdb to be the
  session leader on its pseudo-terminal (bubblewrap's `--new-session` takes that
  away, and without it an interrupt would end bubblewrap), and gdb connects to the
  host's loopback server, which the shared profile's unshared network would cut off.
  The mitigations are the ones above, no program or core file given to gdb, `-nx`,
  and a server that implements neither `vFile` nor `qXfer:libraries`, so a guest
  supplies no ELF and no auto-load script; guest data is dumped only by a command
  the user types.

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
* **Final audit fixes (guest series 0058-0060, revision 17 unchanged).** FF-14
  and FF-15: the engine held each thread's `task_struct` but not its kernel
  stack, where its registers are; an exiting thread frees it (VMAP_STACK). A group
  killed at a breakpoint stop (its own `timer_create` SIGKILL) and then continued
  oopsed the debug worker in `ant_dbg_arch_pc`, and a thread that stepped its own
  `exit` oopsed it in `ant_dbg_arch_step_done`; both reproduced on a 0057 base.
  Every access to another thread's registers now holds the stack
  (`try_get_task_stack`) and finds nothing once it is gone; STATUS and CONT of a
  killed stopped group report it exited (0058). FF-16: the single worker waited
  without bound for a step of a system call; a stepped vfork with FORK hung every
  session and DETACH was refused. A step the kernel holds longer than 2 s now
  finishes by itself as the next event, a stepped thread asleep in a followed
  vfork stops the group with its VFORK event, DETACH is accepted during a
  continue or step, and the child of a stepped fork no longer inherits the trap
  flag and the system-call-exit trap (it died of SIGTRAP once the step could end)
  (0059). FF-21: `clone(CLONE_VFORK)` without `CLONE_VM` gives the child its own
  memory and table (0060). `debug-check p3` runs `killed-stop`, `exit-step`,
  `blocking-steps` and `vfork-own-memory`, which also read the guest kernel log;
  all four fail on 0057 and pass on 0060.

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
  previous base (series 0001-0042) and host: `guest-run` with `ant-workload --only
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
  workload module, linked pairs, cancellation, requests pending at exit, SQPOLL, a
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
  workload module) then the ignored test `recorded_uring_triage`
  (`triage/uring_qa.rs`), which prints every row it matched and fails on any
  that is missing. `uring-check` status modes boot two vCPUs; `record` boots one
  (see Limits).
* **Limits.** A request that never completed has no result and is shown as a call
  with no exit. Requests that an SQPOLL thread submitted on behalf of the ring's
  creator are read since the trace follow-ups (below). Operations that touch no
  file (sockets, timeouts, polls) are not mapped, nor is `TEE` (pipes only).
  The io_uring rename, link and unlink identity came from a lookup just before
  the operation; since series 0057 the operation publishes it (trace
  follow-ups, below). A core of a process whose leader left first is Partial for the
  leader's missing registers, as before. Past 100,000 file requests a scan
  stops reading them and the coverage line says so. On a guest with more than
  one vCPU, a record a worker published after a call (an unlink's content hash)
  could be saved ahead of calls made before it; the host now reads the vCPUs'
  rings merged by guest time (trace follow-ups, below).

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

### Accepted exit re-capture of non-resident inputs (0.7.0)

Approved by the user on 2026-10-22. Guest series 0053, contract section 22;
the contract revision stays 17 (the encoding is additive and 0.7.0 is not
released). The recorder still never faults a page in (15.1: no sleeping, no
userfaultfd or FUSE stall, no residency change a sample could see with
`mincore()`).

* **Guest (`kernel/antinomie/recorder.c`).** `field()` remembers an Entry input
  that ended `ANT_NOT_RESIDENT` (caller's memory, no snapshot or iterator, not
  async) in a fixed array of the task context: at most 8 per call, key under
  96 bytes, nothing allocated. `recapture()` runs at the end of the Exit: a
  string is measured again with its ceiling, a buffer is published only if one
  no-fault byte per page reads, and the field goes out in the Exit with the
  Entry's key, direction input and FIELD_BEGIN flag bit 3 (RECAPTURED). An
  argument and key the Exit already published (an in/out buffer) is not read
  twice. The exec
  vector walk keeps where it stopped (`ant_exec_resume`) and resumes there. If
  the address space changed (a successful exec), nothing is read from the old
  one: `ant_monitor_exec_names()` (a hook in `exec_binprm()` next to the exec
  image hook) keeps a copy of `bprm->filename` only when the path was not
  resident, and the strings from the resume point on come from the new
  image's `[arg_start, arg_end)` / `[env_start, env_end)`, flag bit 4
  (KERNEL_COPY) too; an interpreter exec rewrote argv, so only envp is
  recovered there. A vector pointer on a non-resident page is now classified
  NOT_RESIDENT like other fields.
* **Host (`monitor-core/src/recapture.rs`).** `FieldSummary::recapture`
  (`AtExit`, `KernelCopy`; serialized only when set) comes from the flags
  word. `pair_events()` moves a complete recaptured Exit field into the Entry
  in place of the NOT_RESIDENT field of the same argument and key (keeping
  its object id and dropping its "capture incomplete" issue) or adds it (exec
  strings the Entry never reached), so every reader of a call's inputs sees
  the value and a call whose only gaps were recaptured is complete. The
  process tree takes an exec's path from the Exit when the Entry had none
  (live and archive scan).
* **Trace view.** A small "at exit" or "kernel copy" pill on the field row and
  on its argument row; the tooltip and the inspector say in plain words that
  the bytes are what memory held when the call returned and that another
  thread could have changed them meanwhile. The capture summary reads
  "Captured bytes (N bytes, at exit)".
* **Compatibility.** An older host does not read the flags word: it shows the
  field as one more Exit field and still reports the Entry incomplete (its
  Triage path lookup, Entry then Exit, finds the value). A recording from an
  older guest has no marks and pairs as before.
* **Conformance.** The `recapture` area of the user group (`fixture/recapture.c`,
  `want_recapture()` in the oracle) covers a forked child's literal, a
  successful and a failed exec of literals, the start-up readlinkat, an
  untouched file mapping, a buffer rewritten by a second thread while the call
  blocks (the mark is what tells it apart) and a buffer the call never reads
  (stays NOT_RESIDENT; `mincore` shows the recorder did not load it). Golden
  files show the mark as `complete@at exit`.
* **Cost.** A call whose entry found nothing non-resident pays a 64-byte reset
  at entry and a few branches per field and at exit; the task context grows
  by about 1.2 KiB and stays in the same slab size. The stress groups re-read
  422 of 737k calls (`stress-light`). Their throughput is set by the shared
  host, not the guest: same app, base 0052 → 0053, `stress-light` 31.3k →
  9.6k calls/s, `stress-lossy` (guest bound, no waiting) 95.8k → 190.8k
  calls/s, `threads` 2.8k → 3.3k, in both directions with load averages of
  10 to 15 on the host, so no difference can be attributed to the change.
  `stress-heavy` failed both times the same way (the host's recording writer
  queue filled).

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
* **Limits.** NOT_RESIDENT inputs (static glibc's start-up readlinkat, a forked
  child's first literal) are read again at exit since series 0053 (next
  section); what the call never reads stays NOT_RESIDENT. The ioctl argument is
  decoded for terminal requests only.
  Directory removal publishes its identity since series 0054. Rows without an entry point have
  positional argument names.

### VM regression tiers (0.7.0)

Every guest change used to run the whole VM regression set. One runner,
`scripts/vm-regress.py`, now runs it in two tiers, and a change picks one by what
it touches. Self-tests of the tier choice and the arguments:
`python3 tests/monitor/test-vm-regress.py` (no VM).

```sh
scripts/vm-regress.py quick BASE
scripts/vm-regress.py full  BASE --old-base OLD_BASE [--old-host REV|PATH] [--debugger-tools DIR]
scripts/vm-regress.py auto  BASE [--against REF] [--old-base OLD_BASE ...]
```

`BASE` is a BusyBox base built from the current guest series; `OLD_BASE` an older
one (the previous release's). Common options: `--out DIR` (logs, runs, fixtures and
private HOME and XDG folders; default `vm-regress-out`), `--only CHECK` and
`--skip CHECK` (repeatable), `--rerun-failed` (the checks that did not pass, or
never ran, in the last run in `--out`), `--retries N` (opt-in: every attempt is
listed and a pass after a failure is shown as FLAKY), `--list`, `--no-build`.

| Tier | Runs | Takes (this machine) |
|---|---|---|
| quick | the conformance trace suite's oracle groups `user`, `root`, `threads` (`conf-quick`) | about 1 min with the examples built, 5 to 7 min when the render test has to build too |
| full | quick; `conf-stress-light`, `conf-stress-heavy`, `conf-stress-extreme`, `conf-stress-lossy` (one check and one conformance run each, cleaned up in between); `debug-p2`, `debug-p3`, `audit-stop`, `audit-core`, `uring-status`, `uring-boots`, `tracer-record`, `tracer-qa`, `debugger-live`, `stealth`, `snapshot`; `uring-legacy` and `tracer-legacy` on the old base; interop in both directions (`io-old-new-*`: the old host with BASE; this host with the old base: `io-new-old-audit` and the two legacy checks, since an old guest lacks what the other checks need) | about 2 h 10 min plus, the first time, about 15 min to build the old host; the four stress groups take 80 min of it (light 7, heavy 24, extreme 35, lossy 13) |

Quick is the default for every change. Full is required when a change touches the
kernel/host contract, and for a release check:

* the guest patches `src/antinomie/core/`, `src/antinomie/patches/`,
  `src/antinomie/transport/`;
* `src/antinomie/monitor/protocol/` (contract documents, `control.h`, the schema
  JSON);
* any change to `ANTC_REVISION` (the `#define` in `control.h` or `REVISION` in
  `control.rs`).

`auto` decides this from the diff against `REF` (default: the `origin/release-*`
branch `HEAD` is closest to): the commits since the merge base with `REF`, the
working tree and untracked files. One contract path, or a changed revision line,
makes it full; otherwise quick. It prints the paths that decided. The old host of
interop is a git rev built in a temporary worktree under `--out` (removed
afterwards) or a built checkout given with `--old-host`; it defaults to `REF`, so
for a release check name the previous release.

Rules the runner keeps: one VM at a time, and a wait for 5 GiB of MemAvailable
before each boot; a timeout per check; HOME and the XDG folders of every check are
private folders under `--out`, never the app's own data or settings; only the
processes it started are stopped on a timeout. The report lists each check with
its result, time and log, and the exit status is nonzero unless every check
passed (a check whose prerequisite is missing, such as `--old-base`, counts as not
passed). `debugger-live` needs the managed GEF and pwndbg: `--debugger-tools` names
a data folder that has `tools/gef` and `tools/pwndbg` (`install-tool DATA gef`).

Disk: the runs write a lot (the extreme stress group about 11 GB), and under WSL the
Linux disk is a file on a Windows drive that grows but does not shrink, so `df /`
does not show the danger. Before each check, build and boot the runner refuses to
start (the check is reported ERROR, not started) while the Linux disk uses more than
`--max-used-gb` (default 380) or a `--min-free PATH:GB` path has less free space
(repeatable; on WSL it defaults to `/mnt/e:5`, the Windows drive behind the disk).
Once a check's result is recorded, its VM disks, recordings and private folders are
deleted (logs, `results.json`, the report and the conformance reports stay);
`--keep-data` keeps them. `tracer-qa` reads `tracer-record`'s recordings, which go
after it; rerun `tracer-record` with `--keep-data` before running `tracer-qa` alone.
`tracer-qa` is an ERROR, not run, when `tracer-record` did not pass (in this run or,
for a rerun, the last one in `--out`): a Triage QA over a failed recording proves
nothing. It reads the runs of `tracer-record`'s last attempt.

### Checks that failed under load (0.7.0)

The runner stages its private debugger tools and marks a complete copy before
publication. An interrupted copy previously left a directory that a resumed run
treated as installed; pwndbg then failed to load `libpython3.13.so.1.0`. Resuming
now replaces an unmarked copy, with tests for failed copy, recovery and reuse.

On 2026-10-23 the user scheduled the stress-heavy telemetry drops and
intermittent slow transport reconnect for 0.7.1. They are known 0.7.0 limitations,
not passing zero-loss or reconnect-latency guarantees. Preserve historical
failures, retries and explicit release-qualification exclusions. The remaining
debugger fixes and release work continue independently.

Full-tier checks that failed now and then on this shared host, and why.

* **`debugger-live`: pwndbg "The program has no registers now".** A real bug of
  the RSP server. A new session's console pane starts gdb by itself; Restart
  (which the check pressed) starts a second gdb while the first still holds the
  session. The server serves one client at a time, so the second one's first
  packet (`qSupported`) waited unacknowledged while the first gdb quit and the
  server stopped the process again for the next client. gdb waits its remote
  timeout (2 s) for the `+`, then sends the packet again; the server answered both
  copies, and every later reply answered the request before it ("Remote replied
  unexpectedly to 'vMustReplyEmpty': vCont;c;C;s;S;t"). pwndbg starts fast enough
  to land in that window; GEF, slower to load, usually did not. Fixes: the server
  ignores a copy of the last packet that comes before the client has acknowledged
  a reply (`rsp_client.rs`, `retransmitted`; a client in acknowledgement mode sends
  nothing new before that `+`); the console runs gdb with `set remotetimeout 30`
  (a reply can wait for the guest longer than 2 s on a busy host: a request is
  given 5 s, the link 15 s, and a gdb that times out also misreads every later
  reply). Before: 3 of 3 runs failed at that step (the fourth attempt, with only
  the server fix, connected and failed later in the test, below); after: 5 of 5
  passed, the first while a guest kernel built with `-j6`. A gdb that leaves
  releases the process, so Restart in a Debug on start session lets the program
  run from its entry; the check now uses the pane's own gdb for Debug on start
  and presses Restart in the attach case. The first VM of a fresh data folder
  imports the base (about 20 s on this disk): the check gives it 120 s.
* **`.gdb_history` in the working directory.** pwndbg turns history saving on and
  gdb's default file is `.gdb_history` in the working directory, the app's; the
  live check left one in `crates/monitor-ui`. The console's history goes to its
  private home (`GDBHISTFILE` for pwndbg; GEF names `~/.gdb_history`, which is
  that home). The check fails if one appears in the working directory.
* **`debug-p3` gdb timeouts.** The phase 3 gdb tests set the remote timeout with
  `set remote timeout 30`, which gdb does not have (the command is
  `remotetimeout`; gdb printed "Undefined set remote command"), and the phase 2
  tests set none, so gdb kept 2 s and a slow reply desynchronised it as above;
  which command group then never finished varied by run. The waits were right; the
  timeout never applied. Both now set `remotetimeout 30`.
* **The pty test `closing_asks_the_program_to_quit_first`.** It closed the program
  after a fixed 300 ms; in the full test run the shell had sometimes not yet set
  its INT trap, so the Ctrl-C ended it. It now waits for the shell to say it is
  ready.
* **`build-base` bases named `localhost`.** `build-base.py` passed
  `--hostname localhost` to the BusyBox recipe when the job had no hostname (a job
  written by hand, `"options": {}`), and the stealth check failed `base.hostname`
  and `base.etc-hostname`. It now passes only the answers the job gives; every
  path defaults to `debian` and names uid 1000 `user`.
* **`io-old-new-tracer`: "a segment of the reconnected run captured no packets"**
  (not fixed). `tracer-check record` reconnects the transport 4 s into a 30 s run
  that sends one DNS query a second and wants packets in both segments. A
  reconnect usually takes 0.2 to 1 s; in the two failures it took 41 s and 49 s
  (of 24 recorded: 4.3, 16, 19, 41 and 49 s are the slow ones), so the run's
  queries fell into one segment. The check depends on the reconnect being short;
  where the time goes in a slow reconnect was not measured.
* **`stress-heavy` transport drops** (not fixed; cause found). Two getppid
  records of 13.7 million were dropped by the guest while the host's writer held
  nothing back; a rerun on the same base dropped one more (an Exit's first
  packet). The same kind of drop predates 0054-0057: a 0052 base (`s2final`)
  dropped one write Entry in `stress-light`. The rerun's recording shows what
  happened: the task's records before the lost one are 0.4 to 0.5 us apart, the
  next one comes 6.06 s later, and the rest of the lost event was sent from
  another vCPU. The sender waited the whole send wait (5 s) for room in a full
  ring and dropped, although the host kept taking telemetry: waiting is not first
  come, first served. A waiting sender sleeps 50 to 100 us between looks, and
  the senders that run on its CPU meanwhile take the room the host frees, so under
  a flood of short calls one waiter can starve for the whole wait (the run had
  375,409 waits). The cross-CPU `local_clock()` difference in the same loop was
  ruled out: such a drop would come at once, not after 5 s. A fix belongs in the
  guest's send path (`transport/guest.c`): hand freed room to waiters first (a
  per-ring ticket), or end a wait only when the host made no progress on the ring
  for the whole wait. Not done here: it changes the never-drop contract's timing
  and needs the full tier and the stress groups.

### Trace follow-ups: io_uring, ordering, saving under load, Stop (0.7.0)

Guest series 0054-0057; the contract stays at revision 17 and every addition is
optional (an older guest and an older host keep working).

* **SQPOLL requests in Triage.** An SQPOLL ring's `iou-sqp` thread (and a
  process the ring was passed to) submits with no call of the creator: the
  guest attributes the requests to the creator's task with call id 0 (contract
  14.3). `Recording::attributed_async_page_cancellable` reads that key; the scan
  (`triage/async_files.rs`, `Attributed`) reads it once per task after its
  first successful `io_uring_setup`, turns the requests into calls with the
  creator's identity (its descriptors; the setup call as evidence) and holds
  each until the walk reaches the request's time.
* **More requests read as calls.** `FSYNC` (fsync, or fdatasync with
  `IORING_FSYNC_DATASYNC`), `SYNC_FILE_RANGE`, `SPLICE` (input from
  `splice_fd_in`, a registered input names no descriptor; the request's offsets
  are values, so the call has no offset pointers), `FSETXATTR`, `SETXATTR`,
  `FGETXATTR`, `GETXATTR` (name, value and path from the recorded operands).
  The guest (0054) attaches the file identity (ISSUE) to `SPLICE`, `FSETXATTR`
  and `FGETXATTR` too; one end of a splice is a pipe, so the file end is named.
* **Directory removal (0054).** `do_rmdir` holds the directory's inode across
  `vfs_rmdir` (which takes it off the dentry) and publishes `lifecycle.file_id`
  kind UNLINK, directory, no link left; an io_uring `UNLINKAT` with
  `AT_REMOVEDIR` says no link is left. Triage already routes a removal by
  identity, so a removed directory is one file entry known by its inode.
* **io_uring rename, link and unlink identity (0057).** The lookup just
  before the operation gave the link count the operation would leave; two
  `UNLINKAT`s of one file's two names, run side by side on four vCPUs, both
  saw two links and both said one remains, so the file was never deleted in
  Triage (found by `uring-check record` on four vCPUs). The worker marks the
  request it runs (`ant_async_target`) around `do_renameat2`, `do_linkat`,
  `do_unlinkat` and `do_rmdir`, and the identity they publish when they
  succeed becomes the request's operand, with the count actually left.
* **Process-level attribution (0055).** Every io_uring submission used to carry
  `ANT_ASYNC_PRODUCER_UNKNOWN` and make the run OBSERVATION_INCOMPLETE, so no
  io_uring run was ever ASYNC_COMPLETE. A process writes a ring's entries and
  moves its tail only through a mapping of them: when the entry's page and the
  ring's first page are each mapped by at most one user page table, the entry
  was written by a thread of the submitting process (`ANT_ASYNC_PRODUCER_PROCESS`,
  `async.flags` bit 3) and the run stays complete. A ring kept across a fork,
  mapped by another process or twice by one, an SQPOLL ring and submissions
  from outside the creator's process stay unknown. Specified in
  `native-schema-slices.md` 14.3 and `run-status.md`.
* **Run notes (host).** Lost observations (count above 0) are the note "Async
  observation lost N records" and the health panel's "Runs with async
  observation loss"; OBSERVATION_INCOMPLETE alone is the muted note "Uses
  io_uring: which task submitted each request is not proven …; nothing was
  lost", not loss. A saved run's old note with count 0 reads as the new one
  (`run_note_text`).
* **Async records under load (0056).** The publisher waited up to 10 ms before
  each record while its CPU's ring was more than half full, about 100 records
  a second on a busy guest, and the staging queue (1,024 records) overflowed:
  ant-workload `--only async-io --level light` counted 10,256 async observation
  losses alone and 10,393 beside the other load modules (7,355 staged packets
  failed; 79 of 640 requests saved). In never-drop mode it now keeps an
  eighth of the ring spare, and a task that may sleep waits up to a second
  for staging room instead of losing the record (`ant_send_waits()`, a new
  transport guest call). After: 0 losses, 0 staging failures, all 642
  requests with their final records. Interrupt completions and callers
  holding a lock still cannot wait; their losses are counted.
* **Record order across vCPUs.** The host read the per-CPU rings in turn, so a
  record could be saved ahead of earlier records of another vCPU (a task that
  moved, a hash worker publishing for an unlink) and a file's lifecycle listed
  a step early. `ant_read_ordered()` (host transport) takes the ring head with
  the smallest guest timestamp (`timestamp_ns`, one clock for every vCPU), so
  the rings are merged in time. A record can still come after a later one if
  its sender had not published it yet (waiting for room). `uring-check record`
  runs on four vCPUs.
* **Saving under load.** A raw block or object chunk the writer's full queue
  (256 MiB) could not take stopped the recording for good and every later
  packet was a storage drop; on this shared host even stress-heavy lost its
  recording that way (6,428,035 storage drops after 870 MiB), and
  stress-extreme lost 9.9 million packets (measured by the conformance work). A
  block that does not fit now stays buffered, and while the queue holds more
  than half its limit the transport thread takes no telemetry, so the guest's
  sends wait (never-drop mode). If the disk stalls longer than the guest's
  longest send wait (5 s by default), the guest drops what it cannot hold,
  and those drops are counted exactly; `Health::writer_held_ns` and
  `writer_held_longest_ns` say how long telemetry was held back. After, on the
  same host under a load average of 10-12 from other work: stress-heavy saves
  every packet but 9 of 11.5 million (telemetry held 54 s in all, at most
  20 s), and stress-extreme runs its 1,057 s whole, saving until the suite's
  8 GiB recording quota (19.6 million packets saved, 32 transport drops, held
  46 s in all, at most 17 s; the 19.7 million packets after the quota are the
  quota's, counted as such). A trace page whose previews would pass 64 MiB
  now ends early instead of failing.
* **Stop after heavy file churn.** The guest writes back its page cache before
  it powers off (`ksys_sync` in the SHUTDOWN handler); after ant-workload's
  file churn on a busy host that took 55 s, so the 10 s shutdown timeout
  forced the VM off and marked the capture forced. Stop polls QEMU's
  `query-blockstats`; while the guest's disk writes grow, the deadline moves
  to a timeout after the last write seen, up to 300 s
  (`backend/worker_vm.rs`, `Writeback`).
* **Verification.** `uring-check record` on four vCPUs with the stories
  `sqfiles` and `morefiles` and `recorded_uring_triage`; conformance groups
  `ring-private`, `ring-shared`, `ring-sqpoll` (attribution) and the
  directory removal cases of `user`; unit tests of the request mapping, the
  attributed reader and hold, the ordered read (host simulator in
  `tests/monitor/transport-reconnect.c`), the writer hold, budgeted pages and
  the Stop deadline.

### Suspicious activity: tiers, categories, noise and the Evasion category (0.7.1)

The rules live in `monitor-ui/src/triage/rules/`; `findings.rs` runs them over a
list of calls for the live view and the scan runs them through the same
`rules::Engine`. Host only: nothing here needs a guest change.

* **Classification.** `table.rs` has one entry per rule id: version, tier
  (`high`, `medium`, `low`, `info`; weights 10, 4, 1, 0), one of 13 categories,
  ATT&CK technique and detection-strategy ids (v20; a rule with no technique says
  so), whether failure is the signal and the programs that do the thing as their
  job. A test checks that every id the code emits is in the table and that every
  ATT&CK id is well formed.
* **Rules.** `exec.rs` reads an exec (the program, `argv`, `envp`, and a shell's
  `-c` script command by command); `paths.rs` reads what a call did to a file;
  `process.rs` memory, ptrace, namespace, signal and credential records;
  `network.rs` sockets; `frames.rs` the capture's DNS, HTTP and TLS/SSH rows;
  `evasion.rs` and `probes.rs` the anti-analysis checks. Correlated rules keep
  bounded per-task windows in `state.rs`.
* **eBPF attach.** `bpf_attach.rs` reads the recorded `bpf_attr` bytes
  (`arg1.attr`) at the `bpf_link_create` and `bpf_raw_tracepoint` offsets of Linux
  6.12 and the strings patch 0008 captures (`arg1.attr.syms[i]`, `.path`, `.name`),
  and the `perf_event_attr` of `perf_event_open` (`arg0.perf_event_attr`: type,
  config). `BpfFds` follows, per task, program fds from a successful
  `BPF_PROG_LOAD` and perf event fds, dropping them at `close`; the eBPF table
  (`bpf_notes.rs`) and the rules (`State::bpf`, `process.rs`) share it, so an attach
  row names the load call (`BpfNote::loaded_by`) and a SET_BPF names the
  `perf_event_open` that made the fd. Tiers are set per hit on `bpf.program`
  (ATT&CK T1014, DET0377, as for a load): kprobe_multi, fentry/fexit/modify_return,
  LSM, struct_ops, raw tracepoint, perf tracepoint or dynamic-PMU (kprobe, uprobe)
  events HIGH; cgroup, XDP, tcx, netkit, netfilter, iterator, uprobe_multi and
  perf events of other types MEDIUM; a failed attach INFO under its own object so
  it never folds into a success. Not captured today, and printed as such: the
  kernel function of fentry/fexit/LSM (`attach_btf_id` is chosen at load and is
  not resolved), a perf kprobe or uprobe symbol or path (`config1` is a pointer),
  a perf tracepoint's name (only its id), the netfilter priority, and any attach
  whose program or perf event was created before the slice (inherited fds).
* **Noise.** A hit is lowered one tier for a failed call (unless failing is the
  signal; five failures of a HIGH rule keep the tier) and for an allow-listed
  program, folded by `(rule, task, object)`, and siblings of one parent with the
  same program, arguments and object fold into one row. A steady repeat is shown
  as `×N every ~T`. Caps: 50 rows per rule and task, 2,000 per rule, 500 per
  task, 20,000 per run; the rest is one `+N more not stored (cap)` row that the
  badge counts. INFO is counted by rule, never built unless **Show INFO** is on.
  In a capture of the whole VM (no run root) a process whose creation was not seen
  and that did not start with an exec is outside the scope: one tier down and
  hidden unless **Show hidden** is on, unless the sample wrote its program. Frames
  of VM housekeeping are skipped by a versioned list and counted. A row found in
  packets is tied to a task only when that task's calls reached the address;
  otherwise it is VM-wide and one tier down.
* **Rows.** Twelve columns (Rule, Tier, Category, Process, Summary, Count, Source,
  Time, Confidence, Evidence, Version, Outcome). New filter fields: `finding.tier`
  (`finding.severity` is its alias), `finding.base_tier`, `finding.category`,
  `finding.technique`, `finding.count`, `finding.flags`, `finding.hidden`,
  `finding.object`, `finding.first_ns`, `finding.last_ns`. The journal is
  `triage-findings-v2.jsonl`.
* **Evasion.** Anti-analysis checks are not a tab: they are rows of the
  **Defense evasion / anti-analysis** category (the **Evasion** chip). Per task,
  `probes.rs` keeps each check with the answer the guest gave (DMI strings,
  `cpuinfo` flags, PCI vendors, clocksource, modules, MAC OUI, uptime, `TracerPid`,
  `PTRACE_TRACEME`, `SIGTRAP` handlers, container markers, runs of clock reads),
  judged by what would show a VM, a container or a debugger, and says which Stealth
  profile entry decides the answer. It summarises the task's next 30 s (exited,
  slept, stopped using the network, went on) and, for an exit or long sleep within
  5 s of a VM-revealing answer with no other work, adds `evasion.probe_then_exit`.
  This is a heuristic from the recorded calls and the rows say so. `CPUID` and
  `RDTSC` run in the program and leave no system call, so they are not seen (the
  UI says so); that needs a guest change.
* **Not covered here.** `memory.write_then_exec`, `memory.unpacked_capture`,
  `evasion.cpuid_probe`, `evasion.timing_probe` and the root-level `rootkit.*` and
  `privilege.cred_overwrite` rules need new guest data. `evasion.packed_image` uses
  the Static analysis Unpacking verdict (see Unpacking layers, 0.7.1).
* **Antinomie's own activity.** The resource collector of a base from before 0.7.0
  (uploaded as `/tmp/.antinomie-resource-<token>`, which removes itself) is
  recognised by that path and its tasks are left out. The terminal and the analyst's
  commands are outside a run's tree, and in a capture of the whole VM outside the
  scope above.

### Activity graph (0.7.1)

Host only: `monitor-ui/src/triage/graph/`, nothing needs a guest change.

* **Index.** The scan worker builds it from the rows the Suspicious table
  filters: `Collector` (`graph.rs`) is fed every row the engine returns, once for
  the table's view and filter (`GraphScan::index`, with lanes and the rows kept
  so a marker can open Details) and once for the default view without lanes
  (`GraphScan::overview`, which the Summary strip reads). A `Record` is 32 bytes
  (time span, count, lane, tier, category, phase, flags) and sorted by time; rows
  with no time are counted as `unplaced` and noted above the graph. Level 0
  buckets are `2^shift` ns wide so the run fits in 4,096; a `Cell` is one
  `(lane, bucket)` (rows by tier, worst tier, its category, category mask, first
  record) and only non-empty cells exist. Levels above are kept only while they
  hold at most half the cells of the one below, so the pyramid is at most twice
  the base; a finer level than asked is merged on the fly in the paint loop.
  Dense `Bin`s (tier counts, category counts and worst tier, phase weights) over
  all lanes feed the curve, the heat strip and the phases. 120,000 findings on
  2,000 lanes take about 11 MB; a million findings build in about 100 ms.
* **Lanes.** `lanes.rs` takes the process nodes in depth-first order; a lane's
  subtree is the lanes up to `subtree_end`, so folding is a range. Leaf siblings
  with the same parent, program and arguments fold once there are eight. Findings
  with no process of the run sit on lane 0. An injection finding (`injection.*`
  with an object `pid N`) draws an arrow to the lane of that pid alive at the time.
* **Phases.** `phases.rs`: each rule maps to a phase (by category; the download
  rules and the anti-analysis checks by id). Each base bucket takes the phase with
  the largest weighted sum; equal neighbours merge; a phase lasts until the next
  begins; a span lighter than 5 or, with a neighbour, shorter than 2 % of the run
  is absorbed into its heavier neighbour; at most 8 remain. INFO matches of
  Discovery and anti-analysis rules are counted by the engine without rows
  (`Output::info`) and 20 of them make a recon span.
* **Widget.** `widget.rs` allocates one area and returns `Action`s; it never
  touches the Triage view. `view.rs` is the window arithmetic, `input.rs` the
  hit testing (lane from y, record from x within 7 px, the worst tier wins) and
  the keyboard moves, `paint.rs` the colours (read from one `Palette`), the
  category glyphs and the bands. Individual findings are drawn when fewer than
  5,000 are in the window, otherwise one glyph per bucket at least 3 px wide.
* **Filter sync.** `tab.rs` runs the Suspicious activity filter bar for the Graph
  tab too (same draft, same chips, no pager). A brush, a lane or a phase is
  written into the filter text after what the user typed (`filter.rs` parses it
  back, so the filter is the one truth); the next frame's query bar re-reads the
  index, so the table and the graph change together. Selection is
  `selected_call_id` and the shared Details; a click in the graph sets
  `table_focus`, which scrolls the table to the row.
* **Room and window.** `view::Metrics::roomy` sizes the parts of the widget to
  the area it is given: lanes are `LANE_MIN` (24) to `LANE_MAX` (84) points high
  so a few lanes fill the height, what they cannot use goes to the curve, the
  label column is 16 % of the width (190 to 260) and the markers' radius follows
  the lane height. The Summary strip keeps `Metrics::compact`. The default window
  is `fitted_findings` (the findings' extent plus 6 %), and the buckets cover the
  findings only; `GraphIndex::run_extent` (processes included) bounds pan and
  zoom and is what **Run** shows. A pane shorter than `MIN_HEIGHT` (420) wraps the
  tab in a vertical scroll area. `window.rs` shows the graph in an immediate
  egui viewport (`ViewportId` hashed from the run), the same way detached
  workspace panels are drawn (custom title bar, `title_bar::resize`, an embedded
  `widgets::window` fallback), from `show_finding_windows`; it has its own
  `State`, shares the filter draft, chips and selection, lays Details out beside
  the graph with a draggable splitter, and keeps each run's size for the session
  and the last size in `Settings::graph_window`.
* **Spacing and the axis.** `axis.rs` maps a time to a place on the axis and
  back. `Spacing::Time` is the identity; `Spacing::Events` gives each distinct
  `first_ns` (`GraphIndex::slots`, built when the index is finished, with each
  record's `slot`) one unit, linear in time between two slots and at the median
  gap beyond the first and last. The window a graph shows (`State::window`) is
  kept in the units of `State::units` and converted when the spacing changes,
  so the same stretch stays on screen; pan, zoom and the shortest window
  (`Axis::min_span`, 1.5 slots) are in those units. Gaps of at least 8 times the
  median are `Slots::breaks` (at most 48, the widest). The pyramid stays by
  time, so in Events spacing the findings of the window are counted into columns
  of 3 pixels in one pass (`paint::event_pass`) that feeds the curve, the heat
  strip and the markers (120k findings paint in about 3 ms); few findings are
  still drawn one by one. Ticks are at slot boundaries (`paint::tick_marks`).
  `Settings::graph_spacing` (default Events) is handed to the view and saved
  back when the chip or `T` changes it.
* **Overview ruler.** `ruler.rs` draws a strip under the axis from `Marks`: for
  each pixel column the number of findings and the worst tier, over the whole
  run in the current spacing, built again only when the index
  (`GraphIndex::id`), the width or the spacing changes. The window on it is
  `(t0, t1)`; `begin` decides from the pointer whether a drag moves the window,
  pulls an edge or selects, `drag` and `selected` give the window, and a
  double-click gives the whole run (`Layout::range`). The brush in the filter is
  drawn on it from `State::brush`.
* **Hover, grips and the strip's zoom.** `State::hovered` is the marker under the
  pointer this frame (set before `draw`, from the same hit test the tooltip uses): it
  gets an accent ring (`hover_ring`) and `input::tooltip` returns a `Tip` that
  `tooltip_ui` lays out as a tier chip, the rule, what it did and a grid of facts. The
  ruler's grips are `GRIP_W` wide handles and the edge grab is `GRAB` (8 points). The
  Summary strip keeps `Strip::zoom` (0.6 to 3, buttons step 1.25, Ctrl+wheel through
  `zoom_delta`, the percentage resets): `Metrics::zoomed` scales the bands, the label
  column and `Metrics::text`, which the strip's labels and the axis multiply their font
  sizes by; painting stays one pass over the overview index, so zoom costs no more at
  120,000 findings. Opening the graph from the strip or its pop-out calls
  `TriageView::clear_finding_filters`, so the graph starts on what the strip shows.
* **Spinners.** `theme::spinner` turns in 100 ms steps and asks for a repaint
  every 100 ms; egui's own `Spinner` repaints every frame, which on software GL
  is the full frame rate for as long as an index is being read. All spinners go
  through it, and `triage/idle_tests.rs` asserts an idle view asks for no repaint
  within a second and a waiting one within 50 ms.
* **Live toast.** `notify.rs`: each scan carries the HIGH rules that have a
  shown row. `HighWatch` raises one `toasts::push` per `(run, rule)` while the
  run is live and `toasts::bump` adds `×N` to the same toast afterwards (a toast
  that was dismissed stays gone). The switch is `Settings::toast_high_findings`.
  With it on, a live run whose pane is hidden is still re-read every 15 s.
* **Tests.** `graph/tests.rs` (index, phases, lanes, filter text, hit testing,
  mouse and keyboard through egui, contrast of every theme, hover and the ruler's
  grips), `graph/sync_tests.rs` (filter sync with real scans, strip and its zoom,
  toast, the `native_graph_fixture` and `native_graph_view_fixture` for screenshots
  under Xvfb; the latter takes `ANTINOMIE_QA_SCENE`, `ANTINOMIE_QA_ZOOM` and
  `ANTINOMIE_QA_FILE`), `graph/bench.rs` (120k findings: paint under 4 ms,
  no repaint when idle, memory, the million-finding build).

### File activity: Per-file history tab (0.7.1)

Host only; it uses what the recordings already hold. **Per-file history** is the first tab
of Triage › Files, with the number of files on it (`Metric::History`;
`TriageView::history_tab`; a Changed file's Details button sets it and chooses the file). `file_activity::Window` (the tab's state, at
`TriageView::file_history`) draws into the section's `Ui`. It was a floating
`egui::Window`, whose side and central panels collapsed to a narrow frame with the
content spilling outside it, and whose Result column wrapped letter by letter.

* **Index** (`triage/file_activity.rs`). `FileIndex::note_activity` runs for every file
  call (in the early return of calls that change nothing and in the read/write path,
  before the change bookkeeping), with the call's `file_category::Hit`s, the path (the
  old name for a rename or link, the new one in `new_name`), the descriptor, the guest's
  file identity and, for a successful read or write, a `Transfer`: offset, length, the
  first 64 captured octets (`CapturedPayload::head`, up to the first uncaptured byte),
  whether captured octets are fewer than the transferred, and whether the write ended
  past the file's known size. `Builder` keys a file by its identity, else by the file its
  name leads to (`current`: a rename or link moves or adds a name, an unlink or rename
  frees one), else by the name, else by task and descriptor. Another identity at the
  same name is a second entry. Bounds: 4096 files, 512 calls a file, 100,000 calls, 16
  other names; the rest are counted and the window says so.
* **Kinds.** Delete, Rename, Link, Create, Open, Exec, Write, Resize, Read, Attributes,
  Map, Probe, Other, chosen from the hits in that order. A refused call is kept with its
  errno; a file with only refusals is marked. A delete notes the links left from the
  identity (`last name removed`, `1 link remains`); only a last name sets `deleted`.
* **Contents.** `FileIndex::finish_all` joins each activity to its `Change` (by identity,
  else path) for `Change::contents()`: sizes, the guest's hash, the change gaps and up
  to 32 runs of 32 differing bytes from `original`/`final_data` (`ByteRun`, `?` for an
  octet not captured, `added` past the original size). Nothing is inferred.
* **Graph** (`file_activity/graph.rs`). `layout` merges neighbouring calls of the same
  kind, process and outcome into nodes (60, then one `+N more` node), one lane per
  process; `show` paints boxes and elbow arrows with the theme colours and hit-tests
  clicks. The process names sit in a gutter that stays at the left of what is on screen
  (nodes are clipped at its edge); a name is cut to the gutter by `fit` and its whole
  text is the tooltip. `file_activity/window.rs` holds the list (filter, toggles, order,
  virtualised rows), the header chips, the calls (200 rows) and Content changes. The
  calls are the shared Triage table (`triage::table::table_rows`, table id
  `triage-file-calls`, in a horizontal scroll area sized to its rows) so it spans the
  pane like the others; a click on a row or on a file of the list selects it in the
  shared Details (`details::select`; tables `triage-file-calls` and
  `triage-file-history`), and a double-click on a call opens the original syscall (the
  first cell carries `stream.id`, `process.cookie` and `event.id`). The chosen
  file is kept by path and first call so a new index keeps it.
* **Tests.** `triage/files.rs` tests (story, links, identity reuse, rename without
  identity, offsets/lengths/content/extension, appends, refusals, bounds) and
  `triage/file_activity/tests.rs` (layout, limits, list filters, wording, the window
  through egui: choosing a file and a node, the syscall jump).
* **Guest records.** Files are grouped by `lifecycle.file_id` (device, inode, generation),
  so history follows a file across renames and hard links, and by path where no record
  exists. io_uring and AIO requests arrive through `async_files` as the calls they stand
  for and are marked `async` (`Event::via`). Hash records (`antinomie.hash/1` before a
  delete, `/2` at the last close with `HASH_WRITES`) are kept in order as `HashNote`s with
  their CHANGED flag and skip reason, and the window says when two digests differ.
* **Not in the host data (0.8.0, guest capture).** (0) Writes through a shared mapping
  leave no payload and no call; only a different hash at the last close shows the file
  changed, and which bytes is unknown. (1) Write payloads beyond what the
  tracer captures per call: the bytes of a large write are cut and marked `…`; a
  per-file write journal or content-addressed chunks would give the whole content.
  (2) The file position of each read and write (`f_pos`/`ki_pos`): without it an
  append, a shared descriptor and a descriptor opened before the capture have no offset.
  (3) The file's contents before the run changed it: an overwritten, truncated or
  deleted file, and a rename destination that was replaced, are known only from what
  the run read; a copy-on-first-write capture (or at least a size, and a hash at open)
  is missing. (4) Contents at the last close and just before an unlink: only SHA-256 up
  to 16 MiB exists. (5) Writes through shared mappings (`msync`), `sendfile`,
  `copy_file_range`, `splice`, reflinks and `fallocate` ranges. (6) The size after each
  write, so that "extends the file" is exact and not derived from reads.

### FLOSS strings in static analysis (0.7.1)

Host only. `AnalysisKind::Floss` ("FLOSS strings (decoded, stack, tight)") is a
Deep analysis check, off by default because a run takes minutes.

* **Tool.** `analysis_tools.rs` has a `floss` package (Mandiant FLOSS 3.2.0, the
  `floss-v3.2.0-linux.zip` release asset, 44 MB, one PyInstaller executable,
  Apache-2.0) installed like capa; a system `/usr/bin/floss` or
  `/usr/local/bin/floss` is used first. Tests use a shell script that prints
  FLOSS output, never the tool or the network.
* **ELF support.** FLOSS 3.2.0 loads x86 and x86-64 ELF files through vivisect
  (checked on a dynamically linked ELF: stack and decoded strings of a small
  program were found; static strings are switched off, `--no static`, because
  the Strings category has them). Other machines are not emulated. A statically
  linked program has thousands of routines and exceeds the 8 minute limit
  (`floss::TIMEOUT_SECONDS`); the section is then `Unavailable` and says so. FLOSS
  takes only files up to 16 MiB (`-L` is not passed).
* **Run.** `analysis/floss.rs` starts `floss -j -q --disable-progress --no static
  -- /input/specimen` in the analysis sandbox (offline, `/tmp` of 1 GiB like
  capa, 32 MiB of output at most) and reads the JSON document: `decoded_strings`
  (routine `decoding_routine`, seen at `decoded_at`), `stack_strings` and
  `tight_strings` (`function`, `program_counter`) and `language_strings` (a
  file offset). Strings are kept once per (type, text, routine). Addresses are
  the ones FLOSS reports for its own load of the file (an ELF is placed at a
  base of 0x2000000 when position independent), so they are recorded as
  object addresses, not file offsets; language strings have file offsets.
* **Rows.** `AnalysisData::FlossString { origin, encoding, function, address }`;
  at most 50,000 rows go to `listings/floss.jsonl` (the report keeps 256 as a
  preview) and the section is `Partial` when either bound cut rows.
* **Progress.** The check runs after the light checks, in the same tier as capa;
  the active tool shows as "FLOSS"; the worker deadline adds the run's
  budget. The FLOSS tab shows its row count as a badge like Strings.

### Host copy of an uploaded specimen (0.7.1)

Host and guest. Upload and Run puts the host file in the guest; static analysis
of that run no longer has to read it back.

* **Request.** The UI remembers the finished Upload and Run (`MonitorApp::uploaded`,
  the upload intent with its VM, boot and recording identity) and sets
  `ExecRequest::host_copy` (`#[serde(skip)]`: a host path is never saved with the
  run) only when the run's path is the upload's guest path in the same session.
* **Offer.** After `Jobs::submit` the backend calls `Jobs::offer_host_copy` when the
  guest offers `EXEC_HASH_ROOT`. The file must be a regular file of exactly the
  acquisition's length. It is copied to `specimen.host` in the report's folder,
  synced, read back and hashed there, so the hash is of the store copy and a later
  change of the original does not matter. The job keeps its guest handle but
  `Job::hold_for_host_copy` stops `acquire_next` reading from it for ten
  seconds (`HASH_WAIT`) or until a verdict.
* **Verdict.** `session_transport` and the pre-acknowledgement replay pass every
  ingested event to `launch_image_hash`: the `Exec` hash record of call 0 (the
  launched image). A script's interpreter, a file that changed while read or a
  hash the guest did not compute give no digest. `Jobs::guest_hash(run, digest)`
  sets the job `Matched` when the digest equals the staged hash, otherwise
  `Rejected`. A rejection or the end of the wait removes the staged copy and the
  guest fetch goes ahead unchanged.
* **Adoption.** On `Matched`, `specimen.host` is renamed to `specimen`, the partial
  guest file is dropped, the handle is released unread and the report is queued
  as after a transfer, so the analysis starts before (or without) the fetch.
  `specimen_sha256` is the staged hash, which equals the guest's.
* **Record.** `AnalysisReport::specimen_source` (`host_copy` or `guest`, absent in
  reports from before this and for host-only analyses) is set by the host and
  restored from the host's own report whenever a worker report is read
  (`read_report`). The Identity card shows it as **Specimen source**.
* **Limits.** The guest hashes files up to 16 MiB (`ANTC_HASH_FILE_MAX`); a larger
  program has no guest hash and is fetched. The guest records no hash for a file
  that has not run, so Analyze Only still fetches.
* **Tests.** `jobs/host_copy.rs` (match, mismatch, no hash, late hash, wrong size,
  the store copy is the one hashed, cancel cleanup, report round trip),
  `backend/tests.rs` (which exec record may vouch), `app/tests/upload.rs` and
  `analysis/workspace_tests.rs`.

### Pending analyses always settle (0.7.1)

A run's `analysis` record starts as `acquiring` with every section `pending`. It is
settled by `jobs::abandon` (Acquiring or Queued becomes `Unavailable`, Running becomes
`Partial`, sections follow, the reason is kept) wherever the work cannot go on:

* **The start failed.** `Session::failed_run_launch` calls
  `ProgramRun::settle_unstarted_analysis` before it saves `run.json`, so a run whose
  network capture or `EXEC` failed says `the run did not start: <error>`. (Before, the
  record stayed `acquiring` forever.)
* **The VM ended.** `Session::seal` shuts the job queue down, then settles any run whose
  analysis is still active and has no job (`settle_orphaned_analyses`).
* **The job was lost.** The same sweep runs after every analysis tick, so a run showing
  an active analysis that `Jobs::tracks` does not know is settled the same pass.
* **Load.** A saved run has no job queue behind it, so `saved_run` and `list_runs`
  settle an active analysis in memory with "interrupted: the app or the VM ended first".
  The files on disk are not rewritten.

Every wait in acquisition has a bound and says why it ended, and a failed job always
leaves the acquisition slot: `acquire_next` takes the job out of `acquiring` before it
can fail, and `chunk` does the same.

| Wait | Bound | When it expires |
| --- | --- | --- |
| Guest transfer (all chunks) | `TRANSFER_DEADLINE`, 120 s from submit | `Unavailable`, "specimen acquisition deadline exceeded" |
| One guest read or release | 100 ms request timeout | the read fails the job; a release leaves guest expiry to reclaim it |
| Guest hash for the host copy | `HASH_WAIT`, 10 s | the guest transfer goes ahead; waiting sections say why |
| Copying and hashing the host file | `COPY_BUDGET`, 10 s, checked per 256 KiB | the offer is refused, the guest transfer goes ahead |
| Durable report write | `PUBLICATION_DEADLINE`, 30 s from the end of the transfer | `Unavailable`, "did not finish within 30 seconds" |

Tests: `jobs/acquisition.rs` (stalled report write, failed fetch frees the slot, lost
handle, `abandon`), `jobs/host_copy.rs` (late and mismatching hash say why, copy
budget), `run.rs` (a failed start is settled in `run.json`) and `recording.rs` (a saved
run loads settled). The `Session` sweeps need a live session and are covered by the
VM-backed examples, not by unit tests.

### Checks added to a finished analysis (0.7.1)

Host only. The Categories card of the Static analysis Overview lists a **Run** button
for every `AnalysisKind` the report has no section for. It sends `ReportAction::RunCheck` and the app `Command::AnalyzeMore
{ directory, run_id, checks }`; the backend refuses a relative path or one with `..`
and queues it on `host_analysis`, which needs no VM.

* **Job** (`jobs/supplement.rs`, `Jobs::analyze_more`). The folder's `report.json` must
  be `Complete` or `Partial`, no job of that report id may be waiting, and the kind must
  be new (or `Unavailable`, which the backend accepts to run it again; the window does
not offer that, because the extra button widened the Unavailable row past the narrow
layout). The job's report is the saved one (same id, source path,
  hash, specimen source) with the new sections `Pending`; its specimen is a host-file
  copy of the retained `specimen` (`submit_host_opened_for`, which carries the run id)
  in `<folder>/extra/<id>`, so quota, reservation, cancel and the worker sandbox are
  the ordinary ones. The worker runs only `Pending` sections (`progress::pending_order`),
  budgets only those (`worker_deadline`, rlimits, `/tmp` size), and `progress::merge`
  leaves a finished section, listing included, as it is.
* **Merge** (`Job::merge_supplement`, called from `Jobs::finish`). Carried sections are
  taken from the saved report again, the new listings (`adopt_listings` skips carried
  kinds) and `output/artifacts` move into the folder (an existing name is an error),
  the job folder is removed and the report is saved in the folder as the original was.
  A failed or cancelled check leaves its section `Unavailable` with the reason and makes
  the report `Partial`. Unpacking queues its layers as it does after a first analysis
  (`queue_layers` is skipped when Unpacking was already there). Retained bytes count only
  what the job added (`Job::retained_len`).
* **Updates.** Updates carry the report's id and the run id; `host_analysis_updates`
  gives a run's report to the session run (`Session::run_analysis`, which saves the
  run summary) and does not list it among the standalone reports. The window follows
  by the `AnalysisUpdated` notification. A reopened recording reads `report.json`.
* **Tests.** `jobs/supplement.rs` (join and persist, failed check, refusals),
  `progress.rs` (pending-only order and deadline, finished sections kept),
  `backend/worker_disks/tests.rs` (plain paths, run versus standalone),
  `analysis/workspace_tests.rs` (Run enabled only when finished) and
  `app/tests/analysis.rs` (the command).

### Regex matches pane and window (0.7.1)

Host only. Core: `monitor-core/src/strings_regex/`; view: `monitor-ui/src/regex_matches.rs` (`RegexWindow`: `pane` for a pane, `show` for a window).

* **Patterns.** `catalog.rs` lists the built-in ones by category (network,
  crypto, keys, Linux behaviour, attribution, encoded); an id never changes
  because the rule manager stores the ids it switched off. `RuleSet::build` compiles
  them with the `regex` crate (size limits, so a pattern cannot be slow or huge)
  and a `RegexSet` of the same patterns names the ones worth running on a string.
  Matches are kept once per (pattern, text, encodings) with a repeat count; the list
  holds 50,000 and the category counts keep growing past it.
* **Validation** (`checks.rs`). Domains and the hosts of URLs and emails must end in
  a known public suffix with a registrable name (`psl`, already linked by
  `yara-x`); mixed-case names (`strings.Builder`) and the file-like suffixes
  `so sh py pl pm rs md cc ml ps zip mov run lib` count as hosts only after a
  scheme or an `@`. IPv4: four octets without leading zeros, not inside a longer
  dotted number, not after `v`, `version`, `release`..., classed (public, private,
  loopback, ...) in the type. IPv6 must parse. Bitcoin (base58check and bech32/bech32m),
  Tox ID (XOR checksum), Monero (block structure; the Keccak checksum is not
  verified and the note says so), JWT (header JSON with `alg`), SSH keys (blob
  starts with the key type) and Telegram tokens are structurally checked. A domain or
  address inside a URL or email is dropped in favour of the URL (`weak` patterns).
* **Encoded.** `encoded.rs` decodes base64 (standard or URL-safe) and hex runs of at
  least 24 characters (hex: 12 octets); a run is kept when it decodes to text (90 % printable
  and a quarter letters) or to a known magic (ELF, ZIP, gzip, PE, script...). Text
  is scanned again; two levels deep at most, 8,192 characters per string.
* **Sources** (`sources.rs`). A report scan reads the Strings and FLOSS listings through
  the validating `read_listing_page_with`, so a corrupt listing is rejected as it
  is for the tables; string offsets become match offsets (UTF-16 counts two octets per
  character). A core scan takes the extracted core strings (virtual addresses) and
  `sockaddrs` reads the captured memory in 1 MiB blocks for `sockaddr_in`
  (family 2, nonzero port, address not 0 or 255 or multicast, eight zero octets)
  and `sockaddr_in6` (family 10, zero flow label, nonzero address and port, scope
  up to 65535) on 2-octet boundaries, at most 20,000.
* **Rule manager.** `Config` (`rules/strings-regex.json`, atomic write, 1 MiB read limit)
  holds the switched-off ids and up to 200 custom patterns (2,048 characters each,
  compiled with the same limits before they are saved). The Detection rules page has a
  Strings regex tab with the switches, the custom patterns and a "Try on" field.
* **Placement.** Static analysis draws `RegexWindow::pane` in its own Regex matches tab
  (`workspace/tabs.rs::regex_view`; the same view fills a separate pane opened from the
  category list, and the tab stays enabled when the check was not requested so it can
  offer Run). The tab asks for its scan once per report (`WorkspaceState::take_regex_request`, taken by
  `app/panels.rs` as `ReportAction::ScanRegex`) when a Strings or FLOSS section is
  done **and** the report has a Regex section (`AnalysisKind::Regex`, "Regex matches",
  a Triage check after Strings that needs Strings or FLOSS, `AnalysisSelection::validate`).
  The section is a marker: the worker records that the run asked for the matches, the
  matches themselves are read with the patterns as they are when the tab opens. A report
  without it (one made before 0.7.1's change, or with the check off) shows "Regex matches
  are not part of this analysis" and a **Run** button (`ReportAction::RunCheck`); the
  Overview's Categories lists Regex beside Strings and opens the Regex matches tab for it.
  Core dumps keep the floating window (`show`) behind **Regex matches…**.
  A saved `AnalysisSelection` is read through `SelectionWire`: one without the
  `regex_split` mark that lists Strings or FLOSS gets Regex added once, and it is
  written back with the mark, so unchecking Regex later sticks.
* **Scan.** The scan runs on a worker thread; reopening a report whose scan
  exists shows it as it was, **Scan again** rereads the configuration. A pattern that
  does not compile is listed in the window and skipped.

### Unpacking layers (0.7.1)

Host only. `AnalysisKind::Unpacking` is a Triage check (on by default); the code is
`monitor-core/src/analysis/unpack.rs`, `unpack/upx.rs` and `jobs/layers.rs`.

* **Scope.** UPX only, on ELF (and PE through `upx -d`). Nothing runs the
  specimen: `upx -d` decompresses data, the analysis worker is the offline bubblewrap
  sandbox, a layer is written `0600`, the unpacker's work is confined to
  `output/artifacts/unpack/` of the worker (a bind of the report's folder), and the
  specimen's own file is never opened for writing (the unpacker works on copies).
  Packers that must run the program, and unpacking by emulation or from guest memory
  (the `memory.unpacked_capture` rule), need the guest and are 0.8.0 work. Other
  unpackers were looked at: unlicense targets Themida/WinLicense PE files through
  emulation and Frida (Windows, and it runs code); no non-executing unpacker exists for
  common Linux packers other than UPX, so the chain is built so that a further unpacker
  is another `detect` and `unpack` pair beside `upx.rs`.
* **Limits.** Three layers (a file packed deeper stays packed and the section says so),
  64 MiB per layer and 192 MiB in all (the worker's file size limit also holds), 60 s
  for one `upx` run and 240 s for the whole section (the worker deadline adds 30 s), a
  layer equal to one already seen stops the chain. The quota check reserves the 192 MiB
  when the check is selected.
* **Damaged headers** (`upx.rs`). A packed ELF has `l_info` right after its program
  headers (checksum, `UPX!`, size, version, format) and, near its end, the pack header
  (`UPX!`, the same version and format, method, level, sizes) with a 4-octet overlay
  offset after it and, before it, a zero word with another `UPX!`. Detection looks for
  the last place after `l_info` whose version and format are `l_info`'s and whose sizes
  are plausible, whatever the magic says, so a file whose magic was overwritten is still
  found and says what changed. Mending works on a copy: the magic restored in the three
  places, nothing kept after the pack header. UPX 4.2.4 and 5.2.1 unpacked the mended
  copy of a file with each place overwritten, and with appended data, to the original
  byte for byte. A file with changes is tried mended first, then as it is; any other
  file is tried as it is, then mended.
* **Report.** One `Layer` row per phase (index, parent, method, SHA-256, size, packer,
  file `layer-N.bin`, and the id of the layer's own analysis once the host queued it);
  `layers.json` in the folder repeats them. `unpack_layers(report)` and
  `packer_verdict(report)` read them back: these hashes are what the IOC window's
  Files list will take (that window is not in this branch).
* **Tab** (`monitor-ui/src/analysis/workspace/unpacking.rs`). A `Layer` drop-down
  (`WorkspaceState::unpack_layer`) chooses one layer; a group below shows its size,
  hash, packer, note and, for an unpacked layer, **Show its analysis**. The first
  version drew every layer as a framed phase in a horizontal scroll area; the frames
  took the horizontal layout, so their text laid out in one row and wrapped letter by
  letter.
* **Layer analyses** (`jobs/layers.rs`). When a job with layers finishes, the host opens
  each `layer-N.bin` with `open_regular` (confined, not a link), checks size and SHA-256
  against the validated row, copies it as a host-file job into
  `<report folder>/layers/N/` and queues the packed file's checks without Unpacking.
  The new report has id `<id>-L<N>`, `AnalysisReport::layer` (parent, index, method,
  parent hash) and no run: the run keeps the packed file's report. The worker's rows
  cannot name a report; only the host fills `report_id`, and a worker report whose
  `layer` differs from the request is refused. A layer that cannot be checked is noted
  in its row and not analysed. `analysis_directory` of a layer is its parent's folder
  plus `layers/N`; the Report box lists it as "layer N unpacked by UPX" and it does not
  take over the selection when it appears.
* **Tool.** UPX 5.2.1 (`upx-5.2.1-amd64_linux.tar.xz`, 664 KB, SHA-256 pinned, one static
  executable) is the `upx` package of Tools > Analysis tools; a system `upx` is used first.
  Tests use a shell script in its place.
* **Triage.** `evasion.packed_image` (Evasion, T1027.002, LOW; MEDIUM when the packer's
  headers had been changed) is raised at the first exec of the run's root task when its
  path is the report's path (or the same file name for a path typed relative). The
  verdict reaches the engine through `ScanRequest::packed` and `Options::packed`.

### API keys window (0.7.1)

Host only. `monitor-core/src/api_keys.rs` owns every key; `monitor-ui/src/api_keys_window.rs`
is Tools > API keys.

* **Storage.** `<data dir>/api-keys.json` (`{"schema":1,"keys":{"abusech":…,"malshare":…}}`),
  written through `storage::atomic_json`, whose temporary file is created 0600
  before a byte is written, then renamed; `<data dir>/api-key-use.json` holds
  last-used times only. The abuse.ch Auth-Key is one entry for MalwareBazaar,
  ThreatFox and URLhaus. A `samples/api-keys.json` from an older version moves
  into the new file on first read and is deleted. Keys are not part of
  Settings, run exports, catalogs or saved URLs.
* **Handling.** A key travels as a `Secret` (its `Debug` prints no text).
  `curl` gets it on standard input (`-H @-`, or `-K -` for MalShare), never on a
  command line; `redact` removes it from error text that a server could echo.
  `masked` shows the last four characters of a key of at least eight, else "set".
* **Test.** abuse.ch: a one-sample MalwareBazaar tag search; MalShare:
  `getlimit`. Both run in a worker and record a use time on success.
* **Samples.** `samples::source_key` reads this store. The Malware samples
  window has no key field: it shows a notice and an **Open API keys…** button
  (`SamplesView::take_open_keys`) and reads the key again after a change.

### IOC datasets in the Rule manager (0.7.1)

Host only. `monitor-core/src/ioc/` holds the datasets; `monitor-ui/src/rules_window/ioc.rs`
is the IOC tab of Tools > Detection rules; `monitor-core/src/known_fp.rs` is the
false-positive list.

* **Feeds.** `feeds.rs` has the table of seven (`threatfox`, `urlhaus`,
  `urlhaus-payloads`, `feodo`, `sslbl-ja3`, `sslbl-cert`,
  `urlhaus-recent`): URL, usual size, terms, whether the download needs the
  Auth-Key (ThreatFox, URLhaus, the payload list and the recent list do) and
  whether it is on by default (`urlhaus-recent` is not, so `update_all` and the
  matcher skip it until it is switched on). The abuse.ch exports are
  `https://{threatfox,urlhaus}-api.abuse.ch/v2/files/exports/<key>/…`
  (`full.csv.zip`, `payload.csv.zip`, `recent.csv`); the table holds the URL as
  a template with `{key}`, `Feed::url_for(&Secret)` fills it (an empty key, or
  one with a character outside `A-Za-z0-9._~-`, is refused before any request),
  `Feed::url_display()` shows `****` and `Feed::owns(url)` matches a URL to its
  feed. Feodo and SSLBL are unchanged and keyless. Stored under
  `<data dir>/ioc/feeds/<id>/`: `meta.json` (data file name, fetch time, record
  count, size, SHA-256, URL) is the commit point, `data-<time>-<n>.txt` the plain
  text, `last-error.json` the reason of a failed update. `settings.json` lists
  the feeds switched off and the ones switched on that are off by default. Nothing of this is in the repository or in run exports.
* **Update.** `download.rs`: manual only. A feed is fetched through the rule
  manager's `Fetcher` (HTTPS only, bounded, cancellable), into a private folder
  under `ioc/staging/`, unpacked if it is a zip (one `.csv`, `.txt` or `.json`
  member is streamed to a fixed path, so the member's own name is never used;
  at most 64 entries and the feed's text limit), parsed completely
  (a download with no records, or mostly lines that are not records, is
  refused), then the new data file is renamed into the feed folder and
  `meta.json` is replaced atomically; older data files are removed last. A
  failure or cancel leaves the previous copy and `meta.json` untouched, records
  the reason in `last-error.json` (stored URLs and messages carry `****` for the
  key) and is reported by name (`Updated 5 of 6.
  Failed: SSLBL JA3: …; the previous copy was kept`). Free space for the download
  and the text is checked first. A dataset over 14 days old is flagged
  (`FeedMeta::stale`).
* **Parsing.** `records.rs` reads each feed as a stream, finding columns by the
  names in the `#` header line (with fixed defaults) so a reordered file still
  works. A line is reduced to the normal forms of the values it could match
  (`kind.rs`: `ip:port`, domain, URL without scheme/default port/fragment,
  SHA-256, MD5, SHA-1, JA3, certificate SHA-1); the full record is built only for
  a value somebody asked about. The tests use small files in the feeds' real
  formats; the real feeds are never downloaded by tests.
* **Known false positives.** `known_fp.rs`: entries `{value, kind, dataset?,
  reason, added}` in `<data dir>/known-false-positives.json`; `add`, `remove`,
  `load` and `find` are the whole API, so another window can use the list.
  An entry with a dataset excuses only that dataset's records; one without
  excuses any.
* **UI.** The IOC tab shows the Auth-Key state, a stale banner, a table (on/off,
  dataset, used for, records, size, date, age, state, Download/Update), details
  (source, terms, stored copy, last failure) and the false-positive list. It
  uses the Settings permission for outbound downloads like the other tabs.

### abuse.ch Suricata rule packs with update checks (0.7.1)

Host only. `monitor-core/src/ruleset/abusech.rs` and `monitor-ui/src/rules_window/abusech.rs`
(the **abuse.ch** tab of the IDS engine).

* **Packs.** `LIVE_PACKS`: `abuse-ch-threatfox` (`threatfox_suricata.tar.gz`) and
  `abuse-ch-urlhaus` (`urlhaus_ids.tar.gz`), both under
  `…-api.abuse.ch/v2/files/exports/<key>/` (Auth-Key),
  `abuse-ch-feodo`, `abuse-ch-sslbl-ja3` and
  `abuse-ch-sslbl` (the certificate pack that was already in the catalog, same
  id). Each is a `SourcePack` for the `ids` engine built from the file that was
  just downloaded, so it goes through `install_source` like any pack (filter,
  index, provenance, the previous version kept on failure). The aggressive files
  are never listed.
* **Pin.** The publisher rewrites the file in place, so the pin is the snapshot:
  `revision` is abuse.ch's `Last updated` stamp (`YYYYMMDDTHHMMSSZ`, or `snapshot`
  when the file states none) plus the first 8 hex of the SHA-256, and the source
  is a pinned `file` download with that digest, so the install verifies exactly
  what was checked.
* **Archives.** `rules_text` recognizes a download by its first bytes: gzip is
  read as a tar, `PK` as a zip, anything else as the rules text itself. Only
  regular files whose name ends in `.rules` are taken (symlinks, hard links,
  directories and every other member are skipped; a name with `..`, a leading
  `/`, a backslash or a drive letter is skipped). Limits: 2,000 entries read,
  64 rules files, 32 MiB of rules text in all and per member, and the gzip
  stream is cut at four times that; an archive with no `.rules` member is an
  error. The members are joined in name order into one rules text, and that
  text is what is cached, pinned and installed (so the pin and the `file`
  format below are unchanged). Nothing is ever written under a member's name.
* **Retired pack.** `retired_if_empty` marks the SSLBL JA3 pack: if abuse.ch
  serves `ja3_fingerprints.rules` empty, an empty or comment-only file is a
  valid answer with 0 rules (HTML or other text is still an error);
  `live_states` reports `LiveStatus::Retired`, the tab shows "Retired
  upstream" with the install buttons off, and `install_live` returns a message
  rather than installing. The SSLBL IP list (`sslipblacklist.csv`/`.rules`,
  header only since 2026-06-30) has no dataset and no pack; a stored copy under
  `ioc/feeds/sslbl-ip/` is ignored and `update_all` removes it
  (`feeds::remove_withdrawn`). IP matching comes from `feodo`, `threatfox`
  `ip:port` and `urlhaus` (URLs and IP hosts).
* **Check and update.** `check_live` downloads the file into staging, unpacks
  it, refuses anything without a rule line, keeps it as `rules/live/<id>.rules` and records
  `{at, sha256, size, stamp, rules}` in `rules/live/checks.json`. A pack is not
  requested again until [`MIN_CHECK_SECONDS`] (300) have passed; inside that
  window the recorded answer is returned and no request is made, however often the
  button is pressed. `install_live` runs a check (reusing a fresh one) and installs
  from the kept file through a `Fetcher` that copies it, so check plus install is
  one request. `live_states` compares the installed pack's download digest with
  the last snapshot: Not installed, Not checked, Up to date or Update available.
* **Key.** The Auth-Key is a path segment of the two keyed URLs, so it is
  handled as a secret everywhere a URL goes. `Curl` (`ruleset/source_fetch.rs`)
  passes the URL to curl as a configuration on standard input (`-K -`,
  `url = "…"`), never as an argument, so it is not in `ps` or
  `/proc/<pid>/cmdline`; a URL with a quote, backslash or control character is
  refused. The `Curl` type no longer holds a key or sends an `Auth-Key` header
  (the online IOC check and the sample search still send theirs on stdin, as
  before). `redact_url` turns `/exports/<key>/` into `/exports/****/` in every
  message `Curl` produces (timeouts, size limits, redirects, HTTP status, curl's
  stderr) and in `https_host` errors; `update_feed` and `check_live` also
  remove the key text itself with `api_keys::redact`, so an error that echoes
  the key without a URL is covered. Stored URLs (`meta.json`, the source pack
  and registry) use `url_display()`. The key must be letters, digits and
  `- _ . ~` (checked when it is saved and again when a URL is built). Status
  codes: 401 or 403 from an abuse.ch host is "abuse.ch rejected the Auth-Key
  (HTTP 401); check it in Tools > API keys, or get a free one at auth.abuse.ch",
  404 is "abuse.ch has no file at this address (HTTP 404); the export may have moved
  or been renamed, so update Antinomie", 410 is "abuse.ch has retired this
  endpoint (HTTP 410); update Antinomie", 429 and 5xx say to try again later. A feed
  that needs the key and has none is refused before any request ("needs the abuse.ch
  Auth-Key (free at auth.abuse.ch); set it in Tools > API keys"). The free-space check
  of a dataset download is three times its expected size (at least 64 MiB), not the
  sum of the largest download and text the limits allow.
* **Tests.** Fixtures in the packs' real format and mock fetchers; no request
  leaves the machine.

### IOC window and the Network tabs (0.7.1)

Host only. Core: `monitor-core/src/ioc/` (`indicator`, `verdict`, `online`,
`export`, `strings`, `disk`). UI: `monitor-ui/src/triage/` (`ioc_scan.rs`,
`ioc_view.rs` and `ioc_view/`, `net_tabs.rs`, `rules/ioc.rs`, `files/ioc.rs`).

* **Collector.** `indicator::Collector` merges plain observations into
  `Indicator`s of five types (endpoint, domain, URL, TLS group, file), each with
  its sources, first and last time (host microseconds), per-source details,
  evidence jumps and the normal-form values it can be matched by (`lookups`).
  A private address, a local name or a file with no content has no lookup and
  reads `Not checked`. A process is named only when exactly one process made a
  matching call: an endpoint by its own `connect`/`sendto` calls, a URL or TLS
  row by its `ip:port`, a domain by the addresses it resolved or reached, a file
  by the task that made the call; several processes give `candidates` and no name.
  Each list stops at 20,000 and counts what it dropped.
* **Where the observations come from.** The packet scan: `Inventory`
  (`triage/network.rs`) now also keeps the remote `ip:port` of every frame (the
  non-local side, else the lower port), HTTP requests, DNS answer codes and TLS
  sessions (client hello joined to the server hello and certificate by
  `tcp.stream`; the certificate SHA-1 is computed from TShark's DER; TLS 1.3 hides
  the certificate). New TShark fields: `tls.handshake.ja3s`,
  `tls.handshake.certificate`, `frame.len`,
  `tls.handshake.extensions.supported_version`. The rules pass
  (`rules/ioc.rs`) logs each `connect`/datagram `sendto` and each successful exec
  (with the guest's SHA-256 of the image when it is the program itself). The files
  come from the existing `Change` records (`files/ioc.rs`): created, written at
  close (with the guest's hash), changed, deleted. The sample's hashes and strings
  come from the static report (`strings::scan` finds `ip:port`, URLs and domains;
  file extensions are not domains). Not collected: the eBPF/audit `connect`
  records (`kernel` source).
* **Disk hashes.** `ioc/disk.rs`: with a saved, readable disk dump in the run's
  recording folder, the created, changed and written files (up to 2,000, 256 MiB
  each) are hashed by the sandboxed disk reader (`DiskRequest::Info`) for SHA-256
  and MD5; the answer is kept while the dump and the list stay the same.
* **Matching.** `verdict::scan_datasets` reads each usable feed once, as a stream,
  for the set of wanted values; `Scan` indexes the hits by value (at most 6
  records per value). `evaluate` decides the verdict from the loaded feeds that
  can answer for the type (`coverage`), the hits, the known false positives
  (`known_fp::find`, an entry for a dataset excuses only that dataset) and any
  online answers; the date is that of the oldest feed that answered (the feed that
  matched, for a match). A TLS row needs an SSLBL feed (JA3 or certificate). The answer is cached in
  `ScanRequest::ioc_cache` under a key of the wanted values and the datasets'
  `(id, fetch time, switch)` list, so the 5-second refresh of a live run does not
  read the feeds again; a dataset update, a false-positive entry or an online
  answer changes the scan's stamp and rescans.
* **Findings.** `ioc_scan::list_findings` hands each Matched indicator to
  `Engine::ioc_match`, which records a `c2.ioc_match` row (category C2, T1071,
  tier by confidence) with packet or call evidence, folded by task and object, so
  it reaches the findings journal, the graph, the Summary and the live toast like
  any other row. Known FP and online-excused values make none.
* **View.** `View` keeps tab, filter text (the table filter language,
  `FIELDS`), verdict chips, selection, the verdicts (rebuilt when the scan, the
  false-positive list or the online answers change), a session-only online
  switch and the online job. Export writes `<run>/ioc/ioc-<type>-<time>.csv|json`
  (files 0600, never replacing one; CSV cells that start with `=+-@` get a
  leading apostrophe). The online check (`ioc/online.rs`) asks ThreatFox
  `search_ioc`/`search_hash` and URLhaus `host`/`url`/`payload`, key on curl's
  stdin, only to abuse.ch hosts, 50 values at most per press, and stops at the
  first refusal.
* **Network section.** It shows Endpoints, Domains, URLs and TLS (`net_tabs.rs`).
  The 0.7.0 layout (IPs, Hosts, HTTP, DNS, Sessions) and the switch to it were removed
  after 0.7.1's preview: the scan no longer pages those rows (the DNS and session rows
  still go to the observer for the detection rules, the Domains and TLS tabs and the
  journal). The tables use their own query slots (17 to 19; URLs reuse slot 3 and its
  HTTP fields), and
  `ENDPOINT_FIELDS`, `DOMAIN_FIELDS` and `TLS_FIELDS` keep the old names
  (`network.country`, `dns.name`, `session.alpn`) beside new ones. The IOC column
  is added after paging, from the verdicts of the same scan.
* **Tests.** Core: record parsing of each feed format from small fixtures, the
  collector's process rule, verdicts under missing, partial, old datasets, false
  positives and online answers, the online request shapes and key handling with a
  mock transport, the CSV/JSON export. UI: a fixture pcap scanned with and without
  datasets (served by a mock fetcher), the finding and its removal by a false
  positive, the tabs and the layout switch, export, the session-only online
  switch, and the rules-pass recorder.

### Network routes (0.7.1)

Per-run routing of the guest's traffic, modelled on CAPE's rooter options (none,
Internet, InetSim, Tor, VPN) but without a root daemon: no iptables, no network
namespace, no TUN or tap device, no `sudo`. Host side only; nothing is installed
or patched in the guest. Code: `monitor-core/src/route.rs` and `route/`, the
backend wiring in `backend/run_route.rs`, the interface in
`monitor-ui/src/route_ui.rs` and `app/route_settings.rs`.

**How guest networking worked.** A VM's network was QEMU user networking
(`-netdev user,id=net0`, with `restrict=on` for Isolated) or no card at all
(`-nic none`); `nat` and `isolated_network` in `VmConfig`. A network capture is
a `filter-dump` object attached to `netdev=net0` over QMP, so it records the
frames the guest NIC sees. The user-mode netdev is fixed for the VM's life,
and slirp cannot send a connection through a SOCKS proxy, so a route cannot be
chosen per run on it.

**The Routed network.** A third mode, `VmConfig::routed` (VM dialog: Network >
Routed), wires the NIC (`nic_option`, unchanged, so the stealth profile still
applies) to `-netdev stream,id=net0,server=off,addr.type=unix,addr.path=<runtime
folder>/net.sock` (QEMU 7.2 or newer; checked before launch). The socket is
owned by a `Gateway` thread inside Antinomie, created before QEMU starts and
stopped with the VM process (`VmProcess::gateway`). The gateway is the guest's
whole network: ARP (MACs `52:55:` plus the address, as slirp does), a DHCP
server giving the lease QEMU's user network gives (10.0.2.15/24, router
10.0.2.2, DNS 10.0.2.3, or the profile's NAT network, so the guest configures
itself unchanged), a DNS server, ICMP echo for its own addresses, and a small
TCP endpoint per guest connection (`tcp.rs`: in-order segments, constant window,
go-back-N retransmission; the link is a local socket and loses nothing). Each
accepted connection is dialed upstream on a thread (`upstream.rs`) and the bytes
are relayed through bounded queues, so a slow upstream is a segment the guest
retransmits. IPv6, fragments and everything else are counted and dropped.
Because the capture is on the NIC, **the pcap is the guest-side view on every
route**; nothing about capture changed.

**Routes.** `RouteKind`: `Drop`, `Internet`, `InetSim`, `Tor`, `Vpn`, `Socks5`.
The gateway starts on `Drop` (nothing leaves) and a run changes it only through
`Gateway::claim`.

| Route | DNS | TCP | Other UDP |
|---|---|---|---|
| Drop | unanswered (counted) | SYN dropped, like a firewall (counted) | dropped, counted |
| Internet | the host resolver, on a thread | the host connects, public addresses only: not the gateway, the guest network, loopback, link-local or (unless allowed in Settings) RFC 1918 | dropped, counted |
| InetSim | every A query answers the sinkhole (198.51.100.1), AAAA is empty | any address and port reaches the built-in services (HTTP, SMTP; other ports accept and discard, no TLS) or an external INetSim at `port + offset` | dropped, counted |
| Tor, VPN, SOCKS5 | every A query answers a placeholder in 198.18.0.0/16 and the gateway remembers the name; the connection to that address is sent to the proxy as the **name** (SOCKS5 `ATYP 3`), so the proxy resolves it and no lookup leaves the host | SOCKS5 CONNECT through one upstream path (`socks.rs`, RFC 1928 with RFC 1929 login) | dropped, counted |

* **One upstream SOCKS5 path.** Tor is either Antinomie's own tor (`TorMode::Own`,
  the default; see below) or a SOCKS address the analyst gives (`TorMode::Socks`,
  default 127.0.0.1:9050, nothing started). VPN is
  WireGuard through **wireproxy** (ISC licence): a userspace WireGuard client that
  exposes a SOCKS5 port, run as a separate process with the analyst's own
  configuration file. Antinomie starts it for the run (`managed.rs`: stdout and
  stderr to an owner-only `wireproxy.log`, refuses to start when something else
  already listens on its port, waits for the port, kills it by its recorded
  handle when the route is released or the VM ends). SOCKS5 is any proxy the
  analyst gives, with optional user name and password.
* **OpenVPN is unsupported.** It needs a TUN device (root or `CAP_NET_ADMIN`)
  and there is no userspace OpenVPN client that exposes a socket. An analyst who
  has OpenVPN can run it in a container or namespace of their own with a SOCKS5
  front end and use the SOCKS5 route. Antinomie never uses `sudo`.
* **DNS and UDP.** Over SOCKS5 and Tor, DNS is SOCKS5 hostname resolution (Tor's
  DNSPort is not needed). UDP is not carried (SOCKS5 UDP ASSOCIATE is not used,
  Tor does not support it): UDP other than DNS and DHCP is dropped and counted.
  A name that does not exist therefore shows as a refused connection rather than
  NXDOMAIN. The 198.18.0.0/16 placeholders are cleared when the route changes.
* **Own tor** (`route/tor.rs`). `start_tor` runs in `Gateway::claim` through
  `managed::start_for`, so a failure drops the process and leaves the gateway on
  Drop. It makes `<data>/network/tor/<slot>` (the slot is the gateway's runtime
  folder name; one tor per gateway, so two VMs never contend for a DataDirectory
  lock) and its `data` folder with mode 0700, writes `torrc` (0600) with
  `DataDirectory`, `SocksPort 127.0.0.1:<free port>`, `ControlPort 0`,
  `CookieAuthentication 0`, `ClientOnly 1`, `SafeLogging 1`, `Log notice file
  <slot>/tor.log` and, for the bundle, `GeoIPFile`/`GeoIPv6File`; no other
  listener is configured. The port comes from binding 127.0.0.1:0 and releasing
  it; if something takes it first tor cannot bind, exits, and the route reports
  tor's own output (`tor.out`). tor runs with `--defaults-torrc` pointing at an
  empty file and `-f torrc`, so the system's torrc files are not read. No control
  connection is used: bootstrap progress is the last `Bootstrapped N%` line of
  `tor.log`, truncated at each start, and 100% is the ready signal. The wait is
  `managed::TOR_WAIT` (120 s); on expiry the error gives the last percentage and
  its text and the log path. The bundle's tor needs its own libevent and OpenSSL,
  so for the managed copy `LD_LIBRARY_PATH` is set to its `tor/` folder; a tor
  from the system or a path the analyst set runs with the environment as it is.
  The route's SOCKS port is filled in after tor starts (`RouteSpec::set_socks_port`)
  and the usual SOCKS check (greeting plus the check target) runs before the
  claim succeeds. The settings Test uses the slot `settings-test`.
* **Tools.** INetSim (GPL-2.0) is user provided and not bundled. tor
  (BSD-3-Clause) and wireproxy (ISC) are run as separate processes and are found
  in this order by `config::find_program`: the path set in Settings (an error if
  it is not a file), `PATH`, the usual system places
  (`analysis_tools::system_candidates`), then Antinomie's own copy. The own copy
  is a managed tool in `analysis_tools.rs`, installed on request and not part of
  first run or the Library tools list (`is_route_tool`); Settings > Network routes
  draws its row with `tools_page::tool_row`, the row Library uses. wireproxy 1.1.3
  is the `wireproxy_linux_amd64.tar.gz` asset of windtf/wireproxy (SHA-256
  `e88c1d09...`, the digest GitHub lists). Tor is the Tor Expert Bundle 15.0.26
  (Linux x86-64; tor 0.4.9.14) from archive.torproject.org, which keeps old
  versions where dist.torproject.org does not (SHA-256 `19cf1872...`). The
  installer checks the SHA-256 only. The bundle's OpenPGP signature (Tor Browser
  Developers key, EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290) was verified
  once with `gpg` when the pin was made. Checking it at install time would need
  the key shipped and an OpenPGP implementation (a new dependency, or `gpg`
  on the user's machine) and would check nothing the pinned hash does not, since
  the hash names those exact signed bytes.

**Fail closed.** `route::claim_for_run` runs before the run's directory or
artifacts exist. It picks the route (the request, else the saved default), builds
the checked `RouteSpec` (a missing setting, file or program is an error) and calls
`Gateway::claim`, which starts wireproxy, then **proves the route is up**: a SOCKS
route must answer the SOCKS5 greeting and login and, when it has a check target
(defaults: `check.torproject.org:443` for Tor, `1.1.1.1:443` for SOCKS5), connect
to it through the proxy; an external INetSim must accept a connection. Any
failure is the run's error, the gateway stays on Drop, wireproxy is stopped, and
nothing falls back to another route or to the host's network. A VM that is not
Routed has one fixed network: a request for another route is an error. A route
that goes away mid-run (the proxy dies) makes new connections fail (refused), it
does not redirect them. When the last run holding a route ends, the gateway goes
back to Drop, every connection made under the route is reset and wireproxy is
stopped (each connection and each placeholder address carries the route
generation it was made under, so a connection opened right after a claim is not
mistaken for an old one). ICMP echo is answered for the gateway's own addresses
only and counted otherwise. Runs that overlap on one VM must use the same route
("another run in this VM is using the route ..."). The check runs on the worker
thread before the sample starts, at most about 30 s for wireproxy (start 15 s,
check 15 s) and up to about 135 s for the own tor (bootstrap 120 s).

**Metadata.** `RunSummary::route` (`run.json`) and `RunArtifacts::route`
(`artifacts.json`) hold a `RouteRecord`: `kind`, a plain-text `label` (`Tor via
127.0.0.1:9050`; host and port only), `via` (`gateway`, `vm_nat`, `vm_isolated`,
`vm_disconnected`), `checked_ms` and, once the run's process tree ends, `stats`
(TCP connections, failures, blocks, DNS queries and unanswered, UDP/ICMP/other
dropped, bytes). Counts are for the whole VM during the run, like the capture.
Both fields are absent in older runs, which the UI shows as "Not recorded". A run
restored from a snapshot keeps its record, gets an issue saying the route is not
carried over, and the restored VM's gateway starts on Drop. `ExecRequest::route`
is the per-run choice (`None` is the saved default).

**Settings and secrets.** `<data>/network/routes.json` (`RouteConfig`) is
written through `storage::atomic_json` in a 0700 folder and chmod 0600, the same
as the sample sources' `api-keys.json`; it holds the default route, the Tor
address, the wireproxy program and configuration paths, the SOCKS5 host, port,
user name and password, the InetSim mode, host, port offset and sinkhole, and
the check targets. The backend reads it when a run starts, so the password is
never sent through the command channel. `Debug` for the SOCKS5 settings and the
resolved credentials is redacted; the password is not in a label, a record, a
log or an export (the wireproxy configuration is the analyst's own file and is
passed by path).

**Interface.** VM dialog: Network > *Routed (route per run)*. Run form, Network
section: the **Route** selector (a Routed VM; any other VM names its fixed
network) with what the route does and a warning for the Internet route or a
missing setting. Settings > Network routes: default route, per-route
configuration and a **Test** button (brings the route up the way a run would,
including wireproxy and the own tor). The Tor and VPN sections show the
program's status, version and Install/Remove button. The route is shown in Run History's run details, above the
Triage run header, in Triage > Summary > Network evidence and in Triage > Network.

**Tests.** `route/tests/` drives the real gateway over a Unix socket with a
scripted guest (DHCP, ARP, DNS, a small TCP client with retransmission) and a
fake SOCKS5 server that is also the far end: Drop, InetSim (built-in and
external), Tor, SOCKS5 with login, refusals, fail-closed claims, overlapping
runs, reset on release, 400 KB up and 500 KB down, wireproxy start and stop with
stand-in programs, and the own tor with a stand-in `tor` script (private modes,
torrc contents, library path, bootstrap parsing, a tor that exits, stalls or
does not speak SOCKS, stop on release). The managed tools are tested with the
pins and unpacking only; no test downloads anything. No real Tor, VPN or Internet traffic is used.

### Accepted host UI performance (0.6.2)

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
  resource-only collector described below, which only revision 11 to 16
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

Accepted design: Disks tab implementation design v2, phases 1 to 3 (the dumps are described after the limits below,
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

## MemNixFS beside Volatility (0.7.1)

MemNixFS 1.2 (<https://github.com/MemNixFS/MemNixFS>, Apache-2.0) is a second
backend of the Memory tab for Linux dumps. `memory/memnixfs/` holds it;
`PluginRun` gains `analyzer` (omitted for Volatility, so saved runs read as
before), `tool_version`, `dump_format` and `partial` (reasons a finished
result is known to miss something). A report run is saved as a plugin run
(`run.json`, `output.jsonl`, `log.txt`, `files/`) under the dump's `runs/`, so
the table, filters, Messages, Files and run list work unchanged, and the run
names the dump by `dump_id` (the dump file is never copied or altered).

**Package.** `analysis_tools::PACKAGES` pins the upstream
`MemNixFS-1.2-Linux.tar.gz` release asset by SHA-256 (the Linux build is
dynamic and links the system's libyara, libsnappy, liblzma, libmagic, jansson
and libcrypto). It also needs `libfmt.so.9` and `libfuse3.so.3`, which newer
distributions no longer ship; those two libraries come from the pinned Debian
12 `libfmt9` and `libfuse3-3` packages into `lib/` beside the tool and are
found through `LD_LIBRARY_PATH`. Only Antinomie's pinned install is used (no
system copy). `MemNixFs::locate` runs `--help` once and turns a loader error
into the Debian package that fixes it.

**What it is given.** `format::classify` reads the header only. AVML, LiME,
raw (headerless: the run is marked partial because addresses are assumed to
start at 0) and ELF64 x86-64 cores whose segments carry physical addresses or a
`QEMU` or `VMCOREINFO` note are accepted; a core whose segments all have a zero
physical address is a process core and is refused, as are Windows dumps, ELF
programs, other architectures, unfinished dumps and a dump file that is gone.

**Sandbox.** The shared bubblewrap profile of the other tools
(`run_sandboxed_sized`): no network, the dump and the saved
`symbols/linux/symbols.json.xz` mounted read-only, the managed tools folder
read-only, a private writable folder, `HOME=/tmp`, `--no-http-cache` (no symbol
mirror lookup; `--auto-fetch` is never passed), `prlimit` with an address space
of the dump size plus 6 GiB (at least 8 GiB), 45 minutes at most. A report is
one `memnixfs export PATH DIR`; the dump is read once per run.

**Partial and unavailable.** Stated, not hidden: known warnings of the tool
(unvalidated page-table root, symbol table not matching the banner, unreadable
modules list or mount namespaces) and up to four other `[WRN]` lines become
`partial` notes, with one for a dump without a saved symbol table (the tool
rebuilds one from the kernel's BTF), one for a headerless dump and one for rows
cut at 500,000. A report the tool did not write fails the run with a message
saying so; an error line of the tool becomes the run's error.

**False banner mismatch.** MemNixFS takes a table's kernel release from the
dwarf2json metadata name or the file name (`vmlinux`, `symbols.json.xz`), not
from `linux_banner`, so it logs `ISF/dump MISMATCH` for every base table even
though the offsets are right. When the log has that line, `memnixfs/banner.rs`
reads `linux_banner` from the table (xz JSON, base64 `constant_data`) and
searches the dump for that exact text; if it is there, the note is dropped. An
unreadable table or a different banner keeps the note.

**Check.** `cargo run --release --example memnixfs-check DATA RECORDING DUMP
[SYMBOLS.xz] REPORT...` runs reports on a real dump. On a 2.0 GiB QEMU dump
with the base's dwarf2json table (5 PT_LOAD ranges, no VMCOREINFO) it produced
92 processes, 23 triage lines, the memory ranges and 22 recovered files in 50
to 135 s, with partial notes (the DTB scan found no match; the table names
its kernel `vmlinux`, so the tool reports a banner mismatch that the host
then checks against the table's own banner); processes and
page-cache files were still recovered. Unit tests use a fake `memnixfs`
script and generated headers; no dump is stored in the repository.

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
disk. When the recording writer falls behind, it stops taking telemetry
instead (the guest waits for room; trace follow-ups, 0.7.0). Run, Upload, Stop and snapshots are answered while a recording saturates
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
0.7.0 adds firmware, disk bus, SMT, pointer, clock, NAT and smaller entries:
see "Stealth profile, part 2" below.
The profile is validated before a VM is created, saved or launched: MAC
addresses are six hex pairs and not multicast, identity strings have no
control characters and are at most 64 bytes, ACPI IDs fit their 6 and 8
bytes, and the UUID is in 8-4-4-4-12 form.

**What a profile cannot change.** The fw_cfg device and QEMU's ACPI table
creator ID, the q35 chipset layout and its devices' Red Hat subsystem IDs,
the emulated display and VM-exit timing are outside launch options; the
Stealth profile window and the Summary list them under "Still visible". The
guest kernel's own traces are handled in the guest (see "Guest stealth"
below). A snapshot taken with other hardware may not restore after the
profile changes.

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
image gives the root filesystem a label (nothing mounts it by label; Debian
Minimal mounts it by UUID).

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
* *The emulated display.* Bochs (`bochs-drm`, 1234:1111) or virtio-gpu. The
  disk and the NAT addresses are profile entries since part 2 (below).
* *A fresh boot.* Uptime is seconds to minutes; the VM's CPU count, memory
  and disk size are its settings (pafish flags under 2 CPUs, 2 GiB, 60 GiB).
* *Environment.* A run gets exactly the environment the user set (by default
  `PATH` and `TERM`), not a login shell's `HOME`, `USER`, `SHELL`, `PWD`.
* *Older bases* keep their command line, build string, symbols, worker names
  and `QEMU0002` until rebuilt, and are launched with kthreadd as parent.

## Stealth profile, part 2 (0.7.0)

Guest series 0052, contract revision 17 unchanged. New profile entries
(`monitor-core/src/stealth.rs`; launch options in `stealth/launch.rs`, SMBIOS
tables in `stealth/smbios.rs`, OVMF discovery in `stealth/firmware.rs`, NAT
addresses in `stealth/nat.rs`). Each adds a launch option only when it
differs from QEMU's default, and a profile saved without it reads as that
default, so earlier VMs launch exactly as before.

| Entry | QEMU option | Transparent | Realistic |
| --- | --- | --- | --- |
| Firmware | BIOS: none. UEFI: `-drive if=pflash,unit=0,readonly=on,file=<OVMF code>`, `-drive if=pflash,unit=1,file=<the VM's variable store>`; Secure Boot adds `-machine smm=on`, `-global driver=cfi.pflash01,property=secure,value=on` | SeaBIOS | UEFI (OVMF, no Secure Boot) |
| Disk bus | virtio: `-drive if=virtio` as before. SATA: `-drive if=none,id=osdisk` and `-device ide-hd,bus=ide.0,model=,serial=,ver=,wwn=,rotation_rate=1\|7200`. NVMe: `-device nvme,serial=,use-intel-id=on` | virtio | SATA SSD `Samsung SSD 870 EVO 500GB`, firmware `SVT02B6Q`, a random Samsung NAA WWN |
| CD-ROM | `-device ide-cd,bus=ide.1` (empty) | none | none |
| SMT | `-smp N,sockets=1,cores=N/2,threads=2`, `+topoext` on AMD hosts | `-smp N` | Two threads per core |
| Pointer | `virtio-tablet-pci`, `usb-tablet` or none (the PS/2 mouse) | virtio tablet | virtio tablet |
| SMBIOS type 11 | `-smbios type=11,value=…` | none | The machine's OEM strings (Dell `Dell System`, `1[0A61]`…, HP `FBYTE#…`, Lenovo, Supermicro) |
| SMBIOS entry point | `-machine smbios-entry-point-type=64\|32` (with an identity) | QEMU's | 64-bit |
| Named CPU model | `-cpu <model>,model-id=<brand>[,legacy-cache=off,l3-cache=on]` without passthrough | the VM's CPU setting | passthrough (unchanged) |
| kvm-clock | `-cpu …,-kvmclock` while the KVM signature is shown | on | hidden with the signature |
| SMM | `-machine smm=off` | on | on |
| RTC | `-rtc base=localtime,clock=vm,driftfix=slew` (each when chosen) | UTC, host clock | UTC, host clock |
| NIC subsystem | `-device e1000e,subsys_ven=,subsys=` | Intel's | The machine maker's (Dell 1028:0a61, HP 103c:…, Lenovo 17aa:3179, Supermicro 15d9:…) |
| NAT network | `-netdev user,net=,host=,dns=,dhcpstart=` | 10.0.2.0/24 | 192.168.1.0/24, gateway .1, DNS .10, DHCP from .100 |

**Fitting to the base and the host.** Some entries need the base or the host.
A base says what it boots with in `bundle.json` `stealth_support` (advisory,
not part of the identity), which the image builders compute:

| Value | Written when |
| --- | --- |
| `uefi` | The kernel has `EFI` and `EFI_STUB` and its bzImage holds the EFI stub's bootstrap page claim (0052, found by its warning text) |
| `sata`, `nvme` | The initrd searches that bus for the root disk and the kernel has `ATA SATA_AHCI SCSI BLK_DEV_SD`, or `BLK_DEV_NVME`, built in (BusyBox and Debian Minimal bases; the minimal kernel profile now builds NVMe in) |
| `dhcp` | The guest takes its address from DHCP (BusyBox bases now; Debian desktop bases through NetworkManager, Debian Minimal through ifupdown and dhcpcd) |

The host offers OVMF when QEMU's firmware descriptors (the user's and
`/etc/qemu/firmware`, then `share/qemu/firmware` of the QEMU in use and
`/usr/share/qemu/firmware`, by file name, as QEMU and libvirt read them) name
a UEFI x86_64 q35 flash image with a raw variable store, with Microsoft's
keys enrolled for Secure Boot; each VM copies the store once
(`efi-vars.fd`, `efi-vars-secure-boot.fd` in its folder). SMT is offered on
Intel hosts and on AMD hosts whose CPU has TOPOEXT (without it QEMU warns that
the CPU has no hyperthreading; with `+topoext` the guest sees `thread_siblings
0-1`). `StealthProfile::fitted()` turns an entry the base or host lacks into
BIOS, virtio, 10.0.2.0/24 or one thread per core at launch (`fallbacks()` lists
each as a `Fallback`: setting, one summary line, reason); the Stealth profile
window shows such choices disabled with the reason, puts the summary on the
setting and at its top, and lists the fallbacks under "Still visible". The VM
list and the Summary card carry a badge, the launch keeps the lines in
`VmProcess::stealth_fallbacks` (the snapshot's `stealth_fallbacks`, warned once
in Activity, and a note on each run of the boot). A Debian base keeps virtio: its kernel
builds AHCI and NVMe as modules and its root is `/dev/vda` (APPEND, fstab);
the Debian kernel was not rebuilt here.

**UEFI and the bootstrap page (0052).** Under OVMF the kernel's EFI stub
decompresses and places the kernel itself, with KASLR at a random 2 MiB slot
among the firmware's free memory, and the host's bootstrap page is free
memory to the firmware. When the kernel landed on it, the host read the
kernel's bytes as the boot block and failed (`Protocol error`). The stub now
reads `antinomie_boot_gpa=` as the decompressor does (the last valid one
counts) and allocates that page as loader data at its address before the
kernel, the initrd and the boot data are placed; after `exit_boot()` it is
ordinary RAM and `ant_bootstrap_reserve()` takes it from memblock as before.
Measured: with `nokaslr` OVMF places the kernel at 0x1800000; with the page at
0x2000000 the old kernel failed 3 of 3 boots, the new one moved to 0x2200000
and passed 3 of 3. With KASLR and the default page: 32 of 32 UEFI boots and 6
of 6 Secure Boot boots brought the transport up, each at a different
physical address, plus 6 and 3 on the final base, and `/sys/firmware/efi`
exists in the guest.

**Secure Boot.** OVMF with Microsoft's keys rejects the unsigned kernel
("Secure boot image verification failed") and then starts it with its legacy
Linux loader ("insecure and deprecated"); the stub reports Secure Boot
enabled and the kernel logs `secureboot: Secure boot enabled`. A later OVMF
build without that fallback would refuse the boot; the kernel would then need
a shim.

**The base.** The BusyBox initrd mounts the first of `/dev/vda`, `/dev/sda`
and `/dev/nvme0n1`; init runs `udhcpc` with its own script (address, route,
`resolv.conf`). An isolated VM's NAT (`restrict=on`) answers DHCP without a
router or DNS server; the DHCP server's address then takes both roles, so a
program's lookups still leave the VM and are captured (they get no answer, as
before). The host-side capture, DNS and HTTP decoding and Triage do not assume
10.0.2.x (Triage treats every private address as the local network, which is
why a NAT network must be private). An older host ignores `stealth_support`
and the new base boots from virtio under SeaBIOS and gets 10.0.2.15 from the
NAT's DHCP server; a new host fits a profile to an older base's empty list.

**Disk size.** The disk's size is the VM's; a BusyBox base grows its
filesystem to it on the first boot. A 256 GiB disk took about 400 MiB of
image (virtio 398 MiB, SATA 411 MiB) and nearly two minutes of online
resizing. The VM dialog's fields and the Stealth window show what a real
machine has (pafish flags fewer than 2 CPUs, under 4 GiB RAM, under 60 GiB of
disk).

**What remains.** QEMU's CD-ROM answers the SCSI inquiry with `QEMU
DVD-ROM` whatever its model (so the presets leave it out); its NVMe
controller is `QEMU NVMe Ctrl` with QEMU's version as firmware and an
`nqn.2019-08.org.qemu:` subsystem name (QEMU prefixes any name it is given);
OVMF's firmware vendor (`EFI v2.7 by Debian distribution of EDK II`, root's
kernel log) and its BGRT table (OEM `INTEL`/`EDK2`, root); the ACPI creator
ID `BXPC` and fw_cfg (already listed); the chipset devices' Red Hat subsystem
IDs (only e1000e takes a subsystem); the display. efivarfs is not mounted in
the BusyBox base (its kernel builds it as a module), so OVMF's boot entries,
which name QEMU's devices, are not readable there. The RTC stays UTC by
default: Linux guests read it as UTC.

**Before → after**, with the new probe (`examples/stealth-check.rs`, which
gains `firmware=`, `disk=`, `nat=`, `cdrom=`, `smt=` and `gpa=` entries and a
`boots` mode), Realistic desktop on a BusyBox base: before is the 0.7.0 app
and base before this work, after is this app and base.

| Check | Before | After |
| --- | --- | --- |
| `firmware.type` | fail: BIOS, no `/sys/firmware/efi` | pass: UEFI |
| `firmware.vendor` (root) | (BIOS) | fail: `Debian distribution of EDK II` |
| `smbios.oem-strings` (root) | fail: no type 11 | pass: 2 strings |
| `acpi.oem-ids` (root) | pass | fail: OVMF's BGRT `INTEL`/`EDK2` |
| `virtio.devices`, `block.devices`, `base.root-device` | fail: `vda`, vendor 0x1af4 | pass: `sda`, `ATA Samsung SSD 870`, rev `2B6Q`, non-rotational, WWN `naa.5002538e…` |
| `net.addresses` | fail: 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3 | pass: 192.168.1.100, gateway and DNS 192.168.1.1 (isolated) |
| `pci.vendors` | fail: Bochs 1234:1111, virtio 1af4:1001 | fail: Bochs 1234:1111 |
| `pci.subsystems` | fail: 10 of 11 Red Hat; e1000e 8086 | fail: 9 of 10 Red Hat; e1000e 17aa (Lenovo) |
| `cpu.threads` | one thread per core | two threads per core |
| unchanged fails | `acpi.tables`, `fwcfg.ioport`, `dmesg.vm` (root); `block.disk-size`, `display.fb`, `iomem.names`, `base.uptime`, `base.memory`, `timing.rdtsc-cpuid` | the same |

Totals: 17 of 77 checks gave the VM away before, 13 of 80 after; in the view
of uid 1000, 13 before and 8 after (the display, the chipset's subsystem IDs,
the measurement VM's 8 GiB disk and 2 GiB RAM, uptime and VM-exit timing).
With NVMe, `block.devices` and `block.nvme` fail on the controller's model;
with the CD-ROM, `scsi.models` fails on `QEMU DVD-ROM`.

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

## Accepted run triage (0.6.2)

A later change reorganizes triage presentation around section navigation,
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

A later change extends these host-only views with exact operation-time executable
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
(`saddr`). The trace has no audit keys, so a rule that needs one is reported
as not evaluated; user and group ids, capability sets, file identity (device and
inode) and hashes are recorded from 0.7.0 on and fill the matching fields where
the base is new enough, and are absent for an older base or recording. An event's `_inferred` list (event journal format 2; format 1
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

A later change supersedes the inline lower-pane presentation: every triage entry's
single-click information belongs in the existing shared Details dock panel.
Include suspicious activity, process tree, Opened/Read/Changed files, IPs/Hosts/
HTTP/DNS and BPF decoding/export. Remove row-content hover popups and duplicate
inline inspectors; preserve filter context menus and double-click exact evidence
navigation. Details follows Triage using the existing active/split/detached
panel rules. Changing run/VM clears selection and pending evidence jumps.

## Accepted aligned VM status cards (0.6.1)

The visual clarification requires equal-height VM Status resource
cards within each responsive row. Render the contents once, measure that row's
tallest card and extend all of its frame backgrounds to the shared height in
the same frame. Apply this to guest pairs and host pairs/triples; single-column
cards retain natural height. Width/data/font changes must not depend on a stale
height cache or clip wrapped notes. Measurements and monitoring stay unchanged.

## Accepted upload/picker and collector follow-up (0.6.1)

The latest user clarification supersedes the dialog-tree and immediate-send
portions of the earlier upload browser: keep the sidebar Explorer tree, fill its pane width,
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

## Historical accepted upload browser and Run handoff (0.6.1)

User authorized a new release-0.6.1 branch and an Upload file workflow that
chooses a host folder through the filesystem explorer, displays its expandable
filesystem tree and selects a file to upload. Keep manual path entry and plain
Upload. Upload and Run makes the uploaded file executable and, only after the
matching successful upload in the same VM session, opens the editable Run program
window with its guest path. It never executes without the user's Run action.
Overwrite confirmation retains the chosen action; closing cancels the handoff
without claiming to cancel a guest write already submitted. Reuse the existing
single-file guest protocol and 0.6.0 bases; no guest/image/transport changes.

The accepted clarification adds a persistent Explorer section below
Base images. Choose its host root independently of the Upload dialog; double-click
a regular file or use right-click Send and Run to submit the existing upload and
success-only Run dialog handoff. Right-click Open Directory opens the containing
host folder (the folder itself for directory entries). Stopped/wrongly selected
VMs and pending uploads cannot admit another send. Folded bases never hide Explorer.

## Accepted resource observations and UI repairs (0.6.1)

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

## Accepted tab dragging and docking feedback (0.6.1)

The user reports unclear/nonworking tab movement and requests the expected
drag shadow. Preserve the native dock tree and saved arrangements. Drag tab
labels directly, show a bounded shadowed title and explicit docking action,
and use one resolver for the highlighted destination and the committed drop.
Pane edges split, centers join, and visible tab headers allow insertion/reorder
with source-index removal accounted for. Show grab/grabbing cursors, focus moved
tabs and update the corresponding Details context on a committed drop. Escape
and missing-release cancellation must not silently detach or move a tab; a lone
tab cannot promise a split into an empty source group. No guest/backend changes.

## Accepted manual cores and performance Summary (0.6.0)

User authorized a real Dump core action beside Dump memory and inside Core dumps,
choosing pause/capture/resume of a selected live process. Use validated guest
boot/task/start/TGID identity, a nonfatal bounded guest rendezvous and native ELF
notes, with truthful unavailable memory and independent repeated host captures.
Do not use the exit-core rendezvous, kill the target, replay uncertain acquisition
or add a guest helper. The revision-16 extension retains ABI9 and ordinary
revision-15 exit captures; the manual-core section defines its accepted wire and lifecycle.

Summary uses native performance charts/meters with measured QEMU/host values,
per-VM identity, bounded sample history and explicit unknown states. Guest RAM
utilization remains unavailable. Run program gains title dragging while preserving
its initial viewport-limited size and final actions. Other debugger features and
release/base publication remain separate.

## Accepted process core and VM Summary update (0.6.0)

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

## Accepted host evidence update (0.5.0)

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
0.5.0 bases are reused.

## Ownership

### Accepted 0.3.0 update

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
Product commits and binaries stay local until the user's testing;
documentation publication is independent of that product-release decision.

### Accepted static-analysis results update

User authorized the native static-analysis workspace redesign on 2026-10-08.
One workspace is the default; selecting a category updates local results and
separate dockable section panes open only on explicit request. Typed available
evidence drives searchable/sortable tables, selected details and bounded read-only
specimen previews. Legacy generic reports remain readable. Acquisition, launch
scope, engine availability, guest controls and V7 remain unchanged. No new analyzer
dependency or guest image build is needed. The revision-1 result contract is
this update. Development
and the rebuilt executable stay in feature/static-analysis pending integration.

### Accepted static-analysis launch update

User authorized complete static-analysis acquisition/backend and launch setup
on 2026-10-08. Run Program opens launch fields left, opt-in analysis checkboxes
right and a final Run button. Initial executable only; no descendant/later exec
static acquisition. Triage plus optional deep analysis, local/no network default,
exact initial guest exec-file acquisition with bounded wait, failure continues
execution and reports unavailable. Retained reports reopen without rescanning.
Application control revision
10 adds optional specimen controls; V7 remains unchanged, revision-9 guests
still launch with explicit analysis unavailable. Resource/isolation/compatibility
limits and engine gaps must be recorded, not presented as complete clean scans.
Development is isolated in feature/static-analysis; preserve concurrent dirty
image-builder work and do not replace the normal executable before integration.

### Accepted display settings update

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
arguments. Revision 3 of the contract is this update.

### Accepted Debian Xfce fidelity update

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
bundles, VM disks and recordings are untouched.

### Accepted guest cursor update

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
change.

### Accepted guest pointer update

User reported the guest mouse pointer stuck at the display center: clicks reached
the guest but motion did not move the cursor. Cause is the QEMU GTK relative
pointer grab; the launch attached only the emulated PS/2 mouse. User approved
attaching an absolute pointing device to all non-headless launches. Use
`-device virtio-tablet-pci` (a self-contained PCI device requiring no USB
controller) so the host pointer is tracked directly and never grabbed. The
existing guest kernel already binds `CONFIG_VIRTIO_INPUT`, so this is a
launch-argument change only: no kernel, transport, bundle or user-disk change.
Headless launches are unaffected.

### Debian Minimal base (0.7.1)

A third buildable base beside BusyBox and the Debian desktops: console-only
Debian 13 (profile `debian-minimal`, guest id `debian-minimal`, label
`Debian 13 (Minimal)`, 1024 MiB / 4 GiB minima, `requires_credentials` as on
the desktop bases, `graphical: false` so the VM behaves like BusyBox: QEMU's
default VGA console, no `-vga virtio`, no Run in desktop choices, Stop's configured
timeout without the desktops' 30 s floor). The same recipe builds it
(`build-debian-image.py` with the installer answer `desktop: "none"`, which
`build-base.py` sets for the profile; the job offers every Debian answer but
the desktop): what the Debian installer leaves with no desktop chosen, the
standard task (mmdebstrap's `standard` variant, the default answer for this
base) with recommends (exim4 on 127.0.0.1:25 as the local MTA, as the
installer installs it; timesyncd; the ispell dictionaries), the installer's own
additions in `CONSOLE_PACKAGES` (tasksel, installation-report, discover,
laptop-detect, eject, initramfs-tools, console-setup, sudo) and tasksel's
language task for the locale (`task-english` for English), documentation and
manual pages, the package indexes and apt's caches kept; no curl and no
systemd-resolved. Networking is the installer's: ifupdown with dhcpcd. The
base's `/etc/network/interfaces` has only the loopback (`CONSOLE_INTERFACES`); its
`stealth_support` adds `onboardnic`, and the app puts the NIC at a fixed PCI
slot of the profile's machine and writes the installer's `allow-hotplug`
stanza for the name udev gives it there. `StealthProfile::nic_slot` takes the
slot from the machine the identity copies (`MachineProfile::nic_slot`): Intel
100-series and later chipsets (OptiPlex 7090, EliteDesk 800 G6, Latitude 5420,
X12STH-F) have their I219 at 00:1f.6, `enp0s31f6` (`NicSlot::Pch`; q35's LPC
bridge at 00:1f.0 is multifunction, so function 6 is free); profiles without
an identity (Transparent), with an edited one, or copying an AMD machine (no
integrated LAN on bus 0, and a root port would be QEMU's Red Hat one) keep
00:19.0, `enp0s25`, the ICH9's place (`NicSlot::Ich`). `nic_option_for` adds
the address whatever the model, so the name does not depend on which display
or pointer devices take the first free slots (headless or not). Provisioning
writes the stanza (`interface_commands`: everything from the installer's
`# The primary network interface` comment on is replaced) and the account
record keeps the interface (`GuestAccount::interface`; a record from before
0.7.1 means `enp0s25`, which such a base wrote at build time); the launch puts
the NIC at that interface's slot, so a disk and its NIC always agree, and
both the user-mode network and the Routed gateway's `-device` use it. Saving
a profile whose slot differs rewrites the stanza on the VM's disk
(`set_interface`, VM stopped); with snapshots that is refused, since their
disks name the old interface. A reset writes the current profile's.
`/etc/resolv.conf` is a plain file dhcpcd rewrites from the lease. Packages
configured during the build that recorded
the build host's name (exim4's mail name) get the chosen hostname, and the
leak check also fails on the build host's name. `multi-user.target`,
`/tmp` on the root disk (a `tmp.mount` drop-in, unlike Debian 13's default tmpfs: dropped files reach the VM's disk, and the
conformance cases and goldens, which expect BusyBox's on-disk `/tmp`, pass
unchanged), a 4 GiB disk. Its root is found without naming a device: fstab
mounts `UUID=<root uuid>` (a fresh UUID per bootstrap, given to `mkfs.ext4
-U` and read back from a cached root filesystem's fstab; the build checks
fstab and the filesystem agree), and `kernel_append` names it the way GRUB
does (`root=UUID=`, below). A UUID,
not a label, because a Debian install mounts by UUID and a fixed label would
name the sandbox to a sample reading `/dev/disk/by-label`. Everything else
(account removal, masks for SSH and guest agents only where a package still
ships the unit, locked root, apt check, provenance, initrd) is the desktop
path; the desktops keep `/dev/vda` in fstab and `root=/dev/vda`.

Nothing in the image names Antinomie or the build host: the package inventory
is written to `/tmp` and leaves with the provenance, the network and tmpfiles
snippets and the desktops' display-manager snippets have stock-looking names,
systemd-resolved's backup of the resolv.conf it replaced (the build host's, as
mmdebstrap copied it) is removed, and the build fails (`check_image_leaks`) on
a path naming Antinomie, a `/dev/null` mask for a unit no package ships, or a
configuration or state file holding the build host's nameserver or search
domain (read from its `/etc/resolv.conf`; WSL's resolver and Tailscale
MagicDNS names always). Creating a VM provisions it offline with `guestfish`
(it was `virt-customize`): a read-only probe finds the one ext4 filesystem,
then the root filesystem gets a UUID of its own (`set-uuid` after `e2fsck -f`;
the account record keeps it as `root_uuid`), a directory hash seed of its own
(`debugfs ssv hash_seed random` and `e2fsck -fD` through `guestfish debug`,
best effort), fstab's `UUID=` root line follows, and the account is created as
before without a sudoers.d file (the `sudo` group already allows it). Reset
provisions again and records the new UUID.

The image carries the installation's own timeline. `mkfs.ext4 -d` takes only
modification times from the tarball (every change and access time was the
epoch, every birth time the moment of mkfs), so the last customize hook records
each path's access, change, birth and modification time with nanoseconds
(`find -printf`, stored as `inode-times` beside the tarball and in the root
filesystem cache), and `apply_timeline` writes them back with debugfs: changed
no earlier than modified (cleanup after the record touched some directories),
born no later than changed, accessed no earlier than born; a path added after
the record was born when the installation ended. The superblock follows an
installer's disk: created a minute or two before the first package (mkfs runs
under `E2FSPROGS_FAKE_TIME`), last mounted (once, at `/target`) just before it,
last written when the installation ended, and lifetime writes a little above
the space in use.

Its configuration files are the installer's: apt-setup's `sources.list` (the
netinst image's commented `cdrom` line named after the point release, `main
non-free-firmware`, `deb-src`, the updates comment block, the removable-media
note) with the indexes it lists fetched; fstab's commented header,
`errors=remount-ro` and the `/dev/sr0` line (`/media/cdrom0` and the `cdrom`
link exist); `/etc/hosts` with the IPv6 comment; locale, keyboard and time
zone answered through debconf (`locale.gen` the full commented list,
`default_environment_locale` set, no `/etc/timezone`); `/etc/adjtime` UTC;
D-Bus's `machine-id` link; `tasksel/first` and popcon answers; the
installation's dpkg, alternatives and apt logs (`--skip=cleanup/reproducible`).
`/tmp` stays on the root disk through a `tmp.mount.d/override.conf` condition
(`ConditionPathIsMountPoint=/tmp`), not a mask. Its command line is GRUB's:
`BOOT_IMAGE=/boot/vmlinuz-<release> root=UUID=<uuid> ro quiet` (no serial
console, no `panic=-1`); the app replaces the UUID with the one provisioning
gave the VM's disk (`vm_kernel_append`, from the account record), and the
bootstrap initrd finds it with `findfs` on any bus (falling back to the first
disk for a disk from before), mounts it, grows it, and remounts it read-only
for the boot's fsck. The conformance harness still waits for the login prompt
on the serial port: its VMs ask for a serial console
(`BackendOptions::serial_console` appends `console=tty0 console=ttyS0` to a
command line that names none; the app never sets it), since a readiness probe
run would break the suite's whole-boot packet accounting. Provisioning creates the account as the installer's
adduser does (full name `<Name>,,,`, the installer's groups where they exist,
a 0700 home) and writes a machine ID of the VM's own. The guest hashes the
password itself: provisioning runs the guest's `chpasswd` (through PAM, as
`passwd` does, so Debian 13 stores yescrypt `$y$`) with the password in a
here-document of the guestfish `sh` command, never in a file on the disk or a
command line, and the command prints the hash the guest stored
(`password_commands`, `printed_hash`). The record keeps that hash; a reset sets
it again with `chpasswd -e` and checks the guest kept it. Records written
before 0.7.1 keep their host-made SHA-512 hashes (`validate_hash` takes both).
The host needs no crypt of its own, only `guestfish` (App dependencies:
`libguestfs-tools` on Debian, Ubuntu and Kali, `libguestfs` on Fedora,
openSUSE and Arch).

The disk and kernel are an installed PC's. The base disk carries an MBR table
with one bootable root partition at 1 MiB (`console_disk`; mkfs and every
debugfs pass work at that offset, `CONSOLE_ROOT_SIZE` 3 GiB of the 4 GiB
disk). Provisioning lays the VM's disk out as partman does
(`partition_plan`): the root grown to a MiB before the swap partition, `sda5`
in an extended `sda2` starting two sectors before it, about the VM's RAM (256
MiB at least, a quarter of the disk at most), the last MiB free; the swap gets
a UUID, fstab its line and `initramfs-tools/conf.d/resume` its UUID, the MBR a
disk identifier of the VM's own (set last, after unmounting: sfdisk makes
the kernel read the table again and the partition nodes vanish for a moment), and `update-grub` writes `grub.cfg` for the
VM's UUIDs. Growing the disk in the VM's settings grows the root the same way
(`grow_disk`, keeping the swap's UUID and size); the bootstrap initrd grows only
whole-disk roots (BusyBox, the desktops) now. The kernel packages are
Debian's own (`debian_kernel_debs`): `linux-image-6.12.94+deb13-amd64` and
`linux-image-amd64` 6.12.94-1 exactly as linux-signed-amd64 6.12.94+1 shipped
them to trixie-security, taken from snapshot.debian.org
(`DEBIAN_KERNEL_ARCHIVE`, the day they were published). The archive's
`InRelease` must verify against the Debian archive keyring (`gpgv`, else
`sqv`), `main/binary-amd64/Packages.xz` must match its SHA-256 there, and each
`.deb` the index entry and the SHA-256 pinned in `DEBIAN_KERNEL_PACKAGES`.
build-base.py keeps them in its inputs directory (`--kernel-package-cache`);
a copy there that matches its pin is used without the network, and the root
filesystem cache knows them by the pins, so a cached root needs neither. They
are installed before the rest of the customization (apt brings apparmor by
recommends) and their maintainer scripts run as on an install (depmod,
`linux-update-symlinks` for `/vmlinuz` and `/initrd.img`, initramfs-tools
building `/boot/initrd.img-*` from Debian's modules); GRUB (`grub-pc`,
`os-prober`) is installed as the installer installs it. So `/boot` holds
Debian's signed image (0644), configuration and `System.map`, and
`/usr/lib/modules/6.12.94+deb13-amd64` Debian's module tree; the build fails
unless `dpkg --verify` reports nothing for both packages. QEMU boots the
Antinomie kernel directly (`-kernel`), so the guest never holds it. The
Antinomie kernel reports the same release, and its own few modules
(`modules_archive`) go to that tree's `updates/`. depmod then runs once more
with Debian's `kernel/` excluded (`-C` with `search updates` and `exclude
kernel`, so no depmod.d file stays in the image), and the build checks that
`modules.dep` names only `updates/`: the Antinomie kernel refuses Debian's
modules (their `struct module` differs; "Exec format error" and a kernel log
error each), so an index of them would have udev, systemd and the kernel's
own module requests try two dozen at every boot, and depmod would make ours
depend on Debian's (`x_tables`). A Debian module is therefore "not found" for
modprobe, as a module the kernel lacks was before. The initramfs Debian's
postinst built from all of Debian's modules stays; an `update-initramfs` in
the guest builds a smaller one from the index. apt may install the image from
the trixie mirror rather than the verified copy when the mirror carries the
same version: the archive serves one file per version (the same SHA-256).

The minimal kernel profile, shared with BusyBox, takes Debian 13's
configuration where a program sees it (`DEBIAN_SHAPE`): Debian's LSM order with
AppArmor the active major LSM, lockdown (none), landlock, TOMOYO, BPF, IPE, IMA
and EVM; the memory controller and cgroup BPF; HZ 250; 8192 CPUs (MAXSMP);
perf_event_paranoid 3 (Debian's patch); efivarfs, FUSE, nftables and fq_codel
built in; scheduler autogroup and Debian's hardening defaults; no 9p, no
netconsole, no cgroup debug controller, no legacy TIOCSTI. The release is
Debian's (`6.12.94+deb13-amd64`), it is compiled with
`x86_64-linux-gnu-gcc-14` where the host has it (Debian's compiler and the
string `/proc/version` shows), and the few modular options are built and
installed so the base has a module tree.

Its kernel is the **minimal** profile, the BusyBox kernel: it builds in every
driver and systemd prerequisite the console base uses (`CONSOLE_BUILTIN` is
checked when no modules are given), so the base carries no modules and a
cached BusyBox kernel serves it (`kit::kernel_cache(.., "minimal")`). The
recipe accepts a modular kernel without `--modules` only for this base and
only when `CONSOLE_BUILTIN` is built in. `stealth_support` is decided by the
kernel as for BusyBox (`root_buses` only for this base): the minimal kernel
builds `ATA SATA_AHCI SCSI BLK_DEV_SD` and `BLK_DEV_NVME` in, so the base
offers `uefi, sata, nvme, dhcp`; the desktops, whose controllers are Debian
modules, stay `uefi, dhcp`. The root filesystem cache
is `images/rootfs-debian-minimal.tar`.

Rootless builds: mmdebstrap's hooks run as the user namespace's root, a
subordinate UID that cannot read or write the invoking user's mode-0700
staging directory, so files cross through mmdebstrap's `upload` and
`download` special hooks (run as the invoking user), and the staging directory
is made traversable (0711) in unshare mode. Builds before this ran only in the
QEMU builder (`--mode=root`).

### Accepted Debian Xfce VM base update

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
and duplicate; no plaintext retained. The hash is the one the guest's own
chpasswd made at creation. Reset reapplies original credentials and
publishes replacement disk only after provisioning succeeds. Existing VMs are
not automatically converted or modified.

Image build uses authenticated Debian inputs and retains system account file
ownership, package provenance and licenses. This
does not complete the remaining syscall/async semantics of the native syscalls update below.

### Accepted full native syscalls and dockable workspace update

The user approved these changes on 2026-10-06. Earlier 30-syscall requirements remain historical,
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

### Accepted native terminal windows update

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

Core and UI freeze public run-addressed types before dependent rendering.
Core owns archive validation/paging and headless terminal persistence; UI uses
owned API values and performs offline disk reads outside the rendering thread.
Existing `vt100 0.15` may be used by core without adding a new external package.
`rusqlite 0.40.2` is approved for bounded disk-backed archive indexing; SQLite
is linked from the system and required upstream notices are retained.
Run/session maps, previews, pages and queues remain bounded; new recording
payloads count against the recording quota and preserve explicit failures.

- Guest: kernel patch series under src/antinomie/core, new guest
  protocol header src/antinomie/monitor/protocol/control.h, guest source manifest.
- Host: src/antinomie/monitor/crates/monitor-core only, public backend API.
- UI: src/antinomie/monitor/crates/monitor-ui only, depends on monitor-core.
- Workspace level: Cargo.toml, build/test/rootfs scripts, integration and patch
  exports.
- No wholesale refactor of transport.

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

The guest side establishes protocol/control.h promptly and tells the host side
when ready. Opcodes: 0x1001 upload begin, 0x1002 upload chunk, 0x1003 commit,
0x1004 abort, 0x1010 exec, 0x1011 terminal input, 0x1012 terminal read,
0x1013 terminal resize, 0x1014 signal, 0x1020 recorder stats,
0x1030 shutdown. Explicit little-endian fields, versioned, checked lengths;
results travel in the existing reply queue. Each reply matches request ID.
Persistent health/loss counters queryable even after telemetry loss.

Rust backend runs blocking ant_init/poll/read on one owner thread. It exposes
owned commands and bounded UI snapshots, handles reply matching and telemetry,
and keeps collection/persistence independent of frontend frame rate. Shared
public API types should be established early by the host side for the UI.

## Verification

Build Rust workspace and kernel. Four-core QEMU integration: bootstrap attach,
upload static test program/shell script, launch with UID/cwd/env, terminal I/O,
entry/exit + buffer bytes, descendant execution, invalid pointers, telemetry
overflow, disk persistence/reset and graceful/forced shutdown. Include CPU/RAM
variants if feasible. Use actual measured results and record unavailable tests.

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
