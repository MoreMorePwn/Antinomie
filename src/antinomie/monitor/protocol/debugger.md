# Debugger (guest revision 17)

A ptrace-free, process-scoped debug engine in the guest kernel, driven over the
V7 control channel and exposed to the outside as a GDB Remote Serial Protocol
(RSP) server on the host. Nothing runs inside the guest: no gdbserver, no agent,
no `PTRACE_ATTACH`. The sample's `TracerPid` stays 0 and its own
`PTRACE_TRACEME` still succeeds, because the engine never touches ptrace state.
Opcodes `0x1080..0x1092` and their layouts are in `control.h`; this file records
the semantics and the limits. The revision number is unchanged (17): the
opcodes are additive and an older guest answers `-EOPNOTSUPP`, which the host
reports as "this guest has no debugger". Phase 3 (following forks and execs,
non-stop threads, adoptable sessions) is additive on top of phase 2 in the same
way: an earlier host never asks for any of it and gets the earlier replies; an
earlier guest refuses the new requests and the host offers nothing that needs
them (`CAPS` with the extension flag reports the second capability word).

## Multi-architecture by construction

| Piece | Where | x86-64 today |
| --- | --- | --- |
| Architecture tag on the wire | `CAPS` and `ATTACH` carry the ELF `e_machine` | 62 |
| Registers as regset blobs tagged with their ELF note type | `REGS_READ/WRITE` | `NT_PRSTATUS` (1, `user_regs_struct`), `NT_PRFPREG` (2, FXSAVE), `NT_X86_XSTATE` (0x202) |
| Capability handshake | `CAPS` | software breakpoint lengths (mask), hardware breakpoint and watchpoint counts (4, one pool) and watch lengths (1, 2, 4, 8), hardware single-step, shadowed reads, multi-thread, signals, batched registers, Debug on start, auxiliary vector |
| Shared engine | `kernel/antinomie/debug.c` | threads, stop and resume, memory, breakpoint table, wire format |
| Per-architecture file | `kernel/antinomie/debug_x86.c` | breakpoint instruction, trap recognition, single-step arming, the regset list |
| Host trait | `DebugBackend` (`crates/monitor-core/src/debug/target.rs`) | implemented by `KernelDebugBackend`; a QEMU-gdbstub backend would implement the same trait |
| Register views | `TargetDescription` (`debug/regs.rs`, `debug/amd64.rs`) | one table gives the GDB `g` image, the target description XML and any UI register view |

The generic engine reads and writes registers through the kernel's own
`user_regset` view, so a second architecture needs its arch file and a
`TargetDescription`, not new opcodes.

## Engine

* **Stop** reuses the cooperative machinery of process-core capture (patch 0025):
  a `task_work` callback (`TWA_SIGNAL`) parks each thread at its next return to
  user mode, in a killable sleep, with its registers frozen in its `pt_regs`.
  All-stop: a breakpoint, step or exit stops the whole group. A thread that does
  not park within 3 s is reported (`last_error = -ETIMEDOUT`), the group is
  released, and the engine never claims a stop that did not happen.
* **Registers and memory** of a parked thread: `regset_get`/`regset->set` and
  `access_remote_vm(FOLL_FORCE)`; writes break copy-on-write like a debugger's
  poke.
* **Software breakpoints** (`INT3`) are written only while the group runs and
  removed at every stop, so memory read while stopped is always the sample's own
  bytes. The trap is taken by a die notifier, the instruction pointer is rewound,
  and the thread parks: the sample receives no `SIGTRAP`. While the group runs, a
  read of the sample's own memory through `/proc/self/mem` (or any
  `access_remote_vm` path) returns the original bytes. **A direct load from its
  own code still sees `0xCC`** (measured: 7 of 231 lines in the qualifier);
  hardware breakpoints (P2) are the stealth answer.
* **Single-step** sets `EFLAGS.TF` on the parked thread and hides it again in the
  trap: it never shows in registers, and a stepped `PUSHF` has the engine's TF
  removed from the stored word. `TIF_SINGLESTEP`, `TIF_FORCED_TF` and the debug
  registers are not used. Stepping a breakpoint's own instruction happens with
  the group stopped and the breakpoints out of memory (a repeated string
  instruction is stepped until the instruction pointer moves).
* **Threads** created while the group runs get a record when they are cloned
  (the clone hook) and, when hardware breakpoints are set, install them from their
  own context before their first user instruction; a thread the hook missed is
  adopted at its first breakpoint from preallocated records (no allocation in
  exception context), so a new thread is never handed a `SIGTRAP`.
* **Steps are one user instruction.** The trap flag does it for ordinary
  instructions. The trap flag alone would retire the next instruction after a
  system call (`SYSCALL` clears it and the return restores it) and one iteration of
  a string loop, so those two are special: a step that starts on `SYSCALL` or
  `INT 0x80` arms the `SYSCALL_EXIT_TRAP` work bit that ptrace's single step uses,
  and the engine's hook in `syscall_exit_work()` (taken before the `SIGTRAP`
  report) ends the step at the system call's exit with the flag already removed;
  a `rep`-prefixed string instruction keeps the trap flag armed and the `#DB`
  handler consumes each iteration's trap in place until the instruction pointer
  moves. Phase 2 planted a temporary breakpoint after the instruction with the
  rest of the group stopped; that is gone, which is what lets threads step
  independently. The engine's one worker serves every session and never waits for
  a step longer than 2 s: a step the kernel holds longer (a system call that
  blocks, a long string loop, a handler not reached yet), or one a `DETACH` or
  `STOP_RUN` wants ended, stays armed, the group runs (`RUNNING`), and the thread's
  stop at the step's end is the next event (`STEP`), as a breakpoint would be; a
  step past a breakpoint that a `CONT` left unfinished ends quietly. A stepped
  thread that falls asleep in a vfork the debugger follows stops the group at once
  with that thread's `VFORK` event. A `STOP` during the step stops the group once
  it runs. `DETACH` (with or without kill) is accepted while a `CONT` or step is
  under way and is carried out when it is done (guest series 0059; before, it
  was refused with `-EBUSY` and a step of a vfork hung every session).
* **Registers of a thread that left.** A thread's user registers are on its kernel
  stack, which an exiting thread frees; every access to another thread's
  registers holds the stack and finds nothing once it is gone (`REGS_*` answer
  `-ESRCH`, a thread's pc reads 0), and `STATUS` and `CONT` of a stopped group that
  was killed report it `EXITED` (guest series 0058).
* **Signals** (guest Phase 2). Every signal about to be delivered to a thread of
  the group stops the group first (`get_signal` calls the engine under the
  signal lock; the thread parks as a tracer's signal stop would, without a
  tracer). `CONT` carries the signal to deliver to a thread (0 drops it, another
  number replaces it); a step that delivers a signal to a handler stops at the
  handler's first instruction, and a step armed when a signal arrives is
  disarmed first, so the trap flag is never in a signal frame (the Phase 1 risk).
  A signal whose default action ends the whole group used to do so when it was
  generated, before any delivery path; for a debugged group it is queued like
  any other so the debugger sees it first. The debugger asks for nothing about
  it: a stop reply carries the signal and gdb's `handle` table decides.
* **Hardware breakpoints and watchpoints** (guest Phase 2) use the kernel's
  breakpoint facility (`register_user_hw_breakpoint`), per thread and for every
  thread of the group, and leave nothing in memory. Four slots in one pool (mixed
  kinds); a request with none left is `-ENOSPC`, which the RSP server turns into
  an `E1c` reply (gdb: "Cannot insert hardware breakpoint"). Watch lengths are
  1, 2, 4 and 8 with an aligned address; the RSP server splits any region into
  such pieces and refuses it whole if they do not fit. They are not ptrace's
  virtual debug-register state: a tracer of the sample reads zeros and no
  `SIGTRAP` is raised. A thread created while the group runs gets them at the
  next stop. A hit is reported after the access for a watchpoint and before the
  instruction for an instruction breakpoint (resuming does not retrigger it).
  x86 has no read-only watch: `rwatch` is refused, `awatch` works.
* **Debug on start.** `EXEC` takes a `DEBUG` flag; the launch creates the debug
  session for the task that is about to exec and a `task_work` callback added
  before the exec parks it at its first return to user mode, before its first
  user instruction (the loader's entry for a dynamic program, the ELF entry for a
  static one). `ATTACH` adopts the session by identity (the `EXEC` reply carries
  the start time). `AUXV` returns the auxiliary vector so gdb relocates position
  independent programs and finds the loader.
* **Interactions.** A process core taken while the group is stopped completes
  with the group still stopped (the park runs the core's callbacks). `STOP_RUN`
  tells a debugging session first: no new stop starts, the group is stopped if it
  runs, then every thread is released and a signal it stopped on is delivered;
  the SIGKILL escalation stays the backstop and ends a parked thread through its
  killable sleep. When the group cannot be stopped (job control holds every
  thread, a thread in an uninterruptible wait) the engine's breakpoint bytes are
  taken out anyway after the stop gave up: a program that outlives its Stop must
  not find them (a thread that reaches one in that instant gets the default
  `SIGTRAP`, which is what the Stop is about to do to it anyway). A breakpoint byte a `fork` child inherits in its own copy of the
  memory is repaired in the child at its first trap (no `SIGTRAP`); a `vfork` child
  shares the parent's memory and cannot be repaired. Breakpoint removal restores
  the original bytes only where the engine's byte is still in place: code the
  program rewrote while it ran (self-modifying code) is left alone.
* **Exit** (all sessions): `STATUS` reports `EXITED` with the wait status.
* **Exec** (phase 3, option `EXEC`): the session continues in the new image. The
  hook at the end of `exec_binprm` replaces the session's address-space object
  (breakpoints and debug registers of the old image are dropped), the thread that
  executed is the group leader (its id is the group id after `de_thread`), and the
  thread stops with event `EXEC` carrying the path. Without the option exec still
  ends the session (`EXEC` state), as in phase 2. A launch's own exec (Debug on
  start) is not an event.
* **Sessions and children** (phase 3): sessions are a list (at most 16), each over
  one thread group; the engine's bytes live in an address-space object a vfork
  child shares with its parent until it execs (a `CLONE_VFORK` child shares it only
with `CLONE_VM`; without it the child has its own, as after a fork, and the
event's `SHARED_MM` flag is clear: guest series 0060). With option `FORK` the fork hook (in
  `kernel_clone`, before the child runs) opens a session for the child, parked at
  its first return to user mode with event `CHILD`, holding a record of the engine
  bytes it inherited (taken out when the debugger adopts it); the parent thread
  stops at the system call's return with event `FORK` and the child's identity
  (`ATTACH` with that identity and the debugger's nonce adopts the child). A vfork
  parent sleeps in the kernel until the child execs or exits and cannot park: its
  stop is reported at once without parking it (`VFORK`), the thread counts as
  stopped (its registers are the system call's), and when the child lets go the
  thread reports `VFORK_DONE`. A child nobody adopted when its parent session ends
  is released with its bytes removed; detaching a child does the same. A clone that
  shares memory without being a vfork (a "process" built from `CLONE_VM`) has no
  owner of that memory and is not followed.
* **Events that cannot wait** (phase 3): fork, exec and vfork-done happen once. When
  one arrives while the stop cannot take it (the debugger already asked for a stop,
  or the group is stopped), the thread keeps it and it is reported by the next
  resume, before anything runs; a stop request that raced a fork therefore shows the
  stop first and the fork on the continue.
* **Non-stop** (phase 3, option `NONSTOP`): a thread with an event parks alone and
  the event is queued (64 deep, oldest lost on overflow, counted) for the debugger to
  read with `EVENTS` and acknowledge by sequence number; the others run. Software
  breakpoint bytes stay in memory (`BP_SET` writes, `BP_CLEAR` restores at once, a
  write over one updates the saved original and keeps the byte), so memory and
  breakpoint requests need no stop, while registers need the thread stopped.
  `THREAD_CTL` stops, continues or steps one thread (or every thread). A
  breakpoint under a resumed thread fires again unless the debugger took it out
  first, as gdb does (its own step-over or displaced stepping).
* **Reconnect and restored snapshots** (phase 3): the control fence no longer ends
  sessions. A session, its breakpoints and its stopped threads are guest state like
  any other and survive; `SESSIONS` lists them, `BP_LIST` a session's breakpoints and
  `ATTACH` with `ADOPT` takes one over with a new nonce. See "Reconnect and
  snapshots" below.
* Lock order: `dbg_lock` (attach and teardown) then the session spinlock; trap and
  park callbacks never take `dbg_lock` and never sleep except in the final wait.

## Measurements (BusyBox base, KVM, 1 vCPU, three-thread sample)

Phase 1 polled the V7 control loop every 10 ms and the app's worker loop waited
10 ms between passes unless a loopback debugger was attached, so every request
cost about 22 ms. Phase 2 polls at the next tick while a session exists and keeps
the worker loop on its 1 ms wait for any debug link client. Median over 30
rounds, same machine:

| Operation | Phase 1 guest | Phase 2 guest |
| --- | --- | --- |
| one request (`STATUS`) | 22 ms | 4 ms |
| 2 KiB of memory | 22 ms | 4 ms |
| general registers and FXSAVE, two requests | 44 ms | 8 ms |
| the same in one batched request | 44 ms (not offered) | 4 ms |
| stop all threads | 35-55 ms | 8 ms |
| single step | 44 ms | 8 ms (a step over `SYSCALL`: 12-14 ms) |
| stop and detach | 79 ms | 25 ms |

The remaining 4 ms per request is one control-loop tick (HZ=1000) plus the
host's worker loop. Poll time while no session exists is unchanged (10 ms).

## Host RSP server

The server speaks the remote serial protocol itself (`debug/rsp_packet.rs`
framing, escaping and run-length decoding; `rsp_client.rs` the session loop and
stop replies; `rsp_requests.rs` the queries). No third-party protocol library: the
`gdbstub` crate has no multiprocess ids, fork or exec events or non-stop, which
are Phase 3. Offered: `multiprocess+`, `fork-events+`, `vfork-events+`,
`exec-events+` (each only if the client asks and the guest announces FOLLOW),
`QNonStop+` (guest NONSTOP), `swbreak+`, `hwbreak+`, `vContSupported+`,
`QStartNoAckMode+`, `qXfer:features` and `qXfer:auxv`. Thread ids are
`p<pid>.<tid>` (hex, even length); `Hgp0.0` and `-1` mean any process or thread.

All-stop and non-stop. Software (`swbreak`) and hardware (`hwbreak`, `Z1`)
breakpoints, write and access watchpoints (`Z2`, `Z4`; `Z3` is refused), `vCont`
with `c`, `C`, `s`, `S`, `t` and per-process selectors (`vCont;c:p5f.-1`), signals
as `T<sig>` in GDB's own numbering (`debug/signals.rs` converts both ways),
`Ctrl-C`, `vCtrlC`, `D`, `D;pid`, `k`, `vKill;pid`.

* **Fork and vfork.** A followed fork reaches the client as
  `T05thread:p5e.5e;fork:p5f.5f;` (`vfork:` for a vfork, then
  `vforkdone:;` when the child lets go of the parent's memory). The child is a
  second inferior held at the fork (rax 0, no output); gdb's follow-fork-mode and
  detach-on-fork do the rest: `D;pid` releases one process (the engine repairs the
  child's inherited breakpoint bytes), plain `D` leaves the session. A fork the
  panel left standing when a client connects is what `?` reports.
* **Exec.** `T05thread:p5f.5f;exec:<hex path>;` and the session continues in the new
  image; the breakpoints of the old image are gone and the client sets them again.
  Without the client's `exec-events+` (or an old guest) the old behaviour holds:
  the session ends with the address-space change.
* **Non-stop.** `QNonStop:1` puts the session in non-stop: threads stop and run
  one by one (`vCont;t`, `vCont;c:p..`), stops arrive as `%Stop` notifications
  acknowledged with `vStopped`, memory can be read while threads run. A thread the
  client asked to stop is reported with signal 0 (`T00`), a Ctrl-C in all-stop as
  `T02`. Of the threads already stopped when the client connects, the first
  answers `?` and the others follow as notifications once the client has asked for
  symbols (gdb 17's first wait cannot take two queued stops while it starts up).
* Listens on a Unix socket (mode 0600, in the run's private folder or a short
  private folder under the temporary directory when the path would not fit
  `sun_path`) and an ephemeral `127.0.0.1` port. Never anything else. A Unix
  client must be this user (`SO_PEERCRED`); a TCP client must be a process of this
  user (checked against the kernel's TCP table).
* The process keeps running after "Attach debugger" until a client connects, then
  it is stopped. A client that detaches (`D`) or disappears leaves the process
  running with its breakpoints removed, and the server keeps listening.
  `k` ends the process. The server ends with the process or the VM.
* The register image follows GDB's amd64-linux order and is also published as
  the target description: core (rax..gs, st0..st7, fctrl..fop), sse (xmm0..xmm15,
  mxcsr), linux (orig_rax), segments (fs_base, gs_base); 560 bytes.
* gdb keeps its own `handle` table: the host passes the signals gdb tells it to
  (`C<sig>`) and never filters for a client.

## Reconnect and snapshots

Sessions live in the guest, so they outlast the host's link. The guest's fence no
longer cancels them. After a transport reconnect or a snapshot restore the host
asks `SESSIONS`, adopts its own by identity (`ATTACH` with the ADOPT flag, a new
nonce), reads `STATUS`, `THREADS` and `BP_LIST` and carries on: the stopped threads
stay stopped, the breakpoints stay in memory, the host's registry (the panel's and
a client's) is made to match the guest's list. Breakpoints the host does not know
about are removed, ones it expects are set again.

Snapshots are allowed while a debugger is attached (the P2 refusal is gone). The
guest's session state is bit-exact in a snapshot, so a snapshot taken at a
breakpoint resumes at it; that workflow is worth more than the refusal protected.
A restore is a different time: a connected gdb client is dropped (its picture of
memory and registers is from another moment), the panel reads the state again
and keeps its breakpoints. A reconnect only refreshes. A restore that reboots the
disks ends the session. Snapshots of a guest whose base is older than this
contract still take the old route (`ant_debug_fence` cancelled the session).

## Panel signal table and fork choice

The panel keeps gdb's `handle` table: per signal stop, print and pass, with gdb's
defaults (`SIGCHLD`, `SIGWINCH`, `SIGALRM`, `SIGPROF`, `SIGURG`, ... nostop
noprint pass; `SIGTRAP`, `SIGINT` stop and are not passed). It is editable, saved
with the app's settings (only the differences from the defaults) and sent to the
controller at the start of each session. A quiet signal never stops the program:
the controller passes it on and notes it in a short log. The fork policy
(off, parent, child, ask; detach the other process or keep it) is saved too and
applies at each fork; with "ask" the program stops at the fork and the panel's
Processes list offers the choice. Threads and processes show their run state.

## Known limits

`CLONE_VM` without `CLONE_VFORK` (a thread-like clone of the address space) is not
followed, and a `clone` thread's creation is not reported as an event. A vfork
child shares its parent's breakpoint table until it execs, so a breakpoint the
parent hits while the child runs is missed. In non-stop gdb steps over a
breakpoint itself (the engine does not hold a thread while it does). `rwatch` is
unsupported. Direct reads of the program's own code still see a software
breakpoint's byte while the group runs (use `hbreak`). A thread that reaches a
breakpoint byte just after a `STOP_RUN` took it out gets `SIGTRAP`. The Quilt view
of the series stops at 0038; the guest patches are `src/antinomie/core/6.12`.
A panel watchpoint covers 8 bytes from its address.

Fixed in Phase 3 (they were P2 limits): threads created while the group runs get
their hardware breakpoints at their own first return to user mode; a `STOP_RUN`
that cannot stop the group still removes its breakpoint bytes (they were left in).

## Qualification

`tests/monitor/debug-fixture.c` is a static, non-PIE program that prints the
state an anti-debug check would read (TracerPid, the result of its own
`PTRACE_TRACEME`, `SIGTRAP` count, `0xCC` bytes in its own code through
`/proc/self/mem` and by direct load, the trap flag through `pushfq`) and has
modes that churn threads, `exec` and `vfork`. `crates/monitor-core/examples/debug-check.rs`
drives it in one disposable BusyBox VM:

```
gcc -O1 -static -no-pie -pthread -o debug-fixture tests/monitor/debug-fixture.c
cargo run --release --example debug-check -- spike  BUNDLE NEW_DATA_DIR ./debug-fixture
cargo run --release --example debug-check -- gdb    BUNDLE NEW_DATA_DIR ./debug-fixture
cargo run --release --example debug-check -- stress BUNDLE NEW_DATA_DIR ./debug-fixture
```

`spike` is phase 0 through the `DebugBackend` trait (stop, registers, memory,
breakpoints, stepping, TF, anti-debug lines, detach), `gdb` is phase 1 through a
real `gdb` (and a raw Unix-socket query), `stress` covers threads created while
running, 33-thread stop and resume, a parent that cannot park (`vfork`) and
`exec`. The RSP packets themselves are pinned by `debug::tests::rsp`, against a
mock backend, over the real sockets.

Phase 2 has its own fixture, `tests/monitor/debug-p2-fixture.c` (modes `threads`,
`signal`, `fatal`, `step`, `hw`, `smc`, `anti`, `start`, `fork`; build it static,
static-pie and dynamic) and `debug-check p2`:

```
gcc -O1 -static -no-pie -pthread -o p2fix  tests/monitor/debug-p2-fixture.c
gcc -O1 -static-pie     -pthread -o p2pie  tests/monitor/debug-p2-fixture.c
gcc -O1 -pthread -Wl,--dynamic-linker=/tmp/p2ld.so -Wl,-rpath,/tmp -o p2dyn tests/monitor/debug-p2-fixture.c
mkdir dbgroot && cp -L /lib64/ld-linux-x86-64.so.2 dbgroot/p2ld.so && cp -L /usr/lib/x86_64-linux-gnu/libc.so.6 dbgroot/
cargo run --release --example debug-check -- p2 BUNDLE NEW_DATA_DIR DIR [test ...]
```

Tests: `start`, `pie`, `dynamic` (Debug on start under a real gdb), `gdb-threads`,
`gdb-step`, `gdb-hw`, `gdb-signals`, `gdb-fatal`, `stop-run`, `core-under-stop`
(real gdb), `step`, `signals`, `signal-step`, `forkbp`, `hw`, `slots`,
`hwthreads`, `smc`, `anti`, `latency` (backend trait). With no test names all
run in one VM.

Phase 3 has `tests/monitor/debug-p3-fixture.c` (modes `fork`, `vfork`, `exec`,
`leaf`, `nonstop`, `system`, `spawn`, `chld`, `stopself`, `killtimer`,
`exitstep`, `vforkstep`, `pausestep`, `vforknovm`; the optional fourth
argument is a lead-in in milliseconds, so gdb connects to a program that is idle,
not in the middle of a fork) and `debug-check p3`:

```
gcc -O1 -static -no-pie -pthread -o p3fix tests/monitor/debug-p3-fixture.c
cargo run --release --example debug-check -- p3 BUNDLE NEW_DATA_DIR DIR [test ...]
```

Backend tests: `fork-follow`, `vfork-follow`, `exec-event`, `exec-legacy`,
`nonstop`, `hwthreads`, `sigchld`, `readopt`, `stoprun-bytes`, `fork-stress`,
and the engine's worker under programs that end or block (`killed-stop`: a group
SIGKILLed by its own timer at a breakpoint stop, then `CONT`; `exit-step`: a
thread steps its own `exit` five times; `blocking-steps`: a step of a followed
vfork, `DETACH` with kill during a step of `pause()`, and that step left to run;
`vfork-own-memory`: `clone(CLONE_VFORK)` without `CLONE_VM`). These four also
read the guest kernel log and fail on an oops, BUG or warning.
Real gdb: `gdb-follow-child`, `gdb-follow-parent`, `gdb-keep-both`, `gdb-vfork`,
`gdb-exec`, `gdb-nonstop`. App level (the panel controller through the app's
backend): `reconnect`, `snapshot`, `snapshot-readopt` (these need a release base,
a snapshot of an unversioned development kernel is refused). `P3_TRACE=1` turns on
gdb's `debug remote`, `P3_TRACE_FILE` keeps the whole gdb transcript.

The engine tests and the six real-gdb checks of Phase 3 also ran on a KASAN + lockdep
(PROVE_LOCKING, PROVE_RCU) development kernel with no report in the guest log.
