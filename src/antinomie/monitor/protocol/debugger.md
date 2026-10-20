# Debugger (guest revision 17)

A ptrace-free, process-scoped debug engine in the guest kernel, driven over the
V7 control channel and exposed to the outside as a GDB Remote Serial Protocol
(RSP) server on the host. Nothing runs inside the guest: no gdbserver, no agent,
no `PTRACE_ATTACH`. The sample's `TracerPid` stays 0 and its own
`PTRACE_TRACEME` still succeeds, because the engine never touches ptrace state.
Opcodes `0x1080..0x108c` and their layouts are in `control.h`; this file records
the semantics and the limits. The revision number is unchanged (17): the
opcodes are additive and an older guest answers `-EOPNOTSUPP`, which the host
reports as "this guest has no debugger".

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
* **Threads** created while the group runs are adopted at their first breakpoint
  from preallocated records (no allocation in exception context), so a new thread
  is never handed a `SIGTRAP`.
* **Steps are one user instruction.** The trap flag does it for ordinary
  instructions. A `SYSCALL` (or `INT 0x80`) and a `rep`-prefixed string
  instruction run to the instruction after them under an engine breakpoint with
  the rest of the group stopped: the trap flag would retire the next instruction
  after a system call (`SYSCALL` clears it and the return restores it) and one
  iteration of a string loop. A step that blocks in a system call waits for the
  system call; only the debugger's stop request ends it.
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
  killable sleep. A breakpoint byte a `fork` child inherits in its own copy of the
  memory is repaired in the child at its first trap (no `SIGTRAP`); a `vfork` child
  shares the parent's memory and cannot be repaired. Breakpoint removal restores
  the original bytes only where the engine's byte is still in place: code the
  program rewrote while it ran (self-modifying code) is left alone.
* **Exit and exec**: `STATUS` reports `EXITED` with the wait status, or `EXEC`
  when the address space was replaced (breakpoints are dropped; follow-exec is
  future work).
* **Reattach and snapshots**: the control fence resumes and removes the session
  before it acknowledges; the host refuses VM snapshots while a debugger is
  attached.
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

`gdbstub 0.7.10` owns framing, checksums, escaping, run-length encoding,
`qSupported`, no-ack mode and packet dispatch; `RspTarget` implements the
`Target` callbacks. All-stop, one process, multi-thread listing, software
(`swbreak`) and hardware (`hwbreak`, `Z1`) breakpoints, write and access
watchpoints (`Z2`, `Z4`; `Z3` is refused), `vCont` continue and single-step of one
thread (others stay stopped), `C<sig>`/`S<sig>` to pass a signal, signal stops as
`T<sig>` in GDB's own numbering (Linux and GDB differ for `SIGBUS`, `SIGUSR1`,
`SIGCHLD`, ...; `debug/signals.rs` converts both ways), `qXfer:auxv:read`,
`Ctrl-C`, `D`, `k`. Not offered, so never advertised: non-stop, range stepping,
multiprocess, host I/O. A Phase 1 guest has no hardware kinds, signals or
auxiliary vector and is not offered any.

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

## Known limits (left for P3)

Fork/vfork/exec following (a forked child runs free; its inherited breakpoint
byte is repaired, a `vfork` child's cannot be), non-stop, reconnect that re-adopts
a session across a snapshot (the fence cancels it), threads created while the
group runs miss hardware breakpoints until the next stop, `rwatch`, direct reads
of the program's own code still see a software breakpoint's byte while the group
runs (use `hbreak`), and a `STOP_RUN` while a breakpoint is in memory and the
group cannot be stopped in 3 s leaves the byte in. The panel passes the signal a
thread stopped on when it resumes (except `SIGTRAP`, `SIGINT`); gdb's own
`handle` table applies to a gdb client. A panel watchpoint covers 8 bytes from its
address.

## In-app panel

The Debugger window in the app is a second controller of the same engine, on the
RSP server thread, never through our own socket. See "Accepted in-app debugger
panel" in `docs/implementation.md` for the messages and the rule: one controller
at a time, a connecting client takes the process and the panel is read-only
("controlled by gdb") until it leaves. A client leaving still resumes the process.

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
