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
| Capability handshake | `CAPS` | software breakpoint lengths (mask), hardware breakpoint and watchpoint counts (0), hardware single-step, shadowed reads, multi-thread |
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
* **Exit and exec**: `STATUS` reports `EXITED` with the wait status, or `EXEC`
  when the address space was replaced (breakpoints are dropped; follow-exec is
  future work).
* **Reattach and snapshots**: the control fence resumes and removes the session
  before it acknowledges; the host refuses VM snapshots while a debugger is
  attached.
* Lock order: `dbg_lock` (attach and teardown) then the session spinlock; trap and
  park callbacks never take `dbg_lock` and never sleep except in the final wait.

## Measurements (BusyBox base, KVM, 1 vCPU, three-thread sample)

The V7 control loop polls every 10 ms (12 ms at 250 Hz), so every guest request
costs about one poll period regardless of its size.

| Operation | Median |
| --- | --- |
| stop all threads (`STOP` and polling until stopped) | 44-55 ms (3 requests) |
| registers, two sets | 44 ms (2 requests) |
| 2 KiB of memory | 22 ms (1 request) |
| single step (`CONT` and polling) | 44 ms |
| continue until a breakpoint hit | bounded by the sample (50 ms rounds) plus about 40 ms |
| detach (stop, remove, resume, confirm) | 55 ms |

The documented design guessed "tens of microseconds to low milliseconds" per
round trip; on this transport it is about 22 ms. Batching (several regsets in one
request) would halve register reads; lowering `ANT_POLL_MS` is a transport change
outside this work.

## Host RSP server

`gdbstub 0.7.10` owns framing, checksums, escaping, run-length encoding,
`qSupported`, no-ack mode and packet dispatch; `RspTarget` implements the
`Target` callbacks. All-stop, one process, multi-thread listing, software
breakpoints (`swbreak`), `vCont` continue and single-step of one thread
(others stay stopped), `Ctrl-C`, `D`, `k`. Not offered, so never advertised:
hardware breakpoints and watchpoints, non-stop, range stepping, signal
injection, multiprocess, host I/O.

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

## Known limits (left for P2 and P3)

Debug on start, per-thread stepping with the others running, hardware
breakpoints and watchpoints, signal stops and injection, fork/vfork/exec
following, non-stop, manual core under
a debug stop, kill of a stopped task by `STOP_RUN` (only the SIGKILL escalation
after the Stop grace period reaches a task stopped by the engine), reconnect that re-adopts a
session across a snapshot. A breakpoint left in memory is inherited by a
`fork` child while the group runs; stepping with a signal pending can lose the
step (the engine times out after 2 s and lets the thread run).

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
