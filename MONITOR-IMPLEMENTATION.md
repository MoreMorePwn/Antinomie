# Antinomie initial monitoring release

This brief is the shared implementation contract. User authorized implementation
on 2026-10-01. Core workers/review use gpt-6.1-sol; bounded support may use Luna.

## Accepted requirements

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
  no auxiliary guest helper process. Ordinary init, shell and target programs
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

## Ownership

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
