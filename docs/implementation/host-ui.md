# Implementation record: Host UI

The host application: debugger, workspace and terminal windows, performance and background work, and the accepted UI updates. Part of the [implementation record](../implementation.md).

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

### Background tasks and the stat cache (0.8.2)

Two small helpers keep slow disks and programs off the frame (`monitor-ui/src/background.rs`,
`stat_cache.rs`).

* `background::Task<T>` runs one closure on its own thread; the result sits in an
  `Arc<Mutex<Option<T>>>`, the worker asks the context for a repaint, and the view
  takes the result with `done()` on a later frame. Users: the Build base wizard's host
  checks (container engines, the builder image list, the toolchain chroot's size)
  and the removal of chroots and images (`build_wizard/probe.rs`), and the Network
  capture list (`network_view/display.rs`, which keeps the selection while it loads).
  The core view's saved Ghidra text and Export functions, and the folder openers (a
  failure becomes an error toast and an Activity row; the rules and plugins folders
  are created off the UI thread too), use their own worker threads. The Build mode
  and Summary pages show a spinner until the first answer.
* `stat_cache::is_file` and `stat_cache::len` answer from a per-thread map for one
  second (`KEEP`), at most 256 paths (`MOST`), for code that asks every frame: the
  network toolbar's PATH lookups, the memory dump size and symbol-table checks, and
  the artifact menu's file test. It is for the UI thread only.
* The memory result view looks up the run's files folder once, when the result loads,
  not on every frame.

### Headless foundations: shared settings, data-folder owner, `antinomie-cli` and `antinomie-service` (0.9.0)

Cards of the headless/CLI work (design: `Headless and Auto Mode`). What a user can
run is in `docs/usage.md`, "Command line (0.9.0)"; this section is the contract
behind it.

* **Crates and dependency direction.** `antinomie-cli` (binary `antinomie-cli`,
  `crates/cli/`) depends on `antinomie-service` (`crates/service/`),
  `antinomie-triage` (`crates/triage/`) and `antinomie-monitor-core`. The service
  and the triage crate depend on core. None of them links egui, eframe, winit or
  `antinomie-monitor-ui`; `crates/cli/tests/dependency_tree.rs` runs `cargo tree`
  and fails if one of them appears. The window depends on core and triage. Every
  binary hosts the earlier-bytes copier: `antinomie_triage::copier::host_copier()`
  first thing in `main` serves `--copy-earlier-bytes` or registers the running
  program with `file_before_store::register_copier_host()` (`ANTINOMIE_COPIER`
  still overrides it). Triage of a saved run needs no window either: a
  `RunSummary` becomes Triage's input and scan request through
  `antinomie_triage::SavedRun` (`TriageInput::for_run`, `ScanRequest::for_run`,
  the run's capture from its `artifacts.json`, `TriageSettings::headless` from
  `settings.json` with `dig` and `whois` off), which the window's own selection
  path uses too. The report the Export report dialog writes is
  `antinomie_triage::report_export` (the job, the builder, the run facts, the
  not-started report), the run digest is `antinomie_triage::digest`, and the
  Detection tab's evidence key, scan request, frozen rule selection and run
  identity are `antinomie_triage::detection`; the dialog and the tab keep only
  their state and drawing. `analysis::detection::run_unsaved` runs an engine
  without writing its result, manifest or log into the run's folder.
  `antinomie-cli triage`, `detect` and `report` (`crates/cli/src/commands/`)
  find the run read-only (`recording::list_runs_read_only`, `find_run_read_only`),
  index it through `SavedRun`, and run `report_export::Job::for_saved` /
  `build_report` / `write_built` and `detection::scan`; `detect --save` takes the
  data-folder lock and writes the digest with `digest::Update`, as the window's
  digest tick does.
  The CLI is not a second implementation: every engine step it takes
  (`Command::AnalyzeSample`, the rule registry, the sample library, custody) is a
  core function the window calls too.
* **Data-folder owner (`data_owner.rs`).** The lock on `.app-owner.lock` stays the
  authority. The process that takes it also writes `run/owner.json` (atomic
  replace, mode 0600: pid, kind `gui`, `daemon` or `cli`, start time) and removes
  it on a clean exit. A record whose process is gone, or that no lock backs, is
  stale and ignored; the file describes the owner and is never a lock. A second
  process that finds the lock taken reports "data folder is already in use" with
  the owner's description (the CLI exits 21, `busy`), and the migration of an old
  data folder first checks the owner. `doctor` reports `data_dir.owner`.
* **Lane data folders (`lanes.rs`, multi-lane M1, ANT-T0455 card B).** Groundwork
  for a daemon with several lanes, one engine and one VM each, in one process
  (`daemon.lanes` stays 1 by default; the daemon side is card C). Lane 1 is the
  data folder the operator chose (the daemon's `lane-1`). Lane N (2 to 64) has
  its own data folder, `<lane 1>/lanes/N/` (the daemon's `lane-N`; `lanes/1/` is
  never a lane), for its VMs, runs and settings, and shares lane 1's
  `bases`, `samples`, `ioc`, `rules`, `tools` and `volatility-plugins` and the
  known false positives, with no symbolic links:
  * Its engine starts with `BackendOptions::shared_root` set to lane 1's folder
    and an owner claim with `lane: Some(N)` (recorded in `run/owner.json`, so a
    refusal names "lane N of the Antinomie daemon"). The start checks that the
    data folder is exactly `<shared_root>/lanes/N`, that the shared root is not
    a lane itself and that a root and a lane come together, then writes
    `<lane>/lane.json` (`{"schema":1,"lane":N}`) once it holds the lane's lock.
  * Every path helper that takes a data folder (`samples::samples_dir`,
    `ruleset::rules_root`, `analysis_tools::tools_dir`, `ioc::feeds::root`,
    `lanes::bases_dir`, `memory::plugins_dir`) reads `lane.json` and resolves a
    lane folder into lane 1's, in any process. The shared root is the lane
    folder's grandparent, not a stored path, so a moved tree keeps its lanes
    and `data_move::repair` re-points a lane VM at the moved shared base. A
    folder without `lane.json` resolves to itself, as before.
  * Only lane 1 changes the shared folders. A lane engine refuses `ImportBase`,
    `DeleteBase`, `DownloadBase`, `BuildBase`, `InstallTool` and `RemoveTool`,
    and the rule pack and group writers, the rules catalog, the strings regex
    patterns, the IOC dataset writers, the known false positives, tool install
    and remove and the GeoIP update refuse a lane folder. Every refusal is a
    `lanes::LaneRefusal` whose text contains `lanes::SHARED_WRITER` ("only lane 1
    (the main data folder) changes the folders the lanes share"). A lane skips the rule index
    migration and the staging sweep, which lane 1 does. The sample library is
    shared and written by every lane; its in-process writer lock is keyed by the
    database's canonical path, so all engines of a process share it.
  * `DeleteBase` on lane 1 also checks the VMs of every lane folder and is
    refused while one is built on the base ("used by … Lane 2 (lane 2)"), or
    while a lane's record or VM list does not read.
  * The window (or any plain engine) is refused on a lane folder and sent to
    lane 1, and the old-data-folder migration refuses a folder with lanes.
* **Shared settings (`settings.rs`).** `<data>/settings.json` holds the engine
  settings every front end needs (triage and detection options, quotas, limits,
  report export, disk view and so on). Version 1; written only by the process
  that holds the data lock (mode 0600, atomic replace); a field that is absent
  reads as its default; fields this version does not know are kept on rewrite; a
  file that cannot be read is an error and is never replaced by defaults, and a
  newer `settings_version` is refused for writing. The window reads and writes
  it (a read error is shown as a warning and the file is left alone);
  `antinomie-cli config get` reads it without a lock and `config set` takes the
  lock.
* **CLI contract.** Every reply is one object with `api_version` 1. JSON mode
  prints `{"ok":true,"result":...}` or `{"ok":false,"error":{code,message,
  retryable,details}}`; ndjson prints list items one per line and a closing
  `{"result":{"count","next_cursor"}}`; log lines go to standard error. Error
  codes map to the fixed exit codes of the usage guide (`exit.rs`). `--direct`
  takes the data lock in the process; `--daemon` and `--socket` are accepted but
  nothing listens yet. Commands that only read (`sample`, `custody verify`,
  `config get`, `config validate`, `rules list`) take no lock.
* **`antinomie-service`.** `api/` holds the job and query objects, errors and
  `job-api-1.schema.json` (generated with `schemars`; a test fails when the
  checked-in file is stale). `config/` loads and validates `service.toml` and
  `policies/*.toml` (unknown keys are errors, ceilings, the v1 routes `drop` and
  `inet_sim`, the lane VM); `antinomie-cli config validate` is its only caller
  today. `store/` is the job store under `<data>/service/`: SQLite in WAL mode
  with one writer, the `jobs` table as queue and source of truth, every state
  change one transaction that also inserts its event rows, an events mirror in
  `jobs/<id>/events.ndjson` appended after the commit, idempotency keys, and a
  recovery pass that repairs the mirror and requeues jobs a dead process left
  running. `intake/` stages uploads and applies the common checks (regular file
  opened without following links, size ceiling, type and architecture
  acceptance, library add with origin `Added`, de-duplication by SHA-256). A
  staged file never runs on the host. `custody.rs` names the custody actor of
  a job (`local:<uid>`, `web:<user>` or `auto:policy-<name>`, its `client_id`),
  sets it for the length of the job so the engine's own threads record it too,
  and writes one `automation` entry per job with the policy digest, the route
  and the submitter (the kind and its verifier support are in core). `query/` is the read-only recording API (run lists, calls, process and
  file reads, safe artifact reads, packet reads through the no-cache packet
  worker, cursors with generations and row and byte limits). The Triage reads
  (`query/{scan,tables,triage,files,network,timeline}.rs`) run the same
  `SavedRun` scan the window makes, with `ScanRequest::read_only` set so it writes
  no journal, on a thread of its own: the first read answers `building` with the
  scan's progress, two scans stay in memory, and filter, sort and paging run over
  the whole row set with the Triage crate's `FieldSpec` lists (the catalogue's
  tables are those lists). The summary and indicators come from
  `report_export::build_report`, so counts equal the export's. `antinomie-cli`
  reaches the query API in `commands/query.rs` (`run list`, `run show`, `run
  export` in `run_read.rs`, and `triage`).
* **Tests.** `cargo test --release -p antinomie-cli -p antinomie-service`.

### Statistics window (0.9.0)

The Statistics window (ANT-T0477) is `monitor-ui/src/statistics.rs` and its
`statistics/` folder; the counting is `antinomie_triage::statistics` (see
`triage-and-analysis.md`, "Statistics engine"). What a user sees is in
`docs/usage.md`, "Statistics (0.9.0)".

* **Window.** `StatisticsWindow` floats over the main window (`widgets::window`)
  or, after **Pop out**, is drawn by `show_viewport_immediate` into its own
  operating-system window with the Activity graph window's pattern; where the
  platform has no separate windows it floats again. It is drawn from
  `app/panels.rs::draw`; `app/statistics_ui.rs` tells it which run or capture is
  selected and does what a click asks of the Syscall Trace (`Navigate`:
  `scope_trace`, `jump_triage_call`, a hidden category shown first). Size and the
  pop-out state are settings (`statistics_window`, `statistics_popped`). A body
  must fit the window: a row wider than it, or a body taller than it, makes egui
  widen the window every frame until it fills the screen, so the filter row keeps
  480 points for its buttons and the tab body 52 points for the footer (test
  `b_the_window_does_not_grow_by_itself_on_any_tab`).
* **Worker.** `worker.rs` runs `compute` on a thread named `statistics`, one walk
  per `Key` (run folder, capture flag, root cookie, filter, custom lines), with
  its own cancel flag; the window polls it every frame. The last four complete
  results are kept. A stopped walk keeps its counts marked partial. Custom Call
  rate lines use a second `Worker` (`rate_worker`): a key with lines is a
  `Parts::RateOnly` walk, started when the main walk is over (one walk at a
  time), replaced when the lines change, forgotten when the last custom line is
  removed.
* **Tabs.** A tab is a `Tab` variant, a module, and an arm in
  `StatisticsWindow::tab_body` and `current_table` (`toolbar.rs`). A tab returns a
  `Pick`: a count to open (`Click { clause, group }`, added to the window's
  filter) or one exact call. Properties and the quality strip, Hierarchy, Call
  rate (`rate.rs` model and tab, `rate_lines.rs` line editor, `rate_paint.rs`
  painter and pointer) and Latency (`latency.rs`) read only the `RunStatistics`.
* **Call rate drawing.** The engine's bins are on a grid of whole widths from 0,
  every width a power of two times 1 ms. The tab rounds the chosen interval up to
  a whole number of the coarsest bin on screen, so every interval holds whole bins
  of every line and its count is exact; the click clause
  `event.time_ns >= A && event.time_ns < B` selects exactly those calls (test D3
  compares it with the Trace's count). A line is thinned to at most 640 points
  (the largest count in each group of pixel columns) and a dashed line is dashed
  by columns when it has more than 400 points, so a frame costs the same for
  65,536 bins as for a few hundred.
* **Equality.** The Trace's "N matching" for a clicked clause equals
  `calls + out_of_scope` of the engine for the same filter (tests C4 and D3).

**Measured** (release build, WSL2, 4 jobs, the test machine; tests A9 and D5).

| Bound | Measured |
|---|---|
| Aggregator alone, at least 2 M calls/s | 11.8 M calls/s |
| Walk of the 200,000-call fixture, at most 1.25 times the Trace's count plus 100 ms | Trace count 1.63 s (122,500 calls/s), statistics 1.70 s (117,500 calls/s): 1.04 times |
| Paint of 4 lines x 65,536 intervals at 1280x800, at most 4 ms (median of 15 frames) | 3.2 ms for the whole run, 1.25 ms for a tenth of it, 0.17 ms for a hundredth; no repaint when idle |

The fixture holds 4 packets a call and sits in the page cache, so the walk rate is
the best case of a small, warm recording; a multi-GiB recording that is not cached
reads slower. No real recording has been walked yet, so the 10-million-call
estimate in the design stays an estimate.

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
  no auxiliary guest control helper, except the temporary resource-only
  collector described below (an explicit exception), which only revision 11 to 16
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

## Accepted aligned VM status cards (0.6.1)

VM Status resource cards have equal height within each responsive
row. Render the contents once, measure that row's
tallest card and extend all of its frame backgrounds to the shared height in
the same frame. Apply this to guest pairs and host pairs/triples; single-column
cards retain natural height. Width/data/font changes must not depend on a stale
height cache or clip wrapped notes. Measurements and monitoring stay unchanged.

## Accepted upload/picker and collector follow-up (0.6.1)

This follow-up supersedes the dialog-tree and immediate-send portions of
the earlier upload browser (below): keep the sidebar Explorer tree, fill its pane width,
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
kernel and protocol stay unchanged; kernel-native resource production is deferred to 0.7.0.

## Historical accepted upload browser and Run handoff (0.6.1)

0.6.1 adds an Upload file workflow that chooses a host folder through the
filesystem explorer, displays its expandable filesystem tree and selects a
file to upload. Keep manual path entry and plain Upload. Upload and Run makes the uploaded file executable and, only after the
matching successful upload in the same VM session, opens the editable Run program
window with its guest path. It never executes without the user's Run action.
Overwrite confirmation retains the chosen action; closing cancels the handoff
without claiming to cancel a guest write already submitted. Reuse the existing
single-file guest protocol and 0.6.0 bases; no guest/image/transport changes.

A follow-up adds a persistent Explorer section below
Base images. Choose its host root independently of the Upload dialog; double-click
a regular file or use right-click Send and Run to submit the existing upload and
success-only Run dialog handoff. Right-click Open Directory opens the containing
host folder (the folder itself for directory entries). Stopped/wrongly selected
VMs and pending uploads cannot admit another send. Folded bases never hide Explorer.

## Accepted resource observations and UI repairs (0.6.1)

This update adds explicit disconnected-network capture warnings, loss-counter
definitions on hover and a repair of growing subwindows, and keeps the folder
Upload and Run workflow. Fix the reproduced Import Base row feedback;
validate floating/detached views at normal and large text sizes. Extend the
existing host resource producer with checked MemAvailable and statvfs used/free
values. Label their host scope and preserve session/retention identity.

0.6.1 uses a temporary guest resource collector, an explicit
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

Tab movement was unclear or did not work; this adds the expected drag
shadow. Preserve the native dock tree and saved arrangements. Drag tab
labels directly, show a bounded shadowed title and explicit docking action,
and use one resolver for the highlighted destination and the committed drop.
Pane edges split, centers join, and visible tab headers allow insertion/reorder
with source-index removal accounted for. Show grab/grabbing cursors, focus moved
tabs and update the corresponding Details context on a committed drop. Escape
and missing-release cancellation must not silently detach or move a tab; a lone
tab cannot promise a split into an empty source group. No guest/backend changes.

## Host, guest base and workspace updates

### Accepted 0.3.0 update

Antinomie 0.3.0 dates from 2026-10-09 and its usability follow-up from
2026-10-10. Capture All retains a per-process tree; revision-13 bases use
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

### Accepted display settings update

Adds saved per-VM guest/window resolution, fullscreen, fit-to-window,
KVM/TCG acceleration and bounded CPU-model choices in New VM/settings. Typed
serde-default launch configuration preserves legacy defaults. Settings apply on
next boot only; global force-TCG/headless overrides retain precedence. Host CPU
requires effective KVM. Fixed guest pixels are retained while scaling the QEMU
window. Presets use standard VGA static EDID, built-in Linux Bochs DRM
and video=Virtual-1 mode selection. Fixed/fitted/windowed GTK launches use a
bounded owned-window X11/XWayland initial-size operation; fullscreen/headless
paths need none. Existing x11rb/rustix packages provide safe display operations.
New immutable bundles declare fixed_display capability; legacy hashes and user
disks stay intact. No kernel/transport revision, guest helper or free-form QEMU
arguments. Revision 3 of the contract is this update.

### Accepted native terminal windows update

These changes date from 2026-10-05:

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
  Migrated VMs boot with the newly patched kernel;
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
`rusqlite 0.40.2` is used for bounded disk-backed archive indexing; SQLite
is linked from the system and required upstream notices are retained.
Run/session maps, previews, pages and queues remain bounded; new recording
payloads count against the recording quota and preserve explicit failures.
Areas changed:

- Guest: kernel patch series under src/antinomie/core, new guest
  protocol header src/antinomie/monitor/protocol/control.h, guest source manifest.
- Host: src/antinomie/monitor/crates/monitor-core only, public backend API.
- UI: src/antinomie/monitor/crates/monitor-ui only, depends on monitor-core.
- Workspace level: Cargo.toml, build/test/rootfs scripts, integration and patch
  exports.
- No wholesale refactor of transport.
