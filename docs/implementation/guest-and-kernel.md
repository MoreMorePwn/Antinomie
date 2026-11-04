# Implementation record: Guest, kernel and transport

The guest kernel and tracer, the telemetry transport, the host/control contract, guest base kernels and the native syscall work. Part of the [implementation record](../implementation.md).

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
  the probe and the Triage events.
* **Limits.** A file written through an io_uring worker or closed by a process
  outside the run is not hashed; the launched program of a desktop run is the
  shell wrapper. A file opened for writing and not written is hashed at its last
  close all the same. A run's earlier segments must be in the same recording
  folder as its newest.

### Accepted exit re-capture of non-resident inputs (0.7.0)

Added on 2026-10-22. Guest series 0053, contract section 22;
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
  decoded for terminal requests only (and, since contract revision 21, for the
  requests `fs/ioctl.c` answers for every file; see below).
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
`conf-stress-contended` is judged by attribution: the host times every pause
in its telemetry reads (`Health.read_gaps`, see "Telemetry read gaps" below),
and when transport drops are the only problem its conformance check finds, it
passes if every drop falls in a read gap at least as long as the group's send
wait. A drop no such gap explains fails it. The drops, attributed and
unattributed, the gaps and the calls per second are in the report and
`results.json`; any other problem fails the group as before.

| Tier | Runs | Takes (this machine) |
|---|---|---|
| quick | the conformance trace suite's oracle groups `user`, `root`, `threads` (`conf-quick`) | about 1 min with the examples built, 5 to 7 min when the render test has to build too |
| full | quick; `conf-stress-light`, `conf-stress-heavy`, `conf-stress-extreme`, `conf-stress-lossy`, `conf-stress-contended` (0.8.0) (one check and one conformance run each, cleaned up in between); `debug-p2`, `debug-p3`, `audit-stop`, `audit-core`, `uring-status`, `uring-boots`, `tracer-record`, `tracer-qa`, `debugger-live`, `stealth`, `cloud`, `snapshot`; `uring-legacy` and `tracer-legacy` on the old base; interop in both directions (`io-old-new-*`: the old host with BASE; this host with the old base: `io-new-old-audit` and the two legacy checks, since an old guest lacks what the other checks need) | about 2 h 10 min plus, the first time, about 15 min to build the old host; the five stress groups take 80 to 95 min of it (light 5-7, heavy 10-24, extreme 35-56, lossy 4-13, contended 14-17) |

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

As of 2026-10-23, the stress-heavy telemetry drops and intermittent slow
transport reconnect are deferred to 0.7.1. They are known 0.7.0 limitations,
not passing zero-loss or reconnect-latency guarantees. Historical failures,
retries and explicit release-qualification exclusions are preserved.

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
* **Non-stop debugger input polling.** `debug/rsp_client.rs` previously polled
  guest events before reading every packet byte, including bytes already buffered
  by the socket. Long feature queries and repeated ELF-header reads could exhaust
  a command-group deadline. Each turn now drains up to 256 input bytes within a
  2 ms time slice, ending at a complete packet or control byte. Guest events,
  panel requests and shutdown are serviced between turns. The existing initial
  stop deferral supports GDB 16/17's startup ordering. A real-socket regression
  counts guest polls for a buffered 2 KiB write, without a wall-clock assertion;
  command deadlines and debugger signal/exec semantics are unchanged.
* **Phase-three fork and legacy exec fixtures.** The parent-follow case delivers
  a queued SIGCHLD before continuing to its next fork. The `exec-gated` fixture
  waits for stdin until the host confirms attachment to the original image,
  avoiding a late attach to the replacement image. Its assertion still requires
  `Replaced`, and the fork case still verifies child identity, breakpoint bytes
  and exit status. No guest change is needed for these fixture corrections.
  A non-followed exec is recorded when the new image is installed, and that
  replacement remains the session's cause after the new image exits. Asking
  for status only once the replacement has finished must report `Replaced`.
  On the previous guest this reported `Exited` for both revision 17 and the
  revision 18 BusyBox image. The launch's own exec is still its entry stop,
  and a followed exec still stops inside the new image. The wire values are
  unchanged.
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

### Guest patch series by topic (0.7.1)

The 60 guest patches, written in development order (0004 alone was 40% of the
series, 23 had no description, io_uring was spread over five patches), are
regrouped into fourteen topic patches, each with a description of what it adds,
why, which kernel files it hooks and why there, and its contract revision. The
licence patch for the shared headers stays separate (0002). Mapping, file map,
how the two copies relate and how to verify a rewrite:
`src/antinomie/patches/README.md`. Series numbers elsewhere in this document
and in `CHANGELOG.md` before this entry are the old ones.

The patched source tree matches the 60-patch one (checked by applying both to
the pristine Debian source and `diff -r`; see below for the one comment), so
the contract stays at revision 17. The series hash changes, so `CONFIG_ANTINOMIE_SOURCE_ID` of a new
kernel and the kernel cache key do; hosts do not pin it. Each patch builds on
the ones before it. One comment in `native_capture.c` named an internal ticket;
it now reads "never read, by design", the only difference from the 60-patch
tree.

### Architecture-neutral guest patches (0.8.0)

The shared patches no longer assume x86-64; x86-64 behaves as before. The
series is nineteen patches (`src/antinomie/patches/README.md`, "Architectures"):

* **Per-architecture headers.** Patch 3 is now x86-64's two headers in its own
  tree: `arch/x86/include/asm/antinomie_syscalls.h`, the generated native table
  (`scripts/generate-native-syscalls.py --arch x86_64`, which still writes
  `protocol/native-syscalls.json`, unchanged), and `arch/x86/include/asm/antinomie.h`:
  the ABI of a system call being entered (native, x32, or ia32 without a table),
  the ABI name in layout names (`ANT_LAYOUT()`, `ANT_COMPAT_LAYOUT()` in
  `<linux/antinomie_monitor.h>`) and whether a task has a 32-bit address space.
* **Syscall identity.** Every decoder, the field rules and every syscall check
  of the recorder use the kernel's `__NR_` names, never numbers; the extended
  attribute family is decoded by what each call does instead of number ranges.
  The x86-only decoders (arch_prctl, modify_ldt, uretprobe, the rt_sigreturn
  signal frame, x86 ptrace requests) moved to `capture_x86.c`, which
  `native_capture.c` asks for any call it has no family for.
* **Portable helpers.** The exit hook reads the result with
  `syscall_get_return_value()`, the debug engine the PC with
  `instruction_pointer()`, the x86 decoders the stack with `user_stack_pointer()`;
  the core reader checks `ELF_ARCH`.
* **Architecture hooks in one patch.** Patch 15 holds every change to
  architecture code (`arch/x86/entry/common.c`, `arch/x86/kernel/setup.c`,
  `arch/x86/boot/compressed/kaslr.c` and the x86 EFI stub). `capture_x86.c` and
  `debug_x86.c` stay in `kernel/antinomie/` and are built for x86-64 only: the
  stealth section labels bracket that directory, and the symbols of a file under
  `arch/` would be listed in `/proc/kallsyms`.
* **Handshake.** After INFO the host asks a revision-17 guest for the debug
  engine's CAPS and takes its ELF machine (offset 4, 62 for x86-64) as the
  guest's architecture; an older guest is x86-64. No new wire field: an INFO
  flag was tried first and dropped, because a 0.7 guest counts a refused flag as
  a bad command (the conformance groups and the health view then report one)
  and a 0.7 host rejects a nonzero reserved word in INFO. The host keeps the
  architecture in `GuestKernel::arch` (recordings without it read as x86-64),
  decodes x86-64 guests only, and on another architecture says why and refuses
  launches. (0.9.0 adds arm64: see the arm64 section.)

"No behaviour change" was checked by comparing the recorder's objects before
and after, and by running the conformance and stress groups on bases built from
both series.

### Per-architecture schema sets and portable shared guest code (0.8.0)

Groundwork for arm64 guests (multi-arch plan cards MA-02 and MA-03); x86-64
decodes and records exactly as before.

* **Schema sets.** Each architecture the host ships has a folder
  `src/antinomie/monitor/protocol/<arch>/` with its native table
  (`native-syscalls.json`), its captured layouts (`captured-layout-members.json`)
  and its constants (`constants.json`). The x86-64 files moved there unchanged;
  `aarch64` is new. The generators take `--arch`
  (`scripts/generate-native-syscalls.py`: x86_64, aarch64, riscv64, with
  CLONE_BACKWARDS argument order on the asm-generic architectures;
  `scripts/generate-filter-layouts.py`: x86_64, aarch64, Clang's target ABI over
  that architecture's UAPI, its own `capture_<arch>.c` only) and write to the
  arch's folder by default.
* **Constants.** The host's decoding tables (flag groups, selector names, socket
  options, errno and signal names) keep x86-64's values. A constants file lists
  where another architecture differs (`changed`), which names x86-64 defines and
  it lacks (`absent`) and its own names a group gains (`additions`), with its
  ELF machine and class, byte order, data model, `AUDIT_ARCH_*` value and layout
  prefix. `scripts/generate-arch-constants.py` evaluates every constant name the
  host sources use with libclang over the arch's installed-UAPI view, one header
  at a time, and compares it with x86-64's evaluation; x86-64's own file is empty
  in those three parts. For aarch64: `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT`,
  `O_LARGEFILE` and `O_TMPFILE` differ; `MAP_32BIT`, `SHADOW_STACK_SET_TOKEN`, the
  `ARCH_*` codes and the x86 ptrace requests are absent; `PROT_BTI`, `PROT_MTE`
  and `PTRACE_PEEKMTETAGS`/`PTRACE_POKEMTETAGS` are added. Names no UAPI header
  defines (the kernel-internal `MSG_*` and `SOCK_*` values) keep their generic
  value. All 1023 x86-64 literals the UAPI defines matched it when checked.
* **Host loader.** `syscalls::Abi` has `X86_64` and `Aarch64`; each table carries
  its `Constants`, and flag names (`Table::argument_flags`) and selector names
  (`Table::selector_name`, keyed by the call's name instead of its x86-64
  number) read values through it. The free functions keep using the native
  (x86-64) table, so callers are unchanged; no guest architecture maps to
  `Aarch64` yet. Argument values of C type `long` and `off_t` render by the
  table's data model.
* **Shared guest code.** Legacy calls the asm-generic architectures lack (open,
  stat, rename, poll, select, signalfd, sysfs, getdents ...; also arm EABI's and
  mips o32's few: getrlimit, newfstatat, kexec_file_load) are guarded with
  `#ifdef __NR_<name>` in place, in the topic patch that names them;
  `CONFIG_ANTINOMIE` depends on `HAVE_ANTINOMIE`, which x86-64 selects with its
  definitions (patch 3); `ANT_ARCH_NR_BASE` (0 on x86-64) is the first native
  number the recorder indexes its table from; the core reader checks the native
  ELF class and byte order (`elfhdr`, `ELF_CLASS`, `ELF_DATA`).

### Guest architecture contract, machines and arm64 builds (0.8.0)

Multi-arch plan cards MA-04 to MA-08: the contract, host and tooling an arm64
guest needs. x86-64 guests record, decode and snapshot as before; the host
still starts x86-64 VMs only (arm64 VMs start with MA-16).

* **ARCH_INFO (contract revision 20).** A new control opcode (0x1022, header
  only, 128-byte reply, `protocol/control.h`): the guest's ELF machine, class
  and byte order, page shift, the system call ABIs its records may carry, the
  first native call number and table size, user address bits, the debug
  engine's CAPS flags, the native table id (SHA-256 of the
  `protocol/<arch>/native-syscalls.json` the guest was built with; the
  generator emits it as `ANT_NATIVE_TABLE_ID`) and the layout set
  (`linux-6.12.94/<arch>`). The guest side is patch 0030. A host sends it only
  to a guest whose INFO revision is 20 or later, because an older guest counts
  an unknown opcode as a bad command. Revision 20 also defines
  `ANTC_CORE_NATIVE_ELF32` (process cores of 32-bit guests) and the CAPS flags
  `SW_SINGLE_STEP` and `READ_WATCH`.
* **Transport ABI 10.** 64-bit little-endian guests keep ABI 9 byte for byte.
  ABI 10 is the same LP64 layout with every field little endian, for 32-bit
  and big-endian guests. Its `POS32` profile bit is for 32-bit guests, which
  have no 64-bit atomics: queue positions and counters carry their low 32 bits
  and each reader widens them next to a position it already knows.
  `tests/monitor/transport-reconnect.c` runs the host simulator on both
  profiles.
* **Host handshake.** The host reads `GuestArch` (ELF machine, class, byte
  order) from ARCH_INFO on a revision-20 guest, from the debug engine's CAPS
  on revision 17 to 19, and takes x86-64 for older guests. It warns when the
  guest's table id or layout set differs from its own schema set. x86-64 is
  still stored as `"X86_64"`, so older settings and recordings read
  unchanged. A run records its architecture in `RunEnvironment.arch`, written
  only for non-x86 runs, so x86 environment hashes do not change. The Runs tab
  names a non-x86 architecture, and an upload whose ELF machine differs from
  the VM's gets a note.
* **Machines.** `vm::Machine` is `Pc` (q35/i440FX, `qemu-system-x86_64`) or
  `Virt` (`virt,gic-version=3`, the `qemu-system-aarch64` next to the
  configured QEMU). It supplies the RAM layout (virt: one piece at 1 GiB), the
  default bootstrap page (RAM base + RAM/2, page aligned: 0x60000000 for a
  1 GiB arm64 VM), the memory map check (virt reads the `shared` backend region
  from `info mtree -f`), the serial console (`ttyS0` or `ttyAMA0`) and the
  machine identity that full snapshots check (x86's string is unchanged). An
  arm64 VM needs at least 512 MiB of RAM, because QEMU's initrd or the
  firmware's allocations reach the middle of smaller RAM, and is refused with
  a message otherwise. `ARM64_TIME_SCALE` (8, from the MA-09 TCG
  measurements) is set in one place, `vm/machine.rs`. Bundles name their
  architecture (`"arch"` in `bundle.json`, x86-64 when absent).
* **arm64 kernel builds.** `scripts/build-monitor-kernel.sh` takes
  `ANTINOMIE_ARCH=x86_64|arm64`, with per-architecture fragments in
  `src/antinomie/packaging/kconfig/<arch>/`. `ANTINOMIE_CONFIG_ONLY=1` stops
  after the configuration has been resolved and checked. The container image
  pins the aarch64 and armhf cross toolchains, `qemu-user-static` and `dtc`.
  The adapter holds Debian's arm64 banner (`KERNEL_BANNER_ARM64`).
  `build-base.py` jobs take `"arch"`, and the kernel identity names the
  architecture for arm64 only. The QEMU builder VM installs the arm64 tool
  packages for arm64 jobs. No arm64 image recipe exists until MA-15.
* **Regression tiers.** `scripts/vm-regress.py --arch arm64` cross-builds the
  fixtures with `aarch64-linux-gnu-gcc` (`CC` in the fixture build scripts),
  scales every timeout by `ARM64_TIME_SCALE` (read from `vm/machine.rs`), lists the
  groups that are not ported yet (`ARM64_LATER`: debugger, cloud, interop,
  stress-extreme) as not planned, and names the architecture in the
  report. Conformance goldens for arm64 live in `golden/aarch64/`. The
  stealth probe measures arm64 without its CPUID and I/O port checks (its
  timing checks read the virtual counter, `cntvct_el0`); the snapshot check
  gives an arm64 VM 2 vCPUs and 1 GiB and scales its waits.
* **Old bases and old hosts in the tiers.** An old host refuses a base of a
  newer contract revision before it boots it. That is its intended guard, so
  when BASE's revision (`bundle.json`) is newer than the old host's (`REVISION`
  in its `control.rs`), the `io-old-new-*` checks are reported as SKIP, not
  applicable, and do not fail the tier. `tracer-legacy` needs a guest from
  before the tracer's hash records. It runs on `--legacy-base` (default
  `$ANTINOMIE_LEGACY_BASE`, else `--old-base` when that base is revision 17 or
  older), by convention the 0.7.0 BusyBox base
  (`tests/monitor/conformance/README.md`).

### arm64 guests: core, BusyBox base and launch (0.9.0)

Multi-arch plan cards MA-10, MA-13, MA-15 and MA-16 (BusyBox first). Contract
revision 20 is unchanged: the wire carried the architecture since 0.8.0.

* **Guest series.** Patch 31 makes the generic EFI stub, which arm64 boots
  through, claim the bootstrap page (`antinomie_boot_gpa=`) before the kernel
  image is placed. Patch 32 adds `arch/arm64/include/asm/antinomie.h` and the
  generated native table (318 calls, the same table id as
  `protocol/aarch64/native-syscalls.json`). Patch 33 hooks `el0_svc_common()`
  around `invoke_syscall()` (AArch64 and AArch32 calls), takes the boot options
  after `setup_machine_fdt()`, reserves the bootstrap page after
  `arm64_memblock_init()`, writes the cleaned command line back into the device
  tree's `/chosen/bootargs`, and adds `antinomie_kpti=` (the "faster emulation"
  switch); `capture_arm64.c` decodes the rt_sigreturn frame (with
  `extra_context`) and the MTE tag ptrace requests; `debug_arm64.c` is a stub
  (ATTACH returns EOPNOTSUPP until MA-11). Patch 34 reads clone()'s child TID
  pointer from the fifth argument where `CONFIG_CLONE_BACKWARDS` puts it, and
  names the field `arg4.child_tid` there, as the arm64 schema numbers it.
  Patch 36 fixes never-drop waits on kernels without `CONFIG_PREEMPT_COUNT`
  (arm64's voluntary preemption, as in Debian's arm64 configuration): every
  sender looked atomic there and gave up after the 200 us atomic spin, so a
  host read gap with a full ring dropped a packet; a sender with interrupts on
  now spins for the whole progress-sensitive send wait (it cannot sleep: a
  held spinlock is invisible without the count). x86-64 compiles it out.
  Patch 38 retries the recorder's no-fault reads on CPUs without the hardware
  access flag (ARMv8.0: QEMU's DT boots and a Raspberry Pi 4 use a
  Cortex-A72). There a present page whose entry is old faults, and fork makes
  every page of the child old, so a forked child's execve had no path, argv
  or envp recorded (seven Triage rules missed on the behaviour samples). A
  failed read is retried once after the present, old pages of its range are
  marked accessed as the access-flag fault would, in task context and without
  waiting for `mmap_lock` (`user_read.h`, `user_read_arm64.c`); off arm64 the
  header defines nothing and x86-64's objects are identical.
  Patch 35 renames the debugger's `set_state()`: arm64's build inlines
  `kernel/stop_machine.c`'s function of that name, and pahole described it under
  the recorder's symbol (`check-kernel-btf.py` caught it).
* **Kernel configuration.** The minimal profile resolves arm64 with
  `mod2noconfig` (arm64's defconfig makes about 1150 modules a BusyBox base never
  loads). What a module would have given and x86-64 builds in is listed in
  `kconfig/arm64/minimal.cfg`: IPv6 (Debian has it built in; nftables' inet
  family needs it) and the iptables tables and conntrack. `!NAME` turns a symbol
  off (`PREEMPT`: Debian's arm64 banner says SMP).
* **BusyBox arm64 base.** `build-monitor-image.py --arch arm64` takes its
  userland from Debian 13's pinned arm64 packages (`ARM64_USERLAND`:
  busybox-static, e2fsprogs and the libraries resize2fs and chattr load,
  glibc's loader), as an x86-64 base takes its own from the amd64 ones, through
  the archive's signed index from snapshot.debian.org and cached by SHA-256
  (`--package-cache`); the libraries go to `usr/lib/aarch64-linux-gnu`.
  Applets come from BusyBox's packed name table, so the build needs no
  emulation. The console is `ttyAMA0`; the bundle says
  `"arch": "arm64"`.
* **Launch.** `vm/virt.rs` builds QEMU's `virt` machine under TCG:
  `cortex-a72` with the device tree, `neoverse-n1` with AAVMF (pflash code and a
  per-VM variable store; a device profile's machine sets its own CPU, see
  "arm64 device profiles"), SATA through ich9-ahci, virtio-gpu with xHCI keyboard
  and tablet, shown on the in-app VM screen (VNC on the runtime folder's unix
  socket, display `none`) or in the QEMU window as the VM's screen setting says
  (`VirtDisplay::window`; the GTK check applies to the window only). The
  accelerator is always TCG (`launch_accel`), so every wait of the start and
  the shutdown deadline are the TCG waits of `accel::Waits`.
  `VmLaunchOptions::fast_emulation` (serialized only when set, so x86 VM files
  and snapshot identities are unchanged) boots with `antinomie_kpti=off`; the VM
  dialog offers it for arm64 bases, and the VM summary lists what still tells
  an arm64 VM apart (`StealthProfile::giveaways_for`).
* **Host decoding.** `GuestArch::supported()` includes arm64. Events carry host
  syscall ids (`syscalls::id`: the ELF machine in the high bits; x86-64's tag is
  0, so its ids are its numbers): the live assembler, the archive readers
  (`Recording::guest_arch()` from the run's environment), io_uring request
  equivalents (by the ring owner's table) and struct member filters (the
  record's own ABI layouts) all name calls by the guest's table. Views and the
  query's `syscall.num` show the wire number.
* **Conformance.** The trace fixture builds for aarch64: legacy calls are under
  `#ifdef SYS_<name>` (with traced generic replacements where later cases need
  the result), x86-only requests under `__x86_64__`, and the signal trampoline,
  clone's argument order, the pkey rights bit, `epoll_event` and `semid64_ds`
  are per architecture. The x86-64 fixture is the same program as before (its
  preprocessed source is unchanged). The example converts the fixture's numbers
  into the base's ids, walks the base's table in the coverage matrix, scales its
  waits by the guest's time scale and gives an emulated guest at most 2 vCPUs
  and 1 GiB. arm64 goldens live in `golden/aarch64/`.
* **Process cores.** The guest accepts a core of its own ELF machine; the core
  reader (`core_dump.rs`) opens aarch64 cores (`CoreDump::machine`, serde
  default x86-64 for saved records) with aarch64's `user_pt_regs` names
  (`x0`..`x30`, `sp`, `pc`, `pstate`); disassembly stays x86-64 only (MA-14).
  arm64's minimal kernel has no transparent huge pages, as x86-64's: with them
  a sparse heap was dense, and so was its core (the audit core qualification).
* **Known gap.** The raw `/sys/firmware/fdt` (root only) still shows the
  `antinomie_*` boot options (MA-18).

### AArch32 programs on arm64 guests (0.9.0)

Multi-arch plan cards MA-33a and MA-34: the arm EABI (ILP32) programs most
Linux IoT samples are run on an arm64 guest (`CONFIG_COMPAT`) and are traced
like its own programs. Contract revision 20 is unchanged: ARCH_INFO's ABI mask
already defines bit 3, compat.

* **Schema set.** `protocol/arm/` holds the arm EABI table
  (`generate-native-syscalls.py --arch arm`, from `arch/arm/tools/syscall.tbl`
  and arm's private `__ARM_NR_*` calls), its captured layouts and its constants
  (ILP32, little endian, `audit_arch` 40000028). A 64-bit argument takes an
  aligned register pair, so a row's arguments are registers (`pos_lo`,
  `pos_hi`). A row that is an x86-64 call by another name carries its
  `family` (`send` is `sendto`, `stat64` is `stat`, `setuid32` is `setuid`), for
  the rules, which key on names. A row the guest captures as an aarch64 call
  carries its `native` number: the same arguments by name and objects of one
  layout on ILP32 and LP64 (strings, bytes, 32-bit and fixed-width values,
  `sockaddr`, time64 values); ioctl, fcntl, prctl, clone, ptrace, socket
  options, seccomp and io_uring never are.
* **Guest (patch 37).** arm64 defines `ANT_ABI_COMPAT` (3); the recorder
  includes the generated `asm/antinomie_compat_syscalls.h` and records an
  AArch32 call with its arm number and ABI 3. Its arguments are its registers'
  low halves, with the 32-bit signed ones sign-extended. A call with a native
  counterpart is captured by the native code under the native number (file
  activity, exec, credentials and network captures included); `execve` and
  `execveat` read their vectors as 32-bit pointers (`linux-6.12.94/arm/pointer`).
  prctl's options whose objects have one layout (`PR_SET_NAME`, `PR_GET_NAME`,
  int results, `PR_SET_VMA`'s name) are captured by the native code too.
  Any other call has its path strings captured and its other pointers recorded
  by address. Everything is under `#ifdef ANT_ABI_COMPAT`: x86-64's objects are
  identical.
* **Host.** `syscalls::Abi::Arm` (id tag 40) is aarch64's `compat()` ABI: the
  assembler names ABI-3 records of an arm64 run by it, struct member filters
  read a natively captured field with aarch64's layouts and number, rules see a
  call by its `family`, and `long`/`off_t` arguments render by the call's own
  data model. A result is the 32-bit register the program sees: -4095 to -1
  is an error, any other value is unsigned (an `mmap2` address above 2 GiB is
  that address; the guest records the register sign-extended).
* **Not supported.** The guest writes no process core of a 32-bit program (the
  run says why), and the debugger does not attach to one.

### ia32 programs on x86-64 guests (0.9.0)

Board card "Decode 32-bit x86 (ia32) system calls" (evaluation run 1, B1):
XorDDoS and Rex are i386 programs. An x86-64 guest recorded their calls with
ABI 0 (numbers only) and the host read the numbers as x86-64 ones: i386's
`rt_sigaction` (174) and `rt_sigprocmask` (175) became `create_module` and
`init_module` (a false `persistence.module` per process), schema gaps for
nearly every call, no exec of their children ("?" processes). The AArch32
machinery above now serves ia32 too; contract revision 20 is unchanged
(ARCH_INFO's ABI bit 3, compat, is set on x86-64 guests with
`CONFIG_IA32_EMULATION`).

* **Schema set.** `protocol/i386/` holds the i386 table
  (`generate-native-syscalls.py --arch i386`, from
  `arch/x86/entry/syscalls/syscall_32.tbl`), its captured layouts
  (`linux-6.12.94/x86/`, x86-64's `ANT_ARCH_COMPAT_LAYOUT`) and constants
  (ILP32, `audit_arch` 40000003). A 64-bit argument takes two consecutive
  registers (the `sys_ia32_*` entries already name the halves, `pos_lo`,
  `pos_hi`); clone has `CLONE_BACKWARDS`' order. Rows carry arm's `family`
  names where i386 shares them (`stat64` is `stat`, `mmap2` is `mmap`,
  `setuid32` is `setuid`) and the x86-64 `native` number of 264 calls with the
  same arguments and objects of one layout.
* **Guest (patch 42).** x86-64 defines `ANT_ABI_COMPAT` with
  `CONFIG_IA32_EMULATION`: an ia32 call (`in_ia32_syscall()`) is recorded with
  its i386 number and ABI 3, its arguments the registers' low halves, by the
  code patch 37 added (now compiled on x86-64; the compat ABI's `__NR_` names
  come from `ANT_COMPAT_UNISTD`/`ANT_COMPAT_NR()` of the architecture header).
  i386 programs reach the socket calls through `socketcall(call, args)` (Debian
  13's i386 glibc, built for kernels from 3.2, does; so does Go): such a call
  is recorded as the direct i386 call it makes, its arguments read from its
  array (`accept` as `accept4` without flags, `send` and `recv` as `sendto`
  and `recvfrom` without an address, as `net/socket.c` makes them), with a
  `socketcall.call` field; an unreadable array leaves the socketcall itself.
  On x86-64 only `kernel/antinomie/recorder.o` (the compat code) and
  `control.o` (ARCH_INFO's ABI mask gains bit 3) change; arm64's objects are
  unchanged.
* **Host.** `syscalls::Abi::I386` (id tag 3, `EM_386`) is x86-64's `compat()`
  ABI: the assembler names ABI-3 records of an x86-64 run by it (x32's, and an
  older guest's ia32 records of ABI 0, keep their numbers as before), struct
  member filters read natively captured fields by the x86-64 call's layouts
  and number, and results, argument vectors (4-byte pointers) and data models
  follow the AArch32 rules above.
* **Check.** vm-regress's `tracer-ia32` (x86-64 full tier) runs
  `tests/monitor/ia32-fixture.c` built with `gcc -m32 -static` and for x86-64
  (`ANTINOMIE_IA32_CC` picks the compiler) and checks each behaviour (mkdir,
  open, write, stat, rename, unlink, connect and sendto through socketcall,
  `PR_SET_NAME`, the child's exec) is recorded in both, the ia32 run's own
  calls by the i386 table, none unnamed or raw. `tracer-check` honours
  `ANTINOMIE_FORCE_TCG` (eight times the waits) for hosts without KVM.
* **Not supported.** No process core of an ia32 program; `ipc`, the old
  `mmap` and `select` (argument structures) and the 32-bit time calls record
  their pointers by address only; the debugger does not attach to an ia32
  program.

### x86-64 debugger: forked children (0.9.0)

Board card "x86 debugger: a forked child inherits planted INT3 breakpoints".
A child the program forks with its own memory and that the debugger does not
follow inherited the INT3 bytes of inserted breakpoints: it took a SIGTRAP at
one (killed, or, under the SIGTRAP handler anti-debug code installs, resumed
one byte into the replaced instruction). Patch 43 defines
`ANT_DBG_FORK_REPAIR` for `CONFIG_X86_64` too, so `ant_dbg_fork()` puts the
program's own bytes back in such a child before it runs, as patch 39 does on
arm64 (threads, vforks and followed children are as before; only
`kernel/antinomie/debug.o` changes). debug-p2's `forkbp` now fails when a
child met the parent's breakpoint (the fixture's child exits 3 when its
SIGTRAP handler ran).

### Contract revision 21: generic ioctls, CET status and the fatal signal's sender (0.9.0)

Board cards "Guest decoders for undecoded ioctls and arch_prctl" and "Record the
sender of a fatal signal". Revision 21 adds fields and decoders only: every
field a revision-20 guest wrote is unchanged, and a revision-20 base still runs
on this host (it records neither). An older host refuses a revision-21 base.

* **Generic file ioctls (patch 44).** The ioctl argument was decoded for
  terminal requests on a tty only; FIONREAD on a socket or pipe, FIONBIO and
  `chattr`'s FS_IOC_SETFLAGS were NO_DECODER gaps (about 400 in a 51,000-call
  benign run). `ioctl_field()` now also decodes the requests
  `fs/ioctl.c` `do_vfs_ioctl()` answers for every file, before any driver: an
  `int` written at exit on success (FIONREAD, also for a file that is not
  regular, whose handler writes one by convention; FIGETBSZ), an `int` read at
  entry (FIONBIO, FIOASYNC), an `unsigned int` (FS_IOC_GETFLAGS at exit,
  FS_IOC_SETFLAGS at entry: the request encodes a `long`, the kernel copies an
  `unsigned int`), a `loff_t` (FIOQSIZE). FIOCLEX, FIONCLEX, FIFREEZE, FITHAW
  ignore the argument and FICLONE's is a descriptor: no field and no gap. Any
  other request keeps its NO_DECODER marker. The code is shared, so arm64
  (same request numbers) decodes them too; compat (ia32, AArch32) ioctls keep
  their address-only capture.
* **arch_prctl ARCH_CET_STATUS (patch 44, x86-64).** 0x3001, the query of the
  CET patches mainline did not take, which glibc 2.28 to 2.38 built with CET
  sends at start-up, was an unknown-selector gap. Linux 6.12 answers EINVAL;
  the recorder names it as known and would record its three `u64` (features,
  shadow stack base and size) at `arg1.cet_status` on success. The host names
  it `ARCH_CET_STATUS`.
* **Who sent the fatal signal (patch 45).** The task-exit record held only the
  wait status, so a report could not name who sent SIGKILL. The guest keeps
  one record per thread group in the group leader's recorder state
  (`struct ant_fatal_signal` in the LSM blob, no stock structure changes),
  written and read under the group's siglock:
  * at the send, when the send starts the group exit (`__send_signal_locked()`
    after `complete_signal()`: SIGKILL, which is never queued with a siginfo,
    and fatal signals nothing catches): `si_code`, `si_pid` and `si_uid` as the
    kernel fills them for the target, and, when a call sent it from process
    context (`SI_USER`, `SI_TKILL`, `SI_QUEUE`), the sending task's global
    TGID, UID and `comm`; `SEND_SIG_PRIV` is `SI_KERNEL` with no sender;
  * else at the delivery of a fatal signal (`get_signal()` before its `fatal`
    label: core-dumping signals, a fatal signal a debugged or ptraced task
    gets), from the siginfo the task dequeued;
  * the OOM killer (`mm/oom_kill.c` `__oom_kill_process()`, after its log
    line) marks its victim's record and keeps that line ("Out of memory:
    Killed process ..." or "Memory cgroup out of memory: ...").

  The first record of a group stays. `ant_monitor_task_exit()` adds, when the
  task's wait status names the recorded signal, scalar fields
  `lifecycle.signal.signo`, `.code`, `.pid`, `.uid`, `.origin` (1 send, 2
  delivery), `.sender_pid` and `.sender_uid` with a string
  `.sender_comm` when the sender is known, `.oom` and the string
  `lifecycle.kernel_log` for an OOM kill, to the same event as
  `lifecycle.task_exit` (the archive index keeps classifying the event by
  that first field).
* **Host.** `fatal_signal::FatalSignal` reads the record
  (`InvocationSummary::task_exit_signal()`); the process tree keeps it beside
  the end signal, and Triage's note on killed tasks names the sender: the
  recorded call when it was the same sender (call and time), else the sender
  by pid, name, uid and whether it is in the recorded tree, the kernel, a fault,
  a timer, or the OOM killer with its line. The inference text stays for tasks
  without a record (a revision-20 base says so).
* **Limits.** A process that shares the OOM victim's memory but is another
  thread group gets the same SI_KERNEL SIGKILL without the OOM mark; the kernel's
  other kill messages (seccomp, a fault's "segfault at" line) are not copied;
  a sender's `comm` is read without its task lock, as printk's users read it;
  after an exec by a thread other than the leader the record stays with the
  old leader.

### arm64 debugger (0.9.0)

Multi-arch plan cards MA-11 and MA-14: the debug engine, the RSP server, the
Debugger tab and gdb-multiarch on aarch64 programs of an arm64 guest. Contract
revision 20 is unchanged; one breakpoint kind is new within it (below).

* **Guest (patch 39).** `debug_arm64.c` replaces the stub. A software
  breakpoint is `BRK #0xa71`, an immediate no other Linux user of BRK takes, so
  a program's own BRK keeps its SIGTRAP; shadow reads hide it as on x86. A step
  is the hardware step (MDSCR_EL1.SS with SPSR.SS), armed as ptrace arms it and
  cleared from the saved PSTATE before anything can read it; a stepped SVC is
  reported at the call's exit (`syscall_trace_exit()`). Breakpoints and
  watchpoints are perf hardware events (up to 4 of each, one pool of 4 slots in
  the engine). This Debian 6.12.94 has no `register_user_break_hook()`, so the
  engine is called from `do_el0_brk64()` and `do_el0_softstep()`
  (`debug-monitors.c`) and `syscall_trace_exit()` (`ptrace.c`). Register sets:
  NT_PRSTATUS (`user_pt_regs`, 272 bytes), NT_PRFPREG (`user_fpsimd_state`,
  528) and NT_ARM_TLS (8). An AArch32 program is refused at attach.
* **Stops before the access.** arm64 takes breakpoint and watchpoint
  exceptions before the instruction or its access completes, so a watch stop
  reports the accessing instruction (on x86 the one after it), and resuming
  there would take the exception again. The engine resumes such a thread with
  its debug registers off for one step, as the kernel steps a suspended
  breakpoint, and `try_step_suspended_breakpoints()` turns them on again. When
  the debugger itself steps from that stop (gdb does after every aarch64 watch
  stop: its watchpoints are non-steppable), the step is the engine's: it is
  forced and passed on to `do_el0_softstep()`, where the engine ends it.
  Without that, the kernel ended the step itself, the engine never saw it and
  the program ran free: watchpoints looked as if they never fired.
* **Unfollowed fork children.** A BRK does not advance the pc. A forked child
  the debugger does not follow, with its own copy of the program's memory,
  gets the program's own bytes back where the engine's are before it runs: it
  would otherwise take a SIGTRAP, and under a SIGTRAP handler trap at the same
  BRK for ever (x86-64's INT3 leaves the pc after it; x86-64 is unchanged).
* **Load-only watchpoints.** `ANTC_DEBUG_BP_HW_READ` (5) watches loads alone.
  It is a capability-gated addition to revision 20: only a guest whose CAPS
  have READ_WATCH (the arm64 engine) accepts it, and the host sends it only to
  such a guest, so older hosts never send it and x86-64 guests never offer it.
  gdb's `Z3` (rwatch) is served only with READ_WATCH: x86-64 still refuses it
  (`read_watchpoints_are_served_only_where_the_guest_offers_them`), and a
  read watch stop is reported as `rwatch:`.
* **Host.** `ArchTag::Aarch64` gives gdb the aarch64 core, fpu and TLS target
  description, and the panel the arch's register names (pc, sp, x29). The
  panel's length-1 instruction breakpoints become 4-byte ones. The Debugger
  tab's code pane decodes aarch64 with Capstone (the `capstone` crate built for
  arm64 alone, BSD-3-Clause; x86-64 keeps iced-x86, so x86 output is
  unchanged); every A64 instruction is one word, so the rows before the pc are
  exact, and a word Capstone cannot decode is shown as `.inst 0x...`. A manual
  process core of an arm64 program is checked against the guest's machine, as
  the guest's own cores are.
* **Qualification.** `debug-check gdb` runs gdb-multiarch on the aarch64 P1
  fixture (break, stepi, hbreak, rwatch, watch, tbreak, detach, then exit,
  kill, debugger death and interrupt). `debug-check p2` and `p3` run on arm64
  bases with aarch64 builds of their fixtures (`fixtures-arm64/debug`), and the
  arm64 tier plans `debug-p2` and `debug-p3`. The checks read the base's
  architecture from its bundle.json and scale every guest wait by
  `ARM64_TIME_SCALE`. Where aarch64 differs, they check its behaviour: a watch
  stop is at the accessing instruction, `step_rep` steps a nop (there is no
  repeated string instruction), the smc fixture rewrites `mov w0, #v`, the
  anti-debug probe counts the enabled NT_ARM_HW_BREAK/WATCH slots of a traced
  child and looks for BRK, not INT3, in its code.
* **Not supported.** AArch32 programs on an arm64 guest are not debugged.

### arm64 device profiles (0.9.0)

Multi-arch plan cards MA-17 and MA-18: what an arm64 VM presents of the
machine. The x86 catalog's machines are PCs, so an arm64 VM presents an arm64
machine of its profile's kind instead (`stealth/arm64.rs`, catalog
`stealth/catalog/arm64.rs`, sources and classes in `SOURCES-arm64.md`):

* **Which machine.** Realistic server: an Ampere Altra server (Giga Computing
  R272-P33, HPE ProLiant RL300 Gen11). Cloud VPS: an AWS EC2 Graviton2
  instance, its type (`t4g.nano` ... `t4g.2xlarge`) from the VM's vCPUs and
  memory. Desktop, laptop and custom profiles: the ADLINK Ampere Altra
  Developer Platform with UEFI, a Raspberry Pi 4 Model B or Pi 5 when the
  profile's firmware is BIOS. The pick is stable for a VM (its UUID), and an
  identity whose `profile` names an arm64 machine keeps it. Transparent, or the
  identity turned off, keeps QEMU's own identity as before.
* **UEFI machines** (servers, workstation, cloud) boot AAVMF whatever the
  firmware entry says (the host check finds AAVMF, `HostSupport::detect_arm64`;
  before, the x86 OVMF check made every arm64 VM fall back to the device tree).
  The CPU is QEMU's `neoverse-n1` with the machine's MIDR (Neoverse N1 r3p1)
  and timer frequency (`-cpu neoverse-n1,midr=,cntfrq=`); `-machine
  virt,x-oem-id=,x-oem-table-id=` sets the ACPI OEM IDs; SMBIOS types 0, 3, 4
  (ID = MIDR, family ARMv8, the machine's maker, version and speed, Neoverse
  N1's caches as type 7), 16 and 17 are written whole and types 1 and 2 given
  as options, so no field keeps QEMU's value and none is the host's. The disk
  is SATA with the machine's model (QEMU's NVMe controller names itself QEMU),
  the network card Intel's 82576 (`igb`, the driver of the boards' I350 and
  I210) with the machine's MAC prefix (a cloud's: random, locally
  administered). An x86 cloud provider's metadata service and instance state
  are not used for arm64 VMs (a start-log note says so).
* **Boards** boot on QEMU's device tree, disguised: the launch dumps the tree of
  the same machine, CPUs and memory (`-machine dumpdtb=`), `stealth/fdt.rs`
  reads it, the root gets the board's model, compatible list and serial number,
  the nodes only QEMU's virt has (fw_cfg, the virtio-mmio slots, the platform
  bus, flash, PL061 and its power key) are taken out, the UART, RTC and GIC
  nodes get a board tree's names (`serial@`, `rtc@`, `interrupt-controller@`,
  with `stdout-path` and the aliases following), and QEMU boots it with `-dtb`
  (it still writes `/chosen`). The CPU is the board's (`cortex-a72` r0p3 or
  `cortex-a76` r4p1) at 54 MHz. A UEFI machine whose UEFI cannot boot (no AAVMF,
  or a base without UEFI support) is shown as a board.
* **Guest facade** (patch 0040). `/proc/device-tree/chosen/bootargs` already
  showed the kept command line (0033); root's `/sys/firmware/fdt`, the
  flattened tree as the boot loader gave it, now shows a copy with the same
  bootargs (`ant_fdt_shown()`, from `of_fdt_raw_init()`), on device-tree and
  UEFI boots alike (the EFI stub writes the command line there too). The virt
  machine's ACPI virtio-mmio slots and flash (LNRO0005, LNRO0015) are not
  scanned, as QEMU's own devices are not. The arm64 minimal kernel has no KVM:
  under TCG it boots at EL1, and KVM's init line would say "HYP mode not
  available".
* **One identity.** `/proc/cpuinfo`'s CPU part and revision, the SMBIOS
  processor and DMI name the same machine; a run's machine record and the VM
  summary name the arm64 machine (`arm64::shown_profile`).
* **What stays** (`StealthProfile::giveaways_for`, `arm64::giveaways`): TCG
  timing; QEMU's ACPI tables to root (BXPC creator ID, virt's DSDT); the
  network card and the ICH9 AHCI controller are not the machine's (no ENA or
  NVMe for EC2); a board's tree still has virt's GICv3, ECAM PCIe host and
  devices; the virt PCIe host bridge (Red Hat ID); virtio-gpu; a fresh boot.
* **Measured** by `stealth-check measure` with the probe's aarch64 checks
  (`arm.cpu` MIDR against the firmware's processor, `arm.cntfrq` (62.5 MHz is
  QEMU's), `dt.model`, `dt.nodes`, `fdt.raw`, the LNRO ACPI names); on arm64 an
  L2 without L3 (Neoverse N1) and EDK II firmware (Ampere's, AWS's) are not
  giveaways, and neither is the absence of SMBIOS and EFI on a device-tree
  boot. The x86 probe is byte-identical (.text, .rodata, .data).

### arm64 qualification, limits and Debian arm64 Minimal (0.9.0)

Multi-arch plan cards MA-19 and the Debian half of MA-15. No contract change.

* **Device profile window.** `app/stealth.rs` takes the base's architecture
  (`Fit::new(.., arch, fast_emulation)`): an arm64 VM's host check is
  `HostSupport::cached_arm64()` (AAVMF, no Secure Boot, no two-threads entry),
  Still visible is `giveaways_for(arch, fast_emulation)`, and
  `app/stealth/arm64.rs` replaces the PC catalog with the arm64 machines
  (`arm64::presented()`: the machine the VM shows when it can or cannot boot
  UEFI; picking a board sets BIOS, a UEFI machine UEFI) and the x86 CPU
  settings with the machine's CPU (MIDR, timer). `base_supporting()` offers
  only bases of the current base's architecture.
* **Unsupported features say so.** The Memory tab (`memory_view/plugins.rs`
  `foreign_guest`) of a VM whose base is not x86-64 shows a warning instead of
  plugins: Volatility 3 and MemNixFS read x86-64 guest memory only and arm64
  bases carry no symbol table (`build-base.py has_symbols`). Static Analysis
  (`analysis/worker.rs` `x86_tool_refuses`) marks capa and FLOSS Unavailable
  for an ELF program of another machine than x86 or x86-64 (their code
  analysis, vivisect, has no ARM); PE files and scripts still go to the tools.
  The Run form warns when either is chosen on an arm64 guest
  (`LaunchCapabilities::guest_arch`).
* **Full tier on arm64** (`vm-regress.py full BASE --arch arm64`): every check
  but `ARM64_LATER` (debugger-live, whose GEF/pwndbg session types x86-64
  registers; uring-legacy and tracer-legacy, which need a base from before
  0.9.0; stress-extreme), with timeouts times `ARM64_TIME_SCALE` (8). The
  route and specimen probes are cross-built for arm64; `cloud` expects the
  arm64 instance's identity (an arm64 Cloud VPS is an AWS Graviton2 instance
  without a metadata service, so those checks print SKIP). Interop on arm64 is
  `io-old-arm64-refused`: the old host (`--old-host`, 0.8.0) runs
  `snapshot-check` on the arm64 base and passes only when it fails with its
  refusal (`ARM64_REFUSAL`: "does not start arm64 VMs", or a base of a newer
  revision), before QEMU runs.
* **Build kit.** `monitor-core/build.rs` `KIT_FILES` carries every repository
  file the kit's scripts read (0.8.0: the kconfig fragments per architecture,
  the BTF and ABI checks, Debian's x86-64 module-signing certificate), and
  Debian's arm64 certificate, which the kernel script names as `$signing`;
  `kit.rs` checks the list against the paths the scripts name, both
  certificates for `$signing`.
* **Debian 13 arm64 Minimal.** The stock kernel profile builds for arm64:
  Debian's `config` + `arm64/config`, Debian's arm64 build certificate
  (`module-signing-arm64.pem`, serial 39896D98..., the signer Debian's arm64
  modules name) and the uncompressed `Image` (Debian's arm64 vmlinuz is the
  Image, so no compression symbol is set). As Debian's arm64 build does, it
  names the 32-bit ARM compiler (`CROSS_COMPILE_COMPAT=arm-linux-gnueabihf-`,
  the AArch32 vDSO) and links against the arm64 C library (`CC_CAN_LINK`):
  without them the configuration lacked `COMPAT_VDSO` and the BTF Debian's
  `__vdso_init`, its prototype and a two-entry `vdso_info`. The minimal profile
  keeps its own configuration. Guest patch 0041 does for arm64 what 0022 does
  for x86-64, so the BTF is Debian's type for type: do_coredump()'s exit hook
  is an unlikely branch on arm64 (GCC then keeps Debian's out-of-line
  `__percpu_add_case_32`), kernel/exit.c's exit hooks take an int-only entry
  (no `const kernel_siginfo` among exit.c's types, which renumbered the types
  after it) and setup.c's device-tree bootargs helper lives in the recorder
  (no `const device_node` among setup.c's types); on x86-64 the macros expand
  to the hooks as before and the objects are unchanged. The ABI check reads an
  arm64 call site 8 bytes before its function (call ops), and a header inline
  GCC keeps out of line in several stock files (`__raw_spin_lock_irq`) is no
  recorder name clash.
  Debian's arm64 System.map is a stub (it names the -dbg package), so
  `check-kernel-abi.py` finds the BTF in Debian's Image by its header (exactly
  one complete blob) and takes the exports, licences and CRCs from the
  `Module.symvers` of `linux-headers-6.12.94+deb13-arm64` 6.12.94-1 (pinned by
  SHA-256 from the same snapshot, read by the build only). The
  image recipe (`build-debian-image.py --arch arm64`) bootstraps `arm64` with
  Debian's `linux-image-6.12.94+deb13-arm64` and `linux-image-arm64` 6.12.94-1
  (linux-signed-arm64, pinned from the same trixie-security snapshot), the
  arm64 netinst's sources.list name, no boot loader on the device-tree disk and
  the installer's `grub-efi-arm64` with `shim-signed` (shimaa64) in the UEFI
  copy; the initrd's programs are the BusyBox arm64 base's pinned packages and
  it loads Debian's root modules (crc32c-intel is x86's). A bootstrap of another
  architecture than the machine's runs only in the QEMU builder VM
  (`ANTINOMIE_BUILDER=1` and its qemu-user binfmt handler): `build-base.py`
  refuses it natively and before a container starts, and the app picks the
  QEMU builder for it (`build::arch_mode`; `BuildRequest.arch`, a job's
  `"arch"`, kernel and root filesystem caches of their own); its builder VM
  installs `arch-test`, without which mmdebstrap refuses a foreign bootstrap.
  The container builder builds it too when this host has an enabled
  `qemu-aarch64` binfmt handler with the F flag (the kernel holds the emulator
  open and starts it inside the container's root, where none is installed):
  `build-base.py require_foreign_builder(.., container=True)` and
  `build::arch_mode` (`foreign_handler`) check it and refuse otherwise with
  what is missing and both ways out (the pinned `tonistiigi/binfmt` command or
  the QEMU builder); Automatic picks a container only with the handler, else
  the QEMU builder. The container gets `ANTINOMIE_FOREIGN_BINFMT=qemu-aarch64`,
  which `build-debian-image.py foreign_bootstrap` accepts in place of a
  visible handler (a container has no binfmt_misc of its own), and the image
  pins `arch-test`. A native build still never bootstraps another
  architecture.
  A VM of such a base gets its account in a provisioning boot of its own (next
  section): the x86-64 libguestfs appliance cannot run the guest's arm64
  programs.

### Guest accounts on Debian arm64: the provisioning boot (0.9.0)

Multi-arch plan card MA-15 (Debian half). No contract change; the x86-64
provisioning is unchanged byte for byte (`guest_account/tests.rs`
`the_x86_appliance_script_is_pinned` hashes the appliance's script for a
whole-disk, a BIOS and a UEFI disk, the later edits, the probe and the
uploaded helpers, against the digest of the 0.8.0 code).

On x86-64 the appliance runs the guest's own programs on the disk (`sh` with
adduser, chpasswd, grub-install, the initramfs helper). For a base of another
architecture (`GuestAccount::create`/`provision` with a
`guest_account::ProvisionBoot`, made from the bundle by `for_bundle`: None for
x86-64) `guest_account/foreign.rs` splits the work:

* **Appliance, offline (no guest program).** The probe; a read-only pass that
  downloads fstab and `/etc/network/interfaces` to a private host folder and
  asks which of `BOOT_TRACES` the disk already has; then one writable pass:
  the layout (`layout_commands`, the same as x86-64), the ESP's `mkfs vfat` on
  a GPT disk, `e2fsck-f`, `set-uuid` and the debugfs hash-seed reseed, fstab
  with the root's new UUID and the swap line (`fstab_text`, edited on the host
  as the x86-64 sed and awk do; a test runs both over the same files), the
  NIC stanza (`interfaces_text`, likewise), the machine ID, the staging script
  in a 0700 `/root/.provision-<id>` with the initramfs helper, a oneshot
  service and a target (`unit_files`) linked with `ln-s`, and the GPT GUIDs or
  MBR disk identifier.
* **The provisioning boot.** QEMU `virt` under TCG, two `cortex-a72` vCPUs (no
  pointer authentication to emulate), 1 GiB, the base's kernel and initrd with
  the disk's command line (`vm_kernel_append` with the new UUID) plus
  `console=ttyAMA0 panic=-1 antinomie_kpti=off
  systemd.unit=provision-<id>.target`, the disk on virtio, `-nic none`, no
  display, `-no-reboot`, nothing recording it (no bootstrap page). The target
  isolates the service (`DefaultDependencies=no`, `ConditionPathExists=` on
  the script, `SuccessAction=`/`FailureAction=poweroff-force`, output to the
  serial console only), so no journal, utmp, random seed, timer or tmpfiles
  unit runs. The script (`guest_script`) does the x86-64 script's guest part
  in its order: root remounted read-write, the account as the installer's
  adduser makes it, `passwd -l root`; on a GPT disk the ESP's UUID into fstab
  and `grub-install --target=arm64-efi --force-extra-removable --no-nvram`
  with `update-grub` (the device-tree disk has no boot loader, as the base);
  on a partitioned disk the initramfs's resume device (`initrd_resume.py`);
  then `modprobe qemu_fw_cfg` and the password (a reset: the recorded hash,
  `chpasswd -e`) read once from
  `/sys/firmware/qemu_fw_cfg/by_name/opt/antinomie/provision/raw` straight
  into chpasswd. The host passes it with `-fw_cfg
  name=opt/antinomie/provision,file=<private 0600 file>` (`fw_cfg_option`) and
  deletes the file as soon as the guest prints (QEMU has read it at machine
  creation), and at the end in any case: the password is never on the disk,
  a command line or the console (the private console log goes with the
  host folder). The script prints the hash the guest stored between
  `provision-hash-begin` and `provision-hash-end`, or `provision-failed
  <step>` when a step fails, and the VM powers off.
* **Host.** `console_report` takes the hash only from between the markers (the
  last pair, one line); a failed step, a boot without a report, a QEMU error
  or more than `BOOT_TIMEOUT` (15 minutes) is a plain error naming the step or
  the time, and creation removes the VM. The hash is validated (and on a reset
  must equal the record's); then the appliance removes what the boot left
  (`trace_commands`: the staging folder, the unit, its target and link, the
  journal folder of the VM's machine ID, and each `BOOT_TRACES` path the disk
  did not have before), so the first boot the user sees is the disk's first
  after the installer.

Measured on the VPS (16 vCPUs, no KVM, loaded): the provisioning boot took 22 s on
the device-tree (MBR) disk and 28 s on the UEFI disk (grub-install included),
from QEMU's start to its power-off, while another TCG VM ran beside it;
creating the VM through the app (probe, read, write and trace passes, the
boot) and starting it took 75 s and 147 s (the second laying out the base's
UEFI disk first). The 15-minute `BOOT_TIMEOUT` leaves a slow host ample room.

After creation an arm64 disk is edited by the appliance alone: a moved NIC's
stanza is downloaded, rewritten and uploaded (`set_interface_foreign`); a new
disk bus changes only the record (arm64 has no GRUB for BIOS, so no debconf
answer). On `virt` the NIC of a base that names it by slot sits at 00:19.0
(`enp0s25`) whatever the profile, also beside an arm64 machine's own card
model (`provisioned_interface` with the base's architecture; the PC slots mean
nothing there and the display takes the first free slots).

### Fair, progress-sensitive send waits (0.8.0)

Guest patch 1 (`transport/guest.c`, `ant_send`); transport ABI and contract
revision unchanged.

* **Cause** (found in 0.7.0, see "Checks that failed under load"). In never-drop
  mode a sender that found its CPU's ring full slept 50 to 100 us between looks
  and dropped after the whole send wait (5 s by default). Meanwhile the other
  senders on that CPU took the room the host freed, so under a flood of short
  calls one waiter could lose every race and drop although the host kept
  reading: stress-heavy lost 2 of 13.7 million records that way, stress-light 2
  in this release's baseline.
* **Turns.** A sender that may sleep and must wait takes a turn (a per-CPU
  ticket) and stays on its CPU while it waits (`migrate_disable()`, so the turn
  stays that ring's). Freed room goes to the waiters in turn: a sender that may
  sleep and finds others waiting queues behind them instead of taking it. A
  sender that may not sleep (atomic context) never queues; it takes room when
  there is some and otherwise spins at most 200 us, as before.
* **Progress-sensitive wait.** The send wait now ends only when the host has
  taken nothing from that CPU's ring for the whole wait it set (or is not live,
  or the ring faulted): a sender waits as long as the host keeps reading. A
  queued sender gives up in its turn, so the ones behind keep theirs; they see
  the same dead host or idle ring. Drops and partial events are reported as
  before (`attempted`, `dropped`, `waits`, `wait_ns`; recorder loss marks).
* **Qualification.** The full tier has a fifth stress group,
  `stress-contended`: ant-workload at heavy with a 256 KiB never-drop ring and a
  100 ms send wait, where senders find their ring full all the time. It is a
  measurement, not a pass criterion: a sender still drops when the host reads
  nothing from its ring for the whole 100 ms, which a busy build machine causes
  (`writer_held_ms` counts only waits for the recording writer; the host's
  read gaps are timed separately, see "Telemetry read gaps"). Measured on 2026-10-28 with no writer hold: 38 drops in
  10.5 million records at load ~10, 1 in 13.7 million at load 4.5-8; before the
  change 737 in 7.4 million. The drops were each followed by at least 105 ms in
  which no new guest event began on any CPU, so they were host read gaps, not
  lost races. vm-regress attributes each drop to a host read gap and fails the
  group only for a drop no gap explains.

### Handing a full ring's turn on (0.8.0)

Guest patch 26 (`kernel/antinomie/guest.c`, `ant_send`, ANT-T0203); transport ABI
and contract revision unchanged (nothing changes on the wire).

* **Cause.** A sender waiting for its turn learnt that its turn had come only
  when its own 50 to 100 us sleep ended. Once a ring had filled, the senders of a
  busy program kept finding others queued and stayed in turn, so each CPU sent
  about one packet per sleep however fast the host read. Measured with
  `stress-rate` (below) on 2 vCPUs: 5,153 calls/s, 25.8 k packets/s (77 us per
  packet per CPU), every thread waiting all the time (313,808 waits, 119.8 s of
  120 s thread time), while the ring was full for only 0.59 s in all and the
  host's persist path takes 871,669 packets/s (`replay-bench`).
* **Change.** Senders sleep for their turn on a wait queue of their CPU
  (`ant_producer.turns`); the sender that ends its turn, by sending or by giving
  up, wakes the one whose ticket is next (a keyed wake function passes over the
  others). The sleep is bounded at 1 ms, so a wake-up that never comes costs at
  most that. Waiting in its turn for room still polls the ring every 50 to 100
  us, since the host empties the ring without telling the guest. The wait and
  drop rules are unchanged: a sender still gives up only in its turn, after the
  host took nothing from the ring for the whole send wait.
* **Measurement.** `stress-rate` (conformance trace group, vm-regress full
  tier `conf-stress-rate`): `ant-workload --level extreme --only syscall-load`
  (two threads per vCPU in a loop of cheap calls for 30 s) on the default
  never-drop transport (1 MiB rings, 5 s send wait), 2 vCPUs and 2 GiB, the
  shape of the real-malware evaluation VM. vm-regress prints its calls and
  packets per second, drops and send waits; the group fails under 20,000
  calls/s (four times the convoy's rate, a quarter of the rate after the change,
  so a busy host passes; 10,000 on an emulated arm64 guest, twice the convoy's
  sleep-bound rate: 18,330 calls/s under TCG on a loaded 12-thread host), and on
  every other problem a stress group fails on.
  On 2026-11-01, same host, base revision 20:

  | | Before (0.8.0 series to 25 and 30) | After (patch 26) |
  | --- | --- | --- |
  | Calls in 30 s | 158,300 (5,153/s) | 2,492,254 (82,676/s) |
  | Packets/s, MiB/s | 25,777, 5.3 | 413,391, 85.6 |
  | Transport drops | 0 of 791,807 | 0 of 12,461,581 |
  | Send waits | 313,808, 119.8 s | 2,773,118, 104.0 s |
  | Full-ring spells | 6, 0.59 s | 59, 43.7 s |

  Before, the threads waited all the time with an almost empty ring; after, they
  wait because the ring is full: the host's drain (85.6 MiB/s here) is the limit.

### Lost telemetry per run (0.8.0)

The guest numbers every packet a task tries to send (`packet_seq`, per task),
whether or not it is sent. The host follows the numbers of each run's tasks
(`telemetry_loss.rs`, up to 1,048,576 tasks) in the pump and in the pre-ack
claim; a number missing between two that arrived is a lost packet. Packets after
a task's last arrived one, and tasks none of whose packets arrived, leave no gap,
so the count is a lower bound; a run continued after a transport reconnect
starts a new count. At the end of the run the count goes into the final
`manifest.json` (`telemetry_loss`: `received_packets`, `lost_packets`,
`untracked_packets`) and, when packets were lost, into a run note starting
`Telemetry lost:`. The views show that note as a warning over the run (Trace,
Run History details, Triage) instead of a muted note, and the run report puts
it first in the run overview (HTML, PDF, Markdown, JSON `notes`).

### Telemetry read gaps (0.8.0)

Host only; the guest and the contract are unchanged (`transport/host.c` gained
a diagnostic getter and a starvation guard, see below).

* **What is timed.** `Health.read_gaps` (`read_gaps.rs`) records every pause
  between two read attempts of the transport thread that lasts at least half
  the guest's send wait (10 to 50 ms), and every ring whose head packet waited
  that long while the host read other rings. Per pause: the guest time it
  started at (the newest packet timestamp read, which compares with packet
  timestamps without a clock mapping), the host wall time, the length, the ring
  (ring pauses) and a cause. At most 256 pauses are kept (the shortest give
  way); the count, total and longest cover all. Cost: one clock read and one
  thread-local read per read attempt, two `pread`s of
  `/proc/thread-self/schedstat` per drain pass, no allocation, lock or log per
  read.
* **Causes.** Writer backlog (the pass started held back for the recording
  writer); writer wait (the thread waited in the writer's queue); drain pass
  work (inside a pass, processing or flushing, not reading); not scheduled,
  other host work, blocked (outside the pass, by the thread's run-queue delay
  and CPU time); ring not served (the host read, but not this ring).
* **Where it shows.** The run report (`accounting.read_gaps`,
  `accounting.dropped_packets`, `transport.configured_send_wait_us`) and
  Summary > Health > details ("Telemetry read gaps": count, longest, the
  causes that took the most time).
* **Attribution.** The conformance scan finds each task's missing packet
  numbers with the timestamps of the packets on both sides and of the task's
  next event. vm-regress ties a drop to a gap (or, for a ring pause, a pause
  of the ring the task sent on) of at least the send wait that contains the
  drop's time window or overlaps it by the wait (20 ms of timestamp skew
  allowed). `conf-stress-contended` passes when every drop is attributed and
  fails on one that is not; drops the scan cannot locate (the end of a task's
  numbering) count as unattributed. Timestamps are when an event began, so a
  fragment of a long event looks older than it was sent: windows are widened
  to the task's next event.
* **Causes found (2026-10-28, load 9-15 on a shared host).** (1) Ring
  starvation: `ant_read_ordered` merges the rings by the smallest head
  timestamp, and the fragments of one long event keep the event's start
  timestamp, so a ring holding newer packets was not served while another
  ring's fragments flowed: 53 pauses of 100 ms or more in one run, 762 drops
  all attributed to them or to writer holds. (2) The recording writer behind
  the disk (the data drive, itself under load): 33 s held in a 3 minute run, with pauses
  of up to 14 s; a hold longer than the send wait drops by design.
  (3) The transport thread not scheduled (run-queue delay of 60 to 300 ms
  under load 10 to 15) or doing 100 to 150 ms of other host work in one loop
  pass (several 30 to 50 ms steps: the 250 ms snapshot publish, resource
  sampling, terminal reads). Guest sends only wait 100 ms in this group.
* **Full-ring spells and clock lag (second cause).** A host that keeps reading
  but drains slower than the guest sends keeps a ring full for the whole send
  wait without any pause. `ant_ring_state` (host.c, two loads per ring) lets
  the tracker look at each ring's fill at every read attempt; a ring at 90 % or
  more at each attempt is a spell, recorded when it ends if it lasted half the
  send wait (`FullSpell`: start in guest time, length, ring, bytes read and
  written meanwhile, lowest fill; same 256 slots as the pauses). A gap or spell
  is placed in guest time by the newest packet read, but that packet waited in
  its ring: `skew_ns` (host clock minus the packet's timestamp) minus
  `clock_skew_min_ns` (the smallest over the run, the clocks' offset) is how far
  the guest clock was ahead, and vm-regress also tries each gap and spell moved
  later by that lag. A drop is reported as: in a read gap, in a read gap only
  after the lag, in a full-ring spell, or neither (a failure). In the 2026-10-28
  contended run at load 9-15, 60 of 289 gap-explained drops matched only after
  the lag and none needed a spell (the drops were the writer's holds); the
  15 of 19 unexplained drops of an earlier run were not kept, so they were
  not classified.
* **Fix.** `ant_read_ordered` now takes a ring whose head has waited 10 ms
  before the timestamp order applies (the longest waiting first), so no ring
  is kept from the host for longer while another is read. Records of one ring
  stay in order; across rings the merge can be up to 10 ms off for a starved
  head. Not fixed (proposed): the other host work in the transport loop
  (publish, resource sampling) should drain between steps or move to another
  thread.

### File positions and in-kernel copy operands (0.8.0)

Contract revision 18 (guest patch 16, `kernel/antinomie/fileops.c`; layouts in
`protocol/control.h`). Two kernel-imported fields of a call's Exit, only for
native calls that succeeded on seekable files (regular files and block devices):

* **`file.position`** (`antinomie.filepos/1`, 24 bytes: u64 offset, u64
  length, u64 write order) on read, write, pread64, pwrite64, readv, writev, preadv, pwritev,
  preadv2 and pwritev2. `vfs_read()`, `vfs_write()`, `vfs_readv()` and
  `vfs_writev()` report where the transfer left the position, and the record
  holds where it began (that position less the result). It is the open file's
  real position: a descriptor shared after fork, dup or SCM_RIGHTS moves for
  every task that uses it, and an `O_APPEND` write (or `RWF_APPEND`, or a
  pwrite on an `O_APPEND` file) lands at the end of the file as the write found
  it under the inode lock, which the host could not infer.
* **Write order** (in `file.position` at 16 and `file.copy` at 96): a number
  from one guest-wide counter, taken in `generic_write_checks_count()`, which
  ext4, tmpfs, btrfs and xfs run while holding the file's inode lock, just
  before the write is applied. The position hooks run after the file system
  dropped that lock, and the Exit event is stamped later still, at the end of
  the call, so two processes writing one range at once can have their exits
  recorded in the opposite order to the one the file system applied them in;
  the write order is the applied order. A call that writes in pieces (a splice
  into a file) keeps its first piece's number. Zero when there is none: a read,
  a block device (no inode lock), a clone or an allocation.
* **`file.copy`** (`antinomie.filecopy/1`, 104 bytes) on sendfile, splice (the
  file side; a splice between a pipe and a socket has none), copy_file_range,
  ioctl `FICLONE`/`FICLONERANGE` and fallocate (and the preallocation ioctls):
  the kind, the source and destination (device, inode, generation, mode),
  where the range began in each end that has positions, its length, the
  destination's size after the call and, for fallocate, the `FALLOC_FL_*`
  mode. When the destination is seekable and the source is not (the pipe of
  a splice; sendfile and copy_file_range refuse a source that is not seekable,
  so a socket reaches a file through a pipe), nothing can read the bytes again
  later, so the bytes the destination got follow as **`file.copy.data`** (opaque bytes, from
  `iter_file_splice_write()` while the pipe still holds them), at most 1 MiB per
  call; past it the record's `DATA_CUT` flag says more went in. A seekable
  source is not carried: the host rebuilds the bytes from what it knows of that
  file. `FIDEDUPERANGE` (no content change) and io_uring's splice and fallocate
  requests are not recorded.

The hooks fill the task's recorder context during the call and the Exit
publishes the fields, so a call gets no extra event; a position costs one field
(three packets, about 550 bytes with the ANTT headers) on the Exit of each read
or write of a file. The hooked functions are shared with io_uring and exec, so
each hook checks the call number. The patch is shared by every architecture
(only `__NR_` names of calls every 64-bit table has).

Host: `kernel_notes::{file_position, file_copy}`. Triage's per-file history
takes a read's or write's offset from the record when it has one (so File
activity places `O_APPEND` and shared-descriptor writes instead of counting
them as at an unknown offset), and applies a copy to the destination's known
bytes exactly: only the copied range is dropped, carried bytes are placed (and
listed as the destination's written content, read from the object store),
punched or zeroed ranges read as zeros, a collapsed or inserted range drops the
bytes after it, and the file's size is the record's. A recording from an
earlier guest has no records and is read as before. Overlapping writes are
replayed by write order: in File activity's write store
(`file_writes::Writes::add_ordered`, a numbered write goes under any later
numbered one that reached the host first, never past an unnumbered one) and in
the per-file change bytes (`triage/files/order.rs`, the last 64 numbered writes
of a file are remembered and a write keeps out of the bytes a later-applied one
holds). The conformance suite's
`file_pos` area checks the records (`pos`, `nopos`, `copy` oracle members): a
forked child's write through the parent's descriptor, a dup, racing `O_APPEND`
writers whose offsets the parent reads back from the file, two processes
writing the same range at once (16 rounds; the parent reads which write each
round's bytes are, and the judge requires the other one's write order to be
lower, the `before` member), and each copy call.

### Writes through shared file mappings (0.8.0)

Contract revision 18, extended before its release (guest patch 17,
`kernel/antinomie/filemap.c`; layout in `protocol/control.h`). A store into a
writable `MAP_SHARED` mapping of a file changes the page cache with no system
call. The kernel takes note of such stores only through the page table entry's
dirty bit, and consumes it in two places, which are where the pages are
recorded, in the context of a traced task:

* **Writeback** (cause `WRITEBACK`): `folio_clear_dirty_for_io()`, when
  `folio_mkclean()` found a mapping's entry for the folio dirty or writable,
  inside a traced call (msync with `MS_SYNC`, fsync, fdatasync,
  sync_file_range, sync, syncfs, an `O_DIRECT` transfer or fadvise that
  flushes the cache first). The folio is locked and its mappings are
  write-protected, so the copy is what goes to the file. On tmpfs msync writes
  nothing back and records nothing; the pages come with the unmap.
* **Unmap** (cause `UNMAP`): `zap_present_folio_ptes()`, for a dirty entry of
  a file page of a `VM_SHARED` mapping, when a traced task removes it (munmap,
  mremap, a `MAP_FIXED` mapping over it, madvise, a hole punch, exec dropping
  the old address space, exit dropping the last). The dirty bit moves to the
  page, which the file system writes back later; the copy is the page as the
  mapping left it.

Every architecture keeps that dirty bit and every file system has it (tmpfs
has no `page_mkwrite` and is never written back), so the patch hooks only
generic memory-management code. A `page_mkwrite` hook was not used: it sees the
first store after each writeback, before the store lands, and nothing on tmpfs.

**`lifecycle.file_mapped`** (`antinomie.filemap/1`, 96 bytes per range): the
cause, the file (device, inode, generation, mode), the range (offset of its
first page, length: whole pages, the last clipped to the file size; pages past
the end of the file are not recorded), the bytes copied and why the rest is
missing (`BUDGET`, `MEMORY`), the page size, the file size and the time
(`ktime_get_ns()`) when the first page was copied, a write order, the record's
index and count, and loss counters. The copied bytes follow as
**`lifecycle.file_mapped.data`** (opaque, the declared extent is the range's
length). A call's records are one lifecycle event (phase 3, so the recording
index keeps them with their call) published just before its exit; the address
space a task drops in `exit_mm()` has no exit to go before, so its records are
published just before `lifecycle.task_exit`, under the task's last call.

Copies are made where the kernel sees the page, without sleeping (under the
page table lock for an unmap, the folio lock for a writeback): one page each
from a `GFP_NOWAIT` allocation, at most `ANTC_FILEMAP_DATA_MAX` (4 MiB) per
call and `ANTC_FILEMAP_RANGES` (64) ranges per call; contiguous pages of one
file coalesce. Past the budget, or with no page to be had, the range is still
listed with the reason; pages past the ranges are counted (`unlisted`), and
pages for which not even the list could be allocated are counted (`lost`) and
reported in the next record.

**Write order.** Each range takes a number from the counter writes use
(`fileops.c`, File activity 3), and every page of the range is copied while
holding the file's inode lock shared with `down_read_trylock()` (never waits,
safe under the page table lock). A write takes its number and applies its bytes
under that lock held exclusively, so every write with a lower number is
complete in the copy and none with a higher number has begun; replaying the
higher ones over the copy gives the bytes they left. When the trylock fails a
write is in progress: the page goes to a range without a number, and the host
places it in call order.

**What is not seen.** Only the result of the stores at writeback or unmap,
never each store: two stores to one page before its writeback leave the second.
A page the kernel's background writeback (the flusher, by default some 30 s
after the store) wrote back while the mapping stayed, and that was not stored
to again, is clean when the mapping goes, so it has no record; that writeback
runs outside the program's calls. A page stored to by a process that is not
traced is seen only when a traced call writes it back. Mappings of the kernel's
internal mounts (`SB_KERNMOUNT`: shared anonymous memory, System V shared
memory, memfd, AIO rings) are not files of the run and are skipped; hugetlbfs
mappings are removed by other code and are not seen.

**Hash.** A shared writable mapping holds its open file (opened for writing),
so the file's last close, which the guest hashes for a run that asks for it
(`lifecycle.file_hash`, `antinomie.hash/2`), is the munmap or the exit that
drops the mapping, and the hash covers the content the stores left (the worker
reads the page cache). No change was needed there; the conformance suite checks
it.

Host: `kernel_notes::file_mapped` decodes the records (with the object id of
their data field). Triage applies the records of a call before the call's own
change (a hole punch's zeros, an `O_SYNC` write) and the exit-time records
after the last call: the per-file history (`triage/files/mapped.rs`) lays the
copied pages over the file's known bytes by write order, takes the file size
from the record and says what is unknown; File activity lists each range as a
write of the file (`<call> · mapping`, "page state at writeback/unmap; stores
in between not seen") and places it in the written content as
`file_writes::Piece::Mapped` (the byte map's `~~ mapping` state), with the
uncopied part `NotCaptured(MappedBudget | MappedMemory)`; the per-file and
per-run caps apply as to writes. In the File Reconstruction timeline
(`file_reconstruct`), an `mmap` with `PROT_WRITE` and `MAP_SHARED` of the file
is an `Action::Mapping` over its range (`~~`, may have changed with no further
call), and each record is an `Action::Write` of its extents at its write order:
copied pages become written bytes (their history says "written through a shared
mapping"), uncopied ones not captured, and pages of the mapping the guest never
saw dirty stay `~~`, which is the honest state for a page the background
writeback may have cleaned. An msync that carries records no longer adds
the old "mapped writes are unavailable" entry. The conformance suite's
`file_mmap` area checks the records (`mapped` oracle member: exactly the pages
stored to, with their bytes and a write order) for an msync, a later munmap, a
child that exits with the mapping in place (its shared anonymous page must not
be reported) and a mapping past the copy budget, and the last-close hash
against the bytes read back (`hash`).

### Captured fields decoded by their type (0.8.0)

Contract revision 18, extended before its release (guest patch 18). The trace
renders a captured field by its descriptor's encoding and layout, never by
whether its bytes look like text. Four kinds of field still
had no layout although the kernel copies a fixed native one; patch 18 names
them, with the object encoding (3), and leaves the bytes and extents as they
were: `gid_t[]` (getgroups, setgroups), `linux_dirent[]` and
`linux_dirent64[]` (getdents, getdents64: the records the call filled, each
with its own `d_reclen`), and `desc_struct[]` for modify_ldt's reads (x86-64,
`capture_x86.c`: `read_ldt()` copies the 8-byte descriptors themselves and
`read_default_ldt()` zeros; a write's `user_desc` is a different layout). The
netfilter set options were all labelled `ipt_replace`; only
`IPT_SO_SET_REPLACE` (and `IP6T_SO_SET_REPLACE`, the same header) passes one,
`*_SO_SET_ADD_COUNTERS` passes `xt_counters_info`.

Host: `monitor-core/src/typed_fields.rs` decodes a field's preview (its first
256 captured bytes, the range covered from offset 0) at explicit little-endian
offsets of the pinned 64-bit UAPI layouts. It never follows a pointer (a
pointer member is the address the program passed), never trusts a length or
count inside the data past the bytes present, leaves out members past the
capture and marks a field that holds more than it decoded; reserved and padding
members are not shown.

| Layout | Decoded as |
|---|---|
| `sigset_t` | signal names; more than half set reads as the complement, `~[...]` |
| `sigset_argpack` | pselect6's `{ss, ss_len}` |
| `siginfo_t`, `siginfo_t[]` | `si_signo`, `si_errno` when set, `si_code` by name, then the union branch the kernel's `siginfo_layout()` picks from the signal and code (kill, timer, rt, child, fault with its MCE/BND/PKU/perf variants, poll, sys) |
| `sigevent` | `sigev_notify`, then what that branch uses (`sigev_signo`, `sigev_value`, `sigev_notify_thread_id`; for SIGEV_THREAD, mq_notify's netlink form, the descriptor and cookie) |
| `stack_t` | `ss_sp`, `ss_flags` by name, `ss_size` |
| `bpf_attr` | the members of the branch bpf's command selects (every command of 6.12.94; BPF_LINK_CREATE's tail by attach type), map, program and attach types by name |
| `cap_data[]`; capget/capset `arg0.version`, `arg0.required_version`, `arg0.pid` | effective, permitted and inheritable sets by capability name; the header version by name |
| `uid_t`, `gid_t`, `gid_t[]`, `uid_t[2]` | numbers |
| `linux_dirent[]`, `linux_dirent64[]` | `d_ino`, `d_off`, `d_reclen`, `d_type` by name, `d_name` per record |
| `file_handle` | `handle_bytes`, `handle_type` by name (the handle bytes are a separate opaque field) |
| `io_uring_params` | entries, setup flags and features by name, both rings' offsets |
| `msgbuf` | `mtype`, `mtext` (every byte, quoted) |
| `ipt_replace`, `xt_counters_info` | table name, hooks by name, entry count and size, hook entries and underflows, counter count (the rules are not decoded) |
| `user_desc`, `desc_struct[]` | LDT entry fields; an unused descriptor reads `empty` |

The trace (`trace::fields::preview_in`) shows the decoded line (cut past 240
characters) in the Info column, the argument rows and the field tree, and the
selected field's pane lists every member; any other field keeps its byte
rendering. Triage's BPF view lists each bpf call's attr members and reads a
load's `insn_cnt` and an attach's `attach_bpf_fd` from them (before, it looked
for fields of those names, which the guest never sends), so an attach of a
program loaded earlier in the run is named. The conformance render marks a
decoded field (`decoded`), and the golden files keep it, normalising only the
addresses, kernel handles and the IDs of members named for a process or thread.

Filter keywords (`captured-layout-members.json`, `scripts/generate-filter-layouts.py`):
every branch of `union bpf_attr` is now qualified by the commands that read it
(`args.attr.map_fd` for the element commands, `args.attr.query.attach_type`,
`args.attr.batch.count`, ...), walking each anonymous record at its own offset;
before, only some members were qualified, by name alone, so `attach_type` and
`bpf_fd` also carried the offset of a same-named member of another branch
(PROG_QUERY's, OBJ_GET_INFO_BY_FD's). BPF_LINK_CREATE's tail, which its attach
type selects, stays unqualified. `io_uring_params`, `gid_t[]` and
`xt_counters_info` gain keywords; unnamed bit-field padding (in `timex`, which
had an empty-named keyword) and `resv` words are left out. The generator reads
the capture sources' `__NR_` names (it had read only numbers since the syscall
rows were named, so a regeneration dropped every macro-row layout) and the x86
capture file, and cleans `linux/compiler.h` from every UAPI header it includes.
`ipt_replace` stays unsupported there (its header pulls libc's `sys/socket.h`),
as do the siginfo/sigevent union members (their selector is a member, not an
argument) and `sigset_t` (captured under `signal.mask`, not an argument key).

Not decoded: get_thread_area/set_thread_area (ENOSYS on x86-64 guests), the
iptables rules after the table header, the opaque handle bytes, `sigaction`
and the other structures not listed.

### Record arrays and Decode all captured (0.8.2)

A captured field that is an array of fixed or self-sized records opens as a list of
`Record`s (`monitor-core/src/typed_fields/arrays.rs`; `Records::open`), which the
Syscall Trace draws as an expandable tree (`monitor-ui/src/trace/record_tree.rs`).

* **Table.** One `Spec` per layout in `typed_fields/arrays/table.rs`: the record size
  (fixed, or read from its header: a directory entry's `d_reclen`, a control message's
  `cmsg_len`), the decoder (`arrays/decoders.rs`, `arrays/classic.rs` for
  classic BPF) and the one-line summary a collapsed record shows. Another
  architecture adds table rows; nothing else names x86-64, and only the x86-64 layouts
  are decoded now. eBPF instruction text is `typed_fields/ebpf_asm.rs`
  (`mnemonic`, `ebpf_landing_wide`, and the helper registry of the pinned Linux
  6.12.94 UAPI), shared with the BPF viewer.
* **Bounds.** `Records::open` walks the record boundaries once with checked
  arithmetic and at most `MAX_RECORDS` (1,000,000) records; a final record that does
  not fit, or a length field that cannot be right, ends the walk and is returned as a
  `Cut`, never guessed at. Records are decoded one at a time on demand.
* **Preview and full read.** The tree opens on the owned 256-byte preview.
  **Decode all captured (M bytes)** reads the field's evidence from the run archive
  in 64 KiB chunks on a thread (progress and cancel; up to 16 MiB), then pages 100
  records at a time ("showing X of Y"). Bytes past the contiguous captured run are
  counted as left out and named.
* **JSON.** **Copy row as JSON**, **Copy all as JSON** and **Save as JSON** carry at
  most 50,000 records; Save writes `records/<syscall>-<field>-<unix seconds>.json` beside the run's files
  (folder 0700, file 0600) and never over an existing file. The trace filter reads decoded records
  (`records contains "..."`).

### Transport reconnect, command deadlines and terminal output under load (0.8.0)

Three host fixes; the guest and the contract are unchanged.

* **Slow reconnects** (the 4.3 to 49 s ones of 0.7.0, and 25 and 85 s measured
  here). A reconnect now times each of its steps and the guest's acknowledgement
  (`reconnect.json` `phases` and `guest_acknowledgement`, and the command's
  result). On this host the guest acknowledged in 6 to 26 ms every time, with its
  control worker running (`ant_guest_heartbeat`, a new read of the guest
  worker's pass count, also while a resume is pending); the time went into two
  host steps on the thread that drains telemetry, both waiting for a disk the
  sealed timeline's background flush and other work kept saturated (iostat:
  99 % busy, 3.3 s per flush): the new timeline's boundary markers and receipt
  (`atomic_json`, an `fsync` each: 8.7 and 59 s) and the snapshot listing that
  followed (16.6 and 25.9 s; it reads and fingerprints the base). The markers and
  the receipt now go through the status file queue (published within the disk's
  latency, as run and manifest files already were), and a reconnect no longer
  lists snapshots: it changes neither the disk chain nor the transport ABI, so
  the tree and what can be taken are as they were. A snapshot restore keeps its
  markers synchronous. `tracer-check reconnects BUNDLE DATA FIXTURE [COUNT]`
  reconnects COUNT times (default 10) in one run that writes every second,
  prints each reconnect's steps, and fails if one takes more than 10 s, the run
  is not running afterwards, or the segments do not add up. Under the same
  added disk load (a 256 MiB fsynced rewrite loop): before, 101 to 562 ms
  (median 273), the snapshot listing the largest step; after, 50 to 70 ms, the
  new timeline 3 to 5 ms.
* **Command deadlines in guest time.** On a loaded host the guest's CPU can wait
  longer than a command's deadline (the run status poll's is 100 ms), and the
  host reported "guest command N timed out; outcome unknown" for a command the
  guest had not had the chance to see (8 times in 12 minutes at load 36; in the
  full tier here for the stress-light status poll, debug-p2's and audit-core's
  uploads). `wait_reply` now counts the guest control worker's passes since the
  command went out: past the deadline it waits on until the worker has made 3
  passes (each serves up to 16 commands), at most 2 s more, and a timeout says
  how many passes there were. Terminal reads keep their wall-clock deadline (a
  late reply is applied when it comes). `stall-check pauses BUNDLE DATA [COUNT]`
  freezes QEMU (SIGSTOP) COUNT times for 700 ms, 500 ms apart, while a program
  prints a line every 50 ms, and halfway stops reading the backend's
  notifications for 10 s, as a busy frontend does; it fails on any command
  timeout or missing line. With wall-clock deadlines: 21 timeouts in 20 freezes,
  all the run status poll's "outcome unknown; run status polling paused"; with
  guest-time deadlines none. (`stall-check` also finds QEMU by its
  `-name guest=NAME` now, and waits up to 180 s for a slow boot.)
* **Terminal output the frontend missed.** Terminal chunks go to the frontend on
  the shared, bounded notification lane; a chunk that did not fit was dropped
  (counted as a UI drop), and the frontend's screen resync brought the screen
  back but not scrolled-off text, so a line read "evasion.debugger_check,evasiok,..."
  with a chunk missing. The chunks now wait in order in a per-session backlog
  (`TerminalBacklog`, up to 8 MiB) and go first at the next send; only past that
  bound is the oldest dropped and counted. The recording always had every byte.
  `stall-check pauses`: with chunks dropped when the lane was full, 110 of 680
  lines never reached the frontend (lines 164 to 273, the 10 s it did not read);
  with the backlog all 680 did.

### Specimens up to 128 MiB (0.8.0, contract revision 19)

A launched program's executable and an Analyze Only file are copied by the guest
(`kernel/antinomie/specimen.c`, patch 0008) into one immutable vmalloc buffer,
which the host reads in 16 KiB chunks into `specimen.partial` and releases. Patch
0025 raises that copy's bound and the global reservation from 64 to 128 MiB
(`ANT_SPECIMEN_MAX`); the copy keeps its 5 s limit and the 180 s idle expiry. An
older guest refuses a `max_size` above 64 MiB with EINVAL, so the larger request is
revision 19 (`control::LARGE_SPECIMEN_REVISION`, the one place the number is
written; `REVISION` follows it):

| Item | Value |
|---|---|
| `control::specimen_request(revision, ram_mib)` | 128 MiB from revision 19, 64 MiB from 10, none before; never more than `specimen_ram_bound` |
| `control::specimen_ram_bound(ram_mib)` | a quarter of the VM's RAM, in bytes |
| `control::SPECIMEN_MAX_SIZE` | 128 MiB: what the host keeps and accepts in an acquisition reply |
| `LEGACY_SPECIMEN_MAX_SIZE`, `LEGACY_CORE_MAX_SIZE` | 64 MiB: an older guest's specimen; an exit core whose request names no budget |

The quarter-of-RAM rule (coordinator decision, ANT-T0182) bounds the one guest copy:
`uploads::check_program_size` refuses an executable Upload or a sample sent as
executable that is larger than a quarter of the VM's RAM before any byte is sent,
saying how much RAM (in 256 MiB steps) the VM needs; a plain file is not refused. A
larger program already in the guest is refused by the guest itself (EFBIG for the
`max_size` it was given), and `control::specimen_acquisition` says the program ran
without static analysis and why. On the host the transfer streams to disk; each
sandboxed analysis worker still reads the whole specimen once (`fs::read`), bounded
by `SPECIMEN_MAX_SIZE`, as before. The Unpacking section's layer 0 is the specimen
itself: report validation bounds it by `SPECIMEN_MAX_SIZE`, and only unpacked layers by
`unpack::LAYER_MAX_SIZE` (64 MiB); before, a specimen over 64 MiB failed the whole
worker report ("structured analysis record violates kind, text or evidence bounds")
after every section had finished. `production_worker_all_categories_with_listings`
with `ANTINOMIE_TEST_SPECIMEN` set to a 95.7 MB static ELF runs every section.

### Uploads closed before COMMIT answers (0.8.0)

`UPLOAD_COMMIT` and `UPLOAD_ABORT` run on the guest's `antinomie-control` workqueue, a
kernel thread. A kernel thread's `fput()` does not release the file itself: it queues
it on `delayed_fput_work`, which runs a jiffy or more later. Until then the file still
holds the write access that makes `execve()` refuse it with `ETXTBSY`, so the host
could read the commit's success and launch the program before the guest had closed it
("Text file busy" on Upload and Run; test drivers retried or slept). The upload
command now releases the file with `__fput_sync()` (patch 0001), so the reply comes
after the close and a launch right after the commit finds the file closed. The wire
contract is unchanged (no revision); a base built before this still has the race, and
the launch error says so (`launch_failure`: "the program file is still open for
writing, for example by an upload that has not finished"). `route-check` and
`core-size-check` no longer retry or wait after an upload.

## Kernel BTF without the recorder (0.8.0)

Guest series 0019; contract revision unchanged. Debian's 6.12.94-1 kernel has
BTF (`DEBUG_INFO_BTF`, `DEBUG_INFO_BTF_MODULES`, pahole 1.30): a world-readable
`/sys/kernel/btf/vmlinux` and one `/sys/kernel/btf/<module>` per loaded
module. systemd's bpf-restrict-fs (a BPF LSM program) needs it, and
eBPF-aware programs (CO-RE loaders, `bpftool`) treat its absence as unusual.
BTF is not enough for systemd's program to attach: a BPF LSM program attaches
through a BPF trampoline, which needs the function tracer. Without it systemd
loaded the program, failed to attach it and logged that BPF LSM was not
available at every boot (a giveaway too). Debian Minimal's stock profile
(below) has Debian's function tracer, and its qualification requires both a
working `RestrictFileSystems=` denial and no such boot message. The minimal kernel profile now
enables both options (`scripts/build-monitor-kernel.sh`; its DWARF was
already on, so the cost is pahole: about 7 s and 0.9 GB of memory, plus 2 s
for the filter below, in a build of about an hour; `.BTF` adds 6.6 MB to the
image, 2.1 MB to the compressed bzImage). The kernel tool suite needs pahole
1.21 or newer (`dwarves`; Debian 13 and the container builder have 1.30); the
build stops with a message when Kconfig drops BTF for lack of it.

The guest must not find the recorder in it. pahole builds BTF from the
kernel's debug information, which describes every function, per-CPU variable
and type, so without care it would name the recorder's functions, its
structures and the fields it adds to stock structures.

| Mechanism | What it covers |
| --- | --- |
| `kernel/antinomie/Makefile`: `ccflags-remove-y += $(DEBUG_CFLAGS)` | The recorder's own objects have no DWARF, so pahole describes none of their functions (static helpers with stock-looking names too), variables or local types. The recorder is absent from the Volatility symbol table too (the host's memory tools use stock types only); developers lose its source-level debug information in vmlinux. |
| `scripts/antinomie_btf.py` after pahole (`scripts/link-vmlinux.sh`; both are files of the patched kernel tree, patch 0019 adds the first and changes the second, not of this repository's `scripts/`) | What its headers bring into stock objects: every type, member, enumerator, function, variable or parameter whose name starts with `ant_`/`antc_` after any underscores, in any case, or contains `antinomie` (stock Debian vmlinux BTF has no such name; this kernel's built-in drivers neither), then what refers to a removed type (a structure loses only that member, a data section only that variable), then anonymous types whose every referrer went. The string table keeps pahole's order and the strings pahole left unused (Debian's BTF has them too), without those of what was removed. A structure keeps its size and its other members' offsets: the removed member becomes a hole (none is left since 0.8.0's patch 0020: no stock structure carries a recorder field). |
| `scripts/Makefile.modfinal` | Each module is encoded against pahole's unfiltered vmlinux BTF (`.btf.vmlinux.full`), so it shares the types the filter changed rather than carrying its own copies of `task_struct` and all that reaches it, then filtered onto the filtered vmlinux BTF with the renumbering the vmlinux pass recorded (`.btf.vmlinux.map`). In modules only the names the vmlinux pass removed count, plus `antinomie`: stock wireless drivers have `ant_*` fields of their own (Debian's ath9k, b43, iwlwifi, ...). A module build without those files (an external module) is encoded as before. |
| `scripts/check-kernel-btf.py`, after every build of either profile | An independent reader fails the build when a vmlinux BTF string is a recorder name, a module's has one of the names pahole's unfiltered vmlinux BTF had (or `antinomie`), or a vmlinux BTF function is one of the recorder's own (System.map `ant_text_begin`..`ant_text_end`) with no stock namesake. On the stock 6.12.94-1 kernel and its 4,225 modules it finds nothing. `tests/monitor/test-kernel-btf.py` tests it, the filter (taken from the series patch) on vmlinux and module BTF, and the wiring. |
| `tests/monitor/stealth-probe.c` | In the guest, `kernel.btf` fails when `/sys/kernel/btf/vmlinux` is missing or names the recorder, `kernel.btf.modules` reads every module's file. |

With patch 0019 alone the filter removed 20 types (the forward declarations
of `ant_task`, `ant_run`, `ant_async`, `ant_hash_job`, the structure
`ant_coredump_live`, the functions `ant_coredump_*` and `ant_uring_rw_capture`
with their prototypes, and pointers only they used) and the recorder's
members of `task_struct`, `io_kiocb`, `aio_kiocb`, `io_ring_ctx`,
`coredump_params` and `io_async_msghdr`. Since patches 0020-0022 no stock
structure has such a member, and what is left to remove is the declarations
stock objects see: `ant_hash_job` and `ant_coredump_live` (forward), and the
functions `ant_uring_rw_capture` and `ant_coredump_sort_vma`.
`resolve_btfids` runs on the filtered BTF as before (no stock BTF id names the
recorder), and the output is reproducible.

**What a sample can still see.** No recorder name, in vmlinux or module BTF.
Since patches 0020-0022 (below) no stock structure has a recorder field, so
`task_struct`, `io_ring_ctx`, `io_kiocb`, `aio_kiocb`, `io_async_msghdr` and
`coredump_params` have Debian's sizes and offsets in every profile. Debian
Minimal's kernel (the stock profile, Debian's configuration) has BTF byte for
byte identical to Debian's own 6.12.94-1 image. The minimal profile (BusyBox)
is not Debian's configuration: it builds in what Debian builds as modules, so
its vmlinux BTF has about 147,700 types to Debian's 113,500 and 234 structures
shared with Debian's differ by configuration (`task_struct` has `SCHED_CORE`'s
fields and lacks Debian's `PREEMPT_NOTIFIERS`, PSI and livepatch ones, for
example), and it has no function tracer. Functions of the recorder are not in
BTF, so fentry/fexit cannot attach to them; root can still place a kprobe on
one by name (see the limits below).

### Accepted full native syscalls and dockable workspace update

These changes date from 2026-10-06. Earlier 30-syscall requirements remain historical,
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

The work is split into checked contracts and per-family slices across kernel,
core and UI. Native content/async cases that remain unimplemented are recorded
as such, not as delivered. Existing
archives and per-VM disks are compatibility inputs, not disposable fixtures.

## Telemetry protocol

Use telemetry application protocol 1 (ANTT, 128-byte little-endian
envelope), carried as opaque V7 messages.
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

The guest control contract is `protocol/control.h`. Opcodes: 0x1001 upload
begin, 0x1002 upload chunk, 0x1003 commit,
0x1004 abort, 0x1010 exec, 0x1011 terminal input, 0x1012 terminal read,
0x1013 terminal resize, 0x1014 signal, 0x1020 recorder stats,
0x1030 shutdown. Explicit little-endian fields, versioned, checked lengths;
results travel in the existing reply queue. Each reply matches request ID.
Persistent health/loss counters queryable even after telemetry loss.

Rust backend runs blocking ant_init/poll/read on one owner thread. It exposes
owned commands and bounded UI snapshots, handles reply matching and telemetry,
and keeps collection/persistence independent of frontend frame rate. Shared
public API types are defined by the host side for the UI.

## Verification

Build Rust workspace and kernel. Four-core QEMU integration: bootstrap attach,
upload static test program/shell script, launch with UID/cwd/env, terminal I/O,
entry/exit + buffer bytes, descendant execution, invalid pointers, telemetry
overflow, disk persistence/reset and graceful/forced shutdown. Include CPU/RAM
variants if feasible. Use actual measured results and record unavailable tests.

## Accepted snapshot and reconnect extension (0.5.0)

**Stopped-boot ordering (0.8.0).** Before a stopped VM's snapshot is created,
restored, renamed or hidden, pending recording flushes finish before its automatic
run layer can be finalized. The backend publishes "Waiting for saved recordings"
while collecting active or deferred flush jobs. The wait times out after five
minutes or cancels on application shutdown, retaining the disk layers. The store
then settles the stopped run layer, waiting for a background finalizer's lock,
before reading the snapshot manifest. A running VM keeps its automatic layer;
user-owned checkpoint layers are never merged. This is host-only and does not
change the guest contract.

**Immediate restart (0.8.0).** Starting a VM with a pending automatic run
layer is refused while active or deferred recording writes remain. The error
asks the user to retry after saving finishes; no disk or boot state is changed.
The worker remains free to poll saving and process commands. Once writes finish,
the layer lock serializes a retry with any background finalizer before the
next boot seals its starting disk. The existing bounded flush-queue admission
check also applies when starting a different VM.
Cold snapshot restore waits for its newly sealed recording before invoking
start, using the same five-minute, shutdown-cancellable save wait. If that wait
fails after the disk restore committed, the error explicitly says the disk was
restored and the guest was not started; the user can retry start once saving ends.

The snapshot manager supports disk checkpoints (cold boot recovery)
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
