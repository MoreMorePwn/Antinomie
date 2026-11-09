# Implementation record: Triage and analysis

Run triage, Suspicious activity, file activity, static analysis, IOC datasets and detection inputs. Part of the [implementation record](../implementation.md).

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

### Suspicious activity: tiers, categories, noise and the Evasion category (0.7.1)

The rules live in `triage/src/rules/` (the `antinomie-triage` crate); `findings.rs` runs them over a
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
  that was dismissed stays gone). The switch is `Settings::toast_high_findings` (off by default; stored as
  `toast_high_live`, so the 0.7 value, which was the default for everyone, is not read).
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

### Runs that never ran (0.8.0)

`RunState` has three definite ends besides the recorded ones (ANT-T0182):

| State | Meaning | Set by |
|---|---|---|
| `FailedToStart` | The program never started: the guest refused `EXEC`, or the host could not prepare the run (its record or network capture) before `EXEC` was sent. `recording_error` says why. | `failed_run_launch` |
| `LaunchUnconfirmed` | No usable answer to `EXEC` came (timeout, unreadable reply, VM gone): the program may have started, nothing of it was recorded. | `failed_run_launch` |
| `Interrupted` | The record was left running (or with an unreadable status): the app closed or the VM stopped before the tree's end was seen. | reading a saved run |

A failed start with nothing captured leaves no folder; one with a network capture is
kept, with its state, so the capture stays explained. Reading a saved run
(`saved_run`, `list_runs`) settles the state with `RunState::settled`: `Running` and
`StopRequested` read as `Interrupted` (before, `Unknown`), and an `Unknown` record of a
launch that was never acknowledged (root task cookie 0) reads as `FailedToStart`, or
as `LaunchUnconfirmed` when its error ends with `launch outcome may be unknown`; so
the Unknown entries of the Routed capture bug read as failed to start. `Unknown` stays
for a live run whose status cannot be read and a restored run before its first status.
Run History says *Failed to start*, *Launch unconfirmed* or *Interrupted* with the reason
in the tooltip and no "Saving stopped" badge, and a run that never ran has a red
**Delete…** in its menu (`EvidenceItem::FailedRun`: only `runs/<id>` or
`boots/<boot>/runs/<id>` of the VM's recording, only when its `run.json` names that run
and reads as never run, refused while the running boot still owns it; a capture taken
for it stays in the Network tab). An older app reading a record with a new state skips
that run (one damaged run never hides the others).

### Run state questions (0.8.2)

Views no longer list `RunState` variants to ask whether a run is going (ANT-T0265).
`RunState` in `monitor-core/src/api.rs` answers:

| Helper | True for | Used by |
|---|---|---|
| `is_live()` | `Running`, `StopRequested`, `TerminalClosed`: the run still records. `Unknown` is not live (a record waiting for its first status has no proof of a program; the callers that list it test it themselves). | Run History, the sample window's Runs list and detail, Jobs, the run-state line, the run-finished toast, run deletion, `forgettable` |
| `can_stop()` | `Running`, `TerminalClosed`: what the guest accepts (`StopRun`); `StopRequested` already has a Stop under way. | every Stop run button (formerly Kill), `StopRun` |
| `ended_normally()` | `Finished`, `Stopped`, `Finalized`. `Interrupted` and runs that never ran are left out on purpose: they leave nothing new to show in the history. | `history_sync` |

### Stop run and how a run ended (0.8.3, ANT-T0332)

`Command::StopRun` is the whole action (the UI calls it Stop run; it was Kill). It
sends SIGTERM to the run's tree (the guest's STOP_RUN signals every task of the
run, not only the root) and, on a revision-17 guest, SIGKILL after the grace
period. `RunSummary::stopped_by_user` is set when the guest accepts it, so that a
tree that ended afterwards reads `Stopped` (`execution::state_after_stop`) even
when the root had already exited 0. The run then ends like any run: the tree-end
status makes `check_run_artifacts` close the capture segment (`stop_run_network`)
and release the route (`release_run_route`, which writes the gateway's counts to
`artifacts.json`).

A VM stop used to cut both: `Worker::stop` now calls
`Session::close_run_artifacts_for_vm_stop` before it sends SHUTDOWN (QEMU and the
gateway still answer), which closes the capture (`network_state` stays
`Interrupted`, with the reason in `issues`) and releases the route; `seal` also
releases any claim still held (QEMU ended on its own).

Words (`run_state_line::{describe, detail, ended_by_vm_stop}`, `run_status`):
`Stopped by you · root exited 0`, `Ended by VM stop · root exited 0 · 1 process
still running` (state `Interrupted` or `Finalized` with a live task or no root
exit; with nothing alive the plain "Recording ended" stays).

`artifacts.json` gained `trigger_dumps`: the dump trigger's `TriggerRecord`s, the
same as `run.json` `triggers.records`, written by `save_trigger`. `core_state`
and `core_dump` stay about the exit core (Core dump on exit) only: a trigger takes
up to eight cores and memory dumps, which one state field cannot hold.

The live watch (`dump_trigger::Watch`) judges only the calls the rules read
(`rules::calls::watched`, handed over as `reduced_keep_calls`, x86-64 names). Since
0.9.0 (ANT-T0426) it keeps them by host syscall id on every ABI
(`syscalls::ids_on_every_abi`): x86-64's numbers, as before, and the aarch64, arm and
i386 calls of the same name or family (arm's `send` for `sendto`, `mmap2` for `mmap`).
Before, it kept x86-64 numbers only, so an arm64 run's tagged ids never reached the
judge and its trigger never fired. The telemetry held before a launch is acknowledged
(`pre_ack`, replayed by `replay_pre_ack`) goes to the watch too, through the same
`ProgramRun::watch_event` as live packets; before, a program that made its suspicious
call within milliseconds of its start (a static x86-64 program under KVM) was never
judged. Once a run is over (`recording_complete`) the
worker flushes the entries still waiting for an exit and `ProgramRun::settle_trigger`
writes one note when the trigger took nothing: "armed ... but no rule of that tier
matched", or, for matches the VM stop cut off, a `missed` entry each ("The recording
ended before the dump could be taken.") and a count note. `begin_finalize` settles a
run the VM stop ended first. `dump_trigger::replay` feeds recorded events to a judge
the way the watch does: the unit tests use it, and so does the triage example
`trigger-replay RUN_DIR [--all]`, which prints what the trigger would have matched in a
saved recording. The triage example `trigger-check` is the VM check (vm-regress full
tier, `trigger`, on x86-64 and arm64).

`TerminalClosed` is set only by `Run::eof` when the PTY ends before any execution
status exists; once a status arrived the state stays `Running` with `terminal_eof`.
Before 0.8.2 the sample window's exit column said "Unknown" for such a run; it now says
"Running" like Run History and Jobs. Run states reach a colour through `widgets::Tone`
(`state_tone` in the Summary, the Detection header and the debugger status line,
`run_state_line::state_tone` for runs, `None` meaning plain grey), and the raw colours
the views still held (the terminal's 16 ANSI colours, series colours, `ink_on`,
`hover_wash`, the file reconstruction's Mapping colour) live in `theme`.

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

## Parser fuzzing (0.8.0)

The host parses bytes a sample controls: its own file, the guest disk, guest
network frames and captures, process cores, kernel records and the replies
the guest sends. `src/antinomie/monitor/fuzz/` is a cargo-fuzz crate (not a
workspace member, nightly toolchain only for fuzzing) with twelve targets; each
calls one function of `monitor-core/src/fuzz_entry.rs`, which exists only with
the off-by-default feature `fuzzing`. A parser that is private is reached
through a one-line `#[cfg(feature = "fuzzing")]` shim in its own module, so a
normal build contains none of it.

| Target | Parser reached |
|---|---|
| `antt_assembler` | `parse_packet`, `Assembler::ingest` and the stored-range reader (packets re-shaped to valid headers unless a selector bit asks for raw bytes) |
| `analysis_section` | the worker's in-process checks (object headers and sections, strings, entropy, identification, iced-x86 disassembly, UPX detection), report bounds and validation |
| `disk_image` | qcow2 and ext4 through the sandboxed reader's requests (patches over a valid base disk) |
| `partition` | MBR and GPT probing |
| `core_dump` | `CoreDump::open`, virtual reads, disassembly, sparse core plan |
| `typed_fields` | every typed-field decoder |
| `route_frames` | gateway Ethernet, ARP, IPv4, TCP, UDP, DNS and DHCP parsing |
| `pcap`, `pdml` | the capture page reader, TShark's PDML tree |
| `debug_wire`, `control_wire` | guest debug and control reply decoders |
| `tool_text` | FLOSS, binwalk and capa output, ThreatFox/URLhaus/MalwareBazaar replies, release and catalog documents |

To run them (from `src/antinomie/monitor/fuzz`, once per machine
`rustup toolchain install nightly --profile minimal` and
`cargo install cargo-fuzz --locked`):

```
export CARGO_TARGET_DIR=$HOME/fuzz-scratch/target ANTINOMIE_FUZZ_DISKS=/dev/shm/antinomie-fuzz-bases
./make-bases.sh                              # base disks for disk_image
cargo +nightly fuzz build
python3 make-seeds.py "$HOME/fuzz-scratch/seeds"   # benign seeds from the repository fixtures
mkdir -p ~/fuzz-scratch/corpus/analysis_section
cp -r ~/fuzz-scratch/seeds/analysis_section/. ~/fuzz-scratch/corpus/analysis_section/
nice -n 10 "$CARGO_TARGET_DIR"/x86_64-unknown-linux-gnu/release/analysis_section \
    -max_total_time=1800 -max_len=65536 -rss_limit_mb=2048 -timeout=10 \
    ~/fuzz-scratch/corpus/analysis_section
```

Seeds, corpora and crash artifacts stay out of git: `make-seeds.py` builds the
seeds from the repository's fixtures each time. Set
`ASAN_OPTIONS=detect_leaks=0` to ignore leak reports at exit. Samples are
never used as seeds: the seeds are fixtures of this repository and generated
bytes. A finding gets a regression test in the crate's normal tests and a fix
of the parser, never a limit that hides it.

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
| `filter` | `copy` (extensions, support files), `yara-forge` (allowed rule licenses, allowed repository licenses, repository to license table), `yara-rule-files` (one rule per file: `license_keys`, `allowed_licenses`, `exclude_files`; abuse.ch YARAhub) or `sigma` (log sources to keep) |
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
keeps documents whose log source is listed; the rule-file filter keeps a file's rule when its `yarahub_license` meta is allowed, it is not in `exclude_files` (rules the generator found in YARA-Forge Core) and YARA-X compiles it, and writes the file unchanged. A rolling zip with no `paths` accepts any unlisted `.yar` member. The result is indexed like any
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
hash-locked set of wheels (`src/antinomie/monitor/crates/monitor-core/assets/sigma-requirements.txt`, written by
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

This 0.6.2 triage and history work is host-only. Triage requires one explicit program
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
Network has IPs, Hosts, HTTP, DNS and Sessions tables with compact columns.
Use recorded packet frame links and TShark's existing decoder. Local GeoIP/ASN
data may enrich destination rows; do not contact an external lookup service.
PCAPs record VM traffic, so time-window correlation does not prove process
ownership. Host-time anchors are receipt estimates with transport latency;
historical start-anchored estimates and unavailable timestamps must be labeled.
New summary timestamps are optional serde fields, preserving older archives.

Index/count/coverage explanations are removed. Show actionable missing-feature
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

## Accepted host evidence update (0.5.0)

0.5.0 completes the host evidence work; guest acquisition work is deferred to
0.6.0. The static-analysis priority is result readability.
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
and pre-free memory capture require new guest support and are deferred to 0.6.0.
No guest rebuild is necessary for these host additions; already-built current
0.5.0 bases are reused.

### Accepted static-analysis results update

The native static-analysis workspace redesign dates from 2026-10-08.
One workspace is the default; selecting a category updates local results and
separate dockable section panes open only on explicit request. Typed available
evidence drives searchable/sortable tables, selected details and bounded read-only
specimen previews. Legacy generic reports remain readable. Acquisition, launch
scope, engine availability, guest controls and V7 remain unchanged. No new analyzer
dependency or guest image build is needed. The revision-1 result contract is
this update.

### Accepted static-analysis launch update

Static-analysis acquisition/backend and launch setup were completed
on 2026-10-08. Run Program opens launch fields left, opt-in analysis checkboxes
right and a final Run button. Initial executable only; no descendant/later exec
static acquisition. Triage plus optional deep analysis, local/no network default,
exact initial guest exec-file acquisition with bounded wait, failure continues
execution and reports unavailable. Retained reports reopen without rescanning.
Application control revision
10 adds optional specimen controls; V7 remains unchanged, revision-9 guests
still launch with explicit analysis unavailable. Resource/isolation/compatibility
limits and engine gaps must be recorded, not presented as complete clean scans.
