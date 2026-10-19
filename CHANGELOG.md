# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version says which bases
it runs.

## 0.7.0 — Unreleased

- **Audit fixes (host).** A feature-completeness audit of 0.6.2 and 0.7.0
  found these; all are host-side.
  - Detection > Scanned inputs no longer reads the file system while drawing:
    whether a listed capture or core is gone is answered by a worker on load,
    after a delete and every 30 seconds. The selection digest of the rule
    sets is also computed on a worker, and a run's capture and core state is
    read the same way.
  - Opened files is the five-column table again (time, path, PID/TID, result,
    evidence) and Read files the six-column one; failed opens and reads are
    listed with their result. "Show failed attempts" now applies to the change
    tabs and Changed files only. The extra columns stay in Details. The hint
    line under the File activity tabs is gone.
  - A failed result save restores the selection manifest and report that were
    there before, instead of leaving the new manifest beside the old report.
  - Sizes in Scanned inputs, the Sigma journal header, the capture list, base
    and rule downloads and status messages read "N bytes (X.Y KB)".
  - Sigma auditd records now include `CWD` (`cwd`) and `PROCTITLE`
    (`proctitle`, the arguments joined with NULs, hex-encoded and cut at 128
    bytes as the kernel does). `process_termination` events were not added:
    no rule in the installed SigmaHQ Linux pack uses that category (it has
    `process_creation`, `file_event` and `network_connection` rules, and 53
    `service: auditd` ones).
  - The guest's count of dropped credential and hash records is shown in the
    run summary health, counts as observed loss, and is named in the TRL
    hover.
  - A deleted on-exit core stays in Core dumps as a "Deleted" row, and Run
    History > Analysis enabled says what became of the run's network capture
    and core ("Complete", "Deleted", ...).
  - The TShark coverage note no longer says HTTPS is unavailable: TLS server
    names are read from handshakes; the content of HTTPS and HTTP/3 is
    encrypted, and cleartext HTTP/2 and encrypted DNS are not decoded.
  - App dependencies reports "Wrong version" for a QEMU older than 6.0 (the
    network capture needs its flat `object-add` arguments). No minimum was
    invented for TShark or Suricata. The dnf and zypper package names were
    checked against the Fedora and openSUSE package indexes, except as noted
    in `dependencies/install.rs`.
- **The guest tracer records who a task ran as and what a file contained.**
  Guest contract revision 17 (no new revision) adds two records to the
  syscall trace. Credentials: every traced task's uid, euid, suid, fsuid, the
  gid equivalents, audit login uid and session, and capability sets are written
  at its first traced call and whenever they change (`setuid`, `setgid`,
  `setres*`, `setfs*`, `capset`, a setuid/setgid or file-capability exec, a login
  uid change), from the one place the kernel changes them. File hashes: the
  SHA-256 of the image an exec committed and of a file about to be deleted, or
  the reason there is none (over the 16 MiB limit, unsupported filesystem,
  queue or byte budget full, read error). The hashing never runs in the traced
  call: the call only queues a small job and a kernel worker, one 64 KiB chunk at
  a time, reads the file through a private open that raises no file-change
  notification and leaves the access time alone; at most 16 jobs and 64 MiB
  wait, and a dropped request is recorded and counted. No helper process, file
  or BPF program appears in the guest. SHA-256 only: the SigmaHQ Linux pack has
  no rule that reads a hash, and MD5 would be reads without a consumer. This
  needs a base built with 0.7.0; older bases and recordings simply lack the
  records.
- **Sigma and auditd events now carry them.** Triage follows each task's
  credentials and attaches the ones in effect after a call, the way auditd
  reports them: Sysmon-style events get `User` (the numeric effective uid; a
  guest's `/etc/passwd` is not available on the host without a guest agent, so
  no name is looked up or guessed, not even `root`) and `LogonId` (the audit login
  uid, empty when the guest never set one), `process_creation` and `file_delete`
  get `Hashes` as `SHA256=…`, and `HashSkipped` says why there is none. The
  auditd `SYSCALL` record gets `uid`, `euid`, `suid`, `fsuid`, the gid family,
  `auid` and `ses` (an unset login uid prints as 4294967295, as auditd does). A
  script's interpreter is not reported as the script's hash, and a file that
  changed while it was read gives none. Against the installed SigmaHQ Linux pack,
  177 of 210 rules can now run (was 174): the pack barely reads credentials, so
  most of its rules stay as they were. The event journal is now format 3;
  formats 1 and 2 still open and scan, and recordings from before this have the
  fields missing, not empty.

- **Right-click Delete for core dumps and network captures.** Host-only.
  The Core dumps panel (manual cores, on-exit process cores and imported core
  results) and the Network window (per-run and whole-boot captures) have a
  **Delete…** item in the row's right-click menu. A confirmation names the item
  and its size and says it can't be undone. The backend does the deletion
  (`DeleteEvidence`), off the UI thread, only inside the VM's recording
  folders: paths are canonicalized, `..` and symbolic links are refused, and
  only the places the recorder writes these items are accepted. A capture goes
  with its summary, `.metadata` annotation folder and any derived `<capture>.*`
  file; an imported core loses only its results, never the original file. The
  live capture and a capture or core still being written are disabled with a
  tooltip (and refused by the backend). The boot's recording quota gets the
  freed bytes back. Runs that listed the capture or core now read it as
  deleted (recorded in new `network_deleted` / `core_deleted` fields that
  0.6.x ignores, so the data directory stays readable by older builds) (Run History and Triage counts refresh, Detection says "Evidence
  missing" instead of failing), a selected deleted item is deselected and
  Details cleared, and each deletion is an Activity log entry.

- **Triage > File activity is split by what the program did to a file.** The
  tabs are Opened, Created, Read, Written / resized, Deleted, Renamed / moved,
  Executed, Attributes (chmod and chown, timestamps, extended attributes),
  Metadata probed, Other (links, copies, executable or shared writable
  mappings, directory listings, watches and locks) and Changed files, each with
  a whole-run count. A call can sit in several tabs: an `open` with
  `O_CREAT|O_TRUNC` that made the file is Opened, Created and Truncated.
  Created says "(inferred)" when only a path not seen earlier in the run shows
  the file is new (`O_EXCL`, `mkdir`, `mknod`, `memfd_create` and `O_TMPFILE`
  prove it). Changed files now has a Lifecycle column telling what happened to
  each file, such as "created (inferred) → written 3× → chmod +x → executed →
  deleted", and keeps its original-to-final byte details. Every file row also
  shows its result, a location class (persistence, credentials, system
  binary/library, temp/staging, pseudo-fs, the sample itself, hidden) and how
  the file was reached (by path, by descriptor, or an inherited or unknown
  descriptor), and the table filter accepts `file.category`, `file.result`,
  `file.errno`, `file.location`, `file.access_by`, `file.created_inferred`,
  `file.mode`, `file.mode_flags`, `file.lifecycle` and `file.failed_attempts`.
  Calls the kernel refused are no longer counted as changes or in the tab
  counts and are hidden; "Show failed attempts" lists them. io_uring file
  operations are not mapped into these tabs yet.

- **A Getting started window walks a new user through the first setup.** It
  opens by itself the first time Antinomie starts with no VM and no base
  (once; "Don't show again" and finishing keep it closed), and Help >
  Getting started opens it any time. Steps: pick and download a base from
  the catalog (the same rows, progress and Cancel as Download base); create the
  first VM from it with the New VM defaults (vCPU, RAM and disk within the
  base's minimums, the realistic stealth profile on); check the host
  dependencies; install the missing managed analysis tools one after another
  ("Install all missing"); and download the default YARA, IDS and Sigma rule
  packs through the Rule manager's catalog (downloads stay off until allowed;
  untick a pack to skip it). Every step can be skipped or left, the window can
  be closed at any time, what was skipped is remembered, and each opening
  checks the computer again so what is already installed shows as done. The
  last page summarises what is ready and what was skipped and links to the
  "Your first run" documentation. Long work runs off the UI thread with the
  usual spinner and Cancel.

- **One command installs every missing host dependency.** Tools > App
  dependencies and the Getting started window now detect the distribution
  from `/etc/os-release` (apt, dnf, pacman or zypper) and show a single
  copyable command for only the missing packages, plus
  `sudo usermod -aG kvm $USER` when `/dev/kvm` exists but you are not in the
  `kvm` group (a note to sign in again when you already are). The package
  names are one table in the code with tests for each package manager.
  Tools > App dependencies also lists the Explorer and Upload file chooser
  (Zenity) and Wireshark, both optional.

- **The guest kernel now measures its own RAM and disk use.** Guest contract
  revision 17 adds a `RESOURCES` control command: the kernel reports MemTotal
  and MemAvailable (the same accounting as `/proc/meminfo`) and the statfs
  counters of the root filesystem seen by PID 1 (total, privileged-free and
  user-available space, plus the filesystem's device, type and id), from a
  dedicated worker that never blocks the control channel. Summary asks about
  once a second and keeps its live, stale and unavailable states: a reply that
  is late, an invalid frame, a refresh stuck in the filesystem, a paused VM or
  a snapshot boundary all show the last reading as stale rather than live. No
  helper is uploaded or started in the guest any more on a revision-17 base, so
  no extra process appears there. Bases built before this release (revision 16
  and older) are outdated and keep the temporary bundled collector until you
  rebuild them. This needs a base built with 0.7.0; later 0.7.0 guest changes
  reuse revision 17.

- **The Details panel scrolls, and the process tree has room.** Long Run
  History details and Network capture records are no longer clipped: the
  panel scrolls vertically, keeps its place while the same run or capture
  stays selected and returns to the top when another is chosen. The recorded
  process tree is taller (it grows with the window), can be resized by
  dragging the bar under it (double-click resets), and scrolls on its own in
  both directions for deep trees and long paths; the mouse wheel over the
  tree scrolls the tree first and the panel once the tree reaches its end.
  Capture History's process tree scrolls sideways too.

- **Sigma rules can match more of what a run did.** Host-only; nothing changes
  in the guest. The event journal Sigma reads now has the process's parent
  (`ParentImage`, `ParentCommandLine`, `ParentProcessId`, from the fork result
  and the parent's last exec), its working directory (`CurrentDirectory`,
  from the launch directory followed through `chdir`/`fchdir`), and the name
  a destination address was looked up under in the run's capture
  (`DestinationHostname`). `file_event` now also covers `O_CREAT|O_TRUNC`
  opens, `creat`, `mkdir`, `link`/`symlink`, `mknod` and `O_TMPFILE`, and
  `network_connection` covers accepted connections and UDP peers, with
  `Initiated` true or false and `Protocol`. Rules marked `service: auditd` are
  now evaluated against auditd-style `SYSCALL`, `EXECVE`, `PATH` and
  `SOCKADDR` records built from the same trace. Against the installed SigmaHQ
  Linux pack, 174 of 210 rules can run on a journal with every field the trace
  can supply, up from 119 (process creation 109 to 120, network
  connection 2 to 5, auditd 0 to 41); rules that need an audit key, a file
  mode or a keyword search stay not evaluated, and say so. Users and
  credentials come from the guest tracer's records, below.
- **Inferred values are labelled.** A value that comes from tracking state or
  from matching two sources, not from one recorded call, is listed in the
  event's `_inferred` field: a new file judged by the path not having been seen
  before, a working directory reached by `chdir`, a hostname matched from DNS,
  a path joined from the working directory, auditd's `exe` and `comm`. The
  event journal is now format 2; format 1 journals still open and scan. A
  Sigma finding says how many of its matched events rely on an inferred field,
  and the warning that Sigma events are converted from the syscall trace and
  may not cover everything a Sysmon or auditd log would hold stays.
- **Detection is "partial" only when a scan really is incomplete.** An IDS or
  Sigma scan is now Partial only when its time or rule budget ran out (Sigma:
  90 s, 4096 rules), the evidence was still being captured, the result or its
  provenance could not be saved, the event journal was truncated, an IDS
  segment could not be cleaned up, a finding or match could not be kept, a
  selected rule file could not be staged, or Sigma stopped on an error partway through. Rules an engine cannot use are
  counted instead. IDS shows `2,094 rules loaded · 7 not loadable (TLS
  fingerprint 3, dataset 2, duplicate 1, no SID 1)`; Sigma shows `12 rules
  evaluated · 33 not applicable (no matching events 30, backend 2, syntax 1)`.
  Each has a collapsible list of the rules (the first 200; the counts include
  all of them). A rule with no captured event carrying its fields is not
  applicable to this run, which is different from a rule that failed to
  convert. A capped evidence preview is a note (`Evidence preview limited to 16
  per rule; match counts are complete.`), not Partial. Results now carry
  explicit count fields (`format_version` 1, `coverage`) so nothing reads
  warning text; older saved results still open. They are not migrated, so one
  saved as partial only for these reasons keeps showing Partial until the scan
  is run again.

## 0.6.2 — 2026-10-19

- **Detection says what happened to each input, and never "partial".** Scanned
  inputs now end in exactly one of Succeeded, Failed or Skipped. A Suricata
  failure reads like `Suricata exited with code 1: Error: pcap: failed to get
  first packet timestamp…` (or `timed out after 100 s`, or the signal that
  ended it) with the engine's own error lines instead of its startup notices,
  and Show log opens the detector log. A capture with no packets, such as a
  header-only PCAP or pcapng, is Skipped as `no packets captured` and Suricata
  is not started on it; a run with no capture says so too. YARA (sample,
  memory dump, core, recovered files) and Sigma follow the same rules. Failed
  and Skipped rows have a Scan button that re-runs that engine, and the scan
  line reads `3 matched rules · 2 succeeded, 1 failed, 1 skipped` instead of
  `complete` or `partial`; a failed or skipped input no longer makes the whole
  result partial. The Sigma event journal counts as Succeeded whenever the
  adapter ran, with a note that Sigma events are converted from the syscall
  trace and may not cover everything a Sysmon or auditd log would contain.
  Saved results that say `partial` still open: a row whose reason describes a
  failure shows as Failed, any other as Succeeded with its old note.
- **Loading and in-progress text shows a spinning icon.** Everywhere the app
  says it is loading, reading, checking, indexing, uploading or waiting for
  something that is still running, a small spinner now sits left of the text,
  such as in Triage, Static Analysis, Memory, Core dumps, the base images and
  the rule manager. The spinner disappears when the work ends, so an idle
  screen is not redrawn.
- **Network filters in one place, with Details for captures.** Quick Search,
  Display Filter and Record Filter now sit in one collapsible Filters section,
  one labelled row each, and every box shows a gray `filter e.g. …` example.
  Clicking a capture in the list shows its record (name, ID, tags, state, boot,
  times, packets, size and files) in Details instead of a hover tooltip.
  Capture times show local time with a `(UTC+x)` offset. The Colors legend
  button is gone (rows stay colored like Wireshark), and Open in Wireshark is a
  bright blue button.
- **Filter suggestions no longer scroll back up.** In a filter box the
  suggestion list jumped back to the highlighted entry on every frame, so
  scrolling it with the wheel or scrollbar was undone. It now follows the
  highlight only when the highlight moves or the suggestions change.
- **Run History opens Triage on a double click.** A single click, or an arrow
  key, only selects the run and keeps the top run dropdown and the other panels
  in sync; a double click selects it and opens Triage.
- **Run History details show the process tree and the analysis that was on.**
  The details area is the run's recorded process tree, then the list of enabled
  analysis features (static analyses, memory dump, core dump and network
  capture), then a closed "Launch" fold with the executable, arguments, working
  directory, environment, UID/GID, boot, session and recording folder, plus the
  recording warning when saving stopped. The artifact links and static-analysis
  button there are gone.
- **Cancel a process core from the Core dump panel.** While a manual or
  Core Dump on Exit capture is in progress, the panel shows a "Cancel process
  core" button; it is absent when nothing is being captured.
- **Filter boxes say `filter e.g. ...`.** Every filter box shows a valid
  example of its own syntax as a placeholder in a grayer hint color, and the
  labels that repeated it are gone.
- **Run History filter has one name per value.** Completion, the Filter guide
  and the right-click menu offer only `entry.id`, `entry.name`, `tag`,
  `process.exe`, `process.argv`, `process.cwd`, `process.pid`, `process.cookie`,
  `process.uid`, `process.gid`, `run.state`, `run.error`, `run.started_ms` and
  `run.has_static`. The old names (`id`, `path`, `pid`, `status`, `state`,
  `run.tree_state`, ...) still work in saved filters. `run.state` uses the State
  column's words (and still accepts `Finalized`, `TerminalClosed`,
  `StopRequested`), and `run.root_exit` uses the Root exit column's words, such
  as `Exit 0`. `args` now matches one argument at a time, like `process.argv`.

- **Browse every saved async observation of a call.** Heavy io_uring runs no
  longer lose entry, exit or task-end facts when thousands of completions land on
  one syscall. A call row previews its first 256 observations, says how many were
  saved and how many are not shown, and Trace pages through the rest from the
  archive without reading the whole call. Triage reports the calls it only
  previewed. The packet index cache is rebuilt once; recordings are unchanged.

- **Inspect the Sigma event journal.** The Event journal row under Detection →
  Scanned inputs, and a Sigma finding's evidence, open a read-only viewer of the
  normalized events the rules were matched against: category, time, process and
  main fields per event, a category filter and text search, and every field of the
  selected event. Each event links to its Syscall Trace call or Network packet.
  The header shows the end record (complete or not, events left out, events per
  category) and whether the file is the one the scan read. Sigma findings now keep
  the exact journal event number; older results link by call or packet and say when
  one source produced several events. Journals are read in pages of 100 on a
  worker, bounded and cancelled on a run switch. Open file and Copy path expose the
  raw JSONL; this app never writes it.

- **Late forks preserve recorded child exits.** The host process tracker uses
  guest time and leader identity to distinguish delayed CPU-stream delivery from
  PID reuse. Old lifetime and exec records cannot erase newer terminal facts.

- **Whole-run counts on Triage sections.** Detection, suspicious activity, file
  and network tabs show count badges independent of filters and current pages.
  Pending work and unavailable evidence are distinct from an evaluated zero.

- **Retry unavailable properties in place.** Property sections with missing
  values have a refresh control and busy indicator. Already computed values
  remain visible during a retry and survive a failed retry.

- **Recording warnings follow the selected run.** Full saving-stopped causes
  appear in that run's details, Trace and Triage with a dismiss control. Summary
  no longer lists unrelated run warnings; Activity retains run-specific entries.

- **Configurable syscall pages.** Calls/page accepts 1–256 (default 100), saves
  the choice across restarts and resets page cursors when changed while keeping
  the applied filter. Page totals use the selected size.

- **Health includes recorder and async capture loss.** Recorder statistics are
  sampled without blocking, with overdue replies shown as unavailable. Summary
  shows failed sends and affected runs separately from TRL/UIL/STL. Async-loss
  notes are retained with the run and Activity warnings deduplicate repeated polls.

- **Triage sits beside Run History.** Default tabs, restored tabs and the View
  menu share their order. Untouched old defaults migrate while custom layouts
  and the selected tab are preserved.

- **Simpler storage cards.** Summary omits the extra reserved-free-space line;
  available space, used space and underlying measurements keep their meaning.

- **Run as Root or Normal user.** A preset beside UID/GID sets both to 0 or
  1000. Manual values remain editable and other combinations show Custom.

- **Detection warnings appear once.** Selection diagnostics survive worker and
  parent report merging without duplication; distinct rule warnings and skipped
  counts are preserved.

- **YARA scans physical RAM dumps.** Guest RAM uses QEMU's captured physical
  ELF segments rather than the Linux process-core reader. Missing ranges remain
  explicit, with the existing block, input-size and time limits.

- **Executable capture status.** Triage Properties shows acquisition, captured,
  verification and unavailable states separately from computing properties.
  A failed property attempt can recover when its analysis report advances;
  missing capture data and a mismatched saved analysis now have distinct reasons.

- **Concurrent archive reads.** Archive indexing waits cooperatively for a busy
  SQLite cache and serializes append cursors before indexing new packets. Run
  changes can cancel the wait. Acquired executable metadata is saved before
  the UI announces readiness, so Properties can read it during static analysis.

- **Clear address-lookup warnings.** Unavailable WHOIS enrichment names the
  affected IP and reports unknown country/organization instead of forwarding
  the tool's ambiguous "Please upgrade this program" message.

- **Analysis keeps working after a rebuild.** Rebuilding Antinomie while it
  ran made every sandboxed worker (file properties, detection, static
  analysis) fail with exit status 127, because the running program's file was
  gone. Workers now run a private copy of the running program in that case,
  and a failed worker names the program that failed instead of always saying
  Ghidra.

- **Rules stay active after reopening.** The local rule selection loads at
  startup without opening Rule manager. Changing runs keeps the enabled-set
  list with its cached registry. Local registry failures are reported and can
  be retried with Reload local rules; startup does not download rules.

- **Scanned inputs in Detection.** Below the rule sets, a collapsible
  "Scanned inputs (N)" list shows exactly what the last scan passed to the
  rules, so a count such as "10 objects" can be checked: for YARA the
  executable, the process core and the guest memory dump (blocks scanned,
  ranges not captured) and each recovered file; for IDS each PCAP segment
  with its packets; for Sigma the event journal with its events per
  category. Each row has the file's size, its SHA-256 when known, and
  whether it was scanned, partly scanned or skipped, and why (an option is
  off, a time or 512 MiB budget was reached, the file changed). Clicking a
  row opens the sample in Static Analysis, the PCAP in Network, the core in
  Core dumps or the dump in Memory. Results saved before say the list was
  not recorded.

- **Host clipboard typing.** VM → Type host clipboard into VM, or Ctrl+Shift+Y
  outside an editor, types into the guest's focused input through QMP. It uses
  a US keyboard layout with Caps Lock off, accepts up to 4 KiB, confirms long
  or multiline text, and reports characters it cannot type. Typing stops at
  VM lifecycle boundaries; terminal paste keeps its existing behavior.

- **Kill a program run.** The toolbar's Kill button, directly left of Run
  program, confirms termination of the selected active run and its descendants
  while the VM keeps running. With several active runs, select one in Run
  history first. Finished runs and stale confirmations cannot target a new boot.

- **MalShare downloads and metadata.** Sample downloads follow HTTPS redirects
  and retain SHA-256 verification and encrypted storage. HTTP refusals and
  malformed result rows now produce errors rather than a misleading empty list.
  Details retain file sizes, and duplicate rows no longer consume the result limit.

- **Stealth profiles.** VM configuration has a Stealth row and a Stealth
  profile window that choose the hardware a VM shows its guest. New VMs start
  as a realistic desktop: a real vendor's SMBIOS identity (BIOS, system,
  board, chassis, memory) and ACPI OEM IDs with fresh serials, the host CPU
  passed through without the hypervisor flag or the KVM signature,
  performance counters and the host's cache sizes, one socket of N cores,
  Intel ICH9 USB controllers, an Intel e1000e card with an Intel MAC address,
  and no VMware port. Realistic laptop and server presets
  pick a machine whose CPU vendor matches the host. Every entry can be
  changed (the profile then reads Custom), and the window lists what still
  gives the VM away. VMs saved before keep QEMU's own identity (Transparent).
  The Summary shows the VM configuration as cards, including the stealth
  profile, with a Configure… button. The guest-run plan takes
  `"vm": {"stealth": "desktop"}`. The disk stays
  virtio and the firmware SeaBIOS, and the guest kernel's command line still
  names Antinomie.

- **Runs that survive restarts and failures.** A run that continued after the
  guest was reconnected or restored is listed in Run History again, with a
  note naming the run it continues. One damaged run record no longer hides a
  VM's whole history, and a history past 1,024 runs lists the newest instead
  of failing. A launch the guest rejected leaves no phantom run behind. A
  queued static analysis gets its full transfer time when it starts, not when
  it was queued. Stopping or starting a VM clears a reconnection left over
  from a stalled boot. QEMU is ended with the app when util-linux `setpriv` is
  available, so a crashed app no longer leaves the VM's disk locked, and a
  QEMU start failure says what QEMU reported.

- **Long sessions stay small.** A run whose program tree ended and whose
  terminal closed no longer keeps its event table in memory until the VM
  stops (about 55 MiB per run before); its trace is read from the saved
  archive. The archive index cache drops indexes unused for 30 days and keeps
  itself under 2 GiB, least recently used first. Run History and the run
  dropdowns rebuild their lists only when the runs change (3,000 runs: from
  about 11 ms to under 0.5 ms a frame), and terminals no longer copy every
  run's analysis report on each update.

- **Responsive while recording.** Run, Upload, Stop and snapshots no longer
  wait behind the disk while a heavy run is being saved: small JSON files are
  published by a background writer and the transport thread never syncs to
  disk. Terminal output of a chatty program is read in full each pass instead
  of 4 KiB at a time. Captured buffers go into a few append-only pack files
  instead of one file each (a heavy run made over 100,000 files). Stop asks
  the guest to shut down before the host makes the recordings durable, and a
  desktop guest gets at least 30 s to shut down before it is forced off.

- **No more stuck buttons.** Command results travel on their own channel with
  a slot reserved for every accepted command, so a busy window no longer loses
  them and leaves Upload, Run program or sample sends waiting forever. A
  pending operation whose VM or boot changed, or whose backend went away, is
  ended with "outcome unknown" instead of blocking the next boot, and nothing
  is retried behind your back. A launch counts as started only when its run
  appears. The status line shows a backend error until a newer message
  replaces it, and Cancel in Run program works while the VM is stopped.

- **Recording survives a long session.** After about 20 minutes of VM uptime
  the next program run could stop all recording of the boot (the "storage
  lost" counter grew and terminal output was not saved). The buffer for
  telemetry that arrives before a launch is acknowledged now keeps each root
  cookie apart, drops packets older than 5 s, never holds the app's own
  resource collector, and reports what it lost as a note on that run instead
  of as a saving failure. A terminal write error stops saving for its run
  only, and the first cause stays visible.

- **Recording quota.** Reaching the quota stops new saving for the boot with
  one clear message and keeps everything saved before: runs that had already
  ended are no longer marked failed, and closed captures stay as they were.
  Packets nobody owns are saved once while a capture observes them, not in
  both the capture and the boot archive. The quota rules are in
  docs/implementation.md.

- **Clearer errors.** A normal Stop is recorded as clean even when the guest's
  acknowledgement races its exit; a launch the guest rejects says so (and
  that nothing started) instead of "outcome may be unknown"; a run whose
  saving stopped keeps its closed terminal in its summary; an error of an
  earlier boot no longer lingers when the next VM starts.

- **Large runs no longer freeze the window.** A page of the saved trace costs
  about one page: it seeks to its place in the recording's index instead of
  reading the whole run, and the "page N of M" counts are computed on a
  separate thread once per run and filter. The first read of a recording
  builds its index much faster; the index is a cache, so it is no longer synced to disk while a recording is being saved, and a damaged one is rebuilt. The process tree and the counts
  no longer hold up terminal replay, history or the next trace page. Triage
  re-reads a live run only while its pane is shown and the recording grew, and
  a finished, unchanged run is indexed once and never written to again. The
  process tree panel is built once per change and draws only the rows in view,
  and a recording with more than 65,536 processes lists the first 262,144 with
  a note instead of failing. The capture lookup, evidence file checks and
  drop-hover checks no longer touch the disk every frame.

- **Run selection and run health.** Runs of an earlier boot stay in Run
  History, Triage and the trace dropdown after the VM restarts: the list is
  read again when a boot starts or ends and when a run ends, and a run that
  leaves the live session is kept until the saved list has it. A Run History
  filter no longer deselects the run chosen in a dropdown; it says the run is
  hidden and offers "Clear filter". Deleting the selected VM clears its run,
  capture, process and archive selections. Choosing another run no longer
  drops a queued read that a view waits on. A run whose saving stopped says so
  in the trace, Run History, Details, Triage and Summary, with the facts the
  recording notes hold shown as muted notes. Dropped on-screen previews (UIL)
  no longer mark a complete recording incomplete.

- **Triage layout.** Section navigation and
  grouped report surfaces distinguish detection results, behavior, files and
  network evidence. Wide behavior/network sections share their height; narrow
  panes stack them. Summary observations open shared Details and exact evidence.
  Properties groups identification, hashes and optional classifiers; detection
  status and evidence details have clearer hierarchy in both themes. Emphasis
  uses the palette text and heading colors, so it stays readable on light
  backgrounds. The specimen name, path and hash header is not shown. Detection
  lists each match with the rule’s recorded explanation and location. Match
  cards follow the rule filter, stay in a bounded list, and open the same
  evidence as the table. Local destination addresses show “-” and “local
  network”. Public addresses can use TShark GeoIP, dig/whois, or GeoIP with
  that fallback. A file change is an observed write or metadata change;
  a mapping alone is not.

- **Run selector in the syscall trace.** The Syscalls view has the same
  program-run dropdown as Triage: the live trace first, then the VM's runs,
  newest first. Choosing a past run reads its recorded syscalls from the
  archive in the background. Triage, the trace and Run history share one
  selection.

- **Summary.** Triage opens with whole-run activity, file, network and detection
  counts. Counts precede table filters and pagination; missing captures or scans
  remain unavailable. Select a count to open its corresponding evidence view.

- **Rules.** Tools → Rule manager installs pinned community packs from the
  public rules bucket at `https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve/catalog.json`.
  Production YARA, IDS and Sigma scans use the enabled packs and custom groups.
  The previous Antinomie-authored starter collections are not loaded. Saved
  results keep
  their original source names. Automatic scanning is on by default and can be
  turned off in Settings. Catalog checks and downloads are explicit and stay
  behind the outbound-catalog setting. A scan does not download rules or
  upload evidence. Pack requirements are checked against the tools the scan
  runs, including the configured Sigma interpreter, and each installed version
  keeps the requirements it was installed with, so a missing or edited catalog
  does not change them. Upgrading an old index keeps rule toggles of the
  selected version. With downloads off, the Rule manager offers to allow them
  in place. It shows whether each engine can scan and links to the repair:
  Suricata is an optional system package in App dependencies, and Tools >
  Analysis tools installs Sigma (pySigma 2.0.1 with its SQLite backend) from
  hash-locked wheels into Antinomie's own environment, which scans use unless a
  Sigma Python is set. App dependencies lists Suricata and Python venv support
  as optional; a missing optional tool does not open the dialog at startup.

- **Rules catalog v2.** The rules catalog (schema 2) now lists where each
  collection is published, not archives we host. Tools > Rule manager downloads
  the files from the publisher (GitHub, rules.emergingthreats.net,
  sslbl.abuse.ch), checks them against pinned SHA-256 hashes, filters them on
  your computer and installs the result as a pack. Each pack shows its source,
  license, pinned revision and the hosts it contacts, and "Allow downloads" now
  names every host. Redirects may only reach the publisher's own hosts, a pinned
  file that differs is refused, and a download you cancel changes nothing.
  Packs the publisher updates in place (Emerging Threats, abuse.ch) install and
  are marked as different from the catalog. YARA-Forge keeps a rule when its
  own license allows it or, when it names none, when its source repository is
  openly licensed: about 4,700 rules instead of 2,100. Rules from repositories
  with no license file stay out unless you tick a per-pack option, off by
  default, that warns they are all rights reserved. New packs: Elastic
  protections-artifacts YARA (Elastic License 2.0, stated in the pack),
  Suricata's built-in event rules (GPL-2.0) and the abuse.ch SSL certificate
  blacklist (CC0). SigmaHQ Linux adds auditd, network_connection and
  threat-hunting rules; accepted connect() calls are now recorded as
  network_connection events (destination address and port), while auditd rules
  are imported and listed as not evaluated with their reason. Matches show the
  repository license a rule took, and the rule-set list and each scan record
  keep the pack's source and revision. A pack can be removed from the manager.
  The old schema 1 catalog and packs installed from it keep working;
  `scripts/rules/prepare-catalog.py` generates the new catalog.

- **Detection.** On-demand YARA, IDS and Sigma tabs evaluate retained evidence
  offline, preserve coverage and source provenance, and open match details in
  the shared Details pane. Local rule folders are optional; Suricata and pySigma
  remain optional host tools. Missing fields/tools are explicit unavailable
  states. Byte previews verify scanned digests; packet evidence includes the
  owning capture segment. Network triage aggregates all run-owned segments
  before queries and pagination. Sigma process events carry a CommandLine
  when the exec's whole argument vector was captured; otherwise it stays
  missing, so a rule cannot match on an argument that was not seen.

- **Detection scan progress and rule sets.** While a scan runs, a progress bar
  on its own row names the rules or evidence being checked. The Scan row keeps
  the scan status (shown only when no scan is running), the matched-rule count,
  the Complete / Partial state and the objects and rules evaluated on its right,
  so the match cards stay in view with Details and Activity docked; a narrow
  pane wraps them below the buttons. Limits of a result are one muted line, with
  the full wording on hover. Each engine lists its installed rule sets, with
  their rule counts, in a collapsible list on the same row as the Rule manager
  button. The local rule folders, scan-recovered
  files, memory extent and Sigma Python options moved from the Detection tab
  to Tools > Rule manager > Options; a saved local path stays in use until
  Forget, and can be imported as a custom group.
- **Match cards and the Details window.** Each matched rule is a card with a
  severity stripe and badge, a short summary, and a facts line with hit count,
  first location, rule pack and author, plus MITRE technique chips. Engine
  metadata is no longer printed as raw text. Details… opens a movable,
  resizable window per finding, and several can stay open. It shows the rule
  id, source, license and author, the description and metadata as rows, the
  original rule text with a Copy rule button, and every recorded evidence
  location, each opening its exact evidence. Results saved before this version
  did not keep the rule text and say so. The side Details pane no longer
  repeats the rule.

- **Triage tables.** Click column titles to sort; archive tables sort the whole
  matched query before paging. Missing values stay last, ties preserve recorded
  order, and right-clicking a title restores recorded order. File triage has
  default-on standard-stream and library-path visibility controls. A cell
  shows at most 240 characters, so hovering a long value such as read content
  no longer opens a box taller than the window; Details keeps the full value.
- **Executable identity.** Process names include committed exec events without
  syscall exits and recorded fork inheritance. File rows retain operation-time
  executable names and PID/TID. Standard descriptor roles retain their numbers;
  relative paths have a compact label while Details retains the missing context.
- **Properties.** Triage displays hashes, file identification and size for the
  selected run's retained executable. Reverification and optional local tools run
  off the UI thread in mandatory offline isolation. Results are saved as JSON;
  missing tools/provider-only fields remain explicitly unavailable. Known saved
  properties stay readable when reverification is unavailable.

- **UI performance.** File-chooser availability is checked asynchronously and
  cached instead of scanning PATH during drawing. Explorer caches its expanded
  tree and renders only visible rows. Quiet windows redraw less often; backend,
  archive and chooser results wake the frontend, while active VM updates retain
  their existing polling bound. App dependencies > Check again refreshes the
  chooser cache. Tools > UI performance shows the actual renderer and bounded
  UI CPU timings; `--graphics-driver d3d12` explicitly selects Mesa D3D12 for one
  compatible WSLg launch. Default graphics selection is unchanged.

- **FPS counter.** Settings > Debug > Show FPS counter (off by default, kept with
  the other settings) draws frames per second, frame time and UI build time in
  the top-right corner of the window, averaged over the last second. It only
  reads frames that are painted anyway and never requests a repaint, so a quiet
  window reads “idle” with the last rate dimmed instead of a made-up number.

- **Run History memory.** The Run History list no longer copies every retained
  run's static-analysis rows on each redraw (a list of 500 runs with full
  reports redrew in about 1.3 ms instead of 90 ms and no longer spiked memory
  by hundreds of MiB per frame). The network quick-filter lists keep only the
  entries they show instead of one per distinct port and address.

- **Shared Details.** Selecting any triage row shows its information in the
  docked Details panel, including suspicious activity, process/file/network
  entries, changed-file diffs and BPF decoding/exports. Row information no longer
  opens hover popups or a second inline inspector. Double-clicks still open
  original evidence.
- **Run triage.** An explicit run selector scopes process, suspicious activity,
  file and network views. Selecting Run history opens that run's triage. Run and
  Capture histories show the host start time first and sort newest first;
  historical entries without a host timestamp remain marked unavailable.
- **Evidence navigation.** Double-click a triage row to open its retained syscall
  or original packet. Syscall jumps include stream, task cookie and call ID;
  packet jumps open the run's owned PCAP and reveal frames hidden by old filters.
- **Files.** Compact Opened files and Read files tables show outcomes and bounded
  captured content. Changed files group original-to-final observed bytes with an
  operation timeline and known byte-difference count. Missing originals, partial
  transfers, unknown offsets, namespace changes and shared mappings retain gaps.
  The source of a sendfile, copy_file_range, splice or FICLONE copy is listed
  under Read files with its bytes marked as not captured, and reflink clones
  (FICLONE, FICLONERANGE) are file changes.
- **Network.** IPs, Hosts, HTTP and DNS tables retain packet evidence links.
  Country/organization use locally configured TShark GeoIP data; missing data
  stays unavailable. Hostnames come from DNS questions, HTTP Host and TLS SNI.
  Dedicated capture ownership comes from the run's artifact manifest, so QEMU
  capture-clock offsets cannot discard every packet. Shared captures retain
  their run-time bounds. PCAP timestamps are identified separately from the
  host clock, and a run-owned capture takes priority over another manual
  capture. The capture list's right-click menu no longer offers Filter by
  field, and the panel no longer lists protocol coverage or reconstruction
  counts above the packets.
- **Presentation.** Removed indexing/count explanation blocks; warnings stay
  below the run selector. Times use the host timezone with an explicit UTC offset;
  guest event times mapped through host receipt anchors are marked estimated.
- **Static analysis window.** A tab strip across the top replaces the left
  category list: File Info (name, size, hashes, format, headers, sections,
  segments, hardening, identification and entropy), Content (the retained
  file paged as a hex dump, text, C array, Python bytes, Base64 or a hex
  string), Strings, Binwalk, YARA, Capa Matrix (capabilities by ATT&CK tactic
  or MBC objective, or as a table), Disassembly, Decompilation and Symbols
  (symbols, imports and exports). A selected row with a file offset opens at
  that offset in Content.
- **Static analysis rows.** Result tables, Disassembly and Decompilation use
  the whole window; the right-hand Details and Bytes pane is gone. Right-click
  a row to select it and copy any column or the whole row, show its details or
  bytes in a floating window, or open its offset in Content. The functions list
  no longer repeats the module note.
- **Embedded content and segments.** Static analysis runs binwalk's signature
  scan as its own category; it records each signature's file offset and
  extracts nothing. Structures records every ELF program header (not only
  loadable ones) as a segment with its permissions, and keeps its full
  listing beside the report, so headers, sections, symbols and imports of an
  unstripped binary are no longer cut to fit the report.
- **Static analysis colors.** Lists color the cell that carries the meaning:
  YARA rule names by severity, string encodings by type, structure names by
  kind (section, segment, import, export, symbol, header field) and Hardening
  values by pass or fail. Metadata labels are muted; hashes and hex values are
  monospace; yes/no and present/absent values are green or amber; timestamps
  read in local time. Entropy keeps its chart.
- **Content zoom.** The Content tab has text size buttons, and Ctrl+wheel over
  the content zooms it too.
- **Static analysis sizes.** Every size in the static analysis window reads as
  `4096 bytes (4.0 KB)`: the exact byte count, then a rounded KB, MB or GB
  figure (1024-based) from 1024 bytes up. This covers the file size, function,
  section and range sizes, Content, and the Analysis tools download sizes.
  Static analysis text says bytes where it said octets.
- **Open directory.** Folder actions ask the desktop file manager through the
  FileManager1 D-Bus service and fall back to `xdg-open`, so a folder no longer
  opens in a search tool registered for directories (Catfish on Xfce).
- **Properties.** ssdeep and TLSH are now computed inside Antinomie (the
  `fuzzyhash` and `tlsh2` crates, matching ppdeep and py-tlsh), so they appear
  without installing anything; a file TLSH cannot hash, such as one under 50
  bytes or an all-zero one, says why. vhash and TrID are no longer listed, and
  an older saved properties.json that has them still loads. Labels and values
  in the table are centered on each other.
- **Magika.** Tools > Analysis tools installs Magika 1.1.0, Google's file-type
  detector, from the official release (pinned by SHA-256, one executable with
  its model built in). The Properties tab runs it in the offline sandbox,
  using Antinomie's copy before the system's.
- **File sizes.** Sizes of files read as `16080 bytes (15.7 KB)` in
  Properties, downloaded samples, snapshots and memory dumps.
- **Upload.** The Upload dialog starts with Executable and Overwrite existing
  file checked.
- **Drag and drop upload.** Dropping one file onto the Antinomie window opens
  Upload with it as the host file and the guest path filled in; nothing is sent
  until you press Upload. Several files, folders, items without a path, a VM
  that is not running and an upload in progress are refused with a note on the
  status line. The QEMU display window does not accept drops.
- **Tree views.** Process trees (triage, capture and history), the guest file
  browser, memory results (pstree), the snapshot tree, packet layers, the
  decoded syscall tree and the analysis options draw branches like the `tree`
  command (`├──`, `└──`, `│`), each level in its own color that cycles through
  six in both themes. Labels keep their colors. A sorted table is flat, and a
  filter leaves a tree of the rows that remain.

Uses existing 0.6.0/0.6.1 guest bases; no kernel or image rebuild is required.

## 0.6.1 — 2026-10-15

- **Aligned VM status cards.** Guest and host resource cards in the same row
  share the tallest card's height, including wrapped notes and unavailable
  measurements. Responsive single-column cards keep their natural heights.

- **Tab dragging.** Drag docked tab labels directly to split or join panes,
  or reorder them within a tab bar. A shadowed ghost follows the pointer;
  a blue pane highlight or insertion line previews the exact destination.
  Escape cancels, ordinary clicks still select, and moved tabs receive focus.
- **Guest resource monitoring.** A temporary bundled static collector reads
  guest `/proc/meminfo` and root `statvfs` every two seconds. VM Status shows RAM
  used/available and root filesystem used/free/available, with age and stale or
  unavailable states. The collector self-unlinks, expires without host input,
  and is stopped before snapshots; reconnect verifies ownership before cleanup.
  Existing images need no packages or rebuild. Kernel-native monitoring is
  deferred to 0.7.0; other guest mounts are outside the root meter.
  Collector startup tolerates `/tmp` not being ready during boot: only a
  confirmed Upload Begin or Exec ENOENT is retried, every two seconds for at most
  one minute. Exec readiness reuses the committed file. Unknown transfer outcomes
  and other failures are not replayed.
- **Host resource observations.** Host RAM availability comes from checked
  `/proc/meminfo` values. Data-volume used, free and user-available space come
  from `statvfs`; reserved free blocks remain free. These host observations are
  labelled separately from guest capacities and retained with the selected VM's
  history. They remain separate from the guest resource meters.
- **Capture and loss guidance.** Disconnected mode visibly explains why packet
  capture is unavailable in VM settings and Network, including while browsing
  saved PCAPs. TRL, UIL and STL names and values each explain their loss type.
- **Stable dialogs.** Import Base reserves room for its folder button rather
  than growing horizontally each frame. Repeated-frame checks cover floating
  dialogs, captured-data windows and detached terminal/analysis panels.
- **Sidebar Explorer.** Below Base images, choose and retain a host folder with
  an expandable file tree. Double-click a file or right-click **Send and Run**
  to prefill the Upload dialog. Press **Upload and Run** to transfer it and
  open Run program on success. **Open Directory** reveals the
  containing folder; folders have their own directory action. VM and base lists
  leave space for Explorer, including when Base images is folded. The tree fills
  the sidebar width; the folder header and Refresh align left with proportional text.
- **Upload file picker.** Choose a file in the filesystem dialog rather than
  displaying another tree inside Upload. Manual file paths,
  executable permissions and overwrite confirmation remain available.
- **Upload and Run.** After a successful upload, open Run program with the
  uploaded guest path. Review arguments and other launch settings before pressing
  Run. Failed uploads, cancelled handoffs and changed VM sessions do not open it.
  Opening Upload hides an existing Run program dialog; Explorer never submits
  an upload before the user confirms the destination.
- **History navigation.** Captures no longer intercepts pointer clicks on the
  Runs tab. Capture filters and keyboard selection retain their focus behavior.
- Compatible with the existing 0.6.0 revision-16 BusyBox and
  Debian GNOME bases. No guest image or transport change.

## 0.6.0 — 2026-10-14

- **VM Summary.** A Summary tab immediately before Run History shows selected VM
  status, base, network and configured CPU/RAM/disk. Active VM health reports
  transport, parser, preview and storage losses, recording failures and load
  shedding. Host measurements show QEMU CPU, resident memory, uptime and free
  space on the data volume. Missing values stay unavailable; capacities are
  distinguished from actual usage. Saved layouts preserve custom windows.
  Aligned CPU, resident-memory and data-volume gauges with two-minute, per-VM
  timestamped histories show measured values with explicit gaps. Switching VMs
  preserves each history; stopped VMs retain their last observation and age.
  RAM gauges describe QEMU's
  share of host-visible RAM; guest RAM utilization is unavailable.
- **Structured filters.** History, triage, static results, core mappings and
  Volatility tables use typed fields, quoted tags, inline completion and field
  context actions. Invalid expressions retain the previous valid result.
  Native syscall argument names come from the pinned schema; captured structure
  members use checked x86-64 layouts. Missing capture bytes remain unavailable.
  Syscall predicates scan every retained call in a cancellable worker; pages
  and counts reflect all matching calls, including matches beyond the first page.
  Volatility queries and sorting cover every retained row with bounded pages.
- **Wireshark packet filters.** An installed TShark supplies its display-filter
  grammar and field glossary. Filtering runs in an isolated, resource-bounded
  background job over the whole capture; live captures use a complete-record
  prefix. Capture names/tags have a separate Record filter. Original PCAP files
  remain intact; quick text search is labeled separately. Cancellation confirms
  sandbox child termination before reporting cleanup complete.
- **Triage and BPF.** Process, file, HTTP and DNS views read complete retained
  recordings with refresh controls, paged results and versioned findings linked
  to their evidence. Classic socket/seccomp and eBPF instruction views provide
  exact raw exports, helper names and explanatory pseudocode; failed attempts
  and missing observations remain distinct from successful operations.
- **Historical MalShare.** Last-24-hour, seven-day, thirty-day, custom-range and
  all-cached metadata modes validate dated lists, retain progress and resume
  offline. Archive dates are labeled separately from first-seen timestamps.
- **Retained-result navigation.** Run/capture selection updates Details and
  supports keyboard navigation. Labels, related-run links, mapping/function
  filters and export/directory actions preserve original evidence identity.
- **Core analysis and exports.** Genuine process cores support on-demand
  disassembly and sandboxed Ghidra decompilation, with saved function lists,
  colored code, horizontal scrolling and native project exports. Exported
  projects use the current account's ownership metadata so Ghidra can reopen
  them; original evidence stays unchanged. Failed or cancelled jobs retain
  earlier successful results and bounded diagnostic logs. Per-process memory
  and file-descriptor limits apply to external analysis jobs. Isolated workers
  retain process ownership through cancellation and shutdown, including setup
  failures; incomplete cleanup remains visible and blocks new workers.
- **Live Dump core.** The toolbar and Core dumps offer a process picker for
  pause/capture/resume using exact guest identities. Requires revision 16; older
  bases display the reason capture is unavailable. Repeated cores have separate
  IDs, status, result directories and run links. Native ELF thread notes accompany
  resident-only memory; omitted ranges remain unavailable rather than zero data.
  Manual auxiliary storage adds at most 8 MiB to the existing 128 MiB payload
  pool. Snapshot operations wait for acquisition to release its process pause;
  uncertain admission is reconciled without replaying capture.
- **Movable Run program.** Drag the title bar to reposition the window; reopening
  preserves its position while initial size stays within the viewport.
- **Core Dump on Exit.** Opt-in capture retains a Linux x86-64 ELF core of the
  launched root process before its normal exit or fatal-signal teardown, with
  thread registers and memory mappings. This requires a revision-15 guest base
  and an app-terminal launch; ordinary launches on older bases remain supported.
  Runs link their retained core and metadata to the core viewer and result folder.
  The viewer discovers acquired and unfinished captures without parsing each ELF
  eagerly; reopening a capture preserves its labels and tags.
  Core dumps use Memory's resizable capture sidebar and right-hand analysis area.
  Import controls open in a dialog; mappings and function lists are resizable,
  and analysis controls stay reachable at large font sizes.
  Unfinished captures update automatically as retained metadata and memory become
  available, preserving loaded thread, mapping, code and filter selections.
- **Bounded core acquisition.** Linux's memory filter remains effective. The
  default 64 MiB/5-second serialization limits retain explicit partial results;
  four handles and 128 MiB bound guest reservations. Thread rendezvous and faulting
  memory reads cannot guarantee a strict wall-clock deadline. SIGKILL preserves
  immediate termination and can leave context unavailable. Cancellation stops
  acquisition while allowing the program to continue.
  Bounded disk workers handle writes, hashing and durability without blocking
  ordinary transport passes. Final acquisition state requires durable metadata.
- **Core recovery.** Full snapshots retain core-handle ownership. Restore and
  reconnect validate guest identity before reading into a fresh evidence timeline;
  earlier files remain retained. Launch/arm side effects are never replayed.
  Transfers preserve available prefixes, hashes and quota/failure information.
- **Reliable status and imports.** Late run-status replies remain associated
  with their original run and execution generation, and successful recovery
  clears that poll's stale diagnostic. CLI base imports wait for the verified
  result instead of reporting failure while a large desktop image is still
  being installed. Long status messages stay within the space beside the
  right-aligned loss counters and retain their complete text on hover.

## 0.5.0 — 2026-10-12

Existing bases still cold boot and support disk checkpoints. Full snapshots and
transport reconnect require a new guest base with contract revision 14 / ABI9.

- **Evidence controls.** Dump memory and Core dump sit beside Capture network.
  Saved runs, captures, dumps, Volatility results and static reports have names,
  tags and result-directory actions. Names and tags preserve original files.
- **Launch evidence.** Optional network capture starts before launch and stops
  after the entire process tree exits. Manual captures remain independent.
  Optional Memory Dump on Exit records VM RAM after tree exit; freed process
  memory may already be gone. Core Dump on Exit is deferred to 0.6.0 guest work.
- **Core dumps.** Import Linux x86-64 ELF process cores: select a thread for
  registers, browse mappings and their available hex data, recover file mappings
  and auxiliary notes, and request disassembly using an optional matching binary.
  Original files stay in place. QEMU physical RAM belongs in Memory instead.
  Unwinding, a process-core decompiler and other core ABIs are not implemented.
- **Readable static results and exports.** Wider details, horizontally scrollable
  code and wrapped messages; export retained sections or reports as text/JSON.
  Ghidra analysis retains its native project for export and opening a working
  copy in Ghidra. Reports show related runs; runs mark available static analysis.
- **Run history.** Saved descendant trees, child selection, trace page counts
  (100 calls per page), and available data from unfinished recordings.
  The Run program dialog uses more vertical space.
- **Isolated network.** QEMU restricted user networking permits guest-local
  networking and packet capture without outbound access or host forwarding.
  Disconnected remains the default; unrestricted NAT is still explicit.
- **Recovery.** Run captures resume in fresh segments after transport reconnect
  and unsuccessful snapshot recovery when the original VM survives. Ambiguous
  RAM-dump QMP outcomes retain their files and pause until reconciled.
- Native snapshot manager with disk or disk + memory capture, branching graph,
  current working state, rename and dependency-safe hiding.
- Restore by rebooting from disk or resuming saved RAM/CPU/devices. Confirmation
  can save the current state first. Full resume initially requires the original
  host, QEMU, kernel and hardware configuration.
- Guest acknowledgement fences transport reattachment without resetting per-CPU
  telemetry. Unresolved commands are reported and never automatically retried.
- Full restore and reconnect create fresh recording timelines and retain old
  archives. Disk operations use durable journals and preserve interrupted work.
- Snapshot-aware VM duplication flattens the current branch. Reset, disk resizing
  and data relocation are guarded while checkpoint dependencies exist.
- **Snapshots** on the toolbar; the snapshot window keeps a margin to the app's
  edges and room inside its graph nodes. Memory dumps and snapshot or reconnect
  operations never overlap.
- **Daemonizing programs keep running.** A launched program led its terminal
  session, so its exit hung up the children it had just forked: Mirai and
  most Linux malware died at their first fork. The guest kernel (patch 0020)
  now launches programs as a terminal's shell would; bases must be rebuilt.
- **Capture All no longer freezes a desktop guest.** When the host cannot
  decode and save telemetry as fast as a busy guest (GNOME) makes it, the
  guest drops records instead of waiting on every system call; never-drop
  resumes once the host catches up, and the status bar says so. Twenty
  `ls -la /usr/bin` under Capture All on GNOME: 106 s before, 0.7 s now.
- **A guest that stops answering is reconnected.** When its heartbeat
  stalls (its vCPUs starved by a busy host), the transport gave up for good
  ("Connection timed out") until the VM was restarted. The app now waits
  30 s instead of 10 before giving up, then reconnects by itself (VM >
  Reconnect telemetry, retried 2, 4, 8, 16 s apart) and says so.
- **New VMs get their whole disk.** The guest's filesystem was never grown
  to the VM's disk size ("Guest filesystem resize failed" at first boot): a
  16 GiB Debian VM kept the base's smaller filesystem. It now grows online at
  every boot; bases must be rebuilt.
- **Malware samples: shell scripts, and Send and run… opens Run program.**
  The newest list holds ELF programs and shell scripts (droppers, miner
  installers), which run in the guests (scripts through /bin/sh); "Newest
  Linux" replaces "Newest ELF". Send and run… sends the sample, then opens
  Run program with it as the program, to set arguments, user, where it runs
  and analysis. Sending a sample again replaces the copy in the guest
  instead of failing with "File exists".
- **Window close buttons work again in Comfortable density.** With the
  wider margins of the spacing pass, egui's title bars ignored clicks on
  their close button (every window, text size 16 and up); Escape still
  worked. A test now clicks a window's close button at every density and
  text size from 12 to 24. The Snapshots window also keeps its size while it
  loads and opens centred, even when a position saved by an earlier version
  is off the screen.
- **Recordings still being written open.** A run whose programs live on
  (a daemon, most malware) or a running capture failed to open with "raw
  archive changed while building index; retry after capture settles", which
  never settles while the malware runs. The index now covers what is written
  so far and grows on the next read.
- **Sending a sample again while the last copy runs works.** Each send gets
  its own file in the guest (`/tmp/<hash>-2-<name>`…): a running copy cannot
  be replaced ("Text file busy").
- **A detached program's terminal no longer reports errors.** Resizing the
  terminal of a program that closed it (a daemon, as its window opened) was
  logged as "terminal is closed".
- **How a task ended is shown on the call it ended in.** `exit_group` and
  `exit` never return, so the trace showed them as "missing Exit" (a warning)
  although the kernel records every task's end. The call now shows "exit 1"
  or "killed by SIGKILL" (Task ended), its Exit as none, and the kernel's task
  exit record under Phases; a program killed while blocked in a call shows
  it there. Captures listed exit statuses raw ("exit 256" for `exit(1)`).
- **Phases list what each one captured.** Entry and Exit expand to the
  objects recorded at that point (a read's buffer under Exit, by argument
  name), and a read that returned 0 bytes says there was nothing to capture.
- **stall-check** (example): freeze a guest's QEMU and check that the app
  reconnects.
- **run-dump** (example): print a recorded run's system calls, and how each
  task ended. **event-dump** (example): print every assembled record of a
  run, lifecycle records included, with each captured field.
- **More room everywhere**: taller tab bars with space around tab names,
  menus wide enough that shortcuts stand apart from their items, space above
  section headings, and roomier syscall category chips (Comfortable density).
- **Malware samples** (Tools): the newest ELF samples as soon as the window
  opens (up to 1000, with architectures; "Newest (all)" for every type), a
  SHA-256 column; one search box for a family, tag, file type or hash, with
  your own free API key; File type, Architecture, Family and Tags dropdowns
  (tags as checkboxes) and sortable columns over the results; one-click
  families that run on x86-64 Linux. A second source, MalShare (free key,
  2000 requests a day): its newest ELF samples, search by hash, file type,
  file name or source; MalShare serves files unencrypted, so each one is held
  in memory, checked and written straight into an encrypted archive. Download samples, and send them into the running
  VM, or send and run them as the guest user or root, recorded like any
  program. Samples stay in MalwareBazaar's encrypted archives in the data
  folder and are decrypted only in memory to be sent into the guest: nothing is
  unpacked or run on the host. Each sample shows its processor (only x86-64
  runs in the guests), warns when the VM has NAT on, and keeps every VM it was
  sent into. The first time, a warning about handling live malware (NAT, VM
  escape, antivirus, the law) must be accepted before the window opens; a
  MalwareBazaar refusal such as a search that takes too long is shown as
  MalwareBazaar words it.

## 0.4.1 — 2026-10-11

- **Symbol tables online.** Linux and macOS dumps without a symbol table of
  their own (imported dumps of other machines) have their kernel's table
  looked up by its banner in Abyss-W4tcher/volatility3-symbols, about 11,000
  distribution kernels (Ubuntu, Debian, Kali, Alma, Rocky), after
  Volatility's own folders; downloaded tables stay in Volatility's cache. On
  by default, in the Memory tab's options (gear); dumps of Antinomie's VMs
  keep their base's table and stay offline. A dump whose kernel is nowhere
  says so, and how to make its table.
- **Community plugin catalog.** Community → Plugin catalog lists Volatility 3
  plugins by other authors that run on this Volatility: GnuPG agent secrets
  (Kudelski Security; recovered a cached passphrase on Debian 13), OpenSSH
  session keys (Fox-IT; for older OpenSSH, found none with OpenSSH 10),
  BitLocker keys and Notepad and KUSER time for Windows dumps, each with what
  was tested and its known limits. Install downloads each from its
  author's repository at a pinned commit, checks every file's SHA-256 and
  applies only the compatibility edits shown; Update and Remove as listed.
  Plugins that bring symbol tables have them found.
- **Plugins for another system.** Linux, Windows or macOS above the plugin
  list: the dump's own system by default, with a warning when another is
  chosen.
- **Results.** Click a column name to sort ascending, again descending, a
  third time back to Volatility's order (sorted results are shown flat).
  **Text** shows a result as Volatility prints it, tab-aligned with `*` for
  nested rows; Copy follows the view.
- **Comfortable density everywhere.** Settings → Density (was Table rows):
  Comfortable now also widens spacing, padding and tab margins, not only
  table rows.
- **Fixes.** A long plugin description no longer widens the Memory tab and
  pushes its controls off screen; the result header keeps its controls and
  shortens the plugin name instead. The import dialog lists every base,
  those without a symbol table greyed with the reason. Volatility's own
  deprecation notices no longer fill a run's messages. A plugin that prints
  text itself no longer loses its result rows (the text goes to its
  messages). An imported dump whose file was moved or deleted says "file
  missing" and is not run.

## 0.4.0 — 2026-10-11

Needs new bases for memory analysis of the VM's own dumps (BusyBox and
Debian 13 for Antinomie 0.4.0, which carry their kernel's symbol table).
Bases for 0.3.x still run and can be dumped, but their kernels were built
without debug information, so Volatility has no symbol table for their dumps.

- **Memory tab.** Beside Network: **Dump memory** writes the running VM's RAM
  to a dump of its recordings (QEMU pauses the guest while it writes: seconds
  to minutes, by RAM size and disk speed) and lists every dump of the VM.
  **Import dump…** adds a dump made elsewhere (raw, LiME, ELF core, crash
  dump, VMware or VirtualBox memory, hibernation file) for Linux, Windows or
  macOS; the file stays where it is.
- **Volatility 3 plugins, as in Volatility Workbench.** Pick any of the
  plugins for the dump's system (searchable, grouped by area), set its
  options in a form built from Volatility's own option list (PIDs, dump
  switches, YARA rules...), and **Run**. Each run is saved with its dump —
  result, messages and the files a plugin wrote — and listed under
  **Results**, so earlier results open again at once. Runs show live
  progress, can be cancelled, and are set up again from their right-click
  menu.
- **Community plugins.** Volatility 3 plugins (`.py` files) put in
  `volatility-plugins` of the data folder (**Community → Open community
  plugins folder** in the Memory tab) are listed after Volatility's own,
  with their options; plugins that fail to load are named with the error
  count. They are ordinary Python and run as the user, outside any sandbox.
- **Results.** Columns colored by type (addresses, numbers, flags, text),
  process trees indented, a row filter, copy as tab-separated text, sideways
  scrolling for wide results, and the selected row's full values in Details.
- **Volatility 3 install.** **Tools → Analysis tools** installs Volatility 3
  (2.28.2) with its pinned dependencies (about 5 MB) for the system Python 3.
  The first plugin run builds Volatility's cache (about a minute and a half);
  later runs take seconds.
- **Bases carry their kernel's symbol table.** Base builds compile the
  kernel with DWARF debug information and add its Volatility symbol table
  (`symbols.json.xz`, about 3 MB for BusyBox) to the base, made by
  Volatility's dwarf2json (pinned). Dumps of the VM need no symbol download.
  The builder VM gets a temporary swap file for this step when it has less
  than 12 GiB of RAM.

## 0.3.1 — 2026-10-11

Interface redesign. Runs the same bases as 0.3.0; no new base is needed.

- **Light theme and table density.** **Tools → Settings** switches between
  Dark and Light and between Compact and Comfortable table rows; both apply at
  once and are remembered. Light-theme row colors are pale tints of the dark
  ones, as in Wireshark.
- **Values colored by meaning** in the trace, Details and packet views:
  numbers, strings, pointers, flags, symbolic names and errors each have their
  own color. Data columns use a monospace font. DejaVu Sans and DejaVu Sans
  Mono are bundled, so arrows, box-drawing and other symbols render everywhere.
- **Syscall trace.** Arguments read by meaning (`dfd=AT_FDCWD
  filename="/etc/passwd" flags=O_RDONLY|O_CLOEXEC`), errors shown by name
  (`ENOENT`) with the number on hover, failed calls marked at the row edge,
  columns that adapt to the window, and category filters that wrap to two
  lines instead of scrolling.
- **Details, Wireshark-style.** The selected call's decoded tree is on the
  left and the selected value or captured bytes on the right; the hex dump
  shows 16 bytes per line when there is room. Selecting a call starts on its
  captured data. On the Network tab, Details show the selected packet's
  layers and bytes.
- **Guidance when there is nothing to show.** A stopped VM's trace offers
  Start VM, its recent runs and captures; the Static Analysis and Network
  panels explain what they need.
- **Fewer, clearer toolbar buttons**, a sidebar that shows each VM's state,
  base, CPUs and recordings at a glance, a status bar with the loss counters
  and recording quota, and dialogs laid out in labeled sections. Escape closes
  the topmost dialog.
- The capture process tree has more spacing, and earlier network captures
  are listed by start time (UTC, with boot and file on hover).

## 0.3.0 — 2026-10-10

Needs new bases for the transport settings and Never drop mode (BusyBox and
Debian 13 (GNOME) for Antinomie 0.3.0). Bases for 0.2.0 and 0.1.0 still run,
with 256 KiB buffers that drop when full.

- **App dependencies.** Runtime requirements are checked in the background at
  startup, including QEMU's GTK display support. Missing requirements open
  **Tools → App dependencies** with install commands and a **Check again**
  button; affected actions are blocked while saved recordings stay available.
  VM startup rechecks requirements before allocating RAM or starting QEMU.

- **Capture All by process.** A capture lists the processes it observed as a
  tree, named after the program each one executed (or its command name when
  it was already running), with call counts and exit codes. Selecting one
  shows only its calls, live and in saved captures (`processes.json`).
- **Telemetry transport settings** (VM **Settings → Telemetry transport…**):
  guest buffer per vCPU (256 KiB to 4 MiB, default 1 MiB), **Never drop**
  (the default: a system call waits up to 5 s for the host instead of losing
  its record) or **Drop new telemetry**, and the host event table size
  (default 16,384). Capture All over a GNOME boot lost 52-80 % when dropping
  and nothing in Never drop mode.
- Recording writes go to a background writer thread with a 256 MiB queue, so
  a slow disk no longer stalls telemetry draining; in Never drop mode a disk
  that stays too slow slows the guest instead of losing data.
- The host event table retires finished calls first; only calls still in
  progress count as evicted.
- **Network capture.** With NAT on, start and stop captures without restarting
  the VM. Each capture has its own pcap in the boot recording, outside the
  guest. The **Network** panel offers capture history, protocol colors,
  clickable address/port/protocol filters and counted dropdowns, with a byte
  view and Wireshark integration.
  Network captures count against the boot's recording quota; a running one
  stops when the quota is full.
- Process terminals freely resize and maximize, update the guest terminal
  grid, and retain 10,000 history lines with wheel and scrollbar navigation.
- **Details** offers common numeric copy formats and captured-data windows
  with UTF-8, ASCII, hex, hexdump, C array, Base64 and escaped forms. Invalid
  extents are rejected, and partial captures keep their gap/error status.
- Static analysis names the categories still queued or running until the
  selected report finishes.
- Commands queued while the transport thread is busy are handled together
  instead of one per pass.
- **Run in the guest desktop.** On desktop bases, **Run in** in the launch
  dialog runs a program in the logged-in graphical session, so its windows
  appear on the VM screen (**Guest desktop**), or in a terminal window on the
  VM screen (**Guest desktop terminal**). The program stays in the run's
  process tree and trace. Run History shows each run's choice.
- **Faster base builds.** Debian builds reuse a recently bootstrapped root
  filesystem with the same answers (30 days), so a new kernel only replaces
  the kernel and its modules; kernel builds go through ccache in the
  builder.
- Continuous integration: formatting, lints, tests, build-script tests and a
  machine-path check on every push; a nightly test boots the current BusyBox
  base and requires a heavy Capture All run to lose nothing; version tags
  build and publish the release.

## 0.2.3 — 2026-10-09

Runs bases for Antinomie 0.2.0 and 0.1.0; no new bases.

- **Fewer lost telemetry packets.** While telemetry is flowing, the monitor
  now drains the guest's buffers continuously, instead of reading at most 256
  packets every 10 ms. On a Capture All stress test it saved 8.5 times as many
  packets per second.
- Raw telemetry is written in large blocks and object files stay open between
  chunks, so saving a packet costs fewer system calls.
- Guest RAM is now kept in memory instead of in a file in the VM folder. The
  host no longer writes guest memory back to disk, which used to stall the
  guest and its telemetry. RAM larger than half of memory plus swap still
  uses the file; `ANTINOMIE_GUEST_RAM=file` forces it.
- On startup, the app deletes guest RAM files left behind when the app
  closed without stopping its VM (several GB each). A running VM's file is
  kept.

## 0.2.2 — 2026-10-09

Runs bases for Antinomie 0.2.0 and 0.1.0; no new bases.

- **Download base**: clearer rows, current bases first, older bases behind
  **Show older bases**, versioned names and persistent progress with Cancel.
  Cancelled downloads retain their files for resume; closing the app stops
  its download worker.
- Installed older bases show an outdated hint and link to the download dialog;
  a matching current catalog base adds **newer base available**.
- Base checks run after the window opens, with **Checking base images…** status.
- Unchanged installed bases reuse their verified checksums. Large-file hashing
  releases Linux file cache as it reads, reducing WSL memory use on startup.
- Typed paths expand a leading `~` to the user's home directory.

## 0.2.1 — 2026-10-09

Runs bases for Antinomie 0.2.0 and 0.1.0, like 0.2.0; no new bases.

- **Tools > Analysis tools**: when capa, Detect It Easy or Ghidra is not
  installed on the system, Antinomie can download it from its upstream
  release (checked by SHA-256) into its data folder; static analysis then
  uses it, read-only, inside the sandbox. A tool installed on the system
  still comes first. The launch dialog and unavailable analysis categories
  offer the install when a needed tool is missing.
- Static analysis sandbox: tools that start from `/bin/sh` scripts and tools
  that ask for the user name (capa, Detect It Easy) now run; the sandbox has
  a neutral host name.
- Messages and the About window name app versions for bases and kernels.
- Release executables no longer contain the build machine's file paths.

## 0.2.0 — 2026-10-09

Runs bases for Antinomie 0.2.0; bases for 0.1.0 still run, without process
attachment and capture.

- Static analysis of the guest executable, opt-in per run, in an isolated
  sandbox: metadata, structures, all strings (ASCII and UTF-16LE), entropy,
  hardening, rules, identification, capabilities, disassembly and
  decompilation, in one workspace or separate panes.
- Disassembly built in (x86 and x86-64, iced-x86): every instruction with
  address, bytes and resolved call targets, functions from symbols and call
  targets; other architectures through objdump.
- Decompilation through a locally installed Ghidra (headless, inside the
  sandbox) or radare2, shown as numbered, highlighted source per function.
- Rules with the built-in YARA-X engine: Antinomie's own rules plus 2096
  redistributable community rules from YARA-Forge; capabilities through an
  installed capa with the bundled capa-rules v9.4.0; compiler, language,
  runtime and packer identification from built-in signatures, file magic and
  Detect It Easy when installed.
- Large results (disassembly, decompilation, strings) are kept in full and
  read page by page, with search over the whole listing.
- Attach to a guest process and its future descendants, or capture all of
  userspace, independent of launched programs. No per-boot capture limit
  (earlier guests allowed 64); the process picker lists every process with a
  filter.
- Prebuilt bases for this version: BusyBox `aaf26eed…` and Debian 13
  (GNOME) `a12b52ab…` on the Hugging Face bucket
  `MoreMorePwn/antinomie-bases`.

## 0.1.0 — 2026-10-08

Runs bases for Antinomie 0.1.0.

- QEMU VM monitor with a patched Linux 6.12.94 guest kernel that records
  native x86-64 system calls, their arguments and asynchronous I/O over a
  shared-memory transport (ABI 7).
- Dockable workspace: VMs, bases, runs, paired syscall trace, terminals,
  per-VM history and storage locations.
- Bases: download (checksum-verified catalog), import, and the **Build base**
  wizard: installer-style questions (base, build mode, language, keyboard,
  time zone, hostname, Debian desktop, software, mirror and proxy), built on
  this Linux host or in a QEMU builder VM, with a cached kernel per app
  version.
- Bases record the app version that built them and the oldest app version
  that can run them; the running guest kernel is checked against its base.
- Guest RAM up to 8 GiB (regions above 4 GiB mapped).
- `./run.sh` and per-user `./install.sh` (command, menu entry, icon).
- Syscall trace rows colored by category (eleven groups covering all 375
  native syscalls) with a category filter; failed calls marked in red.
- Debian builds offer the installer's desktops (GNOME, Xfce, GNOME
  Flashback, KDE Plasma, Cinnamon, MATE, LXDE, LXQt) and a base name.
- Prebuilt bases for this version: BusyBox `312bfe10…` and Debian 13
  (GNOME) `64953c89…` on the Hugging Face bucket
  `MoreMorePwn/antinomie-bases`.
