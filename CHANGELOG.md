# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version says which bases
it runs.

## 0.9.0 — 2026-MM-DD

Runs the bases 0.8.3 runs (contract revision 20) and the bases built by this
release (contract revision 21), arm64 BusyBox and Debian 13 Minimal among
them. An app older than 0.9.0 refuses a revision-21 base and an arm64 base
before it starts a VM. x86-64 bases built by this release also record 32-bit
x86 programs by their own table.

### Host

- **Argument positions come from the call's own ABI table (ANT-T0440).** Triage rules, the
  process record, the Sigma and auditd address fields, the trace's field roles and the
  capture's exec path looked up argument positions in the x86-64 table for every
  architecture. They now read the table of the event's ABI, so a role such as `clone`'s
  `tls` (argument 4 on x86-64, 3 on arm64, AArch32 and ia32) is found where that
  architecture puts it. x86-64 results are unchanged.

- **A packed sample gets its family, imported files get MalwareBazaar's signature, and a
  dead command server is a finding (ANT-T0399).**
  - A family named only by a layer static analysis unpacked from the sample (UPX and
    the like, scanned with YARA since T0398) is a family candidate of the sample
    like any other, on the Summary, the sample page and the sample report, and its
    source says "in the unpacked payload". A match is marked as the payload's when
    all its evidence is in unpacked layers.
  - **Settings > Lookup > Imported files > Look imported files up at MalwareBazaar**
    (off by default; a daemon or container never turns it on). After **Add file**, and only
    with your own abuse.ch key (Tools > API keys), the file's SHA-256 (nothing else)
    is sent to MalwareBazaar. A record with a signature or tags is kept with the
    sample, noted in its custody log, and its signature is a family candidate with the
    source "MalwareBazaar signature (looked up by hash)". A sample that already has a
    record is not asked about. With the setting off, or no key, nothing is sent.
  - **Retries a dead command server** (`network.dead_c2`, Medium, Command & control): ten or
    more failed connects (refused, timed out, network or host unreachable) to one public
    address and port that never once succeeded, in the whole run and whatever process
    made them. DNS, NTP, DHCP, mDNS, local addresses and base image programs are not
    counted, and one success clears the address. The row counts the failures from the
    tenth on and shows their pace.

- **Every finished run gets its Triage digest by itself, heavy runs included
  (ANT-T0400).** The digest (behaviour findings, process lineage, written files and
  indicators behind the sample window, the rollups and the reports) was written only
  once someone selected the run and its scan finished, so a run nobody opened had none:
  the Ladvix run (1.18 million calls dropped, 3.7 GB) and Symbiote 1 (telemetry lost)
  of the malware evaluation showed no digest until opened by hand. Now the window hands
  each run that ends to a digest queue that builds one digest at a time, smallest
  recording first, off the UI thread: the recording is streamed page by page and read to
  a budget (400,000 calls, 20 minutes), and the digest is marked partial, with the
  reasons, when the budget ended the read or telemetry was lost. A digest made while
  the recording was still being written is made again when it changes; an interrupted
  build leaves nothing half written and is made again. Selecting the run while it builds
  shows its progress instead of starting a second read (**Read it here now** takes over).
  Auto mode builds the digest of any job's run the scan left none for and warns when it
  is partial, and the new `antinomie-cli digest RUN` / `digest --pending` run the same
  build. The digest records how much of the run it was built from (`coverage`).

- **Persisted copies outside the recorded tree are found, and runs wait for the
  guest's network (ANT-T0433).** Malware that persists had its copy started by cron or
  systemd outside the recorded tree: Mirai's `.e` killed the recorded bots and a
  `Heyiwei.service` kept running, and the run ended "exited" after 15 to 25 s. The host
  now lists the guest's processes during a run, reads the program of each new process
  outside the tree (`/proc/<pid>/exe`, through the existing ACQUIRE command) and hashes
  it: one that runs the sample or a file the run wrote is named in the run's notes
  (pid, name, who started it, SHA-256), listed as the HIGH Triage finding
  `persistence.copy_running`, and named as the killer in the run-end note. When the tree
  ends while such a copy lives, the run is held open (network capture and route go on)
  until the copy exits, Stop run (offered in the window as for a live run), `run exec`'s
  run limit, the VM stops or 10 min pass; while held the run reads "Held: persisted copy
  running (pid N, name)" in Run History, the run header and the sidebar, and `run list`
  shows `held` (query API `RunInfo.held`). `run.json` keeps it under `persisted`. On a Routed VM a launch also waits, after the boot wait,
  until the guest has its address (the gateway sees it send from its lease or answer
  ARP; `start.network_wait_secs`, 30 s, 0 for off), notes a run that started without a
  network, and Triage's notes count the ENETUNREACH calls and their window. No guest
  change; the copy's own calls are still not recorded.

- **A slow TCG boot no longer fails the VM Start at 180 s (ANT-T0442).** The service's
  180 s limit on the VM `Start` command was fixed, so on a busy host the engine's own
  TCG wait for the guest to connect could outlast it and the job failed with "the VM did
  not start in time". The limit is now a silence limit: under TCG, while the engine
  reports that it waits for the guest to connect, it does not run, and a Start still
  ends at 30 minutes at the latest or 180 s after the engine goes quiet. KVM keeps its
  180 s, and a QEMU that exits still fails the start at once.

- **Snapshots restore works every time, and other fixes from the ARM evaluation
  (ANT-T0437).** In the Snapshots window, **Restore disk and boot…** and **Resume
  disk + memory…** did nothing from the second use in a session: the question opened
  behind the window. It now opens on top each time. Opening the Core dumps tab no
  longer raises an error toast (and "Capture issues") for every run that never
  started: such a run has no cores and is not listed. The report's Key findings are
  numbered 1, 2, 3… and each row links to its finding (a folded group of one rule
  links to its shared row); At a glance names the guest architecture, and the
  Transparent profile reads "Transparent QEMU" there. `run export --part trace`
  writes the number the guest used for each call in `nr` (it was 4294967295 on
  arm64, arm and i386); its `args_preview` holds the engine's raw argument previews,
  and the decoded records are in the Syscall Trace's own JSON export. `vm create`
  and `snapshot create` print the created VM or snapshot instead of `null`. The
  partial-core note reads "The VM was stopped before the core was finished. Only the
  part saved so far is kept; it is not continued after a restore or restart." The
  IDS page says "Suricata 8.0.7 is installed.", the status bar says "Sigma (pySigma)
  installed" when an install ends, and the sidebar names the newest run of the
  selected VM even when the command line made it.

- **A program the guest cannot start says why, and the result names its run
  (ANT-T0430).** An armhf program on an arm64 base without
  `/lib/ld-linux-armhf.so.3` used to read "the program or the working directory does
  not exist", an old-ABI ARM (EABI0/OABI) program "Exec format error" and a cut-off
  ELF "Bad address". The host now reads the program's ELF headers and says "needs the
  program interpreter ... (not in this guest's base)", "old-ABI ARM (EABI0/OABI), which
  an arm64 kernel cannot run", "This ELF is truncated: ..." or "wrong architecture for
  this VM", marked as identified on the host, and keeps the guest's own error text. The
  `run exec` result and the Auto job's `failure` carry `run_id` (and `run.id`) of the
  "Failed to start" record in Run History when the launch kept one. A program that
  crashed before its first call no longer shows "running" in the Process tree: its row
  shows the run's signal, and the crash note names a truncated ELF when the static
  analysis found one.

- **Headless runs can take a dump on suspicious activity (ANT-T0439).** The
  live Triage judge was registered only by the window, so `run exec` and Auto
  jobs could not use the dump trigger. The run lane of the service now registers
  the same rule engine before a launch that asks for a trigger (one set of rules;
  the service and the CLI still do not depend on the window's crate).
  `run exec --dump-trigger low|medium|high` (default off) with `--dump-kind
  core|memory|both` (default `core`) and the Auto policy keys
  `evidence.dump_trigger` (`off`, `low`, `medium`, `high`) and
  `evidence.dump_trigger_kind` (checked by `config validate`; a core uses
  `evidence.core_max_mib` and needs a revision-16 base, which `auto init` asks
  for) turn it on; both default to off, so nothing changes until asked. The
  result of `run exec` has a `triggers` object (what was armed, whether it fired,
  each match with its rule, tier, process and call, and the state, size and path
  of its core or memory dump, or the note that it was armed and nothing matched).
  An Auto job's `run.triggers` and `run.trigger_notes` say the same (no host
  paths for a remote caller), and `job.trigger` events report each match and each
  note as it is known. The collect stage now waits for a trigger dump that is still
  being written.

- **`run exec --start` no longer loses Debian arm64 launches under TCG
  (ANT-T0425).** About 30% of launches failed with "the engine did not answer
  Execute within 60 seconds": the launch waits for a Debian guest to finish booting
  (the boot wait, stretched by the TCG multiplier), and the fixed minute of engine
  silence ran out first. The silence now ignores the time the engine reports waiting
  for the boot and is stretched under TCG by the engine's own factor (the TCG
  multiplier times the host load), as are the upload, launch and guest-answer waits
  and the host's own guest commands ("the guest's control worker made 0 passes in
  12000 ms" on a busy host); KVM keeps its times. A launch the engine answers after
  the job gave up on it no longer leaves an unreported run: the VM is stopped, the
  result (or the Auto job) names the run and warns `late_launch`. The boot wait and the
  TCG multiplier are now in `settings.json` (`start`, shared with the window) and
  `--boot-wait` and `--tcg-multiplier` set them for one command. The "guest is not
  ready for files yet" progress is said at most every five seconds with a count,
  instead of four times a second, and the upload retries once a second. A VM whose
  QEMU exits before it opens its monitor socket now fails its start at once with
  QEMU's own words, instead of after the whole startup wait.

- **No more false "UPX (header modified)" on unpacked ARM programs, and no
  "Rust" for GCC builds (ANT-T0431).** The UPX check accepted any ELF whose
  tail had bytes shaped like UPX's version, format and size fields, even with no
  `UPX!` magic anywhere, so unpacked GCC, musl and Go programs were called
  "UPX (header modified)" and tagged packed. It now needs a `UPX!` magic or the
  `$Info: This file is packed with the UPX` line. Detect It Easy's "Rust" is
  its own heuristic and matched GCC and uClibc ARM builds; it is now marked
  DISPUTED, as its Go claim already was, when the file has no Rust library
  path, panic symbol or backtrace variable.

- **AArch32 `execve` keeps its arguments when the guest lost the argv pointers
  (ANT-T0429).** Some compat execs were recorded with `arg1.string[1..]` but not
  `arg1.ptr[1..]`, so a child `sh -c "crontab ..."` showed only `/bin/sh` and the
  shell-command rules missed it (one Mirai: 39 findings against 62). The argument
  vector is now read from the strings in order when a pointer is missing; it is
  still not called complete without the terminating NULL pointer. Calls with no
  pointer argument (arm `cacheflush`, `set_tls`) no longer count as schema gaps.
  The compat calls the guest records by address only (readlink buf,
  `get/setsockopt` optval, `sigaltstack`, `utimensat`, clone's tid pointers,
  `prlimit64`, `sched_getaffinity`, `_llseek`, `set_robust_list`, TCGETS and
  TIOCGWINSZ) need a guest recorder change and are listed in
  `docs/implementation/guest-and-kernel.md`.
- **A data folder taken right after its owner let go is no longer refused
  (ANT-T0423).** The owner lock is a `flock`, and a process another thread had
  just forked, but not yet exec'd, holds a copy of its file until the exec, so a new
  owner (the window, the daemon or a command) starting a moment after the old one
  ended could be told "data folder is already in use ... it left no owner record".
  Taking the folder now waits up to two seconds for a lock that looks held before
  it names the owner; a real second owner is still refused, and a free folder
  does not wait. The indicator list also knows the guest network's gateway, so
  its DHCP is background there as it is in the network table (ANT-T0418).

- **No false "SIGTRAP handler" debugger check on AArch32 and ia32 programs
  (ANT-T0427).** The debugger-check rule read the `sigaction` handler as one 8-byte
  word, so a compat program's reset of SIGTRAP (`sa_handler=SIG_DFL`, flags set)
  read as handler|flags<<32 and every child of an ARM32 Go program got a finding.
  Rules now read `sigaction`, `sysinfo`, sleep and select timeouts, `timerfd_settime`
  and `utimensat` members by the width of the layout the guest captured them with
  (4-byte words for a compat program, 8 for a native or time64 one).

- **Disassembly reads AArch64 and ARM programs, and one unavailable check no
  longer makes the analysis partial (ANT-T0428).** The Disassembly check called
  the host's x86-only `objdump` and was "unavailable" for every arm64 and ARM32
  sample, which also marked the whole run `partial` (exit 11). It now decodes
  AArch64 and ARM/Thumb with the linked Capstone (x86 and x86-64 output is
  unchanged), and an analysis is partial only when a check stopped short, not
  when one is unavailable.

- **A Debian arm64 VM with a realistic profile and a network starts (ANT-T0424).**
  QEMU 11 refused its card (`-device igb,…,addr=0x19: VF addr overflows`):
  QEMU's igb, the card of the arm64 machines, brings eight SR-IOV virtual
  functions from its own PCI place plus 0x80, which at 00:19.0 pass the bus's
  last function. On arm64 a base that names its NIC by slot now has it at
  00:0e.0 (`enp0s14`), the highest slot where they fit, on every profile; x86-64
  is unchanged. A disk provisioned for 00:19.0 before gets the profile's own
  card there, and the start log says so. When QEMU exits during a start, the
  error now begins with QEMU's exit status and its own message; the TCG speed
  advice is added only when a wait ran out. The quick tier of
  `scripts/vm-regress.py` gains `nic-routed` on a Debian base: a realistic
  desktop VM on a Routed network whose card must get a DHCP lease (on arm64 and
  x86-64; `guest-run` takes `"vm": {"routed": true}`).

- **The dump trigger fires on arm64 runs, and says so when it took nothing
  (ANT-T0426).** The live judge kept the calls the rules read by their x86-64
  numbers, so no call of an arm64 run (AArch64 or AArch32) reached it: a run with
  dozens of High findings took no trigger dump and said nothing. It now keeps them
  by id on every ABI, and 32-bit x86 programs on x86-64 are watched too. The calls a
  fast program makes before its launch is acknowledged (held, then replayed into the
  run) now reach the judge as well: on x86-64 a program that wrote a cron entry at
  once took no dump. A run whose trigger was armed but never matched gets a note
  saying so, and matches the VM stop cut off are kept as misses with the reason.
- **Reduced recording keeps and drops arm64 and 32-bit calls by their own names
  (ANT-T0438).** When the quota is nearly full only the calls Triage's rules read are
  kept, but the list was matched against x86-64 numbers, so on an arm64 guest it kept
  and dropped unrelated calls (an `execve` could be dropped, a `read` kept), and the
  dropped-call counts carried the wrong names. The decision now reads each call's id
  on its own ABI (AArch64, AArch32, x86-64, and ia32 programs on x86-64). x86-64
  native decisions are unchanged.

- **Preloaded libraries are linked to their sample, scanned and named
  (ANT-T0398).** A run of `/bin/sh -c '...'` with `LD_PRELOAD` or `LD_AUDIT` naming a
  file the sample library sent into the VM is recorded with that library's SHA-256;
  the library's Runs list shows the run with the role `preloaded`, it no longer says
  "Never run", and the run's Summary and report name the library. A named library
  that was never sent has no hash and is reported as such. The run's YARA scan also
  reads the preloaded library, the ELF executables and libraries the run wrote
  (rebuilt from the recorded writes and kept under the run's `written` folder when Triage saves the run's digest, `detect --save` runs or the Auto lane analyses it), and the
  layers static analysis unpacked; each match records its input (`Preloaded library`,
  `File the run wrote`, `Unpacked layer`), skipped inputs say why, and the budgets are
  unchanged. A library the run wrote and then loaded (`LD_PRELOAD`, `LD_AUDIT`,
  `/etc/ld.so.preload`) is a new high Triage finding. The library sample window has
  **Load into…**, and `run exec` has `--load-into PROGRAM`, to run a program with the
  library preloaded.
- **Runs know their job, sensitive reads reach the service log, `sample add` goes
  through the daemon, and `run export --sensitive` writes packet and call bytes
  (ANT-T0421).** `run list` showed `job_id: null` and `--job` found nothing; the
  reads now take the job from the job store (the job records its run), in the
  daemon and in direct mode alike. Every served read of the sample's own bytes
  (`recording.captured.read`, `files.content`, `network.packet`,
  `artifact.get` of a capture or core, a sensitive job artifact, `sample.download`)
  writes one line with the caller, the operation, the run or sample and the size to
  the daemon's service log, never the bytes. With a daemon, `sample add FILE` uploads
  the file and calls `sample.add`. `run export --sensitive` also writes the frames of
  the recorded packets and the captured bytes of calls under `--out`.
- **Retention clears `processed/`; result files can be group-readable
  (ANT-T0422).** `[inbox] processed_keep_days` (default 7) makes `auto gc` and the
  daemon remove files of `<inbox>/processed/` older than that, with the same dry run
  and log lines. `[results] mode = "group"` writes result drops 0640/0750 instead of
  0600/0700; `config validate` refuses any other value. Documented: retention leaves
  the VM-wide captures and dumps of a deleted run alone, and a failed `on_finish`
  hook is not retried.

- **Network flows name the process that made them, and a capture names its run
  (ANT-T0397).** The capture is VM-wide and the guest tags no packet, so the app
  now matches each flow on the host to the run's recorded network calls
  (`connect`, `sendto`, `sendmsg`, `accept`, `recvfrom`, `bind`) by address,
  protocol and time. **Triage > Network > Endpoints** has a **Source** column
  (and a `network.source` filter key): the process as `name (pid · tid)`, which
  opens it in Details, **Base image background: NTP** (or DHCP or apt, the same
  traffic the Summary's Indicators set apart), or **Unattributed** when no call
  matches (a raw socket, say). The **Network** tab's packet list gets a
  **Made by** column once Triage has the run open (a `source curl` quick
  filter), and every capture in its list says **Run: ...** (exact when the run
  started the segment, by time when it only ran while it was written, VM-wide
  when no run did). The run report's Endpoints table carries the Source, and the
  service's `recording.network.captures` and `recording.network.packets` reads
  expose the same as `link` and `made_by`. It reads only what the recording
  holds, so runs recorded before 0.9.0 attribute too. Per-packet tagging in the
  guest kernel stays a 0.10.0 card.

- **Run History lists every saved run (ANT-T0415).** A run whose analysis
  report was extended after the run ended (Analyse more adds a check to the
  report file only) was skipped as "not matching the run", so a run with all
  its files vanished from Run History and the Triage picker. The report file
  may now hold more checks than the run was saved with. A run whose record
  cannot be read at all is listed with the reason ("run record unreadable: ...")
  instead of being left out, and an analysis report that cannot be used no
  longer hides its run: the run shows with a note.

- **A moved data folder keeps its bases and VMs (ANT-T0416).** A base installed
  from 0.9.0 on records its files relative to its own folder, and the app
  reads the older absolute records from the folder they are in, so a data
  folder moved, restored from a backup or mounted at another path no longer
  shows "No base image" (the check that a recorded file stays inside the base
  folder is kept). At start the app also repairs what a VM keeps outside its
  base: `vm-locations.json`, the VM's own `bundle.json` and the backing-file
  names inside its disk and snapshot layers, when the folder they name is gone.
  A base that cannot load is listed with the reason (Library page, `base
  list`) and no longer hides the others.

- **A file's history keeps every call after a rename (ANT-T0419).** Triage >
  Files > Per-file history listed a file twice, or lost calls, when a program
  renamed a file and then wrote through the descriptor it had opened before (a
  ransomware that writes a trailer after renaming to its own extension, with
  worker threads sharing the descriptor or a `dup` of it). Those writes carry no
  file identity and the name they were opened by no longer led to the file. A
  call made by descriptor now follows the descriptor to the file it was opened
  on, whatever thread made it and whatever the file is called now.

- **DHCP to a custom guest network's gateway is base image background
  (ANT-T0418).** With a profile that gives the guest its own NAT network (a home
  network's 192.168.1.0/24, say), the base's DHCP traffic to that network's
  router (`192.168.1.1:67` and `:68`) showed as **Unattributed** in Triage >
  Network > Endpoints. The run record now keeps the VM's gateway and the Source
  column reads it, so that traffic is **Base image background: DHCP** like
  10.0.2.2's. Runs saved before this keep QEMU's default address only.

- **The data folder says who owns it.** The process that takes the data folder
  writes `run/owner.json` (its pid, whether it is the window, a daemon or a
  command, when it started) and removes it on a clean exit. A second Antinomie
  that finds the folder in use now names the owner instead of only saying it is
  in use, and the ownership is checked before an old data folder is migrated.
  `antinomie-cli doctor` shows the owner too.

- **`antinomie-cli`, a headless command line.** A new binary beside the window
  (`antinomie-cli --help`) with `doctor`, `capabilities` and `config`
  (`path`, `get`, `set`, `validate`), the output formats human, json and
  ndjson, and fixed exit codes. It does not link the GUI libraries. See
  "Command line" in docs/usage.md. `--daemon`, `--direct` and `--socket` choose
  how an `auto` command reaches the job daemon; the other commands run in the
  calling process.

- **Engine settings live in the data folder.** The window now keeps its engine
  settings (detection and report options, limits, quotas, disk view) in
  `<data>/settings.json`, which `antinomie-cli config get` and `config set`
  read and write, instead of only in the window's own storage. The file is
  written by the process that owns the data folder, keeps fields a newer
  version added, and a file that cannot be read is reported and never replaced
  by defaults.

- **Service configuration and the job API contract.** The new
  `antinomie-service` library holds what the coming daemon, command line and
  web layer share: the job and query API types (docs/job-api-1.md, with its
  JSON Schema), `service.toml` and `policies/*.toml` (docs/service-config.md),
  the job store (SQLite, the state machine, the queue and its recovery),
  uploads and sample intake, read-only recording queries, and the `automation`
  custody actor with its frozen-policy entry. Of these only
  `antinomie-cli config validate` is reachable by a user in this build: it
  checks the configuration files without starting anything.

- **The Triage scan runs without the window.** The scan, the activity rules,
  the filter language and the eBPF decoder are a library of their own
  (`antinomie-triage`) that `antinomie-cli` links too. Any Antinomie program
  now copies the earlier bytes of the files a run changed into the recording
  when its boot ends (only a program named `antinomie-monitor` used to), so a
  recording made from the command line is as complete as one made in the
  window; `ANTINOMIE_COPIER` still names another program for it. Triage looks
  and works as before: its rows name a colour role (good, warning, bad,
  muted...) and the theme picks the colour.

- **Samples and custody from the command line.** `antinomie-cli sample add, list,
  show, tag, verify, remove` and `custody verify` (with export and signing) work
  on the sample library without the engine lock, so they run beside the window.

- **Static analysis and rule selection from the command line.** `antinomie-cli
  analyze FILE` runs the static analysis of a host file and prints a summary;
  `rules list, enable, disable` use the rule registry of the data directory.

- **Bases, VMs and snapshots from the command line.** `antinomie-cli base list,
  install, download, build, delete`, `vm list, create, start, stop, status, reset,
  duplicate, delete` and `snapshot list, create, restore, delete` run the engine
  in the command and print the same objects in human, json or ndjson. Destructive
  commands refuse without `--yes`, a guest password is read from standard input
  only, Ctrl-C stops the VM cleanly, and a VM ends with the command that started
  it (`vm start --hold` keeps it up). See "Command line" in docs/usage.md.

- **`antinomie-cli run exec`.** Uploads a library sample into a VM, runs it,
  waits until its evidence is complete (the 300-second rule the window uses), stops
  the VM and waits until the recording is final, then prints the outcome, the run,
  the evidence, the time per stage and the end of the program's output. A run limit
  (`--timeout-run`) stops a program that never ends; `--events` streams the progress
  as it happens. The exit code is 0, 11 for partial evidence, 10 for a failure.

- **`antinomie-cli triage`, `detect` and `report`.** Triage of a saved run from
  the command line: `triage RUN` prints its Summary (assessment, counts, key
  behaviours), `detect RUN` runs YARA, Sigma and IDS over its evidence as the
  Detection tab does (`--save` keeps the results in the recording), and `report
  RUN` writes the report in HTML, PDF, JSON, MISP, STIX or Markdown. The report
  is built by the same code as the window's Export report, so the files are the
  same for the same run and choices; the window's dialog and Detection tab work
  as before. See "Command line" in docs/usage.md.

- **The Auto mode daemon (ANT-T0380).** `antinomie-cli auto daemon` owns a
  data folder (`run/owner.json` says "daemon" and names its socket; the window,
  a command or a second daemon is refused with the owner named), runs the job
  queue on its lane and serves the job API on a local socket,
  `<data>/run/antinomie.sock`. The socket is for its owner only: mode 0600 in a
  0700 folder, and the peer's user id is checked on every connection. Requests are
  checked strictly and bounded (2 MiB per line, 16 in flight and 50 a second per
  connection, 64 connections, 64 event subscriptions per client, idle and slow
  clients closed), files arrive by upload rather than by a path the client names,
  and an event stream resumes from a sequence number with no gap and no
  duplicate. SIGTERM lets a job that is past its VM stages finish its analysis
  and report (up to 120 s, `[daemon] shutdown_host_grace_s`) and puts a job in
  its VM stages back in the queue; a second signal within 5 s stops at once;
  SIGHUP reloads the policies. See docs/job-api-1.md and docs/service-config.md.

- **`antinomie-cli auto init` and the lane commands (ANT-T0378).** `auto init`
  makes the Auto mode lane on an installed base: it creates a routed VM, boots it
  once until the guest answers, stops it, waits until its disk has settled, takes
  the clean snapshot every job starts from, records the lane, and writes a default
  policy pointed at it when the folder has none. `auto lane list` shows the lane and
  what would keep it from a job; `auto lane reset --yes` reverts it to its clean
  snapshot now (lifting a quarantine when that works); `auto lane unquarantine`
  lifts a quarantine without reverting when the checks pass. With a daemon running,
  the lane commands go to it and run when no job does.

- **Submitting jobs: `antinomie-cli auto submit` and friends (ANT-T0381).** `auto
  submit FILE` uploads the file to the daemon and queues a job (`--policy`,
  `--timeout-run`, `--args`, `--route drop|inet_sim`, `--formats`,
  `--evidence-bundle` and more, within the policy's ceilings); `--wait` exits with
  the job's code, `--follow` streams its events as NDJSON, `--verdict-exit` exits
  30, 31 or 32 for a succeeded job labelled suspicious, malicious or inconclusive
  (a partial or failed job keeps 11 or 10), and `--out DIR` copies the reports.
  Without a daemon `auto submit` runs the job in the command and exits with its
  code. `auto status`, `list`, `wait`, `events` (`--since`, `--follow`, `--all`),
  `result` (the label, its basis and the report paths), `artifacts`, `fetch`,
  `cancel`, `retry`, `queue status|pause|resume` and `policy list` complete it; the
  reading ones work without a daemon. A policy's `[verdict] tag_library = true`
  tags the sample `auto:label=...` and `auto:policy=...` in the library, with the
  automation actor in its custody chain. See "Auto mode" in docs/usage.md.

- **Watch folders (ANT-T0383).** A file that appears in a folder named under
  `[[inbox.watch]]` in `service.toml` becomes a job, as the actor
  `auto:policy-<policy>` (the label `watch` names the folder). The folder is
  scanned every 2 seconds; a file is taken only after its size and times have
  been steady for 3 seconds, and never while its name starts with a dot or ends
  in `.part`, `.tmp` or `.crdownload`. Nothing is followed out of the folder: a
  symbolic link, device, FIFO, socket or file with a second hard link is refused
  and left where it is, a file of another user is refused, and a folder that is
  writable by everyone, owned by another user, or (without `allow_group_write`)
  writable by its group is not used at all (`engine.alert`
  `watch_folder_refused`). Each file is opened relative to its folder without
  following links and read from that descriptor. After intake the file moves to
  `inbox/processed/`, is deleted, or is kept (`delete_after`); a file that fails
  intake moves to `inbox/rejected/` with a `.reason` file and is not tried
  again. `policy_by_dir` picks the policy from a subfolder named after one
  (other folders are ignored), `recursive` follows subfolders (8 deep at most),
  and `watch_rate` jobs a minute is the limit: above it the folder pauses for a
  minute and `engine.alert` `watch_flood` is raised. `antinomie-cli auto watch
  list` shows each folder, what it took and what it refused; `auto watch scan`
  scans now. See "Auto mode" in docs/usage.md and docs/service-config.md.

- **Retention and `auto gc` (ANT-T0384).** The daemon removes what Auto mode
  leaves behind: recordings of finished jobs after `[retention] recordings_days`
  (14), through the same run deletion the window uses (a failed job keeps its
  recording while `keep_failed` is set), the oldest recordings first when they
  exceed `max_recordings_gib` (200), job records, events and artifacts after
  `jobs_days` (90), staged uploads after 24 hours and rejected inbox files after
  7 days. It never touches a job that has not ended, a recording with an open
  read or whose artifacts are still being written, the sample library or its
  custody chain; each deletion is logged with the job and run id and recorded in
  the sample's custody chain under `auto:policy-<name>`. `antinomie-cli auto gc
  --dry-run` prints the plan; `auto gc` applies it now (with a daemon, or on its
  own when none runs); `auto delete JOB [--with-recording]` removes one finished
  job. The daemon runs a pass an hour. See "Auto mode" in docs/usage.md.

- **Result files and the command hook (ANT-T0385).** With `[results] dir` set,
  every job that ends leaves `<dir>/<yyyy-mm-dd>/<sha8>-<jobid>/` with a copy of
  its `job.json` and its (non-sensitive) report files, written under a hidden name
  and renamed into place so a poller never sees half of it. With `[notify]
  on_finish = ["/abs/path", "arg", ...]` the daemon runs that command when a job
  ends: directly, without a shell, with an empty environment holding only
  `ANTINOMIE_JOB_ID`, `ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and
  `ANTINOMIE_RESULT_JSON`, as the daemon's user, with no input, a 30-second limit
  (its process group is killed past it) and its output kept in the job's
  `job.log`. A failing drop or hook is a log line and an `engine.alert`
  (`result_drop_failed`, `hook_failed`); it never fails the job. See "Auto mode"
  in docs/usage.md and docs/service-config.md.

- **`antinomie-cli` in the release archive, a systemd unit and the Auto mode guide
  (ANT-T0389, ANT-T0390).** The release archive carries `antinomie-cli` beside
  `antinomie-monitor`, and `./install.sh` installs both (`~/.local/bin/antinomie`
  and `antinomie-cli`; `--uninstall` removes both). The archive also holds
  `packaging/`: `antinomie-auto.service`, a hardened system unit for a dedicated
  user (`Type=simple`, `Restart=on-failure`, `KillMode=mixed`, `TimeoutStopSec=360`,
  `NoNewPrivileges`, `ProtectSystem=strict`, a closed device policy with `/dev/kvm`),
  `antinomie-auto.user.service` for a user manager, and an example `service.toml`
  and `policies/default.toml`. New guide `docs/auto-mode.md` (pipeline, policies,
  revert, watch folders, retention, failure codes, troubleshooting, systemd), a
  "Command line and automation" section in `docs/usage.md`, an "Unattended use"
  section in `docs/security.md`, and the dependencies the headless crates added
  (`toml`, `schemars` and their helpers) in the licence notices.

- **`antinomie-cli run list`, `run show` and `run export`, and Triage reads
  through the query API (ANT-T0367, ANT-T0369).** `run list` lists the recorded
  runs of the data directory (`--vm`, `--sample`, `--job`, `--state`, `--since`,
  `--limit`, `--cursor`), `run show RUN [--summary]` shows one run and, with
  `--summary`, its Triage summary, and `run export RUN --out DIR [--part
  LIST] [--sensitive]` writes the trace, processes, findings, indicators, files,
  network, timeline, analysis, custody and artifacts of a run as NDJSON and
  evidence files into `DIR` only (the bytes the sample produced need
  `--sensitive`). They need no engine lock, so they work while the window is
  open. `triage RUN` now reads its summary through the same read-only query the
  web pages will use (`recording.summary`) and writes nothing into the
  recording; it prints the summary's counts, families, techniques, key
  behaviours and detections, and `--parts` still adds report parts. The query
  API (`docs/job-api-1.md`) serves the Triage reads: the summary, findings,
  indicators, files, network and a merged timeline, with the window's filter
  language, server-side sort and paging, and the `trace.page` filter (`q`). Their
  counts are the window's: a test compares them with the report builder.

- **The daemon serves the reads (ANT-T0417).** Beside the job operations the
  local socket now answers every `recording.*` read (the Triage ones too, with
  the same `building` answer while the scan is made), `sample.list`,
  `sample.get`, `sample.add` (a finished upload, never a path),
  `sample.download` (a range of the AES archive, `artifacts:sensitive`, one
  `exported` custody entry), `sample.tag`, `custody.verify`, `vm.list` and
  `base.list`. With a daemon at the socket, `run list`, `run show`, `run
  export`, `triage`, `sample list|show|tag`, `custody verify` (without
  `--export`), `vm list` and `base list` ask it and print what direct mode
  prints; without one they work as before. `run export` still writes only into
  the folder you give with `--out`: the command pages through the daemon's
  reads and writes the files itself, so no path is ever sent to the daemon. New
  `run export --no-triage` leaves out the parts that need the Triage index
  (findings, indicators, files, network, timeline) so a very large recording is
  not indexed in full. `sample.list` also takes `tags`, `all` and `custody`,
  and `sample.get` takes `origins`, `events` and `runs` (additive).

- **Exporting a large run no longer reads its recording a second time
  (ANT-T0412).** The index Triage makes of a run when it opens it is kept for
  the report: an export, or `antinomie-cli report`, of a recording that has not
  changed (same files, sizes and modification times) builds the report from that
  index and reads nothing again, even after you filtered or paged the tables on
  screen. A 3.5 GB recording took 71 minutes to export. When a recording over
  1 GB has to be read, the dialog says so before it starts, with an estimate
  (Export becomes **Export anyway**) and `report` prints the same warning on
  standard error and in its JSON result (`large_recording`); the progress line
  and Cancel are unchanged.

- **Run report polish (ANT-T0413).** The PDF contents page lists the
  sub-headings of every section, the same entries as the PDF bookmarks. Network
  and Indicators times read `+5.463 s · 17:38:21.480` like the other tables (the
  JSON gains `last_ms`, `last_relative_ms` on Network rows and
  `first_seen_relative_ms` on indicators). The process table shows an indented
  tree (`+- child` under its parent) besides the Parent column; in the JSON the
  Process cell no longer starts with hyphens (use the row's `depth`). The
  Summary's Copy all and Export, and the IOC tab's Export, tell you with a
  toast and an Activity row instead of a line that moved the page.

- **Clock model for the boot age.** A new Clock model setting in a VM's Device
  profile (Auto, Always running, Suspend) chooses whether the boot age steps
  both guest clocks or only CLOCK_BOOTTIME. Auto picks Suspend on Debian bases,
  so systemd's watchdogs no longer kill journald, udevd and logind at the first
  launch of a server or cloud profile; elsewhere it keeps server and cloud
  always running and desktop and laptop suspended. Still visible names the cost
  of the model in use. Saved profiles load as Auto.

- **Remaining trace decoders (ANT-T0302, host part).** The layouts the
  generic reader could not describe now have readers: AIO (`iocb`, `io_event`,
  `__aio_sigset`), io_uring (submission entries, rings, probe, extended
  argument, buffer ring), CPU and node masks as lists (`0-3,6`), `rt_sigframe`
  (x86-64 and aarch64), x87/SSE and extended state summaries, `uretprobe`
  registers, and aarch64/AArch32/x86 `PTRACE_GETREGSET` register sets. Socket
  addresses add `AF_UNSPEC`, netlink, packet, vsock, ALG and CAN;
  `perf_event_attr` names the event and its option flags; SysV IPC, quota and
  LSM structures show dates and flag names. A 32-bit program's wait status,
  socket options, select sets, masks and `fcntl`/`prctl`/`fanotify_mark`
  arguments are named like a native one's.

- **Layout-driven trace decoding (ANT-T0294).** One decoder reads any captured
  layout from the per-architecture member inventory (offsets and widths, so
  `epoll_event` is 12 bytes on x86-64 and 16 on aarch64) as named fields,
  nested structures and arrays, with flags, enumerations, signals, errors,
  descriptors and times named: durations for `timespec`/`timeval`/`itimerspec`,
  socket option values by level and name, `msghdr`/`mmsghdr`/`iovec`
  arrays, `epoll_event`, `sigaction`, `user_regs_struct`, `clone_args`,
  `open_how`, `flock`, wait4 status, select descriptor sets, pipe and
  socketpair pairs; inotify/fanotify masks, access modes, socket protocols,
  mempolicy modes, `ITIMER_*`, `fcntl` and `prctl` arguments read by name. It is
  ABI-aware: compat programs read the compat inventory and show bytes with a
  "No compat layout" note where it has none. The Syscall Trace's JSON export carries the
  decoded fields (`run export --part trace` has the engine's raw previews).
- **arm64 guests.** A BusyBox arm64 base (Debian 13's pinned arm64 BusyBox and
  e2fsprogs packages, the patched kernel cross-built with Debian 13's
  `aarch64-linux-gnu-gcc-14`) starts on QEMU's `virt` machine, on its device
  tree or through UEFI (AAVMF), always under TCG, with the TCG waits (Tools >
  Settings > Advanced, TCG multiplier). Its screen (virtio-gpu, USB keyboard
  and tablet) shows on the VM screen tab or in the QEMU window, as the VM
  screen setting says. Recording, captures, file activity and contents,
  packets and routes, io_uring and AIO, notes, Triage, Sigma, the Files and
  Network tabs, process cores, snapshots and the debugger all work on it. The
  VM settings offer **Faster emulation (KPTI off)**.
- **32-bit ARM programs** run on arm64 guests and are recorded and decoded by
  arm's own EABI numbers and layouts.
- **Core dumps and a debugger for 32-bit ARM programs on arm64 guests** (a base
  of guest revision 21). The core view opens the ELF32 cores they write:
  registers (r0-r12, sp, lr, pc, cpsr, and the VFP registers), mappings, memory,
  mapped files, auxv, the fault address and the process name, and disassembles
  the code in ARM or Thumb state (Capstone; the pc follows the CPSR T bit, other
  addresses their low bit, a Thumb function its symbol's). The debugger, the
  panel and gdb-multiarch both, shows the program with the ARM register set (r0-r12,
  sp, lr, pc, cpsr with its flags, VFP, TPIDRURO), the `arm` target description,
  ARM and Thumb breakpoints (gdb's Z0 kinds 4, 2 and 3), single-step in both
  states and a code pane that decodes in the pc's state. On a base older than
  revision 21, Dump core and Debug say that the guest cannot handle a 32-bit ARM
  program instead of "state 5, status -95".
- **32-bit x86 programs** (ia32, such as XorDDoS and Rex) on x86-64 guests are
  recorded and decoded by the i386 table: their calls by name, their arguments,
  paths, written bytes, socket addresses (also through `socketcall`), task
  names and their children's exec, so the process table, Files, Network,
  Triage and Sigma read them as an x86-64 program's. Before, their numbers were
  read as x86-64 ones (another call's name, "?" processes, a false
  `persistence.module`); a base of 0.8.3 or older still records them by number only, and
  this app shows those raw. Their process cores are still not written.
- **Debugger on arm64.** gdb-multiarch drives the guest's arm64 debug engine;
  the Code pane disassembles aarch64 with Capstone (BSD-3-Clause and NCSA,
  notices in `THIRD-PARTY-NOTICES.md`); hardware breakpoints, write and read
  watchpoints (read watches are offered where the guest says it has them, so
  x86-64 still refuses them); manual cores carry the guest's machine.
- **Debugger on x86-64.** A child the program forks while a breakpoint is set,
  and which the debugger does not follow, now runs its own code: the guest puts
  the program's bytes back in its copy before it runs (before, it met the
  INT3 and took a SIGTRAP).
- **arm64 device profiles.** A realistic preset presents an arm64 machine of its
  kind (Ampere Altra servers and workstation, an AWS Graviton2 instance) with
  its SMBIOS tables, ACPI OEM IDs, CPU, network card and disk, or a Raspberry
  Pi 4 or 5 on a disguised device tree; every value is cited in
  `SOURCES-arm64.md`. The **Device profile** window of an arm64 VM checks AAVMF
  (not OVMF), lists the arm64 machines to pick from, shows the machine's CPU in
  place of the x86 CPU settings and lists the giveaways an arm64 VM keeps; a
  **Use base** suggestion only names bases of the VM's architecture.
- **Plain limits on arm64.** The Memory tab of an arm64 VM says that Volatility
  3 and MemNixFS read x86-64 guest memory only; capa and FLOSS report
  "unavailable" for programs of other architectures than x86 (and the Run form
  warns when they are chosen on an arm64 VM).
- **Build kit.** The app's kit also carries Debian's arm64 module-signing
  certificate, which the kernel script picks for an arm64 kernel, and the kit
  test checks both certificates.
- **Debian 13 arm64 Minimal (recipe).** `build-base.py` and the image recipe
  build a Debian arm64 console base with Debian's own arm64 kernel packages,
  banner and signed modules, bootstrapped where an emulator runs the arm64
  maintainer scripts: in the QEMU builder VM (its own qemu-user) or in a
  container (below), never natively. Its kernel is built as Debian's arm64 kernel is,
  with the 32-bit ARM compiler for the AArch32 vDSO, and the ABI check reads
  Debian's arm64 Image by its BTF header and its exports from the pinned
  `linux-headers-6.12.94+deb13-arm64` Module.symvers (Debian's arm64 System.map
  is a stub). The QEMU builder installs `arch-test` for it (mmdebstrap refused
  the arm64 bootstrap without it).
- **Debian arm64 in a container.** The container builder (`build-base.py
  --container`, and the app's Podman/Docker modes) builds a Debian arm64 base
  when the host has an enabled `qemu-aarch64` binfmt handler with the F flag
  (`docker run --privileged --rm tonistiigi/binfmt@sha256:400a4873... --install
  arm64`); without it the build is refused with what is missing and the QEMU
  builder stays the default. The builder image pins `arch-test`.
- **Debian arm64 VMs.** A VM of a Debian arm64 base asks for its account as on
  x86-64; the account, GRUB (on a UEFI disk) and the initramfs's resume device
  are made by the guest's own arm64 programs in one provisioning boot of the
  VM (no network card, serial console only, about half a minute under TCG), after
  the x86-64 disk tools did everything that needs no guest program. The
  password reaches the guest over QEMU's fw_cfg from a private file and never
  touches the disk; the guest reports the hash it stored, the VM powers off and
  the disk tools remove what that boot left. A failed or overlong (15 minutes)
  provisioning boot fails the creation with its reason. On arm64 the NIC of
  such a VM sits at PCI 00:0e.0 (`enp0s14`) on every profile. The x86-64
  provisioning is unchanged (a test pins it byte for byte).
- **Who sent the fatal signal.** On a revision-21 base the task-exit record
  names the sender of the signal that ended a task, and Triage's note on
  killed processes says it: the process (pid, name, uid, and whether it is in
  the recorded tree), the guest kernel, a fault, a timer, or the kernel's
  out-of-memory killer with the line it logged. The "Inference: the signal
  came from outside the recorded calls" text is left for tasks without a
  record (an older base says so).
- **Fewer schema gaps.** ioctl FIONREAD on sockets and pipes, FIONBIO,
  FIOASYNC, FIOQSIZE, FIGETBSZ, `chattr`'s FS_IOC_GETFLAGS and
  FS_IOC_SETFLAGS show their argument; FIOCLEX, FIONCLEX, FIFREEZE, FITHAW and
  FICLONE no longer count as gaps; arch_prctl 0x3001 is named
  `ARCH_CET_STATUS` (old glibc's CET query) instead of an unknown code.
- **Tests.** `vm-regress.py --arch arm64` runs the full tier on an arm64 base
  (the cloud check expects the arm64 instance; the route and specimen probes
  are built for arm64) and checks that an old host refuses the base
  (`io-old-arm64-refused`). The x86-64 full tier has `tracer-ia32`: one
  program built as a 32-bit x86 and an x86-64 program, recorded alike (its
  32-bit build needs `gcc -m32`: gcc-multilib and libc6-dev-i386).
  `snapshot-uefi` (full tier, Debian bases) runs the snapshot check on a VM of
  the server profile, booted through OVMF or AAVMF with its own variable store
  (`snapshot-check --uefi`). `debug-check a32` checks 32-bit ARM programs on an
  arm64 base: the guest engine, a gdb-multiarch session with ARM and Thumb
  breakpoints, and the ELF32 exit core opened and disassembled by the core
  reader (`tests/monitor/aarch32-debug-fixture.c`).

- **Stealth: guest facade for desktop and laptop profiles.** On a base built
  by this release a realistic desktop or laptop machine no longer shows QEMU's
  devices to the programs in it: `lspci -nn`, `/proc/bus/pci`, sysfs, `nvme
  id-ctrl`, `smartctl`, `/sys/firmware/acpi/tables`, `/proc/fb`, DRM and
  `/proc/bus/input/devices` name the machine's integrated GPU, its NVMe drive,
  its board's PCI subsystem, its firmware's ACPI creator, the maker's USB
  mouse and its EFI vendor (each from a public report of a real unit,
  `catalog/SOURCES.md`). The ThinkPads, the M.2 Latitudes and the ProBook G8s
  boot from NVMe again, and the realistic desktop and laptop presets use the
  USB tablet. Server and cloud profiles keep QEMU's devices: real servers and
  cloud instances show them too. Still visible: root's raw PCI config space
  through I/O ports, USB string requests through usbfs, the ICH9 chipset IDs
  and udev's database (see Still visible). `stealth-check` gains `machine=ID`
  and `screen=on`; the probe gains `pci.config`, `usb.devices`, `input.ids`,
  `display.drm`, `nvme.identify`, `base.monotonic-timers` and
  `base.init-start`.
- **Stealth: aged uptime.** A VM no longer shows a fresh boot: each VM gets a
  boot age when its preset is chosen (desktop and laptop 3 hours to 6 days,
  server and cloud 3 days to 120 days; Transparent stays fresh), the same at
  every start, shown and redrawn under Device profile › Clock. The guest boots
  that long in the past and reaches the present when the first program
  starts, so /proc/uptime, `sysinfo`, the boot time in /proc/stat,
  CLOCK_BOOTTIME and timers on it, process start times, the utmp/wtmp boot
  record (`who -b`, `last reboot`), the journal's boots and `dmesg -T` agree. A
  desktop or laptop looks like it slept for part of that time
  (CLOCK_MONOTONIC smaller); a server or cloud machine like it never stopped
  (CLOCK_MONOTONIC equal to CLOCK_BOOTTIME). A cloud profile's lived-in
  logins, auth.log and history end before the boot. Needs a base built by
  this release (stealth support `uptime`); older bases show a fresh boot.

- **Stealth: a random serial can no longer spell a tell.** The serial numbers, board serial and disk serial drawn for a new machine identity could, rarely, by chance, contain "QEMU" or another text a guest looks for. A draw that holds "QEMU", "pc-q35", "pc-i440fx", "Standard PC" or "Bochs", in any letter case, is drawn again, and the tests check many thousands of identities against a fixed random stream. Identities already saved are unchanged.

- **The sidebar names the VM's own architecture.** A VM's row reads "base name · architecture" from the base, so an arm64 VM says arm64.

- **Texts no longer call the app x86-64 only.** The Core Dump on Exit and core-trigger hints, the Core view's import texts, the Samples page's refusal, the seccomp pseudocode note and the usage guide name the guests that now work (x86-64, arm64, and 32-bit ARM programs on arm64) instead of x86-64 alone; the README roadmap drops arm64. Memory analysis, capa and FLOSS still say they are x86-64 only, because they are. The Samples page now decides by the selected VM's architecture, as Run program does: an x86-64 VM takes x86-64 and 32-bit x86 programs and shell scripts, an arm64 VM takes aarch64 and 32-bit ARM programs and shell scripts, a refused program is named with the VM ("This is an AArch64 program; the selected VM is x86-64. Choose an arm64 VM."), and with no VM selected the table says which VM kinds run the program.

- **Tor keeps its state between runs.** The own tor of the Tor route now keeps
  one data folder per VM (`network/tor/<VM id>`) instead of a new one for every
  VM start, so a run finds the consensus, descriptors and guards of the earlier
  ones and bootstraps faster. A bootstrap that stalls, or a tor that exits, is
  tried once more (after an exit with the cached state cleared); the folder is
  locked, so one tor uses it at a time, and folders of VMs unused for 30 days are
  removed. The evaluation saw two bootstraps stuck at 55% and 62% in 22 runs.

- **The VM screen says when it holds the keyboard.** A click on the picture
  captures the keyboard with an amber frame and a banner over the screen ("Keyboard
  captured. Press Ctrl+Alt to release it."). The keyboard is also given back when
  the window loses focus or another tab comes to the front.

- **New workspace windows open clear of the toolbar.** A terminal or other
  detached window had no position of its own and, without a window manager, opened
  at the corner of the screen over the main window's toolbar. It now opens inside
  the main window's panes.

### Guest

- Patches 31-41 (shared ones compile out of x86-64, whose objects are
  unchanged): the generic EFI stub keeps off the bootstrap page; the arm64
  definitions, system-call table and hooks; clone()'s argument order on
  `CLONE_BACKWARDS`; never-drop send waits on kernels without
  `CONFIG_PREEMPT_COUNT` (arm64's and Debian's arm64 voluntary preemption); AArch32
  programs recorded by arm's numbers; the caller's old pages read on CPUs
  without a hardware access flag (fork's children on a Cortex-A72); a
  debugger state setter named apart from stock ones; the arm64 debug engine (BRK, hardware step, breakpoint and watchpoint
  registers, load-only watches, unfollowed fork children cleaned of inserted
  breakpoints); boot options kept out of the device tree and virt's own devices
  out of ACPI; the stock arm64 kernel's BTF kept Debian's type for type (the
  core exit hooks' arm64 forms, setup.c's bootargs helper in the recorder).
- Patch 42: ia32 programs on x86-64 recorded by the i386 table (ABI 3, compat,
  as AArch32 on arm64), a `socketcall` as the socket call it makes; on x86-64
  only `kernel/antinomie/recorder.o` and `control.o` (ARCH_INFO's ABI mask)
  change.
- Patch 43: the x86-64 debug engine puts the program's own bytes back in a
  forked child it does not follow, as arm64's does; only
  `kernel/antinomie/debug.o` changes.
- Patch 44 (contract revision 21): the ioctl requests `fs/ioctl.c` answers
  for every file are decoded by their shape (an `int`, an `unsigned int`, a
  `loff_t`, or no pointer at all), not recorded as gaps; arch_prctl
  ARCH_CET_STATUS is a known selector.
- Patches 48 and 49 (contract revision 21): ioctl arguments are captured by
  the size their request number encodes, and the socket interface, TUN, loop,
  FICLONERANGE and fsxattr requests by their layouts; reads of eventfd, timerfd,
  signalfd, inotify, fanotify and userfaultfd descriptors name their records;
  epoll_ctl's event is recorded for any operation; the common compat calls'
  structures (iovecs, pollfds, descriptor sets, 32-bit times, dirents,
  rt_sigaction, wait4 and rusage) are captured by their ILP32 layouts.
- Patch 50 (contract revision 21): compat programs' stat64, lstat64, fstat64,
  fstatat64, stat, lstat, fstat, statfs, fstatfs, statfs64, fstatfs64,
  getitimer, setitimer and waitid have their structures captured by their
  ILP32 layouts, and sendmsg, recvmsg, sendmmsg, recvmmsg and recvmmsg_time64
  their message headers, iovec arrays, buffers, names and control data.
- Patches 46 and 47 (contract revision 21): AArch32 programs on arm64 guests
  get ELF32 process cores (`fs/compat_binfmt_elf.c`'s format, core flag
  COMPAT_ELF32) and are debugged by the guest's engine (compat registers, A32
  and Thumb breakpoints, hardware step; debug CAPS flag AARCH32); a debug-on-start
  launch of an image the engine cannot debug is refused instead of attached.
  The host reads those cores and has an ARM debugger (see Host).
- Patch 45 (contract revision 21): the sender of the signal that ended a
  thread group is kept in its leader's recorder state, taken at the send that
  starts the group exit (`kernel/signal.c`) or at the delivery of a fatal
  signal, marked by the OOM killer with its log line (`mm/oom_kill.c`), and
  written into the task-exit record (`lifecycle.signal.*`,
  `lifecycle.kernel_log`). On arm64 `get_signal()` calls the hook through an
  entry that takes the siginfo without const, so the stock arm64 kernel's BTF
  stays Debian's type for type (the const pointer had renumbered 13 types);
  x86-64's objects are unchanged.
- The BusyBox arm64 kernel keeps `CORE_DUMP_DEFAULT_ELF_HEADERS`, as Debian's
  kernels and the x86-64 BusyBox kernel do (arm64's defconfig turns it off):
  a process core carries the first page of each unmodified ELF mapping, so a
  crash early in a program's text has its code in the core view.
- Patch 51 (contract revision 21): compat programs' futex timeouts (time32),
  AArch32's epoll_wait and epoll_pwait events, and the SysV IPC control
  records of msgctl, semctl and shmctl (directly and through ia32's `ipc()`;
  the IPC_64 and the old records) are captured by their ILP32 layouts; ia32's
  semctl no longer reads an LP64 record.
- Patch 52: the guest facade. With the host's `antinomie_f*` boot options the
  guest shows a desktop or laptop machine's GPU, NVMe drive, board subsystem,
  ACPI creator and OEM IDs, mouse and EFI vendor for QEMU's devices where
  programs read them (PCI config space and sysfs, NVMe Identify data and
  admin pass-through, ACPI tables, DRM and fbdev names, USB HID descriptors,
  the boot log); the kernel's own view of the devices is unchanged. Bases list
  `facade` in `stealth_support`.
- Patch 53: the boot age. With `antinomie_boot_age=SECONDS:MODEL` the guest
  boots that long in the past (the wall clock behind while booting) and steps
  to the present at the first program launch, as a resume does (`suspend`) or
  with programs' CLOCK_MONOTONIC carrying the age too (`continuous`); the
  kernel's own monotonic clock, the recorder's timestamps and the host's
  guest-time accounting are unchanged. Bases list `uptime`.

## 0.8.3 — 2026-11-08

Antinomie 0.8.3 is a host-only release on the 0.8 line; it runs the same
revision-20 bases as 0.8.0, 0.8.1 and 0.8.2. It follows an evaluation of 15 real
malware samples: a new Triage Summary with key findings, an indicators tree and a
Relationships graph; Suspicious activity in plain words; a clearer Process tree
and a By file table; dumps taken when suspicious activity is seen, each saying
which run it belongs to; IDS and Sigma scans after every run; the VM screen in
the app with a Screenshots gallery; changeable keyboard shortcuts; foldable
sidebar and panes; YARAhub rules; and reports that open with an At a glance
section, link every entry and come as HTML, PDF and Markdown. Details follow.

### Host

- **Reports no longer colour the ATT&CK tactics.** In the run and sample reports (HTML and PDF) the Tactic column is plain text, a neutral outlined chip in HTML and the table's own ink in the PDF, without the coloured bar at the cell's edge. Tier colours (High, Medium, Low) stay; the app's own tactic colours are unchanged.
- **The PDF contents list shows bare page numbers.** Each line ends with the number, right-aligned like a book's contents page, not "page 3".
- **PDF bookmarks are a tree.** The bookmark pane lists each section with its sub-headings under it: Files > Written or changed, Opened files, Read, Deleted, Renamed, Executed and the rest; Network > Endpoints, Domains, TLS and the rest; any other section that has them. Each child jumps to its heading; sections open by default. Run and sample reports both.
- **Stop run works from any page.** Stop run and Kill were grey for a Running run unless that run was selected in Triage, so a run seen from the Samples page could not be stopped from the toolbar, the Run menu or the command palette. With no live run selected they now act on the newest live run, and the confirmation names it ("the newest of 2 live runs"); a selected live run is still the one that stops.
- **"Stopped by you at 5 min 9 s", not the time of the VM stop.** The moment Stop run was pressed is recorded and shown in Triage's state line ("Stopped by you at 5 min 9 s · tree ended 3 s later · root exited 0", the second part only when the tree took 2 s or more to end) and in the run's tooltip. A stopped run's end time is now when its tree ended; it was the VM stop, which made Tsunami read 6 min 59 s for a stop at 5 min 9 s. Runs saved before this keep the old words.
- **A finished run is scanned as soon as its recording is saved, without a VM stop.** After Stop run or a normal exit, Sigma said "Partial: the recording is still being saved" and rescanned only when the VM stopped. A run whose tree ended and terminal closed is now marked saved once every byte is written; IDS and Sigma wait with "Waiting for the recording to be saved." and then scan the whole run while the VM keeps running.
- **Sigma no longer fails with "No such file or directory".** On heavy runs (Ladvix, Symbiote) the run's event journal was never built, and Sigma tried to read the missing file. The tab now says "Waiting for the run's event index to be built.", or "The run's event journal is incomplete: <why>. Sigma was not run; this is not a clean result.", and a scan of a run with no journal reports missing evidence in words.
- **A QMP "timed out waiting for a reply" on the first restore or resume under load is retried.** The monitor connection waits 5 s for a running QEMU (was 2 s), asks again up to three times when the greeting is late, sends stop and cont again after a timeout, waits 30 s for the reply of a command that cannot be repeated, and says how often it tried and what QEMU last printed when it never answers.
- **A relative `--data-dir` works.** The data directory is made absolute at startup, so Sigma's interpreter path and every helper started from another working directory find it.
- **capa no longer stays "running" after the VM stopped.** A capa that finished (or timed out) after its run's VM had stopped never reached the run's record, so Static analysis showed it running for good. The final report is now written to the run's `run.json` and manifest.
- **Saving or removing an API key updates what can be downloaded at once.** After adding the abuse.ch Auth-Key (or changing it) the IOC datasets page, Triage > IOC's Auth-Key line and Online lookups switch, the Samples window and Samples > IOCs kept showing "needs a key" until Download / Update all ran. One signal now tells every page that a key changed: the key line, the "need a free abuse.ch Auth-Key" banner and the Download button's text follow it in the next frame, with no download.
- **A capa failure reads as a sentence.** When capa could not analyse a file the capabilities row used to show "capa exited with code 13: ERROR capa: Input file '/input/specimen' is not a valid file: main.py:904". It now says what the code means ("capa's ELF loader could not parse this file. The other analyses are not affected."; also for missing rules, an unsupported file type, architecture or system), adds "This file is prelinked, which capa's loader does not handle." for an ELF with `.gnu.prelink_undo`, `.gnu.conflict` or `.gnu.liblist` sections, and keeps capa's own line as a "capa said" entry. When a Ghidra install is available, capa is run again once with its Ghidra backend after code 13 or 14, and the section's tools say which backend produced the result.
- **Process, Files, Network and eBPF tabs carry counts.** Like Detection's `x · y · z`, Triage's **Process** tab shows `processes · findings` (processes, not threads; findings as Suspicious activity lists them by default), **Files** the files of By file with its default filter, **Network** `endpoints · domains · URLs · TLS sessions` and **eBPF** its observations, each capped at 99+, a dash while the run has no scan, and the hover naming every number. The Process tree's own badge no longer counts threads.
- **By file and the Process tree say "x / y rows".** The filter bar of Files > By file ends with the files listed out of all the run touched (it was a line of "x of y files" under the table's head), and the Process tree has the same count beside its filter, as the other tables do.
- **Rule scores are coloured by range.** A rule score such as an Elastic `100` or `50` shows red from 90, orange from 70 to 89, amber from 40 to 69 and muted below 40, in the Detection match cards, their Details and the match table; the 1 to 4 priorities of IDS rules and the named levels keep their colours.
- **The Overview's three configuration cards line up.** The rows of Compute, Storage and display, and Network and transport start at the same height, whatever their headline (the large vCPU and RAM figures, the disk size, "Routed (route chosen per run)").
- **Skipped-dump notes are one line per rule.** A sample whose children each match a High rule and exit within a millisecond or two (13 `cat /etc/shadow` in a row) no longer fills Syscall trace, Run History and the Summary's Notes with one "Dump skipped" line each: they read "Dump skipped 13 times for credential.shadow_read (High): the processes exited 0–2 ms after the match, before a core could be taken (processes 1362, 1363, … +11)". Misses still do not use the trigger's budget, and the full list stays in the trigger log, the run's `triggers` records and the Run artifacts box.
- **Every core and memory dump says which run it belongs to.** Each one records its VM, boot and run (or none), why it was taken (the run's exit, a dump trigger, by hand or imported), the process of a core (pid, thread and task cookie), the finding of a trigger dump (rule and tier) and the time window, in its own metadata, so the link reads both ways. The link is exact for a dump the run asked for and for a core whose task is in the run's process tree, by time for a memory dump taken by hand while runs were live, and VM-wide when none was; dumps from before this read as unknown and still load. In `artifacts.json`, `core_state` means the exit core only: a run with Core dump on exit off and a trigger core is no longer read as having no core.
- **Core dumps lists the cores a trigger took, and both tabs have a Run line.** A run with the dump trigger on and Core dump on exit off used to list 0 cores while its sample page showed them; they are now rows "Trigger: <rule> (<tier>)", for a stopped or a running VM. Core dumps and Memory show each entry's run (short id and sample name; a click opens the run in Triage, "Not in a run" or "VM-wide" where it applies) and a **This run only** checkbox that follows the run selected in Triage.
- **Triage > Summary ends with a Run artifacts box.** It lists the selected run's cores, memory dumps and capture segments in the sample page's Artifacts rows (same columns and Open buttons; Open shows the tab filtered to this run), with the run's time window, each capture segment's packet count and the trigger log.
- **Vendor names are never a family.** `Lnx`, `Sekoia`, `Eset` and `Mirai_ohshit` no longer appear in Family candidates: a rule pack's vendor or author in a rule name (`SEKOIA_`, `ESET_`, `DITEKSHEN_`, `GCTI_`, `MALPEDIA_`, `ELASTIC_`, `LNX` and the rest of the packs' prefixes) is skipped, a family taken from a rule or its `family` meta is the one family word (`MIRAI_OHSHIT_payload` names Mirai, `APT_MAL_LNX_Redmenshen_Bpfdoor` names BPFDoor), not the words glued together.
- **The sample page shows Triage's family and no host path.** Verdict and family no longer stays Unknown after Triage names a family: it lists the latest Triage family candidates of the sample's runs, with their sources on hover, beside MalwareBazaar's. Aliases of a file imported from this computer read "imported from a file on this computer" (the path is the tooltip) instead of the path of the folder it came from, in the page and in the exported report.
- **Family candidates name the real family.** Summary > Family candidates now lists a family from a rule that names one on purpose before any name fragment: an Elastic `Linux_Trojan_<Family>_<hash>` (or `Multi_`, `Linux_Ransomware_`, `Linux_Cryptominer_` and the other `<Os>_<Category>_<Family>` forms), a `family` metadata or a Malpedia rule, and the sample's MalwareBazaar record. Several rules for one family add up (twenty Gafgyt rules beat one Mirai rule), and each candidate shows its source. Generic fragments (MassHunt, Unique, BASE, IoT, Stackstrings, Generic, Sample, Unknown, Hunt, Test, a bare RANSOMWARE) are never a family, and community rule names are left out when a strong rule named a family. When a sample's MalwareBazaar signature and tags name different families (signature Mirai, tags Mirai and Prometei) both are candidates, and the Family column of the Malware samples tables and the sample page shows both (`Mirai · Prometei`, with the sources on hover).
- **Weak and wrong-platform YARA matches fold away, and the base image's background traffic does too.** In Detection > YARA the strong matches (Elastic rules scored 70 or more, rules with a family, curated-pack rules) come first and the rest sit under a folded "Weak or generic matches (N)": unscored community rules without a family, generic and hunting rules, low-score Elastic rules, and rules named for Windows, PE, scripts or web pages. The counts stay totals, and the Summary's YARA card adds "N strong, M weak or generic". In Summary > Indicators the base image's own traffic (NTP, DHCP, and now apt's `metadata.ftp-master.debian.org` lookups, SRV names, TLS session and the address they got) is one muted line at the end of its branch, "Base image background: NTP, apt (N)", which opens its list; Copy all leaves it out unless it is open. On Tor, VPN and SOCKS routes an endpoint on the gateway's stand-in range shows the name it was handed out for (`198.18.0.1:8443 → apache-update.ddns.net`). A program that reads `/etc/resolv.conf` again and again (a DNS loop) is flagged as network configuration once, not once per lookup.
- **IDS and Sigma scan after every run, or say "Not scanned".** With **Settings > Detection > Scan runs with IDS and Sigma when they end** on (the default), a run is scanned by YARA, IDS and Sigma as soon as its evidence is ready, and again when you install, update or remove a rule pack. A run whose VM stopped under its capture (the pcap was never closed) is scanned with the packets it holds, and the result says "scanned the N packets captured so far", instead of waiting for a segment that never closes. An engine that has not scanned a run shows "Not scanned" with a Scan button, and a dash with the hover "not scanned" in the Detection tab and the Summary cards, never `—` (which read as zero). A result made with an older rule set says "Scanned with an older rule set" with a Rescan button. A failed download's message (a ThreatFox update without a key) now stays on the page it happened on, so the Sigma page no longer shows it.
- **Failed launches explain themselves.** A program the guest could not run because its file is cut off (a partial download) now says "This ELF is truncated: its segments need 30.3 MB, the file has 2.0 MB. A partial upload or download; get a full copy." instead of "Bad address (os error 14)", and Static analysis shows the same note in red above Identity. A program that exits 127 because a library is missing gets the run note "Exited 127: the library libhwloc.so.15 is not in the guest."; Static analysis lists the libraries an ELF needs ("Needed library"). A shared object run as a program (Kinsing's `exp.so`) is called a shared library, meant to be loaded by another process, in Identity and on the run (a PIE program or a static-PIE is not mistaken for one). A UPX file whose headers were damaged on purpose says "UPX headers are altered (anti-unpacking); restore the UPX! magic and sizes to unpack it" in Unpacking. A run that failed to start gets a digest that says it did not start and why, so the sample window no longer lists it as waiting for Triage. A static analysis whose uploaded file the guest had vouched for now finishes when the VM stops instead of being lost, and a capa that runs out of time on a Go binary says "capa timed out after 240 s (Go binaries are slow; raise the limit in Settings > Analysis)".
- **A process started by a thread, or by a `vfork` that execs at once, is no longer a root of its own.** The Relationships graph, the Process tree and the Sigma `process_creation` event named no parent for an `sh` that a thread of the run's program started with `vfork` (the usual way a program runs `sh -c`): the child runs its exec before the parent's call returns, and the parent was the thread's task, which the graph does not draw. A child cloned by a thread now hangs under its process (the main task), and the Sigma event for a child that ran first still carries `ParentProcessId`, `ParentImage` and `ParentCommandLine`, read from the whole recording.
- **A process started with `clone3` is no longer a root of its own.** Programs that run `sh -c` through `posix_spawn` (RotaJakiro among them) start it with `clone3`, whose flags sit in an argument struct the process tree did not read, so the `sh` appeared as a separate root in the Relationships graph with no `ParentProcessId` in the Sigma `process_creation` event. The flags are now read from that struct. When they are missing, the guest's own record of the child decides: a task whose thread group is its own id is a new process under the caller's process, and a task in the caller's thread group is a thread. The Sigma parent and the open files a `clone3` child inherits follow the same rule. Opening an older recording rebuilds its cached index once.
- **An open for writing is no longer a creation, a write or a config change.** A file opened with `O_CREAT` that the guest's hash at close finds already holding bytes the run never wrote was there before: Files, Indicators and the Samples file list no longer call it created, the open is listed as "opened with O_CREAT; already existed (186 bytes)", and with nothing written it is not a changed file at all. "Written at close" needs a write, cut, copy or shared mapping on the file; a file that was only opened for writing and closed shows its hash as "closed, nothing written". The Suspicious activity finding "Config or autostart file written" fires on a write, a cut, a creation proved by `O_EXCL`, `O_TMPFILE` or `O_TRUNC`, a rename or a link, and no longer on an `O_WRONLY|O_CREAT|O_APPEND` open of `/etc/hosts` that wrote nothing.
- **A process that renames itself is a finding.** *Process renamed itself* (`evasion.process_rename`, ATT&CK T1036.005, because the new name makes the process pass for a program in the process list, as the argv[0] rule does; T1036.004 is about naming tasks and services) fires on `prctl(PR_SET_NAME)`, on a write to `/proc/self/comm` (or its own pid or thread) and on a write to `/proc/self/attr/*`. It is Low, and Medium when the name is a kernel thread's (`[kworker/0:1]`) or a well-known daemon's (sshd, systemd, cron). A name the recording did not capture still fires and says "new name not recorded". It is separate from *Hiding the process name: argv[0] rewritten*; when both fire for one process, Related links one to the other.
- **Kernel, hardware and network discovery is shown in more cases.** *System details read* now has one row per kind (OS and kernel, hardware, mounts and container) with the files listed in Details, and also counts `/sys/devices/system/cpu/*` files, `/sys/class/dmi/id/*`, `/sys/hypervisor`, `/proc/self/mountinfo` and the `uname` call; the CPU counts and cache sizes the C library and runtimes read as they start are left out. *Network configuration read* also counts the interface ioctls (SIOCGIFCONF, SIOCGIFADDR, SIOCGIFNETMASK, SIOCGIFHWADDR, SIOCGIFINDEX) and netlink requests for links, addresses and routes (RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE), which `getifaddrs` and malware that skips `/proc/net` use.
- **The IOC datasets banner tells a missing key from a network error.** When ThreatFox or URLhaus fail to update for want of an abuse.ch Auth-Key (none set, or refused with HTTP 401 or 403) it says "ThreatFox and URLhaus need a free abuse.ch Auth-Key" with a link to Settings > API keys; only real network errors say "check the network".
- **A run whose Tor route did not start leaves a record.** When the route of a Routed VM cannot come up (Tor stuck at 50% of its bootstrap, for example) the run is saved as Not started with the reason "the Tor route did not become ready in N s" and the last lines of the Tor log, and Run History lists it.
- **Summary's Processes of interest row stays compact.** With several processes whose names together were wider than the row (six names, one of 70 characters), the row left a wide empty band before Files. Each process is now a plain item of the row, its name cut at 36 characters with the full name on hover, at most five are named, and the rest is "+N more", which opens the Process tree.
- **Spawned windows stop at 80 % of the app and scroll or wrap inside.** The rules window (Library > Detection rules > Rules) grew to the whole width or height when a rule had a long source line, reference or description. A spawned window now never takes more than 80 % of the content area each way (or its own opening size, when that fits), and not less than a usable minimum; code scrolls sideways in its box, long text and references wrap inside the details pane. The same cap applies to every other spawned window (a rule hit's Details, Relationships, the regex and content scans, the sample viewer, File reconstruction, Keyboard shortcuts).
- **The rules window opens 40 : 60 and can never outgrow the app.** Library > Detection rules > Rules gives the list 40 % of the window and the details 60 %; the divider is still draggable and keeps its share when the window is resized. The window stays inside 80 % of the content area whatever the rule holds (a long name, a long reference, a 400-character source line): long names are cut with the full name on hover, long text and references wrap, and the source scrolls sideways in its box.
- **The three detection engine cards in Triage > Summary are one height.** YARA's "1 strong · 12 weak or generic" line has a slot in the IDS and Sigma cards too, so the state tag and the **Open results** button sit on one line across the cards.
- **Summary's one-line rows scroll sideways instead of wrapping.** MITRE ATT&CK, Processes of interest, Files and Network are each a single line; when it is wider than the box a scroll bar appears (Shift and the wheel scroll it), and the plain wheel over a row still scrolls the page. Process names are still cut at 36 characters with the full name on hover, and the rest is "+N more".
- **The Detection match list fills the pane.** Triage > Detection showed the matches in a box of a fixed 320 points, so folding the Details, Activity and Jobs pane (Ctrl+`) left empty room under it. The list now takes the height the pane has below it, and grows when the pane folds.
- **Every filter and search box has a cross that clears it.** A small cross inside the right edge shows while the box holds text (Triage tables, rules list, Samples, Run History, Detection, Settings, file and path filters, Find boxes and the others); a click on it, or Esc in the focused box, clears the text.
- **Memory Dump on Exit and Core Dump on Exit moved under the dump trigger.** In Run program they sit in the same Dumps section, below the options of Dump when suspicious activity is seen. Nothing else about them changed.
- **A run that finished with a failing exit shows in amber.** Finished with a root exit other than 0 (or a kill by a signal) now has the warning colour in Run History, the Samples Runs list, Triage's state line and the Trace header; exit 0 stays green, Failed and Interrupted stay red. A timeout's exit 124 stays blue-grey.
- **Small fixes found by the evaluation.** The default route saved in Settings > Network routes (Tor, say) now fills the next Run program form instead of the route chosen when the form was first opened. Clear in Activity asks first, with Don't ask me again (Settings > Notifications turns the question back on). A sample added under a placeholder name (MalwareBazaar's "na", or a file named by its own SHA-256) is named after its family or file type and the first 12 hex digits of its SHA-256 (`Mirai-3fa9c1d20b7e`) instead of the full hash.
- **A MalwareBazaar lookup no longer fails on a null field.** Each field of a reply is read on its own: a null, missing or oddly shaped value (a null last-seen time, imphash or comment, a YARA rule without an author, a vendor entry that is a list, `family_name: null`) is left out and the rest is kept, and a hash lookup now also keeps the ClamAV names, the Triage family and the YARA rule names, shown when you hover the Family cell. A missing family shows as "—".
- **A core taken on suspicious activity says plainly why it was not taken.** The guest's refusal "state 5, status -3" means the process was not found (it had exited, or had started over and no longer matched the request); it now reads "The process had already exited, or had started over...", with the raw state and status kept at the end, in Core dumps, Run History and the run's notes. Such a refusal counts as skipped and keeps the run's dump budget, and when the process is still running under a new identity the host asks once more for that process. Other refusals (process busy, held by a debugger, out of time) read the same way.
- **Detection puts its controls where you look.** The Scan and Result buttons and the match status sit at the right of Scanned inputs (below it in a narrow window), the match filter shares the Sort by row, the not-applicable toggle heads its section, the IDS "rules loaded" text is on the Rule packs line, the Sigma and IDS notes are hover text on Scanned inputs, and the Detection tab shows the matches of YARA, IDS and Sigma as `x · y · z` (99+ at most).
- **Six small fixes in Malware samples, the Runs list, Run program and the toolbar.** The Downloaded table in Malware samples shows at least five rows and more in a taller window. In a sample's Runs list, Arguments takes the spare width (cut, with the whole text on hover) while Tree status, Root exit and VM keep a width that fits their values. Run program's User choice has Nobody (UID and GID 65534) beside Root and Normal user; the guest takes the numeric ids, as for the others. The dump trigger's "At tier ... or higher" is now **Minimum tier** with Low, Medium and High, and its hover says this tier and above. The toolbar keeps the VM's name apart from its state word (Stopping). Start on a VM with no snapshot asks first, saying that nothing can restore the disk, with Start anyway, Cancel and Don't ask me again; Settings > Notifications > Start turns the question back on.
- **Summary boxes are easier to read, and key finding names start with what happened.** In Indicators every part has its own colour instead of all link-blue: the address, domain, URL or path in the normal text colour in monospace, and its country, organization, type and hash muted; hovering an item underlines it and shows the pointing hand. **Show N more** (Indicators) and **Show more** (Key findings) turn the first rows into one scroll area with every item, as tall as those rows were so the page does not jump, with its scroll bar always drawn at its right edge, so it is clear there is more (**Show less** and **Show fewer** put the first rows back). The branch titles (Endpoints, DNS names, URLs, Files) are bold in a colour of their own each (orange, purple, yellow, green; none is the text colour or the blue of links), with a muted count. The page scrolls with the wheel everywhere, over the Relationships graph, in its window and in Full too; the graph zooms only with Ctrl+wheel or a pinch, and the Key findings and Indicators lists and the Activity graph's lanes take the wheel only while they can still scroll that way, handing the rest to the page. In the one-line rows (MITRE ATT&CK, Processes of interest, Files, Network) the numbers are strong and the words muted. About 30 rule titles, which feed Suspicious activity and Details too, start with the behaviour in plain words and then the technical means: *Anti-debug check through ptrace(TRACEME)*, *Avoiding being attached: dumpable turned off*, *Hiding the process name: argv[0] rewritten*. Rule ids and descriptions are unchanged.
- **Five small fixes in Run History, Detection and Core dumps, and a rule window.** The process tree in a run's details now stops short of the details' scroll bar, so the two never overlap. The evidence table in a rule hit's Details uses the window's full width (a long location wraps and shows in full on hover) and shows twelve rows or more before it scrolls. In Library > Detection rules a pack's rules are no longer a table at the foot of the page (a small window squeezed it to its header row, so no rule could be clicked): the pack's buttons start with **Rules** (the open-in-window icon, left of Export manifest), which opens one window per pack or custom group (kept open when you switch pages) with the rule list at its left (the filter box, the "N of M rules" count, sorting and the on/off box of each rule) and the details of the clicked rule at its right, with a draggable divider and no window of its own for a rule. The window opens at about 70% by 75% of the content area, resizes, and scrolls inside instead of growing until it reaches the screen edge. A rule's details show its name as a heading, its ID, File, Author, License, Severity, State, Description, Tags, References (as links) and more as a grid of bold labels with room between the rows, and its source text on a padded code background. A YARA rule's `Description`, `DESCRIPTION` or `description` meta (and the same for author, license and reference) now all count, so no rule is listed without its description, in the list, in a match's details and in the YARAhub license filter. The Detection rules tables draw their column separators like every other table. A core dump list problem is reported once instead of on every frame, and a run stored by an older guest says "This run's core dump record is from an older guest and can't be listed". The Core dumps view's Capture issues list shows each issue as a plain line with no close button, so its count always matches the list, and it stays open or closed when an issue is added.
- **The Relationships graph reads on big runs.** Children of one parent that ran the same image and have no finding are one stacked box (`ps ×120`), and the files one process wrote into one folder are one box (`/tmp/x/ · 1,240 files written`); a click opens or shuts a group, a node with a finding is never grouped, and Mermaid copies what is shown. The graph is a tree from the root: each process has its children, files and endpoints beside it; every level is one column, so all the children of a process (even a hundred or more) are stacked under each other in the next column to its right, and a tall column is reached by scrolling or panning. Compact counts a group as one node. **Full is a tree you open:** it starts with the root, the paths to every node with a finding and what is under them, and the rest is closed; a box with something under it has an arrow (▸/▾) and a muted +N for the nodes hidden below it, the arrow opens or closes the next level while the box stays where it is on screen, **Expand all** opens everything (still about 800 boxes at most, and it says so) and **Collapse all** goes back; the open boxes are kept for the run and shared with the window. The layout and the grouping no longer scan every edge per node, a big run lays out off the UI thread ("Laying out…"), edges and nodes outside the box are not drawn and names are left out below a readable zoom. The zoom bar (−, %, +, **Fit**, **Fit all**) is as wide as its buttons with the same padding on every side (the % has a fixed width). **Fit** and the first view show the whole graph when it can be read, else the top of the tree as wide as the box (the root and the first levels readable); **Fit all** shows every box, however small (a thousand boxes in one column become a thin strip until you zoom in). Both leave room for the bar so no node sits under it, and it is clipped to the box when the page scrolls, and an icon in the box header opens the graph in a window of its own with the same controls.
- **Static analysis cards and code lines are tidier, and an empty view says why.** The Identity and Categories cards end at the same height (the incomplete-analysis note moved above both), Disassembly and Decompilation lines sit one font row plus a little air apart, evenly, with no item spacing between them, and a Symbols, Imports, Exports, Sections, Segments or Headers view with no rows of its kind no longer says "This listing is empty." beside `0 / 41 rows`; it says `No imports in this file; its 41 rows are in the other views.`
- **Suspicious activity reads in plain words.** The table shows eight columns: Tier (a coloured H, M, L or I chip whose hover says what the tier means and why this row has it, with a flag when the evidence is of limited confidence), Behaviour (a short title for each of the 140 rules; the rule id and version are on hover), Target, Process (`name (pid · tid)`; a click opens it in Details), ATT&CK (`T1053.003 Cron`; a click lists the rows that cite it), Count (`×40 every ~5.0 s` for a steady loop), Result (succeeded, `3 of 5 failed`, `all failed`) and When (first → last, from the start of the run, with clock times on hover). Rows come worst tier first, then by time. Category, confidence, evidence, version, source and flags moved into Details; every filter key still works. Details run from the header (tier, title, rule id and version) through What happened (one sentence), Why it matters (the rule's description and the technique, with links), Why this tier (each step that moved it), Evidence (the calls kept, each with Open in Syscall Trace, or the packet), Related (the process, the file or address in Files or Network, other findings of the same process, target or technique), the rule's facts, dumps taken and the observed fields. The four tiers have one wording each, in the graph legend, on the tier chips and in Details. The report lists the new columns.
- **A new Triage > Summary.** It reads top to bottom: a header strip (the sample's name, ELF type and architecture, static or dynamic, the packer Static analysis found, size and SHA-256 with copy; the base, route, how long the run ran and its exit; the HIGH, MEDIUM, LOW and info counts as buttons that open Suspicious activity on that tier; **Family candidates** the detections name, each with its source (a YARA rule's `family` or Malpedia metadata, the rule names of the Malpedia, YARA-Forge and YARAhub packs, IDS signature names); and behaviour tags such as persistence, anti-analysis, injection, network-c2, downloader, packed, miner or botnet). It says what was observed: no verdict, no score. **Key findings** lists the six worst Suspicious findings (by tier, then first time), each with its target, process, count and time and its description on a line of its own (the first sentence, ending in "…" when there is more: a click on it shows the whole text and another folds it); each opens its Details, **all N** opens Suspicious activity, and **Show more** turns the list into a scrolling list of every finding (**Show less** folds it). **Indicators** is a tree of **Endpoints** (with country and organization), **DNS names**, **URLs** and **Files** (the ones it dropped or ran, with type and SHA-256): each branch shows its first five and **Show N more** lists the rest in a scrolling list, **Copy all** (plain text, one per line, grouped) and **Export** (JSON beside the run's files) stay, and the header says how many indicators matched the IOC datasets and the datasets' date (there is no separate IOC datasets box). **Relationships** is a graph of the processes (name and pid), files written or run, endpoints contacted and processes injected into or signalled (ptrace, process_vm_writev, /proc/pid/mem, kill), joined by fork, exec, write, run, connect, inject and signal, with tier dots on the nodes the findings involve. The root sits in the middle and each kind grows its own way: processes to the right, files below, network endpoints to the left; a level is one column however many nodes it has. **Compact** shows the 15 best processes, 15 best files and 15 best endpoints by their findings, the processes they were injected into and the chains that join them to the root; **Full** shows every node in the same box. You pan by dragging the background and zoom with the buttons (kept inside the box at any width), Ctrl and the wheel or a pinch; the plain wheel scrolls the page; a click opens the process, file or endpoint; **Mermaid** copies it. One-line rows follow: MITRE ATT&CK by tactic, **Processes of interest** (tier dot, count and name on one line), **Files** and **Network**, then the folded **MITRE ATT&CK techniques** list (its **Mermaid** button at the left, more room between the tactic dots and the technique number), the detection engines, the notes and the run's last screenshot (a click opens it in Library > Screenshots). **Refresh** is an icon and the Open properties button is gone.
- **abuse.ch YARAhub is a YARA rule pack.** Library > Detection rules lists it beside YARA-Forge Core and Elastic protections-artifacts: about 1,700 community rules from yaraify.abuse.ch/yarahub (the public TLP:CLEAR archive, no Auth-Key), each with its author and its own Creative Commons license shown on findings. CC0 1.0, CC BY 4.0 and CC BY-SA 4.0 rules are kept; non-commercial and no-derivatives rules, rules that name no license, rules YARA-X cannot compile and rules that duplicate a YARA-Forge Core rule are removed on your computer, and the install summary counts each. The archive changes daily, so the pack is a snapshot that the monthly catalog update moves forward. Malpedia rules were already in YARA-Forge. The pack needs 0.8.3; an older app keeps its catalog copy until it updates.
- **A clearer process tree, and a click opens the process.** Triage > Process > Process tree has the columns Process (executable file name and `(pid · tid)`, the full path on hover; a fork that has not exec'd shows its parent's image greyed with "fork"), Argv (every argument shell-quoted, so `sh -c 'curl x | sh'` stays unambiguous; the hover numbers them `argv[0] = sh`, with the count and any argument cut short; the Process name disguised finding covers an argv[0] that does not match the executable; BusyBox, python3 and python3.13, sh and dash, and login-shell dashes do not warn), Findings (count in the worst tier's colour; click lists them), User (uid or uid → euid), Started (relative to the run start), Lifetime, Outcome ("exit 0", "killed by SIGKILL", "in read() at end"; the sender when a recorded kill call has it), Calls and Exec chain. A click on a row opens Details (it no longer jumps to another list) with the executable, arguments one per line, the full environment of its last exec with variables added, changed or removed against its parent marked and the rule that flagged each, working directory, credential changes, clickable parent and children, the exec chain with times, the outcome and a Show its calls link to the Syscall Trace. Triage reports list the new columns.

- **Triage tables have no warning signs; they have findings and tags.** The ⚠ is gone from the Process tree (Process and Argv cells and their hover), the Suspicious activity Process cell and its Details, and the Files tables. A process whose argv[0] names another program than the image the kernel loaded is now a Suspicious activity finding, **Process name disguised** (`evasion.argv_masquerade`, ATT&CK T1036.005): Low, because some tools rename argv[0] on purpose, and Medium when the claimed name is a well-known system tool (ps, ls, sh, sudo, sshd, systemd...) and the image is in a temp, hidden or home directory. BusyBox applets, interpreter families (python3 and python3.13, every shell), a login shell's leading `-` and daemon titles still do not count, and a kernel-thread or daemon name keeps its own finding. The Files tables (By file and each per-operation tab) have a new **Tags** column after Path: where the file lives (`/tmp`, `system`, `home`, `proc`, `hidden`), `+N names`, and a finding tag, the worst tier with the behaviour's title (`High · Dropped file executed`) or `3 findings · High`. Path is only the path; every filter key still works. The Process tree's **User** column is **User ID** (`1000`, or `1000 → 0`), with the name of ids every system has (0 root, 65534 nobody) on hover.
- **Triage tables scroll with the wheel.** In Process tree, Suspicious activity, Files and Network the section's body is a page that scrolls when the filters and notes above a table leave it under 160 points; before, the pane had no scroll area of its own and a table pushed below the bottom edge of a short pane could not be reached. The table keeps its own scroll area and the wheel works over it (render tests turn the wheel over each table at four pane sizes).
- **Detection shows no leftover table.** The YARA, IDS and Sigma pages list their matches as cards only; the table below them is gone (the card opens the same Details).
- **Details headings are bold.** What happened, Why it matters, Why this tier, Evidence, Related, the process facts and the other Details section titles use the bold face; they were only brighter than the text around them.
- **BPF Details are fields, not JSON.** An observation shows Action, Attachment, Source syscall, Process (`name (pid · tid)`), Time (from the start of the run, the clock time on hover), Result, Instructions (captured of declared), Captured bytes, Partial and Padded as words, Program id, fd, SHA-256 (twelve digits, with Copy) and the capture issues as a list; the VM, boot, run, task cookie, stream and event ids are folded under **Recording ids**, and a value the record does not have is left out. The export file keeps its JSON.
- **The Files tables are redone.** A new first tab, **By file**, has one row for each file the run touched: Path, What happened (`created → written 812 KiB → chmod +x → executed → deleted`), By, First → last, Size (`0 B → 812 KiB`), Type (ELF, script, archive, config, text or data from the captured bytes), SHA-256 (cut, with copy) and Tags (where the file lives, other names and the Suspicious activity finding that names the file). The per-operation tabs lose Evidence (Details still opens the original syscall); Location becomes a tag in the Tags column after Path (`/tmp`, `home`, `system`, `proc`, ...) beside `+N names` and the finding that names the file; times are seconds from the start of the run with the absolute time on hover; Process is `name (pid · tid)` as in the process tree, with the header "Process"; Changed files has Changes (`3 writes · 4.1 KiB`), Type and SHA-256 in place of Diff count; the file list's two sizes are one Size. The filter keys are unchanged, and `file.location == "home"` is new.
- **Per-file history.** The Reconstruct contents button is at the top right; dragging the graph's background moves it (Ctrl+wheel zooms, a double-click resets); the title is `name [sha256]` (click to copy) or `name [unknown hash]`.
- **Base builds survive a slow snapshot.debian.org.** Pinned packages (the kernel packages, the initrd's programs, the toolchain chroot's packages) come from the Debian mirror you set in the build wizard (new hint text), then deb.debian.org and security.debian.org, then snapshot.debian.org at the pinned date; each file is still checked against the SHA-256 in the pinned snapshot's signed index, so a mirror is never trusted and a 404 or a wrong file just moves on to the next source. Only the signed InRelease comes from snapshot; the other index files are fetched by hash from the mirrors first and checked against it. Every source gets five tries on 5xx, 429, timeouts, resets and short bodies (waits of 5, 15, 45 and 120 s), resuming with a Range request, and the build log says each retry and fallback, naming the file. A kernel that built and passed its checks goes back into the cache from the builder VM even when a later stage fails, so a retry does not compile it again.
- **One Start/Stop button on the toolbar.** It reads Start (green) while no VM runs and Stop (red) while one runs or starts, and is grayed while the VM is shutting down. VM > Start VM and Stop VM, the palette and the shortcuts are unchanged.
- **Minimal toolbar (icons only).** Settings > Appearance > Toolbar: every toolbar button shows only its icon and its name moves into the hover text. Off by default.
- **Dump core has its own icon** (a file with an archive box, as core dumps have in the notes), on the toolbar and the Dump core buttons.
- **The VM's screen shows in the app.** A VM now opens a "VM screen" tab beside Static analysis (View > VM screen and the palette open it again; closing it is remembered) over QEMU's VNC display on a private unix socket in the VM's runtime folder (no TCP port). Click the screen to type into the guest; Ctrl+Alt gives the keyboard back, and while it is captured no app shortcut fires. The tab has Fit and 1:1, Ctrl+Alt+Del, Screenshot (a PNG in the VM's recording folder under `screenshots`) and Type clipboard. The mouse is absolute with a USB or virtio tablet and relative (while captured) with a PS/2 mouse. VM settings > VM screen keeps the old QEMU window as a choice; it applies at the next start of the VM. The guest sees the same devices either way, and the QEMU GTK check only applies to the QEMU window.
- **A run can take a memory dump or a core the moment suspicious activity is seen.** In Run program, Triggers > "Dump when suspicious activity is seen": choose the tier (Low, Medium or High and above; Triage has no tier above High), what to take (a memory dump, a core of the process that made the call, or both), how many dumps one run may take (1 to 8, default 1), the quiet time between two (default 30 s) and the largest VM RAM a memory dump may take. The core uses the budget and deadline of Core Dump on Exit. While the program runs the recorder judges each call with the same Triage rules the index uses, so a finding arrives within milliseconds of the call (an execve with no exit waits at most 250 ms); rules that need the whole run or the network capture only fire in the index. A finding past the budget or inside the cooldown is counted, not dumped; a dump that cannot be taken (the process already exited, too little disk, another memory dump under way) is recorded with the reason and not retried. A core that cannot be taken because the process is already gone is not an attempt: it is counted as skipped, noted, and the next match may still dump. A trigger is not re-armed when a VM snapshot is restored. A core is taken first and the memory dump after it, because a memory dump pauses the guest. `run.json` keeps the plan and, per trigger, the rule, tier, process, call and time and what was taken (path, size, state); Triage shows "Dump taken" with a link to the Memory or Core dumps tab, Run History lists the dumps under the run's options, the run's notes say what triggered them, and the sample window's Artifacts table says "Triggered by <rule>".
- **A third click on a column title turns the sort off.** Every sortable table (Triage, Run History, Samples, Network packets, rules, Syscall Trace and the rest) now cycles ascending, descending, off: the third click goes back to the recorded order and drops the arrow. Trace was the one table that only flipped between the two.
- **The sidebar folds to a rail of icons.** Ctrl+B, View > Fold or open the sidebar, the command palette or the chevron at the top of the sidebar (the same chevron opens it again) fold Virtual machines, Base images, Detection rules, Analysis tools, Samples and Explorer to one icon each, with tooltips that carry the names and counts. The VM icon shows the state dot of the running or selected VM and opens a list to choose a VM or add one; the other icons open their pages; Explorer opens the sidebar. The choice is saved with the settings.
- **Details, Activity and Jobs can fold to their tab strip.** Click the shown tab, press Ctrl+J, use View > Fold or open Details, Activity and Jobs or the palette, or drag one of the tabs to the bottom edge of the window: no tab is selected and there is no body. Click a tab again, or drag the separator up, to open it at the height it had; View > Details, Activity, Jobs and the Jobs chip open it too. A selection that fills Details does not open a folded pane; the Details tab gets a dot. The folded state and the height are saved.
- **Settings > Recording names its base "Default base for new VMs".** It was "Installed base"; it is the base a new VM starts with (and the folder the app reads bases from), not a base for recordings, and it now says so in a tooltip. The Recording page also has tooltips on the quota and the shutdown timeout.
- **Detection rules keeps its long text in tooltips.** The IOC and abuse.ch tabs show one short line each and the false-positive explanation is on its heading; the sentences are unchanged. The buttons that had no tooltip (Reload local rules, Check for updates, Open rules directory, Cancel, Open datasets folder, API keys, Try on) now have one.
- **Detection rules shows counts** under its title, like the IOC tab's "x of y loaded": "3 packs · 2 enabled · 1 custom group · 40 string patterns".
- **Detection rules counts are in the IOC style.** The page's counts sit on the title row, each engine tab ends its button row with its own "2 of 3 packs enabled · 1 custom group", and Strings regex says "N of M string patterns in use".
- **Detection matches can be sorted.** Under Matches a Sort by menu orders the cards by Risk (default), Name, MITRE technique, Engine (pack), Hit count or First hit (where the first hit was recorded). The choice is saved with the settings. The hit count is now beside the severity tag, the card no longer says "Matched syscall ...", it still names the pack and now shows every author, and the title, description, facts and tags are further apart, as is the filter from the matches.
- **Rule hit details put the evidence under the description**, as a scrollable table (number, location, journal event). Rule text wraps by default, and its window has a background.
- **The Detection page scrolls** when a section grows: expanding "Show the N rules not loaded" no longer runs past the bottom of the pane.
- **The empty-result note says what was left out.** "No rule matched the 2 inputs that were scanned. 3 of 5 inputs were not scanned (reasons...)" with the usual causes (too large, an unsupported type, the time limit).
- **IDS rule counts are explained.** "Rule packs: 1 enabled · 386 rules" counts every rule in the enabled packs; the coverage line now reads "370 rules loaded (of 386 in the enabled packs)" and its tooltip says how many were refused before the scan, switched off one by one or left out by Suricata.
- **Sigma results no longer rescan on their own or vanish.** The Sigma version check waited 20 s and under load answered "unknown"; that answer was cached, replaced the good one, changed the rule selection digest and so started an automatic rescan that evaluated no rule and replaced the result. The check now waits 60 s, an unknown answer is never cached and never replaces a known one, no automatic scan starts while a tool has not answered, and a background re-scan that fails or evaluates nothing keeps the earlier result on screen with a note. The full reason a Sigma pack was not evaluated is shown in the page, not cut to one line.
- **Use Antinomie's own copy of a tool the system has.** Library > Analysis tools and Tools > App dependencies give each tool found on the system a "Use Antinomie's own copy instead" box; the choice is saved per tool and the analysis worker, the Ghidra window and the Tor and wireproxy routes then prefer the copy under the data folder (the system's is used until it is installed). Install all missing still skips tools the system has.
- **A time limit for each analysis tool.** Settings > Analysis tools shows a Time limit for capa, FLOSS, binwalk, YARA, UPX, Ghidra and Detect It Easy, each with its default ("Default (240 s)") and a Reset. Settings > Detection rules has the same for the Triage YARA scan, Suricata, Sigma and TShark (carried in the detection request, defaults 100, 100, 110 and 300 s). A time set for one tool wins over the time limit for every tool; a check's Run again with twice the time is unaffected by them.
- **Settings > Network lookup says only "Database found".** The file name, source and path of each database are in the chip's hover text. The MaxMind wording is clearer: GeoIP.dat files do not work with TShark 4, and the DB-IP Lite install needs no account.
- **The SOCKS5 password field is as wide as the other fields** of the Network routes form.
- **Settings has more room.** The window is wider, the scroll bar no longer lies on a text, rows are further apart, and the pages with many settings (Recording, Analysis tools, Advanced) have sub-headings.
- **Keyboard shortcuts can be changed.** Settings > Keyboard has one row for every action and view (click, press the new keys; Esc cancels), refuses a key another action has until you choose to move it, and has Clear, Reset and Reset all. The menus, tooltips, the palette and the shortcut list show your keys. Saved with the settings.
- **Defaults for a 60 % keyboard.** Start VM is Ctrl+Shift+S (was F5), Stop VM Ctrl+Shift+X (was Shift+F5), fold or open Details, Activity and Jobs is Ctrl+J (was Ctrl+\`), and Show Details is Ctrl+Shift+D. No default uses an F-key, an arrow, Home, End or the backtick.
- **Copy as Mermaid on every diagram.** The samples lineage graph, the VM snapshot graph and the file activity graph have it in their right-click menu; the Triage process tree, the phases of the Graph tab and the MITRE ATT&CK list have a small Mermaid button. Each puts a flowchart on the clipboard with escaped labels and ids made from the node's own key, so they stay the same from one copy to the next.
- **"Select a run to view its details" and the other empty states are centred** on both axes of their pane.
- **The toolbar's sidebar button lights on hover and press** like the other toolbar buttons.
- **Settings keeps explanations in tooltips.** Every page shows a short line where it had a paragraph; the rest is on hover. "Appearance applies at once · other pages apply on Save" is gone.
- **"Use TCG when KVM is unavailable" is on for a new install** (and where the setting was never saved). A saved choice is kept.
- **The time limit rows no longer say "Default (N s)".** The Reset button's tooltip names the default.
- **Table column lines match the row lines.** Cells next to each other were filled up to a position between two pixels, so the page showed through between them as a line one or two pixels wide on a scaled display. Every table fill now ends on a pixel, and the column divider and the header's row rule are one stroke (one pixel, the line colour).
- **The sidebar VM line reads "<base image> · <architecture>"**, for example "Debian 13 (Minimal) · x86-64". CPU and memory are in the hover text.
- **An arrow at the right end of the Details, Activity and Jobs tab strip** hides the pane (down) or shows it (up); its tooltip has the shortcut (Ctrl+J by default).
- **Dots beside text are drawn, not typed**: the tactic dots of ATT&CK badges (Triage > Summary), sample tags and verdicts sit on the middle of the text.
- **Run summaries say what the time is.** "Ran for 3 min 52 s · exit 0" instead of "Finished after 3:52 (exit 0)"; the start and end times are in the tooltip.
- **Preparing run evidence is centred in its panel**, both ways, in Triage > Summary.
- **Column dividers are one pixel wide while hovered or dragged**, with the same drag area as before.
- **The Explorer title no longer shows a count.**
- **The note that a read-only file has no guest hash is an info icon** beside Hash this state in a file's history; hover it for the sentence.
- **Type clipboard is in the run terminal's header** as well as in the VM menu (Ctrl+Shift+Y and the palette entry stay); it is not in the main toolbar.
- **File Reconstruction shows the bytes as hex, text or UTF-16LE.** Beside Hex and Text diff, the view switches to the bytes as UTF-8 (an invalid byte shown as `\xNN`) or as UTF-16LE. Bytes with no value stay marked in every view (`??` never seen, `##` not captured, `~~` shared mapping), and the choice is remembered for the session.
- **A complete reconstruction is hashed as a normal state.** When no byte is unknown and there is no gap, the Hash check computes SHA-256, MD5 and SHA-1 by itself (each with Copy) and compares the SHA-256 with the guest's hash. When there are unknown bytes or gaps, Hash this state is disabled and says why, for example "2 gaps, 140 unknown bytes: a hash would not match the real file".
- **A changed custody entry stays in the table.** When an entry's stored text was edited so it no longer read as an event, the Custody log (and the global custody view and the report) skipped its row, so the numbers went 1, 3, 4. The entry is now listed as "Unreadable entry" with the stored text, marked changed, and the banner, the row, the HTML export, the JSON export (`status.problem`) and the report say what the verifier compared (field, expected hash, found hash).
- **Library > Screenshots is a gallery of the VM screen's pictures.** The sidebar's Library section (and its folded rail), View > Screenshots and the command palette open a page with a thumbnail grid of every screenshot taken on the VM screen tab, newest first, grouped by VM and by the run it followed, each with the time it was taken. A click opens the picture in a window that fits it whole (Fit) or shows it at 1:1; each thumbnail and the window also copy the path, open the containing folder and delete the file after a confirmation. With none yet, the page says to click Screenshot on the VM screen tab. The folders are read when the page opens, on Refresh and after a new screenshot; thumbnails are decoded on a worker thread, only for the cells in view, and a bounded number are kept.
- **Never drop no longer drops under Capture All.** Since 0.5.0, Capture All switched a never-drop VM to dropping whenever the host fell behind (its guest waited more than half the time, or the recording writer was 64 MiB behind): a heavy BusyBox load under Capture All lost 87 % of 635k packets, the launched program's own telemetry included. Never drop now means never drop: the guest waits and runs slower instead (that load took 12.5 s instead of 1.3 s, and lost nothing), and Triage > Summary says while never drop is slowing a Capture All guest. Dropping is an explicit choice, off by default: VM settings > Telemetry transport > Capture All: "Drop telemetry when the host falls behind" keeps a desktop guest responsive and loses events; the Summary (and More health details) then shows how often and for how long it dropped, after the fact too. Settings files from before load with it off; drop mode is unchanged.
- **Processes a launched program forks right away are named.** Under Capture All, a child the program forked before the host knew its PID (a shell's first command, a BusyBox applet run without an exec) was listed without a name; it now carries the program's name until it executes another one.
- **Capture All right after boot says why it waits.** Before the guest kernel has identified itself, Capture All and process attachment said the base needed Antinomie 0.2.0 or newer; they now say to retry in a moment.
- Continuous integration: the nightly VM test requires a heavy launched program and the same load under Capture All to lose nothing in never-drop mode, and, with Capture All dropping allowed, loss only while it drops; it runs its programs by path, since the bases' static BusyBox shell runs a bare `ls` as an applet without an exec. It had failed every night since Capture All load shedding (0.5.0) and the bases' static BusyBox (0.8.0). Its guest-run driver no longer sends a slow command again (which launched the program twice), and lists network captures only once their final summaries (written in the background) are on disk.
- **A full snapshot restore no longer fails on a busy machine with "No such file or directory".** The restore started a new QEMU and asked it for the saved state after waiting only 2 s for its monitor socket; when QEMU took longer to start, the restore failed with ENOENT and left the VM stopped. It now waits as long as a normal start does, and a failure says that the monitor connection failed and what QEMU logged.
- **`antinomie-monitor --version` names the commit it was built from in a git worktree.** A local build from a worktree did not run its build script again after a commit there (the branch and packed-refs live in the main repository's `.git`), so `--version` and About kept an older commit; it now follows HEAD, the branch's ref and packed-refs in a clone, a worktree and on a detached HEAD.
- **A VM can run with no screen.** VM settings > VM screen has a third choice, No screen: QEMU runs with `-display none` and no VNC, and the VM screen tab (View > VM screen) says the VM has no screen and where to change it. Saved VMs keep their choice, the other two choices start QEMU exactly as before, and the guest sees the same devices.
- **The Explorer has a folder button instead of "Choose folder".** The "+" on the Explorer title is a folder icon with the tooltip "Choose Explorer folder", and the Choose folder button below it is gone.
- **File > Open folder and Import sample.** Open folder is the Explorer's folder chooser; Import sample is the Samples page's Add file dialog (the palette says Import sample too).
- **The status bar items share one middle line.** The message, the Jobs chip and the loss, CAP and version figures are centred in the bar's height, not hung from its top.
- **Column dividers are drawn one physical pixel wide** on a pixel's centre in every table, so they no longer smear over two pixels at a fractional position or on a scaled display.
- **The Summary window is now the Overview window** (its tab, View menu, command palette and the docs; the saved layout keeps working). Its Compute card shows the vCPU count and the RAM side by side in the large figure, and the VM name has more room before its state, without the "x vCPU, Network" line (both are in the cards below).
- **State dots are centred on their text.** The dot before a state or a name (the Overview, the VM rows of the sidebar and its popup, the toolbar status, the snapshot "You are here" line and the ATT&CK tactic headings) is drawn on the middle of the letters instead of typed as a "●" glyph that sat lower than the text. One helper draws them all.
- **The VM screen tab folds Details and Activity again when it opens.** While the tab shows, the work area takes the height; the layout asked for 93 % of the window, but the dock keeps the height of the Details pane's usual minimum under the separator and clamped the split back to it every frame (about 77 % in a 900-point window), so only the stored value folded. The separator now reserves nothing while the pane is folded away; the debugger tab and the Samples page, which use the same fold, are fixed with it. The rendered-app tests open the tab the way the app does.
- **Debug on start stops at the first instruction for the console's gdb again.** When a debugger session began, the Debugger tab drew its gdb console (which starts gdb by itself) before the tab had taken the new session, and taking it one moment later ended that first gdb and started a second. The first one could still connect before it quit, and a gdb that leaves lets the program run: a program started under the debugger then ran on from its entry, so the console's gdb found it already past `main` and its breakpoint there was never reached. The tab now takes the session before it draws, and a new session starts one gdb.
- **Triage > Files rebuilds every byte the recording kept of a write, not the first 64 KiB.** A write of 1.2 MiB whose whole buffer was recorded now gives all 1.2 MiB (up to Rebuilt file bytes in Settings > Analysis limits), read from the recording in steps of 64 KiB so memory stays within that limit. The note "A transfer moved N bytes but the buffer the recording captured..." came from the app's own cut and is gone for those writes; it now appears only when the recording really kept less than the call moved, and says so ("This write moved 1,286,144 B, but the recording kept only 65,536 B of its buffer"). Msync pages are placed the same way.
- **Stop run ends a run that never exits, without stopping the VM.** The toolbar button, the Run menu item, the palette entry and the Run History row's stop icon (the old Kill) are now **Stop run**. It ends every live task of the run, children included, and stays available while a child lives after the root exited; the run then finishes normally: the recording closes, the pcap's last segment closes so it is whole, the route's counts are written to `artifacts.json` and the journal is complete, so IDS and Sigma have a whole capture and journal to read.
- **A run cut by a VM stop keeps its route counts and says what happened.** Stopping the VM while a run is alive now closes its capture and writes the gateway's counts for the route (they were `null`). The run reads **Ended by VM stop · root exited 0 · 1 process still running** instead of "Interrupted · Exit 0", and a run ended by Stop run reads **Stopped by you · root exited 0**, in Run History, the Runs list, Summary, Triage's state line and the reports.
- **The dump trigger answers faster, and says plainly when it was too late.** The worker wakes every millisecond while a run waits for a trigger or a core is being started (it was ten), and a match whose process exited first is kept in the run's trigger log with "The process exited 120 ms after the match, before the core could be taken.", in the run's notes, its features and the finding's Details. A partial core says which part is missing, thread contexts or pages, with counts. The run's `artifacts.json` lists the trigger's dumps under `trigger_dumps`, so it no longer says "core disabled" beside a core in `run.json`.
- **Export report stays on the run it was opened for.** Switching runs with the window open made Export fail after a minute with "run manifest identity mismatch": the window kept the first run's recording but took the second run's request. The window now follows the run on screen (its list of written files is cleared) and its title names the sample and run (`Export report: elf-9701ae72 [43b0b44a]`).
- **The export windows stay put and cannot be closed by accident.** The run report window opens at the top and keeps its close button where it was as the list of written files appears; the list shows every file, above the choices; **Close** and Escape close it; its ✕ and Escape do nothing while it writes (**Cancel** stops it); **Export** stays off after a write until a choice changes. The sample report window had no way to cancel: closing it still wrote every file and a custody entry, and a second click wrote a second set. **Cancel** now stops it before anything is written or noted.
- **A large run's export shows progress and reuses Triage's index.** The window says `Indexing the telemetry: 1.2 GiB of 3.3 GiB (36%)`, `Reading the calls, pass 1 of 2: 82,000 of 1,791,320 (4%)` and the elapsed time, and Cancel stops at the next step. When Triage has already indexed the whole run (no filter or sort set) and the recording has not changed, the export builds from that index instead of reading the recording again (a 3.5 GB run took an hour for its second read).
- **A run that never started is in Triage's run picker.** Runs the guest refused or whose Tor route did not come up are listed as `(not started)`; Triage shows why, the request, the route, the static analysis and the sample, and **Export report…** writes a short report (failure, request, static analysis, sample identity) with host paths cut to file names.
- **Static-analysis and custody exports no longer default to your home folder.** They open in `exports/static` and `exports/custody` of the data folder, or in the folder the last export of that kind went to. Every export is told in a toast and an Activity row with the file, size and folder (the eBPF export, the Summary's indicator export and the static-analysis export said nothing or kept a window open), and the Summary, IOC and custody files are named `antinomie-<kind>-<run or sample>-<yyyymmdd-hhmmss>`.
- **Defang is on by default in the run report**, like the sample report. The sample IOC export's CSV and JSON are always raw (a defanged value in a blocklist is useless); the Defanged chip changes the table and Copy only.
- **Data window Copy no longer corrupts bytes.** UTF-8 copy replaced invalid bytes with U+FFFD (170 bytes for 144). Copy now gives Hex when the text view would change the bytes, and **Copy as** disables UTF-8 and ASCII for such bytes.
- **Triage no longer says "Refreshed 3790 s ago · every 5 s" for a finished run.** A run that is read once says `Read at 14:05:12`; the seconds counter and "every N s" stay for a live run.
- **Exported reports name the family and say how the run ended.** The run report's Summary names the families the way Triage's Summary does (Elastic and curated rule names, `family` metadata, IDS messages, the sample's MalwareBazaar record) with their sources, so BPFDoor, Tsunami, Gafgyt and the rest are no longer "no family" (or a weak `Torii` for a Gafgyt run); MISP gets an `antinomie:family` tag and STIX a family `malware`. The overview says "Stopped by you at 6 min 25 s · root exited 0", "Ran for 1 min 20 s · exit 255" or "Ended by VM stop" (it said "finished" for every run), when the run ended and for how long, and lists the environment it was recorded on (base image, kernel, VM, stealth profile, route, rule packs, tools). The sample report's Runs table uses the same words, merges a rule the static scan and a run both matched into one row, and shows the families its rules name when the library holds none.
- **A run of a shell with a preloaded library no longer publishes the shell as the sample.** When the run started `/bin/sh -c '... LD_PRELOAD=...'` (not a library sample), the reports say "none recorded" with the command, name the preloaded library when it is in the library, and no longer export the Debian shell's hash as the malware (MISP and STIX), nor a custody section for a file with no library record.
- **MISP and STIX carry only indicators a consumer can match.** The guest's own resolver, the Tor gateway's stand-in addresses (the document shows `198.18.0.1:20 → mircd.xiao.my.id (Tor stand-in)`, and the domain is the indicator), other private addresses, files with no content kept and Debian programs the run only started stay in the document and the JSON (`stand_in`, `not_shared`) but not in the exchange formats. STIX bundles no longer hold two objects with one id (one indicator per pattern, the paths in its description) and gain a `report` object; MISP gets the sample as a `file` object, a threat level of 3 for an observed-only run and `to_ids` on the sample only when a dataset matched or a rule named a family.
- **Reports keep host paths and copied reads out.** The sample report and the custody HTML name an imported file by its file name (not `/home/<you>/...`), and new custody entries store only the file name. The run report's Read files table keeps the size of each read, not the bytes (dictionary files, `/etc/passwd`, `/proc/*/environ`, the sample's own copies): a PDF of 207 pages is now a few dozen. The JSON keeps up to 120 clipped, escaped characters only with `include_content` set, never of a file the run wrote.
- **Report documents are readable, not a dump.** Identical rows of the Files tabs fold into one with a count and the first and last time (200 rows per tab at most; the JSON keeps all), files with one hash are one indicator row with their paths, the guest's resolver and Tor stand-ins are named, the Summary counts findings by tier and lists the key findings, big numbers have separators, every time is in the app's zone with its date and one footnote explains `~`, Evidence references list the recordings, not the small logs, and the geolocation credit closes the document. The PDF prints the arrow as `->` instead of `?`, keeps each column's longest word whole, has a running header, "Generated ... - Page N of M" as its footer, its kind, subject and keywords in its properties, coloured tier words, and more room above headings. The HTML breaks no short word (`succee/ded`), has table captions, `scope` on headers, a labelled sticky contents list, focusable scroll areas and coloured tier chips. Detection engines show one severity vocabulary (strong, weak, Sigma level) and the rule's reference in a column of its own, without the pack's `sNNN::` number.
- **Smaller report fixes.** The Markdown sample report escapes only what would become markup (`\5 run(s)` is `5 run(s)`, `&amp;` is `&`), the sample report's run row names the fullest report file (not the newest, which can be a near-empty export), the custody HTML fits its columns and scrolls, the evidence bundle has a README, report file names end in `Z` (UTC), the static analysis export says `ELF`, `x86-64`, `alloc, write` and `complete` instead of Rust's debug output, the sample IOC CSV separates lists with `;` and splits `process` from `pids`, and the Summary's indicator export puts the country and organization under their own names (the byte count was in `country`).
- **Reports link every entry, and the key findings are a table.** In the run report's HTML, PDF and the new Markdown format, every process, file, endpoint, domain, rule, finding, detection, technique and indicator has an anchor and every mention of it is a link: a key finding opens its row in Suspicious activity, its process and the file or address it was about; an opened file in any Files tab opens the file's entry; a process lists its parent, the files it wrote and its findings; a file, an endpoint and an indicator list the findings about them. Key findings is a table (#, Tier, Rule, Behaviour, Object, Process, Count, First seen, ATT&CK) instead of a list of cut sentences. The PDF starts with a Contents block that gives each section's page and has real links (it had bookmarks only). A link whose entry is not in the document is plain text, so none is dangling. The sample report links each rule, run and indicator the same way, and its Run report column opens the run's report.
- **The run report reads in the order an analyst works.** It opens with **At a glance** (sample, family linked to a Family evidence table of the rules that named it, how the run ended, the tier counts and what was observed as links, the key findings and indicators), then indicators, techniques, processes, suspicious activity, files, network, detections, evidence, custody and notes, with the environment as an appendix (rule packs and tools one per row, full versions). A rule that fired four times or more with one tier and result is one row with the count (Ladvix's 179 findings fit on a page; the JSON keeps all of them); the file the run wrote or changed is one row with its lifecycle and reconstruction, placed first, and empty tabs are one line; times read `+5.463 s · 17:38:21.480`; private and reserved addresses have no country, and a Tor stand-in endpoint says what it stands for; an indicator seen in 26 `cat` processes reads `cat (26 processes)`; the findings-by-tier line counts INFO findings as the app does. Only the strongest family is the report's family, MISP tag and STIX malware name (twenty Gafgyt rules beat one Mirai rule and a weak Torii rule, which are "also named"), and the family is said once with the pack's name, not its path. Rule ids in MISP and STIX lose the pack's `sNNN::` number, a long rule name in the PDF breaks after `_`, and a hash MISP only knows through a folder such as `/tmp` is a plain `sha256`. The JSON is schema version 2: key findings are objects (the sentences stay in `key_findings_text`), every entry has an `id`, every link a `*_ref`, and tables carry typed `data` (pid, times in ms, counts, bytes); see `docs/triage-report-schema-2.json`.
- **A run that never started is said once and keeps its guest paths.** Its report read "Not started: Not started: …", cut `/proc/net/tcp` and `/etc/shadow` in the request to `tcp` and `shadow`, and pasted the Tor log into the run state. The failure is now said once, only paths on this computer are cut, and the log lines are a separate "Failure detail" (also on the Triage page). Its MISP and STIX no longer present a sample that ran nothing as malware: the sample is a file, a note says the run did not start, and nothing is marked for blocking.
- **Exports land where they say.** The default Static analysis folder `exports/static` (and `exports/custody`) is made on the first export, which failed with "No such file or directory" and an empty popup; an error is now also said in the window. Each kind of export remembers its own last folder, so a custody export no longer opens where a static-analysis export went. eBPF **Export binary and JSON** says "Already exported: <name> in <folder>" beside the button when the capture was exported before (a second press did nothing visible). Custody, indicator and sample IOC file names end in `Z` like the reports'.
- **Custody exports keep host paths out.** An entry recorded before entries stored only file names (an import, a deleted original) gave the analyst's full path in the custody JSON, the HTML's embedded record and the evidence bundle. The export now names the file only and marks the entry withheld with the SHA-256 of the stored text; `verify-custody.py` and the app's check still verify every link and say which entries they took as recorded. **Keep paths on this computer** in the custody dialog keeps them, for internal use.
- **The sample report's rules and runs read like the run report's.** Rules that matched says how much each match says in one vocabulary (`strong (score 100)`, `weak`, `Sigma high`), names the family a rule names (the Tsunami rules now say Tsunami), leaves Title out when it repeats the rule and lists author, licence, pack and reference in a credits table. A run's report is its export with the most sections, the newest of those (it was the largest file, which picked an old export full of copied reads). The merged indicators say whether MISP and STIX carry each one, and the sample's hashes are marked for blocking only when a run was suspicious, a dataset matched or a rule named a family.
- **The page scrolls again after you used the Relationships graph.** Dragging the graph out of the window and letting go outside left the whole page unable to scroll until the next click: the system never told the app the button was released, and a page does not turn the wheel while something is being dragged. A pointer that leaves the window now ends the drag. The plain wheel scrolls the page over the graph too; only Ctrl + wheel or a pinch zooms it.
- **Ctrl + wheel zooms the Lineage graph, the plain wheel scrolls.** The Lineage graph (Samples > a sample) zoomed on the plain wheel, so the page could not be scrolled over it. The VM snapshot graph (Snapshots) followed the wheel with a pan on top of the page's own scroll, and its Ctrl + wheel did nothing; it now zooms on Ctrl + wheel or a pinch, pans by dragging, and leaves the plain wheel to the page.

## 0.8.2 — 2026-11-03

Antinomie 0.8.2 is a host-only release on the 0.8 line; it runs the same
revision-20 bases as 0.8.0 and 0.8.1. It adds a command palette, keyboard
shortcuts and a Jobs window; a Content view with Strings and Regex search for
memory dumps and process cores; record arrays as trees in the Syscall Trace; an
IOCs tab in the sample window; ATT&CK coloured by tactic; reduced recording when
the quota is nearly full; a wait for the guest to finish booting before a run;
offline IP geolocation for TShark; and a time zone setting. The interface moved to
egui 0.36, and saved settings now survive a restart again. Details follow.

### Host

- **A sample's window matches the Samples list after a restart or a new run.** The window read a sample's runs from the VMs the app listed when the read began, so a window opened before the app knew its VMs (right after a restart, or under load) showed "Runs 0", "Never run" and "Not triaged yet" while the list, which also counts runs the library already noted, showed the run. The list and the open sample are now read again whenever the VMs or their runs change.
- **Core mappings are named the way `/proc/PID/maps` names them, and a core taken at exit says so.** A mapping with no file used to read "unknown", which looked like a bad core. The Memory mappings list, the mapping picker, the Content view and the Strings segment now show `[stack]` (holds the saved stack pointer, or the program path from the auxv), `[vdso]` (the auxv AT_SYSINFO_EHDR address), `[vvar]` (the mapping that ends where the vDSO starts), `[vsyscall]` (the fixed x86-64 page), `[heap]` (the first writable anonymous mapping after the program's data, where brk starts) or `anonymous`; the tooltip says how each name was inferred. A core captured at a normal exit shows "Captured at exit (no signal)" instead of "signal 0".
- **The VM Summary Snapshots box always shows the snapshot diagram.** With no snapshots it draws the base image and the "You are here" node; with snapshots it draws the same graph as the Snapshots window, fitted to the box, instead of a text tree. Take snapshot, Restore and Open Snapshots stay; click a checkpoint in the diagram to select it.
- **A run waits for a Debian guest to finish booting, however early it is clicked.** The first run of a boot used to start the moment the guest control channel was ready, so a run started in the first seconds could be rejected ("No such file or directory" for /tmp, which Debian mounts as a tmpfs early in boot) and persistence such as `@reboot` cron could start a second copy outside the recording. Whether a guest runs systemd is now decided from the base (a base with a guest profile, Debian, does; BusyBox does not) instead of from `/run/systemd/system`, which is absent early in boot, and the wait ends only when userspace is up and systemd's boot-finished marker (or cron's @reboot marker) shows; a probe that is unsure keeps waiting. Every launch (Run program, Upload and run, Ctrl+R, re-run from Run History, automation) goes through it and shows "Starting run: waiting for the guest to finish booting" in the status bar and Jobs, with Stop. It waits for at most **Settings > Advanced > boot wait** (default 60 s at KVM speed, stretched by the TCG multiplier), then starts anyway with a note on the run. The wait runs no program in the guest, so it is not in the recording or the process tree. `run.json` has `boot_wait` (`waited_ms`, `outcome` ready, timeout or skipped).
- **Stop gives a Debian guest more time to power off, and Import base shows in Jobs.** A Debian VM stopped soon after it started was forced off after the 10 s shutdown timeout while its kernel was still syncing the disk the boot had written; the shutdown wait is now at least 30 s for a distribution guest and 60 s in its first 90 s (stretched for TCG), and a forced stop is still reported. Importing a base adds a Base import row to Jobs while it verifies and copies.
- **The reduced-recording note no longer says the quota was reached at the 90% switch.** It reads "Recording quota nearly full at <time>; from then on only suspicious-activity calls were kept, N dropped"; "Recording quota reached" is said only when the quota was full and saving stopped.
- **Device profile texts say what they are.** The Cloud VPS preset line reads "Reports a cloud provider's instance identity (independent imitation)" and the metadata line on a Routed cloud VM says the fake metadata, with canary credentials, is served inside the VM only. The README's Trademarks section and `docs/security.md` say the same: names are used only to say what a profile imitates, no affiliation, no logos, firmware, provider software or real credentials, and no provider is expected to accept the canaries.
- **A Content window for memory dumps and process cores.** The Memory tab has
  a Content tab beside Volatility 3 and MemNixFS, and Core dumps has a Content tab
  per mapping. Both show the bytes as a hex dump or as raw text, read one page at a
  time so a multi-gigabyte dump is never loaded, with go-to-offset, paging and
  selection with copy. On-demand Strings and Regex sub-windows search the dump (or
  the mapping shown) only when you press Search, with progress and Cancel, list
  their hits a page at a time in a table, show in the Jobs window with progress and Stop, and jump the view to a hit. Limits and cancels are
  shown as Info notes. A core shows virtual addresses, with file offsets on hover.
- **Record arrays are visible in the Syscall Trace without digging.** The Info column summarizes a decoded array instead of printing its flat struct text: `fd=3 dirent=8+ entries: "group", "hostname", "passwd", ... +2 more`, `ufds=3 fds: 3 POLLIN -> POLLIN, 4 POLLOUT`, `SCM_RIGHTS fds 7, 8`, `N instructions: ...` (`+` after a count means the preview holds more than was decoded; a call that captured nothing keeps its old text). Hovering the Info cell lists every decoded record. In Details the array's records are open under its row in the Arguments tree (each opens to its fields), the right pane opens on the array itself (also for an array nested in an argument, such as a message's control data), and Decode all captured, Copy all as JSON and Save as JSON are as before. The trace filter matches the new text and the decoded fields; exports keep the structured records.
- **A new or copied VM shows up at once, marked Creating, and its work is in the Jobs window.** Creating a VM on a Debian base sets up the guest account by starting the guest once, which takes minutes without KVM; the app listed the VM only when that was over ("Virtual machines 0" and "No saved VMs" meanwhile, although the VM folder already existed). The sidebar now lists the VM straight away as "Creating…" (or "Copying…" for Duplicate) with the step it is in ("Laying out the base's UEFI disk", "Creating the disk", "Setting up the guest account", "Saving the configuration") and the time so far. The Jobs window shows "VM creation" or "VM copy" with the same step and the elapsed time, then Finished ("The VM is ready") or Failed with the error. Rename and Delete already updated the list at once and still do.
- **A run without packets no longer lists every skipped IDS rule.** The notes say "No packets were captured, so no IDS rule was evaluated." and one line per reason, for example "38 rules need a TLS fingerprint keyword the bundled Suricata configuration lacks; they were skipped"; the SIDs sit behind "Show the 38 rules not loaded" on Triage > Detection. Results saved with the long list read the short way too.
- **The Jobs window no longer paints the running table's background under the Finished list.** With a job running, the dark table fill ran from the running rows down to the bottom of the tab and covered the Finished heading; every table's fill now ends where the table does.
- **Every window and page is in the Ctrl+K palette.** It now lists each Settings page (Appearance, Recording, Detection rules, Notifications, Network lookup, Network routes, Analysis tools, Disks, Advanced), the Base images and Samples pages, Add file to Samples, each rules engine (YARA, IDS, Sigma, Strings regex, IOC datasets and downloads) and the download catalog of YARA, IDS and Sigma, every Getting started step, Import memory dump, Memory plugin catalog, Import disk image, Import process core and Choose Explorer folder, plus any view whose tab you closed. Entries have synonyms (for example "proxy", "suricata", "theme", "whois") and the ones that need a VM show why they are greyed.
- **The Ctrl+K palette also lists the VM Telemetry transport and Device profile windows, a run's terminal, the Debugger tab, the abuse.ch packs, and the actions on a selected run or rule.** Open terminal, Edit tags, Delete the selected run (a run that never recorded), Export report and Rule details are listed greyed with the reason ("Select a run first.", "Select a rule in Detection rules first.") until there is something to act on; the Debugger tab says no debugger is attached.
- **Typing in a filter box no longer drops the keyboard after a few characters.** The Syscall Trace filter (and every other filter box built on the shared filter editor) lost focus while its results were being recounted, so you had to click again to keep typing; the box now keeps a fixed identity and focus.
- **Success lines on the Rules page and the Triage IOC tab are green, and Triage Network flags old shifted captures.** A finished job's result in the Rule manager and the IOC status line use the success green like the other notices (progress and cancels stay muted, failures red). Triage Network shows one Info line on a run recorded before the capture-time fix whose first packet is a whole zone offset (a multiple of 15 min, under 15 h) away from the run's start; old recordings are not changed.
- **Network capture times are no longer hours off.** QEMU stamps a capture with `mktime` of the guest clock's date, so outside a UTC host zone every pcap was shifted by the zone's offset (7 h early at UTC+7: Triage Network, the sample IOCs tab and the Network list showed DNS queries hours before the syscalls). The VM now starts with `TZ=UTC` when its clock is UTC (a local-time clock keeps the host zone), so new captures carry the true time. Captures recorded before this keep their old stamps.
- **Times follow a time zone you can choose.** Settings > Appearance > Time zone: Automatic (detected from `TZ` or `/etc/localtime`, shown as "Automatic (Asia/Jakarta)"), UTC or any system zone. Every time in the app and the human-readable times of reports and the custody record use it, with the zone named in the setting, in the Activity tooltip and as `(UTC+7)` beside times. Recordings, JSON and the IOC exports stay UTC.
- **Success notices are green again.** The Samples list notice, the Download window status and the Disk extraction notice ("Saved", "Sent into the VM", ...) had become the muted Info colour when they moved to the shared notice; they use the theme's success green again, still dismissible, with an Info row in Activity. The Download window's failure lines are now red instead of muted.
- **Offline IP geolocation for TShark: a database check, a managed DB-IP Lite download and a folder setting.** TShark 4.x reads country and AS data only from MaxMind-format `.mmdb` files (the old `GeoIP.dat` files are ignored), so a computer without one showed empty Country and Organization columns. Settings > Network lookup and Tools > App dependencies now say whether TShark has a country (or city) and an AS database and where each is, with a Warning and the fix when one is missing. Library > Analysis tools installs the free DB-IP Lite Country and ASN databases (about 9 MiB, CC BY 4.0, no account; pinned month, SHA-256 checked, Cancel and resume as for every download), and a folder of your own GeoLite2 files can be chosen. They reach Antinomie's TShark runs only (mounted read-only into the TShark sandbox with a path list of its own); your Wireshark settings are not touched. A monthly check (needs "Allow outbound catalog and rule downloads") offers a newer month, whose SHA-256 is recorded since DB-IP publishes no signature. The Organization column now reads "AS150895 EZ TECHNOLOGY COMPANY LIMITED", the lookup works at all (TShark's `-n` had switched it off; Antinomie now adds `-N g`), and the attribution "IP geolocation by DB-IP" is shown next to the Endpoints table and in exported reports. TShark answers a lookup after it has read the packet, so a capture of a few packets used to come back empty; the destinations it missed are looked up again in a short throw-away capture. The full pack can carry the databases.
- **The Build base wizard no longer stalls.** Container engine checks, the builder image list, the toolchain chroot size (a walk of its whole folder on every frame) and the chroot and image removals run on a worker; the Build mode and Summary pages show a spinner while the first answer arrives.
- **Core inspection reads and exports on its worker.** Opening a core reads its saved Ghidra text, and Export functions reads and writes, off the UI thread.
- **The Network capture list loads on a worker.** Switching VM, starting or stopping a capture and Refresh list the recording folders off the UI thread; the list shows a spinner meanwhile and keeps its selection.
- **Per-frame file checks are throttled.** The network toolbar's PATH lookups, the memory dump size and symbol-table checks, and the artifact menu's file test reuse their answer for a second.
- **A failed Open folder or Open file shows a toast.** The desktop opener already ran off the UI thread but only logged a failure to the terminal; it now raises an error toast and Activity row. Creating the rules and plugins folders before opening them also moved off the UI thread.
- **Large folders and slow disks no longer freeze the memory result view.** The Files button looked up the run's files folder on every frame; it is looked up once, when the result loads.
- **The sample window has an IOCs tab: every indicator across all runs of the
  sample.** One row per unique indicator (a file by hash and path): kind, value
  (defanged by default, with a toggle), which runs had it ("run 2, 3", "5 runs",
  "every run (4)"), how it was observed (DNS query, connect, packets, file write,
  executed), first and last seen, the process, and the stored abuse.ch records that
  list it. Kind chips carry counts ("Domains (4)"), "Seen in every run" and "Only
  in some runs" show what changed between run settings, and a search box and
  "Hide private and reserved" / "Hide guest infrastructure" (the base image's own
  traffic and the emulated network's 10.0.2.x) narrow the list. The tab count is
  the Triage one: the total in grey and the matched count in red. The selected row
  is in the shared Details pane with one line per run and "Open in Triage", which
  opens that run on the indicator in Triage > IOC. Per row: Copy, Open in Triage,
  Add note (the indicator reference of the note kinds) and Check online, which is
  off without an abuse.ch key and otherwise opens the run's Triage on the row,
  where the existing lookup with its Cancel and rate limits is. Export writes the
  rows listed (or the selected row) as CSV, JSON, a MISP event or a STIX 2.1
  bundle into the data folder's `sample-reports`, defanged in CSV and JSON on
  request, and notes it in the sample's custody log. The sample report's merged
  indicators carry the same observed, first/last, every-run and dataset columns.
  Runs Triage has not read, and runs read by an older Triage (value only), are
  named in a note. IDS, YARA and Sigma rules match runs, not single
  indicators, and stay in Summary > Detections. Triage's run digests keep the
  sources, times, process and dataset records of each indicator from now on;
  open a run in Triage once to fill them in.
- **Syscall Trace shows record arrays as expandable trees.** Selecting a captured
  array (directory entries of `getdents`/`getdents64`, `cap_data`, `gid_t`,
  `siginfo_t`, `desc_struct`, and now `pollfd`, `sembuf`, control messages of
  `sendmsg`/`recvmsg`, classic BPF filters of `seccomp`/`prctl`/socket options,
  `futex_waitv`, `kexec_segment`, eBPF instructions and the BTF func, line and CO-RE
  relocation records, plain `u32`/`u64` arrays) shows "N entries" with one line per
  record (a dirent's name and type, a pollfd's descriptor and revents, `SCM_RIGHTS`
  descriptors, a BPF instruction as assembly, a seccomp filter with action and
  `seccomp_data` field names), each opening to its fields. Copy row as JSON, Copy all
  as JSON and Save as JSON (to `records/` beside the run's files) carry the records.
  "Decode all captured (M bytes)" reads the field's whole evidence (up to 16 MiB) and
  decodes every record past the 256-byte preview, 100 a page, with "showing X of Y";
  a record the capture cut, or whose length field cannot be right, is named instead
  of dropped. The trace filter reads decoded records (`records contains "name"`, or a
  plain word), and a trace row's menu copies the call's decoded records as JSON. Only
  the x86-64 layouts are decoded for now.
- **A full recording quota no longer ends the evidence.** When a boot has used nine
  tenths of its recording quota, the recorder keeps only the system calls the Triage
  suspicious-activity rules read (and process lifecycle), drops the rest and counts
  what it dropped per call; the network capture keeps running until half of the
  last tenth is left, and the quota itself stays the hard ceiling. `run.json`
  (`reduced`), Triage, Run History and the HTML/PDF report say "Recording quota
  reached at <time>; from then on only suspicious-activity calls were kept, N calls
  dropped" as information, not an error. The report no longer says the recording
  "was still being written" after the run ended; it names what is missing.
- **The Triage IOC tab and its kind tabs show matches beside the total.** The
  total number of indicators is in the muted grey count style and, when any
  indicator matched (IDS, YARA, Sigma, abuse.ch or marked malicious), the
  matched count follows it in alert red ("IOC 24 · 3", tooltip "24 indicators,
  3 matched"); nothing red when nothing matched. It uses the same tab count
  painter as the other Triage tabs.
- **Run states have their own colour.** Run History, the sample window's Runs,
  its Summary, the VM's recent runs and the run window's state colour each state from one palette,
  shared with the run-finished toast and the Triage run-state line: running or
  still recording blue, finished with exit 0 green, another exit neutral,
  stopped grey, time limit blue-grey info, crashed or killed by a signal amber,
  failed to start or interrupted red, recording incomplete amber. The words
  stay, so colour is never the only cue.
- **Keyboard shortcuts: command palette, tab keys and a shortcut list.**
  Ctrl+K opens a command palette that searches every menu action, the open
  tabs, the machines, the recent runs and the library samples; Enter runs the
  highlighted entry through the same code as the menus, Esc (or Ctrl+K again)
  closes it, and an action that cannot run now stays in the list with the
  reason ("Start the selected VM first."). Ctrl+1 to Ctrl+9 show the first nine
  tabs of the work area in the order the tab bar shows them (so they follow a
  tab you dragged), Ctrl+Shift+A and Ctrl+Shift+J show Activity and Jobs (the
  lower bar), Ctrl+D opens the debugger's process picker and, with the picker
  open, attaches the selected process, Ctrl+R still runs a program, Getting
  started's Appearance step has a palette entry, and `?` (or Help > Keyboard shortcuts) lists every shortcut by
  area, including the graph, table, filter and terminal keys. Menus and button
  tooltips show the keys, and a tab's tooltip shows its Ctrl+digit. The menu
  bar has a Search button for the palette. The rule for who owns the keyboard:
  a global shortcut never takes a key from a text field or the terminal (Ctrl+K
  stays with them too: it deletes to the end of the line, in a field and in the
  guest shell); a focused button, table or graph no longer blocks the shortcuts.
  A menu item, its shortcut and its palette entry now share one action list, so
  they cannot disagree.
- **A Jobs window lists everything the app is running.** It sits beside Activity
  (View > Jobs), and a "3 jobs" chip in the status bar opens it. One row per job
  with its kind, target, start time, a ticking elapsed time, progress when
  known, its state, and Open and Stop where the job can be stopped. It covers
  runs (also those still recording after the root exited, with the processes
  alive), VM start (with the slow TCG boot wait) and stop, VM snapshots, memory
  dumps, process cores (also armed ones), static analysis checks per report,
  Triage preparing a recording, detection scans, Check online lookups, base
  downloads, catalog refreshes, base builds, tool installs, rule and dataset
  downloads, MalwareBazaar searches and downloads, Volatility and MemNixFS runs,
  plugin downloads, disk jobs, recording saves, exports and update checks. A
  Finished list keeps the last 20 jobs with how each ended and an Open link
  (until cleared). Closing the window while jobs run asks first and lists them.
  It reads the state the app already keeps and starts no work of its own.
- **Triage names a run's root process from the launch request when the
  recording's launch record cannot name it.** A run whose launch record had no
  readable program path (its end record missing, or its text not read back)
  showed the root as "?". The root now takes the program and arguments the run
  was asked to start, kept as the first name in its exec history; a program the
  recording itself names keeps its own name. A run with Core dump on exit
  recorded the same launch end as one without in every test recording (a tiny
  program, a program that writes, runs and deletes a file, and the demo
  sample), so no host or guest change was needed for the end record itself.
- **Export bytes (as before deletion) for a file the run deleted.** The sample
  window's Files written list and the File reconstruction window in Triage
  rebuild a deleted file from the recorded writes as of the last moment before
  the delete. When every byte is known the file is hashed and compared with the
  SHA-256 the guest took just before the delete: a match is "verified" and the
  export is saved with a `.json` record of the check. With gaps (bytes never
  recorded, or a size not known) the window says "partial: N bytes unknown" and
  saves what is known with a `.mask` file marking the rest. The export is noted
  in the sample's custody log (an Exported entry that names the file, its size,
  its hash and the result).
- **ATT&CK techniques are coloured by tactic.** Each of the 15 ATT&CK v20
  tactics (Defense Evasion is now Stealth and Defense Impairment) has its own
  colour, one palette for dark and one for light (every colour is at least 4.2:1
  against the page, so it holds as an outline and a dot); the badge text keeps
  the theme's own colour. A technique ATT&CK files under several tactics takes
  the colour of the tactic of the row it sits in (the sample window groups by
  tactic), else of its first tactic in kill-chain order, and shows one dot per
  tactic. The tactic names are always in the badge's tooltip and in a folded
  "Tactic colours" legend under the Triage Summary and the sample window's
  ATT&CK section. The HTML and PDF exports of runs and samples get a Tactic
  column (named in text, with the colour as a chip in HTML and a bar in PDF).
  The bundled ATT&CK table now carries each technique's tactics.
- **The MITRE ATT&CK techniques of a run overview open into a list.** The
  Triage Summary shows "MITRE ATT&CK (N)" with its badge row and "Show all N"
  (it replaces "+N in the report"); open, it lists the techniques grouped by
  tactic in kill-chain order, one foldable row each: the technique and its name,
  its tactics, the Triage rules that cited it (with tier and count), the YARA,
  IDS and Sigma rules that cited it, and links that open Suspicious activity
  or the engine's matches in Detection filtered to that technique, and Syscall
  Trace at the first call behind it. Open or closed is remembered, for the
  section and for each technique. The sample window's ATT&CK section has the
  same list ("Show all N"), each technique with what cited it and its runs as
  links into Triage. The list is the one the exports use. Filtering Suspicious
  activity no longer shrinks the Summary's technique list or rewrites the run's
  saved digest with the filtered rows.
- **Static analysis check lines put the notice to the right of the Open
  button.** In the sample window's Static analysis section each line is the
  check's name, its state chip, what it found and the Open button in fixed
  columns, so every Open button sits in one column; why a check timed out, was
  partial or could not run (and the limit it met) is to the right of the
  button, wrapping under itself, in the warning colour (the error colour for a
  check that could not run). The Static analysis tab's Categories card has the
  same order: name, state, rows, the open-in-pane button, then the notice.
- **A toast when a run finishes.** When a run's program tree really ends, one
  toast says "Run 3 finished" with the program, how long it ran and how it
  ended, with Open Triage (and Open sample for a library sample): green for
  exit 0; neutral for another exit code, a stop with Kill, or a `timeout`
  program's time limit (exit 124, or the SIGTERM BusyBox's timeout re-raises); a warning for a crash (SIGSEGV and the
  like) or a kill by a signal. A root that exits while children live on does
  not toast until the run ends. Each toast is also an Activity row. Settings >
  Notifications > "Toast when a run finishes" turns it off (on by default).
- **Summary and finding fixes from the third evaluation run.** The key
  behaviours of a report list each rule once (counts added, highest tier kept)
  instead of once per object ("binary_replace" 44, 2 and 1). A Sigma rule of
  low or informational severity (such as "Program Executions in Suspicious
  Folders", which fires in nearly every run because samples run from /tmp) no
  longer adds techniques to the ATT&CK list, and a Sigma tag for a technique a
  run cannot show (Reconnaissance or Resource Development only, like its
  upstream T1584 and T1587) is dropped; the rule stays in Detection. A failed
  call reads "failed (EACCES)" instead of "failed (-13)", with the number and
  its meaning on hover.
- **Core dump on exit works together with Debug on start.** The host read the
  debugger's 16-byte start record as part of the core's arm reply and failed the
  capture with "invalid acquisition reply length or padding". The core's reply is
  now read on its own; a capture that cannot be armed says so in plain words with
  the size and first bytes of the guest's reply.
- **VM creation survives a loaded host.** The offline credential tool's deadline
  grows with the host's load (up to four times), a timeout starts again once from a
  fresh disk, and a creation that still fails says "VM creation failed" with the
  reason and that the unfinished disk was removed.
- **MemNixFS explains an unvalidated page-table root.** The brute-force line is
  translated: process and file lists from physical memory are reliable; modules,
  mounts and the kernel log may be missing or wrong. The partial result offers
  Run in Volatility 3 for modules (linux.lsmod), mounts (linux.mountinfo) and the
  kernel log (linux.kmsg) in one click. The symbol table saved with a dump (and
  the one `make-kernel-symbols.py` writes for new bases) carries the kernel's real
  release instead of `vmlinux`, so MemNixFS no longer reports a false
  "ISF/dump MISMATCH".
- **A sample's Summary lists the files it wrote.** Files written shows one row per
  file the runs wrote, rewrote, deleted or renamed, with run, state, size and
  SHA-256, filterable and paged for ransomware-sized lists, with Open in Per-file
  history, Export bytes (the file's reconstruction in Triage, where its bytes are
  saved) and Copy SHA-256. The list comes from each run's Triage digest, so a run
  Triage has not read yet is listed as such with a link to open it.
- **A malware family is named from IDS signature messages with a platform or
  language prefix, and forked children are no longer "?".** "ET MALWARE
  Golang/Linux Kaiji Variant Activity" now names Kaiji in the report summary
  (the leading `Golang/Linux` words are skipped). A forked child that never ran
  an exec of its own shows its parent's image with "(fork)" in the Process
  column, also when the parent's name (the launch record) became known after the
  fork was seen.
- **Deleting a system program is a finding.** New rule `evasion.tool_delete`
  (medium, ATT&CK T1070.004): a successful delete of a file in `/bin`, `/sbin`,
  `/usr/bin`, `/usr/sbin`, `/usr/local/bin` or `/usr/local/sbin` that the run did
  not create itself (a botnet removing `wget`, `nc`, `reboot` or `killall`). Package
  managers lower it one tier.
- **The report says when the sample's tree ended at once, and what failed
  last.** When every process of a run exited within 10 s, the report's summary
  and notes say "The sample's process tree ended after N ms (P processes). Last
  failing step: openat /var/run/dbus/x.pid ENOENT", the last refused create,
  write, delete, rename, link, permission change or exec, so a failed install
  step is no longer silent.
- **The report and Triage say why a process was killed by a signal.** A task
  whose exit record is a signal now reads "task exit, killed by SIGKILL" in the
  process tables (it showed the raw `Some(Signaled { signal: 9, .. })`), and the
  report's notes and the Summary's Notes name the processes that ended on a
  signal, whatever the tree's length: "2 of 14 processes ended on a signal
  (SIGKILL): pid 489 "systemd" by SIGKILL at +893 ms; pid 537 by SIGKILL at +884
  ms". Each is explained by what the recording holds: a recorded `kill`, `tkill`,
  `tgkill` or `pidfd_send_signal` call that names it ("sent by pid 12 with kill"),
  a parent-death signal it asked for with `prctl(PR_SET_PDEATHSIG)` whose parent
  had exited, or the run's Stop (the run status says a Stop was requested, and
  that the guest needed SIGKILL). With none of these the note says no Stop was
  requested for the run and that nothing in the recorded calls names the sender,
  and marks the likely sources as inference (the guest kernel, a timer the
  program armed, a process outside the tree): the recording does not carry who
  sent a signal.
- **Tables that stop at a page size say "first N of M", and the page size is a
  setting.** Settings > Advanced > "Triage: rows per table" (default 2,000,
  100 to 100,000) sets how many rows one Triage table and one report table keeps; a
  table with more shows "first 2,000 of 10,897 matched" with the setting named,
  and the report says "First 2,000 of 10,897 rows".
- **The report lists which calls are schema gaps.** A note names each kind of call
  the guest recorded without decoding an argument ("ioctl request 0x5421
  (arg2.ioctl) x200"), so a high "schema gaps" count in the recorder line can be
  traced to the calls behind it. The decoder fixes themselves live in the guest
  kernel patches and are not part of this change.
- **Every dock tab stays reachable at narrow windows.** At 1100 points the tab
  bar clipped "Core dumps" and "Static analysis" with only a thin scroll bar to
  find them. A bar whose tabs do not fit now uses short names ("Trace",
  "History", "Cores", "Static"; the hover text keeps the full name) and tighter
  padding, and when even those do not fit it scrolls the active tab into view
  and shows a tab list button at its right end that opens every tab of the bar.
- **Widening a column scrolls the table sideways instead of squeezing the
  others.** Drag a column divider in a table (Triage Suspicious activity, Files
  and the rest, Network, a sample's Runs, the Detection rules tables, the
  Samples list). The last column gives way first; when it is at its minimum the
  table scrolls horizontally inside its own area, the header and the rows
  together, and the other columns keep their fitted width. Double-click a
  divider, or right-click it and choose Fit columns, to fit the box again. The
  dragged widths are kept per table for the session and no longer stick after
  the window grows.
- **The sample Download window looks the same while it loads.** Asking
  MalwareBazaar used to show only a line of text, then the window jumped taller
  when the results came, again when a download ended and again when the first
  sample was stored, and at 1280x720 it was taller than the screen. Now the
  results area (a skeleton table with the same header and columns while loading)
  and the Downloaded list have fixed heights, the status (asking, a download's
  outcome, the listing) is one line of fixed height, the window keeps its size
  and scrolls inside when the screen is small, and a row's download progress
  stays in its own cell.
- **IOC dataset downloads use the real size, not a stale estimate.** The
  progress said "386 MB of about 312 MB" because each abuse.ch dataset carried a
  fixed size from the day it was written. Update now asks each server for the
  real size first (a HEAD request, Content-Length) and shows "386 of 450 MB", or
  "386 MB downloaded" when the server does not say. The free-space check uses
  the real size and what it unpacks to, and the unpacked-text cap follows it.
  Update all shows the total of the datasets (marked "about" when some sizes are
  estimated) in every progress line, and the button's hover text shows the typical
  total before it starts. The safety caps stay (four times the typical size for
  a download); a dataset over its cap is refused before it is fetched with its
  size and the limit in the message, e.g. "URLhaus payloads is 1.4 GB, over the
  1.2 GB safety limit for this dataset". The typical sizes were refreshed. A
  rule pack's progress says "of" for a pinned download and "of about" only for a
  rolling one.
- **Exported HTML and PDF tables never break a column title inside a word.**
  Wide tables (Processes, Suspicious activity, the Network and Files tabs, a
  sample report's runs, lineage and custody tables) cut titles like "Process" or
  "Count" into "Proc|ess" and "Co|un|t". A title now wraps only at spaces: the
  HTML cannot break it inside a word and keeps the longest word of every title
  as the column's least width, the PDF measures each title in bold and keeps it
  that wide. When the longest words side by side are wider than a page the table
  takes a smaller font a step at a time, and as a last resort is split into
  column groups with its first column repeated. The HTML prints on a landscape
  page.
- **Getting started starts with Appearance.** The new first step has the same
  Theme, Text size and Density controls as Settings > Appearance (one shared
  piece of code, so there is a single set of settings behind both) and applies
  every change at once, so the window shows the result as you choose. Next keeps
  what you picked and marks the step Ready; Skip this step leaves the settings as
  they are. The step list, Back and the Finish summary now have seven steps.
- **The VM Summary has a Snapshots box under Device profile.** It lists the VM's
  snapshots as a compact tree (name, whether it is disk only or disk + memory, when
  it was taken, its size, its notes, and a Current marker on the one the VM runs
  from), with Take snapshot…, Restore… (Resume… for a disk + memory snapshot that
  can resume, plus Restore disk and boot…) and Open Snapshots…. An empty list says
  so and points at Take snapshot. The box uses the Snapshots window's own dialogs
  and rules: what is allowed while the VM runs, a running snapshot operation and
  the compatibility of a checkpoint all come from the same data, and its list is
  refreshed when you select the VM and when it starts or stops.
- **The VM Summary's label column fits its longest name.** "Acceleration" no
  longer breaks into "Acceleratio" and "n" in the Compute card; the column is as
  wide as the widest label (at most half the card).
- **A restart keeps your settings.** The debugger's remembered choices were saved
  in a form the settings file could not read back, so every start fell back to the
  defaults (text size, theme, density and the rest). They are now saved as one
  text and read back, and a size such as 12, 17.5 or 24 survives a restart. Settings
  opens centred in the window instead of against the right edge, its footer note
  gives way to the buttons at large text sizes, and the malware catalog notice
  scrolls so its checkbox and buttons stay on screen.
- **The sample window's Runs list says "Running" for a run whose terminal was
  closed.** A run whose terminal closed while its program (or children) kept
  recording showed "Unknown" in the exit column, unlike Run History, Jobs and the
  Stop button, which count it as going. One `RunState::is_live()` now answers
  "is this run going" for all of them (and `can_stop()` for the Stop buttons).
  Internal: the VM, scan and debugger state colours go through `widgets::Tone`,
  and the terminal's ANSI colours and a few meter and overlay colours moved into
  the theme.

- **One size format and one time format everywhere.** Sizes shown in Disks, the
  IOC dataset downloads, process-core limits, the sample report, retention
  notes, Summary, the base library and the VM dialog all use the same binary
  units and rounding as the rest of the app (`1.9 GiB`, `812.0 MiB`, `0 bytes`).
  The IOC download progress said `386 of 450 MB` for what are MiB and now says
  `386.0 MiB of 450.0 MiB`; the Summary figures `8.00 GiB` now read `8.0 GiB`; the
  sample report's size reads `1234 bytes (1.2 KiB)`. Internal: the duplicate
  size formatters are gone, and the run clock, uptime, age, duration, local
  time of day, UTC date and `now_ms` helpers live in `time_format.rs`.
- **One core date module.** Internal: the five hand-rolled day-count to year/month/day
  conversions in core (GeoIP refresh, MalShare, sample report, IOC feeds, chain
  export) are replaced by `monitor-core/src/date.rs`; every date text is unchanged.

### Build and CI

- **The UI toolkit moves from egui 0.31 to 0.36.** `eframe` and `egui_extras` 0.36,
  `egui_dock` 0.21.1 and `egui-phosphor` 0.14 (egui 0.37 is out, but `egui_dock` does
  not support it yet). The app draws its panels into the window's root `Ui`, the
  dock, popups, tooltips, menus and viewports use the new egui APIs, and text now
  renders with font hinting and the new kerning. The look is kept: round slider
  handles, the 1/12 s animations, the 5 pt window-edge grab strip, no scroll-edge
  fade, and the widths and sizes of text fields and windows. A dock layout saved by
  0.8.1 is converted when it is read, so tabs, splits and detached windows survive
  the upgrade; settings are unchanged. Dragging a table or list with the mouse no
  longer scrolls it (egui keeps that for touch screens); the wheel and the bars still
  do. One duplicate version each of `base64` and `synstructure` leaves the tree.

- **Large source files are split and clippy passes on every crate.** Internal: files
  at or over the module size limit (storage, the Detection tab, the VM dialog, the
  Samples window, the workspace dock and a dozen near it) move pieces into their own
  modules with no change in behaviour, `storage.rs` leaves the size allowlist, the
  blanket dead-code allow on the widget kit is gone with the unused code it hid, and
  `clippy -D warnings` is clean on the libraries, binaries and examples.

- **CI runs the remaining build-script suites and audits the fuzz lock.** The
  publish-base-sources tests and `sync-quilt-view.py --check` join the build-script
  step (the full-pack and refresh-bundle tests were already there), and the audit
  job checks `fuzz/Cargo.lock` against the same reviewed list as the host lock.
  The fuzz crate's lock moves from zip 8.6.0 to 9.2.0, the version the core crate
  already requires (it carried both; 8.6.0 was an old lock entry, flagged by
  Dependabot). `scripts/vm-regress.py` no longer assumes `/mnt/e`: its free-space
  guard defaults to the filesystem of `--out` (5 GB) and `VM_REGRESS_MIN_FREE`
  (comma-separated PATH:GB, empty for none) changes the default.
  diskcache 5.6.3 stays: pySigma requires it (<6) and no fixed version exists;
  see docs/dependency-advisories.md.

### Internal

- **Long functions split.** The guest command transport, the backend command
  dispatcher, the static analysis section worker and the sample report layout
  are divided into named steps. The backend worker loop, the report document
  layout, the YARA scan, the Triage archive and capture scans, the file index,
  and the large screens (dialogs, panels, run history, the sample list, the
  syscall trace and its inspector, network packets, the core, memory and
  static analysis views, the New VM dialog, the jobs list) are split the same
  way, into one function per phase, section or row. No behaviour changed. The
  module size check now also lists functions over 300 lines as a warning; the
  one left is the syscall rule table.
- **One table implementation and one inline-notice API.** The Triage tables and
  the list-table styles live in `widgets/fit_table.rs`; status lines that were
  drawn by hand (IOC, Detection journal, Rules, Samples, Disk extraction) call
  `activity::{info,warning,error,status}`, so they get the same look, dismiss
  button and Activity row. Internal; the tables keep their columns, sorting and
  widths.

## 0.8.1 — 2026-11-03

Antinomie 0.8.1 is a fix release for the 0.8.0 line; it runs the same revision-20
bases. A VM on a host without KVM now starts with TCG and a warning instead of
timing out, and every start wait scales for slow TCG boots. Cancelled downloads
resume when they can. Notes reach packets, dumps, cores and static rows and can be
edited and deleted wherever they are shown. Triage names tasks by PID and TID,
counts what its filters hide, shows failed attempts by default and the run's state
beside the network route, and keeps other views' notes out of its Summary. Every
table now fits its window, and many smaller fixes from testing 0.8.0 follow.
Details follow.

### Host

- **Triage > IOC shows the selected indicator in the Details window, not in a
  panel beside the table.** The entries table now takes the full width. Click a
  row and the shared Details pane (the same place, follow-the-selection and
  pop-out as the other Triage tabs) shows its value, kind, sources, first and
  last seen, process, dataset records, Check online, Mark as false positive,
  Copy and the jump to the evidence in the trace or the packets.
- **Every table fits the box it is in.** One shared helper (`fit_table`) plans
  the columns from the width the table really has: fixed columns keep their
  width only while the table fits, every column shrinks in proportion (no 40 %
  floor), the text column takes the rest, cells are cut with an ellipsis and the
  whole text on hover, and only when even the minimums do not fit does the table
  scroll sideways inside its own area. The background is painted from the
  table's real rect, so rows no longer pass it (the Triage Suspicious activity
  table, the sample window, the Detection rules window and the rest).
- **Long sample names are cut in the sample window's header and its tables.**
  The name is cut to the space the buttons leave, the whole name on hover.
- **The sample window's Identity shows the hashes and the archive in its first
  box.** The SHA-256, SHA-1, MD5, TLSH and Archive rows share the label column of
  Type, Added and Source, a long value is cut in the middle
  ("7dd32a00…c1e1a3") with the whole value on hover and a copy button per row,
  and the Identity box and Aliases take the whole width.
- **The Download window's tables show about four rows, then scroll,** with the
  same width, a background that follows the table's height, and a shorter
  window.
- **Static analysis category titles are no longer squeezed.** The Categories
  card sizes its title column to the longest title (Identification, Regex
  matches) and cuts it with an ellipsis only when the pane is narrower; a short
  window scrolls the whole report view instead of leaving its content a few rows.
- **The sample window's Static analysis section says what each check found,**
  one wrapped line per check ("Identification: ELF 64-bit ..., statically linked,
  stripped"), the reason in plain words when a check is not complete, and an
  Open button per check; the Interesting strings caption is gone and the ATT&CK
  tactic column keeps one width so the technique tags start at one x.
- **Edit and Delete work again on a note card,** and right-click anywhere on the
  card offers Edit, Delete... and Copy text.
- **An export dialog's finished state stays inside its window.** The written
  files show against their common folder (Copy path, Open folder), in a list of
  at most four rows that scrolls, with names cut in the middle and the whole
  path on hover; a long sample name no longer sets the title's width.
- **The toolbar never covers the VM name.** When the window is narrow, the
  buttons that do not fit move into a ">" menu, last first (Dump core, Dump
  memory, Capture network, Capture all, Snapshots, Kill, Run program, Stop,
  Start stay longest), and the VM name is cut with an ellipsis.

- **Triage names a task "PID 145 · TID 150", never "PID 145 cookie 900".** The
  Process tree, the file tables, the findings and the Trace read the process and
  the thread; the main thread says "(main)". The recording's own task id stays
  in the task's details ("Recording task id"). A process with many thread tasks
  (four or more) folds them into "+10 threads" on its row, and a "Show threads
  (N)" chip lists them.
- **Triage rebuilds changed files from runs of bytes, with limits you can
  raise.** A file's rebuilt contents were kept byte by byte and cut at 128 KiB
  (4 MiB per run), so a dropped 450 KB program was cut short. They are now kept
  as runs, with defaults of 16 MiB per file and 256 MiB per run, set in Settings >
  Analysis tools > Rebuilt file bytes. When a limit is met the file says which one
  (per file or per run), how much was kept, and has buttons to the setting and to
  the call's syscall evidence. A call whose captured buffer held fewer bytes than
  it moved says so with both byte counts.
- **A run Triage already read is not shown as "preparing" again.** A timer read
  of a recording that did not change keeps the tab counts and views as they are
  (they flashed "…" at every refresh); a finished run is still indexed once. A
  run whose program has exited but whose children are alive says "Still
  recording: 10 processes alive".
- **Triage Files chips carry their own counts.** "Hide stdio (118)" and "Hide
  library (210)" show what each hides, the total sits beside them ("12 of 340
  rows shown", with Show all), and a tab with the chips on reads "12 / 340".
- **Triage says what state the run is in beside the Network route.** "Network
  route: None (VM isolated network) · Running · 12:34 elapsed", "Finished after
  5:02 (exit 0)", "Stopped by the user after 3:10", "Failed to start: …" or "Still
  recording: N processes alive", in the Triage header and in the Summary. The
  elapsed time ticks every second without reading the recording again.
- **The whole row of a sample, a run or an output file opens it.** A click on
  the text of any cell in the Samples list, the sample window's Runs and Output
  files tables now opens the row, not only a click on empty space.
- **Notes can be edited and deleted wherever they are shown.** The Latest note
  on the Summary and each card in the Notes tab have pencil and trash buttons
  (Delete still asks first), a right-click menu with Edit, Delete and Copy
  text, and an "edited <time>" label; the Samples list menu has Notes…. Custody
  entries are unchanged.
- **Interesting strings are the 100 longest strings.** The Summary table lists
  them with their length and offset and scrolls inside its own area. URLs,
  addresses, domains, paths and keys are in Regex matches only, which is now one
  scrolling table with category chips and counts instead of a ten-row pager.
- **The live malware warning in the Samples download window stays.** It has no
  close button, is not an Activity message and shows every time the window opens.
- **A VM starts with TCG on a host without KVM, and a slow TCG boot is waited
  for.** A VM set to Default acceleration used to refuse to start when
  `/dev/kvm` could not be opened; it now runs with TCG software emulation and
  says so once per start, in a Warning toast and in Activity: "KVM is not
  available on this host (cannot open /dev/kvm: ...); <VM> runs with TCG
  software emulation, so expect much slower performance." A VM set to KVM still
  refuses, with the reason, and the message and the App dependencies window
  offer "Use TCG for this VM" and "Use TCG when KVM is unavailable" (Tools >
  Settings > Advanced, for every VM set to KVM). Missing KVM access is a Warning
  in the App dependencies window and in `--check-dependencies` (exit code 0),
  not "some runtime requirements are missing"; a missing QEMU stays an error.
  The VM settings dialog warns under Acceleration. The accelerator a boot used
  (`kvm`, `tcg`, or `tcg (KVM unavailable)`) is in the run's environment record
  (run.json, report), the snapshot identity and the builder VM pick it the same
  way, and the builder VM's limits stretch under TCG.
- **A TCG VM no longer fails with "transport: Connection timed out".** The host
  gave the guest 20 s to publish its transport, a KVM-speed limit: a BusyBox VM
  with TCG took 15 to 22 s on an idle 8 vCPU host and longer under load, so
  starts failed at 21 s and QEMU was stopped. Every start wait (the guest
  connection, the guest health check, QMP replies, the snapshot stream and
  migration, the resume handshake) is now scaled for the accelerator (a TCG
  multiplier, 10 by default) and for the host load, a read-only QMP question is
  asked again before QEMU is taken for dead, and the wait says "Waiting for a
  slow TCG boot: the guest has not connected after N s (waiting up to M s)" in
  the status instead of failing. A timeout says why (TCG is 10 to 50 times
  slower, and host load slows it more) and what to do (raise the TCG multiplier,
  reduce the load, or use KVM). Tools > Settings > Advanced > VM start and guest
  connection timeouts sets the guest connection wait and the multiplier. Stop
  cancels the wait, and a QEMU that exits is reported at once.

- **Cancelled downloads resume when they can and restart when they cannot.**
  The partial file of a base, an analysis tool, the kernel source or the
  builder's Debian cloud image stays in the download's own folder (never where
  the app looks for installed items) with a small record of what it is. The next
  download resumes it (`Range` with `If-Range`) when the pinned hash and size
  still match, the server sends the same ETag or Last-Modified and answers with
  206; otherwise it starts again from zero without an error, and says why
  ("Resuming Ghidra from 22.0 MiB", "Starting Debian 13 again: the server
  changed it or cannot resume it"). A resumed file is still checked against its
  SHA-256 or SHA-512; when that fails it is deleted and fetched once more from
  zero. Cancel stays Information and says how much was kept. A cancelled base
  build is not resumed (a build step is not a download): it starts from the
  beginning. Partials are deleted when the download finishes, when the base or
  tool is removed, and when the catalog no longer lists the base. Plugin
  and rule-pack downloads are small and always start again.

- **Notes on the remaining surfaces.** "Add note…" now exists on the rows of
  Network packets and captures, memory dumps, disk dumps, imported and manual
  process cores, and Static analysis rows. Each has its own note kind with a
  chip that opens its target (the VM's panel with the packet, capture, dump or
  core selected; the report's section filtered to the row). Old notes load
  unchanged and the custody log and its exports name each target.

- **The build says which commit it was made from.** `build.rs` stamps a short
  commit (`git rev-parse HEAD` in a checkout, `-dirty` after tracked changes;
  else `source_commit` of a BUILD-INFO.json at the repository root; else
  `unknown`; `ANTINOMIE_BUILD_COMMIT` overrides). `--version` prints
  `antinomie 0.8.1 (built from abc12345)` and the base refusal says "this
  build is Antinomie 0.8.1 (built from abc12345)". No network; the same source
  without .git gives the same text.

- **A failure is an Error, and one condition has one level.** About fifty
  messages that said a read, a save, a copy or an update had failed were Warnings;
  they are Errors now, with the reason and what to do: the clipboard that was
  not typed, a refused or non-UTF-8 upload or explorer path, a disk dump that
  never finished or whose image is gone, the partition table, a MalShare day
  lookup, the core dump list, the saved-recording index, the event journal, the
  properties, the detection scan and its evidence preview, the IOC datasets and
  their updates, the capture, a frame, TShark's packet details and field list, the
  process tree, a terminal history, the debugger's code and memory windows, a
  copy over 8 MiB, the route settings file, and a builder image or chroot that
  could not be removed. A run that failed to start or whose saving stopped is the
  same Error in the Trace, History, Details and Triage as in the status bar, and a
  capture's saving error is an Error while "incomplete" stays a Warning. The same
  archive read error, final terminal screen and resource sampling note now have
  one level wherever they appear. A filter box or a form that does not parse yet
  (the run filter, the listing filter, the analysis selection) is typing feedback
  in every place: coloured text with no Activity row and no toast.
- **Plain values are not drawn as warnings.** The warning colour is kept for
  sentences about something wrong. Starting and Stopping, a changed diff entry, a
  changed signal, the stack registers, jump mnemonics and numeric literals in the
  code listing, ARP, Metadata values such as "no" or "absent", imports, an unusual
  string encoding, the invalid UTF-8 stand-in, raw terminal escape marks, "not
  set" and "Not installed" for optional keys and tools, "No rules enabled", the
  file graph's writes, the reconnect marker, "Waiting for guest shutdown", the
  RAM-dump pause text and "Controlled by gdb" use the neutral accent
  (`theme::neutral_accent()`). The "Saving stopped" badge and a core with an issue
  use the error colour.

- **Failed attempts are shown by default, in every Files tab.** The chip was off
  while Opened and Read listed their failed rows anyway, so it looked off and
  hid nothing there. It is on by default, applies to Opened, Read, Changed files
  and the operation tabs, and it reads "Failed attempts (3)" with the failed calls of the open
  tab (failed opens on Opened, failed reads on Read, ...); the tooltip gives the
  total for the run and the count per tab. Failed attempts still never count as changes.
- **Triage Summary keeps other views' notes out.** The Detection scan notes
  ("No packets were captured", why an engine is unavailable) and the network note
  no longer repeat on the Summary; one line, "Detection: 1 note needs attention",
  opens the Detection view when a scan is partial or failed. In the IDS view,
  the HOME_NET fallback and "N rules loaded" are Information, and "the IDS reads
  the VM-wide capture, so its matches are not attributed to a process" is said
  once instead of in every scan.

### Fixed

- **Library > Analysis tools shows where Antinomie's copy of a tool is
  relative to the data folder** (`tools/capa/capa`), with the full path on
  hover, like the run views.
- **The custody log's "Run started" line names the base** of a run on a base
  that has no chosen name: the catalog label, else the base identity's first
  eight characters. It used to read "base , device profile ...".
- **Export report (sample) shows its default folder relative to the data
  folder** (`sample-reports`) with the full path on hover. A folder typed
  without a leading `/` is inside the data folder; an absolute one is used as
  typed.
- **The App dependencies window fits the main window.** Its list scrolls
  inside the window, so the title bar and the close button stay on screen at
  1280x820. A probe that only ran out of time ("could not check QEMU GTK
  support: QEMU probe timed out") no longer opens the window by itself; the
  status bar says what was not checked and Check again settles it. The GTK
  probe retries once with 10 seconds before reporting a timeout.
- **A base label that already ends in " — Antinomie X.Y.Z" shows the version
  once** ("BusyBox · Antinomie 0.8.0", not "BusyBox — Antinomie 0.8.0 ·
  Antinomie 0.8.0").
- **`scripts/publish-base-sources.py` computes the identity of a base with
  UEFI files** (`uefi-root.tar.xz`, `uefi-layout.json`) as the app does, and
  `scripts/build-monitor-image.py` `bundle_identity` accepts them. A test
  vector (`tests/monitor/fixtures/base-identity-uefi.json`) is checked by both
  the Python and the Rust tests.
- **A fresh install no longer says "legacy migration destination is not
  empty".** An old data folder that holds only the window state eframe saves
  (`app.ron`) is not old data. Installing a tool goes through the same
  migration as the app start, and when the message is real it says what to
  do.
- **A backend that did not start shows an error screen** with the reason,
  what to do, Retry and Quit, instead of a window whose buttons do nothing.
- **Refresh catalog gives feedback.** The status line changes from
  "refreshing base catalog" to "base catalog updated: N bases" or "catalog
  refresh failed: ...", the spinner stays long enough to see, and
  "Updated hh:mm" shows next to the button (Getting started and Download
  base).
- **Getting started > First VM has the Device profile dropdown** of the New
  VM dialog (default still Realistic desktop) with a one-line description,
  the base's fallback warning and Details… for the full window, instead of
  one checkbox.

## 0.8.0 — 2026-11-02

Antinomie 0.8.0 is the first release since 0.7.1. It moves to guest contract
revision 20 with rebuilt bases: Debian 13 Minimal and the Debian 13 desktop (GNOME)
are assembled from pinned Debian userland, and BusyBox takes its programs from
Debian's packages. Live network routes gain an egress abuse filter, and a run that
fails to start now says why. Static analysis adds Ghidra disassembly and accepts
programs up to 128 MiB. A run's Triage can be exported as a report in HTML, PDF,
JSON, MISP or STIX 2.1, with an optional evidence bundle, and a sample's runs as a
sample report. Triage counts the work of multi-threaded programs per process, so
ransomware that spreads its writes over worker threads is caught. Device profiles
now cover whole machines, including cloud VPS identities, and the recorder keeps up
with busy programs and says how much telemetry a run lost. The interface had two
more rounds of fixes, run views and reports no longer show host paths, and several
security advisories in bundled libraries are closed. Details follow.

### Host

- **Fixed: every download can be cancelled, and a cancel changes nothing.**
  Cancel buttons were missing for the base catalog refresh, the Memory tab's
  Volatility 3 and MemNixFS installs, MalwareBazaar and MalShare searches and
  sample downloads, the online IOC check, the API key test and the update check;
  those calls also could not be stopped (they blocked up to five minutes). All
  downloads now share one mechanism: the wait loop watches a cancel flag every
  50 ms, so a stalled, trickling or vanished server cannot delay it, and the
  `curl` or `pip` child is killed with its whole process group. A cancelled
  download removes its partial files and temporary folders (the base staging
  folder, tool downloads, plugin staging, the kernel source and builder image
  parts, a cancelled build's log), keeps an installed tool or base as it was and
  leaves catalogs unchanged. The message is Information ("Cancelled"), not an
  error toast or an Activity error. Quitting the app cancels every transfer,
  waits for the clean-up and kills any child still running. Build steps run in
  their own process group, so cancelling a native build also stops the compilers
  and downloads it started. Base downloads no longer resume after a cancel
  (they still resume after a network failure).

- **UI round 6: the sample window, Triage and the install pages fixed after
  the RC1 walk.** Install, download and catalog sizes show only the rounded unit
  (12.4 MiB). Activity rows show the date with the time. Centred dialogs such as
  Getting started stay centred while the main window settles. The Run program
  window no longer widens itself at fractional text sizes (egui columns fed a
  rounding overshoot back into the resizable window). Every chip, tag and state
  pill is drawn by one painter: text centred, fixed height, never squeezed to one
  character, and a row of them wraps whole chips (the Triage Summary ATT&CK row
  and the sample window's technique rows, which ran off the window and pushed
  the Summary tables' right columns out of view). The All samples back link uses
  the normal link colour. Evasion check summaries drop the "would show a VM"
  wording; each check's run line keeps its evidence calls and offers Show in
  Syscall Trace. The sample window's Interesting strings and Regex matches page
  10 rows at a time with links to the full views; its Static analysis lines carry
  a state chip in the state's colour (Partial is no longer green); Identity no
  longer leaves half its box empty; the Edit tags window fits the screen; the
  Artifacts section says where the files a sample wrote are. The lineage graph
  wraps a level with many nodes into side-by-side columns and grows its viewport,
  so a sample that wrote dozens of files is a readable graph instead of a strip
  at 20%. An IDS scan with no packets and a Sigma scan that evaluated nothing say
  why (no packets captured, Suricata or pySigma missing) instead of a bare
  Complete or Unavailable. A string kept only at its start leaves Strings and the
  run Complete with an Info note. Triage > Detection shows saved results at once
  when a run is shown again instead of the preparing bar, its rule text is in a
  taller resizable monospace box with wrap, Copy and Open in a window, and the
  rules window's pack table no longer jitters sideways. File reconstruction
  drops the "What this call changed" panel and labels positions "Offset 0x…";
  Per-file history keeps its filters in one collapsible section with a "Name:
  Last name / First name" choice for renamed files.

- **Fewer warnings: setup hints, optional features and confirmations are now
  information.** 60 messages that described a normal state (Stop the VM to
  change these, Install a base image first, an optional tool or dataset that is
  not set up, an update is available, a list or search limit note, a refused
  drop, a stale Kill or Upload press) are now Info: muted text, an Info row in
  Activity, no toast and no count in the Activity badge. Filter and form typing
  errors (12 places: table, record, display, trace, IOC, memory, core and
  listing filters, the debugger input and the VM form) stay as red or orange
  text on the field and no longer write an Activity row for every keystroke. The
  first-use malware dialog lists its points as plain text, and the "Live malware"
  reminder in the Samples window is shown once per session instead of every time
  the window opens. A clicked register or offset that leads nowhere says so in
  the status line only.
- **Fixed: a finished run no longer says its analysis was interrupted while it is
  still running.** When a program ended, the Run History and the Samples page
  read the run back from disk and settled any analysis not yet finished as
  "interrupted before it finished: the app or the VM ended first", although this
  session's job queue was still working on it (capa and FLOSS can take minutes
  after a short program). The label was only shown, never saved, and the
  results arrived afterwards, but it was wrong. A run is now settled that way
  only when no job queue of this app session holds its analysis, which is the
  case after a restart or a VM that ended first. Triage likewise no longer
  calls a recording "marked incomplete" (and Sigma "Partial") while the VM is
  still saving it: the recording's totals are written when the VM stops, so the
  index says "still being saved" and reads the run again by itself once they are
  there.

- **Fixed: the Tor route's own tor starts again.** The generated torrc wrote
  `Log notice file "<path>"`; tor only unquotes a value quoted as a whole, so
  it looked for a file whose name contained the quote characters and every run
  on the Tor route stopped with "tor stopped before it was ready (exit status:
  1)". The torrc now says `Log notice stdout` and tor's stdout is the private
  `tor.log` (mode 0600), which is still read for the bootstrap progress; data
  folders with spaces work. Tested with a real tor (`ANTINOMIE_TEST_TOR` or
  `tor` on PATH) under `DisableNetwork 1`.

- **Fixed: run views and reports no longer show host paths.** Per-file history
  said "unavailable: /home/<user>/.../disk.qcow2 changed after the run started";
  it now says "the VM's disk changed after the run started". Disk-layer errors,
  network index warnings and the evidence bundle's skipped list name files, not
  host folders, and the sample report's run table and JSON give each run's
  folder and report relative to the data directory.
- **Fixed: multi-threaded ransomware is triaged as one process.** The stateful
  Triage rules (mass rewrite, mass delete, ransom rewrite and note, file search,
  process and user enumeration, scans, kill lists, fork bombs, uploads, floods,
  dirty pipe, write-then-execute) kept their counters per thread, so a program
  that shares twelve renames over five worker threads never reached any
  threshold; they now count per process (thread group). Worker threads are named
  by their process in the file tables, findings and the report (they showed as
  "Unknown (pid / tid)"). The Summary's ATT&CK row and the export now come from
  one function, the union of the behaviour rules' and the detection engines'
  techniques, so they cannot disagree.

- **Security: zip 9.2, wasmtime 48.0.8 and one check for every untrusted zip.**
  The zip crate moves from 8.6.0 to 9.2.0, which fixes RUSTSEC-2026-0367 to
  RUSTSEC-2026-0369 (SUID/SGID bits kept on extraction, symlink targets outside the
  destination, Unix permissions applied unsafely) and the parser-differential,
  path-escape, symlink-target, legacy-decoder and AES-HMAC advisories fixed in 9.0.x.
  Every zip the app reads from outside (sample library, sealed specimens, report
  bundles, tool and rule downloads, abuse.ch and IOC feeds) is now opened through one
  function that refuses duplicate entry names, local headers that disagree with the
  central directory, overlapping entries and local headers the directory does not
  list, so every reader sees the same single entry per name. Unpacking a tool zip no
  longer creates symlink entries and never writes through an existing symlink.
  YARA-X moves from 1.21.0 to 1.22.1, which brings wasmtime 48.0.8 and fixes
  RUSTSEC-2026-0222, 0269, 0316, 0327, 0359, 0362, 0363, 0379 and 0424. The Sigma
  tool's pip lock script now pins certifi 2026.10.18, as the lock file already did.
  diskcache 5.6.3 (PYSEC-2026-2447, no fix) is a pySigma dependency that the
  scanner never calls; see the task record for the assessment.

- **Base builds started from the app find every file the kernel script reads.**
  The app's build kit lacked the kernel configuration fragments, the BTF and ABI
  checks and Debian's module-signing certificate, so a base build started from the
  app (native, container or QEMU builder) stopped at the kernel stage. A test now
  reads the kit's scripts and fails when one names a file the kit does not carry.

- **Fixed: TShark could not read captures on Ubuntu 25.10 and later.** Ubuntu's
  enforced AppArmor profile for TShark allows only `/tmp`, `/var/tmp` and
  Wireshark's own files, so every read of a capture in the data directory was
  refused: Triage had no network index (no DNS or HTTP events, silent Sigma DNS
  and HTTP rules) and display filters failed. TShark now runs in its sandbox with
  each capture bound read-only under the sandbox's private `/tmp`, and a refusal
  that still happens names the AppArmor profile instead of the raw message.

- **UI round 5: the 0.8.0 review list.** Notes can now point at one entry of a
  run's Syscall Trace (the run and the record's event sequence), beside the run as a
  whole; right-click a Syscall Trace row, a Triage process, evidence or IOC row, a
  run in Run History or a core, and choose Add note…, and clicking the note's chip
  opens the trace at that record. The note picker groups what a note can be about,
  with icons, a hover and selection state. Existing notes load unchanged, and
  the custody log and its exports name the run and the sequence. Right-click menus
  of tables are one short menu on the clicked cell (filter on its value, add it with
  AND or OR, exclude it, copy, add a note) instead of a list of every column, and no
  menu grows past the screen. A file with no hash now says why (too large, queue
  full, changed while reading, only read, still open at run end, empty file), and
  files a run only read or ran are hashed from its starting disk after the run
  (marked "hashed from the starting disk"; at most 200 files, 64 MiB each, 1 GiB in
  all, off the UI thread). Smaller fixes: the Identity boxes of a sample fit their
  content; rule-source and dataset details no longer touch their table; the regex
  Add button stays in the window; the Strings and Regex tables of the Samples window
  use the standard rows; the Static analysis lines have a real Open button; neutral
  chips and every placeholder read in light and dark; the sample name and its back
  link have their own colour; Samples section titles are a step larger.

- **A launch's first telemetry stays with its run.** Telemetry a program sends
  before the host has taken in its launch reply is held for the run; it used to
  be dropped once it was 5 s old, so a host held up between the reply and the
  run's start (a slow disk) lost the run's start, the root's execve among it
  (1,537 packets of a Gafgyt run in the 2026-11 evaluation). Nothing that arrives
  while a launch waits for its reply ages out now, and the run takes all of its
  own packets however late. A library sample's custody-log entries, and the
  record that a sample was sent into a VM, are written by a background thread,
  so their disk sync no longer pauses the telemetry drain.

- **Each run says how much of its telemetry was lost.** The host counts the
  packets a run's tasks numbered that never arrived (a lower bound, from the
  guest's per-task packet numbers) and keeps the count in the run's final
  manifest (`telemetry_loss`). A run that lost some shows a warning over its
  trace, Triage and Run History details, and its report says so first in the
  run overview.

- **Faster whole-run export.** Reading a recording's packets and checking its
  archived fields against them takes far fewer filesystem calls (the archive
  root is resolved once instead of for every field chunk, packets are read
  through one window): Export report on a 158,000-call run takes 17 to 19 s
  instead of 43 to 46 s once the run's index is built (B16 of the 2026-11
  evaluation).

- **Sources for the downloadable bases.** The `sources/` folder of the base
  bucket now holds the corresponding source of every listed base: the Debian
  `linux` source package, the Antinomie patch series and exact kernel
  configuration, the BusyBox, glibc and e2fsprogs source packages, and a package
  inventory with snapshot.debian.org links for each Debian base. New builds record
  the kernel and BusyBox source identity in `bundle.json`, and
  `scripts/publish-base-sources.py` assembles the sources for an upload.

- **Route helpers die with the app; the Samples warning covers routes.** The
  wireproxy and tor a route starts now end when Antinomie is killed (a death
  signal and a process group), and the next start ends any left over by their
  recorded process id and start time, never by name. The Samples window's warning
  now also covers a Routed VM whose default route can reach the Internet (Internet,
  Tor, VPN, SOCKS5) and names that route.

- **Egress abuse filter on live routes.** The Internet, Tor, VPN and SOCKS5 routes
  refuse outbound mail ports (25, 26, 465, 587, 2525), cap new connections per
  second (30), open connections (200) and new destinations per minute (100, a scan
  guard), limit ICMP echo replies, and can stop forwarding after a time limit (off by
  default). It is on by default and set under Settings > Network routes (a limit of 0
  turns that limit off). What it refused is counted by reason, and by port for mail, in
  the run's network route line and report ("Egress filter blocked 3 connections to
  port 25"). It runs in the host's gateway: nothing changes in the guest.

- **Routed runs with a network capture start.** A run with Capture network on a
  Routed VM, on any route, failed to start and was listed as Unknown; the toolbar
  capture failed the same way. Both now work. A run that cannot start (a capture on
  a VM without a network card, a route the network cannot carry or that is not set
  up) is refused before it exists, and the Run form says what to change with a
  VM settings… or Open Network routes settings button.

- **Routes across snapshots and reconnects; a route whose program stops.** A run
  restored from a snapshot gets its route back (the restored VM's traffic was
  dropped); after a transport reconnect the route is released when the run ends.
  When the VPN route's wireproxy or the Tor route's tor stops during a run, the
  run's record and a notice say so, the VM's traffic is dropped from then on, and
  no other run joins the dead route.

- **Runs that never ran say so.** Run History shows Failed to start, Launch
  unconfirmed or Interrupted instead of Unknown, with the reason in the tooltip,
  and a run that never ran can be deleted from its menu. Older Unknown entries of
  launches that never started read as Failed to start.

- **Upload and Run starts at once.** The guest answered an upload's commit
  before it had closed the file, so a launch right after it could fail with
  "Text file busy". The guest now closes the file before it answers (needs a
  base built from this release).

- **Programs up to 128 MiB are analysed.** Static analysis takes a specimen of
  up to 128 MiB (was 64 MiB) from a base of this release (contract revision 19),
  and at most a quarter of the VM's RAM, since the guest keeps one copy of it in
  memory. Uploading a program larger than a quarter of the VM's RAM is refused
  before anything is sent, saying how much RAM the VM needs; a larger file
  already in the guest runs without static analysis and says why.

- **Sample notes and Delete run.** Notes with links to runs, processes,
  artifacts and custody entries, a Notes tab, Latest note and Add note… menus;
  every note change is in the custody log. Delete run asks which of the run's
  files to keep (kept files move into Samples) and refuses a live run. The
  library's database layout moves to version 2; older versions refuse it.

- **Sample page layout.** The name and its actions sit under All samples;
  Family comes from the download signature, a YARA family or the category
  tags; Output files is Artifacts with a short SHA-256 and right-click menus;
  the lineage graph has node menus and edge tooltips; the Runs tab shows the
  selected run in Details; a broken custody log is marked in the list.

- **Analysis timeouts and limits.** A section that runs out of time says
  Timeout, as a warning, with Run again with 2× time; the time limit is set in
  Run program and Settings. Structures lists every row in its listing. Status
  lines say which limit was hit; capa failures show capa's error; capa keeps its
  compiled rules between runs. Run History shows each run's short id.

- **Static-analysis size limits are settings.** Settings › Analysis tools has a
  field for each bound a warning can name: rows a check keeps in its report
  (256 to 8,192, default 2,048; also the signatures binwalk lists), the size of
  one listing (16 to 512 MiB, default 64), the text kept per value (1,024 to
  16,384 bytes, default 4,096), the output read from a local tool (1 to 16 MiB;
  binwalk reads four times that), the output read from capa and FLOSS (32 to 256
  MiB), the strings FLOSS may list (10,000 to 500,000) and the largest file FLOSS
  is given (16 to 64 MiB). The Analysis settings button of a warning opens
  Settings at its field; a bound no setting raises (a file that disagrees with
  itself, the unpacking depth) has no button. A change applies to analyses
  started afterwards and to checks run again from a tab; a report records the
  limits it was made with, and the report may grow with the row setting.

- **Reports credit the rules that matched.** Every export format (HTML, PDF,
  JSON, MISP, STIX) names each matching detection rule's author, licence, source
  pack and own reference link, as the rules' licences ask. A machine profile
  shows the same no-affiliation note a cloud profile did.

- **Triage notes and clearer warnings.** Run and device-profile notes sit in a
  Notes section at the bottom of the Triage summary; the Internet route note is
  no longer a warning. Written-content, Sigma coverage, Guest network (formerly
  NAT network) and cloud metadata messages say what happened and what to do.

- **Larger text.** The default text size is 18 (it was 16); a saved size of
  16 moves to 18 once, any other size stays. Sub-header titles are two points
  bigger and headings six, the graph, refresh and strip labels follow the text
  size, and the Run History buttons, the Settings page list and the Static
  analysis overview make room for it instead of being cut off.

- **Windows say "name value" the same way.** UI performance lists its facts in
  one aligned table with a subtitle under each title, and the lines that said
  "x: y" in Summary and Triage use the same muted name and plain value.

- **Every limit says where to change it.** A static analysis check that met a
  bound (rows, size, text or unreadable parts) shows its warning with a button to
  Settings, which now lists the bounds that no setting changes; Disks limits and
  Triage route problems have their buttons too. A refresh that found part of a
  run missing says what is missing instead of "partial evidence". A process
  picker action that is not available says why.

- **Cloud notes.** A VM on NAT running on a cloud instance gets a note that the
  sample can reach the provider's real metadata service; the Run program window
  says when the simulated metadata service answers beside the route.

- **Error toasts time out.** An error toast now shows a countdown bar and leaves
  after 30 seconds like the others; hovering it still pauses the timer, and the
  error stays in Activity.

- **abuse.ch downloads without a key.** abuse.ch now requires an Auth-Key for the
  URLhaus and ThreatFox packs; a refused download says so plainly (HTTP 401),
  points to Tools > API keys and offers a button for it.

- **Stealth profiles are now device profiles.** The feature keeps its settings
  and saved data under a new name throughout the app. A question-mark icon next
  to the VM configuration's Device profile row explains what it is for, and the
  note about what bases built by 0.7.0 hide is gone from the profile window.

- **VM configuration.** The Machine, Display, Storage and Network sections have
  more room between them. Disconnected and NAT no longer raise warnings: NAT
  applies at once like Isolated and keeps a yellow note saying the guest can
  reach the host network and the Internet. Choosing Cloud VPS no longer widens
  the window.

- **Check for updates.** Help › Check for updates asks GitHub for the latest
  release only when you choose it, says whether a newer version exists and links
  to its release page. It downloads nothing and follows the outbound download
  setting. Help also links to the online documentation.

- **Window frame and menus.** The title bar shows "Antinomie" without the
  version, the FPS counter sits beside the window buttons, floating windows have
  bold titles, every Tools menu entry has an icon, and About shows the tagline
  "A local, kernel-level Linux malware analysis sandbox and workspace."

- **One guidance panel for windows with nothing selected.** Static analysis
  and its sections, Triage, Core dump and Details show the same panel when no
  run or core is selected.

- **Tools windows.** Tools Antinomie installed show where they were saved. App
  dependencies lists Tor and wireproxy with install controls and a button to the
  Network routes settings, and their install buttons show only the rounded size.
  The base images table has balanced columns, API keys show what uses each key
  as a tree, and hints that point at a settings page name it as
  Tools › Settings › page.

- **Detection rules.** The rules, packs and catalogue tables have more room and
  fit their pane; the selection mark sits at the row edge and Remove lines up
  with Export manifest. About this pack wraps inside the window, rule counts are
  exact, and the filter guide has a maximum width with aligned columns.
  "Downloads are off" is a plain note rather than a warning, and a download
  asked for while they are off shows a red message instead of an error. A failed
  abuse.ch pack install says what went wrong and what to do, keeps the installed
  version, and accepts a plain gzip of the rules.

- **Disks and the file viewer.** The listing lines up size, permissions and
  uid:gid as columns, and long names end in an ellipsis with the full name on
  hover. The free-space line is gone, Extracted files shows whole names, and the
  extraction message names the file in bold and can be dismissed. The file
  viewer shows the file name in bold and its text in a framed area.

- **Malware samples window.** Its tables fit the window at common sizes: columns
  follow the window width, line up with their headers and cut long text with a
  hover, so the buttons are no longer pushed off screen. The window is at least
  900 px wide.

- **Cloud profile launch advice.** VM configuration offers Routed networking
  for the local simulated metadata service without silently changing saved
  policies, and shows the i440FX-to-q35 RAM fallback before launch. Provider
  metadata references distinguish documented paths from simulated values;
  Vultr's JSON response includes its canary user-data.

- **A replaced debug target stays replaced after it exits.** When the debugger
  is not following exec, the guest keeps that replacement as the reason the
  session ended, including when the new program has already exited before the
  first status query. A guest patch change: needs a new base (the guest
  kernel changed); older bases keep their previous behaviour.

- **Responsive non-stop debugger input.** Buffered debugger packets are read in
  bounded bursts between guest event polls, avoiding a guest round trip for each
  packet byte. Debugger qualification forwards child-exit signals and waits for
  attachment before allowing its legacy-exec fixture to execute a new image.

- **Immediate restart preserves earlier-file evidence.** Starting a VM whose
  previous automatic disk layer is pending now asks you to wait for recording
  saves to finish, preventing a disk merge from overtaking those saves.

- **Stopped-VM snapshots wait for saved recordings and disk finalization.**
  Snapshot changes finish the previous boot's automatic disk layer before using
  it, so a background merge cannot remove a layer selected for a checkpoint.
  Pending recording writes finish first, preserving the evidence needed to copy
  earlier file contents. The snapshot window reports the recording wait; a
  timeout or shutdown cancels the operation with the disk layers retained.

- **Device profiles: cloud VPS profiles with a fake metadata service.** A new "Cloud
  VPS" preset makes the VM an instance of a KVM cloud (Tencent Cloud CVM,
  Alibaba Cloud ECS, DigitalOcean Droplet, Vultr VC2) instead of a PC: the
  provider's DMI strings, SeaBIOS, i440FX or q35 chipset (new machine type
  setting), virtio devices, MAC prefix and DHCP network, with the CPUID
  hypervisor flag and kvm-clock left visible as on the provider's machines.
  The first start writes a lived-in instance into the VM's disk: cloud-init
  data and logs, the provider's agent directories as inert stubs, the default
  user's shell history and login records, an aged host name. In a Routed
  network the gateway answers the provider's metadata address (169.254.169.254,
  169.254.0.23, 100.100.100.200) on every route, with the instance id, region,
  user data and canary credentials that are new for each run (in the provider's
  own form and length, with no marker a sample could look for, and expiry times
  that follow the request). Triage lists the
  requests, the credentials handed out and any use of the canary in what the
  guest sends out (ATT&CK T1552.005), and the destination as an endpoint
  indicator. Sources and gaps are in `stealth/catalog/SOURCES-cloud.md`; Hetzner
  and Linode have no public dump to copy.

- **Device profiles: whole processor table, RAM-sized DIMMs, network chip listed.** The
  processor is written as one firmware table (socket `U3E1`, not `U3E1 0`;
  CPUID signature, voltage, upgrade, clock, core and thread counts, and L1, L2
  and L3 cache tables the processor points at). The memory modules are real parts
  of the machine whose sizes add up to the VM's RAM (one module up to 8 GiB, two
  above), with the machine's other slots empty, and the memory array lists the
  slot count and capacity. Realtek and Broadcom machines still show Intel's
  82574L (QEMU emulates neither; the RTL8139 would be the bigger giveaway), now
  listed as a giveaway. Dell board serials carry a `CN` number. NVMe-only laptop
  profiles keep their SATA stand-in.

- **Debian Minimal runs Debian's own kernel modules.** Its kernel is now
  built with Debian's own configuration (the new `stock` kernel profile:
  nothing changed but the recorder and the embedded configuration the image
  builders read), and the recorder keeps none of its state in a stock kernel
  structure (series patch 0020: per-task state in the LSM task blob,
  io_uring/AIO requests and rings in side tables, process-core state with the
  writing task), so structure layouts, exports and modversions CRCs are
  Debian's, and its BTF is byte for byte that of Debian's own image (patch
  0022), so Debian's module BTF is valid too. The kernel trusts Debian's
  module-signing certificate (the public certificate of Debian's build, read
  from Debian's kernel package), so Debian's signed modules load untainted:
  `lsmod`, `modprobe`, udev and the module index are Debian's own, and
  Debian-built out-of-tree modules load too. The bootstrap initrd loads
  Debian's own root-disk and ext4 modules, as Debian's initramfs would. The
  function tracer is on as in Debian (BPF LSM and fentry programs attach;
  systemd's bpf-restrict-fs works), with the recorder kept out of it (patch
  0021: nothing of it in tracefs). Every stock kernel build compares its
  exports, BTF and traceable functions with Debian's kernel
  (`scripts/check-kernel-abi.py`). New Debian Minimal bases only; the kernel
  build now needs `zstd`.

- **The Debian desktop base gets Debian Minimal's kernel.** The desktop
  (GNOME, Xfce and the other desktops) now runs the same stock kernel as
  Debian Minimal instead of its own `debian` profile (removed): it installs
  Debian's pinned kernel packages (`/boot`, `/usr/lib/modules` and the module
  index are Debian's, `dpkg --verify` reports nothing) instead of purging
  every `linux-image-*`, loads Debian's signed modules (its bootstrap initrd
  loads Debian's virtio-blk and ext4 modules, udev the rest, virtio-gpu
  among them), and its `/proc/version` is Debian's banner, so its kernel, like
  Minimal's, is compiled with Debian 13's compiler and linker (natively in the
  rootless Debian 13 toolchain chroot where the host's are others). The
  `debian` profile's built-in drivers (virtio-blk, ext4, DRM and virtio-gpu)
  are modules in Debian's configuration and are no longer built in; no other
  option differs from Debian's. Both Debian bases share one cached kernel. New
  desktop bases only; their root stays on virtio.

- **Debian images build on other distributions.** The image bootstrap names
  Debian's archive keyring (`--keyring`), not the host's default, and a
  rootless bootstrap stages in `/var/tmp` (`ANTINOMIE_STAGING_DIR`) when a
  folder above the work folder, such as Ubuntu's 0750 home, keeps the
  namespace's root out.

- **Conformance goldens for Debian Minimal, and kexec_file_load's flags.**
  With Debian's configuration some calls answer differently from the BusyBox
  kernel (kexec_file_load and userfaultfd exist, transparent huge pages,
  the shadow stack, the persistent keyring, a smaller log buffer, fewer
  built-in file systems), so the quick tier compares a Debian Minimal base
  with goldens of its own (`trace/golden/debian-minimal/`). The Syscall Trace
  names kexec_file_load's flags (`KEXEC_FILE_UNLOAD`, `KEXEC_FILE_ON_CRASH`,
  `KEXEC_FILE_NO_INITRAMFS`, `KEXEC_FILE_DEBUG`) instead of showing raw bits.

- **Export the whole Triage as a report.** Triage › Export report… writes the
  run as HTML (one self-contained file), PDF (the same layout, written by the
  app with no browser or network), JSON (versioned schema, documented in
  `docs/triage-report.md`), a MISP event (attributes, `to_ids` only for dataset
  matches, ATT&CK galaxy tags) and a STIX 2.1 bundle (indicators, malware,
  attack patterns, relationships). A dialog has a checkbox per section
  (summary, indicators, ATT&CK, processes, findings, every Files tab, file
  activity and reconstruction, network, detection engines, evidence
  references, custody head), remembered between exports. The report is of the
  whole run: the screen's filters and pages do not apply. HTML and PDF show at
  most 1,000 rows of a table (the JSON keeps them all) and the file activity
  lists at most 2,000 changed files, with a note for the rest. Optional evidence
  bundle: the packet captures, the files the run dropped in an inner AES-256
  zip (password `infected`), the sample's custody export and a SHA-256
  manifest. Optional defanging (`hxxp://example[.]com`) applies to HTML and PDF
  only; JSON, MISP and STIX keep raw values. Nothing in a report is a verdict.

- **A custody log chains everything done to or by each sample.** Every entry
  (added, edited, sent to a run, seen in a run, exported, removed) stores the
  SHA-256 of the entry before it, and a library index chain records each log's
  head, so an edited, removed or reordered entry, or a removed sample log, is
  found. Verify names the first entry that changed. The Custody log tab shows
  a check per entry and a copyable head hash; Samples has a global view with
  event-kind filters. Export custody record writes JSON with a stdlib Python
  verifier, or HTML, optionally signed with your own minisign or SSH key (never
  an app key). Terminal input is recorded by size only. Plain events from earlier
  versions are migrated once and marked "recorded before the custody log".
  Remove keeps the log with a Removed entry. A full purge (log and index
  entry) exists in the library code and is recorded in the index chain, but no
  button offers it yet. The log is tamper-evident, not tamper-proof:
  someone who rewrites the whole library can rewrite both chains, so keep the
  head hash somewhere else.

- **File activity keeps what a run wrote, within a budget.** Every write
  the kernel captured is indexed per file as a byte range (offset, length) that
  reads back exactly from the run's object store, however many writes the file
  took (the call list is still bounded; the written content is not). Two caps,
  64 MiB per file and 1 GiB per run, can be changed in Settings › Advanced;
  past a cap the first writes are kept and the later ranges are listed as *not
  captured*, never dropped. The window shows the bytes kept and skipped per run
  and per file, and says why a range is missing (cap, not recorded by the
  kernel, unknown offset).

- **File activity reads a changed file's earlier bytes, and a boot keeps them in
  its recording.** When a VM starts, the disk it was left in is sealed under a
  fresh empty layer (instant, nothing is copied), so the boot cannot overwrite it
  and a plain restart of a used VM has a readable starting state like a new one.
  At every boot the app records which frozen layers (the installed base, any
  checkpoint and that sealed layer) sit under the VM's writable disk. For a file
  the run changed that existed at the start, the window finds it on that disk
  (by path, and by inode, generation, size, owner and time when the guest named
  the inode, so a name another file took over is not mistaken for it) and reads
  its bytes with the sandboxed disk reader over the qcow2 chain. When the boot is
  over and its recording is saved, the earlier bytes of only the files the runs
  changed are copied into the recording from the sealed layer, and the layer is
  merged back down at once: at most one extra layer, and only while the VM runs.
  The earlier bytes then read without the base or any checkpoint, even after they
  are deleted. Two caps, 64 MiB per file and 1 GiB per run (Settings › Advanced),
  keep the copy small; a file over one keeps its size and SHA-256 and is listed
  as not captured. The layer is not a snapshot and is never shown in Snapshots;
  your snapshots are never merged or changed (if you take or restore one during
  the boot, the layer stays in the chain as the snapshot's own). If the app or the
  machine dies mid-run the VM still boots, and the next start or launch of the app
  finishes the copy and the merge. The copy is not counted in the Recording
  quota. Several runs in one boot share the boot's starting state; a boot started
  by a snapshot restore still reads its checkpoint. Files the run created start
  empty. The window says when earlier bytes are not available: the file is on
  tmpfs or another mount, it is over 1 GiB, the VM's disk chain was at its limit
  and already held changes from earlier boots when the run started (create an
  independent duplicate of the VM, or delete snapshots), a snapshot restore
  replaced the disk while the run used the file, or the base or checkpoint was
  deleted or changed afterwards and the bytes were not yet copied.

- **File activity shows writes through shared file mappings.** With a
  revision-18 guest, the pages a program stored into a `MAP_SHARED` mapping of
  a file appear in the file's history and its written content as "through a
  shared mapping", with their bytes, when msync (or fsync, sync) wrote them
  back or munmap, exec or the program's exit dropped them dirty. Each page is
  known as it was at that moment, not every store before it; pages past the
  guest's 4 MiB copy budget per call are listed as not captured, with the
  reason. The guest's hash at the file's last close covers the final content
  (the munmap or the exit is that close when the mapping held the file). In
  the File Reconstruction window a shared writable `mmap` marks its range
  `~~` (may have changed), and the pages the guest copied replace it with
  their bytes; a page it never saw written stays `~~`.

- **The Syscall Trace decodes more captured structures by their type.** Signal
  sets read as signal names (`[SIGINT SIGUSR1]`, `~[SIGKILL SIGSTOP]` for all
  but those), a `siginfo_t` as its common members and the branch its signal and
  `si_code` select (`si_pid`/`si_status` of a child, `si_addr` of a fault,
  `si_value` of a queued signal, `si_syscall`/`si_arch` of seccomp), a
  `sigevent` by `sigev_notify`, an alternate stack (`stack_t`) by its members,
  bpf's `union bpf_attr` by the command that passed it (map, program, attach,
  link, BTF, query members and their type names; members past the size the
  program passed are left out), capget/capset's header (the version by name)
  and capability sets by name, getdents' directory entries (inode, offset,
  type, name), group lists and the ids getres*id wrote, `file_handle` headers,
  `io_uring_params` (flags and features by name, ring offsets), System V
  messages (`mtype`, `mtext`), iptables table headers (`ipt_replace`,
  `xt_counters_info`) and x86 LDT entries (`user_desc`, the descriptors
  modify_ldt reads). The trace line shows the decoded form; selecting the field
  lists each member. Triage's BPF view lists the attr members of each bpf call,
  and takes a load's instruction count and an attach's program descriptor from
  them, so an attach of a program the run loaded says so. Filter keywords now
  cover every bpf command's attr members (`args.attr.map_fd`,
  `args.attr.query.attach_type`, ...); `args.attr.attach_type` of a
  BPF_PROG_ATTACH and `args.attr.bpf_fd` of a BPF_OBJ_PIN read the wrong word
  before. `io_uring_params` and group lists have keywords too.

- **Library › Samples lists every sample across runs and VMs.** One flat list,
  the sample with the latest run first: name, description, tags (verdict and
  malware category; techniques and custom tags fold into `+N`), run count,
  parents / children, latest run and short SHA-256. Search by name,
  description, tag or SHA-256 prefix; filter by tags (every selected tag), or
  keep only roots. *Add file…* (and *Add to Samples…* in the Explorer) reads and
  hashes the file, never runs or unpacks it, says whether the hash is already
  in Samples, and can delete the original after the archive was read back and
  matched. Tags come in four groups (verdict, malware category, ATT&CK
  technique searched by ID or name, and custom with a colour from nine theme
  colours). *Verify all* reads every archive back. Everything uploaded into a
  VM is archived first (a file over 256 MiB is too large for the library and is
  streamed into the VM without an archive copy), and Run History gains a Sample column and a
  `sample ==` filter. *Download…* opens the MalwareBazaar and MalShare search
  (Tools › Download malware samples).

- **A sample has its own window.** Double-click a sample in Library › Samples:
  a header with the name and verdict, and tabs Summary, Runs and Custody log.
  The Summary shows the verdict and family, the latest five runs, the
  interesting strings and the regex matches of the static report (six rows
  each, longest first, addresses defanged), the static analysis lines, the
  identity with every hash, the archive and the names the sample went by.
  The Runs tab is Run History across every VM, limited to the sample, with the
  environment each run started in (VM, base image, kernel, rule packs, tools,
  app) saved with the run and the processes that run library samples tinted in
  the process tree. A run opens in Triage of its own VM.

- **The sample window adds up Triage over the sample's runs.** When Triage
  finishes reading a finished run it keeps a small digest beside the run (the
  highest finding tier, the rules that matched, the ATT&CK techniques they map
  to, the evasion checks, the detection engines' matches and the indicators).
  The Summary shows Highest suspicion with the runs that reached it, Rules
  matched (YARA, IDS and Sigma, with the runs and the latest hit), ATT&CK
  techniques by tactic, Evasion attempts (virtual machine, debugger, sandbox
  and timing checks, folded by check and run) and Indicators, and the Runs
  table gains a Suspicion column. A run Triage never opened says "not
  triaged" instead of guessing.

- **The sample window draws a lineage graph.** Under Identity, the Lineage
  section shows where the sample came from and what it dropped or ran, merged
  across its runs: parents on the left, the sample in the middle, children on
  the right, one node per file by SHA-256 (a file with no hash is kept apart
  per run and drawn dashed), command nodes for `sh -c` style launchers, and
  edge labels that list the runs ("run 4, 7, 9" or "5 runs") with a shape per
  kind (dropped, downloaded, executed; a fourth shape, loaded, is drawn but the
  recording's index records no such edge yet). Clicking a label opens the
  per-run table. *Hide system binaries* is on by default and shows how many
  are left out; Parents and Children steppers add a level each; a node's
  `+N` badge expands it; the run filter limits the graph to one run. Drag to
  pan, wheel to zoom about the pointer (20 to 300 percent), Fit and 1:1, a
  minimap, and arrow, `+`, `-` and `0` keys on the focused graph. Triage keeps
  the run's lineage index in the run's digest.

- **The sample window has a file viewer, Output files and Add to Samples… for
  files of a run.** *View content* in Identity opens the archived file in a
  window over the page (Escape or the close button ends it): 4 KiB pages with
  first, previous, next and last, *Go to offset*, the shown range, *Copy page*,
  formats Text (opened for scripts), Hex dump, Strings (printable runs of five
  or more over the whole file, with offsets), C array, Python bytes, Base64 and
  Hex string, and text size 8 to 32 px by buttons or Ctrl+wheel. Output files
  lists each memory dump, core dump and network capture the runs left, with why
  it was saved, its size and whether it is still in the run's folder, deleted
  or missing, and the actions Open in Memory, Core dumps or Network, Go to run
  and Open folder. A grey or dashed node of the lineage graph has *Add to
  Samples…*: the file is read from the run's saved disk dump (only bytes that
  exist are read; none available says so), refused if its SHA-256 no longer
  matches the one the run recorded, and added with the run, path, writing
  program and parent sample.

- **Add to Samples… finds the run's saved disk dump.** The dump is saved in the
  VM's recording beside `runs/`, but the dialog and the Indicators scan looked
  inside the run's own folder and always said "no disk dump". Both now look in
  the recording the run belongs to (checked against a real test VM run).

- **The sample window lists similar samples.** Below Output files, Similar
  samples shows up to five other library samples by TLSH distance (150 or
  less, nearest first), with what they share: the imported symbols when both
  are ELF files, printable strings of eight or more characters otherwise. A row
  opens the other sample. Its parents and children are left out, the lineage
  graph shows them. The comparison reads archives of up to 16 MiB each, at most
  300 of them, on a worker thread once per window.

- **Samples are kept in a library.** Downloads from MalwareBazaar and MalShare,
  and files added from this computer, now go into one library under
  `samples/`: one encrypted archive per sample (password `infected`) in a folder
  of its first two hex digits, with names, descriptions, tags, every route by
  which the same bytes arrived (origins), what was sent into which VM, and a
  plain event list in a SQLite database beside them. Identity is the SHA-256, so
  the same file by two routes is one sample with two origins. Archives and
  records of earlier versions move in on first start (the old JSON records are
  kept in `samples/legacy/`) and are marked as recorded before the library. A
  sample is read back and its SHA-256 checked each time it is sent into a VM,
  and a mismatch is refused. A run of a program the library sent names that
  sample in its run record.

- **Machine profile values come from public sources.** The catalog's strings
  are now taken from public hardware reports of real units (hw-probe uploads in
  the linuxhw DMI, Dmesg, HWInfo and SMART collections), cited one by one in
  `stealth/catalog/SOURCES.md`. Disks and memory modules are per model, as seen
  in its units (Dell writes the memory maker as a JEDEC code, firmware and WWN
  from smartctl dumps; a spinning disk gets its own rotation rate); ACPI table
  IDs come from the kernel's table list (OptiPlex 7090/5090/7000 and the
  Latitudes say `Dell Inc`, not `CBX3`; ProBooks `SLIC-BPC`); CPU generations
  are the ones seen in units (ThinkPad E15 Gen 3 AMD units carry Zen 2 Ryzen
  5000U); the onboard LAN chip and subsystem ID come from hwinfo. Machines
  whose old strings had no public unit behind them were replaced by sourced ones:
  the ThinkCentre M75q Gen 2, EliteDesk 805 G8 (Desktop Mini) and ThinkPad T14
  Gen 3 AMD units, the H12SSL-i as a Supermicro "Super Server", and the X12STH-F
  by the X11SCL-F. Weights are the number of public reports of each model. A few
  values have no public source and are listed as such in `SOURCES.md` (class C:
  the serial number formats, the memory array's slot count and capacity, and the
  SATA stand-ins of NVMe-only ThinkPads).

- **No QEMU strings left in a device profile's SMBIOS.** Dell and HP
  profiles showed QEMU's machine type (`pc-q35-11.0`) as their product and
  board version, and every profile showed QEMU's `CPU 0` socket, 2000 MHz
  processor speed and a `DIMM 0` memory module of type `RAM`. Every field QEMU
  would fill is now set to what real units of the model report: system version
  (empty on Dell, a space on HP), board version (`A00`, `KBC Version …`,
  `SDK0J40697 WIN …`), board location, chassis version and SKU, processor socket,
  family and the host CPU's clocks, and DDR4 modules in the model's memory slots
  with its form factor. Existing VMs take their machine's values at the next
  boot.

- **Debian Minimal VMs with a UEFI profile get a UEFI PC's disk.** GPT with
  an EFI system partition, GRUB for UEFI and the shim installed as the Debian
  installer installs them (no grub-pc), `/boot/efi` in fstab, and a `debian`
  boot entry first in the VM's firmware. The app lays the disk out once per
  base, beside it, for the base's first UEFI VM (progress window, refused
  cleanly without the room); BIOS VMs are unchanged. Needs a base built by
  this version.

- **The QEMU builder uploads the UEFI files and has more memory.** A Debian
  Minimal build in the QEMU builder VM now returns the UEFI root and layout
  files with the bundle, and the builder VM gets half of the host's memory, at
  least 4 GiB and at most 8 GiB (the kernel link is killed by the guest's OOM
  killer below 3.5 GiB).

- **Container builder for bases.** **Build base…** now offers Automatic plus
  Native, Podman, Docker and the QEMU builder. Podman and Docker build in a
  pinned Debian 13 container (image fixed by digest, package snapshot and exact
  versions), so Debian Minimal's kernel gets Debian's exact banner on any host.
  Automatic takes Native (when the host toolchain is Debian 13's), then Podman
  (rootless preferred), Docker, then the QEMU builder, and falls through to the
  QEMU builder when the image cannot be fetched offline. The Podman and
  Docker paths are covered by unit tests of the commands the app builds, not yet
  by a container build in the test suite. Each unavailable choice
  says why; Docker's help says it needs root-equivalent access (the `docker`
  group). The image is kept and listed with a Remove button; a build leaves no
  container behind. `scripts/build-base.py --container` does the same from the
  shell.

- **Debian Minimal disks carry GRUB's boot code.** Provisioning runs
  `grub-install` as the installer does, so the VM's MBR and `/boot/grub` hold
  GRUB (and debconf its install device) instead of an empty boot sector.
  The debconf answer names the VM's own disk on its bus (`/dev/vda` on
  virtio, `/dev/sda` on SATA, `/dev/nvme0n1` on NVMe), not the provisioning
  tool's `/dev/sda`, and follows a device profile that moves the disk to
  another bus, so a grub-pc upgrade in the guest installs to a disk that
  exists.

- **Debian Minimal's kernel banner is Debian's.** `/proc/version` now matches
  the banner of Debian's own `/boot/vmlinuz` exactly, down to the linker
  version (a Kali or Debian testing host linked it with binutils 2.47, Debian
  13 with 2.44). Debian Minimal therefore builds natively only on a Debian 13
  host; elsewhere Automatic builds it in the QEMU builder, and the build fails
  if the banner differs. `/boot/System.map` stays Debian's placeholder, as on
  every Debian install.

- **Debian Minimal's initramfs is an installed system's.** Each VM's
  `/boot/initrd.img-*` names its own resume device (`conf/conf.d/resume`,
  the swap partition's UUID or `none`), as the installer's initramfs does,
  with the installed disk's device and inode numbers instead of the build
  machine's; and the base's initramfs carries Debian's modules again (later
  packages had rebuilt it from the index of the Antinomie kernel's modules,
  leaving none). New bases only for the module part; the resume device needs
  this app's provisioning.
- **Terminal Raw view.** Each process terminal has a **Formatted / Raw**
  switch. Raw shows the byte stream with escapes written out, searchable and
  copyable, and highlights the escapes that can hide output (cursor moves,
  line erases, overwrites, concealed text, control strings including the OSC 52
  clipboard command, the alternate screen). Formatted now draws bold and italic.
  Saved runs open in either view.
- **Snapshots keep their device profile.** Each snapshot records the VM's
  profile; restoring under a different one is refused with "taken as <machine>"
  and offers **Switch profile and restore**. Snapshots from before this have no
  recorded profile and restore with a note.
- **More machines for the device profiles.** The realistic presets now pick at
  random, per VM and for its life, among about 40 popular machines: Dell
  OptiPlex, Latitude, Vostro and PowerEdge, HP EliteDesk, ProDesk, ProBook and
  250, Lenovo ThinkCentre, ThinkPad and ThinkSystem, and the Supermicro servers,
  the commoner models more often and only those the host CPU's generation could
  have shipped in (or a warning when none can). Each machine has its real BIOS
  releases and units, and its disk model, firmware and memory part vary within
  what such machines have. Each run records the machine its guest looked like.
- **Supermicro network card.** The X12STH-F and H12SSL-i profiles name their card
  `eno1` (firmware index), as their boards do; the X12STH-F has no I219.
- **Toasts show their time left, and the live HIGH toast is off by default.**
  Every toast that closes by itself (notices, warnings) draws a thin bar along
  its bottom edge in its level colour; it shrinks to nothing as the timer runs
  out, the toast closes when it does, hovering pauses both, and toasts that stay
  until dismissed (errors) draw none. **Settings › Notifications › Toast for
  live HIGH findings** is now off by default. The setting is stored under a new
  key because 0.7 saved its default for everyone: a machine that has it on
  turns it on again once.
- **Transport reconnects no longer wait for the disk.** A reconnect took up to
  tens of seconds on a busy disk (its boundary files were fsynced and the VM's
  snapshots listed on the thread that drains telemetry); it now takes well under
  a second, and its receipt says how long each step and the guest took.
- **Command timeouts count the guest's time.** On a loaded host a command no
  longer times out ("outcome unknown") before the guest had a chance to see it.
- **No terminal output lost on a busy screen.** Output the frontend could not
  take at once waits and follows in order instead of being dropped.

- **The host times its telemetry read gaps and says which drops they caused.**
  Every pause of 10 to 50 ms or more (half the guest's send wait) between the
  host's telemetry reads is recorded with its start in guest time, its length
  and a cause (recording writer behind the disk, writer wait, drain pass work,
  thread not scheduled, other host work, blocked), as is every ring whose head
  packet waited that long while the host read other rings. They are in the run
  report and in Summary > Health > details ("Telemetry read gaps"). The VM
  regression's `conf-stress-contended` ties each guest send drop to such a gap
  and passes only if every drop has one. On a loaded machine the gaps were the
  recording writer behind the disk, the transport thread not given a CPU, and
  ring starvation: the host merged the vCPU rings by packet timestamp, and the
  fragments of one long event kept the event's old timestamp, so another
  ring's packets waited for as long as that event was sent. The host now takes
  a ring head first once it has waited 10 ms. The host also records the spells
  in which a ring stayed 90 % full at every read (the host kept reading but
  drained slower than the guest sent) with what it read and what the guest
  wrote meanwhile, and the clock offset between packet and host time, so a
  pause placed in guest time by an old packet is moved to where the guest was.
  `conf-stress-contended` passes when every drop has a read gap or such a spell
  and fails on a drop with neither; the run reports the drops by cause.

- **A Partial Sigma scan says why.** The fixed note "Category acceptance is not
  full compatibility..." no longer takes the first place among the scan's
  warnings, so the header names the real reason (incomplete captured events,
  the 4,096-rule budget, the 90 second deadline, a rule that failed while it was
  evaluated, matches that could not be reported) instead of "(+1 more)". The
  note is in the header's hover text. Results saved by 0.7.x show without it.
- **Behaviour samples carry no product name.** The suite is now `demo-all` and
  `demo-<scenario>` (was `ant-sample-*`). Domains are neutral names under
  `.invalid` (`update.example-cdn.invalid`, `exfil.example-dns.invalid`,
  `remote.example-host.invalid`, `pool.example-pool.invalid`), files, units and
  configs are `demo-sample*`, decoy credentials and notes carry `DEMO-DECOY`,
  and the sinkhole banner and temp dir are `demo-sinkhole`. The binaries are
  built without source paths. Endpoints, work-directory-only writes and
  counted-never-executed downloads are unchanged, and every scenario lists the
  same rule ids.

- **Captured data reads by its type, not by its bytes.** The Syscall Trace
  (Info column, argument rows, field rows, async operands) used to show any
  captured object whose bytes looked printable as a quoted string, so a
  timespec, a pointer or a struct could read as text in one run and hex in the
  next. Now strings and character data (a task name, mount options) are
  always quoted; structs, times, integers, pointers and arrays are always hex;
  socket addresses are decoded only when the field is a `sockaddr` (a pointer
  whose name mentions an address no longer reads as `a.b.c.d:port`); and data
  buffers (what `write` sent, a key payload, a bpf map key) are always quoted
  with every byte, binary bytes escaped (`"\x06\0\xb6A"`) instead of
  switching to hex. The conformance golden files no longer change with a
  run's clock or most addresses (the line for `prctl.set_name_long` still holds
  an address of the fixture build).

- **File Reconstruction: replay a file's calls and see what each byte is.** In
  Triage › Files › Per-file history, *Reconstruct contents…* under Content
  changes (and *Reconstruct contents…* in the right-click menu of a row in any
  Files tab) opens a window that replays the file's reads, writes, resizes and
  zeroed ranges in the order the file system applied them, over what the file
  held when the run started. Each byte is shown as it is known: `??` never seen,
  read, from the starting disk (before-image), written, `##` changed with the
  new value not captured, `~~` under a shared writable mapping. Step with the
  slider, the buttons or the arrow keys; click a byte for its history, with the
  time each state was learned. *Hash this state* takes the SHA-256 of the
  reconstruction when every byte is known and compares it with each hash the
  guest took. *Save reconstruction* writes the file with unknown bytes as 00 and
  a `.mask` file marking them (00 known, 01 unknown, 02 not captured, 03
  mapping) to `reconstructed/` in the recording; *Text diff* shows the lines a
  text file gained or lost.

### Guest

- **A busy program's telemetry is no longer held to one packet per sleep.** In
  never-drop mode a sender waiting for its turn on a full ring now sleeps on a
  wait queue and the sender before it wakes it as its turn ends (guest patch
  26; no contract change). Before, each waiter found its turn only when its own
  50 to 100 us sleep ended, so once a ring had filled every CPU sent about one
  packet per sleep: a syscall flood on two vCPUs made 5,153 calls a second with
  every thread waiting all the time. It now makes 82,676, and the host's drain
  is the limit. The full tier measures it (`stress-rate`).
- **Every base's programs come from Debian's packages.** The BusyBox base and
  the Debian bases' bootstrap initrd take BusyBox, resize2fs, chattr and their
  libraries from pinned Debian 13 packages, checked against the archive's
  signed index, whatever system builds the base (a base built on Ubuntu carried
  Ubuntu's BusyBox and glibc). `bundle.json` lists those packages for the base's
  published sources, and a native build no longer needs busybox or ldd on the
  host.
- **Debian desktop bases keep /tmp on disk**, like Debian Minimal and BusyBox:
  what a sample drops in /tmp reaches the VM's disk (Disks tab, disk dumps,
  checkpoints). The conformance suite checks every Debian base against the
  Debian goldens and keeps the work folder's device number only where a call
  names a device.

- **Real file positions and in-kernel copy operands (contract revision 18).**
  A read or write family call on a regular file or block device records where
  it began in the file and how much it moved (`file.position`, 24 bytes), from
  the position the file system used, and for a write the order in which the
  file system applied it (a number taken under the file's inode lock), so
  writes that raced on one range are replayed in the order they really
  happened, not the order their calls returned. sendfile, splice, copy_file_range,
  FICLONE/FICLONERANGE and fallocate record their operands (`file.copy`: both
  files, both offsets, the length, the destination's size after the call, the
  fallocate mode); when the source is the pipe of a splice, whose bytes cannot
  be read again, the bytes the destination got come along (`file.copy.data`,
  up to 1 MiB per call). Both are fields of the call's Exit,
  no extra event. New patch 16 (shared by every architecture); bases need
  rebuilding for it, and older bases keep working without the records.
- **Writes through shared file mappings (contract revision 18).** A store into
  a shared file mapping makes no system call; the guest now records the pages
  where the kernel consumes the page table entry's dirty bit, in the context of
  a traced task: when a call writes them back (msync, fsync, sync: cause
  WRITEBACK) and when a call removes a mapping that held them dirty (munmap,
  mremap, a MAP_FIXED mapping over it, madvise, exec, exit: cause UNMAP).
  `lifecycle.file_mapped` (96 bytes per range: the file, the range, the size,
  the time, a write order, why bytes are missing) with the page contents as
  `lifecycle.file_mapped.data`, up to 4 MiB and 64 ranges per call; one
  lifecycle event before the call's exit, or before `lifecycle.task_exit` for
  the address space a task drops when it exits. Each page is its state at that
  moment, not every store. Not seen: a page the kernel's background writeback
  cleaned while the mapping stayed and that was not stored to again, and
  mappings of the kernel's internal files (shared anonymous memory, System V
  shared memory, memfd). New patch 17 (shared by every architecture).
- **Typed layouts for group lists, directory entries and LDT reads (contract
  revision 18).** getgroups and setgroups name their array `gid_t[]`, getdents
  and getdents64 their records `linux_dirent[]` and `linux_dirent64[]`, and
  modify_ldt's reads the descriptors they copy (`desc_struct[]`, x86-64 only);
  these were plain bytes before. The netfilter set option
  `IPT_SO_SET_ADD_COUNTERS` (and its IPv6 twin) is now labelled
  `xt_counters_info` instead of `ipt_replace`. The bytes are unchanged. New
  patch 18; a host that does not know a layout shows the bytes.
- **Architecture-neutral guest patches.** The shared patches no longer assume
  x86-64: system calls are keyed by their `__NR_` names, registers are read
  through the kernel's portable helpers, and what only x86 has (its system call
  table, its decoders, the debug registers, the system call entry hook and the
  boot-time reservation of the bootstrap page) is in per-architecture files and
  one x86-64 hook patch (the series is nineteen patches). No change on x86-64.
  The host reads the guest's architecture from the debug engine's capability
  reply when it identifies the guest and decodes x86-64 guests only. No wire
  change; a new base is needed for the new series identity, and older bases
  keep working.
- **A waiting telemetry sender keeps its turn.** In never-drop mode a guest
  sender that found its ring full could lose every race for the room the host
  freed to the other senders on its CPU and drop records although the host kept
  reading (stress-heavy lost 2 of 13.7 million). Senders that may sleep now wait
  in turn per CPU and get freed room in that order, and a send wait ends only
  when the host has taken nothing from the ring for the whole wait (or is gone),
  not after a fixed time while it is still reading. Senders in atomic context
  still never queue. Drops and partial events are reported as before. The full
  VM tier gains a `stress-contended` group (heavy load on a 256 KiB never-drop
  ring with a 100 ms send wait), judged by attribution (see the host entry on
  read gaps): each drop must fall in a host read gap or a full-ring spell at
  least as long as the send wait. Loss is reduced, not gone: a
  sender still drops when the host reads nothing from its ring for the whole
  wait, and on a loaded build machine that group measured 1 drop in 13.7
  million records and 38 in 10.5 million (737 in 7.4 million before the
  change).
- **Guest kernels have BTF, without the recorder in it.** The BusyBox and
  Debian Minimal kernel now builds `/sys/kernel/btf/vmlinux` and module BTF
  like Debian's 6.12.94-1, so the missing file no longer gives the VM away
  to eBPF tooling. BTF alone did not let systemd's bpf-restrict-fs attach
  (it logged that BPF LSM was not available, which also gave the kernel
  away): that also needs the function tracer, which Debian Minimal's stock
  kernel profile now has (see the Debian module entry above). The recorder's own code is built without debug information, and a
  filter run after pahole (series patch 0019) removes every type, field,
  enumerator, function and variable the recorder's headers leave in stock
  objects; module BTF is encoded against the unfiltered vmlinux BTF and
  remapped, so modules share the filtered types. This also covers the Debian
  desktop kernel, whose BTF (Debian's configuration) named every recorder
  function until now. Every kernel build checks vmlinux and module BTF for
  recorder names (`scripts/check-kernel-btf.py`), and the stealth probe reads
  `/sys/kernel/btf` in the guest. No stock structure carries a recorder
  field any more (next entry), so every structure has Debian's layout; the
  minimal profile's configuration still differs from Debian's (see
  docs/implementation/bases-and-stealth.md). Building the minimal kernel now needs `pahole`
  (dwarves).

## 0.7.1 — 2026-10-26

The first release since 0.6.2: 0.7.0 was not published separately, so this
section lists both.

### Since the 0.7.0 work

- **Debian Minimal base.** **Build base…** offers a third base beside BusyBox
  and the Debian desktops: console-only Debian 13 (trixie) as the Debian
  installer leaves it with no desktop chosen (the standard system utilities;
  the inventory is in
  `src/antinomie/packaging/debian-minimal-trixie/packages.txt`), no desktop,
  display manager or SSH server. It boots on BusyBox's kernel,
  needs 1024 MiB RAM and 4 GiB disk,
  and its VMs ask for a per-VM account like the desktop bases and behave like
  BusyBox on screen (console, App terminal runs). Its root is mounted by
  UUID, so stealth profiles can put its disk on SATA or NVMe as on BusyBox.
  The bundle is about 890 MB.
  Runs on the 0.7.0 guest contract (revision 17); its VMs need this app's
  provisioning and launch (an older app gives them no network and no grown disk).
- **Debian Minimal looks installed, not built.** The image no longer names
  Antinomie or the build host (the package inventory, network and tmpfiles
  file names, the build host's resolv.conf that systemd-resolved kept, masks for
  agents that are not installed); the build fails if such a trace comes back.
  Each new or reset Debian VM gets its own root filesystem UUID and directory
  hash seed, and no sudoers.d file. Account provisioning now uses `guestfish`.
  Files keep the change, access and birth times (with nanoseconds) their
  installation gave them instead of 1970, and the filesystem's creation, mount
  and write history reads like an installer's.
  Its packages are what the Debian installer installs with no desktop: the
  standard system utilities with recommends (exim4 for local mail, timesyncd,
  lsof, dig, man pages and documentation), tasksel and its language task,
  without curl and systemd-resolved; the package indexes stay. It takes its
  address with ifupdown and dhcpcd on the interface the stealth profile's
  machine would have.
  Its configuration files are the installer's (sources.list with
  non-free-firmware and deb-src, fstab, hosts, locale.gen, adjtime, the debconf
  answers, the installation's dpkg and apt logs), `/tmp` stays on disk without
  a mask, and it boots with GRUB's command line for Debian (`root=UUID=` of
  the VM's own disk, `ro quiet`, no serial console, no `panic=-1`). Accounts
  get the installer's groups and full-name field, and each VM its own machine
  ID.
  Its disk is partitioned as the installer partitions it (MBR, the root at
  1 MiB, a swap partition sized for the VM's RAM, laid out when the VM is
  created or its disk grown), it carries GRUB and Debian's own
  `linux-image-6.12.94+deb13-amd64` and `linux-image-amd64` packages (see
  below), and its kernel reports Debian's release, compiler and
  configuration where programs look (AppArmor, the memory cgroup, HZ 250,
  8192 CPUs, perf_event_paranoid 3, no 9p, no netconsole). BusyBox shares the
  kernel and gets the same; the conformance goldens follow it (fanotify and
  landlock answer, AppArmor's bind error, HZ 250, the LSM list) and name the
  root disk by role so one golden serves both bases.
- **Debian Minimal's /boot is Debian's.** The kernel packages in the image are
  Debian's genuine `linux-image-6.12.94+deb13-amd64` and `linux-image-amd64`
  6.12.94-1, fetched from snapshot.debian.org and checked against the Debian
  archive's signed index and pinned SHA-256s (kept with the build inputs), so
  `/boot` (the image world-readable as Debian ships it, its configuration,
  System.map and an initramfs of Debian's modules) and the module tree are
  what a real installation has and `dpkg --verify` reports nothing; the build
  fails otherwise. QEMU still boots the Antinomie kernel directly, which the
  guest no longer holds anywhere (it was `/boot/vmlinuz-*`, mode 0600). The
  Antinomie kernel's few modules sit in the tree's `updates/` and are the only
  ones the module index names, so nothing tries Debian's (which that kernel
  refuses) at boot.
- **Debian accounts hashed by the guest.** A new Debian VM's password is
  hashed by the guest's own `chpasswd` (PAM and libcrypt), so it is stored as
  Debian 13 stores it (yescrypt, `$y$`) whatever the host's crypt supports; the
  host no longer hashes it with Perl or OpenSSL. The password reaches the guest
  only on chpasswd's standard input, never as a file on the disk, and a reset
  sets the recorded hash again. **App dependencies** names the package with
  `guestfish` for each distribution (`libguestfs` on Fedora, openSUSE and
  Arch; it said `guestfs-tools` before), and resetting such a VM checks for it.
- **Debian Minimal's NIC follows the stealth profile.** The network card sits
  where the profile's machine has its built-in LAN: PCI 00:1f.6 (`enp0s31f6`,
  Intel's I219) for the Intel OptiPlex, EliteDesk 800, Latitude and Supermicro
  X12 profiles, 00:19.0 (`enp0s25`) for Transparent, AMD machines and edited
  identities, the same headless or with a display. The interfaces stanza is
  written per VM when it is created or reset and again when a saved profile
  moves the card (refused while the VM has snapshots), no longer at build
  time. VMs created before keep `enp0s25` until they are reset or their
  profile moves the card.
- **Rootless Debian builds.** Native (`--mode=unshare`) Debian image builds
  move files in and out of the new root as the invoking user, so they no longer
  fail on the private staging directory; the conformance trace suite also runs
  on a Debian Minimal base (account, minima, login prompt).
- **UI polish.** The Summary detector cards say *Queued* or *Scanning* instead
  of *Not scanned* while a scan waits or runs. The Main activity graph has zoom
  buttons and Ctrl+wheel (60 % to 300 %), its click opens the graph without
  carrying a filter along, and the graph's overview ruler has wide grips and a
  hover card and ring on markers. Per-file history is the first Files tab with
  its file count, keeps process names clear of its graph, shows its calls in a
  table that spans the pane and shows a clicked file or call in Details.
  Suspicious activity starts with Time and its category chips wear their icons.
  Regex matches are their own analysis choice beside Strings, and the regex
  add row is one line. The 0.7.0 Network tabs and the layout switch are gone.
  More lists say when they are empty (cores first), more tables span their
  pane, and the terminal's focus edge shows on all four sides. Settings >
  Network routes describes each route in one line (the full text is the
  picker's tooltip), and an empty static analysis Details pane says
  *Nothing selected.*
- **abuse.ch downloads.** A dataset that needs the Auth-Key is refused before
  any request when none is set, with a message that names auth.abuse.ch; HTTP
  404, 429 and server errors are explained. The SSLBL IP list, which abuse.ch
  retired (it now serves a header and no entries), is removed: no IOC dataset,
  no IDS pack, no row. A copy left on disk is ignored and removed by the next
  update. Run endpoints are still matched against Feodo Tracker, ThreatFox
  `ip:port` and URLhaus IP hosts. The free-space check no longer asks gigabytes for a 300 MB list.
- **Test sample names.** The stress samples are now the workload samples
  (`ant-workload`, `build-workload.sh`, `ANTINOMIE_WORKLOAD_*`), their modules
  have plain names (`syscall-load`, `terminal-load`, `network-load`,
  `decoder-variants`, `core-on-crash`) and the behavior samples replace the
  malware-named ones (`ant-sample-*`, `build-behavior-samples.sh`). Older
  entries keep the names they were written with.
- **Guest kernel patches by topic.** The guest's patch series is fourteen
  documented patches, one per part of the design (control channel and
  transport, the MIT licence of the shared headers, the system call table, the
  recorder and capture sessions, argument decoders, run tracking and Stop,
  io_uring and AIO, the executable image, credentials and file records,
  process cores, the debug engine, resource samples, launch modes, hiding the
  recorder), instead of 60 in the order they were written;
  `src/antinomie/patches/README.md` maps the topics, the files they hook and
  the old patch numbers that entries below cite. The patched kernel source is
  unchanged apart from one reworded comment, and the contract stays at
  revision 17, so every base keeps working; the series hash in a new kernel's
  source id changes, and the app builds its kernel once more. The Quilt view is now regenerated whole from
  the canonical series (`scripts/sync-quilt-view.py`), with DEP-3 descriptions.

### 0.7.0 work (not released separately)

- **Workspace title bars.** Main and detached workspace windows use matching
  custom title bars with vector minimize, maximize/restore and close controls,
  native dragging and edge/corner resizing. Terminal-view close and application
  shutdown retain their existing behavior.

- **Terminal interaction and layout.** Live, saved and debugger terminals support
  mouse text selection, double-click word selection, clipboard shortcuts and a
  copy context menu. Ctrl+C interrupts when no text is selected. Terminal output
  fills its surface, with a block cursor, focus edge and a compact process header.
  The main workspace no longer has outer left/right background gutters.

- **Dependency security.** The locked transitive `ctutils` is updated to 0.4.4
  for RUSTSEC-2026-0385. The audit remains enabled; this does not suppress the
  advisory or change the other dependency applicability assessments.

- **Archive navigation.** Syscall trace has direct page entry and accepts
  positive page sizes above 256. Set calls/page to 0 or -1 for an all-matches
  virtual table; visible rows load in bounded windows. Core strings and memory
  analysis results also have direct page entry.

- **Specimen acquisition.** Guest specimen transfers progress independently
  of the single static-analysis worker, rotating between pending handles.
  Waiting for Ghidra or another analysis tool no longer postpones acquisition
  until a guest handle expires. Missing handles remain unavailable evidence;
  cleanup of an already expired handle no longer produces a second leak error.

- **Portable release checks.** TLS fixture checks accept TShark's older record
  label while verifying the ClientHello version and evidence; the debugger
  Restart unit test stays on its fake GDB. Newly reported dependency advisories
  are assessed against the enabled features and archive APIs in
  `docs/dependency-advisories.md`; the upstream versions are unchanged.
  The live debugger's attach target outlives its connection deadline, and its
  Debug on start target outlives the console-close observation window.

- **VM check recovery.** Debugger tool copies are staged and published only
  after completion. Resuming an interrupted regression run replaces an unmarked
  partial copy instead of starting pwndbg with a missing runtime library.
  Redirected tool-output parents are refused before writing, and CI runs the
  regression-runner and Quilt-view self-tests.

- **Host licensing.** Original application, host transport, tooling, tests and
  product documentation use GPL-3.0-only from 0.7.0. Earlier releases remain MIT.
  Shared headers compiled into the kernel remain MIT; kernel patches, kernel
  transport, Debian inputs, fonts, dependencies and community rules retain their
  own licenses. Application archives retain component notices and a locked
  dependency inventory. See LICENSING.md for boundaries and source obligations.

- **Known issues scheduled for 0.7.1.** Under stress-heavy, a waiting guest
  telemetry sender can starve and drop records even while the host keeps
  consuming the ring. Transport reconnect occasionally takes long enough that a
  timed sample has packets in only one recording segment. Both remain unfixed
  in 0.7.0 by the user's release decision; loss and partial-recording indicators
  remain enabled. A passing retry does not establish a repair.

- **Final audit fixes (host).** Packets and the Static analysis tables sort
  from their headers; the DNS table is back to its 0.6.2 columns; Summary >
  Health shows how long telemetry was held back for the recording writer (a
  line when it happened, a row in More health details). Debugger: **Detach and
  kill** asks first, and **Add** can make a hardware breakpoint or a watchpoint
  (write, read or access) where the guest offers them. The confirmation and
  Snapshots dialogs, and four windows that were pinned to the centre (the
  Samples first-use note, Delete memory dump, the disk import and the memory
  import), are plain windows like the rest: nothing dims and they move. The
  Sigma conversion note above the findings is plain text; a real Partial of a
  scan (a budget stop, evidence still captured, a result that could not be
  saved, rules not run) shows Partial and says why even when every input was
  read. The remaining six in-page tab rows (Memory OS, Samples source, capa
  views, Memory Text and Table, Run History All, Live, Past and the Disks diff
  filter) use the thin-bordered tabs. The terminal cursor shows in the Light
  theme. The stealth note no longer says Debian bases boot from SATA or NVMe
  (they stay on virtio). The Quilt view of the guest series lists all patches,
  0001-0057 (`scripts/sync-quilt-view.py` keeps it in step). The gdb console
  runs with a cleared environment (only PATH, locale and TZ) and a private home
  for GEF too; it is not sandboxed, because Ctrl-C must reach gdb on its own
  terminal and gdb must reach the loopback server. A program launched before
  the guest reported its tracer capabilities is refused with "retry in a
  moment" instead of starting without the shell-job shape and hashing.
  `scripts/vm-regress.py` never deletes through a linked folder, refuses `/`,
  the home and XDG folders and the app's own folders by their real path, and a
  check that is stopped takes its whole process tree with it.
- **Debug engine fixes from the final code audit.** Guest series 0058-0060,
  contract revision 17 unchanged. Continuing a program that was killed while
  the debugger held it stopped, or stepping a thread through its own exit, no
  longer oopses the guest's debug worker (which ended every debug session
  until reboot); the engine holds a thread's kernel stack while it touches its
  registers. A step of a system call no longer makes the engine wait without
  bound: stepping a vfork the debugger follows stops at the vfork at once
  instead of hanging every session, a step that blocks lets the program run
  until it returns, Detach works while a step is under way, and the child of a
  stepped fork no longer dies of SIGTRAP. A `clone(CLONE_VFORK)` child without
  `CLONE_VM` has its own memory. Bases built from this tree have these fixes.
- **The Debugger console connects on a busy host, and checks that failed
  under load.** A gdb that connected while another was leaving (the console's
  Restart, or the pane's own gdb replaced) had its first packet answered twice
  and misread every later reply ("Remote replied unexpectedly to
  'vMustReplyEmpty'", then "The program has no registers now"); the debug
  server now ignores such a retransmission, and the console gives gdb 30 s
  for a reply instead of 2 s. The console keeps gdb's history in its
  own home instead of `.gdb_history` in the app's working directory. A base
  built from a job without a hostname is named `debian`, not `localhost`.
  The debug checks set gdb's remote timeout with the command gdb has
  (`remotetimeout`), the Tracer Triage QA fails when its input recording
  failed, and a pty test no longer races the shell it starts.

- **io_uring follow-ups, records in order across vCPUs, saving under load,
  Stop after heavy churn.** Guest series 0054-0057, contract revision 17
  unchanged. Triage now reads the file requests an SQPOLL ring's kernel thread
  submitted (the guest attributes them to the ring's creator with no call of
  its own), and files io_uring FSYNC, SYNC_FILE_RANGE, SPLICE, FSETXATTR,
  SETXATTR, FGETXATTR and GETXATTR requests as the system calls they stand
  for. rmdir and unlinkat(AT_REMOVEDIR) publish the removed directory's
  identity (0054), so Triage knows a removed directory by its inode; splice
  and xattr requests carry the identity of their file; an io_uring rename,
  link or unlink takes its file's identity from the operation (0057), so two
  of them run side by side no longer leave a deleted file "name removed". An io_uring ring that
  only one process maps is attributed to that process (async.flags bit 3,
  0055): its run is ASYNC_COMPLETE instead of OBSERVATION_INCOMPLETE, which
  every io_uring run used to be; a ring a forked child or another process
  maps and an SQPOLL ring stay unproven. The run note says which: "Async
  observation lost N records" (a warning, and the run is listed under loss in
  Summary › health) or "Uses io_uring: which task submitted each request is
  not proven …; nothing was lost" (information); an old run's note with count
  0 reads as the second. Async records are no longer lost under load (0056):
  ant-torture's async-io module at its lightest level lost 10,256 records
  alone and 10,393 beside the other load modules (7,355 staged packets
  failed, 79 of 640 requests saved); now none, all 642 requests saved whole.
  The host reads the guest's per-CPU rings merged by guest time, so a record
  of one vCPU (a hash worker's, a moved task's) is no longer saved ahead of
  earlier records of another and a file's lifecycle no longer lists a step
  early; uring-check record runs on four vCPUs. A recording whose writer
  falls behind the disk no longer stops for good ("recording writer queue is
  full"): the host holds telemetry back and the guest waits, so saving goes
  on; on this shared host stress-heavy had lost 6.4 million packets that way,
  and now saves every packet, except what a disk stall longer than the
  guest's longest send wait drops (counted; Health says how long telemetry
  was held). A trace page whose previews pass 64 MiB ends early instead of
  failing. Stop waits for a guest still writing back its page cache as it
  powers off (up to 300 s while the disk writes grow) instead of forcing it
  off after 10 s and marking the capture forced. The conformance suite gains
  the attribution groups ring-private, ring-shared and ring-sqpoll and
  directory identity cases, and records Stop times; the user golden expects
  the kernel log to be root's (stealth), on bases built from this tree.
- **Inputs that were not resident at a call's entry are read again at exit.**
  Guest series 0053, contract section 22, contract revision 17 unchanged
  (approved 2026-10-22). The recorder copies user memory without faulting, so
  an argument on a page the program had mapped but not touched yet (a forked
  child's literal path, static glibc's start-up `readlinkat` of
  `/proc/self/exe`, an untouched file mapping) was recorded NOT_RESIDENT with
  no bytes: the largest capture gap left. The recorder now reads such an input
  again when the call returns, still without faulting, and the Syscall Trace
  shows it with an "at exit" tag whose tooltip says the bytes are what memory
  held after the call (another thread could have changed them meanwhile).
  After a successful exec the program's memory is gone, so the path is the
  exec's own copy and the argument and environment strings come from the new
  program's stack, tagged "kernel copy" (an interpreter exec rewrote its
  arguments, so only its environment). The field takes the place of the
  NOT_RESIDENT one in the call's Entry, so the call is no longer incomplete and
  Triage, filters and rules see the value; the process tree names an exec from
  it, and JSON carries the mark (`recapture`). An older app shows the field as
  one more Exit field; an older base records as before. Memory a call never
  reads stays NOT_RESIDENT, and the stealth probe checks with `mincore` that
  the recorder loads nothing. Conformance (same app, same fixtures, base 0052 →
  0053): calls left with a NOT_RESIDENT input 4 → 0 as uid 1000, 1 → 0 as
  root, 1 → 0 under concurrency, 422 → 1 in `stress-light` (an exec that fails
  with E2BIG before reading its string) and 1,282 → 0 in `stress-lossy`; slots
  with data captured stay 374 of 375 (the ioctl decoder gap). A new area covers
  each case, including a buffer a second thread rewrites while `write` blocks.
- **Stealth profile, part 2: UEFI, a SATA or NVMe disk, SMT, a home network
  and the smaller entries.** Guest series 0052, contract revision 17
  unchanged. The profile gains the firmware (BIOS, UEFI or UEFI with Secure
  Boot, OVMF found through QEMU's firmware descriptors, a variable store per
  VM), the disk bus (virtio, SATA with model, serial, firmware, WWN and SSD or
  hard disk, or NVMe), an empty CD-ROM, two threads per core (with TOPOEXT on
  AMD hosts), the pointer (virtio tablet, USB tablet or PS/2 only, each with
  its cost), SMBIOS OEM strings and entry point, a named CPU model with a
  brand and its own caches, kvm-clock apart from the KVM signature, SMM, the
  RTC's clock and drift fix, the network card's PCI subsystem IDs and the
  NAT's network, gateway, DNS server and DHCP range. Realistic presets choose
  UEFI, a SATA SSD, two threads per core and 192.168.1.0/24. Before → after
  on a BusyBox base with the Realistic desktop preset (17 of 77 checks giving
  the VM away before, 13 of 80 after; 13 and 8 as uid 1000):

  | Giveaway | Before | After |
  | --- | --- | --- |
  | Firmware | BIOS: no `/sys/firmware/efi` | UEFI (root still reads OVMF's `EDK II` vendor and BGRT) |
  | Root disk | `vda`, Red Hat 1af4, `/dev/vda` | `sda`, `ATA Samsung SSD 870`, non-rotational, Samsung WWN |
  | Addresses | 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3 | 192.168.1.100, gateway 192.168.1.1 |
  | SMBIOS type 11 | missing | the machine's OEM strings |
  | Network card subsystem | Intel 8086 | the machine maker's (Lenovo 17aa) |
  | CPU topology | one thread per core | two threads per core |

  The guest kernel's EFI stub now claims the host's bootstrap page before it
  places the kernel (0052): with KASLR under OVMF the kernel could land on
  it and the transport then failed (shown deterministically with the page
  inside where the kernel goes; then 38 UEFI and Secure Boot boots without a
  failure, each kernel at a new address). BusyBox bases find their root on
  virtio, SATA or NVMe, build NVMe in, and take their address by DHCP; bases
  list what they boot with in `bundle.json` (`stealth_support`), and an entry
  an older base, a Debian base or the host lacks falls back to BIOS, virtio,
  10.0.2.0/24 or one thread per core, shown in the Stealth profile window.
  QEMU's CD-ROM still answers `QEMU DVD-ROM` and its NVMe controller names
  QEMU, so the presets use neither. `stealth-check` gains profile entries and
  a `boots` mode; the probe checks firmware, disks, NAT addresses, PCI
  subsystems, OEM strings and CPU threads. See docs/implementation/bases-and-stealth.md,
  "Stealth profile, part 2".
- **Debugger check p2 "dynamic" no longer depends on the host's /tmp.** gdb
  ran with the host's root as its sysroot, so a file named `p2ld.so` or
  `libc.so.6` in the host's `/tmp` replaced the fixture's loader or libc and
  the test failed, alone or in the full sequence. gdb now gets a sysroot that
  holds the fixture's copies at the guest's paths.
- **Guest conformance suite, part 1: the syscall trace log; what it found is
  fixed.** One command (`cargo run --release --example conformance -- trace
  BASE_DIR OUT_DIR`, see `tests/monitor/conformance/README.md`) boots a new
  disposable VM per fixture group, runs a fixture that prints what each of its
  calls was given and got back, and checks the recording call by call: all 375
  native x86-64 slots with success, failure and decoding variants as a user, as
  root and under concurrency, then `ant-torture` at light, heavy and extreme and
  with a dropping transport. It fails on any warning or error in the trace, any
  loss the counters do not account for exactly, any rendering fallback in the
  Syscall Trace view (rendered with the view's own code), an unexplained gap or
  slot, and golden-file changes (`--bless` rewrites them). Fixed on the way:
  fields with nothing to copy (a NULL pointer, memory of another process,
  memory the kernel uses after the call such as a thread's clear-tid word or
  rseq area) no longer mark calls "incomplete"; a call's packets numbered around
  another record of the same task no longer show a false "packet sequence gap";
  the recorder's own incomplete flags are reported only when no field explains
  them. The trace places captured data by the argument the guest captured it for
  (accept's address, `rt_sigprocmask`'s set), names enumerated arguments (fcntl
  commands, arch_prctl codes, ioctl requests, clocks, rlimits, advice, address
  families, IPC and scheduling commands, reboot commands…), shows address
  lengths as numbers, exec vectors as lists, and how many objects an argument
  captured instead of its address. Guest series 0051 (contract revision 17
  unchanged): an async request that fails has no payload to lose, so a failing
  io_uring read no longer flags the run with observation loss; the terminal ioctl
  decoder knows TCGETS2 (glibc's `tcgetattr`) and the process-group requests.
- **The guest gives less away: measured, then fixed where the guest kernel
  and the base can.** Guest series 0050, contract revision 17 unchanged. A new
  check, `examples/stealth-check.rs` with the static probe
  `tests/monitor/stealth-probe.c`, launches the probe the way a sample is
  launched (as root and as uid 1000) on a Realistic desktop VM and prints a
  table of 72 checks: systemd-detect-virt and virt-what (CPUID, DMI, the SMBIOS
  VM bit, block and PCI vendors, fw_cfg), the Linux side of pafish (user and
  host names, uptime, CPUs, memory, disk size, rdtsc around cpuid, sleep
  skew), MAC prefix and NAT addresses, `/proc/cmdline`, `/proc/version`,
  `uname`, `/proc/kallsyms`, `/proc/modules`, the kernel log, tracing, ACPI
  devices, `/proc/*/comm` and kworker names, and the launched program's
  parent, session and process group. Before → after, on a BusyBox base:

  | Giveaway | Before | After |
  | --- | --- | --- |
  | `/proc/cmdline` and the kernel log | `antinomie_ring_kib=1024 antinomie_boot_gpa=0x40000000` | `console=tty0 console=ttyS0 panic=-1` |
  | `/proc/version`, `uname -v` | `(<user>@<machine>) … #1 SMP PREEMPT_DYNAMIC <build time and zone>`: whoever built it, where and when | `(debian-kernel@lists.debian.org) … #1 SMP PREEMPT_DYNAMIC Debian 6.12.94-1 (2026-06-20)` |
  | `/proc/kallsyms` | 365 `ant_*` symbols and about 490 more of the recorder's | none of the recorder's |
  | kworker names | `kworker/u8:0-antinomie-control`, `-antinomie_resources` | `-events_unbound` |
  | Launched program | PPid 2 (kthreadd), its own session id | PPid 1 (init), its own process group in a session whose leader is gone |
  | ACPI devices, `/proc/ioports` | `QEMU0002:00` | none |
  | SMBIOS BIOS "virtual machine" bit | set | clear |
  | Kernel log for users | readable (`dmesg_restrict` 0) | root only, as on Debian |
  | Hostname, users, root label | `localhost`, `analyst`, `antinomie` | `debian`, `user`, none |

  The guest kernel now takes its `antinomie_*` options off the command line
  before it first prints it (0046); leaves the recorder's functions and data
  out of `/proc/kallsyms` and `wchan`, by the address ranges of its own
  sections plus its `ant_*` names, while stack traces, kprobes and every
  in-kernel lookup keep them (0047); runs the resource refresh on the system
  unbound queue and names its other queues `events_unbound` (0048, audit F-13);
  does not enumerate QEMU's own ACPI devices, so no `QEMU0002` in sysfs or
  `/proc/ioports`, and nothing for a `qemu_fw_cfg` module to load for (0049); and, for a host that asks
  with the new optional EXEC flag `SHELL_JOB` (offered in TRACER_CAPS), starts a
  program as a job of a terminal shell that has closed: init adopts and reaps
  it, it leads its own process group, still the terminal's foreground group,
  in a session whose id is a PID no process has (0050, audit F-14). This app
  asks for it whenever a base offers it; an older base offers nothing and an
  older app asks for nothing (checked both ways). The kernel build writes
  Debian's build string for the pinned package (maintainer, version and
  changelog date, also a reproducible build) instead of the builder's user,
  machine and time, keeps the release exactly 6.12.94 from a git checkout, and
  restricts the kernel log to root in the BusyBox kernel too. The stealth
  profile writes the SMBIOS BIOS table itself, with real BIOS characteristics
  and without QEMU's "virtual machine" bit, which systemd-detect-virt reads. New
  bases default to the hostname `debian` (both profiles), the BusyBox base names
  uid 1000 `user`, the Debian account form proposes `user`, and neither image
  labels its root filesystem `antinomie`. Observation is unchanged: the probe's
  run recorded about 31,000 calls, and p2, p3, audit stop and core, io_uring,
  tracer record, legacy and Triage, and the live debugger console pass on the new
  base (p2's dynamic-loader case fails within the full p2 sequence with the
  previous app and base too, and passes on its own on both). Still visible, and listed in the Stealth window: VM-exit timing (cpuid
  takes about 16,000 cycles), the virtio disk and the emulated display, the q35
  layout with Red Hat PCI subsystem IDs, QEMU's ACPI tables and fw_cfg port to
  root, a fresh boot's uptime and QEMU's NAT addresses; see
  docs/implementation/bases-and-stealth.md "Guest stealth" for every check and limit. Bases
  built before this change keep their old traces until rebuilt.
- **Written files and the launched program are hashed; user names; a
  reconnected run is read whole; the gdb console checked on a live VM.** Guest
  series 0045, contract revision 17 unchanged. A base that offers it (new
  optional command TRACER_CAPS) is asked for two more SHA-256 records: each
  regular file a run wrote, taken when its last writer closes it (also at exit,
  after `dup2` or `munmap`, a memfd when its last reference goes), with the file's
  device, inode and link count in the record (`antinomie.hash/2`), and the image
  of the launched program itself, which the kernel starts without a traced
  execve. Same budget and refusals as the other hashes (16 MiB a file, 16 jobs,
  64 MiB queued), the same CHANGED check, nothing new running in the guest; an
  older base is asked for nothing and an older app asks for nothing. Triage
  lists the launched program's own `process_creation` (image, command line,
  directory, user, and `Hashes` from such a base), so Sigma rules on the sample's
  own start apply; a file the run created carries the hash of its last close in
  the Sysmon `Hashes` of its `file_event` (or `HashSkipped` with the reason), and
  Files › Changed shows it in the file's lifecycle ("closed after write ·
  SHA-256 …", "hashed before delete · …") with the full digest in Details. An exec
  whose path was not captured is named by the image the guest says it loaded,
  never by its parent's. Sysmon `User` is the guest's user name, read on the
  host from the `/etc/passwd` of the base the VM's disk came from (the disk
  reader now opens a base's qcow2 file directly) plus the account the app
  provisioned; an id with no name stays a number. auditd ids stay numbers and get
  the interpreted `UID`, `AUID`, `GID`… fields of auditd's enriched format.
  Triage, its file lifecycles, the detection journal and the network evidence
  now read every recording segment of a run that lived through a transport
  reconnect, oldest first, with "reconnected" in the story of a file that spans
  the boundary. The Debugger tab's console was run against a real guest with
  GEF, the managed portable pwndbg and a system pwndbg: attach, Debug on start, a
  breakpoint, steps, registers and memory, detach and closing the console. A
  pwndbg whose user's `~/.gdbinit` loads another pwndbg used to stop at once
  ("double-loading"); the console now runs pwndbg with a private home.
- **Debugger tab beside Static, with a gdb console.** Attaching the debugger
  (Run › Attach debugger…) or starting a run with Debug on start opens a
  **Debugger · PID** tab right after Static Analysis and shows it; detaching, or
  the run or VM ending, closes it (it is never restored with the saved layout).
  Details and Activity fold down to their tab strip while the tab shows, so
  the listing gets the height; the split comes back when you leave it.
  The old floating window is gone and every feature moved in: the main view is
  the listing around the instruction pointer with the registers and the run
  controls, and threads, processes (with the fork choice), breakpoints, memory,
  stack, the signal handle table and the console sit in panes folded below a
  strip until you open them, each on its own; which are open is remembered. The
  tables sort from their headers, and a chip says "gdb is driving; panel is
  read-only" while an external or console gdb controls the process. The
  **gdb console** pane runs host gdb on a terminal, attached to the session
  through the same loopback server (`target remote`), with **GEF (bata24)** by
  default or **pwndbg** (Settings › Analysis tools › Debugger console). Both are
  new managed tools in Library › Analysis tools: `gef.py` at a pinned bata24/gef
  commit (it uses the system's gdb), and pwndbg 2026.09.15's portable build with
  its own gdb, each checked by SHA-256 (licenses in THIRD-PARTY-NOTICES.md). A
  missing gdb or front end is said in the pane with an Install… link. The pane
  can be folded and reopened, restarted or stopped, and closing it quits gdb
  cleanly so the process keeps running. The shared function sidebar is not used:
  the debug engine reads memory windows and has no symbols to list functions by.
- **Static analysis Strings sorts from its headers; the Run program window keeps
  UID and GID together.** The Strings table in Static analysis sorts by Offset,
  Encoding, Length or Text over the whole listing, not the page on screen: the
  archive reader orders every matching row and returns the page asked for, the
  rows on screen stay while the new order is read ("Sorting…"), and filtering
  still applies first. Disassembly and Decompilation keep their address and line
  order, so their headers do not sort; hovering one says why. In Run program the
  User row no longer leaves the GID value alone on a line: UID and GID move
  down together when the column is narrow, and the Upload source's Host file
  field takes the full column with Choose… under it. Settings' Detection page, the
  README and the docs call the rules page Detection rules, not Rule manager.
- **Core dumps and Static analysis in the new layout; a Strings tab for cores;
  functions count lines.** The Cores view keeps its list on the left and its tabs
  (Context, Memory mappings, Disassembly, Strings, Recovered notes, with counts
  on the tabs that have them). Registers sit in two cards (instruction pointer
  and stack; general) under a thread row with Copy all, with the note that a
  saved core has no unwinding. The mappings are a sortable table you click to
  choose a mapping; the hex view below it is unchanged. Disassembly and
  Decompilation share one function sidebar and one listing with Static analysis,
  and a function now reads `0x401c20 · 12 lines` instead of its size in bytes or
  octets: its instructions in Disassembly, its source lines in Decompilation
  (`– lines` for a core function not disassembled yet). A core's Disassembly
  has a Disassembly / Decompilation switch, and decompiling no longer replaces
  the disassembly you had decoded. The new **Strings** tab lists the printable
  ASCII and UTF-16LE strings of the core's captured memory (four or more
  characters, as in Static analysis) with address, file offset, encoding,
  length and the mapped file or `[anonymous rw-]`. The search, the filter and
  the sort run on worker threads, with the spinner and a Cancel while it reads;
  the table shows 500 strings a page and lists at most 200,000. Static analysis
  keeps every category and table: the File Info views are a segmented control,
  the Summary has Identity and Categories cards (Identity links to Triage ›
  Properties), categories the report lacks are disabled with a tooltip instead
  of dimmed, tabs show row counts, and tables sort from their headers with the
  same arrows as elsewhere. The Details panel now follows the Cores and Static
  analysis tabs and shows the function, mapping, string, note or row you
  selected; the floating details and bytes windows stay in the row menu.
- **Notification toasts: warnings and errors move out of the status line and
  inline notices.** A stack at the bottom right, above the status bar, shows an
  icon, a title, a one-line detail (full text on hover), an "Open Activity" link
  and a close button. Info toasts leave after 6 s, warnings after 12 s, errors
  stay until closed; hovering a toast pauses its timer. A burst of the same
  toast is one toast with a count (×N). Every toast is also an Activity row, and
  the Activity tab shows the warning and error counts as two small chips. The
  stack moves aside rather than cover a window's footer buttons, and works with
  no Activity pane open. Now toasts: the status line's "Failed: …" and other
  command errors, the backend's last error, download, build and tool-install
  failures, the results of Memory, Disks, Samples, Snapshots and Rules actions,
  and the evidence-action error window. The status line keeps plain status
  messages and "Saving stopped". Form validation, "Stop the VM to change this"
  style notes, empty-state sentences and the "No base image" banner stay where
  they are.
- **Fixed: triage tables kept the previous theme's colors after a theme switch.**
  Rows are indexed with their text colors; they are now painted in the palette
  of the active theme. Packet and syscall tints were already read at paint time.
- **Fixed: bold text was white in the Light theme.** egui draws `strong()` text
  in the pressed-widget text color, which was the white of the primary fill. The
  pressed state now uses the selection tint with normal text; primary buttons
  keep their own fill and white text.
- **A run that uses io_uring ends with its own exit status, and finishes.** A
  program that used io_uring and was run with Core Dump on Exit could end with
  its run status unreadable: the core was complete, but the run showed no
  execution status and an unknown state, and the app waited for a completion
  that never came. The cause was in the guest: an io_uring worker thread is a
  thread of the program, and when it left last (the core copy and a group exit
  make that likely) nothing recorded how the program ended, so the status
  reported the tree as ended with no root exit, which the app rejected as
  inconsistent. The guest now counts those threads as part of the run (the task
  counts include them, like the threads in the core) and the last thread out
  records the exit. The app also reads the two facts apart: a run whose process
  tree ended with nothing outstanding is **Finished** (or **Stopped**), while
  "observation incomplete" and the lost-record count stay beside it as notes. An
  io_uring run always reports incomplete observation, because the program that
  wrote a shared ring's entry is not proven, so it used to stay Unknown for ever
  even without a core. A reply the app cannot use no longer clears a root exit
  it already knows, names the fields it rejected, and with a base from before
  this release (which still loses the exit) the run finishes with the exit code
  **unknown**, never zero. Needs a base built for this release for the exit
  status; the contract revision stays 17 and earlier bases and apps keep
  working. `uring-check status`, `boots` and `legacy` repeat the cases: the
  torture async-io module, linked pairs, cancellation, requests pending at exit,
  a submission-queue thread, a root that exits from a non-leader thread, a
  crash and Stop, each with and without a core.
- **Triage Files follows io_uring and AIO.** Programs that do their file work
  through io_uring or AIO showed nothing in Opened, Read, Written, Deleted or
  Renamed. Each request is now read as the system call it stands for
  (`IORING_OP_OPENAT`/`OPENAT2`, `READ*`, `WRITE*`, `FTRUNCATE`, `FALLOCATE`,
  `CLOSE`, `RENAMEAT`, `LINKAT`, `SYMLINKAT`, `UNLINKAT`, `MKDIRAT`, `STATX`, and
  AIO `pread`/`pwrite`/`preadv`/`pwritev`) from the submission entry, the paths
  and data the guest records and the request's result, so the same tabs, lifecycles
  and detection events cover it. The Operation column says `openat (io_uring)`,
  and `file.via` filters by `syscall`, `io_uring` or `AIO`. A request on a
  registered descriptor is tied to its file by the identity the guest records,
  not by a descriptor number that means something else, and an open straight
  into the ring's registered table shows its descriptor as `registered`. Requests past the
  per-call preview are read too, up to 100,000 per scan, and the coverage line
  says what was not read. A vector read shows all the data it read, segment
  after segment.
- **Triage follows one file across renames and hard links.** The guest now records
  the device and inode of the file a call opened, renamed, linked or removed (and
  of the file an io_uring request used). A file renamed or hard-linked keeps one
  entry with all its names; a name that a new file takes over starts its own; and
  an unlink that leaves another link is "name removed (1 link remains)", not
  "deleted". `file.inode` and `file.names` filter on it. With a base from before
  this release files are known by name only, as before.
- **Triage shows the interpreter of an executed script.** The Executed tab says
  `script run through /bin/sh (loaded /bin/busybox)`: the interpreter exactly as the
  `#!` line names it and the file that was loaded; `file.interpreter` filters on
  the first. Earlier bases still say that the path was not recorded.
- **Detection rules: engines, Installed and Catalog tabs, and every rule of a
  pack.** The page has **YARA / IDS / Sigma** tabs and, inside each, **Installed**
  and **Catalog** tabs. Installed lists the packs and custom groups of the engine
  in a sortable table (enable, version, update available); selecting one lists
  all of its rules in a sortable table with a filter, and a click on a rule
  shows its name, metadata and its own source text, cut from the installed file.
  Catalog lists the packs on offer with their rules, size, license and state;
  selecting one shows the catalog's facts (source, license, hosts, options) and
  says the rule list is available only after install; nothing is fetched to
  show it. The rules step of **Getting started** now has the same engine tabs
  with a row per pack; it still needs the explicit Allow downloads, and a pack
  with terms to read still starts unticked.
- **The sidebar gets a Library; base images, detection rules and analysis tools
  are pages.** The *Base images* list is now a **Library** section with three
  entries: **Base images** (the image count), **Detection rules** (the number of
  installed packs; custom groups are not counted) and **Analysis tools** (no
  count). Each opens as a tab of the main area instead of a window. The Base
  images page lists the bases in a sortable table (status, size, VMs using it,
  guest) with Import base, Download base and Build base above it and New VM from
  this base, Open directory and Delete base for the selected row (also on
  right-click). The Rule manager and Analysis tools windows became the Detection
  rules and Analysis tools pages with every control they had; the Tools menu,
  Run program, the Static Analysis report, the Triage detection header and
  Getting started open the pages. The VM list stays flat under Virtual
  machines. The saved fold state of the old Base images section now folds the
  Library.
- **Process, Files and Network triage in the new layout.** Process tree and
  Suspicious activity are one segmented control with counts, and a process with
  suspicious observations shows their count as a small warning chip; its Details
  list those observations and offer **Filter Trace to this process**, **Files
  it touched** and **Suspicious activity** for its PID. In Files, **Hide
  stdio**, **Hide library** and **Failed attempts** are toggle chips in the
  filter bar (the first two still start on), and a file under a hidden
  directory, a persistence path or a credentials path gets a warning bar and a
  warning-coloured Location. Network gets an **Open Packets** button that shows
  the run's capture in Packets. The "Refresh, Every, Refreshed N s ago" row of these three
  sections is one status at the right of the tab bar; its menu has Refresh now
  and the interval, and the refresh itself is unchanged. Table columns and rows
  are unchanged (the DNS table has the columns it had before) and every header
  still sorts.
- **Process cores are no longer limited to 64 MiB.** Core Dump on Exit and Dump
  core now have a **Budget** (64 MiB to 1 GiB) and a **Deadline** (up to 60 s).
  The budget bounds the bytes the guest *stores*: untouched mappings cost
  nothing, so a 256 MiB budget (the new default, also set under Settings >
  Recording) is free for a small process. The guest tells the app what it
  accepts, from its RAM (half of RAM less 128 MiB, 64 MiB to 1 GiB), and the
  list shows it with the guest's available memory; a base built before this
  release accepts 64 MiB only and says so. The guest buffer now grows in 8 MiB
  chunks, so running out of guest memory gives a labelled partial core instead of
  a failed allocation. Every core records what was requested, accepted, expected
  and saved, and why it is incomplete (budget reached, guest memory, deadline,
  recording quota, host disk, canceled...), shown in the list ("Partial · 64 MiB
  of 128.4 MiB · budget reached"), in the details and as `capture.reason`,
  `capture.requested_size`, `capture.saved_size` filter fields. A core that the
  host disk cannot hold is refused before anything is written. Saving a core is
  several times faster: reads are pipelined and the guest polls every tick
  while a core is read. Needs a base built for this release; the contract
  revision stays 17 and earlier bases and apps keep working.
- **Settings, Snapshots and Run program in the new window style.** Settings has
  a page list at the left (Appearance, Recording, Detection, Network lookup,
  Analysis tools, Disks, Advanced) and one page at the right; the page scrolls
  and the footer stays in view on an 820 px screen. Address lookup still
  defaults to TShark GeoIP only. Snapshots has the primary **New snapshot...**
  action, a Graph / Tree switch, and the selected checkpoint in a card beside
  the graph; creating, restoring, renaming, deleting, branches and progress are
  unchanged. **Run program** gets the new layout, a footer with the VM state at
  the left and Cancel, Analyze Only and Run at the right, and a **Source**
  choice: a **Guest path**, or an **Upload** of a host file (the existing upload
  as executable, after which the window continues from its guest path). The
  Arguments field shows "One argument per line" and an example argument on
  each line below it while empty. The analysis checkbox tree is unchanged.
- **Light, dark and blue themes, and a new look for tables, tabs and windows.**
  Settings > Appearance has a **Theme** choice of Dark, Light and Blue (the dark
  theme on deep navy surfaces instead of grey); it applies at once and is
  remembered, and settings saved by an earlier version keep their light or dark
  choice. Every color the app draws now comes from one token set per theme,
  matching the redesign mockup. Tables get a panel-colored header with muted
  semibold labels and a rule under it, zebra rows, hover and selection fills
  and an accent bar on the selected row. Every in-page tab strip (Triage
  sections and counts, Static Analysis, Core dumps, Run History, the Rule
  manager's engines and the Getting started steps) is drawn as thin-bordered
  tabs with an accent underline on the selected one. Spawned windows have a
  title row with the name at the left and a close button, a 1 px line, rounded
  corners and a shadow; nothing dims behind them and they still move freely.
  **Getting started** is now wide enough for all six steps on one row at every
  text size, and its size is locked. No table contents changed.
- **Network viewer: TShark parses every packet, the app only displays it.**
  The packet list (Protocol and Info as Wireshark shows them) and the details
  tree of the selected packet now come from the installed TShark, so every
  protocol it knows is labeled: all TLS versions and handshakes, HTTP/2,
  QUIC/HTTP/3 Initial packets with their server name, SSH, SMB, FTP, SMTP,
  IRC, NTP, mDNS, DNS on any port and the rest, where before only
  Ethernet/ARP/IP/ICMP/TCP/UDP, TLS Client Hello, HTTP/1, DNS on port 53 and
  DHCP were labeled and everything else read as TCP or UDP. The details pane
  is Wireshark's tree with expand and collapse (Expand all, Collapse all; a
  line stays open in the next packet), and the hex pane marks the bytes of the
  chosen line from TShark's own offsets; an offset that does not fit the frame
  is dropped. Without keys it shows what TShark parses: handshakes with ALPN,
  cipher suites, certificates, JA3/JA4 when the installed TShark computes them,
  QUIC Initial server names, cleartext h2c and SSH banners. TShark runs in the
  same sandbox as the display filters (no network, bounded time, memory and
  output) and its output is treated as untrusted: values are validated and
  sanitized, the details tree is capped at 20,000 lines and 24 levels, and
  every byte range is checked against the frame. The app's own decoder of
  frames (layers, summaries, HTTP/DNS reconstruction) is removed. Without
  TShark the Network tab says "TShark not installed — install it from Tools"
  and still lists raw frames (number, time, length) with their bytes.
  Large captures: TShark prints the list once per capture on its own thread
  (cancel with **Stop parsing**; the first 500 rows appear within a moment and
  the page fills as parsing goes on), only one page of rows is held in memory,
  and a finished capture's parsed list is cached beside it
  (`<capture>.pcap.view`, keyed by the pcap's size and modification time and
  the TShark version, deleted with the capture). A live capture is re-read
  about once a second and the capture is parsed again into the same list.
  A synthetic 144,000-packet capture parses in about 11 seconds (the first
  page after 1.5 s, a reopen from the cache in 0.3 s) while the slowest window
  frame stays at 20 ms. Triage > Network gains a **Sessions** table (TLS and
  QUIC hellos with server name, ALPN, cipher suites and fingerprints, and SSH
  banners), lists cleartext HTTP/2 requests with the HTTP requests, and names
  QUIC and HTTP/2 hosts in Hosts. The HTTP, DNS, IPs and Hosts tables were
  already built from TShark fields; their earlier built-in reconstruction path,
  which only the tests used, is removed.
  Known limits: TShark reports byte ranges of reassembled or decrypted data
  relative to that data, so such lines can highlight the wrong bytes of the
  frame; and the details are parsed in one pass, so earlier segments of a
  reassembled stream do not show "reassembled in" links.

- **Detection shows what happened to each input.** Beside *Scanned inputs* the
  tab now reads "N complete · N skipped · N failed". The scan's status follows
  from those counts: Partial only when at least one input completed and at
  least one failed, Failed when something failed and nothing completed,
  Skipped only when every input was skipped, and Complete otherwise (completed
  plus skipped with no failure is Complete). A run with no packet activity is
  Complete, not Skipped or Missing: an empty capture is a finished input with
  nothing to read. The Sigma note that events are converted from the syscall
  trace is ordinary text and never a warning. The line saying a row is a rule
  match and not a verdict is removed.

- **The Triage Summary names MITRE ATT&CK techniques.** A reference reads
  "T1059 Command and Scripting Interpreter" or "T1059.004 Command and Scripting
  Interpreter: Unix Shell", from a table of ATT&CK Enterprise v20.0 technique
  names bundled with the app (no network). `scripts/generate-mitre-attack.py`
  regenerates it from the public STIX data; the terms are in the third-party
  notices.

- **Every table sorts by a clicked column header.** Run History, Activity, the
  process picker, capture history, the Detection event journal (the events on
  the current page), the filter guide, core notes, the downloaded samples
  list (which gained a header row), Packets (the rows of the page shown, or all
  of them without TShark) and the Static analysis tables (Structures and the
  other record tables sort the whole listing on the archive reader, as Strings
  does; the disassembly and decompiled source keep their order) join the
  tables that already sorted. The
  first click sorts ascending, the next descending, and an arrow marks the
  column. The **All live traces** buttons in Run History and Capture History
  are gone.

- **A detached window no longer freezes the app when it sits idle.** Buffer
  swaps no longer wait for the compositor. A window the compositor stops
  showing, such as a detached terminal left idle on WSLg, receives no frame
  callback, so its swap never returned; the detached windows are drawn from the
  main window's update on the one UI thread, so every window stopped answering.

- **A Disks tab shows what is on a stopped VM's disk.** The new tab sits
  between Memory and Core dumps. Its **Current disk (VM off)** entry is
  disabled while the VM runs, with a **Stop VM** button that does what the
  toolbar's Stop does. With the VM off it measures the disk (logical size, an
  allocation estimate from `qemu-img map`, free space and whether the folder
  holds sparse files) and **Open** copies the allocated data into a temporary
  sparse image under the VM's recordings (`disks/.scratch-…`) with a progress
  bar and Cancel. Nothing is written to the VM's disk; the image is deleted
  when you close the view or start the VM, and leftovers of a crash are
  removed at the next start. While the disk is being read, Start, Reset,
  Restore, taking a snapshot, Delete and Duplicate are refused with a message,
  and Open is refused while the VM runs. The view says whether the guest shut
  down cleanly or was forced off ("not cleanly unmounted": committed journal
  transactions are applied while reading). The filesystem tree is lazy and
  paged, shows modes and owners, links with their target (never followed) and
  special files, and has Find by name, path or glob. Details show a file's
  type, size, mode, owner, times and, on request, SHA-256 and MD5 (up to
  64 MiB). **Extract to view** opens a file up to 16 MiB in the data viewer,
  **Save to host…** and **Open with…** extract up to 256 MiB (more after a
  confirmation) into a private, never executable copy, and **Hand to Static
  Analysis** analyzes an extracted ELF file offline. Nothing from the guest is
  ever run on the host. All parsing of the guest's filesystem happens in a
  sandboxed worker (`antinomie-monitor --disk-reader`: bubblewrap with no
  network, the image mounted read-only, one writable extraction folder and
  `prlimit` bounds) using the new `ext4-view` crate. Whole-disk ext4 only in
  this first step; checkpoint sources and partitions are described below.

- **Disks tab: disk dumps.** With the VM off, **Dump disk** flattens the
  current disk straight into a standalone sparse `root.ext4` under the VM's
  recordings (`disks/<id>/`), and **Keep as dump** turns an open view into a
  dump by renaming its temporary folder: no second conversion, and the view
  stays open on the kept file. The image is written as `root.ext4.part`,
  synced, checked (size, ext4 magic and state), renamed, hashed and only then
  named by its `dump.json` sidecar (VM, time, clean or not cleanly unmounted,
  sizes, the source layers with their sizes and times, SHA-256), so a half-
  written dump is never listed; Cancel, a failure and the sweep at the next
  start remove what an unfinished dump left. A dump is bounded by the
  recording quota as a per-dump ceiling on its estimated allocation (the
  refusal says to raise the quota) and by free space under the `disks` folder,
  and shows progress through the conversion and the hash. The SHA-256 of a
  dump is on by default (Settings > Disks: dump hash); views are never hashed.
  A second Settings toggle also records the SHA-256 of every layer of the
  source chain (off by default; it doubles the time of a dump). Dumps are listed
  newest first below the Current disk entry with badges (not cleanly
  unmounted, imported, SHA-256, incomplete, file moved), a record filter and a
  right-click menu (rename, tags, copy path, save, verify, delete); they stay
  browsable while the VM runs, because they are plain files read by the same
  sandboxed reader. Their Details show the record, and **Verify SHA-256**
  hashes the image again. **Import image…** takes a raw ext4 image made
  elsewhere (a truncated or non-ext4 file is refused with the reason); the
  file stays where it is. A qcow2 image is converted instead (below).
  **Save image to host…** writes a sparse raw copy (holes stay holes) or a
  compressed standalone qcow2 with `qemu-img`. **Delete…** uses the same
  confirmation and backend command as the Core dumps and Network capture
  deletes; the backend only deletes `disks/<id>` of the VM's recording folders
  (no links, no `..`, a folder that has a `dump.json`), removes the sidecar
  first, and never deletes an imported image's own file.

- **Disks tab: checkpoint sources, partitions, diff, content search and qcow2
  import.** The Current disk card has a **Source** menu: the current disk, any
  saved (not deleted) checkpoint's frozen layer, or the installed base image.
  Each is flattened by the same `qemu-img convert`, under the same rule (the VM
  must be off) and the same lease; the entry, the view header and the dump
  record say which source it is ("Disk at before-run"), and a checkpoint taken
  while the VM ran usually reads as not cleanly unmounted. A disk with an MBR or
  GPT partition table lists its partitions (type, name, size, ext2/3/4 or
  "unsupported filesystem"); the root partition (or the largest ext4 one) is
  the default, any ext4 partition can be chosen, and it is carved out in the
  same conversion with `qemu-img --image-opts driver=raw,offset=…,size=…`.
  Other filesystems cannot be opened or dumped (a clear message, never a
  crash); **Save partition to host…** writes any partition's bytes to a file.
  The table is read from the first 64 KiB of the guest disk by a small bounded
  parser (at most 128 entries, entries outside the disk are dropped and
  counted, logical partitions of an extended MBR partition are not read).
  **Compare with…** (on an open view or a dump) diffs it against the installed
  base image, a checkpoint, another dump or the open view: the sandboxed
  reader walks both ext4 images and lists the added, deleted and changed
  entries with +/−/~ badges, the reasons (type, size, content, mode, owner,
  time, link target), totals, a status filter, a path filter and a filter that
  hides time-, mode- and owner-only changes; **Details** show both sides of
  each. A rename is a deletion and an addition. Two files with the same size,
  mode, owner and modification time are equal without being read, and a
  directory's own times are not compared; the comparison is bounded (20,000
  listed differences with the totals kept counting, 2,000,000 entries, 120 s)
  and can be cancelled. Where a path is also in Triage › Changed files for
  the selected run, the diff row is marked, Details link to Triage (filtered to
  that path) and Triage's Details link back; each says which kind of evidence
  it is: the diff is block evidence (what differs between two disk images),
  Changed files is syscall evidence (what the kernel was seen doing in one
  run). **Find** gains **Content** and **Content (any case)**: bytes inside
  regular files, reported with the byte offset and a clean snippet, bounded to
  the first 16 MiB of each file, 512 MiB in all and 60 s (the result says how
  many files were read and partly read, and which limit ended it) and
  cancellable. **Import image…** also takes a **qcow2** image: `qemu-img` reads
  it only inside the analysis sandbox (nothing of the host visible, the file
  read-only, one writable folder, `prlimit`), after an inspection that refuses
  an image with a backing file (the message names it), an external data file,
  encryption or a size over 2 TiB; a partitioned image is carved to its ext4
  partition, the conversion is watched so an image that expands cannot fill the
  disk, and the result is a normal dump that does not depend on the original.
  Separately, the reader's bubblewrap setup now uses the shared sandbox profile
  of the analysis workers instead of repeating it.

- **Code audit fixes (host).**
  - The release archive is reproducible: members carry the commit time (or
    `SOURCE_DATE_EPOCH`) and the gzip header has no name or time, so two builds
    of one commit give the same archive when the binary is the same.
  - TShark runs in the analysis sandbox's minimal mount profile: only `/usr`,
    a few read-only `/etc` entries, a private `/etc/passwd`, a minimal `/dev`
    and `/tmp`, the capture (read-only) and a private scratch directory. The
    session bus, X11 and Wayland sockets, `/dev/shm`, other mounts and the
    data directory are not visible, and every namespace (network included)
    is unshared. CI and release probes use the same profile.
  - The Debian cloud image's SHA-512 checksums are fetched from the fixed
    `cloud.debian.org` URL, not from the mirror that serves the image. Debian
    publishes no detached signature for the current cloud images, so there is
    no key to pin and gpgv is not needed.
  - One shared `curl` helper (`--disable`, HTTPS only including redirects,
    connect and total timeouts, size limits, `--fail` unless the caller reads
    the status, never `-k`) is used by MalShare, MalwareBazaar, base, tool and
    image downloads and the rule catalog. The libicu66 `.deb` is fetched over
    HTTPS (its SHA-256 was already pinned).
  - A community rule pack is downloaded through the rule fetcher into a
    private (0700) staging directory under the rules folder, not a predictable
    file in the shared temp directory; redirects stay on the pack's hosts.
  - `cargo audit` can fail CI. The reviewed ignore list is in
    `.cargo/audit.toml`: RUSTSEC-2023-0071 (rsa timing channel; yara-x only
    verifies signatures with public keys) and the Wasmtime 45 advisories
    RUSTSEC-2026-0316, -0222, -0327 and -0269 (component-model, hostcall fuel,
    type indices and WASI paths; yara-x runs core modules only, in the sandbox).
  - A VM name is passed to QEMU as `-name guest=<name>` with commas doubled.
  - Deleting evidence runs on its own thread, in order, and answers its
    command when done; the run records it changes are written as one batch
    through the JSON writer, so the thread that drains telemetry never waits
    for an unlink or an `fsync`.
  - The archive index is stamped with its writer; an older build that appends
    to it clears the stamp and the index is rebuilt, so kernel notes are not
    silently lost. The index disk budget is four times the archive.
  - A first index of a large recording is built in steps of about 256 MiB,
    each its own transaction, instead of one that also holds the drop of the
    old tables. A cancelled or interrupted index keeps what it finished and
    the next open continues from its cursor, and other readers wait for one
    step rather than the whole build.
  - A guest resource request without a reply is abandoned after 60 s and
    polling resumes.
  - "Open in Wireshark" no longer leaves zombie processes.
  - The rules registry lock is per data directory, not process-wide.
  - The capture list stats the file at most four times a second.
  - Flaky tests: the MalShare tests use a fresh script per case and no speed
    bound; Triage refresh tests and the Summary card test use a synthetic
    clock; the sandbox process tests wait for a hang bound, not for speed.
    Added tests for the TShark mount set, the transport-thread invariant of
    `DeleteEvidence` and malformed packets.

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
    bytes as the kernel does).
  - Sigma `process_termination` events (Sysmon event 5) are built from the
    task-exit records in the trace, one per process that ended, with `Image`,
    `ProcessId`, `ThreadId` and `User` where the trace has them. A thread that
    ended is not reported, and there is no `ProcessGuid`; the event time is
    kept in the journal. Journal format 3 is unchanged and older journals still
    load. No rule in the installed SigmaHQ Linux pack uses the category yet.
  - Triage › File activity › Executed says when the exec was a script run
    through its interpreter, using the guest's own flag on the exec's hash
    record; the entry on the interpreter of an executed script above shows the
    interpreter's path.
  - The guest's count of dropped credential and hash records is shown in the
    run summary health, counts as observed loss, and is named in the TRL
    hover.
  - A deleted on-exit core stays in Core dumps as a "Deleted" row, and Run
    History > Analysis enabled says what became of the run's network capture
    and core ("Complete", "Deleted", ...).
  - The TShark coverage note no longer says HTTPS is unavailable: TLS server
    names are read from handshakes; the content of HTTPS and HTTP/3 is
    encrypted, and encrypted DNS is not decoded (cleartext HTTP/2 requests are
    listed with the HTTP requests).
  - App dependencies reports "Wrong version" for a QEMU older than 6.0 (the
    network capture needs its flat `object-add` arguments). No minimum was
    invented for TShark or Suricata. The dnf and zypper package names were
    checked against the Fedora and openSUSE package indexes, except as noted
    in `dependencies/install.rs`.
- **Audit fixes (guest).** Found by the feature-completeness and code audits
  of 0.7.0. Guest contract revision stays 17; the kernel series gains patches
  0032 to 0034 and changes 0029, which no release carries yet. Older bases
  keep working; a revision-17 base is needed for the guest side of each item.
  - **Stop can end a program that ignores SIGTERM.** After the SIGTERM the
    guest itself, with no process of its own, waits a grace period (4 seconds;
    `BackendOptions::stop_grace` sets 100 ms to 30 s) and then sends SIGKILL to
    every task of the run still alive, including `setsid()` children and
    orphaned grandchildren, and repeats it every 250 ms while any remain. A
    process core being copied is not interrupted (the escalation waits, at most
    15 s more). The run status gets a new flag, "Stop needed SIGKILL"; the
    signal that ended the program is its wait status (Signal 9 after an
    escalation, Signal 15 or its own exit code when it obeyed). Checked in a
    VM with a program that ignores SIGTERM (ended after 4.3 s), one that
    handles it (ended in 0.3 s, no escalation) and a tree of seven tasks.
  - **A transport reconnect no longer splits a run into two records.** The run
    keeps its id, so the selection, an open terminal and a pending Stop still
    mean it, and its terminal sequence continues. Run History lists the run
    once, with a note per reconnect that names the boot holding the earlier
    part, and Triage reads every recording segment (see above). Restoring a snapshot still starts a new run.
  - **Process cores of programs with large untouched memory are no longer cut
    short.** The guest kept a core in a buffer indexed by file offset, so a
    segment beyond 64 MiB of file offset could not be stored: a program with a
    large reserved but unused mapping lost everything after it (a core cut at
    364,544 bytes in the reported case; 200 KiB for a 300 MiB mapping with one
    page touched in the VM). The limit now counts the bytes stored, not the
    file's size: holes are kept as holes, named in the transfer instead of
    sent, written as sparse ranges and covered by the digest. The file may be
    up to 16 GiB long; the ceiling on stored bytes stayed at 64 MiB in this
    step and is configurable (up to 1 GiB) in the Process cores entry above.
    Live cores share this.
  - The file-hash `CHANGED` flag compares inode identity, size, mtime, ctime
    and the inode change counter, not just size and mtime, and a digest is
    documented as the bytes at hashing time. An unlink by the sample itself
    does not count as a change. The digest cache is keyed the same way and
    uses a monotonic age instead of the wall clock; it missed every repeat exec
    before (stepping the clock moved what it served) and now hits (`CACHED`).
  - Credential records carry all five capability sets and the securebits
    (`antinomie.creds/2`, 96 bytes; the host still reads `/1`), and a `prctl`
    that changes the ambient or bounding set is recorded.
  - A telemetry sender that cannot sleep waits at most 200 microseconds for room
    in a full ring instead of up to the host's whole allowance.
  - The hash worker no longer reads a file when it cannot publish the result.
- **A debugger for guest processes, without ptrace and without anything in
  the guest.** Run > Attach debugger… (or the process picker) attaches to a
  running program and shows a ready-to-paste command, for example
  `gdb -ex 'target remote 127.0.0.1:PORT'`; gdb, IDA, Ghidra and radare2 connect
  to the same local RSP server (a private Unix socket and a loopback port, only
  for processes of your user). The guest kernel does the work: it stops every
  thread of the process, reads and writes registers and memory, plants engine
  breakpoints and single-steps. The program sees no tracer: `TracerPid` stays 0,
  its own `PTRACE_TRACEME` still succeeds, breakpoints and steps raise no
  `SIGTRAP`, the trap flag is hidden, and reading its own code through
  `/proc/self/mem` shows the original bytes (a direct load of its own code can
  still see an engine breakpoint). The program keeps running until a debugger
  connects; a debugger that detaches or dies leaves it running with its
  breakpoints removed. First release: all-stop, one process, software
  breakpoints, single-step of one thread, x86-64. Guest contract revision 17
  (unchanged; older bases say the debugger is unavailable). Fork and exec
  following, Debug on start, hardware breakpoints and signals are in the next
  entries. Every guest request costs about one 10 ms control poll, so registers take
  about 44 ms and a step about 44 ms; see `protocol/debugger.md`.
- **The debugger gets Debug on start, threads, hardware breakpoints, signals and
  fast requests.** Run dialog > Debugger > **Debug on start** parks the new
  program before its first instruction (the loader's, for a dynamic program) and
  opens the debugger on it; the run shows the gdb command to attach with and the
  program waits until a debugger continues it or detaches. gdb now lists every
  thread, steps one thread (`stepi` over a `syscall` stops on the next
  instruction and over `rep movsb` retires the whole copy), sets hardware
  breakpoints and watchpoints (`hbreak`, `watch`, `awatch`; four debug registers
  shared by all of them, a fifth is refused cleanly and gdb carries on), reports
  signal stops (`Program received signal SIGSEGV`) and passes or drops them, and
  places position independent and dynamic programs from the auxiliary vector.
  Hardware breakpoints leave nothing in the program's memory, and the program
  cannot see the debug registers. Stop ends a debugged run at once, whether it
  runs or sits at a breakpoint; a process core can be taken while the debugger
  holds the program stopped; code a program rewrites while a breakpoint is in it
  is no longer overwritten when the breakpoint comes out; a forked child that
  inherited a breakpoint byte no longer dies of `SIGTRAP`; a single step meeting
  a pending signal no longer loses the step or leaves the trap flag in a signal
  frame. Requests take about 4 ms instead of 22 ms (registers in one request);
  see `protocol/debugger.md`. Guest series 0035-0038, contract revision 17
  (unchanged): a base built before this release keeps working and says plainly
  what it cannot do (Debug on start, hardware kinds, signal passing). The panel
  uses the new kinds and passes the signal a thread stopped on.
- **The debugger has a panel in the app.** After **Attach debugger…** the
  Debugger tab shows the process, a thread selector, the stop reason and
  address, and **Continue**, **Step**, **Stop**, **Refresh** and **Detach**
  buttons, with the gdb command and a copy button above. Threads and
  breakpoints are on the left (add a breakpoint by address, enable or disable
  it, remove it, or click the dot beside an instruction); the middle column
  disassembles around the instruction pointer with the same decoder as the
  static listing; the right column has the registers with `rflags` decoded
  (`[PF ZF IF]`), `fs_base`, `gs_base` and `orig_rax`, 256 bytes of stack
  from `rsp`, and a memory range you can read by address (up to 4 KiB per
  read). The panel reads only when the process stops or you press Refresh, in
  bounded ranges; each part appears as it arrives, with a spinner beside the
  text still loading. One controller at a time: while the panel drives the
  process, a connecting gdb takes control (the process is stopped for it, as
  gdb expects) and the panel turns read-only, saying it is controlled by gdb,
  until gdb disconnects (which leaves the process running); breakpoints set in
  the panel stay set. Breakpoints can be changed only while the process is
  stopped. Saved process cores keep their own viewer (registers, memory
  mappings and disassembly in Core dumps); they are not opened in the debugger.
- **The debugger follows forks and execs, runs in non-stop mode and survives a
  reconnect or a snapshot.** gdb's `follow-fork-mode` (parent or child),
  `detach-on-fork`, `catch fork`, `catch exec` and vfork work as they do against
  gdbserver: a followed fork or vfork arrives as `fork:`/`vfork:`/`vforkdone:` with
  the child held at the fork (a second inferior; `D;pid` lets one go), an `exec`
  is an event with the new program's path and the session carries on in the new
  image instead of ending (breakpoints of the old image are dropped). `set
  non-stop on` stops and runs threads one at a time (`vCont;t`, `continue -a`,
  `interrupt`, `%Stop` notifications) and memory can be read while threads run.
  After a transport reconnect or a restored snapshot the app adopts the guest's
  sessions again: stopped threads stay stopped and breakpoints stay in place.
  Snapshots are therefore **no longer refused while a debugger is attached**; a
  connected gdb is dropped on a restore (its picture is from another time), the
  panel reads the state again. The panel's Processes list shows forks and execs
  and lets you pick which process to follow (off, parent, child, ask; detach the
  other or keep it), threads show running or stopped (with their signal), and a
  Signals table (stop, print, pass per signal, gdb's defaults: SIGCHLD,
  SIGWINCH, SIGALRM, SIGPROF, SIGURG... nostop noprint pass) is editable and
  remembered; a gdb client keeps its own `handle`. Also fixed: threads created
  while the program runs get hardware breakpoints at their first instruction
  (they missed them until the next stop), and Stop on a program that cannot be
  stopped no longer leaves a breakpoint byte in its memory. The `gdbstub` crate
  is gone: the app speaks the protocol itself (it had no multiprocess, fork
  events or non-stop). Guest series 0041-0042, contract revision 17 (unchanged):
  every addition is optional, an older base keeps working with the Phase 2
  behaviour (a fork's child runs free, an exec ends the session, snapshots drop
  the session) and says what it cannot do.
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
  reports them: Sysmon-style events get `User` (the user's name from the base's
  `/etc/passwd`, or the number when no name is known) and `LogonId` (the audit login
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
  `O_CREAT|O_TRUNC` that made the file is Opened and Created (a create is not
  also Truncated).
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
  counts and are hidden there; "Show failed attempts" lists them (Opened and
  Read always list failed attempts with their result).

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
- **Fixed: the Disks reader could hang, and leave its sandbox running.** When
  the reader stopped, cancelled or timed out a worker, it killed only the
  bubblewrap launcher; the namespace init behind it, in a session of its own,
  could survive and keep the output pipes open, so the thread reading them
  waited for ever (seen under load as a test run that never ended). The reader
  and the Disks conversion jobs now stop the launcher first, kill its
  namespace init and the whole process group, and reap it; their pipe reads
  and thread joins after a kill are bounded. The analysis tool runner shares
  the same helper, and the reader's lifecycle tests now fail after a minute
  instead of hanging.
- **Fixed: a tool that timed out kept running and stalled the analysis.**
  An analysis tool is now started in its own process group, and a timeout or a
  cancel kills the whole group, not only the first process. capa's launcher
  forks the real interpreter, which used to keep running at full CPU and hold
  the output pipe open, so the analysis never finished. A pipe that still
  does not close two seconds after a kill is abandoned instead of waited for.
- **Fixed: a worker deadline discarded the sections that had finished.** The
  analysis worker now publishes its report after every section, and the host
  keeps the finished sections (and their validated full listings) when the
  worker is stopped at its deadline or crashes. Only the unfinished sections
  are marked as not finished. While the worker runs, each section shows what
  it is doing (waiting, running, or its result) instead of "pending
  acquisition". The worker's deadline is now the sum of its sections' own
  budgets, so a slow capa run no longer uses up the time decompilation needs.
- **capa on a statically linked program says why it stopped.** capa analyses
  the whole bundled C library of a static program and often runs out of its
  4 minutes; the Capabilities section now says so.
- **Fixed: a RAM dump on exit looked like a failure.** While QEMU writes the
  RAM dump the VM is paused. A banner now shows "Writing RAM dump 41% - VM
  paused" with a progress bar, Run, upload, capture and debugger actions are
  disabled, and the terminal's automatic resize and the debugger's polling are
  held back instead of being refused with "Failed: the VM is paused while its
  memory is written".

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
  docs/implementation/disks-memory.md.

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
