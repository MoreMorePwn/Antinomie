# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version says which bases
it runs.

## 0.6.1 — Unreleased

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
  to upload it and open Run program on success. **Open Directory** reveals the
  containing folder; folders have their own directory action. VM and base lists
  leave space for Explorer, including when Base images is folded.
- **Upload browser.** Choose a host folder with the filesystem explorer and
  select a file from an expandable tree. Directory reads run in a background
  worker; large folders have Previous/Next entry controls. Manual file paths,
  executable permissions and overwrite confirmation remain available.
- **Upload and Run.** After a successful upload, open Run program with the
  uploaded guest path. Review arguments and other launch settings before pressing
  Run. Failed uploads, cancelled handoffs and changed VM sessions do not open it.
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
