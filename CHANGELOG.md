# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version says which bases
it runs.

## 0.5.0 — unreleased

Existing bases still cold boot and support disk checkpoints. Full snapshots and
transport reconnect require a new guest base with contract revision 14 / ABI9.

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
- **Malware samples** (Tools): search MalwareBazaar by family, tag, file type
  or hash with your own free API key (ELF only by default; one-click families
  that run on x86-64 Linux), download samples, and send them into the running
  VM, or send and run them as the guest user or root, recorded like any
  program. Samples stay in MalwareBazaar's encrypted archives in the data
  folder and are decrypted only in memory to be sent into the guest: nothing is
  unpacked or run on the host. Each sample shows its processor (only x86-64
  runs in the guests), warns when the VM has NAT on, and keeps every VM it was
  sent into.

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
