# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version says which bases
it runs.

## 0.8.0 — unreleased

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

- **Cloud profile launch advice.** VM configuration offers Routed networking
  for the local simulated metadata service without silently changing saved
  policies, and shows the i440FX-to-q35 RAM fallback before launch. Provider
  metadata references distinguish documented paths from simulated values;
  Vultr's JSON response includes its canary user-data.

- **A replaced debug target stays replaced after it exits.** When the debugger
  is not following exec, the guest keeps that replacement as the reason the
  session ended, including when the new program has already exited before the
  first status query.

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

- **Export the whole Triage as a report.** Triage › Export report… writes the
  run as HTML (one self-contained file), PDF (the same layout, written by the
  app with no browser or network), JSON (versioned schema, documented in
  `docs/triage-report.md`), a MISP event (attributes, `to_ids` only for dataset
  matches, ATT&CK galaxy tags) and a STIX 2.1 bundle (indicators, malware,
  attack patterns, relationships). A dialog has a checkbox per section
  (summary, indicators, ATT&CK, processes, findings, every Files tab, file
  activity and reconstruction, network, detection engines, evidence
  references, custody head), remembered between exports. The report is of the
  whole run: the screen's filters and pages do not apply. Optional evidence
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
  Remove keeps the log with a Removed entry; a full purge is separate and
  recorded in the index chain. The log is tamper-evident, not tamper-proof:
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

- **File activity reads a changed file's earlier bytes from the disk the run
  started from.** At every boot the app records which frozen layers (the
  installed base and any checkpoint) sit under the VM's writable disk. For a file
  the run changed that existed at the start, the window finds it on that disk
  (by path, and by inode, generation, size, owner and time when the guest named
  the inode, so a name another file took over is not mistaken for it) and reads
  its bytes on demand with the sandboxed disk reader over the qcow2 chain; nothing
  is copied into the recording or mounted. Files the run created start empty.
  The window says when earlier bytes are not available: the file is on tmpfs or
  another mount, it is over 1 GiB, the VM's disk already held changes from earlier
  boots when the run started (start from a new VM or restore a checkpoint to keep
  the starting state), a snapshot restore replaced the disk while the run used the
  file, or the base or checkpoint was deleted or changed afterwards.

- **File activity places writes where the kernel put them.** With a
  revision-18 guest, each read and write of a file carries the position the
  file system used, so an `O_APPEND` write and a write through a descriptor
  shared with another process (fork, dup) land at their real offset instead of
  being counted as at an unknown offset, and two processes writing the same
  range at once leave the bytes of the write applied last. A sendfile, splice, copy_file_range,
  reflink clone or fallocate now changes only its own range of the
  destination, with the file's size after it; the bytes a splice from a pipe
  put into a file are shown as written content.

- **A boot's earlier file bytes now live in its recording.** When a VM starts, the
  disk it was left in is sealed under a fresh empty layer (instant, nothing is
  copied), so the boot cannot overwrite it, and a plain restart of a used VM has a
  readable starting state like a new one. When the boot is over and its recording
  is saved, the earlier bytes of only the files the runs changed are copied into
  the recording from the sealed layer, and the layer is merged back down at once:
  at most one extra layer, and only while the VM runs. The earlier bytes then read
  without the base or any checkpoint, even after they are deleted. Two caps, 64 MiB
  per file and 1 GiB per run (Settings › Advanced), keep the copy small; a file over
  one keeps its size and SHA-256 and is listed as not captured. The layer is not a
  snapshot and is never shown in Snapshots; your snapshots are never merged or
  changed (if you take or restore one during the boot, the layer stays in the chain
  as the snapshot's own). If the app or the machine dies mid-run the VM still boots,
  and the next start or launch of the app finishes the copy and the merge. The copy
  is not counted in the Recording quota. Several runs in one boot share the boot's
  starting state; a boot started by a snapshot restore still reads its checkpoint.

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
  VM is archived first, and Run History gains a Sample column and a
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
  kind (dropped, downloaded, executed, loaded). Clicking a label opens the
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

- **Every machine profile value has a public source.** The catalog's strings
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
  by the X11SCL-F. Weights are the number of public reports of each model.

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

- **Container builder for bases.** **Build base…** now offers Automatic plus
  Native, Podman, Docker and the QEMU builder. Podman and Docker build in a
  pinned Debian 13 container (image fixed by digest, package snapshot and exact
  versions), so Debian Minimal's kernel gets Debian's exact banner on any host.
  Automatic takes Native (when the host toolchain is Debian 13's), then Podman
  (rootless preferred), Docker, then the QEMU builder, and falls through to the
  QEMU builder when the image cannot be fetched offline. Each unavailable choice
  says why; Docker's help says it needs root-equivalent access (the `docker`
  group). The image is kept and listed with a Remove button; a build leaves no
  container behind. `scripts/build-base.py --container` does the same from the
  shell.

- **Debian Minimal disks carry GRUB's boot code.** Provisioning runs
  `grub-install` as the installer does, so the VM's MBR and `/boot/grub` hold
  GRUB (and debconf its install device) instead of an empty boot sector.

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

### Guest

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
  one x86-64 hook patch (the series is fifteen patches). No change on x86-64.
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
  run's clock or addresses.

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

- **Guest kernels have BTF, without the recorder in it.** The BusyBox and
  Debian Minimal kernel now builds `/sys/kernel/btf/vmlinux` and module BTF
  like Debian's 6.12.94-1, so systemd's bpf-restrict-fs no longer fails at
  every Debian boot and the missing file no longer gives the VM away to eBPF
  tooling. The recorder's own code is built without debug information, and a
  filter run after pahole (series patch 0019) removes every type, field,
  enumerator, function and variable the recorder's headers leave in stock
  objects; module BTF is encoded against the unfiltered vmlinux BTF and
  remapped, so modules share the filtered types. This also covers the Debian
  desktop kernel, whose BTF (Debian's configuration) named every recorder
  function until now. Every kernel build checks vmlinux and module BTF for
  recorder names (`scripts/check-kernel-btf.py`), and the stealth probe reads
  `/sys/kernel/btf` in the guest. Stock structures the recorder extends
  (`task_struct`, `io_kiocb`, `aio_kiocb`, `io_ring_ctx`, `coredump_params`,
  `io_async_msghdr`) keep their real size and offsets in BTF, with a hole
  where its fields are: names are gone, the layout still differs from
  Debian's, as does the minimal profile's configuration (see
  docs/implementation.md). Building the minimal kernel now needs `pahole`
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
  subsystems, OEM strings and CPU threads. See docs/implementation.md,
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
  docs/implementation.md "Guest stealth" for every check and limit. Bases
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
