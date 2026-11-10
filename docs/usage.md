# Using Antinomie

[← Back to the overview](../README.md)

This guide follows 0.8.2. Available controls depend on the application and base
versions; existing VMs keep their pinned base.

## Dependencies and analysis tools

- Linux x86-64 host with glibc 2.39 or newer (WSL2 works with an X11 display)
- QEMU 6.0 or newer (`qemu-system-x86_64`, `qemu-img`) with its GTK display backend;
  on Debian/Ubuntu install `qemu-system-x86 qemu-utils qemu-system-gui`.
  KVM (`/dev/kvm`) strongly recommended; TCG works without it
- `guestfish` (libguestfs) for VMs of the Debian bases: creating, resetting
  and growing their disks and setting up their account. It is in
  `libguestfs-tools` on Debian, Ubuntu and Kali and in `libguestfs` on Fedora,
  openSUSE and Arch; **Tools > App dependencies** checks it and names the
  package for your distribution
- Rust to build the app; building kernels and bases needs the tools listed in
  [CONTRIBUTING.md](../CONTRIBUTING.md). Host source builds also need
  `musl-tools` for the compatibility collector used by older guest bases;
  prebuilt installs do not need that build tool.
- **No internet on the analysis computer?** Build a **full pack** on a connected
  computer with `scripts/build-full-pack.py`: it carries every tool listed below,
  pre-downloaded and checked. Antinomie does not publish a pack. After installing
  the application, extract the pack and run `./install-full-pack.sh`; the tools
  then show as installed in **Tools > Analysis tools**. See
  [the full pack](full-pack.md).
- Memory analysis runs Volatility 3, which **Tools > Analysis tools** (or the
  Memory tab) installs for Antinomie; it needs Python 3 (`python3`). MemNixFS 1.2
  is a second backend for Linux dumps, installed the same way (about 2 MB plus
  two small Debian libraries); it also needs `bwrap`, `prlimit` and the
  system libraries `libyara10 libsnappy1v5 liblzma5 libmagic1 libjansson4`
  (the Memory tab names any that is missing)
- Static analysis runs in a bubblewrap sandbox (`bwrap`). Disassembly, rules
  and identification are built in. Decompilation (Ghidra), capabilities
  (capa), FLOSS strings, UPX unpacking and Detect It Easy use the system's copy when
  installed; otherwise **Tools > Analysis tools** downloads them for Antinomie. The Properties tab
  computes ssdeep and TLSH itself; it also shows Magika's file type when
  **Tools > Analysis tools** has installed Magika (or the system has it)
- The Network tab (packet list and details), Wireshark packet display filters
  and network triage use the installed `tshark` command with `prlimit`
  resource limits; Antinomie decodes no protocol itself. On Debian/Ubuntu install
  `tshark util-linux`; these tools are checked in **Tools > App dependencies**.
  Ubuntu 25.10 and later enforce an AppArmor profile that lets TShark read only
  `/tmp`, `/var/tmp` and Wireshark's own files; Antinomie runs TShark in a sandbox
  that shows each capture under `/tmp`, so the profile needs no change. If a
  message still says Ubuntu's AppArmor profile for TShark refused a file, it names
  `/etc/apparmor.d/local/tshark` as the place to allow the folder.
- Detection rules come from **Tools > Detection rules**, which downloads each
  pack from its publisher (GitHub, rules.emergingthreats.net, sslbl.abuse.ch),
  verifies it and filters it on your computer, only after you allow it; it
  shows each pack's source, license and the hosts it contacts. YARA is built in. IDS scans need Suricata
  (`sudo apt install suricata`, listed in App dependencies). Sigma scans use
  pySigma, which **Tools > Analysis tools** installs for Antinomie; it needs
  Python 3.11 or newer with venv support (`python3-venv` on Debian/Ubuntu).
  The page shows counts under its title (installed packs, how many are enabled,
  custom groups, string patterns); its long explanations are in tooltips.
  The YARA packs are YARA-Forge Core, Elastic protections-artifacts and
  **abuse.ch YARAhub** (community rules shared as TLP:CLEAR at
  yaraify.abuse.ch/yarahub, downloaded from abuse.ch without an Auth-Key). Each
  YARAhub rule names its own Creative Commons license in `yarahub_license`:
  CC0 1.0, CC BY 4.0 and CC BY-SA 4.0 rules are kept, non-commercial and
  no-derivatives rules and rules that YARA-X cannot compile are removed on
  your computer, and the install summary counts each. A rule that duplicates a
  YARA-Forge Core rule (same name, or same strings and condition) is not
  installed twice. abuse.ch rewrites the archive daily, so the pack is a
  snapshot; the catalog is regenerated monthly and Check for updates offers the
  newer snapshot. The pack needs Antinomie 0.8.3 or newer and shows the rule's
  own license with every finding.

- **Tools > Detection rules > IOC** keeps abuse.ch datasets on your computer
  for matching a run's indicators offline: ThreatFox `full.csv`, the URLhaus
  dump (`full.csv`, the URLs that are active or were added in the last 90 days)
  and payload list, Feodo Tracker's `ipblocklist.json` and the SSLBL JA3 and
  certificate lists, which are six on by default. A seventh, URLhaus
  `recent.csv` (the last 30 days), is a smaller choice that is off until you
  switch it on. They are stored in the data folder (about 640 MB together for
  the six), never in the project, and change only when you press
  **Download** or **Update** (or **Download / Update all**); nothing updates by
  itself. Each row shows its records, size, the date it was fetched and its age
  (a warning appears when a dataset is over 14 days old), its terms (Feodo and
  SSLBL are CC0; ThreatFox and URLhaus are free under abuse.ch's fair use with
  an Auth-Key set in **Tools > API keys**) and a switch. **Update** first asks
  the server for the file's real size (a HEAD request) and shows "386 of 450 MB"
  while it downloads, or "386 MB downloaded" when the server does not say;
  **Update all** shows the total of the datasets (marked "about" while some sizes
  are estimates), and the button's hover text shows the typical total before it
  starts. The free-space check uses the real size. A dataset larger than four
  times its typical size is refused before it is fetched, with its size and the
  limit in the message. A download is saved
  whole or not at all: when one fails the previous copy stays in use and the
  status line names the dataset that failed. If abuse.ch answers that it does
  not accept the Auth-Key, the line says so (check the key in **Tools > API
  keys**, or get a free one at auth.abuse.ch); if it answers that the endpoint
  is retired or the file is not there (HTTP 410 or 404) the line says to update
  Antinomie, and a slow-down or server error says to try again later. A dataset
  that needs the key is refused before any request when none is set. Run
  endpoints are matched against IP addresses from Feodo Tracker (botnet C2
  IP:port), ThreatFox (`ip:port` indicators) and URLhaus (URLs and hosts that
  are IP addresses); abuse.ch retired the SSLBL IP list, so Antinomie no longer
  offers it, and a copy left on disk by an earlier version is ignored and
  removed by the next update. The Auth-Key is part of the address abuse.ch serves its ThreatFox
  and URLhaus files from, so Antinomie hands the address to the download
  program out of sight of other users of the computer, and shows it everywhere
  as `/exports/****/`; the key does not appear in the details, the status line,
  an error or a saved report. The same tab lists the **known false positives**
  you have marked, which you can remove.

- **Tools > Detection rules > IDS > abuse.ch** offers five Suricata rule packs from
  abuse.ch: ThreatFox, URLhaus (exact-URL HTTP rules), Feodo Tracker, SSLBL
  JA3 fingerprints and the SSL certificate blacklist. The
  *aggressive* variants, which abuse.ch itself warns produce false positives,
  are not offered. abuse.ch regenerates these files about every five minutes, so
  the tab shows how old each installed pack is and **Check** compares the live
  file with the installed one (a pack is asked at most once in five minutes, even
  if you press the button again); **Update** installs the newest snapshot and
  keeps the old version if it fails. ThreatFox and URLhaus need the Auth-Key in
  **Tools > API keys** (they are sent as `.tar.gz` archives, from which only the
  `.rules` files are taken); Feodo and SSLBL are CC0 and need none. When
  abuse.ch serves the SSLBL JA3 rules file empty, that pack shows **Retired
  upstream** and cannot be installed; the JA3 list is also an IOC dataset.
  Nothing is fetched until you press a button and have allowed downloads.

## 1. Get a base image

The **Base images** section in the left sidebar lists installed bases. Use
**Add base** to get one:

- **Download base…**: fetch a published, checksum-verified base.
- **Import base…**: install a bundle folder you already have.
- **Build base…**: build one with the app's own build kit. Choose **BusyBox**,
  **Debian 13 (minimal, console)** or **Debian 13 (desktop)**. A short wizard asks
  installer-style questions (hostname; for Debian also language, keyboard, time
  zone, software and mirror), then builds where you choose and installs the result.
  **Where** is Automatic or one of Native (this Linux host, needs the tool suite),
  Podman or Docker (a pinned Debian 13 container) or the QEMU builder (a builder
  VM, needs only QEMU and curl). Automatic takes the first that can run: Native,
  then Podman (rootless preferred), then Docker, then the QEMU builder. A choice
  that cannot run says why (tool missing, no subordinate UID range, engine
  missing, daemon not reachable, no permission, image not available). Docker needs root-equivalent access (the
  `docker` group), which is why Podman comes first. The container image
  (`antinomie-builder:<id>`, Debian 13 pinned by digest and package snapshot) is
  built from the app's Dockerfile the first time and kept, so later builds start
  at once; it needs the network once. If Automatic cannot get it (offline), it
  falls through to the QEMU builder and the log says why. The dialog lists the
  kept images with a **Remove** button. A build leaves no container behind.
  Debian Minimal has no desktop: it boots to a console login (the program
  terminals stay in the app, as with BusyBox) and keeps APT. Both Debian bases
  run the same kernel, built with Debian's own configuration, so they install
  Debian's kernel packages and load Debian's signed modules, and the second
  builds in minutes once that kernel is cached. That kernel must report
  Debian's own build string, compiler and linker versions included, so it is
  compiled with Debian 13's gcc-14 14.2.0-19 and binutils 2.44. Native
  uses the host's tools where they are those; on any other distribution it
  compiles in a rootless Debian 13 chroot instead (no root, no container
  engine, no VM): `mmdebstrap` unpacks the packages the container image pins,
  from the same snapshot.debian.org timestamp and at the same exact versions,
  the first time (about 110 MiB downloaded, about 500 MiB on disk) and the
  chroot is kept under the app's build folder and reused. It needs `mmdebstrap`,
  `unshare` and a subordinate UID range for your user (the same as the Debian
  image); the wizard says which toolchain the build uses, shows the chroot's
  size and has a **Delete** button (the next build makes it again). BusyBox
  keeps compiling with the host's toolchain. A Debian Minimal VM whose
  device profile boots UEFI gets a UEFI PC's disk (GPT, an EFI system
  partition, GRUB for UEFI with the shim, a `debian` firmware boot entry): the
  first such VM of a base lays that disk out once (a progress window shows the
  steps; it needs about the base's size in free space), and later ones share
  it. The firmware of an existing VM cannot be switched between BIOS and UEFI;
  create a new VM instead.

Downloads during a build: the Debian bases pin the archive to one
snapshot.debian.org date and check every package against the SHA-256 and size
in that snapshot's signed index. snapshot.debian.org is often slow, so each
package file is tried at the Debian mirror you chose (the build wizard's
mirror; a mirror near you from debian.org/mirror/list), then deb.debian.org
(and security.debian.org for the kernel packages), then snapshot at the pinned
date; a 404 or a file that is not the pinned one just moves on, because no
mirror is trusted. Only the signed InRelease comes from snapshot: the other
index files (Packages.xz) are fetched by hash from the mirrors first and
checked against it. A failing source is retried up to five times (5, 15, 45 and
120 s waits, resuming a partial file where the server allows), and the build log
has a line for every retry and fallback naming the file; the build fails only
when every source has failed, naming them. A kernel that built is kept in the
cache even if a later stage fails.

Bases are read-only templates. Right-click a base to make a **New VM from this
base** or to **Delete base**. Deleting is refused while any VM still uses it.

A VM's device profile can ask for more than its base or this host can give: SATA
or NVMe disks, UEFI, a NAT network of its own or two threads per core need a base
built by Antinomie 0.7.0 or later (or a host with OVMF or a suitable CPU), and a
base built earlier has no list of what it supports. Such a setting is not applied;
the VM starts with the choice every base has (virtio, BIOS, 10.0.2.0/24, one
thread per core). The app says so in several places: the **Device profile**
window lists them at its top and on the setting itself ("SATA (AHCI) not supported
by this base: virtio will be used"), with a **Use base** button when another
installed base supports it; the VM dialog's device profile row shows "N fall back"; the
VM list and the Overview's **Device profile** card carry a **Device profile fallback**
badge; and each start warns in **Activity** and adds the same lines as notes to
every run of that boot, shown under the run's header.

The realistic presets (desktop, laptop, server) report the identity strings of one
real, popular machine model, picked at random when the VM is created and kept for its life, never per boot.
The pick is weighted by how common the model is, and limited to machines the
host CPU's generation was sold in. The BIOS release, the unit (product, SKU, board), the disk
model and the memory part come from what real units of that model report, so two
VMs of the same model differ, as two such machines do. The catalog's
`SOURCES.md` names a public hardware report for every value, and the weight is how
many public reports of the model exist. A run's details show the
machine its guest looked like. RAM size and disk size stay the VM's own settings.
The model catalog is in `src/antinomie/monitor/crates/monitor-core/src/stealth/catalog/`;
the names belong to their owners and imply no affiliation or endorsement (see
[Trademarks](../README.md#trademarks)).

On Debian Minimal the network card sits where the profile's machine has its
built-in LAN, so the interface has that machine's name: `enp0s31f6` for the
Intel desktops and laptop (their I219 at PCI 00:1f.6), `eno1` for the
Supermicro servers (a board LAN that firmware numbers; the card keeps PCI 00:19.0
and gets ACPI index 1), `enp0s25` otherwise. A VM already on the old X12STH-F
slot keeps `enp0s31f6` until its machine is changed (0.8.0 replaces that profile
with the X11SCL-F, which has public reports). Changing the profile to a machine with another slot moves the card
and rewrites the VM's network configuration when you save; a VM with snapshots
keeps its slot (delete the snapshots, or pick a machine with the same chipset).

Each snapshot records the device profile the VM had when it was taken (machine,
serials, UUID and MAC address, network card, CPU, disk bus, firmware). A snapshot
only restores under that same profile: if the VM's profile was changed since, the
restore dialog says "This snapshot was taken as <machine>" and its button becomes
**Switch profile and restore**, which gives the VM that profile and then restores.
The current state is saved first when you ask for that, with the current profile.
A snapshot taken before profiles were recorded has no profile to compare; it
restores as it is, and the result says so.

## 2. Create a VM
Choose **New VM**, pick the installed base, and set name, CPU count, RAM and
disk size. Debian bases (desktop and Minimal) also ask for a username and
password; the guest account is created for you. Debian Minimal needs at least
1024 MiB RAM and 4 GiB disk. Each VM gets its own disk layered on the base, so
the base never changes.

Right-click a VM for **Rename**, **Duplicate** (the VM must be stopped),
**Open Directory**, **Settings** (resolution, **VM screen**, fullscreen or fit to
window, acceleration, CPU model) and **Delete**.

**VM screen** says where the VM's display shows and applies at the next start of
the VM, not to a running one: **In the app (VNC)** (the default) opens the VM
screen tab, **QEMU window** opens QEMU's own window (fullscreen and fit to window
are options of that window), and **No screen** runs the VM with no display at all
(`-display none`, no VNC). With No screen, **View > VM screen** opens a tab that
says the VM has no screen and how to change it. The guest sees the same devices
in all three.

On the VM screen tab, a click on the picture captures the keyboard for the
guest. While it is captured the picture has an amber frame and a banner,
"Keyboard captured. Press Ctrl+Alt to release it.", and the bar above reads
"Keyboard captured". Ctrl+Alt gives the keyboard back; so does the window losing focus, or
another tab coming to the front. No app shortcut fires while it is captured.

The **Overview** (the first tab of the work area) shows the selected VM: its name
and state dot, the resource cards, the **Compute** card with the vCPU count and
the RAM side by side, the configuration cards and the **Snapshots** box.

The sidebar's **Explorer** title has a folder button that chooses the folder to
browse; **File > Open folder…** does the same, and **File > Import sample…** opens
the Samples page's **Add file** dialog.

**Settings → Telemetry transport…** tunes how records leave the guest (bases
for Antinomie 0.3.0 and newer):

| Setting | Effect |
|---|---|
| Guest buffer per vCPU | 256 KiB to 4 MiB of guest memory per virtual CPU (default 1 MiB); bigger buffers ride out longer bursts |
| When buffers fill | **Never drop** (default): a system call waits until the host has room, so heavy tracing can slow the guest; its wait deadline can still cause counted drops. **Drop new telemetry**: the guest never waits (keeps its timing) and the loss is counted |
| Longest wait per event | In Never drop mode, how long one call may wait (default 5 s) before its record is dropped after all |
| Capture All: drop telemetry when the host falls behind | Off (default): Never drop holds under Capture All too, so a busy guest runs slower (a heavy BusyBox load about 10 times slower) and Triage > Summary says it is being slowed. On: while Capture All runs and the host falls behind, the guest drops telemetry instead of waiting, which keeps a desktop guest responsive but loses events; the Summary counts how often and how long. Drop mode ignores it |
| Host event table | How many calls the host keeps assembling at once (default 16,384) |

The VM's **Overview** shows a **Snapshots** box under **Device profile**: the VM's
snapshots as a compact tree (name, whether it is disk only or disk + memory, when
it was taken, its size, its notes, and a **Current** marker on the one the VM runs
from) with **Take snapshot…**, **Restore…** (**Resume…** for a disk + memory
snapshot that can resume, and **Restore disk and boot…**) and **Open Snapshots…**
for the full window. It uses the Snapshots window's own dialogs and rules, so
what is allowed while the VM runs is the same in both, and the list refreshes when
you select the VM and when it starts or stops. The label column of the Overview
cards is as wide as its longest label.

## 3. Start it and run a program

Saved **Syscall trace** recordings have a **Go to page** number beside
**Calls/page**. Type a page number directly instead of stepping through arrows.
Calls/page accepts any positive signed 64-bit value; **0** or **-1** shows all
matching calls in one scrollable table. Large pages and all-matches mode load
visible rows in windows of at most 256 calls, with a 64 MiB preview budget;
they do not copy the entire recording into memory. A first jump through a
filtered recording can scan the preceding matches in the background. Revisited
ranges of finalized recordings reuse a bounded cursor cache. Unfinished
recordings seek from the start because arriving results can change earlier
filter matches. Column sorting applies to the loaded window.
Core strings and saved memory-analysis results also offer direct page entry;
packet history already has it, and specimen Content supports a byte-offset jump.

1. Select the VM and press **Start VM**. Only one VM runs at a time, and its
   network is disconnected by default. A VM with no snapshot asks first: there
   is nothing to restore after the run, so what the program changes stays in the
   VM's disk (take one in **Snapshots**). **Start anyway** starts it; **Don't ask
   me again** turns the question off, and **Settings > Notifications > Start**
   turns it back on.
2. **Upload file** copies a program from the host (**Host file**) to a path in
   the guest (**Guest path**).
3. **Run program** runs it. Set the **Executable**, **Arguments**,
   **Working directory** and **Environment**. **User** is Root, Normal user
   (1000), Nobody (65534, the unprivileged account every system has) or a custom
   UID and GID. Under **Dumps**, **Dump when suspicious activity is seen** has
   a **Minimum tier** of Low, Medium or High: the first finding at that tier or
   above takes the dump. The trigger watches x86-64 and arm64 runs alike, 32-bit
   programs (i386, AArch32) included. A run whose trigger took nothing says so in
   its notes: either no rule of that tier matched while the program ran, or the
   matches came too late (the process or the recording had ended), with the
   reason. **Memory Dump on Exit** and **Core Dump on Exit** sit
   below the trigger's options in the same section. Each launch gets its own terminal
   window for input and output.
   A library sample's window has **Load into…**: give a program (and its
   arguments, split on spaces) and it sends the library into the running VM, then
   opens **Run program** with that program and `LD_PRELOAD` set to where the library
   landed. The run is linked to the library sample (see the **Runs** list in section 5).
   On a VM with a desktop base, **Run in** picks where the program runs:
   **App terminal** (the default), **Guest desktop** (the program joins the
   graphical session, so its windows appear on the VM screen; its output
   stays in the app terminal) or **Guest desktop terminal** (a terminal
   window on the VM screen runs it). Both desktop choices need the run's user
   logged in on the VM display; otherwise the app terminal says so.
4. **Stop** ends a run together with all of its child processes. Closing a
   terminal window does not stop the program, which keeps recording; the run
   is shown as still going (and **Stop** stays available) until its processes
   end. When a run's program tree really ends, a toast says "Run 3 finished"
   with the program, how long it ran and how it ended, with **Open Triage**
   (and **Open sample** for a library sample). A root that exits while children
   live on does not toast until the run ends. See *Run states* below and
   **Settings > Notifications**.
5. **Static Analysis** in the launch dialog analyzes the program's file before
   it runs; pick the categories, from triage to disassembly and decompilation.
   **Strings** and **Regex matches** are two choices (Triage, on by default): the
   regex patterns are matched over the strings and listed in the Regex matches
   tab, which needs Strings or FLOSS strings. **Unpacking** (Triage, on by default) looks for UPX packing; a packed file is unpacked
   (without ever running it) and the result is a **layer** with its own hash and
   its own static analysis. See **Static Analysis > Unpacking** below.
   **FLOSS strings** (under Deep analysis, off by default) recovers the strings a
   program builds on the stack or decodes at run time, which Strings cannot see;
   it needs FLOSS from **Tools > Analysis tools** and can take several minutes
   (a statically linked program may hit its 8 minute limit). FLOSS reads the file
   with its own disassembler and emulates snippets of it; the program is never
   run. Results are in the **FLOSS** tab beside Strings, one row per string with
   its type (decoded, stack, tight, or language for Go and Rust strings), its
   encoding and the address FLOSS reports for the routine. Files over 16 MiB are
   not taken.
   When you run a file you just sent with **Upload and Run**, static analysis uses
   the copy still on the host instead of reading the program back from the guest,
   but only if the guest's own hash of the file that ran equals the hash of that
   copy. If the file is gone, differs (the program rewrote itself, or another file
   ran) or the guest recorded no hash for it, the program is fetched from the
   guest as usual. The **Specimen source** row of the report's Identity card says
   which happened ("host copy, hash matched guest" or "fetched from guest"); the
   evidence identity is the guest's hash either way. On a base of contract
   revision 22 the guest gives the hash of the copy it keeps in its launch reply,
   so the host copy is used even for a program that exits within milliseconds,
   and its analysis goes on after the VM stops; an older base sends the hash a
   little later, and a VM stopped before it arrives ends the analysis.
   A launch the guest refuses (it cannot load the file) still gets the static
   analysis you selected: the file is read from the guest's disk (on a
   revision-22 base the host copy stands in once its hash matches), and the run
   stays in **Run History** as "Failed to start" with its report, so the analysis
   can say what the file is. When the file cannot be read either, the run is not
   kept, as before.
6. **Attach to process** traces a process that is already running in the guest
   (and its future children); **Capture all** traces all of userspace. Neither
   stops or signals anything. A capture lists the processes it saw as a tree
   (named after the program each one ran); select one to see only its calls.
7. With the guest network connected, select **Capture network** to record
   packets of the VM's network interface outside the guest. Stop it to finish the capture;
   each start creates a separate retained pcap in the boot recording.
   On a Routed VM, **Route** in the same section picks where the run's traffic goes
   (see *Network routes* below).

## arm64 guests (0.9.0)

Antinomie also runs arm64 Linux guests: a BusyBox arm64 base (Debian 13's
arm64 BusyBox and e2fsprogs packages with the patched 6.12.94 kernel built for
arm64) runs arm64 programs and, on the same kernel, 32-bit ARM (AArch32)
programs. On an x86-64 host QEMU emulates the CPU (TCG, no KVM), so an arm64
VM is several times slower than an x86-64 one; it always starts with TCG and
its waits (**Tools > Settings > Advanced**, TCG multiplier). Its screen shows
on the VM screen tab or in the QEMU window, as for x86-64 VMs. The host needs `qemu-system-aarch64`, AAVMF
(`qemu-efi-aarch64`) for the UEFI machines below and `gdb-multiarch` for the
debugger console.

**Getting a base.** The Build base wizard builds x86-64 bases. Build an arm64
BusyBox base with the kit and import it (**Add base → Import base…**):

    echo '{"format":1,"profile":"busybox","arch":"arm64"}' > job.json
    scripts/build-base.py --job job.json --inputs INPUTS --work WORK --output BUNDLE

It cross-compiles the kernel with Debian 13's `aarch64-linux-gnu-gcc-14` (the
container image and the toolchain chroot have it) and takes its programs from
Debian's pinned arm64 packages, so no arm64 program runs on the build host.
A run's details name the guest's architecture.

**Debian 13 arm64 Minimal.** Its bootstrap runs arm64 maintainer scripts, so
it needs a CPU emulator for them and is never built natively on an x86-64
host. It builds in the container builder when the host has an enabled
`qemu-aarch64` binfmt handler with the F (fix-binary) flag, which a container
shares with the host kernel; register one with

    docker run --privileged --rm tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0 --install arm64

(qemu 10.2.3; it lasts until the next reboot, and `--uninstall qemu-aarch64`
removes it), then `scripts/build-base.py --job job.json --container docker ...`
with `"profile": "debian-minimal", "arch": "arm64"` in the job (about 25
minutes on a 16-vCPU host, kernel included). Without the handler a container
build is refused with what is missing, and it builds in the QEMU builder VM,
which brings its own emulator: from a source checkout,
`ANTINOMIE_BUILD_ARCH=arm64` with the `build-base` example (`build-base DATA
debian-minimal qemu`) builds it and installs it in the data folder DATA (more
than five hours on a 16-vCPU x86-64 host without KVM: the builder VM is
emulated and the arm64 programs are emulated again inside it). Creating a VM of
it asks for the account as on x86-64 and takes longer: the host's disk tools do
what needs no guest program, then the VM boots once by itself, without a
network card, to make the account, GRUB (on a UEFI disk) and the initramfs with
its own arm64 programs, and powers off (about half a minute under TCG). The
password goes in over QEMU's fw_cfg and is never written to the disk. If that
boot fails or takes more than 15 minutes, the creation fails with the reason
and leaves no VM. Then start the VM and log in with the account, as on x86-64.

**What works.** Everything an x86-64 BusyBox VM records: every system call
(by arm64's own numbers and names), file activity and contents, captured
programs, packets and routes, io_uring and AIO, notes, Triage, Sigma, the Files
and Network tabs, process cores, snapshots, and the debugger (gdb-multiarch;
the Code pane disassembles with Capstone; hardware breakpoints and write and
read watchpoints).

**32-bit ARM programs on an arm64 guest** (a base of guest revision 21 or
later) have cores and a debugger too:

- **Core view.** An ELF32 core opens like an arm64 one. The Context tab lists
  r0-r12, sp, lr, pc, cpsr and orig_r0 (the VFP registers d0-d31 and fpscr
  under their own heading); the other tabs show the mappings, captured memory,
  mapped files, auxv, the fault address and the process name. **Disassemble**
  decodes ARM or Thumb: at a thread's pc the CPSR T bit decides; at another
  address a set low bit (a Thumb symbol) means Thumb, and a function chosen from
  a symbol binary uses its symbol's mode; any other address is ARM. The header
  line of the listing says which mode it used.
- **Debugger.** The panel recognises the program at the first stop (its
  registers are 32 bits wide) and shows r0-r12, sp, lr, pc and cpsr with its
  flags (`T` is Thumb state). The Code pane decodes in the pc's state, marked
  ARM or Thumb; clicking the gutter sets a 4-byte ARM trap in ARM state and a
  2-byte Thumb trap in Thumb state (instructions before the current one in
  Thumb are a best guess). gdb-multiarch gets the `arm` target description
  (core, VFP and TPIDRURO registers); gdb's breakpoint kinds are honoured:
  4 is an ARM trap, 2 and 3 a Thumb one (a 32-bit Thumb-2 instruction too),
  and gdb picks the kind from the pc's state or the symbol. Single-step moves
  one ARM or Thumb instruction. Hardware breakpoints are ARM code only (a
  Thumb breakpoint is a software one); hardware watchpoints are unverified for
  AArch32. A breakpoint inside a Thumb IT block is planted as asked: the
  guest does not refuse it, but whether it traps when the block's condition
  fails is architecturally unpredictable.
- **Older bases.** A base of guest revision 20 or earlier has no AArch32 core
  writer and debugger. For a library sample known as 32-bit ARM, Core Dump on
  Exit and Debug on start are refused before the program starts, naming the
  revision 21 base they need. For any other program the guest's own refusal is
  explained the same way: the core's failure reads "needs a base of guest
  revision 21 or later" (not "state 5, status -95") and Debug says the guest's
  debugger refused the program.

**Device profiles.** An arm64 VM does not present a PC. With a realistic preset
it presents an arm64 machine of the preset's kind, the same one for the VM's
life: an Ampere Altra server (Gigabyte R272-P33, HPE ProLiant RL300 Gen11) or
workstation (ADLINK Altra Developer Platform), or an AWS EC2 Graviton2 instance
for Cloud VPS, all booting UEFI (AAVMF) with that machine's SMBIOS tables, ACPI
OEM IDs, CPU (MIDR and timer frequency), network card and SATA disk; with BIOS
firmware, a Raspberry Pi 4 Model B or Pi 5 on a disguised device tree. The
**Device profile** window shows the arm64 machine list instead of the PC
catalog (pick one, or let the preset pick by the VM's UUID), the machine's CPU
instead of the x86 CPU settings, and, under **Still visible**, what an arm64
VM still gives away (instruction timing under emulation, QEMU's ACPI tables to
root, the PCIe host bridge, no CPU cache sizes, the emulated display). **Faster
emulation (KPTI off)** in the VM's settings boots without kernel page-table
isolation, which emulation runs slowly; a program can notice, and Still visible
says so.

**What does not work on arm64.** The app says so where it applies:

- **Memory analysis.** Volatility 3 and MemNixFS read x86-64 guest memory only
  and an arm64 base carries no symbol table: the Memory tab of an arm64 VM says
  so instead of offering plugins.
- **capa and FLOSS** analyse x86 and x86-64 programs only: Static Analysis
  reports them as unavailable for an arm64 or ARM program ("capa finds
  capabilities in x86 and x86-64 programs only; this program is for AArch64"),
  and the Run form warns when they are chosen on an arm64 VM. The other checks
  (metadata, structures, strings, entropy, hardening, rules, identification,
  disassembly) read arm64 programs. Disassembly decodes AArch64 and 32-bit ARM
  (ARM and Thumb, chosen by the ELF mapping symbols, or by the entry point's low
  bit in a stripped file) with the built-in Capstone, not the host's `objdump`;
  big-endian ARM is reported as unavailable. A check that is unavailable does not
  make the analysis **partial**: it shows as unavailable in its own category, and
  the analysis is partial only when a check stopped short (a limit, a timeout).

An app older than 0.9.0 refuses an arm64 base before it starts QEMU ("this
Antinomie does not start arm64 VMs yet").

## Network routes

A VM whose network is **Routed** (VM dialog > Network) lets you choose, for each
run, where the sample's traffic goes. Between runs a Routed VM has a working
network card and an address, but nothing leaves. Everything runs as your own
user: no root, no firewall rules, no VPN client on the computer.

| Route | What the sample can do |
|---|---|
| **None (drop)** | Nothing leaves. Connections and DNS go unanswered; the attempts are still captured. |
| **Internet** | Connect to public addresses through this computer's connection. It cannot reach this computer or your local network unless you allow private addresses. |
| **InetSim (fake services)** | Every name resolves to a fake address and every connection reaches a fake service (HTTP, SMTP; other ports accept and discard). Nothing leaves. |
| **Tor** | Connect through Tor, which Antinomie starts for the run (or through a SOCKS address of your own Tor); Tor resolves the names. |
| **VPN (WireGuard)** | Connect through a WireGuard tunnel run by wireproxy (userspace, no root). |
| **SOCKS5 proxy** | Connect through a SOCKS5 proxy you give (optional user name and password). |

Pick the route in the Run form (**Network > Route**); the default comes from
**Settings > Network routes**, where the other settings are too:

* **Tor**: either *Antinomie runs its own tor* (the default) or *Use a SOCKS
  address*. With its own tor, Antinomie starts `tor` when the run claims the
  route, on a free port of `127.0.0.1`, with a private data folder under its data
  folder (`network/tor/<VM id>`, readable by you only) and no control port, and stops it
  when the run ends. The folder belongs to the VM and is kept between its runs,
  so later runs reuse the consensus and guards that the first one downloaded and
  start faster; only one tor uses it at a time. The run waits for Tor to finish
  bootstrapping (up to two minutes). A start that makes no progress, or whose tor
  exits, is tried once more (after an exit with the cached state cleared), and
  the run does not start if the second try fails. Folders of VMs not used for 30
  days are removed. The other mode connects to a Tor you run yourself
  (a `tor` service listens on `127.0.0.1:9050`) and starts nothing.
* **Getting Tor and wireproxy**: you do not have to install them. A program you
  name in Settings is used first, then one on `PATH` or in the usual system
  places, then the copy Antinomie installed. Under the Tor and VPN settings the
  page shows each program's status (on this system, installed by Antinomie with
  its version, or not installed) and an **Install** button. Install downloads the
  pinned release (wireproxy 1.1.3 from GitHub; the Tor Expert Bundle 15.0.26,
  which holds tor 0.4.9.14, from archive.torproject.org), checks its SHA-256 and
  unpacks it into your data folder. **Remove** deletes Antinomie's copy.
  Downloads need `curl`; nothing is downloaded until you press Install.
* **VPN**: a wireproxy configuration file with your WireGuard peer and a
  `[Socks5]` section (`BindAddress = 127.0.0.1:25344`), and the wireproxy program
  if you want a different one than the above. Antinomie starts wireproxy for the
  run and stops it afterwards. OpenVPN is not supported: it needs a TUN device, which needs root.
  If you have OpenVPN, run it yourself in a container with a SOCKS5 front end and
  use the SOCKS5 route.
* **SOCKS5**: host, port and optional user name and password. The password is
  saved in your data folder, readable by you only, and never shown, logged or
  exported.
* **InetSim**: the built-in services, or an INetSim of your own. INetSim must
  listen on high ports, because you run it as yourself: a guest connection to
  port P goes to P plus the *port offset* (10000 by default). In `inetsim.conf`
  that is, for example, `service_bind_address 127.0.0.1`, `http_bind_port 10080`,
  `https_bind_port 10443`, `smtp_bind_port 10025`, `ftp_bind_port 10021` and a
  `start_service` line for each. Antinomie answers DNS itself (every name resolves
  to the fake address), so INetSim's DNS service is not used. The built-in
  services have no TLS: HTTPS needs INetSim.
* A **Test** button for each route brings it up the way a run would and says
  whether it answers.

**Network wait before a run (0.9.0).** A program started before the guest has
its address gets "network is unreachable" (ENETUNREACH) for every connection: a
Debian guest under TCG can take 20 s after its boot wait to finish DHCP, and a bot
that kills the DHCP client early leaves the run with no network at all. The
gateway is the guest's DHCP server and router, so on a Routed VM the launch waits,
after the boot wait, until the guest has its address: it has sent a packet from
the address the gateway's DHCP gives, or answers the router's ARP request for it
(the gateway asks once a second while it waits; nothing runs in the guest). The
wait is **Tools > Settings > Advanced > network wait before a run**
(`start.network_wait_secs`, 30 s at KVM speed by default, stretched by the TCG
multiplier; 0 turns it off). A guest that still has no address then gets the
program anyway, with a note on the run, and later launches of the same boot do
not wait again. `run.json` records the wait under `boot_wait.network`. Triage's
notes count the calls that failed with ENETUNREACH, say from when to when, whether
the network came up later, and what the wait did.

A route that cannot start stops the run with the reason; Antinomie never falls
back to another route, and in particular never to the plain Internet. The route
is checked before the sample starts. Over Tor, VPN and SOCKS5, UDP other than DNS
is dropped (the network capture still shows the attempts), and a name that does
not exist shows as a refused connection. Ping is answered only for the gateway
itself; IPv6 is not carried on any route.

The route a run used is recorded with the run. It is shown in Run History's
details, above Triage, in **Triage > Summary > Network evidence** and in
**Triage > Network**, with what the gateway counted once the run ended. Runs from
before routes existed read **Not recorded**. A VM that is not Routed has one fixed
network (shown as the run's route); to choose per run, set the VM's network to
Routed. A VM has one route at a time, so runs that overlap must use the same one.
The network capture is the guest's own view on every route.

## 4. Read the results

- **Syscall Trace**: every recorded call with its arguments, return value and
  captured data. Flags and options are decoded into names (for example
  `O_CREAT | O_CLOEXEC`, `SOL_SOCKET / SO_RCVBUF`, `PR_SET_NAME`), unknown bits
  are listed separately, and captured buffers can be inspected byte by byte.
  Captured data reads by its type: strings quoted, socket addresses decoded,
  data buffers quoted with every byte (binary bytes escaped as `\x..`), and
  these structures by their members: signal sets as signal names
  (`[SIGINT SIGTERM]`), `siginfo_t` by the branch its `si_code` selects,
  `sigevent` by `sigev_notify`, `stack_t`, bpf's `union bpf_attr` by the
  command that passed it, capget/capset headers and capability sets by name,
  directory entries (getdents), group lists and the ids getres*id wrote,
  `file_handle` headers, `io_uring_params`, System V messages (`mtype`,
  `mtext`), iptables table headers and LDT entries. Selecting such a field
  lists every member. Every other captured layout that the member inventory
  of the run's architecture describes is decoded from its members by one
  layout-driven reader: times as durations (`1.5 s`; absolute times as dates),
  `epoll_event` (12 bytes on x86-64, 16 on aarch64), `sigaction` (handler,
  `SA_*` flags, mask as signal names), `flock`, `open_how`, `clone_args`,
  `user_regs_struct`, `rlimit`, `stat`/`statx`/`statfs`, socket option values by
  level and name (`on`/`off`, `SOCK_STREAM`, `ucred`), `msghdr`, wait4 status
  (`exited 0`, `killed by SIGSEGV`), select's descriptor sets (`fd 3`), the
  descriptor pairs of `pipe`/`socketpair`, and more, with nested structures
  and arrays as an indented tree in Details; the hex dump of the raw bytes stays
  below it. Arguments that are plain numbers read by name where they hold flags
  or enumerations (inotify and fanotify masks, `access` mode, the socket
  protocol by family, memory-policy mode, `ITIMER_*`, `fcntl` arguments by
  command, `prctl` sub-arguments). A 32-bit (compat) program's structures are
  read by the compat inventory (`ia32`, AArch32); where it has no layout the
  bytes show undecoded with a "No compat layout" note, never read with 64-bit
  offsets. Decoded fields are also in the trace JSON export (`decoded_fields`)
  and in the `records` filter text. Integers and pointers of layouts nothing
  decodes show in hex.
  Hand-written readers cover the layouts the inventory cannot describe: AIO
  (`iocb`, `io_event`, `__aio_sigset`, the pointer arrays of `io_submit`),
  io_uring (`io_uring_sqe` with the opcode and `IOSQE_*` flags by name, the
  rings, the probe reply, the extended `enter` argument, the buffer ring), CPU
  and NUMA masks as lists (`0-3,6`; `sched_setaffinity`, `mbind`, io_uring's
  worker affinity), signal frames (`rt_sigframe` on x86-64 and aarch64: where
  the handler returns), the floating-point and extended state as a summary of
  the components in use, `uretprobe` registers, and `PTRACE_GETREGSET` /
  `SETREGSET` register sets by note type and length (aarch64 `x0`-`x30`, `sp`,
  `pc`, `pstate` as `EL0t N|C`; AArch32 `r0`-`r12`, `cpsr`). Rows show a
  decode of the first 256 captured bytes; the selected call's Details re-reads
  up to 64 KiB of the capture so long frames and register sets (aarch64 `pc`,
  `pstate`) decode whole when the recording is readable. Socket
  addresses cover `AF_UNSPEC`, netlink (pid, groups), packet (protocol,
  interface, hardware type, packet type, MAC), vsock, ALG and CAN.
  `perf_event_attr` names the event by type and config (hardware, software,
  cache, tracepoint) and gathers the option bits as `flags`; SysV IPC and quota
  times read as dates and their flag words by name; LSM contexts show the module
  and label. A 32-bit program's wait status, socket options, select sets,
  `fcntl`/`prctl`/`fanotify_mark` arguments and masks read the same way.
  A captured **array of records** (directory entries of `getdents`/`getdents64`,
  `cap_data`, `gid_t`, `siginfo_t`, `desc_struct`, `pollfd`, `sembuf`, the
  control messages of `sendmsg`/`recvmsg`, classic BPF filters of
  `seccomp`/`prctl`/socket options, `futex_waitv`, `kexec_segment`, eBPF
  instructions and the BTF func, line and CO-RE relocation records, and plain
  `u32`/`u64` arrays) shows as "N entries" with one line per record (a dirent's
  name and type, a pollfd's descriptor and revents, `SCM_RIGHTS` descriptors, a
  BPF instruction as assembly, a seccomp filter with its action and
  `seccomp_data` field names), each opening to its fields. **Copy row as JSON**,
  **Copy all as JSON** and **Save as JSON** (into `records/` beside the run's
  files) carry the records. The preview holds the first 256 bytes;
  **Decode all captured (M bytes)** reads the field's whole evidence (up to
  16 MiB) and decodes every record, 100 a page, with "showing X of Y". A record
  the capture cut, or whose length field cannot be right, is named instead of
  dropped. The trace filter reads decoded records (`records contains "name"`, or a
  plain word), and a trace row's menu copies the call's decoded records as JSON.
  Records are decoded on x86-64 and arm64 guests, and for ia32 and AArch32
  programs where the compat inventory has a layout.
- **Run History**: every run on the selected VM, including earlier boots, with
  its command line, user, status and exit code. The state is coloured (see
  *Run states* below). Double-click a run to open its
  Triage view. Select a trace entry to inspect its recorded call details.
  The table spans the pane. A run's process tree scrolls inside its own box, which stops short of the details' scroll bar so the two never overlap. A run's details list **Analysis enabled** as a tree:
  the static analysis with its checks below it, then the capture options; a check
  that produced no result, or a capture that was deleted or failed, is greyed.
  In a process's Details, **Show its calls** opens **Syscall Trace**
  filtered to that process (clear the filter to see all).
- **Export report…** (right of the Triage tabs): writes the whole Triage as
  HTML, PDF, Markdown, JSON, MISP or STIX 2.1, with a checkbox per section,
  optional IoC defanging and an optional evidence bundle. The key findings are
  a table, and every process, file, endpoint, domain, rule, finding, detection
  and technique a report mentions is a link to its entry (the PDF has a
  contents block and internal links). See
  [the report guide](triage-report.md).
  The export reads the run with no filter. When Triage already indexed the run
  and its recording has not changed since, the report is built from that index
  and the recording is not read again, whatever the tables on screen are
  filtered to. A recording over 1 GB that has to be read is warned about in the
  dialog first, with an estimate (about 70 minutes for 3.5 GB; Export becomes
  **Export anyway**); the progress line and **Cancel** work as always.
- **Other exports** (Summary > Indicators **Export**, the IOC tab's CSV and JSON,
  eBPF **Export binary and JSON**, Static analysis **Export**, **Export custody
  record…**) name what they write `antinomie-<kind>-<run or sample, 8
  characters>-<yyyymmdd-hhmmss in UTC>Z.<ext>` (the Static analysis export keeps
  its analysis id and the eBPF export its program hash), tell you in a toast and
  an Activity row (file, size and folder), and open in a folder that is not your
  home folder: the run's `ioc` or `bpf` folder, or `exports/static` and
  `exports/custody` in the data folder (made on the first export), or the folder
  the last export of that kind went to (a custody export never opens where a
  static-analysis export went). The eBPF export names its files after the
  capture, so a second press says "Already exported: <name> in <folder>" beside
  the button instead of failing. **Export custody record…** gives a path on
  this computer (an import, a deleted original) as its file name only and marks
  the entry withheld; `verify-custody.py` still checks every link and says which
  entries it took as recorded. **Keep paths on this computer** keeps them.
  A run's Data window **Copy** copies the format shown, and Hex
  for bytes the text views would change (UTF-8 for bytes that are not valid
  UTF-8, ASCII for control bytes); **Copy as** switches those two off for such
  bytes.
- **Triage › Process › Process tree**: one row per task, in the columns
  **Process** (tree lines, the executable's file name and `(pid · tid)`; the
  full path on hover; a fork that has not exec'd shows its parent's image
  greyed with "fork"), **Argv** (every argument shell-quoted, so `sh -c 'curl x | sh'` stays unambiguous; hover numbers them as `argv[0] = sh`, `argv[1] = -c` with the count and any argument cut short; no warning sign: an
  argv[0] whose file name is not the executable's is the Suspicious activity
  finding **Hiding the process name: argv[0] rewritten**, counted in Findings; BusyBox applets,
  interpreters through symlinks such as python3 and python3.13, sh and dash,
  and a login shell's leading `-` do not count), **Findings** (the count,
  coloured by the worst tier; click it to list that process's findings),
  **User ID** (the numeric uid, or uid → euid, from the guest's credential
  records; hover for the name where it is known, such as root),
  **Started** (relative to the run start; the absolute time on hover),
  **Lifetime** ("running" when no exit was recorded), **Outcome** ("exit 0",
  "killed by SIGKILL", "killed by SIGKILL (from pid N)" when a recorded kill
  call sent it, "in read() at end"), **Calls** and **Exec chain**
  (`sh → busybox → demo-all`). The parent pid, working directory and task
  cookie are not columns; filter on `process.ppid` and `process.cookie`.
  Click a row to open **Details**: the executable, arguments one per line, the
  full environment of its last exec (+ added, ~ changed, − removed against its
  parent's, with the Triage rule that flagged a variable), the working
  directory when the task changed it, the user and credential changes, the
  parent and the children (click to jump), the exec chain with times, the
  outcome and its findings. **Show its calls** opens the Syscall Trace
  filtered to the process.
- **Triage › Process › Suspicious activity**: behaviour recognised in the run's
  calls, kernel records and packets, worst tier first and each tier in the order
  it happened. The columns are **Tier** (a coloured H, M, L or I chip: hover it
  for what the tier means and why this row has it; a flag after it says the
  evidence is of limited confidence, and why), **Behaviour** (a short title;
  the rule id and its version are on hover), **Target** (the path, `ip:port` or
  process the behaviour was aimed at), **Process** (`name (pid · tid)`; click it to
  open that process in Details), **ATT&CK** (the technique, `T1053.003 Cron`; click it to list the
  rows that cite it), **Count** (`×12`, or `×40 every ~5.0 s` for a steady
  loop), **Result** (succeeded, `3 of 5 failed` or `all failed`, greyed) and
  **When** (the first and last time, as offsets from the start of the run;
  the clock times are on hover). The category, confidence, evidence, version,
  source and flags are in Details; every filter key still works. A row has a
  tier (HIGH, MEDIUM, LOW; INFO is only counted unless **Show INFO** is on).
  **Retries a dead command server** (`network.dead_c2`, Medium) is the loop of a bot
  whose command server is gone: ten or more connects to one public address and port
  failed (refused, timed out, network or host unreachable) and none ever succeeded,
  counted over the whole run and across the processes that made them. Fewer tries are
  ordinary retry noise. DNS (port 53), NTP, DHCP and mDNS, loopback and private
  addresses, and the base image's own programs (time sync, DHCP, apt) are never counted,
  and one successful connect to the address clears it. The row appears at the tenth
  failure and counts the failures from there on (**Count** and **Result** read
  `all failed`), with the last error in Details. A non-blocking connect that only
  reports "in progress" is neither a failure nor a success.
  Repeats fold into one row with a count.

  The tiers mean: **High**, something ordinary software essentially never does
  and that directly gives control, persistence or privilege, so look at these
  first; **Medium**, often malicious but with legitimate uses, so it needs
  context; **Low**, unusual but common in normal software, supporting evidence;
  **Info**, neutral facts that tell the story, hidden by default. Context lowers
  a tier by one: the program is on the rule's allow-list, every call failed, the
  process is outside the run's tree, or it was seen only on the network. The
  same words are in the graph legend and on the tier chips.

  **Details** of a row, top to bottom: the tier, title and rule id with its
  version; **What happened** in one sentence; **Why it matters** (what the rule
  saw, and the ATT&CK technique with links to its rows and to the Summary);
  **Why this tier** (the rule's tier and each step that moved it); **Evidence**
  (the calls the row kept, with their time, syscall, what they did and result,
  each with Open in Syscall Trace, or the packet); **Related** (the process, the
  target in Files or Network, and the other findings of the same process, target
  or technique); the rule's facts; dumps taken; and the observed fields. A row
  is something to look at, not a verdict. **Evasion** lists every anti-analysis
  check the sample made through system calls (machine identity, CPU, MAC address,
  uptime, `TracerPid`, container markers, long sleeps) with the answer the guest
  gave, and a heuristic note on what the sample did in the next 30 seconds.
  `CPUID` and `RDTSC` checks leave no system call and are not visible.
- **Triage › eBPF & seccomp** and `bpf.program` in Suspicious activity: a program
  load, and now also each way a program is attached, in order, so the table reads
  load then attach for the same program. `bpf(BPF_LINK_CREATE)` (kprobe_multi,
  fentry/fexit, LSM, cgroup, XDP, netfilter, uprobe_multi and the rest),
  `bpf(BPF_RAW_TRACEPOINT_OPEN)` and `ioctl(PERF_EVENT_IOC_SET_BPF)` on an
  earlier `perf_event_open` each give a row with the attach type, the target (the
  tracepoint name, the kernel symbols, the cgroup fd or interface index, the
  perf event type and config), the program fd and the call that loaded it, and
  the result. Attaching to the whole kernel (kprobe, fentry/fexit, LSM, raw
  tracepoint, a perf tracepoint or kprobe) is HIGH, cgroup, socket, XDP and
  netfilter hooks are MEDIUM, and a failed attach is INFO. A target the recording
  did not capture (an fentry/LSM function chosen at load, a perf kprobe's
  symbol, a tracepoint known only by id) is shown as "not captured", never
  guessed.
- **Triage › Process › Graph**: the same findings on process swimlanes against
  time. The lanes follow the process tree (▾/▸ folds a subtree; many leaf
  siblings of one program fold into one `name ×N` lane); markers take their
  colour from the tier (HIGH red, MEDIUM amber, LOW cyan, INFO grey) and carry
  the category's icon (a hollow disc when only packets showed the finding), so
  colour is never the only cue; with many findings in view they become plain tier
  dots. **Legend** on the toolbar explains every colour, icon, edge and band. Above the lanes are
  the **phases** of the run (recon, download, persistence, escalation,
  hide/inject, C2, spread, impact: a stretch needs one HIGH, a MEDIUM with a LOW,
  two MEDIUMs or five LOWs), a **severity curve** (HIGH counts 10, MEDIUM 4, LOW
  1, scaled to the tallest bar in view) and a **heat strip** with one row per
  category. Thin lines join a parent to the processes it started and an injecting
  process to its target. The graph shows exactly what the Suspicious activity
  table is filtered to: it shares the filter bar and the tier and category
  chips. Hover a marker for a card with a tier chip, the rule, what it did and
  when, the process, count and outcome (the marker gets a ring in the accent
  colour); click it
  to select the row (Details follows, and the table scrolls to it) and
  double-click or press Enter for its first evidence. Click a lane name to keep
  only that process (Shift: and its descendants); click a phase to keep only its
  time range. Drag across the time axis to keep a time range, and press Escape
  to lift it.
  The graph opens fitted to the findings, so a burst of a few milliseconds at the
  end of a minute-long run fills the plot; **Run** (or `R`) shows the whole run
  and **Fit** (or `F`) goes back. Lanes grow to fill the room (a run with few
  processes gets tall rows and larger markers) and shrink to a readable minimum
  with many; a pane too short for the graph scrolls. **Open in window** (on the
  tab, and the arrow icon on the Summary strip) opens the graph in its own
  resizable window, one per run, with the same filter bar and chips and
  **Details beside the graph** (a splitter sets its width); the window's size is
  remembered, and a click in it selects the same row as in the table.
  **Spacing: Events | Time** (bottom right of the graph, or `T`) chooses how
  the time axis is laid out. **Events**, the default, gives every distinct moment
  a finding happened at one slot of equal width, in time order, so a burst of
  findings in a few milliseconds is as wide as the same number of findings
  spread over minutes; the tick labels are the real times at slot boundaries, a
  slanted break mark and the length of the gap show where a long stretch with
  nothing in it was squeezed, and the phases, the severity curve and the heat
  strip follow the same axis. **Time** is the true scale. The choice is
  remembered in the settings. Under the axis, the **overview ruler** shows every
  finding of the whole run squeezed into its width, with the stretch the graph
  shows as a window on it: drag the window to pan, drag its edges (the wide
  grips at each end) to zoom, drag
  across an empty part to show that stretch (a click there centres the window),
  and double-click the ruler to show the whole run. A time range brushed for the
  filter is marked on the ruler. It works in both spacings, in the tab and in the
  window.
  Mouse: wheel scrolls the lanes, Shift+wheel or a drag pans, Ctrl+wheel or a
  pinch zooms at the pointer, a double-click on the axis zooms 2x. Keyboard (click the graph first): ←/→ previous and next
  finding in time, ↑/↓ lane, Enter evidence, `T` spacing, `F` fit, `+`/`-` zoom at the
  selection, Space fold the lane, `H` `M` `L` `I` the tier chips and Show INFO,
  `1`…`9` and `0` the first ten category chips.
- **Triage › Files › By file** is the first tab of Files and opens by default (its filter bar ends with "x / y rows", the files listed out of all the run touched, as the Process tree's does): one row
  for each file the run touched, with **Path** (the path only) and
  **Tags** (where it lives, such as `/tmp`, `home`, `system`, `proc`, `hidden`,
  `persistence` and `credentials`; `+2 names` when it was also seen under other names,
  listed in Details; and, when a Suspicious activity finding of Low or above names the
  file as its object, the worst tier with the behaviour's title, `High · Dropped file
  executed`, or `3 findings · High`), **What happened** (a chain
  such as `created → written 812 KiB → chmod +x → executed → deleted`), **By** (the process,
  and how many more), **First → last** (seconds from the start of the run, the absolute
  time on hover), **Size** (`0 B → 812 KiB`), **Type** (ELF, script, archive, config, text
  or data, read from the first bytes the run captured; `unknown` when none were) and
  **SHA-256** (the first twelve digits; the whole digest on hover and in the row menu's
  **Copy SHA-256**). **Hide stdio**, **Hide library**, **Changed only** and a path
  filter narrow the list. A click shows the file in Details; the row menu opens its
  **Per-file history** or its reconstruction. The Opened, Created, Read, Written, Deleted,
  Renamed, Executed, Attributes, Probed, Other and Changed files tabs stay as the
  per-operation views, with the same filter keys. They no longer have an Evidence column
  (Details has **Open original syscall**) or a Location column (it is a tag in the
  Tags column after Path), their times are seconds from the start of the run (the absolute time on hover),
  **Process** is `name (pid · tid)`, and Changed files has **Changes** (`3 writes ·
  4.1 KiB`), **Type** and **SHA-256** where it had Diff count.
- **Triage › Files › Per-file history** is the second tab of Files, before Opened, with
  the number of files the run touched on it (it was a floating window). The
  left list holds every file the run touched, in order of the first call (also
  those that were only opened, read or probed); **Hide stdio**, **Hide library**
  and **Changed only** narrow it, the filter matches the path and any other name
  the file was given, and the order can be first or last touched, most calls or
  path. A call made through a descriptor (a write after the file was renamed, by
  any thread or a `dup`) stays in the history of the file it was opened on.
  Choose a file to see its history as a graph: one box for each stretch of
  the same call by the same process (create, open, read, write ×3, rename, delete),
  joined in the order the calls happened, on a lane for each process involved.
  Process names (`name (pid · tid)`) stay at the left of the graph, cut to fit (the
  whole name is the tooltip). Drag the background of the graph to move it, Ctrl+wheel or a pinch
  zooms at the pointer, and a double-click puts it back. The title of the history is the
  file and its SHA-256, `name [sha256]` (a click copies it), or `name [unknown hash]`;
  **Reconstruct contents…** is at its top right. A click on a file in the list shows it in Details (its
  names, first and last call, steps, state, sizes and hash).
  Click a box to list its calls in a table that spans the pane: time, process, call, result (a rename shows the new
  name, a delete says whether another link remains), and for reads and writes the
  **offset**, the **length** and the first 64 bytes the kernel captured. A click on a call
  shows it in Details, with **Open original syscall**, and a double-click opens it. A write
  that went past the end of the file as far as the run knew says so. **Content
  changes** below lists the bytes the run changed where it captured both sides:
  `0x00000001  42 43 → 7a 7a`, or `added` for bytes past the size it first saw
  (`??` is a byte it did not capture, `∅` one beyond the known size), the file's
  size before and after, and the guest's SHA-256 when it took one. An offset the run could not know (an append,
  a descriptor it did not see opened) shows `unknown`, and bytes the kernel did not
  capture show `not captured`; nothing is guessed. In **Changed files**, Details has
  a **Per-file history** button that opens the tab on that file. The rebuilt bytes
  are every byte the recording kept of each write, up to **Rebuilt file bytes** in
  Settings > Analysis limits (per file and per run); a note about a call that moved
  more bytes than the recording kept of its buffer says so, and a note about the
  limit says that instead.
- **Triage › Summary** reads top to bottom: the **header strip** (the sample's name, ELF
  type and architecture, static or dynamic, packed when Static analysis found a
  packer, size and SHA-256 with a copy button; the base, route, run time and exit;
  the HIGH, MEDIUM, LOW and info counts, each a button that opens
  Suspicious activity on that tier; **Family candidates** from the detections and the
  sample's MalwareBazaar record, strongest first, each with its source (an Elastic
  `Linux_Trojan_<Family>` rule, a `family` or Malpedia metadata, MalwareBazaar's
  signature and its tags, which may name two families; an IDS signature `ET MALWARE
  <Family> ...`, named from its `malware_family` metadata, else from the one family
  word of its message, else from a known family word in its title, which ranks below
  every strong YARA match and above the weak ones; a rule known to match more than its
  name says, such as `Linux_Trojan_Gafgyt_28a2fe0c` (it hits Mirai builds), counts as
  weak evidence for both families and yields to a specific rule; name fragments such as
  MassHunt, IoT or Unique, and a rule pack's vendor or author in a rule name such as
  `SEKOIA_` or `ESET_`, are never a family; a family is the one family word of the
  rule, so `SEKOIA_Backdoor_Lin_Bpfdoor` and `MIRAI_OHSHIT_payload` name BPFDoor and
  Mirai; a family named only by a layer Static analysis unpacked from a packed
  sample says "in the unpacked payload", and a signature fetched for a file you
  imported says "looked up by hash"); and behaviour tags), **Key findings** (the six worst by tier and
  then first time, each with its description on a line below, cut to its first sentence
  with "…" when there is more: a click on the description shows all of it and another
  folds it; a click on the row opens the finding's Details, **all N** opens Suspicious activity, **Show more** turns
  the six rows into one scroll area of every finding, as tall as the six rows
  were, with its scroll bar always drawn at the right edge; **Show less** puts the six back), **Indicators** (the base image's own clock-sync, DHCP and apt traffic is one muted
  "Base image background" line at the end of its branch, shut until clicked, and left
  out of Copy all unless open; an address on a Tor, VPN or SOCKS route's stand-in range
  shows the name it stands for; a tree of
  **Endpoints** with country and organization, **DNS names**, **URLs** and **Files**
  dropped or run with type and SHA-256; each item shows its value in the normal
  text colour in monospace and its country, organization, type or hash muted
  (hover underlines it and shows the pointing hand; nothing is link-blue); each
  branch shows five and **Show N more** turns the five rows into one scroll area of every item,
  as tall as the five rows were, with its scroll bar always drawn (**Show fewer** puts the five back); the branch titles (Endpoints, DNS names, URLs, Files) are bold, each in a colour of its own that is neither the text colour nor link blue, with a muted count; the one-line rows (MITRE
  ATT&CK, Processes of interest, Files, Network) show numbers strong and words muted, stay one line each and scroll sideways when wider than the box (a scroll bar shows then, and Shift and the wheel scroll it; the plain wheel still scrolls the page); **Copy all** and **Export**, which writes JSON to the run's `ioc`
  folder; the header says how many indicators matched the IOC datasets), **Relationships**
  (a process, file, endpoint and injection graph laid out as a tree from the root
  at the top left: each process has the processes it started, the files it wrote or
  ran and the endpoints it contacted to its right, and every level is one column however
  many children there are (a tall column is reached by scrolling or panning); children of one parent that ran the same image
  and have no finding are one stacked box (`ps ×120`), and the files one process
  wrote into one folder are one box (`/tmp/x/ · 1,240 files written`); a click on
  a stacked box opens it and a click on its header shuts it, and a node with a
  finding is never grouped; **Compact** shows the 15 best of each kind (a group
  counts as one) and what joins them, **Full** is a tree you open: it
  starts with the root, the path to every node with a finding and what is under those
  nodes, and every other process is closed; a box with something under it has an arrow
  (▸ closed, ▾ open) and a muted **+N** for the nodes hidden under it, a click on the
  arrow opens or closes the next level (the box stays where it is on the screen), a
  click on the box itself opens its details; **Expand all** opens everything (about 800
  boxes are drawn at most, and the note says so) and **Collapse all** goes back to how
  Full starts; the open boxes are kept for the run, also when you switch to Compact and
  in the window; **Laying out…** shows while a big run is
  placed; the icon beside **Mermaid** opens the graph in a window of its own with the
  same controls; drag the background to pan, Ctrl and the wheel or the
  buttons (a small bar that fits its buttons: **Fit** shows the whole graph when it can be read, else its top as wide as the box; **Fit all** shows every box, however small) to zoom, the plain wheel scrolls the page everywhere, over the graph too, and the Key findings and Indicators lists and the Activity graph's lanes take it only while they can still scroll that way; click a node to open it,
  **Mermaid** to copy what is shown; edges read fork, exec, write, run, connect, inject, signal),
  then one line each for **MITRE ATT&CK**, **Processes of interest**, **Files** and
  **Network**, the folded **MITRE ATT&CK techniques** list, the **Detection engines** (three cards of one height, so the state tag and **Open results** line up),
  the notes and the run's last screenshot. The Summary states observations only: no
  verdict and no score. Family
  candidates and tags show only what a detection or rule named, so a run nothing
  matched has none.
- **Run digests are built on their own.** When a run ends, the window builds its Triage
  digest (the behaviour findings, process lineage, written files and indicators the
  sample window, the rollups and the report read) in the background, without waiting for
  anyone to select the run. This holds for a heavy run too, such as a write flood of a
  million calls: the build streams the recording page by page, reads at most 400,000
  calls and spends at most 20 minutes, one build at a time, smallest recording first,
  and never blocks the window. A digest that was cut short, or built from a run that
  lost telemetry (dropped or unsaved packets), is marked partial with its reasons
  ("the digest was built from the first 400,000 calls of the recording (the size
  budget)", "telemetry was lost before it reached the host (N dropped)"). Selecting the
  run while its digest builds shows a progress line in Triage and waits instead of
  reading the run a second time; **Read it here now** stops the background build and
  reads the run in the window, which then writes the digest from the whole run. Opening
  the run in Triage always reads all of it, so the digest of a budget-limited run is
  replaced by a whole one. A digest made while the run's recording was still being
  written is made again when the recording changes. Only runs started in the last seven
  days are taken at start; `antinomie-cli digest --pending` does the rest. If the app
  quits during a build, nothing is half written and the run is built again the next time.
  Auto mode does the same for every job's run when Triage did not leave a digest (not in
  the policy, failed or out of time), and records a `digest_incomplete` warning when the
  digest is partial.
- **Triage › Summary** has a card for each detection engine (YARA, IDS, Sigma). Its
  status reads **Queued** while the scan waits for its turn and **Scanning** while it
  is checked, **Not scanned** only when neither is the case. It also shows the same curve, phases and heat strip for the whole
  run as **Main activity graph**; a click opens the Graph (nothing is filtered by
  it). The magnifier buttons beside the title, and Ctrl+wheel over the strip, make
  it larger or smaller (60 % to 300 %, bands, labels and text together); the
  percentage takes it back to 100 %. When nothing is above
  LOW it is one line (`No medium or high activity · 11 low · 340 info`); the
  arrow opens or closes it, and the choice is kept until you quit.
  Like the Graph it spaces its findings equally by default, so a few findings
  fill the whole width instead of sitting in a sliver of a long run; it follows
  the Graph's **Events** or **Time** choice. In both, a run with only a few
  findings has them near the left and right edges of the plot.
- **Triage › Summary › MITRE ATT&CK (N)** counts the techniques by tactic in a
  one-line row; the folded **MITRE ATT&CK techniques** list below the one-line rows lists the techniques grouped by tactic in
  kill-chain order, one foldable row each: the technique and its name, its
  tactics, the Triage rules that cited it (with tier and count), the YARA, IDS
  and Sigma rules that cited it, and links that open **Suspicious activity** or
  the engine's matches in **Detection** filtered to that technique, and **Syscall
  Trace** at the first call behind it. Whether the section and each technique are
  open is remembered. Filtering Suspicious activity does not shrink this list.
  Each of the 15 ATT&CK v20 tactics has its own colour (one palette for dark and
  one for light; Defense Evasion is now Stealth and Defense Impairment). A
  technique that ATT&CK files under several tactics takes the colour of the
  tactic of the row it sits in (the sample window groups by tactic), else of its
  first tactic in kill-chain order, and shows one dot per tactic. The tactic
  names are always in the badge's tooltip and in a folded **Tactic colours**
  legend under the Summary and the sample window's ATT&CK section. The Sigma
  rules of low or informational severity add no techniques to the list.
- **YARA scan inputs.** Besides the sample, the memory dump, the core and the files
  recovered from the dump, the YARA scan reads: the **Preloaded library** (a library
  sample the run named in `LD_PRELOAD`, `LD_AUDIT` or its arguments, read from the
  sample library by its hash); each **File the run wrote** that is an ELF executable
  or library (Triage rebuilds it from the recorded writes when it saves the run's digest,
  in `detect --save` and in the Auto lane, and keeps the whole ones under the run's
  `written` folder; a file that could not
  be rebuilt whole is listed as skipped with the reason); and each **Unpacked layer**
  static analysis produced (UPX and the like). Every match records the input it came
  from, and the match's evidence line begins with it. Families named by these matches
  count for the run like any other. The scan keeps its time budget and the 64 MiB file /
  512 MiB total size limits; a library, file or layer left out for budget (or because it
  is missing) is a **Skipped** row with the reason, and the scan notes name it. Written
  files are limited to 64 files of 64 MiB (256 MiB together). The Detection tab scans
  again by itself when Triage keeps new written files.
- **Triage › Detection** lists each engine's matches as cards under **Matches**.
  On the YARA page the strong matches (an Elastic rule scored 70 or more, a rule
  with `family` metadata, a curated pack's non-generic rule) come first; unscored
  community rules without a family, generic and hunting rules, low-score Elastic
  rules and rules named for Windows, PE, scripts or web pages sit in a folded
  **Weak or generic matches (N)** group under them. Nothing is removed and the
  counts are totals.
  **Sort by** orders them by risk (the default), name, MITRE technique, engine
  (rule pack), hit count or first hit (where the first hit was recorded:
  journal event, call or packet order; matches with no position come last); the
  choice is saved. A card shows the rule's title, severity tag and hit count, the
  description, the rule pack and every author, and the MITRE tags. **Details…**
  opens the rule: description, then the evidence locations as a scrollable
  table (the full width of the window, twelve rows or more before it scrolls, a long location wraps and shows in full), the rule's metadata and its text (wrapped by default). The page scrolls
  when a section grows. An empty result says how many inputs were not scanned
  and why. For IDS, "Rule packs: N rules" counts every rule in the enabled
  packs and the grey "N rules loaded" text at the right end of that line counts
  what Suricata loaded; hover it for the difference.
  The **Scan** and **Result** buttons, the matched-rule count, the state and the
  "objects · rules evaluated" text sit at the right of the **Scanned inputs**
  heading (below it in a narrow window). Hover that heading for the note on how
  Sigma events are converted from the syscall trace, or on the IDS reading the
  VM-wide capture so its matches name no process. The match filter shares the
  **Sort by** row. A Sigma or IDS result with rules that did not apply has its
  toggle ("Show the N rules not applicable") as the title line, the counts under
  it and the list under them. The **Detection** tab of the Triage strip shows
  the matched rules of YARA, IDS and Sigma as "x · y · z", each capped at 99+;
  hover it for the engines by name. The **Process**, **Files**, **Network** and
  **eBPF** tabs carry the same kind of badge: processes (not threads) and
  Suspicious activity findings as "p · f"; the files of By file with its default
  filter; Endpoints, Domains, URLs and TLS as "p · q · r · s" in the tab order;
  and the eBPF observations. Each is capped at 99+, shows a dash when the run
  has no scan yet, and names its numbers in the hover ("12 processes · 3
  findings"). A rule score (Elastic's 0 to 100) is coloured by range in the
  match cards and their Details: red from 90, orange from 70, amber from 40,
  muted below. A scan that starts by itself and fails never replaces the result
  on screen, and no scan starts by itself while an engine tool has not answered.
  **Settings > Detection > Scan runs with IDS and Sigma when they end** (on by
  default) makes each engine scan a run once its evidence is ready, and again
  when a rule pack is installed, updated or removed. A run whose VM stopped
  under its capture (the pcap was never closed) is scanned with the packets it
  holds, and the engine's row says "scanned the N packets captured so far". An
  engine that has not scanned the run says **Not scanned** with a **Scan**
  button; in the tab badge it shows as a dash whose hover says "not scanned"
  (a zero would mean the engine scanned and found nothing). A result made with
  an older rule set says "Scanned with an older rule set." with **Rescan**.
  A run on a VM that keeps running is scanned as soon as its recording is
  **saved** (its tree ended, its terminal closed, every byte written and its
  pcap segment closed), without a VM stop; until then the engine says "Waiting
  for the recording to be saved." Sigma reads the run's event journal, which
  Triage builds for the selected run: without one the tab says "Waiting for the
  run's event index to be built.", or, when building it failed, "The run's event
  journal is incomplete: <why>" and never a raw "No such file or directory".
  Only the run selected in Triage gets an event index, so a run you never
  selected has no Sigma scan until you select it.
- **Failed launches.** A program the guest could not start because its file is
  cut off says "This ELF is truncated: its segments need 30.3 MB, the file has
  2.0 MB. A partial upload or download; get a full copy." in the run's failure
  message, and Static analysis shows it in red above Identity. A root that exits
  127 for a missing library gets the run note "Exited 127: the library
  libhwloc.so.15 is not in the guest."; Metadata/Structures list each **Needed
  library**. A shared object run as a program is called a shared library, meant
  for LD_PRELOAD or dlopen, in Identity and on the run. Unpacking says "UPX
  headers are altered (anti-unpacking); restore the UPX! magic and sizes to
  unpack it" for a UPX file whose headers were damaged on purpose. A run that
  failed to start has a digest that says so and why. When the guest refuses
  a program, the host reads its ELF headers and adds what the guest's error
  number cannot say: the interpreter the program needs and the base lacks (the
  guest reports that as a missing program), an old-ABI ARM (EABI0/OABI) program
  an arm64 kernel cannot run, a cut-off ELF, or the wrong architecture for the
  VM. That text says it was identified on the host and keeps the guest's words.
- **Triage › Summary** also names the run's root process from the launch request
  when the recording's launch record cannot (the program and arguments the run
  was asked to start, kept as the first name in its exec history), and the
  Process column shows a forked child that never ran an exec as its parent's
  image with "(fork)". A failed call reads "failed (EACCES)", with the number and
  its meaning on hover.
- **Recording quota nearly full.** When a boot has used nine tenths of its recording
  quota (**Settings > Recording**), the recorder keeps only the system calls the
  Triage suspicious-activity rules read (and process lifecycle), drops the rest
  and counts what it dropped per call. The network capture keeps running until
  half of the last tenth is left; the quota itself stays the hard ceiling. Triage,
  Run History and the HTML/PDF report say "Recording quota nearly full at <time>; from
  then on only suspicious-activity calls were kept, N calls dropped" as
  information, not an error (`run.json` has it as `reduced`); "Recording quota
  reached" is said only when the quota itself was full and saving stopped.
- **Tables that stop at a page size** say "first N of M" (for example "first 2,000
  of 10,897 matched") and name the setting **Settings > Advanced > Triage: rows
  per table** (default 2,000, 100 to 100,000), which sets how many rows one Triage
  table and one report table keeps.
- **Settings › Notifications › Toast for live HIGH findings** (off by default):
  the first HIGH finding of each rule in a run that is still going raises one
  toast; later matches of that rule add `×N` to it. It is raised when the run's
  index is read again, every 5 s while Triage is shown and every 15 s otherwise.
- **Triage › IOC**: the run's indicators of compromise, matched offline against
  the abuse.ch datasets in **Tools > Detection rules > IOC**. The tabs are
  **Endpoints** (`ip:port`), **Domains** (DNS questions, TLS server names, HTTP
  Host headers and domain-like strings of the sample), **URLs** (HTTP method,
  host and URI; HTTP/2 only when it is cleartext), **TLS** (server name, JA3, JA4,
  JA3S and the certificate SHA-1) and **Files** (SHA-256 and MD5 of the sample,
  executed programs, and files the run created, changed, deleted or left written;
  the guest hashes executed, deleted and written files, and a saved disk dump of
  the run adds MD5 for created and changed files, up to 2,000 files of 256 MiB).
  Network rows come from TShark; each row shows its **sources** (`pcap`, `syscall`,
  `disk`, `static`), the **process** when exactly one process made a matching call
  (otherwise "unattributed", with the candidates in Details; a pcap row never
  gets a guess), when it was first and last seen, and a verdict: **Matched**,
  **Known FP**, **No match** or **Not checked**. Every verdict carries the
  dataset's date. **No match is not a clean result**: the datasets list only
  what abuse.ch has seen. Private, loopback, link-local and multicast addresses
  and local names, and files with no recorded content, are listed as *Not checked*
  and are not counted as matched or unmatched. JA4 and JA3S are shown but no
  abuse.ch feed lists them. A matched indicator also appears in **Process >
  Suspicious activity** as `c2.ioc_match` (HIGH, or MEDIUM below 75 % and LOW below
  50 % confidence), with the packet or call as evidence, so it shows in the graph and the
  Summary; a Known FP does not. **Jump** opens the packet or the call. **Mark as
  false positive** (with an optional reason) adds the value to the known false
  positives for the datasets that list it; **Export…** writes the rows listed as
  CSV or JSON, with dataset dates and verdicts, into the run's `ioc` folder. The
  filter bar takes `ioc.match == matched`, `ioc.value contains example`,
  `tls.ja3 == "…"`, `file.role contains executed` and the other fields in the
  guide. Update the datasets with **Datasets…**; with none loaded every row reads
  Not checked, and a banner says the datasets are over 14 days old. The tab and
  the kind tabs show the total in grey and, when any indicator matched (IDS,
  YARA, Sigma, abuse.ch or marked malicious), the matched count after it in red:
  "IOC 24 · 3" (tooltip "24 indicators, 3 matched"); nothing is red when nothing
  matched.
  **Online lookups** are off at every start. When switched on (needs the Auth-Key)
  **Check online** sends only public values with no offline match (never files,
  never JA3 or certificate fingerprints, never a value a known false positive
  excuses) to threatfox-api.abuse.ch and urlhaus-api.abuse.ch, at most 50 values
  per press; the answers are marked *online* with their time and kept in the run's
  folder (`ioc-online.json`). **Triage › Summary** says how many indicators matched
  and the dataset date in its Indicators header.
- **Triage › Network** shows **Endpoints**, **Domains**, **URLs** and **TLS**, all
  read from TShark, each with an IOC column. The capture is VM-wide and the guest
  tags no packet, so **Endpoints** has a **Source** column made on the host from
  the run's recorded network calls (`connect`, `sendto`, `sendmsg`, `accept`,
  `recvfrom`, `bind`), matched by address and protocol, with time telling processes apart when several made calls to one address (the host's estimate of the guest's clock can be seconds off, so a single caller is believed whatever the clocks say): a process as
  `name (pid · tid)` (a click opens it in Details; several processes show the
  first and `+N`), **Base image background: NTP** (or DHCP, apt: the traffic the
  Summary's Indicators set apart, and a base program's own flows; DHCP to the
  gateway of a profile's own guest network counts too, read from the run's
  record), or
  **Unattributed** when no recorded call matches, as for a raw socket. Filter it
  with `network.source`, `network.source_kind` (`process`, `background`,
  `unattributed`), `network.source_process` and `network.source_pid`. A run
  recorded before 0.9.0 attributes the same way, from its recording. The 0.7.0 tabs (IPs, Hosts, HTTP, DNS, Sessions) and the switch
  between the layouts are gone. The filter field names of the old tabs
  (`http.method`, `dns.name`, `session.alpn`, `network.country`, ...) work in the
  new ones, so a saved filter keeps working; Endpoints add the port, protocol,
  frames and bytes, Domains the DNS answer code, TLS one row per server name,
  server and JA3.
- **Network**: select an ongoing or saved capture from capture history, or start
  one there. Protocol colors help scan the packets; click an address, protocol
  or port to filter it, or use the counted dropdowns. The packet list and the
  expandable details tree are exactly what the installed TShark prints
  (protocol, info, every field), with a byte view that marks the bytes of the
  selected line. Without TShark you see raw frames and bytes and a note to
  install it. **Open in Wireshark** opens the capture when installed. Each capture
  in the list has a **Run:** line saying which run it belongs to, like the Core
  dumps and Memory tabs: the run itself when it started the segment (exact), the
  runs live while a hand-started segment was written (**by time**), or **VM-wide**
  when no run was; a click opens the run in Triage. While Triage has a run open
  whose capture you look at, the packet list adds a **Made by** column (the
  process, **Base image background: ...** or **Unattributed**, as in Triage ›
  Network; the Source column there is the packet's address) that sorts, and the
  quick filter `source curl`, `source background` or `source unattributed` lists
  the packets of one source.
- **Memory**: dumps of a VM's memory (or imported ones) and their analysis.
  **Analyse with** picks the backend: Volatility 3 (plugins, any system) or
  MemNixFS (Linux only; reports instead of plugins: processes, process tree,
  hidden-process scan, TCP/UDP sockets, triage, indicators, findings, malfind,
  YARA, IOCs, syscall table, modules, kernel log, shell history, timeline and
  files recovered from the page cache). A run is saved with its dump and keeps
  the dump's identity; it is listed beside Volatility's runs, opens in the same
  table, text and Messages views, and its **Files** button opens the folder with
  MemNixFS's raw export (recovered files included), to copy or save from. MemNixFS reads only a dump of the
  guest's whole physical memory: QEMU `dump-guest-memory` ELF cores (what
  Dump memory writes), LiME, AVML, kdump and raw images. A process core, a
  Windows dump and anything else is refused with the reason. It runs offline
  in the analysis sandbox (no network, the dump and its saved symbol table
  read-only, a private working folder). With no saved symbol table it builds
  one from the kernel's BTF. Whatever it could not read is stated: a finished
  result with gaps is marked **partial** in the run list, with a banner that
  lists the reasons (for example an unvalidated page-table root, unreadable
  module list or mounts, or a symbol table whose kernel banner is not the
  dump's); a report the tool could not produce fails with the reason instead
  of showing an empty table. A report takes about a minute on a 2 GiB dump.
  An unvalidated page-table root is explained in plain words (process and file
  lists from physical memory are reliable; modules, mounts and the kernel log may
  be missing or wrong), and the partial result offers **Run in Volatility 3** for
  modules (`linux.lsmod`), mounts (`linux.mountinfo`) and the kernel log
  (`linux.kmsg`) in one click.
  The **Content** tab (beside Volatility 3 and MemNixFS) shows the dump's bytes as
  a hex dump or as raw text (**Hex** and **Text**), 16 KiB a page, read a page at a
  time so a multi-gigabyte dump is never loaded. The toolbar has **Go to** (an
  offset in hex), **Start**, **Page up**, **Page down** and **End**, selection
  with **Copy hex**, **Copy text** and **Copy address**. **Strings…** and
  **Regex…** open windows that search the dump only when you press **Search**
  (Strings: minimum length 4, ASCII and UTF-16LE; Regex: a pattern that matches
  octets, with **Ignore case**; **Max hits** 10,000 by default, up to 200,000),
  with progress and **Cancel**, a page of hits at a time, and a click on a hit
  jumps the view to it. A hit limit or a cancel is shown as an information note.
  The searches are jobs in the **Jobs** window with progress and **Stop**. In
  **Core dumps** each mapping has the same Content tab, with virtual addresses
  (file offsets on hover); its Strings and Regex windows search the mapping
  shown, while the **Strings** tab searches the whole core.
- **Static Analysis**: a **Run** button beside the file's hash opens the run the
  report belongs to in Run History. The selected run's report: an overview, then each
  category; disassembly and decompilation are full listings with search. The
  **Strings** tab lists the strings, and the separate **Regex matches** tab
  (also an Overview category, and it opens in its own pane) shows every
  pattern match in the Strings and FLOSS strings, by category (Network, Crypto, Keys, Linux
  behaviour, Attribution, Encoded) with a type for each match (IPv4 public or
  private, URL, Bitcoin address, persistence path, ...). Matches are checked to
  cut false positives: a domain must end in a real public suffix, `libc.so` and
  `install.sh` are files, a version number is not an IP address, and a Bitcoin
  address, Tox ID or token must pass its checksum or structure. Base64 and hex
  text is decoded and scanned again (two levels deep); the **Inside** column says
  which. The same list opens as a window from **Core dumps > Strings**, where it also lists
  the binary `sockaddr_in` and `sockaddr_in6` structures in the core's memory.
  In **Library > Detection rules**, the page shows the selected pack's details and buttons; its rules are not a table on the page. The **Rules** button (the open-in-window icon, left of **Export manifest**; custom groups have it too) opens one window per pack or group with the rule list at its left (a filter box, the "N of M rules" count, sortable columns and an on/off box for each rule) and the clicked rule's details at its right, separated by a divider you can drag. There is no window of its own for a rule. The window opens at about 70% by 75% of the content area, can be resized, and both panes scroll inside it. The details show the rule's name as a heading, then a grid of bold labels (ID, File, Author, License, Severity, State, Description, Tags, References as links and more) and the source text on a padded block of the theme's code background. A YARA rule's meta keys are read in any case, so `Description`, `DESCRIPTION` and `description` are all its description (the lowercase key wins when a rule has both). The window stays open when you switch pages until you close it. Core dump list problems of a run are reported to the activity log once each.
  Switch patterns off or add your own in **Library > Detection rules > Strings
  regex** (**Add patterns**: a name, a category, a regular expression that
  fills the rest of the row, and **Add**, all on one row); **Scan again** reads the change. An analysis that was not started
  with **Regex matches** shows **Not part of this analysis** and a **Run** button there.
- A list, table or tab with nothing in it says so in one muted line, in the words the
  Disks list uses (`No disk dumps for this VM`): the Core dumps list, a core's threads,
  mappings, strings and notes, the Per-file history list and the guest process list of
  the attach dialog do too, and a filter that matches nothing says that.
- **Static Analysis > Overview**: the **Identity** and **Categories** cards side by side
  are the same height; a note about an incomplete analysis sits above both. In
  **Disassembly** and **Decompilation** the lines sit one font row apart, with no
  extra space between them. A Symbols, Imports, Exports, Sections, Segments or Headers
  view with no rows of its kind (a static binary has no imports) reads
  `0 / N rows` with `No imports in this file; its N rows are in the other views.`
  instead of calling the listing empty.
- **Static Analysis > Overview > Categories**: a category the analysis was not
  started with shows **Not requested** and a **Run** button. Run adds that check
  to the same report without starting the analysis again: the specimen kept with
  the report is analysed by the one check, and its tab fills in when it ends.
  The button waits while the analysis is still being made; no VM has to be
  running, and the result is saved with the report like the others. Each line is
  the check's name, its state chip, what it found and the **Open** button in fixed
  columns, so every **Open** is in one column; why a check timed out, was partial
  or could not run (and the limit it met) is to the right of the button, in the
  warning colour (the error colour for a check that could not run).
- **Static Analysis > Unpacking**: the unpack chain, one layer at a time. A
  **Layer** drop-down chooses the file as it came (packed with UPX or not) or a layer
  UPX recovered from the one before; below it are that layer's size, SHA-256 and the
  packer found in it. A file packed twice
  gives two layers. UPX is needed for this (**Tools > Analysis tools** installs it);
  without it a packed file is reported as packed and left alone. Files whose UPX
  headers were tampered with (the `UPX!` magic overwritten, data appended) are
  repaired on a copy first and the layer says so (`UPX (header repaired)`).
  Each layer is analysed as a report of its own, the same checks as the packed
  file's, listed in the **Report** box as "layer N unpacked by UPX"; **Show its
  analysis** under the chosen layer opens it. The original file is never changed, the layers
  are plain files that are not executable, at most three layers of 64 MiB each are
  kept, and unpacking stops after 4 minutes. Other packers are not unpacked; they
  need the program to run, which is for a later version (guest memory capture).
  When the program the run started is such a packed file, Triage shows
  **Suspicious activity** `evasion.packed_image` (LOW for standard UPX, MEDIUM when the
  packer's headers were changed) as a fact about the file.
- **Details** and **Activity**: the selected call or run, and VM events.
  Right-click values to copy common numeric formats. Open captured data in its
  own window, initially UTF-8, then choose ASCII, hex, hexdump, Base64 or other
  forms and copy the result. Partial captures keep their gap/error information.

Process terminals resize their grids with the window and retain up to 10,000
history lines. Use the mouse wheel or scrollbar to read earlier output; the
**newer lines** button or **Shift+End** returns to the newest output.
Drag across terminal text to select it, or double-click a word. Copy with
**Ctrl+Shift+C**, **Ctrl+Insert**, or **right-click → Copy selection**. This
works in live terminals, saved output, and the debugger console. **Ctrl+C**
copies a selection; without one it interrupts the running program. Paste with
**Ctrl+Shift+V** or **Ctrl+V**. The context menu also offers **Select all output**
and **Clear selection**. Copies contain plain text, joining soft-wrapped lines;
selections whose cells change or leave retained history are cleared. A copy
larger than 8 MiB is refused with an Activity warning. Host clipboard delivery
still depends on the desktop display server.

Each process terminal has a **Formatted / Raw** switch in its header. Formatted
draws the output as a terminal does, including bold and italic. **Raw** shows
the byte stream as text with the escapes written out (`\e` is ESC, `\xNN` a
control byte, `\r` and `\n` the line ends, `\\` a backslash), with the same
10,000-line scrollback. Escapes that can hide output are highlighted: cursor
moves and line erases, a carriage return or backspace that lets later text
overwrite the line, concealed text (SGR 8), control strings such as the window
title and hyperlinks, the clipboard command OSC 52 (in red), and switches to the
alternate screen. Hover a highlight for what it does. Raw has a **Find** field
(case-insensitive, with previous and next). Copy from Formatted gives plain
text; copy from Raw gives the escaped text. A saved run opens in whichever view
is chosen.

Panels can be dragged out into their own windows and docked back;
**View → Reset layout** restores the default arrangement. Text size is under
**Tools → Settings**.

The main window and detached workspace windows use Antinomie's own title bar,
matching the selected theme. Drag its title to move the window; double-click
the title or use **Maximize/Restore** to toggle its size. The other controls
minimize and close the window. Resize using its edges or corners. A new
detached window opens inside the main window's panes, below its toolbar, and
without a window manager too. Closing a
detached terminal hides its view and leaves its program running; closing the
main application follows the normal VM shutdown path. Embedded floating panes
retain their existing controls, and QEMU's separate display uses its own frame.

**Tools → API keys** is the one place API keys are typed, replaced, tested or
removed: the abuse.ch Auth-Key (MalwareBazaar, and the IOC datasets and rule
packs that follow) and the MalShare key. Each key shows only its last four
characters, which features use it and when it was last used; **Test** asks the
service whether it accepts the key. Keys are kept in the data folder in a file
only you can read and are never written to run exports, reports, logs or
screenshots. Malware samples has no key field of its own: it points here.

**Tools → UI performance** shows the graphics renderer and recent UI update
CPU timings. If WSLg selects software rendering, a compatible GPU driver can
be selected for one launch with `antinomie --graphics-driver d3d12`; the dialog
can copy a command preserving the data directory. Close the app normally before
using it. The default `--graphics-driver system` keeps the existing environment.

## Run states

Run History, the sample window's Runs list and Summary, the VM's recent runs, the
run window, the run-finished toast and Triage's run-state line colour a run's
state from one palette. The words always stay, so colour is never the only cue.

| State | Colour |
|---|---|
| Running, stopping, or still recording after the terminal was closed or the root exited | Blue |
| Held: the tree ended but a persisted copy runs outside it, and the run still captures | Blue |
| Finished with exit 0 | Green |
| Finished with another exit code | Amber |
| Stopped by you (Stop run) | Grey |
| Ended at its time limit (a `timeout` program: exit 124, or the SIGTERM BusyBox's `timeout` re-raises) | Blue-grey (info) |
| Finished after a crash or a kill by a signal (SIGSEGV and the like), or launch not confirmed | Amber |
| Failed to start, or interrupted | Red |
| Recording incomplete (saving stopped part way) | Amber |

A run is "going" while it still records: a run whose terminal was closed, or whose
root exited while children live on, shows **Running** in every list and keeps its
**Stop run** button (toolbar, Run menu, the command palette and the Run History
row).

Stop run works from any page, not only for the run selected in Triage: with no
live run selected it acts on the newest live run, and the confirmation names the
run it will stop ("the newest of 2 live runs"). Select a live run in Run history
or Triage to stop that one instead.

**Stop run** ends the whole recorded process tree, every live task of the run and
not only the root, with SIGTERM and then SIGKILL after the grace period, while
the VM keeps running. The run then ends the way any run ends: the recording
closes, the network capture's last segment closes so the pcap is whole, the
route's counts are written to `artifacts.json` and the journal is complete. Stop
run is the way to end a run whose program never exits, such as a bot or a
backdoor; stopping the VM instead cuts the run where it stands.

How a cut or stopped run is worded, in Run History, the sample window's Runs
list and Summary, Triage's state line and the reports:

- **Stopped by you at 5 min 9 s · root exited 0** (or "root killed by signal
  15"): Stop run ended it, and the time is when the button was pressed. When the
  tree took 2 s or more to end it adds "tree ended 3 s later"; the run's tooltip
  gives the press time and the end time. Runs saved before 0.8.3 do not record
  the press and read "Stopped by you after 6 min 59 s" (to the end of the
  recording).
- **Ended by VM stop · root exited 0 · 1 process still running**: the VM stopped
  while the tree was alive. The words give what the root did and how many
  processes were left; the run's pcap is closed at the stop and its route counts
  are still written.

### Copies of the program outside the recorded tree (0.9.0)

The guest records only the launched program and its descendants. Malware that
persists (a cron entry, a systemd unit, an init script) has its copy started by
cron or systemd, outside that tree: the copy can kill the recorded processes
(Mirai's `.e` does) or keep running as a service after the tree exited. The host
looks for such copies itself, with the guest commands it already has and nothing
started in the guest:

- Just before the launch it lists the guest's processes. While the run goes on
  it lists them every 3 s; a process that was not there before the launch and is
  not in the recorded tree is read (the guest kernel opens `/proc/<pid>/exe`, the
  way static analysis reads the sample) and hashed on the host.
- It is a copy when that SHA-256 is the launched program's (for a library
  sample), or that of a file the run wrote (the guest's hash at the file's last
  close). Names are never enough, and a file the run copied from a program the
  tree had run (BusyBox's `cp` copying busybox) does not count. At most 64
  programs are read per run, and only those of the size of one of the run's
  images are read whole.
- The run's notes name each copy: "pid 1050 ".e" runs a copy of the sample
  outside the recorded tree (started by pid 1049 "cron", uid 0, SHA-256 …)".
  Triage lists it as the HIGH finding **Persisted copy running outside the
  recorded tree** (`persistence.copy_running`), and the run-end note says when a
  recorded process was killed by that copy.
- When the guest says the tree ended, the host takes one last look (a few
  seconds, at most 30) before the run reads as ended, so a copy started just
  before the end (a short installer that starts its service and exits) is found
  too.
- When the tree ends while a copy is alive, the run is **held open**: its network
  capture and route go on, so the copy's traffic is in the run's pcap. The hold
  ends when every copy has exited, when the run limit of `run exec` or Auto mode
  sends its stop (the run then ends at its limit, not as exited), when the VM
  stops, or after 10 minutes. The run's notes say when and why it ended.
- While it is held, Run History, the run's window header, the Samples window's Runs
  and the VM's sidebar row say **Held: persisted copy running (pid 1050, .e)** in
  the colour of a live run (during the last look, "Held: looking for persisted
  copies"), and the run-finished toast waits. **Stop run** (toolbar, Run menu,
  command palette, the Run History row) is offered for it and works as on a live
  run: the hold ends and the run reads "Stopped by you at …". The copy itself is
  not signalled: the guest cannot, so it may still run. The copy's own system calls
  are not recorded (following them would need the guest to trace it), and it may
  still run in the guest after the hold; restore the VM's snapshot.

`run.json` keeps what was found under `persisted` (each copy's pid, name, parent,
uid, SHA-256, size, when it was seen and whether it ended, and the hold).

## 5. Samples

**Library > Samples** (sidebar) lists every sample across runs and VMs with its
origins and tags; opening one shows the sample window with the tabs **Summary**,
**Runs**, **IOCs**, **Custody log** and **Notes**. **Export report…** in its header
is described in [the sample report guide](sample-report.md). The **Runs** list
fills the window's width: **Arguments** takes the spare width (a long command
line is cut, the whole of it is on hover) and **Tree status**, **Root exit** and
**VM** keep a width that fits their usual values.

- **Runs that load a library.** A run of `/bin/sh -c '...'` with a library in
  `LD_PRELOAD` or `LD_AUDIT` (in the environment, or set in the command line) is
  linked to the library sample when the library sent that file into the VM: the
  match is by the SHA-256 recorded when it was sent, not by the name. The sample's
  **Runs** list shows the run with the **Role** `preloaded` (`audit library`, or
  `named in arguments`), the sample no longer says "Never run", and the run's
  Summary names the library above the tier counts. A named library the library never
  sent has no hash: the Summary says so ("not a library sample: the library did not
  send this file into the VM") and nothing is linked. A shell variable or glob in
  the command line is not a name and is not resolved. When a run writes a shared
  library and then preloads it (through `LD_PRELOAD`, `LD_AUDIT` or by listing it in
  `/etc/ld.so.preload`), Triage reports **A library the run wrote is loaded into
  programs** (high) naming the file.
- **Summary** holds the identity, the **Static analysis** section (each check on a
  line: name, state chip, what it found, **Open**, and the notice to the right of
  the button), the ATT&CK section, **Detections** and **Files written**. Files
  written shows one row per file the runs wrote, rewrote, deleted or renamed, with
  run, state, size and SHA-256, filterable and paged for ransomware-sized lists,
  with **Open in Per-file history**, **Export bytes** and **Copy SHA-256**. The list
  comes from each run's Triage digest. Every finished run gets its digest on its own
  (see **Run digests** below), so a run is listed as not read yet only in the moments
  before its digest is built, or when its recording cannot be read. The ATT&CK section has **Show all N**: the same
  list as in Triage, each technique with what cited it and its runs as links into
  Triage.
- **Runs**: the sample's runs in start order, with the run-state colours above.
  Selecting one shows it in the shared **Details** pane.
- **IOCs**: every indicator across all runs of the sample, one row per unique
  indicator (a file by hash and path): kind, value, which runs had it ("run 2, 3",
  "5 runs", "every run (4)"), how it was observed (DNS query, connect, packets,
  file write, executed), first and last seen, the process, and the stored abuse.ch
  records that list it (**Detections**). The kind chips carry counts ("Domains
  (4)"); **All**, **Seen in every run** and **Only in some runs** show what
  changed between run settings; a search box, **Hide private and reserved** and
  **Hide guest infrastructure** (the base image's own traffic and the emulated
  network's 10.0.2.x) narrow the list, and **Defanged** (on by default) shows
  `hxxp` and `[.]` instead of live values, which Copy follows (**Copy raw value**
  appears when it is on). The tab count is Triage's: the total in grey and the
  matched count in red. The selected row is in the **Details** pane with one line
  per run and **Open in Triage**, which opens that run on the indicator in
  Triage > IOC. Per row: **Copy**, **Open in Triage**, **Add note** and **Check
  online**, which is off without an abuse.ch key (**Tools > API keys**) and
  otherwise opens the run's Triage on the row, where the existing lookup with its
  **Cancel** and rate limits is. **Export** writes the rows listed (or the
  selected row) as CSV, JSON, a MISP event or a STIX 2.1 bundle into the data
  folder's `sample-reports`, with raw values in every file (the **Defanged** chip
  changes the table and Copy only), and notes it in the sample's custody log. Runs Triage has not read are named in a note: open the
  run in Triage once to fill them in. IDS, YARA and Sigma rules match runs, not
  single indicators, and stay in Summary > Detections.
- **Custody log** and **Notes**: the sample's history and notes; a note chip jumps
  to what it is about.

A file a run deleted can be rebuilt from the recorded writes as of the last
moment before the delete: **Export bytes (as before deletion)** in Files written
and in Triage's File reconstruction window. When every byte is known, the file is
hashed and compared with the SHA-256 the guest took just before the delete; a
match is "verified" and the export is saved with a `.json` record of the check.
With gaps (bytes never recorded, or a size not known) the window says "partial: N
bytes unknown" and saves what is known with a `.mask` file marking the rest. The
export is an **Exported** entry in the custody log (file, size, hash and result).

## 6. Keys, the command palette and Jobs

**Filter and search boxes** (the Triage tables, the rules list, Samples, Run
History, Detection, Settings and the others) show a small cross at the right
edge while they hold text. A click on it, or Esc in the focused box, clears the
text.

**Spawned windows** (a rules window, a rule hit's Details, Relationships and
the like) never grow past 80 % of the app's content area each way (a window
still opens at its own size when that fits), and not below a small minimum. What does not fit scrolls inside the window: code scrolls
sideways in its box, and long text wraps. A rules window opens with the list at 40 % and the details at 60 % of its width (drag the divider to change it).

Menus: **File**, **VM**, **Run**, **View**, **Tools** and **Help**; the menu bar's
**Search** button at the right (with its key) opens the command palette. Menus and
button tooltips show the keys, and a tab's tooltip shows its Ctrl+digit.

**Ctrl+K** (or **Search**, or **Help > Command palette**) opens the palette. It
searches every menu action, the open tabs, the machines, the recent runs and the
library samples; **Enter** runs the highlighted entry through the same code as the
menu, **Esc** (or Ctrl+K again) closes it, and an action that cannot run now stays
in the list with the reason ("Start the selected VM first."). A menu item, its
shortcut and its palette entry share one action list, so they cannot disagree.
**Help > Keyboard shortcuts** (or **?**) lists every shortcut by area, with a
**Change shortcuts…** button that opens **Settings > Keyboard**.

**Settings > Keyboard** has one row for every action (each menu item, each view and
each page or window the palette opens, about 90 rows, under the menu they belong
to), with a **Find** field. Click a row's key, then press the new one (**Esc**
cancels). A shortcut must hold **Ctrl** or **Alt** (a lone letter would type), may
not take **Ctrl+1** to **Ctrl+9** (the tabs) or the copy, paste and undo keys, and
a key another action already has asks first: **Move it to ...** takes it from the
other action, **Keep it where it is** leaves both. **Clear** leaves the action
without a shortcut, **Reset** (per row) and **Reset all** bring the defaults back.
The choice is saved with the settings (an older settings file just has the
defaults), and the menus, tooltips, the palette and the Keyboard shortcuts window
show what is in force.

The rule for who owns the keyboard: a global shortcut never takes a key from a
text field or the terminal (**Ctrl+K** stays with them too: it deletes to the end
of the line, in a field and in the guest shell; use **Search** there). A focused
button, table or graph does not block the shortcuts.

| Keys | Action |
|---|---|
| Ctrl+K | Command palette |
| ? | Keyboard shortcuts |
| Ctrl+N | New VM |
| Ctrl+Shift+S, Ctrl+Shift+X | Start VM, Stop VM |
| Ctrl+R | Run program |
| Ctrl+U | Upload file |
| Ctrl+D | Attach debugger (the process picker); with the picker open, attach the selected process |
| Ctrl+Shift+Y | Type host clipboard into VM |
| Ctrl+Comma (the app shows it so) | Settings |
| Ctrl+Q | Exit |
| Ctrl+1 to Ctrl+9 | Show the 1st to 9th tab of the work area, in the order the tab bar shows them (they follow a tab you dragged) |
| Ctrl+J | Fold or open the lower bar (Details, Activity and Jobs); the arrow at the right end of its tab strip does the same |
| Ctrl+Shift+D, Ctrl+Shift+A, Ctrl+Shift+J | Show Details, Activity, Jobs (the lower bar) |
| Esc | Close the window on top (not while a field has the keyboard). In a filter or search box, Esc clears the text first |

**Defaults for a 60 % keyboard.** Every default is a Ctrl or Ctrl+Shift chord on a
letter, the comma or a digit, which a 60 % board has without a Fn layer. Three
changed in 0.8.3 because they needed keys such a board puts behind Fn or in an awkward
place:

| Action | Before | Now |
|---|---|---|
| Start VM | F5 | Ctrl+Shift+S |
| Stop VM | Shift+F5 | Ctrl+Shift+X |
| Fold or open Details, Activity and Jobs | Ctrl+\` | Ctrl+J |
| Show Details | none | Ctrl+Shift+D |

Ctrl+N, Ctrl+R, Ctrl+U, Ctrl+D, Ctrl+K, Ctrl+B, Ctrl+Q, Ctrl+Comma,
Ctrl+Shift+Y, Ctrl+Shift+A and Ctrl+Shift+J, and Ctrl+1 to Ctrl+9, were already of
that kind and stay. The area keys below (arrows, Home, End, PgUp, PgDn) belong to
the graph, table and terminal that has the focus and are not global shortcuts.

The graph, table, filter and terminal keys (arrows, `F`, `T`, Ctrl+Space, Shift+PgUp
and the rest) are listed by area in the Keyboard shortcuts window; the Triage
graph's are in section 4.

**View > Jobs** (Ctrl+Shift+J) opens a Jobs tab beside Activity, and a "3 jobs"
chip in the status bar (shown only while something runs) opens it. One row per
running job: **Kind**, **Target**, **Started**, a ticking **Elapsed**, a
**Progress** bar when it is known, the **State**, and **Open** and **Stop** where
the job can be stopped. Jobs cover runs (also those still recording after the
root exited), VM start (with the slow TCG boot wait) and stop, VM snapshots,
memory dumps, process cores (also armed ones), static analysis checks per report,
Triage preparing a recording, detection scans, Check online lookups, base
downloads, catalog refreshes, base builds, tool installs, rule and dataset
downloads, MalwareBazaar searches and downloads, Volatility and MemNixFS runs,
plugin downloads, disk jobs, recording saves, exports and update checks. The
**Finished** list keeps the last 20 jobs with how each ended (Finished, Failed or
Cancelled), the time it took and an **Open** link, until **Clear finished**.
Quitting while jobs run asks first and lists them (the VM is shut down and its recordings are saved first). Jobs reads the state the
app already keeps and starts no work of its own.

**Getting started** (Help) has seven steps: **Appearance**, **Base image**,
**First VM**, **Dependencies**, **Analysis tools**, **Rules** and **Finish**. The
first step has the same **Theme** (Dark, Light or Blue), **Text size** and **Density**
(Compact or Comfortable) controls as
**Settings > Appearance** (one shared piece of code, so one set of settings behind
both) and applies each change at once. **Next** keeps what you picked and marks the
step Ready; **Skip this step** leaves the settings as they are. **Help > Getting
started: Appearance** is in the palette.

On **Settings > Recording**, **Default base for new VMs** is the base a new VM
starts with; each VM keeps the base it was created with. Its explanations are
tooltips.

**Settings** has the pages Appearance, Recording, Detection rules, Notifications,
Network lookup, Network routes, Analysis tools, Disks, Keyboard and Advanced. It
opens centred in the window, wide enough that the scroll bar never lies on a text,
with room between the settings; a page with many settings (Recording, Analysis
tools, Advanced) is split under sub-headings. The settings are kept between starts: text size, theme,
density and the debugger's remembered choices all survive a restart (0.8.2 fixed
a bug where an unreadable debugger setting made every start fall back to the
defaults). **Analysis tools** lists each tool with its **Time limit**: the seconds the tool
may run before it is stopped and its check marked Timeout. The field shows the
tool's default beside it ("Default (240 s)": capa 240, FLOSS 480, binwalk 180,
YARA scan 60, UPX unpacking 240, Ghidra decompilation 840, Detect It Easy 120),
and **Reset** puts the default back. A time set for one tool comes before the
older **Time limit for every tool** below it, which still applies to the tools you
did not set; a **Run again with twice the time** from a check's tab uses its own
doubled time for that run. **Settings > Detection rules** has the same **Time
limits** for the detection engines, each with its "Default (N s)" and a **Reset**:
the Triage YARA scan (100 s), Suricata (100 s; its retry and the sandbox time follow
it at twice and 3.6 times), Sigma (110 s) and TShark (300 s per capture, with the
extra time larger captures already got). The time is carried in the detection
request to the worker, and an older settings file has the defaults. The detection
engines have no "Run again with twice the time"; **Scan** runs them again with the
times in force. **Library > Analysis tools** and **Tools > App
dependencies** give a tool the system has a **Use Antinomie's own copy instead**
box: the copy Antinomie installed under its data folder then comes first (until
it is installed the system's copy is used, and the row offers **Install**).
**Install all missing** still skips a tool the system has, so installing the own
copy of such a tool is always your click. The choice is saved per tool.
**Notifications** has **Toast for live HIGH findings** (off) and **Toast
when a run finishes** (on), **Start** (on): the question before starting a
VM that has no snapshot, and **Ask before clearing Activity** (on): the question
before **Clear** empties the Activity log. Both questions have **Don't ask me
again**. A failed **Open folder** or **Open file** raises an
error toast and an **Activity** row.

Layout at narrow windows: a tab bar whose tabs do not fit uses short names
("Trace", "History", "Cores", "Static"; the hover text keeps the full name) and
tighter padding, and when even those do not fit it scrolls the active tab into
view and shows a tab list button at its right end that opens every tab of the bar.
Drag a column divider in a table to widen a column: the last column gives way
first, and when it is at its minimum the table scrolls sideways inside its own
area. Double-click a divider, or right-click it and choose **Fit columns**, to fit
the box again. The dragged widths are kept per table for the session.

The sample **Download** window (**Tools > Download malware samples…**) keeps its
size while it loads: the results area and the Downloaded list have fixed heights
(the Downloaded list shows at least five rows, and more in a taller window),
the status is one line, and it scrolls inside when the screen is small.

A MalwareBazaar lookup by hash reads every field on its own: MalwareBazaar sends
`null` for what it does not know (the last-seen time, the imphash, a comment, a
YARA rule's author) and puts vendor facts in several shapes, and none of that
fails the lookup. A missing value shows as "—". Hover the Family cell of a
result that came from a hash lookup to see its tags, the ClamAV signature names
and the family Triage named.

### Dump when suspicious activity is seen

The command line and Auto mode have the same trigger: `run exec --dump-trigger
TIER [--dump-kind core|memory|both]`, and the policy keys `evidence.dump_trigger`
and `evidence.dump_trigger_kind` (see [auto-mode.md](auto-mode.md)). Both are off
by default. `--core-nonresident` (policy key `evidence.core_nonresident`) makes the
trigger's cores read the pages that are not in memory too, as **Read non-resident
pages** does (a revision-22 base; it needs a core or both trigger); the result reports what fired or that it was armed and nothing matched.

In **Run program > Dumps**, a core that cannot be taken because the process
is gone is not an attempt: it is kept in the run's trigger log as a miss, noted
in the run's notes and shown in the run's features and in the finding's Details
with the reason ("The process exited 120 ms after the match, before the core
could be taken."), and the next match may still dump. A match is judged the
moment its call arrives and the worker wakes every millisecond while a run waits
for one. On a base of contract revision 22, a run that asks for a core holds
each of its processes at its exit, before anything of it is torn down, for at
most 50 ms (400 ms on a TCG guest, such as an arm64 one, where every answer is
slower), until the host has judged that process's last calls: a process that
writes its cron entry and exits a millisecond later still has its core taken
(its note says "held at its exit"), and one no rule matched is let go at once.
Under heavy host load the host can answer after that time, and the process is
then gone as before. On an older base the run's notes say the base cannot hold
a process at its exit, and a program that matches and exits within a few tens of
milliseconds can be gone before the guest can pause it.

A core is partial when the guest could not read every page: it copies only the
pages that are in memory when it reads them (never swapped-out or untouched
pages) and the thread contexts it could park. The core's message says which part
is missing, thread contexts or pages, with the counts. On a base of contract
revision 22, **Read non-resident pages** (under the trigger's core, and in the
**Dump core** dialog of a running process) reads the pages that are not in memory
in as well, from swap or from the file a page belongs to, as a core on exit does;
it takes longer and stays within the core's budget and deadline. Pages the
process never touched hold nothing and stay out. On such a base the guest also
counts what the core lacks, and the message gives its counts (thread contexts
lost, pages left out, pages read in) without opening the core file. On an older
base the box is disabled: the guest reads resident pages only.

The dumps a trigger took are listed in the run's `artifacts.json` under
`trigger_dumps` (the same records as `triggers` in `run.json`); `core_state`
there describes the exit core (Core dump on exit) only. The guest's refusal is
explained in plain words ("The process had already exited, or had started over
...") with its raw state and status in brackets. When the process is still
running under a new identity (a thread of it called exec, which replaces the
main thread's start time), the host asks once more for that process.

Every core and memory dump records where it came from, in its own metadata
(`metadata.json` of a core, `core.json` of a manual core, `dump.json` of a memory
dump): the VM, boot and run (or none), why it was taken (the run's exit, a trigger,
by hand or imported), the process of a core (pid, tid and task cookie), the finding
of a trigger dump (rule and tier) and the time window. The link to the run is
**exact** for a dump the run asked for and for a core whose task is in the run's
process tree, **by time** for a memory dump taken by hand while runs were live
(the dump holds the whole VM, so the live runs are only linked by the time), and
**VM-wide** when no run was live. A record from before this field reads as
unknown ("Not in a run").

**Core dumps** and **Memory** show this as a **Run** line under each entry: the
run's short id and the sample's name; a click opens the run in Triage. The
**This run only** checkbox keeps only the entries of the run selected in Triage
and follows that selection. **Core dumps** also lists the cores a trigger took,
as "Trigger: <rule> (<tier>)", for a run whose Core dump on exit is off, whether
the VM is running or stopped. `core_state` in `artifacts.json` means the exit
core only; "Disabled" there never means the run has no cores.

**Triage > Summary** ends with a **Run artifacts** box: the selected run's cores,
memory dumps and capture segments in the rows of the sample page's Artifacts
(same columns; **Open** shows the tab for this run only), the run's time window,
the packet count of each capture segment and the trigger log (each match that took
a dump, each that came too late, and how many more the budget held back).

### Country and organization of addresses (GeoIP)

**Tools > Settings > Network lookup** decides how the public destination
addresses in the Network tabs get a Country and an Organization. **Address
lookup** has three choices: **TShark GeoIP only** (the default), **dig and whois
only**, and **TShark GeoIP, then dig and whois when unavailable**. Local addresses
are never queried. Below it, **IP geolocation database (TShark)** is about the
first choice: TShark needs `.mmdb` databases to fill Country and Organization.
Older `GeoIP.dat` files (such as `/usr/share/GeoIP` on Debian) do not work with
TShark 4. Antinomie hands its databases to its own TShark runs only and never
changes your Wireshark settings.

**Imported files** on the same page has **Look imported files up at MalwareBazaar**,
off by default. When it is on and you have set your own abuse.ch key (Tools > API
keys), **Add file** sends the new sample's SHA-256, and nothing else, to
MalwareBazaar. If it knows the file, the sample keeps the record (signature and tags),
the custody log notes where it came from, and the signature is a family candidate
shown as "MalwareBazaar signature (looked up by hash)". A sample that already has a
record, or that MalwareBazaar does not list, is left as it is; with the setting off,
or without a key, nothing is sent.

A sample's **Family** field on the Samples page takes its candidates from the newest run
with detections. A sample with no such run (it never started, as a truncated or armhf
ELF on an arm64 base does) takes them from the YARA matches of its newest kept static
analysis report, shown as "Static analysis: ...", so an Elastic `Linux_Trojan_Kinsing_...`
or `Linux_Trojan_Tsunami_...` match names the family without a run.

**Database status.** While it looks, the page says "Looking for databases…". Then
**Country / city** and **Organization (AS)** each show **Database found** or **No
database**, and nothing more. Hover the chip for one line per database: its file
name, where it came from ("TShark's own folder", "Antinomie's DB-IP Lite copy" or
"your folder") and its path. When something is missing, an amber warning says which column stays empty
and how to fix it (install DB-IP Lite in Library > Analysis tools, or choose a
folder in Settings > Network lookup).

**Installing DB-IP Lite.** Under **DB-IP Lite (free, no account)** the page shows
the same row as **Library > Analysis tools**, "IP geolocation (DB-IP Lite)", with
an **Install <month> · <size>** button. The note under it reads: "Country and AS
databases from db-ip.com, CC BY 4.0. By installing you accept that licence and the
attribution it asks for. A cancelled download is kept and resumed when you install
again." The button downloads the month's Country and ASN files from db-ip.com
(checked against a hash pinned in Antinomie) and unpacks them into the data
directory. When it is installed the row reads **DB-IP Lite  Installed by
Antinomie (<month>)** with a **Remove** button ("Delete Antinomie's copy").

**Monthly refresh.** DB-IP publishes one file per month. **Check for a newer
month** makes two small requests to download.db-ip.com and downloads nothing; it
is off, with a note, until **Settings > Detection > Allow outbound catalog and
rule downloads** is on. With downloads allowed and a copy installed, the page asks
once per session by itself. The answer is "Up to date: <month> is the newest
month." or "DB-IP published <month>." with a **Download <month>** button. A newer
month has no published signature, so it is fetched over HTTPS and its SHA-256 is
recorded instead of checked against a pin (the row then says "newer month; its
SHA-256 was recorded, not checked against a pin"). A progress bar shows
"Downloading ... of about ...", "Recording SHA-256" and "Unpacking", with
**Cancel**; a failed ask shows "Could not ask DB-IP: ...".

**Your own GeoLite2 folder.** The text field (or the folder button, **Choose the
folder**) names a folder with `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb`
(GeoLite2 or GeoIP2: a Country or City database and an ASN database). MaxMind
requires a free account to download them, so Antinomie cannot fetch them for you;
the DB-IP Lite install needs no account. The files are read where they are, not
copied. The
**X** button (**Stop using this folder**) clears it.

**Attribution.** DB-IP's licence (CC BY 4.0) asks for credit wherever the data
appears, so the page ends with "IP geolocation by DB-IP" (linking db-ip.com) and
"DB-IP Lite databases, CC BY 4.0" (linking the licence).

### Zooming a graph

In every graph (the Relationships graph, the lineage graph, the VM snapshot graph,
the file activity graph and the Activity graph) the plain mouse wheel scrolls
the page, also over the graph; Ctrl + wheel or a pinch zooms the graph, and a
drag moves it.

### Copy as Mermaid

Every diagram can be copied as a Mermaid flowchart to paste into a README or an
issue. The lineage graph of a sample, the VM snapshot graph and the file
activity graph have **Copy as Mermaid** in their right-click menu; the Triage
process tree, the phases of the Graph tab and the MITRE ATT&CK list in
Summary have a small **Mermaid** button. Labels are escaped and each node's id
is made from its own key (a hash, a task, a snapshot id), so a copy keeps its
ids when the diagram grows.

### Exported tables

HTML and PDF exports never break a column title inside a word: a title wraps only
at spaces, the table keeps the longest word of every title as its least width,
takes a smaller font a step at a time when the longest words side by side are wider
than a page and, as a last resort, is split into column groups with its first
column repeated. The HTML prints on a landscape page. The exports of runs and
samples have a **Tactic** column for ATT&CK techniques (named in text, with the
colour as a chip in HTML and a bar in PDF).

## Command line and automation (0.9.0)

`antinomie-cli` runs the engine without a window: for scripts, for a server with no
display, and for Auto mode, where a sample goes in and a report comes out. This
section takes you from install to a running daemon; the [Command line](#command-line-090)
section below is the reference for every command and exit code, and [Auto mode](auto-mode.md)
explains the pipeline, policies, retention and failure codes.

**Install.** The release archive holds `antinomie-monitor` (the window) and
`antinomie-cli` side by side. `./install.sh` puts both on your path as `antinomie` and
`antinomie-cli` in `~/.local/bin` (`./install.sh --uninstall` removes them; your data
stays). Or run `./antinomie-cli` from the unpacked folder. `antinomie-cli --version`
prints the app version; `antinomie-cli --help` lists the commands. QEMU, bubblewrap
and the other tools are the same as for the window (see [Dependencies and analysis
tools](#dependencies-and-analysis-tools)); the CLI needs no display, GTK or window system.

**Check the host with `doctor`.** `antinomie-cli doctor` lists each runtime tool and who
owns the data folder, and exits 20 when a required one is missing. For an unattended
host say what you need: `antinomie-cli doctor --require qemu,qemu-img,bubblewrap,kvm`.
A missing KVM is only a warning by default (VMs then run with TCG, slowly).

**Use a data folder of its own.** `--data-dir PATH` selects it (the default is
`$HOME/antinomie`, the window's). One process owns a data folder at a time, so give
automation `~/auto`, `/var/lib/antinomie` or similar, never the window's folder.

**The first job.** Install a base into the folder, make the lane VM, and submit one
sample; the command runs the job itself and exits with its code.

```text
antinomie-cli --data-dir ~/auto base install ./bases/busybox
antinomie-cli --data-dir ~/auto auto init --base busybox
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
echo $?     # 0 clean_observed, 30 suspicious, 31 malicious, 32 inconclusive, 10 failed, 11 partial
```

`auto init` makes a VM, boots it once, and takes the clean snapshot that every job
starts from; it also writes `policies/default.toml`. The report files (HTML and JSON by
default) are in `./report`. See [Auto mode](#auto-mode-090) for the job commands.

**The daemon.** For a queue that stays up, run `antinomie-cli --data-dir ~/auto auto
daemon` (in the foreground; under systemd it is a service, see [Run it under
systemd](auto-mode.md#run-it-under-systemd)). `auto submit`, `auto status`, `auto wait`
and the other `auto` commands then talk to it over its socket, and `antinomie-cli ...
config validate` checks `service.toml` and the policies before you reload it with
`SIGHUP`.

**Watch folders.** Add a folder to `service.toml` and every stable file dropped in it
becomes a job under the policy you name:

```toml
[[inbox.watch]]
path = "/srv/drop/default"
policy = "default"
```

Files that are still growing, links, devices and files of other users are never
taken, and a file the intake rejects moves to `rejected/` with a `.reason` file. The
rules are in [Auto mode](auto-mode.md#watch-folders); `antinomie-cli auto watch list` shows each
folder's state.

**Before you leave it running,** read [Unattended use](security.md#unattended-use):
the daemon's user, what the systemd unit restricts, which routes jobs may use, and what
leaves the machine.

## Command line (0.9.0)

`antinomie-cli` is the headless front end: the same engine as the window, with no
display. It ships beside `antinomie-monitor` and does not link the GUI libraries.
It links the same Triage scan (the `antinomie-triage` library), so a recording
made from the command line also keeps the earlier bytes of the files a run
changed: the program that ran the VM copies them when the boot ends.
The grammar is `antinomie-cli [GLOBAL FLAGS] GROUP COMMAND [FLAGS] [ARGS]`; the
global flags may also follow the command.

| Global flag | Meaning |
|---|---|
| `--data-dir PATH` | Data directory (default `$HOME/antinomie`; `~` is expanded). Use a directory of its own for automation, never the one the window uses |
| `--bundle PATH`, `--qemu PATH`, `--qemu-img PATH`, `--tcg`, `--no-headless` | Engine options, as in the window. The CLI is headless unless `--no-headless` is given |
| `--boot-wait SECONDS`, `--tcg-multiplier N` | The waits of a VM start and a launch for this command, over `settings.json`'s `start` section (the window's **Tools > Settings > Advanced**, VM start and guest connection timeouts; `config set start.boot_wait_secs 120`). `--boot-wait` (5 to 600, default 60) is how long a launch waits at KVM speed for a Debian guest to finish booting before it starts the program anyway; `--tcg-multiplier` (1 to 100, default 10) is how many times longer every start wait, that boot wait and each guest command may take under TCG. They matter to the commands that start an engine with a VM: `vm start`, `run exec --start`, `snapshot restore`, `auto daemon` |
| `--socket PATH` | The daemon's socket (default `<data>/run/antinomie.sock`) |
| `--daemon`, `--direct` | `--daemon` requires a running daemon (exit 21 when none answers), `--direct` never uses one. Without either, the `auto` commands and the reads (`run list`, `run show`, `run export`, `triage`, `sample list`, `sample show`, `sample tag`, `custody verify` without `--export`, `vm list`, `base list`) use the daemon when one answers and work in the calling process when none does. The other commands always run in the calling process and take the lock (`--direct` and `--daemon` conflict) |
| `-o, --format human\|json\|ndjson` | Output format; `human` on a terminal, `json` otherwise |
| `--color auto\|always\|never` | Colour of human output; `NO_COLOR` is honoured |
| `-q`, `-v`, `-vv`, `--log-format text\|json` | Log lines on standard error |
| `--timeout SECONDS` | Overall limit of the command |

**Output.** `json` prints exactly one document on standard output:
`{"api_version":1,"ok":true,"result":...}`, or on failure (with a non-zero exit)
`{"api_version":1,"ok":false,"error":{"code":...,"message":...,"retryable":...,"details":...}}`.
A list result is `{"items":[...],"next_cursor":...}`. `ndjson` prints one object
per line: a list command prints its items and then a last line
`{"result":{"count":N,"next_cursor":...}}`; any other command prints
`{"result":...}`; a failure prints `{"error":...}`. Log lines stay on standard error.

**Exit codes.**

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Success |
| 1 | failed | Other failure |
| 2 | usage | Bad arguments |
| 3 | not_found | Sample, run, VM, base or job does not exist |
| 4 | invalid | The arguments were refused (`invalid_argument`, `precondition_failed`, `conflict`) |
| 5 | denied | Policy or file permission |
| 10 | job_failed | A waited job (or `run exec`) failed |
| 11 | job_partial | A waited job (or `run exec`) ended partial |
| 12, 13 | job_cancelled, job_rejected | A waited job was cancelled, or a submitted job was rejected |
| 14 | wait_timeout | A wait ran out: the engine did not answer in time, or `--timeout` passed (the job is still queued or running; `run exec` stops the VM) |
| 20 | dependency | A required tool is missing; `doctor` shows which |
| 21 | busy | The data directory is owned by another process, or the daemon is starting or stopping |
| 22 | quota | `quota_exceeded` |
| 30 to 32 | suspicious, malicious, inconclusive | With `--verdict-exit` only: the waited job succeeded and its label is `suspicious` (30), `malicious` (31) or `inconclusive` (32). The job's state comes first: a partial or failed job exits 11 or 10 whatever its label |
| 130 | interrupted | Interrupted with Ctrl-C |

**Commands in this build.** This list is what `antinomie-cli --help` shows; the
`auto` commands are in [Auto mode](#auto-mode-090) below, and the walk-through from
install to a daemon is [above](#command-line-and-automation-090). The web layer is not shipped yet.

- `doctor [--require tool,...]` lists the runtime tools and exits 20 when a
  required one is missing. Without `--require` the tools the window also treats as
  required count; a missing KVM is a warning (VMs then run with TCG). Tool names:
  `qemu`, `qemu-img`, `gtk`, `kvm`, `curl`, `debian-account`, `bubblewrap`,
  `tshark`, `prlimit`, `suricata`, `python-venv`, `wireshark`, `file-chooser`.
- `capabilities` prints the API version, the app version and revision, the lane
  count, the report formats and the accelerator (`kvm` or `tcg`).
- `doctor` also reports who owns the data directory (`data_dir.owner`, from
  `run/owner.json`, ignored when its process is gone). A command that needs the
  engine while the window owns the directory exits 21 and names the window.
- **Bases.** `base list` lists the installed bases (`--remote` fetches and lists the
  catalog's; needs `config set outbound_catalog true`, exit 5 otherwise). `base install
  DIR` installs a boot-bundle folder. `base download ID [--wait]` fetches one from the
  catalog and `base build [--profile busybox|debian-minimal|debian-xfce] [--engine
  automatic|native|podman|docker|qemu] [--name N]` builds one here; both wait for the
  end in direct mode, because leaving would cancel them. `base delete ID --yes` removes a
  base no VM uses. A base is named by its identity, the start of it (4 characters or
  more) or its label.
- **VMs.** `vm list`, `vm status ID` (state, boot, guest kernel, snapshots, a pending
  disk layer), `vm create NAME [--base ID] [--cpus N] [--ram-mib N] [--disk-gib N]
  [--network disconnected|isolated|routed|nat] [--stealth realistic-desktop|
  realistic-laptop|realistic-server|transparent] [--user NAME] [--password-stdin]`,
  `vm start ID [--wait] [--hold [SECONDS]]`, `vm stop ID`, `vm reset ID --yes`,
  `vm duplicate ID NAME` and `vm delete ID --yes`. A VM is named by its identity or
  its name. The defaults are the window's (4 CPUs, 2048 MiB, 8 GiB, disconnected,
  realistic desktop). A Debian base needs a guest account: give the password as one
  line on standard input with `--password-stdin` (never on the command line); a base
  with no account refuses the flag. `vm reset` is refused for a VM that has snapshots
  (duplicate it first). Every destructive command (`base delete`, `vm reset`, `vm
  delete`, `snapshot restore`, `snapshot delete`) refuses without `--yes` and exits 4.
- **Snapshots.** `snapshot list VM`, `snapshot create VM NAME [--mode disk|full]
  [--description TEXT]`, `snapshot restore VM ID [--cold-boot] --yes` and `snapshot
  delete VM ID --yes`. A Disk snapshot keeps the stopped VM's disk; a Full one also keeps
  the memory of the running guest. A snapshot is named by its identity or its name.
- **Run a program.** `run exec SAMPLE` uploads one library sample into a VM, runs it, and
  waits until the recording is complete and settled. `SAMPLE` is a SHA-256 from `sample
  list`, or a file, which is added to the library first. The low-level form of what an
  Auto job does: no revert, no triage, no report. Flags: `--vm ID` (optional when there is
  one VM), `--start` (boot a stopped VM; without it a stopped VM is refused), `--args A B
  ...` (or after `--`), `--env K=V`, `--as user|root|UID:GID` (`user` is UID 1000),
  `--route drop|internet|inet_sim|tor|vpn|socks5` (a routed VM only), `--timeout-run
  SECONDS` (default 300: the run is then told to stop), `--net-capture`, `--memory-dump`,
  `--core-dump`, `--dump-trigger low|medium|high` (take a dump when the live Triage rules match at that tier or above, as the window's **Dump when suspicious activity is seen**; default off) with `--dump-kind core|memory|both` (default `core`; a core needs a revision-16 base), `--core-nonresident` (the trigger's cores also read pages that are not in memory, as **Read non-resident pages**; needs a core trigger and a revision-22 base), `--static CHECKS` (the guest-side analysis too), `--load-into PROGRAM` (the sample is a shared library: it is uploaded, then the guest program PROGRAM, an absolute path, runs with `LD_PRELOAD` set to it, and the run is linked to the library sample) and `--wait` (always on in
  direct mode). The program runs in the app terminal as `/tmp/<sha8>-<name>`; the end of
  its output is in the result. The wait covers the evidence the way the window's runs do
  (network capture, memory dump and core finished, up to 300 s), then stops the VM and
  waits until the recording is final: the stop is saved and the disk layer is gone.
  The result says `outcome`: `succeeded` (exit 0), `partial` (exit 11: a piece of evidence
  finished incomplete), or `failed` (exit 10, with `failure.code` such as `no_vm`,
  `upload_failed`, `launch_failed`, `guest_lost`, `recording_failed`, `internal`). It also
  gives the run (state, exit status, why it ended: `exited` or `run_limit`; for a launch the
  guest refused, `failure.run_id` and `run.id` name the "Failed to start" record, when the
  launch kept one, and `failure.detail` the explanation), the evidence
  states and paths, the time per stage and the output. The launch carries the library's copy of the sample as its host copy (read only; a private file removed when the run ends), so a program the guest refuses still gets static analysis. With `--dump-trigger` it also has a
  `triggers` object: what was armed (`tier`, `memory`, `core`), `fired`, each match (`rule`,
  `tier`, `pid`, `syscall`, and the `core` and `memory` dump with `state`, `size` and `path`),
  the counts of matches missed, skipped over the budget or lost, and `notes` (the run is
  noted "armed, but no rule of that tier matched" when nothing fired). `--events` prints the progress as it
  happens, one event of the job API per line (`job.stage`, `job.progress`, `job.run`,
  `job.warning`, `job.trigger`, `job.finished`; `job_id` is null, `seq` counts from 1), then the result;
  it implies `-o ndjson`. `--timeout SECONDS` limits the whole command (exit 14).
  While the guest finishes mounting its disk the upload is tried again once a second, and
  `job.progress` says so at most every five seconds, with the count of tries.
  **Under TCG** (every arm64 VM on an x86-64 host) the upload, launch and guest-answer
  waits, and the minute after which an unanswered guest command is `internal`, are
  stretched by the same factor as the engine's own waits: the TCG multiplier times the host
  load factor. The time the engine reports waiting for a Debian guest to finish booting
  does not count as silence. The `Start` of the VM is the same: its 180 s is a limit on
  silence, and under TCG the time the engine reports waiting for the guest to connect does
  not count against it (at most 30 minutes in all); under KVM it is 180 s as before.
  If the engine still answers a launch after the job gave up
  on it, the VM is stopped (which ends the program), the result names that run and a
  `late_launch` warning says what happened.
- **Run digests.** `digest RUN` builds the Triage digest of one finished run, and
  `digest --pending` builds it for every finished run that has none (or whose digest
  was made while its recording was still being written and has changed since), one at
  a time. It is the same build the window and Auto mode run on their own; use it for
  runs older than a week, which the window leaves alone, or after an interruption
  (nothing is written until the digest is whole, so running it again is safe). `--max-calls`
  (default 400000) and `--max-seconds` (default 1200) are the budget of one build. It
  writes the digest into the run's folder, so it takes the engine lock (exit 21 while a
  window or daemon owns the data directory); the result lists each run as `built`,
  `built_partial` (with the reasons), `current` (nothing to do), `busy` (another build
  of the run holds it) or `unreadable`.
- **Triage, detection and reports of a saved run.** `triage RUN [--parts LIST]`,
  `detect RUN [--engine yara,sigma,ids] [--out DIR] [--save]` and `report RUN
  [--formats html,pdf,json,misp,stix,md] [--parts LIST] [--evidence-bundle] [--defang |
  --no-defang] [--include-content] [--out DIR]` read a saved run with no window.
  `RUN` is the run's id or its first characters (4 or more), `vm:boot:run`, a run
  key, or the run's folder; every VM of the data directory is searched. Each command
  indexes the whole run the way Triage does when the run is selected, with the
  data directory's `settings.json` (the window's defaults when there is none) and
  with `dig` and `whois` lookups off (TShark's installed GeoIP fields stay); the
  progress goes to standard error and Ctrl-C stops it (exit 130).
  `triage` prints Triage's Summary as the query API serves it
  (`recording.summary`): the assessment and its basis, the counts, the
  families, the techniques, the key behaviours and the detections, and it writes
  nothing into the recording; `--parts` adds report parts to the result (`summary`, `indicators`, `attack`,
  `processes`, `findings`, `files`, `file_activity`, `network`, `detections`,
  `evidence`, `custody`, or `all`). `report` writes the files the window's
  **Export report** writes for the same run and choices (see
  [Triage report export](triage-report.md)); formats and parts default to the
  export choices in `settings.json` (HTML and PDF, every part, defanged), and the
  files go to `--out` (default `report-<first 8 characters of the run id>` in the
  current folder), never into the recording. A recording over 1 GB that has to be read is warned about on standard error first (and the JSON result carries `large_recording` with its size and the estimated seconds). `detect` runs the engines over the
  run's evidence as the Detection tab does: the same evidence check, the same frozen
  rule selection and the same sandbox. YARA needs the static analysis of the run's
  sample (`run exec --static`), IDS a capture (`run exec --net-capture`), Sigma the
  event journal the index writes; an engine without its evidence is listed as not
  scanned, with the reason. Without `--save` nothing is written into the recording:
  the matches are printed and `--out DIR` writes each engine's full result as
  `detection-<engine>.json`. `--save` keeps the results where the Detection tab keeps
  them and adds them to the run's digest, so a later `report` lists them; it takes
  the engine lock (exit 21 while the window owns the data directory). `detect` exits
  1 when an engine failed. Apart from `detect --save`, these commands take no lock.
  `report`, `detect` and `triage --parts` write nothing into the recording but the
  index Triage keeps there (its event and finding journals), as the window does
  when it shows the run; `triage` without `--parts` writes nothing.
- **Look at recorded runs.** `run list [--vm ID] [--sample SHA256] [--job ID] [--state
  STATE] [--since SPAN] [--limit N] [--cursor C]` lists the recorded runs of the data
  directory, newest first (`--since` takes a span such as `90m`, `24h` or `7d`, or a
  Unix time in milliseconds). A run held open for a persisted copy (see *Copies of
  the program outside the recorded tree*) shows `held` in the STATE column, and its
  JSON item has `held` ("Held: persisted copy running (pid 1050, .e)") beside
  `state`, which still says how its tree ended. `run show RUN [--summary]` shows one run: its state,
  whether its recording is `live`, `finalizing`, `complete` or `interrupted`, its
  evidence and `generation`; `--summary` adds the Triage summary. `run export RUN --out
  DIR [--part LIST] [--sensitive]` writes the parts `trace`, `processes`,
  `findings`, `indicators`, `files`, `network`, `timeline`, `analysis`, `custody`
  and `artifacts` (default: all) as `*.ndjson` files, one row per line (a `trace` row's `nr` is the number the guest used for the call; `args_preview` holds the engine's raw argument previews, and the decoded records are in the Syscall Trace's own JSON export), and the
  retained evidence files of `artifacts` into `DIR` and nowhere else; the bytes the
  sample produced are written only with `--sensitive`: the capture, memory and core
  files and file copies (`artifacts/`), the contents of changed files (`files/`), the
  captured bytes of calls (`captured/`, named by `captured.ndjson`) and the frames of
  the recorded packets (`network-packets-<capture>.ndjson`, one `{n, frame_len,
  bytes_b64}` line per packet). The frames are capped at 100 000 packets and the
  captured bytes at 10 000 fields and 256 MiB per export; a file list entry says
  `truncated` when a cap was reached. With a daemon each of these reads is written to
  its service log; `--no-triage` leaves out the
  parts that need the Triage index (findings, indicators, files, network, timeline), so
  a very large recording is not indexed in full. `RUN` is as for `triage`.
  These commands are the read-only query API of the job API (`docs/job-api-1.md`,
  "Recording queries"): they take no engine lock and write nothing into a recording,
  so they work while the window is open. A recording that is still being written
  (`live`) can be listed, shown and exported in its core parts, but its Triage parts
  (summary, findings, indicators, files, network, timeline) are refused with exit 4
  until it is saved. The first Triage part of a run indexes it, with progress lines
  on standard error; Ctrl-C stops (exit 130) and `--timeout SECONDS` limits the wait
  (exit 14).
  **With a daemon** (`auto daemon`) at the socket these commands, `triage`, `sample
  list|show|tag`, `custody verify` (without `--export`), `vm list` and `base list`
  ask the daemon and print the same objects; `--direct` keeps them in the command and
  `--daemon` insists on the daemon. `run export` still writes only under `--out`: the
  command asks the daemon for the rows and the bytes and writes the files itself, so no
  path is sent to the daemon. `triage --parts` builds its report parts in the command
  from the recording folder (no lock is needed). `vm list` and `base list` from the
  daemon print the contract's summaries (id, name, base, lane; identity, name,
  architecture), fewer columns than direct mode, which needs the lock and so cannot
  run beside a daemon. `run list` shows the `job_id` of the Auto-mode job that made a
  run, and `--job` finds its runs, both through the daemon and in direct mode (the
  command reads the job store without writing). With a daemon `sample add FILE`
  uploads the file and adds it as the socket's caller (`local:<uid>`);
  `--delete-original` then removes the file after the daemon reported the same
  SHA-256. `sample verify`, `sample remove` and `custody verify --export` work in the
  command: they read or write files by path.
- **A VM lives as long as the command.** In direct mode the engine runs inside the
  command and stops the VM when the command ends, so `vm start` boots the guest, waits
  until it answers, reports how long that took and stops it again; `--hold` keeps it
  up for that many seconds, or until Ctrl-C (exit 130) when no number is given. `vm
  stop` stops a VM this process started, and says so when there is none. `snapshot
  create --mode full` boots the VM first, and `snapshot restore` shows the restored
  guest answering and stops it. Keeping a VM up between commands is what the daemon
  (`--daemon`, not built yet) is for. Progress lines go to standard error, Ctrl-C
  stops the VM cleanly, and `--timeout SECONDS` limits the waits (exit 14).
- `sample add FILE... [--name N] [--tag K=V] [--delete-original]` hashes and archives
  files in the library (never runs them) and prints the SHA-256 of each; a tag is
  `verdict=`, `category=`, `technique=` or `custom=` plus a value, or a bare custom
  value. `sample list [--q TEXT] [--tag K=V] [--limit N] [--cursor C] [--all]
  [--custody]`, `sample show SHA256 [--origins] [--events] [--runs]`,
  `sample tag SHA256 TAG... [--remove]`, `sample verify [SHA256]` (exit 1 when an
  archive does not match its hash) and `sample remove SHA256 --yes` (deletes the
  archive; the record and its custody log stay). A sample is the `Sample` object
  of the job API: `sha256`, `size`, `type`, `architecture`, `name`, `tags`,
  `first_seen_ms`, `run_count`, `last_job`, `custody_ok` (null unless
  `--custody` or `show`). These commands and `custody verify` need no engine
  lock, so they work while the window is open.
- `custody verify [SHA256] [--export PATH] [--sign minisign|ssh --key KEY]` checks
  the custody chain of one sample, or every chain and the library index when no
  SHA-256 is given (exit 1 when something does not verify). `--export` writes the
  custody record of the sample (JSON with `verify-custody.py` beside it, or a
  readable page for a `.html` path), optionally signed with your own key.
- `analyze FILE [--checks LIST] [--time-limit-min N] [--out DIR]` adds the file to the
  sample library, runs the static analysis of that copy on the host, with no VM, and
  prints a summary of each check. It starts the engine itself (so it needs the data
  directory to be free: exit 21 names the owner) and needs bubblewrap. The report folder
  is `<data>/analyses/<report id>`; `--out` also copies it, and the folders of any
  unpacked layers, into `DIR`. `--checks` takes the names metadata, structures,
  strings, regex, entropy, hardening, rules, identification, capabilities,
  disassembly, decompilation, embedded, floss, unpacking; the default is the
  triage set.
- `rules list [--engine yara|sigma|ids]` lists the installed rule packs and
  custom groups with their state; `rules enable ID` and `rules disable ID` switch
  one (`pack:ID` or `group:ID` when an id names both). Changing the selection
  takes the data-directory lock; listing does not.
- `config path` prints the paths of `settings.json`, `service.toml` and `policies/`.
  `config get [KEY]` prints one engine setting, or all of them; a dotted key reaches
  into an object (`disks.hide_dotfiles`) and the command takes no lock.
  `config set KEY VALUE` changes one (the value is JSON when it parses, else text) and
  takes the engine lock, so it refuses while the window owns the data directory.
  `settings.json` is the file the window itself now uses for its engine settings,
  including the VM start waits (`start.boot_wait_secs`, `start.tcg_multiplier`,
  `start.guest_connect_secs`, `start.kvm_fallback`), which the CLI and the daemon start
  their engine with.
  `config validate [--policy NAME]` checks `service.toml` and `policies/*.toml`
  without starting anything (see [service configuration](service-config.md)); it
  prints each problem as `file:line:column` and exits 4 when there is an error.
- Not shipped yet: watch folders, retention (`auto gc`), result files and
  notifications. The job contract is written down in [Job API,
  version 1](job-api-1.md).

### Auto mode (0.9.0)

Auto mode runs samples unattended: a sample goes in, it runs in a VM that is
reset to a clean snapshot first, the recording is analysed, and a report and a
label come out. Give it a data folder of its own (`--data-dir`), never the one
the window uses: one process owns a data folder at a time, and the daemon keeps
it for as long as it runs.

The pipeline, policies, retention, failure codes and troubleshooting are in
[Auto mode](auto-mode.md); this section lists the commands.

**The daemon.** `antinomie-cli --data-dir ~/auto auto daemon` runs in the
foreground until it is stopped; put it in the background with your service
manager or `&`. It owns the data folder (`run/owner.json` says "daemon" and names
its socket), so the window, another daemon or a command that needs the engine on
that folder is refused with exit 21 and told who owns it. It reads
`service.toml` and `policies/` (see [service configuration](service-config.md)),
finishes what a crash left behind, runs the queue one job at a time on its lane,
and serves the job API on `<data>/run/antinomie.sock`.

| Signal | What the daemon does |
|---|---|
| `SIGTERM` or Ctrl-C | Stops taking jobs (queued jobs stay queued). A job that is past its VM stages finishes its analysis and report first, for up to 120 s (`[daemon] shutdown_host_grace_s`). A job still in the VM is stopped and put back in the queue without using an attempt |
| a second one within 5 s | Stops at once, VM included (exit 130); the next start finishes the rest |
| `SIGHUP` | Reads `policies/` and `service.toml` again; a file with an error keeps the old settings. Jobs already queued keep the policy they were submitted under |
| `SIGUSR1` | Writes the queue's state to the log |

**Setting up the lane.** A lane is one VM kept for automation, with a clean
snapshot that every job starts from.

```text
antinomie-cli --data-dir ~/auto base install ./bases/busybox
antinomie-cli --data-dir ~/auto auto init --base busybox --cpus 2 --ram-mib 2048
```

`auto init` creates the lane VM (`--name`, default `auto-1`) on a routed network
(each job chooses where its traffic goes; between runs nothing leaves), boots it
once and waits for the guest to answer, stops it, waits until its disk has settled,
takes the Disk snapshot `auto-clean` (`--snapshot`) and writes
`<data>/service/lanes/lane-1.json`. When the folder has no policy yet it writes
`policies/default.toml`, pointed at the new VM; that policy accepts ELF x86-64
programs only (add `"sh"` to `[sample] accept_types` for shell scripts). A Debian
base needs a guest account: `--user NAME --password-stdin`, the password on
standard input. `auto init` runs in the calling process, so stop the daemon first;
`--replace` makes a new lane VM for an existing lane (a new base) and keeps the old
VM for you to delete. `auto lane list` shows the lane, whether it is quarantined and
what would keep it from a job; `auto lane reset --yes` reverts the VM to its clean
snapshot now and lifts a quarantine when that works; `auto lane unquarantine` lifts
it without reverting when the checks pass (the clean snapshot is there, the VM is
stopped, nothing is still being saved).

**Submitting and following jobs.**

| Command | What it does |
|---|---|
| `auto submit FILE` (or `--sha256 HEX`) | Uploads the file to the daemon and queues a job; prints the job. `--policy`, `--priority`, `--label K=V`, `--timeout-run S`, `--args ...`, `--env K=V`, `--as user\|root\|UID:GID`, `--route drop\|inet_sim`, `--static none\|triage\|CHECKS`, `--no-static`, `--formats html,pdf,json,misp,stix,md`, `--evidence-bundle`, `--defang`/`--no-defang`, `--idempotency-key K`, `--name`. The policy decides what a job may change. `--wait` waits for the end and exits with the job's code; `--follow` also prints the job's events as NDJSON; `--verdict-exit` waits and exits 30, 31 or 32 for a succeeded job labelled suspicious, malicious or inconclusive; `--out DIR` copies the report files there. A rejected job exits 13 |
| `auto status [JOB]` | One job, or the queue and the lane |
| `auto list` | Jobs, newest first: `--state`, `--outcome`, `--sha256`, `--label K[=V]`, `--since 24h`, `--limit`, `--cursor` |
| `auto wait JOB...` | Waits until the jobs have ended (`--timeout` bounds it, exit 14) and exits with the worst code; `--verdict-exit` as above |
| `auto events JOB` | The job's stored events; `--since SEQ` starts after an event, `--follow` keeps printing new ones until the job ends, `--types job.stage,job.state` filters. `auto events --all --follow [--since GSEQ]` follows every job and the engine |
| `auto result JOB` | The outcome, the label, its score and basis sentence, and the paths of the report files |
| `auto artifacts JOB`, `auto fetch JOB KIND [--out PATH\|-]` | The job's artifacts; copy one (`html`, `json`, ..., or `report.bundle`) to a file, a folder or standard output |
| `auto cancel JOB [--reason TEXT]` | A queued job is cancelled at once; a running one stops its run and VM and ends `cancelled` (its recording is kept) |
| `auto retry JOB [--override KEY=VALUE]` | A new job from a finished one, with `repeat_of` set |
| `auto queue status\|pause\|resume` | The queue; a paused queue starts no job (running jobs finish) |
| `auto policy list` | The policies you may submit to |
| `auto delete JOB [--with-recording]` | Removes a finished job: its record, events and artifacts (the sample stays in the library). `--with-recording` also deletes the job's recording through the run deletion the window uses; a recording a client is reading, or still being written, is refused |
| `auto gc [--dry-run]` | Applies retention now (below) and prints what was deleted and what was skipped and why; `--dry-run` deletes nothing. Works with a daemon, or on its own when none runs |
| `auto watch list` | The watch folders: state, files taken, files rejected, entries refused and why. Without a daemon, the folders `service.toml` names |
| `auto watch scan` | Scans every watch folder now (a file still has to be steady for 3 seconds). Needs the daemon |

Without a daemon, the reading commands read the job store directly (they work
beside the window), `cancel` and `queue pause/resume` take the data folder for a
moment, and **`auto submit` runs the job in the command itself**: it owns the data
folder while the job runs and exits with the job's code, so one command takes an ELF
to a report:

```text
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
echo $?     # 0 clean_observed, 30 suspicious, 31 malicious, 32 inconclusive, 10 failed, 11 partial
```

**Watch folders.** Name a folder in `service.toml` and every file dropped into it
becomes a job:

```toml
[[inbox.watch]]
path = "/srv/drop/default"
policy = "default"
delete_after = "move"       # processed files go to <data>/inbox/processed/
```

A file is taken about 3 seconds after it stops changing, so a file being copied in
is never read half-way, and names ending `.part`, `.tmp`, `.crdownload` or starting
with `.` are waited for. The daemon opens each file from inside the folder without
following links, and refuses what could lead out of it: a symbolic link, a device or
FIFO, a file with more than one hard link, a file of another user. It uses the
folder only when it is yours and no one else can write to it (a group-writable folder
needs `allow_group_write = true`; a folder anyone can write to is never used).
Refused entries are left alone and listed by `auto watch list`. A file the intake
rejects (wrong type, too large, a duplicate the policy denies) goes to
`<data>/inbox/rejected/` with a `.reason` file and is not tried again. More than
`watch_rate` (10) files a minute pauses the folder for a minute and raises an
`engine.alert` `watch_flood`. `policy_by_dir = true` makes a subfolder named after
a policy use that policy; other subfolders are ignored. The jobs carry the label
`watch=<folder name>` and the custody actor `auto:policy-<policy>`. The keys are
in [service configuration](service-config.md#watch-folders).

**Results and the hook.** With `[results] dir` set, each job that ends leaves
`<dir>/<date>/<sha8>-<jobid>/` with its `job.json` and its reports, for a program
that polls a folder. With `[notify] on_finish = ["/path/to/hook"]` the daemon runs
that program when a job ends, without a shell and with only `ANTINOMIE_JOB_ID`,
`ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and
`ANTINOMIE_RESULT_JSON` (the path of `job.json`) in its environment. It has 30
seconds, runs as the daemon's user, and what it prints goes to the job's `job.log`.
A failing hook never fails a job; it raises an `engine.alert` `hook_failed`.

**Retention.** The daemon cleans up after itself once an hour: a recording is
deleted 14 days after its job ended (through the window's own run deletion; a failed
job's is kept until its record goes), the oldest recordings go first above 200 GiB,
a job's record and artifacts go after 90 days, staged uploads after 24 hours and
rejected inbox files after 7 days (`[retention]` in `service.toml`). It never
touches a job that has not ended, a recording that is being read through the API or
written, the sample library or the custody chain. `auto gc --dry-run` shows the
plan first; every deletion is logged with the job and run id.

**The label.** A succeeded job has an assessment: the raw Triage assessment, the
highest tier, a policy label (`malicious`, `suspicious`, `clean_observed`,
`inconclusive`), an optional score and the `basis` sentence that says why.
`clean_observed` means "nothing seen in this run", not "clean". With `[verdict]
tag_library = true` in a policy, the sample also gets the library tags
`auto:label=<label>` and `auto:policy=<name>`, recorded in its custody chain under
the actor `auto:policy-<name>`.

**Who can talk to the daemon.** Only you. The socket file can be opened only by
its owner (mode 0600, in a folder only you can enter, 0700), and on every
connection the daemon asks the system which user is on the other end and closes
the connection, without a word, unless it is the user the daemon runs as. Every
local client therefore acts as you, with every right. The daemon never opens a
file a client names: a sample travels over the socket in pieces and is checked and
stored by the daemon, and a report path it hands back is checked to be inside the
job's own folder. Each request is checked strictly (an unknown field is an error
that names it), and the socket has limits so a broken or hostile local program
cannot wear the daemon down: 2 MiB per message, 16 requests at a time and 50 a
second per connection, 64 connections, 64 event subscriptions, idle connections
closed after 5 minutes, and a client that stops reading is dropped. Nothing the
daemon does contacts the network on its own; a sample's traffic is dropped unless
its policy chooses the simulated internet (`inet_sim`).

**Event streams.** Every change of a job is an event with a number: `seq` counts
the events of one job, `gseq` counts every event of the daemon and never repeats.
A client that lost its connection asks for the events after the last number it
saw and gets each one exactly once, then the new ones as they happen.

## Troubleshooting

- **Moving the data folder (0.9.0).** Close Antinomie, move or copy the whole data
  folder (bases, VM folders, `vm-locations.json`), and point the app at the new place
  (`--data-dir`, or the default location). Installed bases record their files
  relative to their folder, and bases installed before 0.9.0 are found by file name
  inside their own folder. At the next start the app repairs the paths a VM keeps
  outside its base (`vm-locations.json`, the VM's `bundle.json`, the backing-file
  names inside `disk.qcow2` and `snapshots/`), and prints what it could not repair
  on standard error as "data folder: ...". A base that still cannot load is listed
  in the Library with its reason and in `antinomie-cli base list`, and the menu bar
  says "Base image not usable". Left as they were: a VM or recordings folder placed
  outside the data folder (it stays where it was recorded), the recorded start
  state of a boot (`disk-start.json`, only used to read a run's earlier file bytes),
  and the user's own absolute paths in settings.
- **A run is missing from Run History.** A run whose files cannot be read still
  shows (0.9.0), with "run record unreadable" and the reason; its folder is
  untouched. Older builds skipped a run whose analysis report had gained a check
  after the run (Analyse more); 0.9.0 lists it.
- **"Data folder is already in use" (0.9.0).** One process owns a data folder at a
  time: the window or an `antinomie-cli` command that needs the engine. The message
  now names the owner (its pid, whether it is the window or a command, and since
  when), taken from `run/owner.json`. Close that process, or give the second one a
  folder of its own with `--data-dir`. A record whose process is gone is ignored.
- **Settings did not survive a restart** (0.8.1 and earlier): fixed in 0.8.2; the
  debugger's remembered choices were saved in a form the settings file could not
  read back, so every start used the defaults. Set them once more.
- **A VM creation failed on a busy computer**: the offline credential tool's
  deadline grows with the host's load (up to four times) and a timeout starts again
  once from a fresh disk; a creation that still fails says "VM creation failed"
  with the reason and that the unfinished disk was removed.
- **Core dump on exit with Debug on start** works together since 0.8.2; a capture
  that cannot be armed names the size and first bytes of the guest's reply.
