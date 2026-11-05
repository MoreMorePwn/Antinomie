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
   network is disconnected by default.
2. **Upload file** copies a program from the host (**Host file**) to a path in
   the guest (**Guest path**).
3. **Run program** runs it. Set the **Executable**, **Arguments**,
   **Working directory** and **Environment**. Each launch gets its own terminal
   window for input and output.
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
   evidence identity is the guest's hash either way.
6. **Attach to process** traces a process that is already running in the guest
   (and its future children); **Capture all** traces all of userspace. Neither
   stops or signals anything. A capture lists the processes it saw as a tree
   (named after the program each one ran); select one to see only its calls.
7. With the guest network connected, select **Capture network** to record
   packets of the VM's network interface outside the guest. Stop it to finish the capture;
   each start creates a separate retained pcap in the boot recording.
   On a Routed VM, **Route** in the same section picks where the run's traffic goes
   (see *Network routes* below).

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
  folder (`network/tor`, readable by you only) and no control port, and stops it
  when the run ends. The run waits for Tor to finish bootstrapping (up to two
  minutes) and does not start if it cannot; a first start is slower than later
  ones, which reuse the folder. The other mode connects to a Tor you run yourself
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
  lists every member. Other structs, times, integers and pointers show in hex.
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
  Only the x86-64 layouts are decoded for now.
- **Run History**: every run on the selected VM, including earlier boots, with
  its command line, user, status and exit code. The state is coloured (see
  *Run states* below). Double-click a run to open its
  Triage view. Select a trace entry to inspect its recorded call details.
  The table spans the pane. A run's details list **Analysis enabled** as a tree:
  the static analysis with its checks below it, then the capture options; a check
  that produced no result, or a capture that was deleted or failed, is greyed.
  In a process's Details, **Show its calls** opens **Syscall Trace**
  filtered to that process (clear the filter to see all).
- **Export report…** (right of the Triage tabs): writes the whole Triage as
  HTML, PDF, JSON, MISP or STIX 2.1, with a checkbox per section, optional IoC
  defanging and an optional evidence bundle. See
  [the report guide](triage-report.md).
- **Triage › Process › Process tree**: one row per task, in the columns
  **Process** (tree lines, the executable's file name and `(pid · tid)`; the
  full path on hover; a fork that has not exec'd shows its parent's image
  greyed with "fork"), **Command line** (a ⚠ when argv[0]'s file name is not
  the executable's, with the explanation on hover; BusyBox applets,
  interpreters through symlinks such as python3 and python3.13, sh and dash,
  and a login shell's leading `-` do not warn), **Findings** (the count,
  coloured by the worst tier; click it to list that process's findings),
  **User** (uid, or uid → euid, from the guest's credential records),
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
  calls, kernel records and packets, with the **Time** of each row first. Each row has a tier (HIGH, MEDIUM, LOW;
  INFO is only counted unless **Show INFO** is on), a category and an ATT&CK
  reference. Repeats fold into one row with a count, a failed call or a program
  that does the thing as its job lowers the tier by one, and **Details** says
  why a row has its tier. The chips narrow the table by tier and category (each
  category chip carries the icon its markers have in the graph). A row
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
- **Triage › Files › Per-file history** is the first tab of Files, before Opened, with
  the number of files the run touched on it (it was a floating window). The
  left list holds every file the run touched, in order of the first call (also
  those that were only opened, read or probed); **Hide stdio**, **Hide library**
  and **Changed only** narrow it, the filter matches the path and any other name
  the file was given, and the order can be first or last touched, most calls or
  path. Choose a file to see its history as a graph: one box for each stretch of
  the same call by the same process (create, open, read, write ×3, rename, delete),
  joined in the order the calls happened, on a lane for each process involved.
  Process names stay at the left of the graph while it scrolls, cut to fit (the
  whole name is the tooltip). A click on a file in the list shows it in Details (its
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
  a **Per-file history** button that opens the tab on that file.
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
- **Triage › Summary › MITRE ATT&CK (N)** shows the techniques as a badge row
  and **Show all N**. Open, it lists the techniques grouped by tactic in
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
- **Triage › Detection** lists each engine's matches as cards under **Matches**.
  **Sort by** orders them by risk (the default), name, MITRE technique, engine
  (rule pack), hit count or first hit (where the first hit was recorded:
  journal event, call or packet order; matches with no position come last); the
  choice is saved. A card shows the rule's title, severity tag and hit count, the
  description, the rule pack and every author, and the MITRE tags. **Details…**
  opens the rule: description, then the evidence locations as a scrollable
  table, the rule's metadata and its text (wrapped by default). The page scrolls
  when a section grows. An empty result says how many inputs were not scanned
  and why. For IDS, "Rule packs: N rules" counts every rule in the enabled
  packs and the coverage line counts what Suricata loaded; hover it for the
  difference. A scan that starts by itself and fails never replaces the result
  on screen, and no scan starts by itself while an engine tool has not answered.
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
  folder (`ioc-online.json`). **Triage › Summary** has an IOC card with the
  matched count and the dataset date.
- **Triage › Network** shows **Endpoints**, **Domains**, **URLs** and **TLS**, all
  read from TShark (the capture is VM-wide, so no row names a process), each with
  an IOC column. The 0.7.0 tabs (IPs, Hosts, HTTP, DNS, Sessions) and the switch
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
  install it. **Open in Wireshark** opens the capture when installed.
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
  Switch patterns off or add your own in **Library > Detection rules > Strings
  regex** (**Add patterns**: a name, a category, a regular expression that
  fills the rest of the row, and **Add**, all on one row); **Scan again** reads the change. An analysis that was not started
  with **Regex matches** shows **Not part of this analysis** and a **Run** button there.
- A list, table or tab with nothing in it says so in one muted line, in the words the
  Disks list uses (`No disk dumps for this VM`): the Core dumps list, a core's threads,
  mappings, strings and notes, the Per-file history list and the guest process list of
  the attach dialog do too, and a filter that matches nothing says that.
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
minimize and close the window. Resize using its edges or corners. Closing a
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
| Finished with exit 0 | Green |
| Finished with another exit code | Neutral |
| Stopped (by you) | Grey |
| Ended at its time limit (a `timeout` program: exit 124, or the SIGTERM BusyBox's `timeout` re-raises) | Blue-grey (info) |
| Crashed or killed by a signal (SIGSEGV and the like), or launch not confirmed | Amber |
| Failed to start, or interrupted | Red |
| Recording incomplete (saving stopped part way) | Amber |

A run is "going" while it still records: a run whose terminal was closed, or whose
root exited while children live on, shows **Running** in every list and keeps its
**Stop** button.

## 5. Samples

**Library > Samples** (sidebar) lists every sample across runs and VMs with its
origins and tags; opening one shows the sample window with the tabs **Summary**,
**Runs**, **IOCs**, **Custody log** and **Notes**. **Export report…** in its header
is described in [the sample report guide](sample-report.md).

- **Summary** holds the identity, the **Static analysis** section (each check on a
  line: name, state chip, what it found, **Open**, and the notice to the right of
  the button), the ATT&CK section, **Detections** and **Files written**. Files
  written shows one row per file the runs wrote, rewrote, deleted or renamed, with
  run, state, size and SHA-256, filterable and paged for ransomware-sized lists,
  with **Open in Per-file history**, **Export bytes** and **Copy SHA-256**. The list
  comes from each run's Triage digest, so a run Triage has not read yet is listed
  as such with a link to open it. The ATT&CK section has **Show all N**: the same
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
  folder's `sample-reports`, defanged in CSV and JSON on request, and notes it in
  the sample's custody log. Runs Triage has not read are named in a note: open the
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
| Ctrl+J | Fold or open the lower bar (Details, Activity and Jobs) |
| Ctrl+Shift+D, Ctrl+Shift+A, Ctrl+Shift+J | Show Details, Activity, Jobs (the lower bar) |
| Esc | Close the window on top (not while a field has the keyboard) |

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
when a run finishes** (on). A failed **Open folder** or **Open file** raises an
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
size while it loads: the results area and the Downloaded list have fixed heights,
the status is one line, and it scrolls inside when the screen is small.

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

### Exported tables

HTML and PDF exports never break a column title inside a word: a title wraps only
at spaces, the table keeps the longest word of every title as its least width,
takes a smaller font a step at a time when the longest words side by side are wider
than a page and, as a last resort, is split into column groups with its first
column repeated. The HTML prints on a landscape page. The exports of runs and
samples have a **Tactic** column for ATT&CK techniques (named in text, with the
colour as a chip in HTML and a bar in PDF).

## Troubleshooting

- **Settings did not survive a restart** (0.8.1 and earlier): fixed in 0.8.2; the
  debugger's remembered choices were saved in a form the settings file could not
  read back, so every start used the defaults. Set them once more.
- **A VM creation failed on a busy computer**: the offline credential tool's
  deadline grows with the host's load (up to four times) and a timeout starts again
  once from a fresh disk; a creation that still fails says "VM creation failed"
  with the reason and that the unfinished disk was removed.
- **Core dump on exit with Debug on start** works together since 0.8.2; a capture
  that cannot be armed names the size and first bytes of the guest's reply.
