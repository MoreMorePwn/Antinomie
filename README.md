# Antinomie

Antinomie is a desktop application for watching what a program does inside a
virtual machine. You start a QEMU/KVM guest, copy a program into it, run it, and
the app records every system call the program and its child processes make,
together with the data they pass to the kernel. Recordings are saved, so you can
reopen and inspect any run later.

It is built for malware analysis and reverse engineering: run untrusted code in a
disposable guest, then read exactly which files, sockets, processes and kernel
features it touched.

## Demo

[![Watch the Antinomie 0.1.0 workflow demo](assets/demo/antinomie-0.1.0-preview.png)](assets/demo/antinomie-0.1.0.mp4)

[Watch the video](assets/demo/antinomie-0.1.0.mp4): create and boot a BusyBox VM,
upload and run a harmless program, inspect syscall flags and captured bytes,
then reopen its saved trace and terminal output. Recorded with **0.1.0** on
main; pauses are trimmed. [Recording details](assets/demo/README.md).

## How it works

- **Guest kernel.** The guests run Linux 6.12.94 with a small patch that records
  system calls. The kernel itself runs your programs and terminals, so no helper
  program sits inside the guest for malware to spot or tamper with.
- **Transport.** Records reach the host over shared memory, through a buffer per
  virtual CPU. If the host cannot keep up, the loss is counted and shown, never
  hidden; in **Never drop** mode the guest waits for the host instead.
- **Host app.** A native Linux desktop application (Rust, egui) manages VMs and
  shows live and saved traces.
- **Guests.** Two base images:
  - **BusyBox**: tiny and fast to boot, good for quick tests.
  - **Debian 13 (Xfce)**: a full desktop, closer to a real target machine.

Captured data is an observation, not proof: memory can change while it is being
read, and anything the app could not decode or lost is marked as such.

## Requirements

- Linux x86-64 host (WSL2 works with an X11 display)
- QEMU (`qemu-system-x86_64`, `qemu-img`) with its GTK display backend;
  on Debian/Ubuntu install `qemu-system-x86 qemu-utils qemu-system-gui`.
  KVM (`/dev/kvm`) strongly recommended; TCG works without it
- Rust to build the app; building kernels and bases needs the tools listed in
  [CONTRIBUTING.md](CONTRIBUTING.md)
- Memory analysis runs Volatility 3, which **Tools > Analysis tools** (or the
  Memory tab) installs for Antinomie; it needs Python 3 (`python3`)
- Static analysis runs in a bubblewrap sandbox (`bwrap`). Disassembly, rules
  and identification are built in. Decompilation (Ghidra), capabilities
  (capa) and Detect It Easy use the system's copy when installed; otherwise
  **Tools > Analysis tools** downloads them for Antinomie. The Properties tab
  computes ssdeep and TLSH itself; it also shows Magika's file type when
  **Tools > Analysis tools** has installed Magika (or the system has it)
- The Network tab (packet list and details), Wireshark packet display filters
  and network triage use the installed `tshark` command with `prlimit`
  resource limits; Antinomie decodes no protocol itself. On Debian/Ubuntu install
  `tshark util-linux`; these tools are checked in **Tools > App dependencies**.
- Detection rules come from **Tools > Rule manager**, which downloads each
  pack from its publisher (GitHub, rules.emergingthreats.net, sslbl.abuse.ch),
  verifies it and filters it on your computer, only after you allow it; it
  shows each pack's source, license and the hosts it contacts. YARA is built in. IDS scans need Suricata
  (`sudo apt install suricata`, listed in App dependencies). Sigma scans use
  pySigma, which **Tools > Analysis tools** installs for Antinomie; it needs
  Python 3.11 or newer with venv support (`python3-venv` on Debian/Ubuntu).

## Quick start

```bash
git clone https://github.com/MoreMorePwn/Antinomie.git ~/src/antinomie
cd ~/src/antinomie
./run.sh        # build if anything changed, then start the app
./install.sh    # or install it for this user: `antinomie` command and menu entry
                # (./install.sh --uninstall removes it; application data stays)
```

Your bases, VM disks and recordings are kept in `~/antinomie`. The app's
version is in its title bar and **Help > About Antinomie**; see
[CHANGELOG.md](CHANGELOG.md) and the versioning rules in
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning).

At startup, Antinomie checks its runtime dependencies in the background and
shows **Tools → App dependencies** when something is missing. The window lists
the affected actions and package commands; install the missing packages, then
select **Check again**. VM startup also checks QEMU's actual GTK support, so a
headless-only QEMU install is caught before a VM starts. Missing dependencies
block the actions that need them; saved recordings remain available. Build
tools and optional analysis tools have separate checks in their own dialogs.
For a terminal-only report, run `antinomie --check-dependencies`.

## Using the app

### 1. Get a base image
The **Base images** section in the left sidebar lists installed bases. Use
**Add base** to get one:
- **Download base…**: fetch a published, checksum-verified base.
- **Import base…**: install a bundle folder you already have.
- **Build base…**: build one with the app's own build kit. A short wizard asks
  installer-style questions (hostname; for Debian also language, keyboard, time
  zone, software and mirror), then builds on this Linux host when the tool suite
  is installed or inside a QEMU builder VM otherwise, and installs the result.

Bases are read-only templates. Right-click a base to make a **New VM from this
base** or to **Delete base**. Deleting is refused while any VM still uses it.

### 2. Create a VM
Choose **New VM**, pick the installed base, and set name, CPU count, RAM and
disk size. Debian bases also ask for a username and password; the guest
account is created for you. Each VM gets its own disk layered on the base, so
the base never changes.

Right-click a VM for **Rename**, **Duplicate** (the VM must be stopped),
**Open Directory**, **Settings** (resolution, fullscreen or fit to window,
acceleration, CPU model) and **Delete**.

**Settings → Telemetry transport…** tunes how records leave the guest (bases
for Antinomie 0.3.0 and newer):

| Setting | Effect |
|---|---|
| Guest buffer per vCPU | 256 KiB to 4 MiB of guest memory per virtual CPU (default 1 MiB); bigger buffers ride out longer bursts |
| When buffers fill | **Never drop** (default): a system call waits until the host has room, so heavy tracing slows the guest but nothing is lost; or **Drop new telemetry**: the guest never waits (keeps its timing) and the loss is counted |
| Longest wait per event | In Never drop mode, how long one call may wait (default 5 s) before its record is dropped after all |
| Host event table | How many calls the host keeps assembling at once (default 16,384) |

### 3. Start it and run a program
1. Select the VM and press **Start VM**. Only one VM runs at a time, and its
   network is disconnected by default.
2. **Upload file** copies a program from the host (**Host file**) to a path in
   the guest (**Guest path**).
3. **Launch program** runs it. Set the **Executable**, **Arguments**,
   **Working directory** and **Environment**. Each launch gets its own terminal
   window for input and output.
   On a VM with a desktop base, **Run in** picks where the program runs:
   **App terminal** (the default), **Guest desktop** (the program joins the
   graphical session, so its windows appear on the VM screen; its output
   stays in the app terminal) or **Guest desktop terminal** (a terminal
   window on the VM screen runs it). Both desktop choices need the run's user
   logged in on the VM display; otherwise the app terminal says so.
4. **Stop** ends a run together with all of its child processes. Closing a
   terminal window does not stop the program.
5. **Static Analysis** in the launch dialog analyzes the program's file before
   it runs; pick the categories, from triage to disassembly and decompilation.
6. **Attach to process** traces a process that is already running in the guest
   (and its future children); **Capture all** traces all of userspace. Neither
   stops or signals anything. A capture lists the processes it saw as a tree
   (named after the program each one ran); select one to see only its calls.
7. With **NAT network** on, start **Network capture** to record packets of the
   VM's network interface outside the guest. Stop it to finish the capture;
   each start creates a separate retained pcap in the boot recording.

### 4. Read the results
- **Syscall Trace**: every recorded call with its arguments, return value and
  captured data. Flags and options are decoded into names (for example
  `O_CREAT | O_CLOEXEC`, `SOL_SOCKET / SO_RCVBUF`, `PR_SET_NAME`), unknown bits
  are listed separately, and captured buffers can be inspected byte by byte.
- **Run History**: every run on the selected VM, including earlier boots, with
  its command line, user, status and exit code. Double-click a run to open its
  saved trace.
- **Network**: select an ongoing or saved capture from capture history, or start
  one there. Protocol colors help scan the packets; click an address, protocol
  or port to filter it, or use the counted dropdowns. The packet list and the
  expandable details tree are exactly what the installed TShark prints
  (protocol, info, every field), with a byte view that marks the bytes of the
  selected line. Without TShark you see raw frames and bytes and a note to
  install it. **Open in Wireshark** opens the capture when installed.
- **Static Analysis**: the selected run's report: an overview, then each
  category; disassembly and decompilation are full listings with search.
- **Details** and **Activity**: the selected call or run, and VM events.
  Right-click values to copy common numeric formats. Open captured data in its
  own window, initially UTF-8, then choose ASCII, hex, hexdump, Base64 or other
  forms and copy the result. Partial captures keep their gap/error information.

Process terminals resize their grids with the window and retain up to 10,000
history lines. Use the mouse wheel or scrollbar to read earlier output; the
**newer lines** button or **Shift+End** returns to the newest output.

Panels can be dragged out into their own windows and docked back;
**View → Reset layout** restores the default arrangement. Text size is under
**Tools → Settings**.

**Tools → UI performance** shows the graphics renderer and recent UI update
CPU timings. If WSLg selects software rendering, a compatible GPU driver can
be selected for one launch with `antinomie --graphics-driver d3d12`; the dialog
can copy a command preserving the data directory. Close the app normally before
using it. The default `--graphics-driver system` keeps the existing environment.

## Development

Kernel changes, the patch workflow, building kernels and base images, and the
test suites are described in [CONTRIBUTING.md](CONTRIBUTING.md) and
[the implementation contract](docs/implementation.md). Coding agents follow
[AGENTS.md](AGENTS.md).

See [project layout and artifact retention](docs/project-layout.md) for the
source/build/release boundaries. Each new version starts on its own
`release-X.Y.Z` branch with `scripts/new-release.sh X.Y.Z`; finish and tag that
version on the same branch. The helper creates the branch without bumping the
application version or publishing anything.

## License

Original Antinomie host and tooling code is [MIT licensed](LICENSE), copyright
2026 MikiMiku (MoreMorePwn). Kernel-derived and imported material keep their own
terms. Read the [licensing scope](LICENSING.md) and
[third-party notices](THIRD-PARTY-NOTICES.md) before redistributing; the kernel
and guest images as a whole are not MIT licensed.

Building from source also requires `musl-tools` for the embedded static guest
resource collector, which only bases older than 0.7.0 (revision 16 and earlier)
still use. Prebuilt installations need no guest packages.
