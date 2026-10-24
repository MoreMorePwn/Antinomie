# Using Antinomie

[← Back to the overview](../README.md)

This guide follows the 0.7.0 source branch. Available controls depend on the
application and base versions; existing VMs keep their pinned base.

## Dependencies and analysis tools

- Linux x86-64 host (WSL2 works with an X11 display)
- QEMU (`qemu-system-x86_64`, `qemu-img`) with its GTK display backend;
  on Debian/Ubuntu install `qemu-system-x86 qemu-utils qemu-system-gui`.
  KVM (`/dev/kvm`) strongly recommended; TCG works without it
- Rust to build the app; building kernels and bases needs the tools listed in
  [CONTRIBUTING.md](../CONTRIBUTING.md). Host source builds also need
  `musl-tools` for the compatibility collector used by older guest bases;
  prebuilt installs do not need that build tool.
- Memory analysis runs Volatility 3, which **Tools > Analysis tools** (or the
  Memory tab) installs for Antinomie; it needs Python 3 (`python3`)
- Static analysis runs in a bubblewrap sandbox (`bwrap`). Disassembly, rules
  and identification are built in. Decompilation (Ghidra), capabilities
  (capa), FLOSS strings and Detect It Easy use the system's copy when
  installed; otherwise **Tools > Analysis tools** downloads them for Antinomie. The Properties tab
  computes ssdeep and TLSH itself; it also shows Magika's file type when
  **Tools > Analysis tools** has installed Magika (or the system has it)
- The Network tab (packet list and details), Wireshark packet display filters
  and network triage use the installed `tshark` command with `prlimit`
  resource limits; Antinomie decodes no protocol itself. On Debian/Ubuntu install
  `tshark util-linux`; these tools are checked in **Tools > App dependencies**.
- Detection rules come from **Tools > Detection rules**, which downloads each
  pack from its publisher (GitHub, rules.emergingthreats.net, sslbl.abuse.ch),
  verifies it and filters it on your computer, only after you allow it; it
  shows each pack's source, license and the hosts it contacts. YARA is built in. IDS scans need Suricata
  (`sudo apt install suricata`, listed in App dependencies). Sigma scans use
  pySigma, which **Tools > Analysis tools** installs for Antinomie; it needs
  Python 3.11 or newer with venv support (`python3-venv` on Debian/Ubuntu).

## 1. Get a base image

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

## 2. Create a VM
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
| When buffers fill | **Never drop** (default): a system call waits until the host has room, so heavy tracing can slow the guest; its wait deadline can still cause counted drops. **Drop new telemetry**: the guest never waits (keeps its timing) and the loss is counted |
| Longest wait per event | In Never drop mode, how long one call may wait (default 5 s) before its record is dropped after all |
| Host event table | How many calls the host keeps assembling at once (default 16,384) |

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
   terminal window does not stop the program.
5. **Static Analysis** in the launch dialog analyzes the program's file before
   it runs; pick the categories, from triage to disassembly and decompilation.
   **FLOSS strings** (under Deep analysis, off by default) recovers the strings a
   program builds on the stack or decodes at run time, which Strings cannot see;
   it needs FLOSS from **Tools > Analysis tools** and can take several minutes
   (a statically linked program may hit its 8 minute limit). FLOSS reads the file
   with its own disassembler and emulates snippets of it; the program is never
   run. Results are in the **FLOSS** tab beside Strings, one row per string with
   its type (decoded, stack, tight, or language for Go and Rust strings), its
   encoding and the address FLOSS reports for the routine. Files over 16 MiB are
   not taken.
6. **Attach to process** traces a process that is already running in the guest
   (and its future children); **Capture all** traces all of userspace. Neither
   stops or signals anything. A capture lists the processes it saw as a tree
   (named after the program each one ran); select one to see only its calls.
7. With the guest network connected, select **Capture network** to record
   packets of the VM's network interface outside the guest. Stop it to finish the capture;
   each start creates a separate retained pcap in the boot recording.

## 4. Read the results

- **Syscall Trace**: every recorded call with its arguments, return value and
  captured data. Flags and options are decoded into names (for example
  `O_CREAT | O_CLOEXEC`, `SOL_SOCKET / SO_RCVBUF`, `PR_SET_NAME`), unknown bits
  are listed separately, and captured buffers can be inspected byte by byte.
- **Run History**: every run on the selected VM, including earlier boots, with
  its command line, user, status and exit code. Double-click a run to open its
  Triage view. Select a trace entry to inspect its recorded call details.
- **Triage › Process › Suspicious activity**: behaviour recognised in the run's
  calls, kernel records and packets. Each row has a tier (HIGH, MEDIUM, LOW;
  INFO is only counted unless **Show INFO** is on), a category and an ATT&CK
  reference. Repeats fold into one row with a count, a failed call or a program
  that does the thing as its job lowers the tier by one, and **Details** says
  why a row has its tier. The chips narrow the table by tier and category. A row
  is something to look at, not a verdict. **Evasion** lists every anti-analysis
  check the sample made through system calls (machine identity, CPU, MAC address,
  uptime, `TracerPid`, container markers, long sleeps) with the answer the guest
  gave, and a heuristic note on what the sample did in the next 30 seconds.
  `CPUID` and `RDTSC` checks leave no system call and are not visible.
- **Triage › Process › Graph**: the same findings on process swimlanes against
  time. The lanes follow the process tree (▾/▸ folds a subtree; many leaf
  siblings of one program fold into one `name ×N` lane); markers take their
  colour from the tier (HIGH red, MEDIUM amber, LOW cyan, INFO grey) and their
  shape from the category, so colour is never the only cue. Above the lanes are
  the **phases** of the run (recon, download, persistence, escalation,
  hide/inject, C2, spread, impact: a stretch needs one HIGH, a MEDIUM with a LOW,
  two MEDIUMs or five LOWs), a **severity curve** (HIGH counts 10, MEDIUM 4, LOW
  1, scaled to the tallest bar in view) and a **heat strip** with one row per
  category. Thin lines join a parent to the processes it started and an injecting
  process to its target. The graph shows exactly what the Suspicious activity
  table is filtered to: it shares the filter bar and the tier and category
  chips. Hover a marker for its rule, tier, process, count and outcome; click it
  to select the row (Details follows, and the table scrolls to it) and
  double-click or press Enter for its first evidence. Click a lane name to keep
  only that process (Shift: and its descendants); click a phase to keep only its
  time range. Drag across the time axis to keep a time range, and press Escape
  to lift it.
  Mouse: wheel scrolls the lanes, Shift+wheel or a drag pans, Ctrl+wheel or a
  pinch zooms at the pointer, a double-click on the axis zooms 2x, **Fit**
  shows the whole run. Keyboard (click the graph first): ←/→ previous and next
  finding in time, ↑/↓ lane, Enter evidence, `F` fit, `+`/`-` zoom at the
  selection, Space fold the lane, `H` `M` `L` `I` the tier chips and Show INFO,
  `1`…`9` and `0` the first ten category chips.
- **Triage › Summary** shows the same curve, phases and heat strip for the whole
  run as **Main activity graph**; a click opens the Graph. When nothing is above
  LOW it is one line (`No medium or high activity · 11 low · 340 info`); the
  arrow opens or closes it, and the choice is kept until you quit.
- **Settings › Notifications › Toast for live HIGH findings** (on by default):
  the first HIGH finding of each rule in a run that is still going raises one
  toast; later matches of that rule add `×N` to it. It is raised when the run's
  index is read again, every 5 s while Triage is shown and every 15 s otherwise.
- **Network**: select an ongoing or saved capture from capture history, or start
  one there. Protocol colors help scan the packets; click an address, protocol
  or port to filter it, or use the counted dropdowns. The packet list and the
  expandable details tree are exactly what the installed TShark prints
  (protocol, info, every field), with a byte view that marks the bytes of the
  selected line. Without TShark you see raw frames and bytes and a note to
  install it. **Open in Wireshark** opens the capture when installed.
- **Static Analysis**: the selected run's report: an overview, then each
  category; disassembly and decompilation are full listings with search. In the
  **Strings** and **FLOSS** tabs, **Regex matches…** opens a window with every
  pattern match in the strings, by category (Network, Crypto, Keys, Linux
  behaviour, Attribution, Encoded) with a type for each match (IPv4 public or
  private, URL, Bitcoin address, persistence path, ...). Matches are checked to
  cut false positives: a domain must end in a real public suffix, `libc.so` and
  `install.sh` are files, a version number is not an IP address, and a Bitcoin
  address, Tox ID or token must pass its checksum or structure. Base64 and hex
  text is decoded and scanned again (two levels deep); the **Inside** column says
  which. The same window opens from **Core dumps > Strings**, where it also lists
  the binary `sockaddr_in` and `sockaddr_in6` structures in the core's memory.
  Switch patterns off or add your own in **Library > Detection rules > Strings
  regex**; **Scan again** reads the change.
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

**Tools → UI performance** shows the graphics renderer and recent UI update
CPU timings. If WSLg selects software rendering, a compatible GPU driver can
be selected for one launch with `antinomie --graphics-driver d3d12`; the dialog
can copy a command preserving the data directory. Close the app normally before
using it. The default `--graphics-driver system` keeps the existing environment.


