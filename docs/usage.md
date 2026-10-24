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
- Detection rules come from **Tools > Detection rules**, which downloads each
  pack from its publisher (GitHub, rules.emergingthreats.net, sslbl.abuse.ch),
  verifies it and filters it on your computer, only after you allow it; it
  shows each pack's source, license and the hosts it contacts. YARA is built in. IDS scans need Suricata
  (`sudo apt install suricata`, listed in App dependencies). Sigma scans use
  pySigma, which **Tools > Analysis tools** installs for Antinomie; it needs
  Python 3.11 or newer with venv support (`python3-venv` on Debian/Ubuntu).

- **Tools > Detection rules > IOC** keeps abuse.ch datasets on your computer
  for matching a run's indicators offline: ThreatFox `full.csv`, the URLhaus
  dump (`full.csv`, the URLs that are active or were added in the last 90 days)
  and payload list, Feodo Tracker's `ipblocklist.json` and the SSLBL IP, JA3 and
  certificate lists, which are seven on by default. An eighth, URLhaus
  `recent.csv` (the last 30 days), is a smaller choice that is off until you
  switch it on. They are stored in the data folder (about 640 MB together for
  the seven), never in the project, and change only when you press
  **Download** or **Update** (or **Download / Update all**); nothing updates by
  itself. Each row shows its records, size, the date it was fetched and its age
  (a warning appears when a dataset is over 14 days old), its terms (Feodo and
  SSLBL are CC0; ThreatFox and URLhaus are free under abuse.ch's fair use with
  an Auth-Key set in **Tools > API keys**) and a switch. A download is saved
  whole or not at all: when one fails the previous copy stays in use and the
  status line names the dataset that failed. If abuse.ch answers that it does
  not accept the Auth-Key, the line says so (check the key in **Tools > API
  keys**); if it answers that the endpoint is retired, the line says to update
  Antinomie. The Auth-Key is part of the address abuse.ch serves its ThreatFox
  and URLhaus files from, so Antinomie hands the address to the download
  program out of sight of other users of the computer, and shows it everywhere
  as `/exports/****/`; the key does not appear in the details, the status line,
  an error or a saved report. The same tab lists the **known false positives**
  you have marked, which you can remove.

- **Tools > Detection rules > IDS > abuse.ch** offers six Suricata rule packs from
  abuse.ch: ThreatFox, URLhaus (exact-URL HTTP rules), Feodo Tracker, SSLBL
  botnet C2 IPs, SSLBL JA3 fingerprints and the SSL certificate blacklist. The
  *aggressive* variants, which abuse.ch itself warns produce false positives,
  are not offered. abuse.ch regenerates these files about every five minutes, so
  the tab shows how old each installed pack is and **Check** compares the live
  file with the installed one (a pack is asked at most once in five minutes, even
  if you press the button again); **Update** installs the newest snapshot and
  keeps the old version if it fails. ThreatFox and URLhaus need the Auth-Key in
  **Tools > API keys** (they are sent as `.tar.gz` archives, from which only the
  `.rules` files are taken); Feodo and SSLBL are CC0 and need none. abuse.ch
  no longer fills the SSLBL JA3 rules file, so that pack shows **Retired
  upstream** and cannot be installed; the JA3 list is still available as an IOC
  dataset. Nothing is fetched until you press a button and have allowed
  downloads.

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
   **Unpacking** (Triage, on by default) looks for UPX packing; a packed file is unpacked
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
  shows as a window on it: drag the window to pan, drag its edges to zoom, drag
  across an empty part to show that stretch (a click there centres the window),
  and double-click the ruler to show the whole run. A time range brushed for the
  filter is marked on the ruler. It works in both spacings, in the tab and in the
  window.
  Mouse: wheel scrolls the lanes, Shift+wheel or a drag pans, Ctrl+wheel or a
  pinch zooms at the pointer, a double-click on the axis zooms 2x. Keyboard (click the graph first): ←/→ previous and next
  finding in time, ↑/↓ lane, Enter evidence, `T` spacing, `F` fit, `+`/`-` zoom at the
  selection, Space fold the lane, `H` `M` `L` `I` the tier chips and Show INFO,
  `1`…`9` and `0` the first ten category chips.
- **Triage › Files › Per-file history…** opens the **File activity** window. The
  left list holds every file the run touched, in order of the first call (also
  those that were only opened, read or probed); **Hide stdio**, **Hide library**
  and **Changed only** narrow it, the filter matches the path and any other name
  the file was given, and the order can be first or last touched, most calls or
  path. Choose a file to see its history as a graph: one box for each stretch of
  the same call by the same process (create, open, read, write ×3, rename, delete),
  joined in the order the calls happened, on a lane for each process involved.
  Click a box to list its calls: time, process, call, result (a rename shows the new
  name, a delete says whether another link remains), and for reads and writes the
  **offset**, the **length** and the first 64 bytes the kernel captured. A write
  that went past the end of the file as far as the run knew says so. **Content
  changes** below lists the bytes the run changed where it captured both sides:
  `0x00000001  42 43 → 7a 7a`, or `added` for bytes past the size it first saw
  (`??` is a byte it did not capture, `∅` one beyond the known size), the file's
  size before and after, and the guest's SHA-256 when it took one. Click a call
  name to open the original syscall. An offset the run could not know (an append,
  a descriptor it did not see opened) shows `unknown`, and bytes the kernel did not
  capture show `not captured`; nothing is guessed. In **Changed files**, Details has
  a **Per-file history…** button that opens the window on that file.
- **Triage › Summary** shows the same curve, phases and heat strip for the whole
  run as **Main activity graph**; a click opens the Graph. When nothing is above
  LOW it is one line (`No medium or high activity · 11 low · 340 info`); the
  arrow opens or closes it, and the choice is kept until you quit.
- **Settings › Notifications › Toast for live HIGH findings** (on by default):
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
  Not checked, and a banner says the datasets are over 14 days old.
  **Online lookups** are off at every start. When switched on (needs the Auth-Key)
  **Check online** sends only public values with no offline match (never files,
  never JA3 or certificate fingerprints, never a value a known false positive
  excuses) to threatfox-api.abuse.ch and urlhaus-api.abuse.ch, at most 50 values
  per press; the answers are marked *online* with their time and kept in the run's
  folder (`ioc-online.json`). **Triage › Summary** has an IOC card with the
  matched count and the dataset date.
- **Triage › Network** shows **Endpoints**, **Domains**, **URLs** and **TLS**, all
  read from TShark (the capture is VM-wide, so no row names a process), each with
  an IOC column. The 0.7.0 tabs (IPs, Hosts, HTTP, DNS, Sessions) are one click
  away: **Current layout (0.7.0)**. The filter field names of the old tabs
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
  module list or mounts, or a symbol table that does not match the kernel
  banner); a report the tool could not produce fails with the reason instead
  of showing an empty table. A report takes about a minute on a 2 GiB dump.
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
- **Static Analysis > Overview > Categories**: a category the analysis was not
  started with shows **Not requested** and a **Run** button. Run adds that check
  to the same report without starting the analysis again: the specimen kept with
  the report is analysed by the one check, and its tab fills in when it ends.
  The button waits while the analysis is still being made; no VM has to be
  running, and the result is saved with the report like the others.
- **Static Analysis > Unpacking**: the unpack chain as phases, left to right: the
  file as it came (packed with UPX or not), then each layer UPX recovered from the
  one before, with size, SHA-256 and the packer found in it. A file packed twice
  gives two layers. UPX is needed for this (**Tools > Analysis tools** installs it);
  without it a packed file is reported as packed and left alone. Files whose UPX
  headers were tampered with (the `UPX!` magic overwritten, data appended) are
  repaired on a copy first and the layer says so (`UPX (header repaired)`).
  Each layer is analysed as a report of its own, the same checks as the packed
  file's, listed in the **Report** box as "layer N unpacked by UPX"; **Show its
  analysis** in the phase opens it. The original file is never changed, the layers
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


