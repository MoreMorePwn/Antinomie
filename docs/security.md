# Security model and safe use

[← Back to the overview](../README.md)

This page describes 0.7.1: what Antinomie isolates, what it does not, and how
to run it safely. To report a vulnerability in Antinomie itself, see
[SECURITY.md](../SECURITY.md).

## What it is for

Antinomie runs Linux samples you choose in QEMU virtual machines on your own
computer and records what they do from inside the guest kernel. It is a tool
for analysts who are allowed to handle the samples they run. It is not a
containment product, and it assumes the computer it runs on may be lost to a
sample one day.

Run it on a dedicated analysis computer, or at least a dedicated user account,
with KVM. Keep nothing on that account you would mind a sample reading:
no SSH or GPG keys, browser profiles, cloud or work credentials, source
checkouts with tokens, or other people's data. Run only samples you are
permitted to have, and only on a computer you can rebuild. Detections are leads
to investigate, not a verdict.

## What runs where

Antinomie needs no root. Everything below runs as your user unless it says
otherwise.

| Component | Where it runs | Handles hostile data |
|---|---|---|
| Host app: UI, recorder, transport client, route gateway | Your user, no sandbox | Telemetry from the guest kernel; on Routed VMs, the guest's network frames |
| QEMU (`qemu-system-x86_64`) | Your user, no extra sandbox | Everything the guest does |
| Patched guest kernel (Debian Linux 6.12.94) with the recorder | Inside the VM | The sample, on the same machine |
| Static analysis worker: built-in ELF/PE/Mach-O parsing and strings, capa, FLOSS, UPX, Detect It Easy, Ghidra | bubblewrap | The specimen |
| Properties worker (hashes, ssdeep, TLSH, Magika) and detection worker (YARA, Sigma, Suricata) | bubblewrap | Specimens, recordings, captures |
| TShark: packet list, display filters, network triage | bubblewrap and `prlimit`, as user 65534 | Packet captures |
| Disk browser and `qemu-img` for imported qcow2 images | bubblewrap and `prlimit` | Disk images |
| MemNixFS | bubblewrap | Memory dumps |
| Volatility 3 and its community plugins | Your user, **no sandbox** | Memory dumps |
| GDB console (GEF or pwndbg) | Your user, no bubblewrap; cleared environment, private home | The debugged guest process |
| **Open in Wireshark** | Your user, no sandbox | The capture |

The bubblewrap profile unshares every namespace (network included), disables
further user namespaces, drops all capabilities and clears the environment.
Inside are only `/usr`, a few read-only `/etc` entries, a private
`/etc/passwd`, a minimal `/dev`, `/proc` and a size-limited `/tmp`. Your home,
the data directory, `/run`, X11, D-Bus and `/dev/shm` are not visible; each
tool gets its input read-only and one folder to write to, with address-space,
open-file and time limits. bubblewrap is mandatory: if it cannot start, the
analysis fails with that reason instead of running unsandboxed. On some
distributions (Ubuntu 24.04, for example) an AppArmor restriction on
unprivileged user namespaces can stop bubblewrap. A sandbox narrows what a
compromised tool can reach. It still shares the host kernel.

The recorder sends telemetry through rings in the VM's RAM, which QEMU keeps in
a file in the VM's private runtime folder (mode 0700). The host app maps the
data rings read-only and the control region read-write, and parses the records
in its own process with bounded, checked parsing. That parser and the route
gateway are host code that reads guest-controlled bytes without a sandbox.

No host folder is shared into the guest. Files reach it only through
**Upload file**.

## What a sample can and cannot do

* **Inside the guest** it can do whatever its account allows. Programs run as
  **Normal user** (UID/GID 1000) unless you pick **Root** or another identity in
  the Run dialog. On Debian bases that account has password-protected `sudo`.
* **With guest root or a guest kernel exploit** it runs at the same level as the
  recorder. It can then stop, blind or falsify the telemetry and anything else
  the guest reports, such as resource figures. A recording shows what the guest
  kernel reported, not proof of what happened. Treat everything after a sample
  gains root as unreliable evidence.
* **Escaping QEMU** is QEMU's and KVM's boundary, not something Antinomie can
  prevent. QEMU runs as your user, so an escape gets your user's access: the
  data directory (API keys, other samples, recordings) and whatever else the
  account can read. This is why the account should hold nothing of value. Keep
  QEMU and the host kernel updated.
* **The host-side tools** read hostile data: recordings, packet captures, disk
  images, memory dumps and the specimens themselves. That is why the tools
  above run in bubblewrap. Volatility, the GDB console and Wireshark do not;
  use them on dumps and captures from samples you are prepared to trust that
  far.
* **Over the network** a sample can reach whatever its VM's network mode and
  the run's route allow (below).

## Network modes

Each VM has one network mode (VM dialog > **Network**). New VMs are
**Disconnected**.

| Mode | What the guest gets |
|---|---|
| **Disconnected** | No network card. Nothing to capture. |
| **Isolated** | QEMU user-mode networking with `restrict=on`: a card and an address, but QEMU forwards nothing to the host or other networks. Captures work. |
| **Routed (route per run)** | A card wired to Antinomie's own gateway in the host app. Between runs nothing leaves; each run picks a route. |
| **NAT (Internet)** | QEMU user-mode networking **without** `restrict=on`. |

**NAT is the least isolated mode.** The guest can open connections through the
host, as your user, to the Internet and to your local network. Through QEMU's
gateway address (10.0.2.2 unless a stealth profile changes the subnet) it can
also reach services listening on the host's loopback interface: a local
database or development server, a Tor or proxy you run, and the `127.0.0.1`
port Antinomie's debugger opens during a debug session. The VM dialog warns
"NAT permits guest access to the host network and Internet." The guest system
itself (Debian's time synchronisation, for example) also uses whatever network
you connect.

On a Routed VM the run's route decides where traffic goes (Run form,
**Network > Route**; the default is set in **Settings > Network routes** and is
**None (drop)** until you change it):

| Route | Traffic |
|---|---|
| **None (drop)** | Nothing leaves; attempts are still captured. |
| **InetSim (fake services)** | Names resolve to a fake address and connections reach fake services on this computer. |
| **Internet** | TCP is connected and DNS resolved by the host. Loopback, link-local, multicast and other special addresses are refused; private (RFC 1918 and 100.64.0.0/10) addresses are refused unless you allow them in Settings. |
| **Tor**, **VPN (WireGuard)**, **SOCKS5 proxy** | TCP goes through the proxy, which also resolves names. |

Only TCP and DNS are carried; other UDP is dropped and IPv6 is not carried on
any route. A route that cannot start stops the run; Antinomie never falls back
to another route. Details are in the
[user guide](usage.md#network-routes).

Traffic a sample sends over Internet, Tor, VPN, SOCKS5 or NAT leaves under
your connection, your Tor exit or your provider's, and may reach third parties:
command-and-control servers, scan targets, spam recipients. You are responsible
for it. Prefer **Disconnected** or **Isolated**, or a Routed VM on **None
(drop)** or **InetSim**, and choose a live route only when the analysis needs it.

## What the app itself contacts

Downloads use `curl` with HTTPS only (also across redirects) and ignore your
`~/.curlrc`.

* **First launch.** When there are no VMs and no bases, the Getting started
  window opens. Its first step reads the base catalog `index.json` from
  `huggingface.co/buckets/MoreMorePwn/antinomie-bases` when `curl` is installed.
  **Add base > Download base** and **Refresh catalog** read it again.
* **Volatility symbol tables.** For a memory dump without its own symbol table
  (an imported dump, for example), Volatility looks one up on GitHub
  (`Abyss-W4tcher/volatility3-symbols`). This is on by default; the Memory tab
  has the switch.
* **Only when you ask:** base downloads and Debian base builds; analysis tools,
  Tor and wireproxy (**Install** buttons); the rule catalog and rule packs
  (also off until **Allow outbound catalog and rule downloads** is set);
  abuse.ch IOC datasets; MalwareBazaar and MalShare searches and downloads;
  IOC **Check online** (off at every start); API key and route **Test**
  buttons; and Tor itself when a run uses the Tor route.

## Downloads and their checks

* **Bases**: each file is checked for size and SHA-256 against the catalog,
  which is fetched over HTTPS from the same bucket. Antinomie checks no
  signature on the catalog. Bases you import or build yourself are used as
  supplied.
* **Analysis tools, Tor and wireproxy**: URLs and SHA-256 values are pinned in
  the source (`monitor-core/src/analysis_tools.rs`); a file that fails its
  check installs nothing. Sigma's Python wheels are installed with
  `--require-hashes`. A copy already installed on the system takes precedence
  and is trusted as installed.
* **Offline computers**: build a [full pack](full-pack.md) yourself from the
  same pins; its installer checks every file against `SHA256SUMS`.
* **The app**: verify release archives with `SHA256SUMS` (see the
  [quick start](../README.md#quick-start)).

## Sensitive data and where it lives

Treat the data directory and everything exported from it as both malware and
confidential material.

* **Recordings are full-content.** System-call buffers and terminal transcripts
  are saved, so a password typed into a monitored program, and any key or token
  the sample reads or sends, can end up in the recording. Do not type real
  credentials into a guest.
* **Malware on disk.** Static analysis keeps the complete specimen, unencrypted,
  in the recording's `analysis/` folder. Unpacked layers, disk dumps, memory
  dumps, process cores and packet captures hold the sample, its files or its
  memory. Exports (reports, IOC CSV/JSON, cores, disk images, Ghidra projects)
  are plain files wherever you save them.
* **Downloaded samples** from MalwareBazaar and MalShare are kept in
  `<data>/samples` as AES zip archives with the password `infected`. They are
  decrypted only in memory, to check the hash and stream into a guest.
* **Secrets Antinomie keeps**, each readable by you only: API keys
  (`api-keys.json`), the SOCKS5 password, Tor's data folder (`network/tor`) and,
  per Debian VM, `guest-account.json` with the guest account's salted password
  hash.

The data directory is `~/antinomie` unless you start with `--data-dir`. Each
VM has a folder there with its configuration, disk, snapshots and recordings;
bases, samples and managed tools sit beside them. A VM can also keep its disk
or recordings in folders you chose in its settings. A rebuildable index cache
lives in `$XDG_CACHE_HOME/antinomie/browse` (or `~/.cache`). After an upgrade
from an old layout, the previous `~/.local/share/antinomie` stays as a backup.

The app deletes network captures, cores, disk and memory dumps, snapshots,
VMs and bases. **Delete VM** removes the configuration, disk and snapshots but
keeps the run recordings and terminal history. To remove everything, quit
Antinomie, then delete the data directory, any disk or recording folders you
chose, the cache and any old backup.

## Stealth limits

A stealth profile changes what the guest can read of its hardware identity
(SMBIOS, CPU, disk and network models, MAC address, firmware), and current
bases keep the guest kernel's own traces out of view. It does not make the VM
undetectable. The **Still visible** list in the Stealth profile window names
what remains for that profile and base: timing, the display, the chipset and
QEMU's firmware tables among them. `CPUID` and `RDTSC` checks leave no system
call and are not recorded. Software breakpoints are `0xCC` bytes a sample can
read. A setting a base cannot support falls back, and the app says so. Assume a
sample can tell it is being analyzed.

## Checklist before running a sample

* Use a dedicated computer or user account with no keys, credentials or other
  people's data, and a host you can rebuild.
* Use KVM, and keep QEMU and the host kernel updated.
* Check **Tools > App dependencies** (or `antinomie --check-dependencies`):
  bubblewrap must work, or static analysis and packet decoding fail.
* Set the VM to **Disconnected** or **Isolated**; if the sample needs a
  network, use **Routed** with **None (drop)** or **InetSim**.
* Choose **NAT** or a live route only on purpose; while a NAT VM runs, keep
  sensitive services off the host's loopback interface.
* Run as **Normal user** unless the analysis needs root, and treat telemetry
  after a sample gains root as unreliable.
* Do not type real credentials into the guest; recordings keep them.
* Afterwards, reset the VM's disk to its base or restore a snapshot, and
  handle exports as malware.
