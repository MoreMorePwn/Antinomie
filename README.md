<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/branding/antinomie-logo-white.svg">
    <img src="assets/branding/antinomie-logo-color.svg" alt="Antinomie" width="440">
  </picture>
  <p><strong>Follow a program from syscall to evidence.</strong></p>
  <p>A native Linux desktop for malware analysis and reverse engineering,<br>powered by telemetry from the guest kernel.</p>
  <p>
    <a href="#getting-started"><strong>Get started</strong></a> ·
    <a href="docs/usage.md">User guide</a> ·
    <a href="https://github.com/MoreMorePwn/Antinomie/releases">Releases</a> ·
    <a href="CHANGELOG.md">Changelog</a> ·
    <a href="CONTRIBUTING.md">Contributing</a>
  </p>
  <p>
    <a href="#requirements"><img src="assets/badges/platform.svg" alt="Platform: Linux x86-64"></a>
    <a href="docs/implementation.md"><img src="assets/badges/kernel.svg" alt="Guest kernel: Linux 6.12.94"></a>
    <a href="LICENSING.md"><img src="assets/badges/license.svg" alt="Original host license: GPL-3.0-only"></a>
  </p>
</div>

Run a sample in a disposable QEMU VM, inspect what it did, and return to the saved
evidence later. Antinomie brings syscall traces, process and file activity,
packets, memory, cores, static analysis and debugging into one workspace.

**Branch status:** this README describes **0.7.0, currently unreleased**. Features
and base compatibility can differ from the published builds in
[Releases](https://github.com/MoreMorePwn/Antinomie/releases).

## See it in action

[![Antinomie 0.1.0: a VM, program terminal and captured syscall evidence](assets/demo/antinomie-0.1.0-preview.png)](assets/demo/antinomie-0.1.0.mp4)

**[Watch the workflow demo →](assets/demo/antinomie-0.1.0.mp4)**
Create a VM, upload and run a sample, inspect its calls, then reopen the recording.
This is the **0.1.0 demo**; it shows an earlier interface, not the current 0.7.0
layout. [Recording details](assets/demo/README.md).

## What you can investigate

| Workspace | What it gives you |
|---|---|
| **Syscall trace** | Arguments, return values, decoded flags and captured buffers, with filters and links to evidence. |
| **Triage** | Run properties, process trees, file operations, suspicious activity, HTTP/DNS and detection results. |
| **Debugger** | Debug on start or attach; inspect threads, registers and memory, use breakpoints and stepping, and open GDB with GEF or pwndbg. |
| **Memory and cores** | Capture memory and process cores, browse mappings and context, and analyze supported memory images with Volatility 3. |
| **Static analysis** | File identification, hashes, strings, structures, capabilities, disassembly and Ghidra decompilation. |
| **Network** | Saved PCAPs, TShark packet decoding and Wireshark display filters, with an option to open captures in Wireshark. |
| **Detection rules** | Manage community and custom YARA, Suricata IDS and Sigma collections, then scan the evidence their engines support. |
| **VM management** | Read-only base templates, separate VM disks, branching snapshots, resource monitoring and a stopped-VM disk browser. |

Optional analysis engines are installed through **Tools → Analysis tools** or
provided by the host. See the [tool requirements](docs/usage.md#dependencies-and-analysis-tools)
for each workflow.

## Getting started

### Install a published build

Download the Linux application archive and `SHA256SUMS` from
[Releases](https://github.com/MoreMorePwn/Antinomie/releases). In the download
directory, verify the archive:

```sh
sha256sum --check SHA256SUMS
```

Extract the verified archive, open a terminal in its extracted folder, and run:

```sh
./install.sh
antinomie
```

This installs the application for your user and adds its desktop entry. Prebuilt
application installs do not need Rust. Running `./install.sh` from a newer
extracted release updates the executable; application data stays in place.

### Run this branch from source

Install the [host build prerequisites](src/antinomie/monitor/README.md#build-and-run),
then:

```sh
git clone --branch release-0.7.0 https://github.com/MoreMorePwn/Antinomie.git
cd Antinomie
./run.sh
```

`run.sh` rebuilds when its inputs change, then starts the app. Use `./install.sh`
in the checkout to build and install it for your user. Building the host app does
not build a guest kernel or base image.

### Make your first recording

1. Open **Base images** and download, import or build a compatible base.
2. Create a **New VM** from that base, choose its resources, and start it.
3. Upload your sample and launch it. Enable the captures you need for the run;
   network recording requires a connected guest network.
4. Inspect the live views, then reopen the saved run from **Run History**.

**BusyBox** is the small, fast-booting guest for command-line samples. A
**Debian desktop** base provides a fuller userspace. Choose a base compatible
with the application; installing a newer app does not replace an existing VM's
pinned base.

The default data directory is `~/antinomie`. It contains your bases, VM disks and
recordings. See the [user guide](docs/usage.md) for controls, transport settings,
optional tools, desktop execution and layout customization.

## Requirements

- **Host:** Linux x86-64 with a graphical session. WSL2 needs a working graphical
  display; KVM access depends on its virtualization configuration.
- **Virtualization:** QEMU (`qemu-system-x86_64`, `qemu-img`) with its GTK display
  backend. On Debian/Ubuntu: `qemu-system-x86 qemu-utils qemu-system-gui`.
  KVM is strongly recommended; TCG is available without it.
- **Analysis:** bubblewrap for static-analysis isolation; TShark and `prlimit`
  for decoded packets and display filters. Other tools depend on the selected
  analysis. [Full dependency list](docs/usage.md#dependencies-and-analysis-tools).

The app checks runtime dependencies at startup. **Tools → App dependencies**
shows missing tools and the affected actions. For a terminal report:

```sh
antinomie --check-dependencies
```

## How observation works

```text
Program and descendants in the guest
                ↓
      Patched Linux guest kernel
                ↓
       Shared-memory transport
                ↓
   Native host app → saved recordings
                ↓
  Trace · Triage · Network · Analysis
```

The kernel records supported activity without a resident userspace tracing
agent. The host manages the VM, retains records and presents the evidence.
Memory and captured data can change while observed; unreadable bytes,
unsupported information and recording gaps must remain visible.

Transport buffering is configurable. **Never drop** waits for host capacity up
to its configured deadline; it can slow the guest and still report drops when
the deadline expires. **Drop new telemetry** favors continued guest progress
and counts what was lost. A detection match is evidence to investigate, not a
maliciousness verdict.

Known 0.7.0 limitations include telemetry drops under heavy stress and
intermittently slow reconnect; those follow-ups are scheduled for 0.7.1. See
[the changelog](CHANGELOG.md) and [implementation notes](docs/implementation.md).

## Testing and development

The **torture samples** are controlled workload generators: syscall floods,
process trees, file churn, network traffic, async I/O, unusual syscall arguments,
intentional crashes and detection markers. `ant-torture` combines the modules;
individual `ant-*` programs isolate a feature, with light/heavy/extreme levels.

A sample's `PASS` means its action ran. The separate **conformance suite** checks
what Antinomie actually recorded: arguments, results, captured bytes, identities,
loss accounting and trace rendering. A workload completing is not a claim that
the recording is complete or every detection rule matched.

| Start here | Purpose |
|---|---|
| [Contributing](CONTRIBUTING.md) | Kernel patch workflow, builds, checks and version branches. |
| [Host build guide](src/antinomie/monitor/README.md) | Native monitor builds and development commands. |
| [Conformance suite](tests/monitor/conformance/README.md) | Disposable-VM checks and the recording oracle. |
| [Torture sample builder](tests/monitor/build-torture.sh) | Build the combined and individual workload executables. |
| [Implementation contract](docs/implementation.md) | Supported behavior, wire contracts, measurements and limits. |
| [Project layout](docs/project-layout.md) | Durable source, build outputs and artifact retention. |

## License

Original host application, tooling and product documentation use
**[GPL-3.0-only](LICENSE) from 0.7.0**. Earlier releases retain their original MIT
terms. Shared kernel headers remain MIT; kernel-derived code, guest components,
third-party tools, rules and assets keep their own licenses.

Read [LICENSING.md](LICENSING.md), [third-party notices](THIRD-PARTY-NOTICES.md)
and the [dependency notice inventory](docs/license-inventory.md) for the scope
and redistribution requirements.
