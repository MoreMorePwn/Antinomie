# Native Antinomie monitor

Initial native Rust/egui application, C V7 transport and kernel-only guest
controls. The guest is Linux 6.12.94 with the project's Debian source baseline
and Antinomie patch. Installed bases can contain either the minimal BusyBox
root filesystem or Debian 13 amd64 with Xfce.

## License

Original monitor code and the host/shared transport are MIT licensed, copyright
2026 MikiMiku (MoreMorePwn). Kernel implementation and third-party components
retain their terms. See the root [licensing scope](../../../LICENSING.md) and
[required notices](../../../THIRD-PARTY-NOTICES.md); guest images are not wholly MIT.

## Build and run

Use an ext4 workspace. Required tools include Rust/Cargo, a C compiler, the
kernel build dependencies listed in CONTRIBUTING.md, QEMU with its GTK display
backend, qemu-img, BusyBox, cpio, gzip, e2fsprogs, and Python 3.10 or later.
Native GUI development also needs the host's X11/Wayland/OpenGL libraries.
The archive browser needs SQLite 3.34.1 or later at runtime and its development
headers/pkg-config when building; the release executable links system SQLite.
KVM requires access to `/dev/kvm`; WSLg or an X11 server provides the desktop.
TCG is available with `--tcg`, but has not been performance-qualified.

From `~/src/antinomie`:

```bash
scripts/bootstrap.sh
scripts/build-monitor-kernel.sh
scripts/build-monitor-image.py --kernel work/monitor-build/arch/x86/boot/bzImage
scripts/build-monitor-host.sh
scripts/run-monitor.sh
```

`build-monitor-host.sh` builds the locked release application and publishes it
at `work/monitor-host/antinomie-monitor`. Rebuild after changing host source.
`run-monitor.sh` executes that binary directly; it does not invoke Cargo or
silently build a missing executable. The launcher sets the repository's default
guest bundle path and forwards all application arguments unchanged.

The ELF can also run directly from any directory, without Rust/Cargo installed:

```bash
~/src/antinomie/work/monitor-host/antinomie-monitor \
  --bundle ~/src/antinomie/work/debian-6.12.94-1-trixie/images/monitor-base
```

This is a native dynamically linked Linux executable, not a static all-in-one
image. Runtime still needs compatible system libraries, X11/Wayland/OpenGL,
`qemu-system-x86_64`, `qemu-img`, and guest base artifacts. Without `--bundle`,
the existing saved setting or `ANTINOMIE_BUNDLE`/`images` default applies.
Generated executables are ignored build products, not tracked source or a
public distribution. Redistribution must retain required notices and undergo
the dependency/license review described in the root licensing documents.

The initial VM list is empty. Retained data defaults to `~/antinomie`.
Each VM lives in `<sanitized-name>_<random-identifier>/`, with its configuration,
disk overlay, per-boot records and separate `runs/` directories. Imported immutable
bases live under `bases/<content-hash>/`. `--data-dir` selects an explicit root.
On default startup, legacy `$XDG_DATA_HOME/antinomie` or
`~/.local/share/antinomie` data is copied, verified, path-adjusted and published
at the new location. Migration refuses active old monitor/VM processes and
nonempty conflicting destinations. The original data is retained as a backup;
do not resume using both roots as independent copies of the same VM.
The build directory can be removed without breaking those installed bases.
Do not remove application data to clean build products.

## Debian desktop base

**Build base…** builds this base without a repository checkout (ANT-T0028).
Natively it needs the kernel tool suite plus `mmdebstrap`, `uidmap` (and a
subordinate UID range), `dwarves`, e2fsprogs 1.47.1 or newer and `qemu-utils`;
the QEMU builder needs only QEMU and curl and downloads Debian's cloud image
once. Either way the root filesystem is bootstrapped with `mmdebstrap` from
authenticated Debian repositories (trixie, trixie-updates, trixie-security),
runs without host root, and preserves package ownership, extended attributes
and license files. Build-time Internet access does not enable networking in
created VMs. From a checkout the same orchestrator runs directly:

```bash
printf '{"format":1,"profile":"debian-xfce","options":{}}\n' > job.json
scripts/build-base.py --job job.json --inputs src/debian --work work/build \
    --output work/debian-xfce-base
work/monitor-host/antinomie-monitor --install-base work/debian-xfce-base
```

Alternatively use **File > Import base** with the completed bundle directory.
Creating a Debian VM still provisions its account with `virt-customize`
(libguestfs).
In **New VM**, choose **Debian 13 (Xfce)**, then enter a username, password and
confirmation. Minimum resources are 2048 MiB RAM and 16 GiB disk; the RAM
ceiling is 8192 MiB. Creation provisions the disk offline and
can take longer than BusyBox creation. The account uses UID/GID 1000 and
password-protected sudo. Root login, autologin and SSH are disabled. The desktop
appears in QEMU's separate display window; program terminals stay in the monitor.

Passwords accept 8..128 UTF-8 bytes without NUL/CR/LF. They are transient,
redacted in Debug output and absent from VM configuration, UI settings and
recording metadata. A private mode-0600 `guest-account.json` retains the username
and salted password hash for reset and duplication. Protect this file as
sensitive credential material. Reset reapplies the original account, not later
guest password changes; duplicate inherits the current disk and original reset
credentials. Recording remains full-content: credentials typed into a monitored
program can be captured as ordinary syscall/terminal content.

Changing an existing disk from BusyBox to Debian is rejected. Create a new VM;
existing disks and recordings remain unchanged. Debian supplies dynamic-program
libraries and shell interpreters, but uploaded programs can still need packages
not installed in the base. Package versions and authenticated build provenance
are retained in the generated bundle's `provenance/` directory and in the guest.

On boot the currently selected bundle supplies the patched kernel/initrd;
the existing disk overlay and original disk backing base remain unchanged.
Recordings distinguish boot-bundle and disk-base identities. Reset still uses
the VM's original disk base, not the current boot bundle's root filesystem.

The current QEMU memory profile supports 1..64 CPUs, 256..8192 MiB RAM, and
1..2048 GiB virtual storage. On q35, QEMU keeps up to 2.75 GiB of RAM below the
PCI hole, or only 2 GiB once RAM reaches 2.75 GiB, and places the rest at 4 GiB.
Both parts come from one backing file, the high part directly after the low
one. The backend declares both regions to the V7 host library and, at every
start, compares them with QEMU's own memory map (`info mtree` over QMP),
refusing to attach on a mismatch. The bootstrap GPA is the aligned middle of
the low region and is passed to both the guest and the V7 API.

## VM launch settings

New VM and VM settings save display and CPU options separately for each VM.
Changes apply on the next boot; stop the VM before saving settings.

| Setting | Behavior |
|---|---|
| Resolution | Auto preserves the base's default. Fixed 800x600 through 2560x1440 presets require a fixed-display-capable base and use standard VGA static EDID plus the kernel Bochs driver. Guest users can deliberately change the mode later. |
| Fullscreen | Starts QEMU's separate display fullscreen. |
| Fit to window | Scales guest pixels to the display-window size; not a live guest-resolution command. |
| Acceleration | Default uses KVM unless the application is launched with `--tcg`; KVM/TCG can be selected per VM. Global `--tcg` always forces TCG. No silent fallback when KVM is unavailable. |
| CPU model | Default keeps QEMU's default; qemu64, host and max are available. Host requires effective KVM and is rejected with TCG, including the global override. |

Headless mode suppresses the GTK window, fullscreen and scaling, but keeps the
configured guest display device/mode. Legacy configurations missing these fields
preserve their previous defaults. No disk or guest credentials are rewritten by
changing launch settings.

Fixed, fitted, windowed launches use X11/XWayland for a bounded initial window
size, clamped to the host screen. Only that QEMU child is forced to X11 and starts
without its menubar/tabs, so drawable dimensions are unambiguous. Fullscreen or
resizing scales pixels; it does not change the fixed guest resolution. A local
`DISPLAY` is required for this path; no silent Wayland geometry fallback.

To refresh a local base without rebuilding its root filesystem:

```bash
python3 scripts/refresh-monitor-bundle.py --source OLD_BUNDLE \
  --kernel work/monitor-build/arch/x86/boot/bzImage \
  --kernel-config work/monitor-build/.config --output NEW_BUNDLE
scripts/run-monitor.sh --install-base NEW_BUNDLE
```

Use the configuration matching that kernel build. Refresh publishes a new bundle,
preserves disk/initrd bytes and records parent/artifact/config hashes. It never
overwrites an installed base or selects a new boot kernel for existing VMs.
The supplied configuration must exactly match embedded IKCONFIG in the bzImage;
missing or unsupported embedded configuration fails closed. Provenance remains
in the installed manifest, but is not a publisher signature.
Select the compatible boot base in VM settings; the original disk/reset base
and guest credentials remain pinned. Fresh image builders accept the same
optional `--kernel-config`; absence means fixed-display capability is unknown.

## Display troubleshooting

If WSLg reports `Io error: Broken pipe` and `WinitEventLoop(ExitFailure(1))`,
the Wayland display connection may have been lost. A process-local X11 launch
was verified on the development host:

```bash
env -u WAYLAND_DISPLAY -u WAYLAND_SOCKET scripts/run-monitor.sh
```

Keep `DISPLAY` and `XDG_RUNTIME_DIR` intact. The pinned winit version does not
honor `WINIT_UNIX_BACKEND`; remove both Wayland variables for this comparison.
This does not change saved settings, automatically restart the monitor, reconnect
an earlier capture, or repair a crashed compositor. WSLg hosts XWayland too,
so X11 does not isolate the application from all WSLg display-server failures.
Check `/mnt/wslg/stderr.log` and `weston.log` if the failure recurs. Do not
restart display/WSL services while a VM or another application is active.

## Ownership and APIs

The native workspace uses one saved-VM list, a filtered paired syscall table,
and a resizable lower pane with Details and Activity tabs. Configuration,
launch, upload and recording settings open in bounded dialogs. Toolbar icons
have tooltips; menus expose the same implemented commands. There are no
placeholder process/rules/build views or duplicate image/run catalogs.

Each program opens its own native interactive terminal window. Concurrent
programs have independent terminal IDs, input, resize, recording and Stop
actions. Closing a terminal window leaves the program running; reopen it from
the run selector. Closing the main application still shuts down its VM.
Core drains and saves terminals independently of UI/window visibility.

Text size is persisted in Settings, from 12 to 24 points (default 16).
Terminal cell metrics follow its font so displayed rows/columns and guest resize
requests agree. Tables show Time, Sequence, TID, CPU, Syscall (number), Return
and Info. Entry/Exit correlate by stream/task/call identity, never by CPU/PID.
Missing phases remain visible. Expand Entry/Exit and their arguments/captured
objects in Details; the split inspector shows captured hex/ASCII and numeric
interpretations. Float values are bit reinterpretations, not proof of the
argument's semantic type. Sparse holes are not manufactured bytes.
Loss counters and recording failures remain visible. A run selector reopens
past recordings without replacing live collection; offline reads use a bounded
worker. Terminal output sequence gaps trigger a core-owned screen snapshot.

| Module | Responsibility |
|---|---|
| `crates/monitor-core/src/api.rs` | Owned VM/launch options, commands, status and notifications |
| `backend.rs` | One VM session owner; bounded commands, coalesced snapshots, shutdown |
| `transport.rs` | Unsafe C FFI boundary; features never inspect CPU rings |
| `control.rs` | Versioned command encoding and guest response validation |
| `parser.rs` | Checked ANTT envelopes, correlation, fragments, gaps and bounded previews |
| `storage.rs`, `recording.rs` | Durable base import, overlays, recordings and offline range reads |
| `guest_account.rs` | Private offline account provisioning and reset credential state |
| `run.rs` | Per-program metadata, transcript/journal and headless terminal-screen persistence |
| `vm.rs` | Argument-vector QEMU launch, QMP force-stop and process ownership |
| `crates/monitor-ui/src/` | Native VM list, settings, event table and VT terminal |
| `protocol/guest-profile.json` | Exact syscall set, UAPI layouts, capture rules and known gaps |
| `protocol/control.h` | Kernel/host application-control wire contract |
| `../transport/` | Unchanged V7 transport API and layout |

The guest patch adds syscall entry/exit and task lifecycle hooks, streaming
recording, and sleepable upload/exec/PTY/stats/shutdown handlers. Only programs
launched through control and their descendants are traced. There is no resident
guest control helper. Initial execution supports static x86-64 binaries and
BusyBox scripts; uploading does not supply interpreters or shared libraries.
Network is disconnected unless explicitly enabled. Guest credentials default
to UID/GID 1000. Closing the application requests synchronized guest shutdown,
then forces power-off after the configured timeout.

## Recording semantics

Raw files contain repeated little-endian u32 packet length followed by the
exact application packet. Object files store captured field ranges; a sparse
hole is never presented as captured content. Manifests include final transport,
parser and recorder health, and clean/forced/unexpected termination state.

Each launch has independent raw telemetry, objects, `run.json`, terminal output
in `terminal-transcript.raw`, output/resize/EOF in `terminal.journal`, and a final
`terminal-screen.ansi` screen with saved grid metadata. Terminal EOF does not
prove detached descendants exited: recording stays active until VM stop.
Stop requests SIGTERM for tracked tasks in the selected launch tree; programs
can ignore it and concurrent forks can escape that signaling pass. The host
currently allows 64 total launches per VM boot; restart the VM to begin another
batch. Historical terminal views are read-only.

The configured quota covers raw packets, assembled payloads and terminal payloads
together across the VM boot's runs.
Bounded event indexes/manifests, installed bases and VM disks are separate;
this is not a hard filesystem-wide disk cap. On quota/I/O failure the backend
stops saving payloads, preserves prior data, and continues draining telemetry.
`received_packets` and `storage_dropped_packets` count actual collector reads
and failed raw append attempts separately from guest transport drops.
Nonblocking guest overflow drops new records and increments queryable counters.
Complete content is therefore best effort, never guaranteed delivery.

Pointer reads are observational no-fault copies, not atomic syscall operand
snapshots. Supported fields stream in 4096-byte chunks to argument/kernel
limits, with faults and losses explicit. Unknown ioctls and compat ABIs are
marked unsupported; the profile lists all limitations. Coverage is the selected
30 native syscall families, not the full syscall catalog or a measured malware
frequency ranking. No snapshot restoration/reconnection is supported.

ANTT 1.1 extends the application header to 136 bytes with an inherited launch
root task cookie at offset 128. V7 is unchanged. Legacy 1.0 packets remain
readable but cannot be reliably assigned to program runs after lifecycle loss;
old VM-wide recordings are explicitly labelled legacy recordings.

## Checks

```bash
cargo test --manifest-path src/antinomie/monitor/Cargo.toml --workspace --all-targets
gcc-14 -O2 -static -Wall -Wextra -Werror tests/monitor/guest-probe.c -o work/monitor-probe
gcc-14 -O2 -Wall -Wextra -Werror -I src/antinomie/transport \
  -I src/antinomie/monitor/protocol tests/monitor/integration.c \
  src/antinomie/transport/host.c -o work/monitor-integration
python3 tests/monitor/run-integration.py --cpus 4
cargo run --manifest-path src/antinomie/monitor/Cargo.toml \
  -p antinomie-monitor-core --example headless -- \
  "$PWD/work/debian-6.12.94-1-trixie/images/monitor-base" \
  "$PWD/work/monitor-backend-test" "$PWD/work/monitor-probe"
```

The headless example also accepts `--recording CAPTURE_DIR`. Full saved-history
pages and terminal replay are available through the recording API and native UI,
not limited to the bounded live event summary. A rebuildable SQLite cache lives
outside recordings under `$XDG_CACHE_HOME/antinomie/browse` (or `~/.cache`), not
inside VM disk/payload quota accounting. Index construction and cancellation
run on the archive reader, not the transport owner or rendering thread.

The concurrent-run integration fixture uses an isolated new data directory:

```bash
cargo run --manifest-path src/antinomie/monitor/Cargo.toml \
  -p antinomie-monitor-ui --example run-history-check -- \
  "$PWD/work/debian-6.12.94-1-trixie/images/monitor-base" \
  "$PWD/work/run-history-test"
```

Test outputs are disposable under `work/`; production application data is not.
Set `ANTINOMIE_TEST_QUOTA_SIZE=1024` for the headless quota-cutoff scenario; use
a fresh, short data path so its QMP Unix socket fits the system path limit.

## Agent skills

Root `AGENTS.md` defines shared conventions and skill routing. Rust workers read
relevant `rust-skills` rules, the native UI worker also reads `frontend-design`,
and the kernel worker reads the project-specific `antinomie-kernel` skill.
`security-threat-model` is installed for explicit threat-model work, not run
automatically as a substitute for behavioral tests. Keep local skills focused;
read only the rules needed for the current responsibility.

The kernel build runs `tests/monitor/check-contracts.sh` to reject drift between
exported guest copies and the host transport/control contracts.
