# Native Antinomie monitor

Initial native Rust/egui application, C V7 transport and kernel-only guest
controls. The guest is Linux 6.12.94 with the project's Debian source baseline
and Antinomie patch, plus a minimal BusyBox root filesystem, not Debian userspace.

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
KVM requires access to `/dev/kvm`; WSLg or an X11 server provides the desktop.
TCG is available with `--tcg`, but has not been performance-qualified.

From `~/src/antinomie`:

```bash
scripts/bootstrap.sh
scripts/build-monitor-kernel.sh
scripts/build-monitor-image.py --kernel work/monitor-build/arch/x86/boot/bzImage
scripts/run-monitor.sh
```

The initial VM list is empty. VM data defaults to
`$XDG_DATA_HOME/antinomie`, or `~/.local/share/antinomie`. An imported immutable
base lives under `bases/<content-hash>/`; saved VM overlays are under `vms/`.
The build directory can be removed without breaking those installed bases.
Do not remove application data to clean build products.

The current QEMU memory profile supports 1..64 CPUs, 256..3072 MiB RAM, and
1..2048 GiB virtual storage. Flat RAM stays below the PCI hole. The backend
chooses an aligned bootstrap GPA from the configured RAM size and passes the
same value to the guest and V7 API. Larger/non-flat RAM layouts require a
different validated memory profile, not guessed GPA-to-file arithmetic.

## Ownership and APIs

| Module | Responsibility |
|---|---|
| `crates/monitor-core/src/api.rs` | Owned VM/launch options, commands, status and notifications |
| `backend.rs` | One VM session owner; bounded commands, coalesced snapshots, shutdown |
| `transport.rs` | Unsafe C FFI boundary; features never inspect CPU rings |
| `control.rs` | Versioned command encoding and guest response validation |
| `parser.rs` | Checked ANTT envelopes, correlation, fragments, gaps and bounded previews |
| `storage.rs`, `recording.rs` | Durable base import, overlays, recordings and offline range reads |
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

The configured quota covers raw packets plus assembled payloads together.
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

The headless example also accepts `--recording CAPTURE_DIR` to reopen a finalized
capture. Offline reopening is currently an API/example operation, not a UI view.
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
