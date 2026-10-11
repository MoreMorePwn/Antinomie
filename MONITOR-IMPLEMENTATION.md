# Antinomie initial monitoring release

This brief is the shared implementation contract. User authorized implementation
on 2026-10-01. Core workers/review use gpt-6.1-sol; bounded support may use Luna.
The accepted 0.5.0 snapshot/reconnect extension below supersedes the historical
V7-only restriction; older requirements remain recorded for their releases.

## Accepted requirements

- Linux 6.12.94 existing baseline, BusyBox filesystem; Debian userspace later.
- Native Rust desktop interface without HTML. Separate QEMU display window.
- Initially empty VM list, create named VMs from one base image. Configurable
  CPU count, RAM, disk capacity. Many saved configurations, one running VM.
- Persistent VM disk overlays with explicit confirmed reset to base. User VM
  data lives outside disposable work/ build trees.
- Disconnected network default; explicit NAT enable with warning.
- Host file upload to guest path: overwrite confirmation, separate executable
  option. Never execute automatically after upload.
- Kernel implements control, upload, execution, tracing, and terminal I/O;
  no auxiliary guest helper process. Ordinary init, shell and target programs
  remain userspace processes.
- Launch path, argument list, cwd, environment, UID/GID. Default unprivileged.
- Interactive terminal in host control view, independent of QEMU console.
- Trace only control-launched processes and all descendants, surviving exec,
  double fork, parent exit, CPU migration. Per-task unique identity, not PID only.
- Entry/exit correlation and full semantically defined pointer content. Stream
  large buffers in bounded chunks. Nofault observations may be incomplete.
- Nonblocking drop-new transport; capture and delivery losses remain explicit.
- Save raw telemetry and manifest. Stop saving on quota/full disk, preserve
  earlier data, visibly report persistence failure while continuing collection.
- Closing app: request guest shutdown, continue capture; after configurable
  timeout force power-off; finalize and mark clean/forced recording.
- V7 no snapshot/reconnect. No next transport version. Existing transport API
  is opaque; frontend/backend never manage CPU rings.

## Accepted ANT-T0055 host evidence update (0.5.0)

User authorized inspection, completion and release of current 0.5.0, with guest
acquisition work deferred to 0.6.0. Static-analysis priority is result readability.
This extends the existing revision-14 / ABI9 snapshot baseline without changing
the guest contract. Host launch controls optionally own a separate network filter
from before execution through whole-tree exit and queue one post-exit VM RAM dump.
Snapshot/reconnect boundaries split captures into new retained segments.

Evidence labels are bounded sidecars; recorded IDs and paths never change.
Full retained static text/JSON and native Ghidra project exports preserve partial
status, reject unsafe paths and never overwrite existing output. Opening Ghidra
uses an exported working copy. Saved trees and numbered 100-call trace pages read
a bounded snapshot of ongoing archives. Imported process cores use bounded,
file-backed Linux ELF64/x86-64 inspection, thread registers, mappings and on-demand
disassembly; missing pages remain explicit. They are separate from physical RAM.

Isolated networking uses QEMU user networking with restrict=on, no forwarding,
TFTP or SMB. Exact process core capture before exit, all-thread register freezing
and pre-free memory capture require new guest support and remain 0.6.0 backlog.
No guest rebuild is necessary for these host additions; already-built current
0.5.0 bases are reused. The documentation acceptance record is ANT-T0055.

## Ownership

### Accepted ANT-T0042 Update

User authorized local Antinomie 0.3.0 on 2026-10-09 and the usability follow-up
on 2026-10-10. Capture All retains a per-process tree; revision-13 bases use
transport ABI 8 with tunable rings and bounded never-drop waits. Legacy ABI 7
bases remain supported with their original dropping behavior. This supersedes
the initial drop-only/V7 requirement for new bases; no snapshot or reconnect.
Network capture is explicitly started/stopped on a running NAT VM using QMP,
retained separately per boot and capture, and browsed with history, protocol
colors and structured filters. Terminals resize their guest PTYs and retain
bounded scrollback. Details offer numeric copy formats and bounded captured-data
windows; analysis displays ongoing progress. Optional guest-desktop launches
join an already logged-in graphical session using the run's kernel-controlled
process tree. No persistent guest helper or automatic login is introduced.
The task record and resumption contract are ANT-T0042 in the documentation task
directory. Product commits and binaries stay local until the user's testing;
documentation publication is independent of that product-release decision.

### Accepted ANT-T0033 Update

User authorized the native static-analysis workspace redesign on 2026-10-08.
One workspace is the default; selecting a category updates local results and
separate dockable section panes open only on explicit request. Typed available
evidence drives searchable/sortable tables, selected details and bounded read-only
specimen previews. Legacy generic reports remain readable. Acquisition, launch
scope, engine availability, guest controls and V7 remain unchanged. No new analyzer
dependency or guest image build is needed. The revision-1 result contract and
acceptance record are ANT-T0033 in the documentation task directory. Development
and the rebuilt executable stay in feature/static-analysis pending integration.

### Accepted ANT-T0025 Update

User authorized complete static-analysis acquisition/backend and launch setup
on 2026-10-08. Run Program opens launch fields left, opt-in analysis checkboxes
right and a final Run button. Initial executable only; no descendant/later exec
static acquisition. Triage plus optional deep analysis, local/no network default,
exact initial guest exec-file acquisition with bounded wait, failure continues
execution and reports unavailable. Retained reports reopen without rescanning.
The frozen revision-1 implementation contract is in the documentation task
directory, ANT-T0025 - Implementation Contract.md. Application control revision
10 adds optional specimen controls; V7 remains unchanged, revision-9 guests
still launch with explicit analysis unavailable. Resource/isolation/compatibility
limits and engine gaps must be recorded, not presented as complete clean scans.
Development is isolated in feature/static-analysis; preserve concurrent dirty
image-builder work and do not replace the normal executable before integration.

### Accepted ANT-T0012 Update

User authorized saved per-VM guest/window resolution, fullscreen, fit-to-window,
KVM/TCG acceleration and bounded CPU-model choices in New VM/settings. Typed
serde-default launch configuration preserves legacy defaults. Settings apply on
next boot only; global force-TCG/headless overrides retain precedence. Host CPU
requires effective KVM. User approved retaining fixed guest pixels while scaling
the QEMU window. Presets use standard VGA static EDID, built-in Linux Bochs DRM
and video=Virtual-1 mode selection. Fixed/fitted/windowed GTK launches use a
bounded owned-window X11/XWayland initial-size operation; fullscreen/headless
paths need none. Existing x11rb/rustix packages provide safe display operations.
New immutable bundles declare fixed_display capability; legacy hashes and user
disks stay intact. No kernel/transport revision, guest helper or free-form QEMU
arguments. Detailed revision 3 contract is ANT-T0012 in the documentation task
directory.

### Accepted ANT-T0015 Update

User found the Debian Xfce guest did not resemble a VM installed from the Debian
ISO; analysis showed a `virt-builder debian-13` cloud template plus a curated
`--no-install-recommends` package list missing the desktop meta-package and its
recommends. User chose the closest-to-ISO completeness level and to keep guest
integration purged. Install `task-xfce-desktop` with recommendations, move
networking to NetworkManager (dropping the custom `ifupdown`/`dhcpcd` setup),
and grow the immutable base to a 16 GiB whole-disk layout with 16 GiB guest
minimum. `openssh-server`, `qemu-guest-agent`, `spice-vdagent`, `cloud-init`,
`cloud-guest-utils` and `linux-image-*` remain purged; root stays locked, no
ordinary users exist in the base, `/dev/vda` remains the fstab root and the
hostname stays `antinomie`. No kernel, transport or application change; existing
bundles, VM disks and recordings are untouched. Task record is ANT-T0015 in the
documentation task directory.

### Accepted ANT-T0014 Update

User reported that after the absolute-pointer fix the guest showed two cursors
(the guest's software cursor plus the host pointer). The fixed-resolution path
used standard VGA (`-device VGA,edid=...`), which has no hardware cursor, so the
guest X server painted its cursor into the framebuffer. User approved switching
the fixed path to a hardware-cursor GPU. Use
`-vga none -device virtio-gpu-pci,edid=on,xres=W,yres=H`. The connector is a
`DRM_MODE_CONNECTOR_VIRTUAL` named `Virtual-1`, so `video=Virtual-1:WxH` is
retained. This matches the Auto path's virtio-gpu device and gives a single,
VMware-like pointer. Both virtio-gpu and Bochs DRM use the `Virtual-1` virtual
connector, so existing fixed-display bundles whose kernels build
`DRM_VIRTIO_GPU=y` remain compatible. Image/bundle capability checks now require
`DRM_VIRTIO_GPU` and `DRM_VIRTIO_GPU_KMS`. No kernel, transport or user-disk
change. Task record is ANT-T0014 in the documentation task directory.

### Accepted ANT-T0013 Update

User reported the guest mouse pointer stuck at the display center: clicks reached
the guest but motion did not move the cursor. Cause is the QEMU GTK relative
pointer grab; the launch attached only the emulated PS/2 mouse. User approved
attaching an absolute pointing device to all non-headless launches. Use
`-device virtio-tablet-pci` (a self-contained PCI device requiring no USB
controller) so the host pointer is tracked directly and never grabbed. The
existing guest kernel already binds `CONFIG_VIRTIO_INPUT`, so this is a
launch-argument change only: no kernel, transport, bundle or user-disk change.
Headless launches are unaffected. Task record is ANT-T0013 in the documentation
task directory.

### Accepted ANT-T0010 Update

The user authorized full Debian userspace on 2026-10-06, selected Xfce and
requested per-VM credential creation with password-protected sudo. Add Debian13
trixie amd64 alongside BusyBox; retain patched Linux6.12.94, V7, kernel-only
monitoring controls, disconnected default and existing disk/archive identities.

Optional bounded guest-profile bundle metadata distinguishes installed bases,
declares resource minima and credential/display requirements. Legacy bundles
without metadata preserve their old identity. Base import and creation stay
backend-owned; UI only selects values and transient credentials.

Debian New VM requires username/password/confirmation; create UID/GID1000 with
local password login and sudo, root locked, SSH disabled, no autologin. Offline
libguestfs provisioning precedes publication. Passwords must not be serialized
in configuration/preferences/recordings, displayed in Debug, or passed in argv.
A private0600 per-VM username/salted-hash provisioning record can support reset
and duplicate; no plaintext retained. Reset reapplies original credentials and
publishes replacement disk only after provisioning succeeds. Existing VMs are
not automatically converted or modified.

Image build uses authenticated Debian inputs and retains system account file
ownership, package provenance and licenses. Full source task/API/check contract
is `Agents/Tasks/ANT-T0010 - Debian Xfce VM Base.md` in the docs checkout. This
does not complete ANT-T0009's remaining syscall/async semantics.

### Accepted ANT-T0009 Update

The user approved these changes on 2026-10-06. The task record is
`Agents/Tasks/ANT-T0009 - Full Native Syscalls and Dockable Workspace.md` in
the documentation checkout. Earlier 30-syscall requirements remain historical,
not the completion target for this update.

- Cover all 375 named native `common`/`64` syscall slots in Linux 6.12.94.
  Use the pinned syscall table and checked argument/schema inventory; exclude
  x32/i386 from native decoding. Empty/ni entry points and disabled features
  remain explicit. Raw metadata expansion alone is not full pointer decoding.
- Capture asynchronous submissions/completions, including native io_uring/AIO
  observation. Use request and originating-run identities, bounded staging,
  explicit losses and safe callback lifetimes. V7 remains task-context-only
  and unchanged. Unknown multiplexed/device variants retain raw arguments and
  explicit Unsupported decoder status; do not guess pointer extents.
- Add kernel-owned queryable full-tree run status; root wait status is separate
  from surviving descendants and pending async work. Stop acknowledgement still
  means signal requests, not termination. Legacy/unknown state is not Finished.
- VM-scoped Run History replaces the sidebar program list. It displays launch
  path/name, argv, cwd, environment, UID/GID/stable identity and truthful status.
  Double-click selects that run's syscall archive independently of collection.
- Independently chosen disk and recording locations; durable per-VM paths and
  preserved existing data. Folder changes never silently move active files.
- Installed-base dropdown initially labelled Linux 6.12.94; ordinary startup
  must work without disposable build inputs after a verified base import.
- Display captured lengths with units, e.g. Captured bytes (52 bytes). Decode
  argument flags with named masks/enums/composites, raw values and unknown bits.
- VM context actions: Rename, Open Directory, Delete, Duplicate and Settings.
  Duplication requires a stopped source, copies its current disk independently
  with a new identity and omits history. Destructive actions are confirmed.
- Syscall Trace, Run History, Details, Activity and program terminals can detach
  into native windows and dock/merge back. VM list stays fixed; panel movement
  cannot duplicate transport/readers or terminate programs.
- Static syscall exercise ELF and host verifier: safe/reversible disposable
  resources, bounded children/timeouts/cleanup, explicit PASS/FAIL/SKIP and
  incomplete-capture outcomes. Do not execute irreversible guest/host changes.

Implementation is split into checked contracts and family slices, with bounded
kernel/core/UI ownership and an independent review gate. Do not claim the whole
task delivered while native content/async cases remain unimplemented. Existing
archives and per-VM disks are compatibility inputs, not disposable fixtures.

### Accepted ANT-T0008 Update

The user approved these changes on 2026-10-05:

- Each launched program opens a native terminal-only window. Concurrent runs
  are supported within the single running VM. Closing that window leaves the
  program running; it can be reopened and explicitly stopped.
- Main trace pairs entry/exit by stream/task/call identity and shows Time,
  Sequence, TID, CPU, Syscall (number), Return and Info. Missing phases remain
  explicit. Entry/Exit argument trees and captured-object expansion feed a
  separate hexdump/numeric inspector. Never infer uncaptured pointer content.
- Text size is configurable and persisted. Terminal grid uses the same font.
- Default retained data root is `~/antinomie`; VM directories are sanitized
  names plus random identifiers. Existing user VM data/archives are migrated
  by validated publication, never by moving an active VM's backing files.
  User also approved booting migrated VMs with the newly patched kernel;
  existing disk overlays/backing bases and explicit reset-to-base behavior
  remain intact. Record boot bundle and disk base identities separately.
- Each launch retains separate telemetry, launch metadata, terminal output,
  resize history and a final terminal-screen snapshot. This is NOT a QEMU RAM
  snapshot; V7 restore/reconnect remains unsupported. Offline paging must not
  replace active collection or allocate the entire history.
- Application telemetry extends major 1 with minor 1 and a 136-byte header:
  original offsets 0..127 unchanged, root task cookie u64 at offset 128,
  inherited independently of successful lifecycle transmission. Host also
  reads legacy minor 0 / 128-byte headers with explicitly unknown ownership.
- STOP_RUN opcode `0x1015`: version header (8 bytes), root task cookie u64 at
  offset 8, total 16 bytes. Signals matching tracked tasks with SIGTERM;
  success means signals issued, not atomic full-tree termination. No matching
  tasks returns `-ESRCH`. Existing SIGNAL semantics remain separate.
- PTY EOF/root exit alone do not prove detached descendants finished. Per-run
  recording remains active until VM stop, with that distinction visible.
- Cleanup removes old generated test VM disks/captures only after migration
  validation; kernel author/source trees, build inputs and executable remain.

Core/UI workers freeze public run-addressed types before dependent rendering.
Core owns archive validation/paging and headless terminal persistence; UI uses
owned API values and performs offline disk reads outside the rendering thread.
Existing `vt100 0.15` may be used by core without adding a new external package.
`rusqlite 0.40.2` is approved for bounded disk-backed archive indexing; SQLite
is linked from the system and required upstream notices are retained.
Run/session maps, previews, pages and queues remain bounded; new recording
payloads count against the recording quota and preserve explicit failures.

- Guest worker: kernel author tree work/debian-6.12.94-1-trixie/core, new guest
  protocol header src/antinomie/monitor/protocol/control.h, guest source manifest.
- Host worker: src/antinomie/monitor/crates/monitor-core only, public backend API.
- UI worker: src/antinomie/monitor/crates/monitor-ui only, depends on monitor-core.
- Coordinator: workspace Cargo.toml, build/test/rootfs scripts, integration,
  patch exports, final documentation. Workers must not commit outer repository.
- No nested delegation, no wholesale refactor of transport. Return concise
  changed files / tests / failures / outstanding work. Never invent test results.

## Telemetry protocol

Use existing Syscall Telemetry Plan application protocol 1 (ANTT, 128-byte
little-endian envelope) from the docs vault, carried as opaque V7 messages.
Implement EVENT_BEGIN (120), FIELD_BEGIN (40 + key/layout), FIELD_DATA,
FIELD_END (32), EVENT_END (32); emit lifecycle/health where implemented. Parse
explicit offsets, never native Rust struct casts. Missing begin/end/chunks,
copy faults, decoder gaps, parser limits and persistence failures are explicit.
CPU is metadata. Stream ID + task cookie + call ID identify invocations.

Initial 30 syscall numbers/names for behavioral malware analysis (selected
coverage, not a measured popularity ranking):
0 read, 1 write, 2 open, 3 close, 4 stat, 5 fstat, 9 mmap, 10 mprotect,
11 munmap, 16 ioctl, 19 readv, 20 writev, 41 socket, 42 connect, 43 accept,
44 sendto, 45 recvfrom, 49 bind, 50 listen, 56 clone, 57 fork, 58 vfork,
59 execve, 60 exit, 62 kill, 82 rename, 87 unlink, 231 exit_group,
257 openat, 322 execveat.
Output buffers use actual return bounds and saved entry capacities. Vector
descriptors are entry snapshots. Exec argv/env strings obey kernel ceilings.
Unknown ioctl operations report NO_DECODER, not guessed nested memory layouts.
Lifecycle hooks must follow descendants regardless of selected syscall number.

## Host/control contract

Guest worker establishes protocol/control.h promptly and tells host worker
when ready. Opcodes: 0x1001 upload begin, 0x1002 upload chunk, 0x1003 commit,
0x1004 abort, 0x1010 exec, 0x1011 terminal input, 0x1012 terminal read,
0x1013 terminal resize, 0x1014 signal, 0x1020 recorder stats,
0x1030 shutdown. Explicit little-endian fields, versioned, checked lengths;
results travel in the existing reply queue. Each reply matches request ID.
Persistent health/loss counters queryable even after telemetry loss.

Rust backend runs blocking ant_init/poll/read on one owner thread. It exposes
owned commands and bounded UI snapshots, handles reply matching and telemetry,
and keeps collection/persistence independent of frontend frame rate. Shared
public API types should be established early by host worker for UI worker.

## Verification

Build Rust workspace and kernel. Four-core QEMU integration: bootstrap attach,
upload static test program/shell script, launch with UID/cwd/env, terminal I/O,
entry/exit + buffer bytes, descendant execution, invalid pointers, telemetry
overflow, disk persistence/reset and graceful/forced shutdown. Include CPU/RAM
variants if feasible. Use actual measured results and record unavailable tests.

All final docs in the separate documentation repository. Obsidian
Mermaid. Declarations/arguments/returns in tables; executable source explained
using short excerpts with actual filename/line numbers and prose below. Preserve
unrelated v5 walkthrough edit. Coordinator commits/pushes docs after validation.

## Accepted snapshot and reconnect extension (0.5.0)

The authorized snapshot manager supports disk checkpoints (cold boot recovery)
and full CPU/RAM/device checkpoints (resume recovery), with a branching native
graph. External qcow2 layers are frozen; each branch owns a separate writable
child. A durable manifest and pending-operation journal own active disk selection.
Live disk capture is crash-consistent; full capture pauses CPUs and suspends host
RAM writes. Full recovery requires ABI9 and exact QEMU/config/bundle compatibility.

ABI9 adds a host attachment nonce/guest acknowledgement mailbox independent of
command queues. The guest services it before/between control dispatches, fences
executed and abandoned request IDs, and preserves per-CPU telemetry producers.
The host skips stale replies, reads from restored owned tails and never replays
unresolved side effects. ABI7/8 retain cold attachment and disk checkpoints.

Full restore creates fresh recording IDs/directories, retains restored guest
run/capture cookies, seals old archives and records incomplete boundary tails.
Old recordings and saved ancestors remain immutable. Restore confirmation can
save current state first; failure to save prevents restore. Hidden checkpoints
retain all disk/memory artifacts until confirmed whole-VM deletion. Snapshot-aware
reset/data relocation are guarded until their dependency-safe implementations.
