# Implementation record: Disks, memory and recording

The Disks tab, process cores, MemNixFS and the recording quota. Part of the [implementation record](../implementation.md).

### Accepted configurable process-core size (0.7.0)

The 64 MiB / 5 s ceiling of process cores is configurable. The guest series gains
0039 (limits from guest RAM, chunked buffer, one budget enforcer, `CORE_CAPS`
0x1066, `CORE_STATUS` STORED flag) and 0040 (control worker polls every tick while a
finished core is read). The contract stays at revision 17; an older guest answers
`CORE_CAPS` with `-EOPNOTSUPP` and the host keeps the 64 MiB / 5000 ms contract,
and an older host never sends either request. Host: `core_limits.rs` (limits,
validation messages, reasons), `backend/core_stream.rs` (pipelined reads, host
disk and quota checks), a probe in `session_transport.rs`, budget and deadline
choosers (`core_budget.rs`) in Run program, Dump core and Settings.

* **Decisions**: default budget 256 MiB clamped to the guest; hard cap 1 GiB; the
  guest maximum is half of RAM less 128 MiB (64 MiB to 1 GiB), pool twice that;
  exit cores still allocate 64 MiB when armed; deadline 5 s + 10 ms per MiB up to
  60 s. Buffering stays in the guest (no streaming during capture).
* **Evidence** (BusyBox base, `core-size-check`, workload `core-on-crash`): light
  33,996,800 bytes and heavy 134,660,096 bytes complete at budget 256 MiB (stack
  and vsyscall pages captured; heavy at 64 MiB is Partial, reason budget, cut at
  67,321,856 of 134,660,096); extreme 524,730,368 bytes complete at the 1 GiB cap
  on a 3 GiB guest; a 335 MiB heap on a 512 MiB guest is Partial, reason guest
  memory, never Complete; a 300 MiB manual core completes its transfer in 13.9 s;
  a deadline of 2 s under software emulation is Partial, reason deadline; a 100 MiB
  recording quota cuts a heavy core at the quota (reason quota); a host disk with
  137 MiB free refuses a 129 MiB core before writing (reason host disk); canceling
  a manual core at 50 % keeps a hashed prefix (reason canceled).
* **Transfer**: 1.2 MiB/s before (guest poll of 10 ms, one read per pass) to
  25-31 MiB/s after (eight reads in flight, joined writes, tick polling).
* **Still true**: a manual core reports Partial with reason coverage when the
  resident-only policy leaves mappings out, as before.

## Disks tab: the disks of a stopped VM (0.7.0, phases 1 to 3)

Accepted design: Disks tab implementation design v2, phases 1 to 3 (the dumps are described after the limits below,
phase 3 after them). Host only; no guest kernel change.

**Mechanism.** The VM's qcow2 chain (`snapshots::active_disk`) is flattened by
`qemu-img convert -p -f qcow2 -O raw` into a sparse raw ext4 image,
`<recording dir>/disks/.scratch-<id>/root.ext4` (a scratch image). Progress is
the `(NN.NN/100%)` lines of `-p`; the converter runs under `setpriv
--pdeathsig KILL` so an app crash cannot leave it attached to the chain, and
without `-U`, so QEMU's own image lock is the backstop. After conversion the
size must equal the chain's virtual size and the ext4 magic must be at offset
1080; the superblock `s_state` gives `clean` or `not cleanly unmounted`.
`qemu-img map` (output capped at 64 MiB, falling back to the layers' allocated
sizes) gives the estimate: the sum of extents that are data and not zero, an
upper bound of the sparse output. Free space is `statvfs` of the `disks`
folder against estimate + 64 MiB (the whole logical size when a one-megabyte
probe file shows the folder cannot hold holes).

**Backend (`backend/worker_disks.rs`, `disks/{measure,job}.rs`).** One disk job
at a time (`Worker.disk_job`) holds the lease on its VM's image while
`qemu-img` reads the chain. `Worker::command` first runs `disk_lease_gate`
(`lease()` is a pure function with a test over every command).

| Command | While a job holds this VM's image | While a view of this VM is open |
| --- | --- | --- |
| `Start` | Refused ("being read for the Disks tab") | Allowed; the view is closed after the start |
| `Reset`, `RestoreVmSnapshot`, `CreateVmSnapshot`, `Delete` | Refused | Allowed; the view is closed after success |
| `Duplicate`, `Save` that resizes | Refused | Allowed; the view stays |
| `MeasureDisk`, `OpenCurrentDisk` | Refused ("another disk inspection or dump is still running") | `Open` replaces the view |
| Either, while this VM runs | Refused ("stop the VM before inspecting or dumping its disk") | n/a |

Another VM running does not matter. Scratch folders are swept when the backend
starts and before a new materialization; closing the backend deletes the open
view. `Snapshot` gains `current_disk`, `disk_measure` and `disk_job`; commands
are `MeasureDisk`, `OpenCurrentDisk`, `CloseCurrentDisk`, `DumpDisk`,
`KeepCurrentDiskAsDump`, `CancelDiskJob`.

**Reader (`disks/reader/`).** A second mode of this program, `--disk-reader`
(`worker_main_if_requested`, before CLI parsing like the analysis workers),
under the `sandbox_run` bubblewrap recipe: `--unshare-all --unshare-user
--disable-userns --die-with-parent --new-session --clearenv --cap-drop ALL`,
`--ro-bind /usr`, `--proc`, a 16 MiB `/tmp`, the program at `/worker`, the image
`--ro-bind` at `/image`, the extraction folder `--bind` at `/out`,
`--remount-ro /`, and `prlimit --as=2147483648 --nofile=64 --core=0`. The
protocol is JSON lines (`Probe`, `List`, `Info`, `Find`, `Extract`), one
request in flight, each answer echoing its id, bounded line sizes, typed
`ReadError`. The parent (`Reader`) starts the worker lazily, kills it on a
timeout, an abort or drop, and starts a new one with the next request. Guest
paths are labels: a path must be absolute without `..`, every parent must be a
real directory (a path through a link is refused), links are reported with their
target text and never followed, extraction of a link writes its target as data.
The worker writes `/out/<request id>`; `disks::extract::place` then (in the
parent, after the answer) checks it is a regular file, names it `<n>-<leaf>` with
`host_leaf` (controls, separators and direction overrides replaced, leading dots
dropped, 100 bytes) and seals it with `openat2(NO_SYMLINKS)` and `fchmod 0600`.
Bounds: listing pages of 256 (a directory is read up to 65,536 entries), Find
at most 5,000 matches, 1,000,000 entries, depth 64 and 15 s, hashes up to the
setting (64 MiB), extraction up to the setting (256 MiB; 4 GiB after the user
confirms, with a free-space check), the viewer up to 16 MiB.

**Interface (`disk_view/`).** `Panel::Disks` after Memory (layout version 7 puts
the tab after Memory in saved layouts without changing which tab shows);
`DetailsOf::DiskEntry` for the shared Details dock. The tab keeps two reader
threads (browse; find and extract) so a long find does not block the tree. The
tree is the host explorer's cached-flatten design (shared `PAGE_LEN`,
`DIRECTORY_LIMIT`, `DEPTH_LIMIT`, `tree_lines`, viewport-only rows) over reader
listings. Extract to view uses `DataWindows::open_bytes` (the data viewer);
Static Analysis uses the new `AnalyzeHostFile` command, because `AnalyzeOnly`
reads a guest path from a running VM: `Jobs::submit_host_file` copies the
extracted file into the report's specimen slot and the ordinary isolated
worker, report and quota accounting follow, with its own `Jobs` in the backend
worker so it needs no VM. Settings: `disks.{extract_cap_mib, hash_cap_mib,
hide_dotfiles, numeric_modes}`.

**Limits.** `ext4-view` 1.0.0 exposes no inode numbers or link counts, so
neither is shown and a directory cycle is bounded by the Find depth and entry
limits instead of a visited-inode set. A filesystem other than ext2/3/4 is the
"unsupported filesystem" state. The lease is held by one job per backend; the
view itself holds nothing.

### Disk dumps (phase 2)

**Folder and record (`disks/dump.rs`).** `<recording dir>/disks/<id>/` holds
`root.ext4` and `dump.json` (`DiskDump`: ids, VM, `fs_state`, `started_ms`,
`finished_ms`, `logical_size`, `allocated_size`, `sha256`, the `source` with
its layers, `system`, `imported`, `error`); `extracted/` holds files extracted
from the dump. Every field is `#[serde(default)]`, unknown fields are ignored
and an image format a later version wrote deserializes as `Unsupported` (listed,
not opened), so records move between versions. The image name in a sidecar is
reduced to its last component, so a hand-edited record cannot point outside the
folder. `list` reads `disks/*/dump.json` of every recording directory (not
`.scratch-*`, hidden folders or `extracted`; at most 1 MiB per sidecar), newest
first, one entry per folder.

**Finalization.** `Dump disk` (`Job::dump`): measure, quota and free-space
checks, `disks/<id>/` (0700), `qemu-img convert` into `root.ext4.part`,
`fsync`, size and ext4 magic/state check, rename to `root.ext4`, `fsync` of
the folder, SHA-256 (1 MiB reads of the full logical content, the `Hashing`
stage, cancelable), optional per-layer digests, then `dump.json` written
atomically and the folder synced. Any error or Cancel removes the folder;
a folder without `dump.json` is therefore never a dump. `sweep_partial` (backend
start and before every dump or view) removes folders without a sidecar that
hold nothing but `root.ext4`/`root.ext4.part`, and a stale `.part` in a finished
dump. `Keep as dump` (`Job::keep`) checks the quota ceiling against the view's
allocation, hashes the scratch image in place, then renames
`.scratch-<view>/` to `<id>/` (`promote`; on `EXDEV` it copies the scratch image,
never the chain, with `qemu-img convert -f raw -O raw` and leaves the view on
the scratch image) and writes the sidecar. The view keeps its id and extraction
folder and now reads `disks/<id>/root.ext4` (`CurrentDiskView.kept_as`, `image`);
closing it removes nothing of the dump, and deleting a dump an open view reads
is refused until the view is closed.

**Quota and space.** `JobSpec.quota` is `capture_quota_size`, applied as a
per-dump ceiling to the `qemu-img map` estimate (`DiskMeasure.quota_error`,
shown on the card before the click; the job checks it again). Views are not
bounded by it. The free-space and sparse-support preflight is the phase 1 one.

**Commands.** `DumpDisk` and `KeepCurrentDiskAsDump` carry the two Settings
flags (`disks.dump_hash`, default on; `disks.source_digests`, default off) and
go through the same lease as `OpenCurrentDisk`; `CancelDiskJob` cancels them.
`EvidenceItem::DiskDump { directory }` deletes through `DeleteEvidence`: the
path is canonicalized, must not contain `..` or be a link, must be exactly
`<recording dir>/disks/<id>` of the VM, and must hold a `dump.json`, which is
removed first. Nothing else records a dump, so no other file is rewritten.

**Import and save (`disks/dump.rs`, `disks/export.rs`).** `import` validates a
raw ext4 image: regular file, the superblock magic, a sane block size, a block
count that fits, and a file at least as long as the filesystem; qcow2 and an
MBR boot signature are named as such. It reads only the superblock, writes a
sidecar with `imported: true` and the canonical path, and leaves the file where
it is. `export` runs `qemu-img convert -p -f raw -O raw|qcow2 [-c]` (the source
format is explicit, so the guest's bytes are never probed) into a temporary
file beside the destination, then renames it with mode 0600; it refuses the
image itself, checks free space and can be cancelled.

**Interface.** The entries list is the Current disk row, **Dump disk**,
**Import image…** and the dumps (record filter `disk-dump-history` over the
query engine, context menus). The list is scanned when the recording folders,
a job's presence or `kept_as` change and on Refresh, never per frame. Whether
an imported image moved is checked in the same scan. Verify and Save run on
their own threads and are polled. Settings: `disks.{dump_hash, source_digests}`.

### Checkpoint sources, partitions, diff, content search, qcow2 import (phase 3)

**Sources (`DiskSourceSpec`).** `MeasureDisk`, `OpenCurrentDisk` and `DumpDisk`
carry a source: `Current` (`snapshots::active_disk`), `Checkpoint(id)`
(`snapshots::checkpoint_disk`: the saved, not deleted node's frozen layer,
through the same `owned()` validation and the same "no unfinished snapshot
operation" check, then `validate_disk` of that layer's whole chain against the
pinned base) or `Base` (the VM's pinned `bundle.json` base). They differ only
in the file `qemu-img` starts from, so measure, convert, lease, scratch
folders, Keep as dump and the VM-off rule are the same code. The record
(`DiskSourceKind::{Current, Imported, Checkpoint{id,name}, Base}`) lands in the
view and in `dump.json`; older sidecars read as before. The UI lists the
checkpoints of `Snapshot.vm_snapshot_trees` (which the backend fills at start
and after every snapshot change).

**Partitions (`disks/partition.rs`).** The measure step reads the first 64 KiB
of the guest disk (`qemu-img convert --image-opts` of the byte range, which
always writes its full length) and `partition::parse` decides: an ext
superblock at 1024 means a whole-disk filesystem (the Antinomie bases, no
table); a boot signature with a protective-MBR entry means GPT (header at LBA 1,
at most 128 entries of 128 to 256 bytes inside the probed window; entries whose
range is reversed, outside the usable range or outside the disk are dropped
and counted); otherwise an MBR (four primary entries; an extended entry is
listed as such, its logical partitions are not read). The filesystem of the
first 16 partitions is read (the 512 bytes at partition start + 1024). The
default partition is the GPT Linux root (x86-64 or arm64) that holds ext4, else
the largest ext4 one. The estimate is `qemu-img map --image-opts` over the same
carve, and the conversion is `qemu-img convert --image-opts
driver=raw,offset=…,size=…,file.driver=qcow2,file.file.filename=…` (commas of
the file name doubled), verified against `dd`. A partition that is not ext2/3/4
(or a table with no ext4 partition) is `DiskMeasure::unsupported()`: Open and
Dump are refused with the "unsupported filesystem" sentence. `SaveDiskPartition`
carves any partition to a host file (written as a hidden `.part` beside it,
synced, size-checked, renamed).

**Reference image and diff.** `OpenDiskReference` flattens a source into a
second scratch image beside the open view (`Snapshot.disk_reference`; a new
scratch image does not sweep the view's folder); it is closed with the view, on
the same triggers, and shares the one job slot and the VM-off rule. The UI
reuses an existing reference of the same source. The diff itself is a request of
the sandboxed reader: a reader started with a second image mounted read-only at
`/other` (the "before"; `/image` is the "after") answers `Diff` (`reader/diff.rs`).
Both trees are walked together by name; an entry in one tree only is added or
deleted and its whole subtree with it; kinds that differ are a change of type
and each side's subtree is added or deleted; directories are changed only by
kind, mode or owner; files by size, mode, owner, modification time or link
target, and when only the time differs (equal size) the bytes are compared up
to 64 MiB to tell `Content` from `Time`. Equal metadata means equal: a guest
that sets a file's time back after editing it is not seen (the Triage evidence
or a hash comparison of dumps covers that). A rename is a deletion plus an
addition. Bounds: 20,000 listed entries (totals keep counting), 2,000,000
entries over both trees, 120 s, depth 64, 65,536 entries per directory;
cancelling kills the reader. The UI keeps the results, filters them in a cached
index list (recomputed when the filter or results change) and draws only the
viewport's rows.

**Triage links.** Triage keeps the absolute guest paths of the selected run's
Changed files (`TriageView::changed_paths`, rebuilt when its index is). A diff
row whose path is in the set is marked and its Details offer **Show in Triage ›
Changed files**, which opens the Files section's Changed files tab filtered to
`file.path == "…"`. The diff publishes its non-directory paths through egui's
data store; Triage's Details of a Changed file show a link back that asks the
Disks tab to select the path. Both say what kind of evidence they are (block
evidence versus syscall evidence), never that one confirms the other.

**Content search.** `FindMode::Content` / `ContentAnyCase` (ASCII letters in any
case) in the reader's `Find`: regular files only, never through links, the first
16 MiB of each file, 512 MiB read in all, 60 s, a needle of 2 to 256 bytes, one
hit per file with its offset and a snippet in which every non-printable byte is
a dot. The answer counts files read, bytes read and files read only in part, and
says whether the byte limit or the time ended it. Cancel kills the search reader
(the tree's reader is not touched) and a new one starts with the next search.

**qcow2 import (`disks/job/import.rs`, `disks/sandbox.rs`).** A qcow2 image has
attacker-controlled metadata, so `qemu-img` runs only as `bwrap` (the shared
`sandbox_profile`: every namespace unshared, `/usr` read-only, a private
`/etc/passwd`, a 64 MiB `/tmp`) with the file `--ro-bind` at `/input`, one writable
folder at `/out`, `--remount-ro /`, and `prlimit --as=8 GiB --nofile=64
--core=0`; `qemu-img` must be under `/usr`. Steps: `info --output=json` (refused:
not qcow2, a `backing-filename`, an external `data-file`, encryption, a virtual
size over 2 TiB or none), a free-space check, `convert -f qcow2 -O raw` to a
temporary raw disk (the conversion is watched: the output's allocation may not
pass the free space left, which stops a compressed image that expands), a
partition probe of the raw disk and, for a partitioned image, a second sandboxed
conversion that carves the default ext4 partition, then the same checks as any
dump (size, ext4 magic and state), optional hash, and `dump.json` with
`source.kind = imported`. Even without the pre-check the sandbox cannot see a
backing file outside the image: the host path does not exist in it. The import
job does not hold the VM's chain (`Job::holds_chain` is false), so the VM can run
meanwhile, but it takes the one job slot.

**Reader sandbox.** `disks/reader/client.rs` builds its command line from
`sandbox_profile::apply` (with a private one-line account file from
`disks/sandbox.rs`) and adds only `/worker`, `/image`, `/other` (a diff) and
`/out`, then `prlimit --as=2147483648 --nofile=64 --core=0`.

**Commands.** `MeasureDisk`, `OpenCurrentDisk`, `DumpDisk` (+ `source`,
`partition`), `OpenDiskReference`, `CloseDiskReference`, `SaveDiskPartition`,
`ImportQcow2Disk`; `Snapshot.disk_reference`. `DiskJobPurpose` gains
`Reference`, `Carve` and `Import`. Settings are unchanged.

## MemNixFS beside Volatility (0.7.1)

MemNixFS 1.2 (<https://github.com/MemNixFS/MemNixFS>, Apache-2.0) is a second
backend of the Memory tab for Linux dumps. `memory/memnixfs/` holds it;
`PluginRun` gains `analyzer` (omitted for Volatility, so saved runs read as
before), `tool_version`, `dump_format` and `partial` (reasons a finished
result is known to miss something). A report run is saved as a plugin run
(`run.json`, `output.jsonl`, `log.txt`, `files/`) under the dump's `runs/`, so
the table, filters, Messages, Files and run list work unchanged, and the run
names the dump by `dump_id` (the dump file is never copied or altered).

**Package.** `analysis_tools::PACKAGES` pins the upstream
`MemNixFS-1.2-Linux.tar.gz` release asset by SHA-256 (the Linux build is
dynamic and links the system's libyara, libsnappy, liblzma, libmagic, jansson
and libcrypto). It also needs `libfmt.so.9` and `libfuse3.so.3`, which newer
distributions no longer ship; those two libraries come from the pinned Debian
12 `libfmt9` and `libfuse3-3` packages into `lib/` beside the tool and are
found through `LD_LIBRARY_PATH`. Only Antinomie's pinned install is used (no
system copy). `MemNixFs::locate` runs `--help` once and turns a loader error
into the Debian package that fixes it.

**What it is given.** `format::classify` reads the header only. AVML, LiME,
raw (headerless: the run is marked partial because addresses are assumed to
start at 0) and ELF64 x86-64 cores whose segments carry physical addresses or a
`QEMU` or `VMCOREINFO` note are accepted; a core whose segments all have a zero
physical address is a process core and is refused, as are Windows dumps, ELF
programs, other architectures, unfinished dumps and a dump file that is gone.

**Sandbox.** The shared bubblewrap profile of the other tools
(`run_sandboxed_sized`): no network, the dump and the saved
`symbols/linux/symbols.json.xz` mounted read-only, the managed tools folder
read-only, a private writable folder, `HOME=/tmp`, `--no-http-cache` (no symbol
mirror lookup; `--auto-fetch` is never passed), `prlimit` with an address space
of the dump size plus 6 GiB (at least 8 GiB), 45 minutes at most. A report is
one `memnixfs export PATH DIR`; the dump is read once per run.

**Partial and unavailable.** Stated, not hidden: known warnings of the tool
(unvalidated page-table root, symbol table not matching the banner, unreadable
modules list or mount namespaces) and up to four other `[WRN]` lines become
`partial` notes, with one for a dump without a saved symbol table (the tool
rebuilds one from the kernel's BTF), one for a headerless dump and one for rows
cut at 500,000. A report the tool did not write fails the run with a message
saying so; an error line of the tool becomes the run's error.

**False banner mismatch.** MemNixFS takes a table's kernel release from the
dwarf2json metadata name or the file name (`vmlinux`, `symbols.json.xz`), not
from `linux_banner`, so it logs `ISF/dump MISMATCH` for every base table even
though the offsets are right. When the log has that line, `memnixfs/banner.rs`
reads `linux_banner` from the table (xz JSON, base64 `constant_data`) and
searches the dump for that exact text; if it is there, the note is dropped. An
unreadable table or a different banner keeps the note.

**Check.** `cargo run --release --example memnixfs-check DATA RECORDING DUMP
[SYMBOLS.xz] REPORT...` runs reports on a real dump. On a 2.0 GiB QEMU dump
with the base's dwarf2json table (5 PT_LOAD ranges, no VMCOREINFO) it produced
92 processes, 23 triage lines, the memory ranges and 22 recovered files in 50
to 135 s, with partial notes (the DTB scan found no match; the table names
its kernel `vmlinux`, so the tool reports a banner mismatch that the host
then checks against the table's own banner); processes and
page-cache files were still recovered. Unit tests use a fake `memnixfs`
script and generated headers; no dump is stored in the repository.

## Recording quota and pre-acknowledgement telemetry (0.6.2)

The recording quota (Settings, 4 GiB by default) bounds what one VM boot may
save: raw telemetry, assembled objects, terminal journals and screens, analysis
metadata, cores and network captures. The limit is read when the VM starts.

**Reaching the quota** is a boot-wide, permanent condition that stops *new*
data; it never rewrites what is already complete.

| Recording | State when the quota is reached |
| --- | --- |
| Run whose program tree ended and whose terminal is closed | Untouched: no `recording_error`, finalizes normally. A packet of such a run that still arrives is counted and noted once in the run's `notes`. |
| Run still open | Stops saving telemetry, objects and terminal output, keeps everything saved so far, `recording_error` is the quota message. |
| Capture still open | Same as an open run. |
| Closed capture archive | Untouched. |
| Boot unassigned archive | Stops growing; `health.persistence_error` is the quota message. |
| Run or capture started after the quota was reached | Born stopped with the quota message. |

The message names the limit and says that everything saved before is intact.
The frontend reads it in `health.persistence_error`; `storage_dropped_packets`
counts the packets that were not saved. A quota failure of one terminal write
is the same event: it stops every open recording, not only that run. Any other
terminal write failure stops saving for that run only, and the run's first
recorded cause stays the reported one. Raising the quota applies to the next
VM start; a running boot is not resumed.

**One copy of a packet nobody owns.** While a capture that can still save
observes a packet no run owns, that capture's archive is the packet's only
raw copy; the boot's unassigned raw archive skips it. Run-owned packets are
still written to the run archive and, under Capture All, to the capture
archive, because each archive must be readable on its own; the capture's
object store also keeps its own objects. Capture All therefore still costs up
to twice the run's own telemetry while a run is active.

**Pre-acknowledgement buffer.** Telemetry of a launched program can arrive
before the reply to its EXEC command. Such packets wait in a buffer keyed by
root cookie until the reply claims them.

| Rule | Value |
| --- | --- |
| Per-cookie size | 16 MiB (`PreAckLimits::cookie_size`) |
| Size for all cookies | 32 MiB (`PreAckLimits::total_size`) |
| Age limit | 5 s (`PreAckLimits::max_age`); older packets are dropped, except while a launch waits for its reply (below) |
| Cookies tracked | 64; the one quiet longest is forgotten first |
| Never buffered | Cookie 0 and the app's own resource collector |
| On claim | The cookie's entry is removed, so an overflow never outlives it |

A cookie that overflows or ages out only counts its own loss. When that cookie
is claimed the loss becomes an entry in the run's `notes` (a field separate
from `recording_error`, which gates terminal journaling); the lost packets
remain in the boot's raw archives. A cookie nobody claims disappears.

The age limit counts time the host could answer in, not time a packet waited
(0.8.0, ANT-T0203). From the moment an EXEC is sent until the launch command
ends, packets that arrived since the send do not age (they are bounded by size
only), and a claim never ages the cookie it claims. Before this, a Gafgyt run
on a busy host lost its first 1,537 packets (1.1 MB, the root's execve among
them): the transport thread was held for 42.8 s between the reply and the
claim (a custody-log commit that synced the disk), and the claim's own expiry
pass dropped every packet older than 5 s.

### Reduced recording near a full quota (0.8.2)

The boot's quota (raw capture, assembler, run archives and PCAP share it) used to stop
all saving when full. Now the last tenth is a reserve (`monitor-core/src/reduced.rs`,
`backend/reduced.rs`).

* **Switch.** `Session::reduce_packet`, in the pump loop before saving, switches the
  boot to reduced mode when `stored_len + packet` reaches 90 % of the quota
  (`RESERVE_DIVISOR` 10). The switch is boot-wide; each run going on records it in
  `run.json` as `reduced` (`at_ms`, `at_guest_ns`, `quota_bytes`, `used_bytes`,
  `kept_packets`, `dropped_packets`, `dropped_calls` per system call, and when they
  happened `full_at_ms` and `network_stopped_ms`). Older runs without it load (serde default).
* **Verdict.** A packet is dropped only when it is a phase 1 or 2 event of a
  native-ABI call whose system call is not on the kept list. Lifecycle (phase 3) events,
  other record types, other ABIs and unknown numbers are always kept. One drop is
  counted per call, at its entry. A dropped packet's sequence number is not telemetry
  loss: it is counted as received.
* **Kept list.** Derived in one place in the UI, `triage/rules/calls.rs`: lifecycle plus
  the calls each Triage rule group matches, minus a documented bulk set (read, write,
  stat, getdents, clock, poll), handed to the backend as
  `BackendOptions.reduced_keep_calls`; empty keeps the old behaviour.
* **Network.** The PCAP keeps running past the switch until half of the reserve is left,
  so calls keep the other half (`network_stopped_ms` records when the capture was
  stopped). The quota stays the hard ceiling: when it is full saving stops as before and
  `run.json` records `full_at_ms`.
* **Report.** Triage, Run History's tooltip and the HTML/PDF report show
  `reduced_text.rs`'s message as information. A finished run's report note reads "The run
  has ended. What this report may be missing: ..." instead of saying the recording was
  still being written.

## Recording disk work off the transport thread (0.6.2)

The thread that drains telemetry and serves commands never waits for the
disk. When the recording writer falls behind, it stops taking telemetry
instead (the guest waits for room; trace follow-ups, 0.7.0). Run, Upload, Stop and snapshots are answered while a recording saturates
the disk.

| Write | Where it happens | Durability |
| --- | --- | --- |
| Small JSON publications (`artifacts.json`, capture summaries, process lists) | A bounded queue drained by one writer thread (`storage/json_queue.rs`) | Published within the disk's latency, not when the call returns. A later value of a path replaces a pending earlier one and is never overwritten by it; a direct write to the same path waits for the queued one first. Queued values are capped at 8 MiB and the queue at 64 MiB / 4,096 paths; direct writes have no cap. |
| Raw packets and object chunks | The recording writer thread (`writer.rs`) | Ordered per archive; payload before the index records that name it. |
| A library sample's custody-log entries for a run (start, typing, actions, end), and the record that a sample was sent into a VM (Upload, Run sample) | One custody writer thread (`samples/runlog.rs`, a queue of 4,096 entries; `record_push_later` keeps the time of the send) | Written in the order they were made; the commit syncs the disk, which on a busy disk held the transport thread for seconds (5.4 s and 42.8 s in the 2026-11 evaluation). Best effort as before: a full queue drops the entry like a refused write, and the Samples page's Verify shows what is missing. The app waits for the queue when it closes. |
| Durability of a stopped boot (fsync of archives, final manifest) | One bounded background flush worker (`recording_flush.rs`) | Done after the guest is told to stop; the boot manifest is written after the archives it lists. |

**Object packs.** Captured buffers of an archive are stored in append-only
segment files `objects/objects-NNNNNN.seg` with an append-only index
`objects/objects.idx`, instead of one file per buffer. A field keeps its
`stream-task-call-phase-seq-object.raw` name; readers look for that file first
(archives made before packing) and otherwise resolve it through the index.
Identical chunks within an archive are stored once. Quota counts the segment
and index bytes actually written.

**Terminal output.** One worker pass reads a run's terminal until it is
empty, up to 4 MiB or 40 ms per run, instead of a single 4 KiB read, so a
chatty program is not throttled to the pass rate.

**Stop.** Guest shutdown is requested before the host makes the recordings
durable, so host disk work does not use up the guest's shutdown time. A
graphical guest gets at least 30 s to shut down (`shutdown_timeout` applies
as configured to console guests) before the VM is forced off.

## Accepted manual cores and performance Summary (0.6.0)

A real Dump core action beside Dump memory and inside Core dumps pauses,
captures and resumes a selected live process. Use validated guest
boot/task/start/TGID identity, a nonfatal bounded guest rendezvous and native ELF
notes, with truthful unavailable memory and independent repeated host captures.
Do not use the exit-core rendezvous, kill the target, replay uncertain acquisition
or add a guest helper. The revision-16 extension retains ABI9 and ordinary
revision-15 exit captures; the manual-core section defines its accepted wire and lifecycle.

Summary uses native performance charts/meters with measured QEMU/host values,
per-VM identity, bounded sample history and explicit unknown states. Guest RAM
utilization remains unavailable. Run program gains title dragging while preserving
its initial viewport-limited size and final actions. Other debugger features and
release/base publication remain separate.

## Accepted process core and VM Summary update (0.6.0)

0.6.0 adds guest process-core-on-exit acquisition and a native
Summary tab immediately before Run History, showing VM status, health and
resources. A live debugger and other unscheduled features are outside this update.
Opt-in core acquisition targets the launched root thread group on native x86-64,
before normal/fatal exit releases its address space. Reuse Linux ELF core notes
and its memory filtering; bound retained guest buffers and host transfers, expose
partial/unavailable results, preserve original exit status and old-base launches.
Acquisition requires guest revision 15; revision-14 snapshot ABI9 is unchanged.
Host timelines never replay acquisition effects across snapshot recovery.

Summary uses owned backend snapshots and per-VM identity guards. Configured guest
vCPU/RAM/disk capacities are separate from QEMU host CPU/resident memory and
available data-volume space. Missing measurements remain unavailable. Existing
layouts gain Summary before Run History without losing custom windows.

A UI follow-up aligns Core dumps with Memory: a resizable capture
list on the left, selected evidence and analysis tabs on the right, and a separate
import dialog. Waiting/unfinished entries, names/tags and lazy inspection remain
available. This changes presentation only; core acquisition/recovery is unchanged.
