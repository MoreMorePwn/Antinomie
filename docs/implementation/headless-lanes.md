# Implementation record: Headless lanes

The lane state file, the engine seam, the recovery of a lane after a crash, and the lane stages `prechecks` to `launch`. Host only; part of the headless mode in `antinomie-service` (`crates/service/src/{engine,lane,stages}/`). The stages `run` and `collect`, retries and the watchdog come in the next card. Part of the [implementation record](../implementation.md).

### The engine seam

`antinomie_service::engine::Engine` is the trait the waiter, the lane stages and recovery talk to: `send(Command) -> id`, `recv(timeout) -> Option<Notification>` (an `Err` means the engine is gone) and `shutdown()`. `Backend` implements it by forwarding. `FakeEngine` implements it for tests and needs no VM or KVM.

* A **script** is a list of steps per command name (`fake.on("Start").after(5 s).then(1 s, edit).ok("running")`). A step replies with success, failure, silence, a send error, or a death of the engine, and can change the `Snapshot` at later times. An unscripted command fails by name, so a test that forgot a step does not pass by luck. `fake.after(delay, edit)` changes the snapshot with no command behind it.
* **Time** is a `ManualClock`. A receive with nothing due moves the clock by the timeout; one with a later item inside the timeout moves it to that item. A 30 minute layer wait costs no real time.
* A **trace** (`engine::trace::replay`) builds the script from a P0-1 spike recording (`tests/fixtures/auto-cycle/*.trace.jsonl`): for each recorded command, its result with the recorded delay and the snapshot digests that followed with theirs. A trace keeps only the digest of a snapshot (state, active VM, boot id, guest kernel present, `last_error`, recording flush counters), so runs, terminal bytes and disk layers are added with scripted steps.

### The lane state file

`<data>/service/lanes/lane-N.json`, mode 0600 in a 0700 directory. One lane per file. It is **not** the truth about the engine: recovery reads it together with the engine's `Snapshot`.

```json
{
  "version": 1,
  "lane": "lane-1",
  "vm_id": "auto-1",
  "clean_snapshot_id": "e992dd29237bd295294d94c54f377d94",
  "base_identity": "busybox-r21",
  "created_ms": 1794000000000,
  "quarantine": { "reason": "lane_changed", "detail": "…", "since_ms": 1794000000000 },
  "failures": 0,
  "current": { "job_id": "j_…", "attempt": 1, "stage": "run", "checkpoint": "started", "updated_ms": 0 },
  "collected": [ { "job_id": "j_…", "attempt": 1, "collected_ms": 0 } ],
  "qemu": { "pid": 4242, "start_ticks": 123456, "marker": "auto-1", "recorded_ms": 0 },
  "updated_ms": 0
}
```

| Field | Meaning |
|---|---|
| `version` | `1`. A file with a higher version is refused and never rewritten. |
| `vm_id`, `clean_snapshot_id`, `base_identity`, `created_ms` | Set by `auto init`. A snapshot id that is no longer among the VM's snapshots means the VM was used by hand: `lane_changed`. |
| `quarantine` | Absent when the lane takes jobs. `reason` is `revert_failed`, `lane_changed`, `vm_start_failed` or `guest_unreachable`. The first reason is kept. |
| `failures` | Consecutive `vm_start_failed` / `guest_unreachable`. The third quarantines. A success resets it. A crash of the service does not count. |
| `current` | The job the lane is on (from `provision` to `collect`) and the last checkpoint: `started` is written before a stage's first engine command, `finished` after its exit condition held. Absent when the lane is free. |
| `collected` | Jobs whose `collect` finished (VM stopped, recording final, layer settled). The entry stays until the job's `analyse` begins, so a crash in between resumes at `analyse`. |
| `qemu` | The VM's QEMU process as recorded at start. `marker` is a text its command line must contain (the VM id); `start_ticks` is field 22 of `/proc/<pid>/stat`. |

Unknown fields are an error. A file that is empty, truncated, not an object, without a version, of another lane, or with a field of the wrong type is *damaged*: it is left as it is and that lane takes no job until a person looks.

**Writes are atomic.** The new content goes to `.lane-N.json.<pid>.<n>.tmp` in the same directory (created exclusively, 0600), is synced, renamed over the old file, and the directory is synced. A process killed at any point leaves the old file or the new one. A leftover temporary file is ignored by readers and deleted at the next start.

### Recovery at start

`lane::recover_startup(store, lanes, waiter, processes, options)`, after the engine started and its first snapshot arrived:

1. Sweep temporary lane files, read every lane file.
2. A `collected` job whose store row is still `running` at or after `collect`, in the attempt that collected, is **kept**: `Store::recover_keeping` leaves it `running` and it resumes at `analyse`. Any other `collected` entry is dropped.
3. The store recovers every other `running` job as a new attempt (`guest_lost`, reason `service_restart`; the first restart of a job is free, a second counts), and `cancelling` jobs as before.
4. For each lane:
   * A recorded QEMU pid is ended **only if** `/proc/<pid>/cmdline` has a `qemu-system*` program whose arguments contain `marker`, and the start time still equals `start_ticks`. A pid that is gone is forgotten; a pid that belongs to something else is left alone. A QEMU that matches and will not end quarantines the lane (`lane_changed`) and keeps the record, so the next start tries again.
   * A VM the engine reports as not stopped is stopped and its recording settled (`stop_wait`, default 120 s).
   * A pending disk layer or recording flush of the lane VM is waited for (`layer_wait`, default 1800 s). If it is still pending, the report says so; the lane is not quarantined, and `provision` waits (`waiting_for: layer_pending`).
   * The clean snapshot is looked up. Missing while the VM's snapshots are listed: quarantine `lane_changed`, one `lane.state` (`quarantined`) and one `engine.alert` (`lane_quarantined`), stored once. A VM with no snapshot list, or no VM at all, is reported as a problem without quarantine.
   * The lane file is written without `current` and without a dead `qemu`.

Recovery never starts a VM or a stage, and it is safe to run twice. Engine failure during recovery is an error; the lane file is not rewritten then, and the next start repeats the lane steps.

`lane::check_lane(file, snapshot)` lists what keeps a lane from taking a job (quarantined, no VM, snapshot missing, VM not stopped, layer pending). `prechecks`, recovery and `auto lane unquarantine` use it.

### The stages `prechecks` to `launch`

`stages::LaneStages` holds the engine waiter, the store, the lane files, the policy lookup, a `Processes` seam and a `HostChecks` seam, and has one method per stage. A stage returns what the next one needs or a `StageStop`: `Failed(Failure)` (the code of design 4.1; the job's retry or end belongs to the next card), `Wait` (not a failure: the job is `queued` with `waiting_for`), `Cancelled`, or `Abort` (a signal or a dead engine). `run_to_launch(job)` runs the five with the store's stage records and the lane file's checkpoints (`started` before a stage's first engine command, `finished` after its exit condition).

| Stage | What it does | Failure codes |
|---|---|---|
| `prechecks` | The frozen policy still exists and still allows the client; `HostChecks` (resources, dependencies, KVM; the real probes are a later card); the lane has a file, is not quarantined or busy, its VM is stopped; the clean snapshot id is still among the VM's snapshots. A pending disk layer does not stop it: `provision` waits | `policy_denied`, `host_resources`, `dependency_missing`, `no_vm`, `lane_changed` (quarantines the lane when the VM's snapshots are listed and the id is gone). Waits: `resources`, `dependency`, `lane`, `lane_quarantined` |
| `provision` | Wait for the previous layer (`layer_s` 1800 s), stop a VM still running, revert, wait for the guest (`boot_s` 180 s), check the guest revision (a core dump needs 15), find the VM's QEMU and record it in the lane file | `revert_failed` (quarantine after one retry; never a `Reset` fallback on a snapshot lane), `vm_start_failed`, `guest_unreachable` (three in a row quarantine), `dependency_missing` |
| `upload` | `UploadSample` to `<guest_dir>/<sha8>-<name>`; "read-only file system" is retried inside `upload_s` (60 s plus 1 s per 10 MiB); the byte count in the reply must equal the sample's size | `upload_failed`, `internal` (engine silent for 60 s) |
| `launch` | `Execute` with the request of `stages::plan::effective` (audit G7), then the new run in the snapshot (`launch_s` 30 s); the job gets `run`, `recording` and the `job.run` event | `launch_failed`, `internal` |

Revert by policy `vm.revert`: `snapshot_disk` is `RestoreVmSnapshot { boot_from_disk: true, confirmed: true, save_current: None, switch_profile: false }` alone, because a Disk restore starts the VM itself (a `Start` after it fails "only one VM may run at a time"; spike ANT-T0345). `snapshot_full` is the same with `boot_from_disk: false`, which resumes the running guest. `reset` is `Reset { confirmed: true }` then `Start`.

**The launch request.** `path` is the guest path; `args` and `env` come from the spec (a default `PATH` is added when the spec has none, as `run exec` does); `cwd` is the policy's `run.guest_dir`; `uid`/`gid` 1000 for a user run, 0 for root, or the ids given; guest-side analysis disabled; `run_in` from the spec or the policy; `capture_network`, `memory_dump_on_exit`, `core_dump_on_exit` with `core_max_size` (policy `core_max_mib` in bytes) and `core_timeout_ms` (5000 unless the spec gives one); `debug_on_start` false; `route` set; `host_copy` none; `sample` set, so the run is linked to the library sample. `ExecRequest::validate` refuses a core dump in a desktop run: `launch_failed` before the engine is asked.

**Finding the QEMU process.** The engine exposes no pid. After the guest answers, `provision` scans `/proc` for `qemu-system*` processes whose command line holds the VM's folder (from the snapshot's `vm_locations`, else the VM id). Exactly one match is recorded in the lane file (`pid`, `start_ticks`, `marker`); any other count is a `qemu_pid_unknown` job warning and the record is cleared. `lane::clear_for_reset` is the bookkeeping of `auto lane reset`: it clears `failures` and `qemu` only after the recorded QEMU is confirmed gone with the test recovery uses.
