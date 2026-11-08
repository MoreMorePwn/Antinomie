# Implementation record: Headless lanes

The lane state file, the engine seam and the recovery of a lane after a crash. Host only; part of the headless mode in `antinomie-service` (`crates/service/src/{engine,lane}/`). The stages that use these (`prechecks` to `collect`) come in later cards. Part of the [implementation record](../implementation.md).

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
