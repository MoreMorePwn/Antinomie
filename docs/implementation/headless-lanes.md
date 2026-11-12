# Implementation record: Headless lanes

The lane state file, the engine seam, the recovery of a lane after a crash, and the lane stages `prechecks` to `launch`. Host only; part of the headless mode in `antinomie-service` (`crates/service/src/{engine,lane,stages}/`). The stages `run` and `collect`, cancellation, retries, quarantine and the watchdog close the lane cycle (crates `antinomie-service`, `stages/{run,collect,cleanup,drive,retry}.rs`, `watchdog.rs`). The host stages `analyse`, `report` and `cleanup` follow, then the daemon that runs them (`daemon/`) and its local socket (`server/`). Part of the [implementation record](../implementation.md).

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
| `upload` | `UploadSample` to `<guest_dir>/<sha8>-<name>`; "read-only file system" and "no such file or directory" (a guest resumed in its initramfs, ANT-T0472; the engine retries the latter only for a guest it booted) are retried inside `upload_s` (60 s plus 1 s per 10 MiB); the byte count in the reply must equal the sample's size | `upload_failed`, `internal` (engine silent for 60 s) |
| `launch` | First the console of the running boot (`Snapshot::serial_log`) is read: a guest kernel that crashed while the VM booted (a kernel `BUG`, an oops, a panic, or "Guest filesystem resize failed"; such a guest still answers, ANT-T0476) is not given the program. Then `Execute` with the request of `stages::plan::effective` (audit G7), then the new run in the snapshot (`launch_s` 30 s); the job gets `run`, `recording` and the `job.run` event | `guest_unreachable` (the crash line as detail; retried, and three in a row quarantine the lane), `launch_failed`, `internal` |

Revert by policy `vm.revert`: `snapshot_disk` is `RestoreVmSnapshot { boot_from_disk: true, confirmed: true, save_current: None, switch_profile: false }` alone, because a Disk restore starts the VM itself (a `Start` after it fails "only one VM may run at a time"; spike ANT-T0345). `snapshot_full` is the same with `boot_from_disk: false`, which resumes the running guest. `reset` is `Reset { confirmed: true }` then `Start`.

**The launch request.** `path` is the guest path; `args` and `env` come from the spec (a default `PATH` is added when the spec has none, as `run exec` does); `cwd` is the policy's `run.guest_dir`; `uid`/`gid` 1000 for a user run, 0 for root, or the ids given; guest-side analysis disabled; `run_in` from the spec or the policy; `capture_network`, `memory_dump_on_exit`, `core_dump_on_exit` with `core_max_size` (policy `core_max_mib` in bytes) and `core_timeout_ms` (5000 unless the spec gives one); `debug_on_start` false; `route` set; `host_copy` none; `sample` set, so the run is linked to the library sample. `ExecRequest::validate` refuses a core dump in a desktop run: `launch_failed` before the engine is asked.

**Finding the QEMU process.** The engine exposes no pid. After the guest answers, `provision` scans `/proc` for `qemu-system*` processes whose command line holds the VM's folder (from the snapshot's `vm_locations`, else the VM id). Exactly one match is recorded in the lane file (`pid`, `start_ticks`, `marker`); any other count is a `qemu_pid_unknown` job warning and the record is cleared. `lane::clear_for_reset` is the bookkeeping of `auto lane reset`: it clears `failures` and `qemu` only after the recorded QEMU is confirmed gone with the test recovery uses.

### The stages `run` and `collect`

| Stage | What it does | Failure codes |
|---|---|---|
| `run` | Reads the run's state and terminal every 200 ms. The run ends when its state is `Finished`, `Stopped`, `TerminalClosed` or `Finalized` and no task is live. At the run limit (`run_s`, the spec's `timeout_s`) it sends `StopRun` once; the run then ends with `end_reason = time_limit` and **the job is not failed**. A run still going 120 s after `StopRun` is lost | `launch_failed` (`FailedToStart`, `LaunchUnconfirmed`), `guest_lost` (`Interrupted`, a run that vanished, a VM that stopped or failed under the program, no end after `StopRun`), `internal` (60 s with nothing from the engine) |
| `collect` | Waits until network, memory and core evidence are no longer being written (`collect_s` 300 s), then `Stop` (answered within `stop_s` 120 s), then waits until the VM is stopped, the recording flush is over and the VM has no pending disk layer (`layer_s` 1800 s). Only then does the lane write `collected` and become free | `recording_failed` (evidence not complete in time, an unreadable `artifacts.json`, an unanswered `Stop`, a layer that does not settle), `guest_lost` (the VM failed meanwhile). Evidence left `Partial`, `Interrupted` or `Failed` is not a failure: the job outcome is `partial` with a warning each. A guest kernel crash on the console during the run (the sample's doing, or not) is the warning `guest_kernel_crashed` |

The run record of the job (`job.run`) gets `ended_ms`, `end_reason` (`exited`, `signaled`, `time_limit`, `stopped`, `guest_lost`), the exit code or the signal and the core flag from the root task's wait status; the recording phase goes `live`, `finalizing` (run over), `complete` (settled) or `interrupted` (the guest was lost).

**The lane file at `collect`.** `collect started` is a normal checkpoint. The end of `collect` is **one** write that moves the work into `collected` (and clears the QEMU record), instead of a `collect finished` checkpoint, so a crash leaves either "collect started" (recovery makes a new attempt) or "collected" (the job resumes at `analyse`), never both. The store's `stage` row is closed after that write; a crash between the two is the "collected" case.

### Driving a job: `LaneStages::drive`

`drive(job)` runs `prechecks` to `collect` with the store's stage records and the lane checkpoints, and ends or requeues the job:

| The cycle ends with | The lane | The job |
|---|---|---|
| `collect` finished | `collected` entry, free | stays `running`; `LaneStages::host` runs `analyse`, `report` and `cleanup` and ends it (`finish_collected` is the shortcut that skips them) |
| a failure the policy retries | VM stopped and settled, work ended, QEMU record cleared | `queued` with `waiting_for: backoff` and `job.requeued`; the failure is kept on the attempt |
| any other failure | the same | `failed` with the failure |
| a cancel | the same; the recording is kept | `cancelled` (back in the queue when the cancel is the daemon's shutdown) |
| the job limit (`job_hard_s`) | the same | `failed`, `internal`, detail `watchdog`; never retried |
| a wait from `prechecks` | untouched | `queued` with `waiting_for`; no attempt is used |
| a signal or a dead engine | untouched | untouched; recovery at the next start finishes it |

**Cancellation** is polled inside every wait of every stage: `drive` gives the waiter a cancel hook (a subscription to the store's `job.state` events) and a wait that sees the cancel ends with `WaitError::Cancelled` within one pump (100 to 200 ms). The run and collect stages turn that off and act on the cancel themselves: `run` sends `StopRun`, waits up to 120 s for the run to end and returns `Cancelled`; `collect` skips the rest of the evidence wait. In every case the cleanup then waits for any command that was given up (a restore the engine is still doing), stops the lane VM if it runs and waits for the recording and the layer, so the recording is kept and the VM is never left running. A cancel that arrives while the VM stops is honoured after the stop.

**Retry** (design 4.7.2, `stages/retry.rs`). A failure is retried when its code is in the policy's `retry_on` (default `vm_start_failed`, `guest_unreachable`, `upload_failed`, `guest_lost`) **and** it is not permanent **and** the job has an attempt left (`max_attempts`, the store decides). Permanent, whatever the policy lists: `sample_*`, `duplicate_denied`, `policy_denied`, `no_base`, `no_vm`, `revert_failed` (the lane is quarantined instead), `lane_changed`, `cancelled`, and the waits `quota_exceeded`, `dependency_missing`, `host_resources`. `launch_failed` is permanent (the desktop run with a core dump is refused before the engine is asked) unless the engine's words name a transient cause (`capacity`, `too many terminals`, `terminal limit`). `guest_lost` and `recording_failed` happen at most once per job: a sample that ends the guest twice is final and the job gets the warning `crashes_guest`. The wait before the next attempt is the policy's `backoff_s` (the n-th entry after the n-th failure, the last one repeated), plus or minus 20 percent from a hash of the job id and the attempt. Every attempt starts with a full revert. Each failed attempt is recorded with its code in the store (`attempts.failure_code`).

**Quarantine** (design 4.5.3) keeps the rules of the previous stages: `revert_failed` after one retry of the restore, `lane_changed` when the clean snapshot is gone, and `QUARANTINE_AFTER` (3) consecutive `vm_start_failed` or `guest_unreachable`; a boot that reaches the guest resets the count. A job that fails because of the third failure is still requeued (if the policy retries it) and then waits `queued` with `waiting_for: lane_quarantined` until `auto lane reset` or `unquarantine`.

**The watchdog** (`watchdog.rs`, design 4.7.1):

| Trigger | Rule | Result |
|---|---|---|
| the whole job | `job_hard_s` = run limit plus 1800 s from the start of `drive`, enforced through the waiter so it ends any wait | cleanup, `failed` (`internal`, `watchdog`) |
| the engine, during `run` | 60 s with nothing from it (the lane reads the terminal every 200 ms, so it answers all the time) | `internal`, then cleanup |
| a quiet `collect` | `stall_s` 120 s with nothing heard is a job warning (`collect_stalled`); twice that ends the wait | `recording_failed` |
| a stage | the deadlines of 4.1 (`boot_s` 180, a silence limit for the VM `Start` and for the revert's `RestoreVmSnapshot` under TCG: the engine's start note, "waiting for the guest to connect" (a Full resume: "Restoring the snapshot"), is progress, with a 30-minute hard bound; `upload_s`, `launch_s` 30, `collect_s` 300, `stop_s` 120, `layer_s` 1800) | the stage's failure code |
| a hung `Stop` | no answer in `stop_s`: the **hard path** kills the QEMU recorded in the lane file, only if its `/proc/<pid>/cmdline` and start time still match, and gives the engine 30 s to notice; the job gets the warning `vm_hard_stop` | `recording_failed`; if the cleanup's own `Stop` (asked twice) does not settle the VM either, the lane is quarantined (below) |

`FakeEngine` can run a callback at a point of its script (`StepBuilder::call`, `FakeEngine::call_after`), which the tests use to cancel a job or arm a lane-file fault at an exact moment.

**A stop that never settles.** The cleanup after a failed, cancelled or timed-out job asks for the VM to stop and settle. If the first answer is not "settled" (a `Stop` that was killed through the hard path, a flush or layer that does not clear), it asks once more. If that does not settle the VM either, the lane is **quarantined** with the reason `revert_failed` and the detail "the lane VM did not stop and settle after a forced stop": the next job's revert could not happen on a machine the engine still holds, and the lane waits for `auto lane reset`. `lane.state` (`quarantined`) and `engine.alert` (`lane_quarantined`) are sent, the QEMU record stays in the lane file, and queued jobs wait with `waiting_for: lane_quarantined`. (Design 4.5.3 lists four quarantine reasons; `revert_failed` is the closest.)

**The library tag `auto:crashes-guest`.** When a job ends `failed` with the warning `crashes_guest` (the sample ended the guest in two attempts), the service adds the custom tag `auto:crashes-guest` to the library sample through `Library::add_tag`, which keeps the other tags and writes the custody entry (`edited`, tags) under the actor `auto:policy-<policy name>` (`custody::automation_actor`), not `analyst`. A tag that cannot be written is the job warning `tag_failed`. Adding it twice writes nothing.

### The host stages: `LaneStages::host`

`drive` returns `Driven::Collected(end)` when the lane stages are over; `host(job, end)` then runs the host stages and ends the job. The lane is free, and the stages need no VM, so a daemon with a second waiter can run them beside the next job's lane stages (this card runs them on the waiter it is given). The Triage work is the crate `antinomie-triage`, the same builders the GUI and `antinomie-cli triage`, `detect` and `report` call, behind the seam `HostTriage` (`stages/host.rs`; the real one is `RealTriage`).

| Stage | What it does | Deadline | Failure |
|---|---|---|---|
| `analyse` | (1) `Command::AnalyzeSample` for the policy's checks on the library copy, then waits for the report: `static_s` = tools x `static_time_limit_min` x 60 + 60 (a limit of 0 assumes 5 minutes a tool). (2) On a worker thread: open the saved run read-only (`find_run_read_only`), index it (`SavedRun::scan`), run the policy's engines (`detection::detect_saved`, results kept in the recording as the Detection tab keeps them) and write the digest (`detection::save_digest`). (3) Build the summary and detections and store the **assessment** (`job.assessment`) through the verdict mapping | `analyse_s` 900 s for (2) and (3), a cancel flag the scan honours; the worker is always joined | `analysis_failed` if the policy requires `analyse` (`analysis.required_stages`, default yes); otherwise one warning per problem and the job ends `partial` |
| `report` | Builds the report for the policy's formats, bundle and defang choice (`report_export::build_report` and `write_built`) into `jobs/<id>/artifacts/`, renames the files to `report-<sha8>.<suffix>` and `report-<sha8>-bundle.zip`, hashes them and records them as artifacts (`job.artifact`). Skipped when no format and no bundle is asked for | `report_s` 300 s | `analysis_failed`, or a warning and `partial` when `report` is not required; with no Triage scan there is nothing to report |
| `cleanup` | Ends the job with the outcome the stages settled, releases the lane's `collected` entry, writes `jobs/<id>/job.json` | `cleanup_s` 60 s (never reached: nothing waits) | never fails the job |

Departures from 4.1: the assessment is built at the end of `analyse`, not in `report`, so a job that asks for no report still has its label; the report files carry the design's stable names, not the writer's `antinomie-report-<run8>-<time>`; `cleanup` only ends the job and writes `job.json` (retention, notifications and the `[results]` drop belong to the daemon cards); `job_hard_s` is not enforced in the host stages, only their own deadlines.

**Endings** (`Hosted`):

| The stages end with | The job |
|---|---|
| all worked | the outcome `collect` found (`succeeded`, or `partial` for incomplete evidence) |
| a problem in a stage the policy does not require | `partial`, one warning per problem (`analysis_failed`, `report_failed`, `detection_skipped`) |
| a failure in a required stage | `failed`, `analysis_failed`, stage `analyse` or `report` |
| a cancel | `cancelled`; the recording and the reports written so far are kept |
| a shutdown cancel | back in the queue (a new attempt: the VM runs again) |
| a signal or a dead engine | untouched; the lane file keeps the `collected` entry, and `resume_host` finishes the job |

`analysis_failed` is repeated in place (analyse and report only, no VM) when the policy lists it in `retry.retry_on`, up to `max_attempts` runs of the two stages, with no backoff and a `analysis_retry` warning each time. A stage that failed or was interrupted may be entered again in the same attempt (`Store::begin_stage` re-opens a `started` or `failed` row; a `finished` or `skipped` one is still a conflict).

**After a crash.** The `collected` entry stays in the lane file until the job is final, so `recover` lists the job in `resume` and keeps it `running`; `resume_host(job)` runs the stages again from `analyse`. The outcome `collect` found is read again from the run's `artifacts.json`; its warnings are already in the job. A digest or an assessment written before the crash is simply written again.

### The verdict (`verdict/`)

The assessment is the Triage summary and the detections plus a label, a score and the `basis` sentence. The default mapping is the table of design 4.9.2 (first match wins): the run did not complete (`end_reason` not `exited`, `signaled` or `time_limit`) or Triage did not run: `inconclusive`; matched indicators with a named family, a high or critical YARA hit, or matched indicators: `malicious`; highest tier `high` or the assessment `suspicious_behaviour`: `suspicious`; `observed_only` or `no_findings`: `clean_observed` (the basis says that this is not "clean"). The default sets no score. With no indicator dataset loaded, the basis says that indicators were not checked.

A policy may give its own rules instead: `[[verdict.rule]] when = "..." label = "..." score = 70`. The first rule that holds gives the label, the score is the largest of the rules that hold, and no rule holding is `inconclusive`. The `when` text is parsed by `verdict/expr.rs`: equality, comparison, `and`, `or`, `in`, parentheses and list literals over a closed field set (`assessment`, `highest_tier`, `counts.*`, `detections.engine`, `detections.severity`, `families`, `techniques`, `run.end_reason`); strings compare without case; a list field matches when any element does; nothing in it is executable. `config validate` parses every rule and names the key (`verdict.rule.<n>.when`); `verdict.mapping` may only be `default`.

### Resource floors and the queue pause (`resources.rs`)

| Resource | Floor | Below it |
|---|---|---|
| RAM | `MemAvailable` at least the lane VM's RAM plus 2048 MiB (`[resources] min_free_ram_mib`) | the job waits (`resources`); `engine.alert` `low_memory`, once an hour |
| disk | free space on the data directory and every recording root at least `min_free_disk_gib` plus the job's estimate (the capture quota; plus the VM's RAM for a memory dump) | the job waits (`resources`). During `run` the floor itself is looked at once a minute: the run is stopped (`end_reason: stopped`), the warning `low_disk` is added, the queue pauses (`low_disk`, `engine.alert` `low_disk`) and the job ends `partial` |
| KVM | `/dev/kvm` readable and writable when `require_kvm` | the job waits (`dependency`); the queue pauses (`no_kvm`) |

`ResourceChecks` implements `HostChecks` with injected `Probes` (the real ones read `/proc/meminfo`, `statvfs` and `access(2)`); the lane asks `admission()` before a job is claimed and `check()` in `prechecks`. `Governor::tick(now_ms)` is what the daemon calls every few seconds, on every lane's loop before it claims a job (with several lanes the governors take turns through one `GovernorShare`, which also keeps the hourly `low_memory` alert single): it sets the queue's `pause_reason` to `file` (the operator's `run/PAUSE` file, a dangling symlink counts), `low_disk` or `no_kvm` with an `engine.alert` (`queue_paused`, `low_disk`, `no_kvm`), lifts a pause it set when the condition is gone (`queue_resumed`), and never replaces or lifts `operator` or `lane_quarantined`. A paused queue leaves jobs `queued` with `waiting_for: queue_paused`. There is no `queue.paused` event in the contract: the `engine.alert` is the signal (5.5).

### The daemon (`daemon/`) and its socket (`server/`)

`antinomie-cli auto daemon` starts the engine with the owner claim `daemon` and the socket path (so `run/owner.json` names both and the window, a command or a second daemon is refused with the owner named), then hands it to `Daemon::start`:

1. the first snapshot; the job store; `service.toml` and `policies/` (a policy with an error is left out and logged);
2. recovery (`lane::recover_startup`): jobs left `running` go back to the queue, jobs whose lane stages were over resume at `analyse`;
3. the staging store (its `noexec` check), the intake, the recording reads;
4. the socket is bound **before** the lane starts, so a socket that cannot be served stops the start with nothing running;
5. the lane's thread, then the accept loop.

**The lane's thread** owns the engine. `LaneLoop::run` keeps the snapshot current, runs the resource governor every 5 s, the wait expiry every 30 s and an hourly janitor (staged uploads, idempotency keys, engine events), serves a lane command when idle, and claims the next job (`Store::claim_next` with the lane's eligibility). A job runs `drive` and then `host` **on the same waiter** (coordinator decision for 0.9.0): the next job's VM stages do not overlap this job's host stages yet. `Phase` (`Idle`, `Lane(job)`, `Host(job)`, `Command`) is the shared word the supervisor reads; it is changed under its mutex, and the supervisor holds the same mutex while it decides and cancels, so a job is never cancelled for shutdown after it has entered its host stages. A submit wakes the loop through a channel; with nothing to do it sleeps a second.

**Shutdown** (`shutdown_step`, called every 100 ms by `Daemon::supervise` after the first stop signal): a job in `Lane` is cancelled for shutdown once (`shutdown = drain`: after `drain_timeout_s`), and `drive` puts it back in the queue with the attempt forgiven; a job in `Host` runs on until `shutdown_host_grace_s` (120 s), then the lane's waits are interrupted and the job is left `running` with its `collected` entry, so recovery resumes it at `analyse` and the VM does not run again. The loop claims nothing once stopping. A second stop signal within 5 s interrupts at once (exit 130). `SIGHUP` reloads the policies and `service.toml` (not the socket); `SIGUSR1` logs `queue.status`. The CLI's handlers only add to atomics that the supervisor reads.

**The socket** (`server/`):

| Piece | What it does |
|---|---|
| `Server::bind` | The folder must be a directory (not a symlink) of the daemon's user with mode 0700, or the start fails; a stale socket file is removed, any other file is not; `chmod 0600` after `bind`; the socket's device and inode are kept so the server removes only its own file when it stops |
| `admit` | `SO_PEERCRED` on accept: another UID, or credentials that cannot be read, is closed before the hello. The 65th connection gets one `too_many_connections` line |
| `frame` | `LineReader` never holds more than one line of 2 MiB plus a 64 KiB read; `parse_request` accepts `{id, op, params}` and nothing else; `encode` turns a reply above 2 MiB into `payload_too_large` for its id. `fuzz_entry` is the libFuzzer target `socket_frames` (and a stable test runs it over 2000 generated inputs) |
| `conn` | One thread per connection, one per request in flight (16 per connection, 256 in all), a token bucket per connection (50/s, burst 100) and one for the socket; `cancel` sets the request's flag; a closed connection sets every flag. Replies are whole lines under a lock, each written within 10 s (a deadline over the whole line, not per `write`) |
| `subscribe` | The resume rule of 5.5 (see docs/job-api-1.md): live channel first, then the table, then live with a skip by `gseq` (all-jobs) or `seq` (one job). The store publishes while it still holds its connection, so live events arrive in commit order; a bounded channel (4096) that overflows makes the stream read the table again instead of losing events, and a client that cannot take a line in 10 s is closed as a slow consumer |
| `client` | The other end: hello check (`api_version`), `call`, `subscribe` with cancel, a deadline and an interrupt check |

`daemon::service::Service` is the `Handler`: every op parses its parameters with the contract's types (an unknown member is named in `field`), checks the op's scope, and refuses `sample.path` from the socket (`Transport::Socket`); the same object is called in-process by direct mode (`Transport::InProcess`), where a path is the command's own file. `artifact.get` resolves the stored location inside the job directory with `canonicalize` and a prefix test and reads ranges through `O_NOFOLLOW`. `job.retry` is `Store::retry`: the canonical submitted spec, the sample by hash, the overrides merged, `repeat_of` set, the duplicate rule skipped.

Tests: `server/tests.rs` (21, over a real socket: modes and refusals of the folder and the file, the hello, the peer check, a 2 MiB line, an oversized reply, malformed lines, 16 in flight and the 17th, a duplicate id, `cancel`, the rate, 64 connections, idle and unfinished lines, the subscription cap, a client killed mid-stream that resumes by `gseq` with no gap or duplicate while events keep coming, a job stream that carries only its job and ends after `job.finished`, `truncated` both ways, bad subscriptions, ping and `types`, an overflowing subscription refilled from the table, a slow consumer, the commit order under four writers, the stop); `frame`, `b64` and `limits` unit tests (11); `daemon/tests.rs` (15: uploads and the refused path, bad Base64 and chunk sizes, unknown, reserved and unserved ops, scopes, a stopping daemon, retry, the queue and capabilities, health, artifact paths, and the lane loop with a scripted lane: order and wake-up, shutdown in the lane stages, in the host stages, past the grace, and drain).

### Making and mending a lane (`lane/provision.rs`) and the `auto` commands

`init_lane` (on any `Engine`): refuse an existing lane unless `replace` (and a replaced lane that still has `current` or `collected` work), refuse a VM name in use, then `Create`/`CreateWithCredentials` with the `VmConfig` the CLI built (`vm create`'s own builder with `network = routed`: `routed = true`, `nat = false`, `isolated_network = false`; defaults 2 CPUs, 4096 MiB, 40 GiB, `realistic-desktop`), `Start`, the guest answering the INFO probe (`guest_kernel`), the revision check (15 when a policy allows core dumps), `AwaitBoot` (the guest finished booting: `/sbin/init` of its own root is there, so the initramfs no longer grows the root file system, and a systemd guest's start-up has finished; the guest answers from the initramfs, and a VM stopped then kept a half-grown file system in `auto-clean` that crashed every later boot's kernel in `resize.c`, ANT-T0476), the console checked for a guest kernel crash (`waiter::console`: a kernel `BUG`, an oops, a panic or the base's "Guest filesystem resize failed" fails the init with the line, after a stop), `stop_vm` (flush and disk layer settled), `CreateVmSnapshot` Disk `auto-clean`, and only then `lanes/lane-1.json`. A failure after the VM exists names the VM left and the `vm delete` to remove it; no lane file is written. The CLI then writes `policies/default.toml` (the shipped policy with `vm.lane_vm` and `vm.revert_to` set) when there is no policy. `reset_lane`: an idle lane only; the running VM stopped; `clear_for_reset` (refused while the recorded QEMU lives); `RestoreVmSnapshot { boot_from_disk: true, confirmed: true }`; the guest answering; `AwaitBoot` and the console check, as in `init_lane`; `stop_vm`; the quarantine lifted. `unquarantine_lane`: the VM's snapshot tree asked for first (`RefreshVmSnapshots`: an engine that just started may not have loaded it, found on the PC), then `check_lane` without the quarantine itself; the flag lifted only when nothing is left. `list_lanes`: the files with the checks in words. In the daemon these are the `lane.*` ops, served by `StagesRunner::command` on the lane's thread between jobs (`Phase::Command`); a busy lane answers `conflict` at once and an expired request is dropped.

The CLI's `auto` group (`crates/cli/src/commands/auto/`): `link` picks the way (the socket when a daemon answers; else the store read-only for reads, or the store under the data-folder lock for `cancel` and `queue pause/resume`); `submit` uploads in 768 KiB pieces with the SHA-256 checked by the daemon, waits through the job's event stream, and in direct mode starts `Daemon` in the command (owner kind `cli`, no socket), submits in-process (`sample.path`), runs `supervise` until the job is terminal, then shuts the engine down; `render::job_exit` is the exit precedence of 3.3 (state first; the label only on `succeeded` with `--verdict-exit`); human output strips control characters from sample-derived text.

`[verdict] tag_library` (coordinator decision): at `cleanup`, before the job is final, the sample gets `auto:policy=<name>` and `auto:label=<label>` through `SampleTags` (`LibraryTags`: the custody actor `auto:policy-<name>`); a failure is the warning `library_tag`.

### Watch folders (`watch/`, `daemon/watch_env.rs`)

`Watcher` holds one `FolderRun` per `[[inbox.watch]]` entry (a reload keeps the state of a folder that is still listed); the daemon's `antinomie-watch` thread configures it from the live `service.toml` and scans every 2 s (or at once for `watch.scan`), then publishes the folder statuses for `watch.list`. A scan of a folder (`scan.rs`):

1. open the folder with `O_DIRECTORY | O_NOFOLLOW`; `fstat` it and apply `safety::folder_problem` (a real directory, ours, not writable by everyone, not by its group without `allow_group_write`; a foreign owner only through a group the daemon is in with `allow_group_write`); a refused folder is a status and one `engine.alert` per distinct reason;
2. list it through the descriptor (`rustix::fs::Dir`), `fstatat` every entry with `AT_SYMLINK_NOFOLLOW`; directories are entered only when `recursive`, or, at the top with `policy_by_dir`, when the name is an existing policy (other names are ignored); a subfolder is opened with `openat(O_NOFOLLOW | O_DIRECTORY)` and its inode compared with the `fstatat`; the inbox's own `uploads`, `processed` and `rejected` are skipped by device and inode;
3. a regular file passes `safety::file_problem` (single link, ours or the shared group); the names `.x`, `*.part`, `*.tmp`, `*.crdownload` are skipped; links, devices, FIFOs and sockets are refused with a reason (shown by `watch.list`, logged once, never opened);
4. the stability clock: `(dev, ino)` maps to the size, mtime and ctime first seen and since when; any change restarts it; a file is ready after 3 s;
5. ready files in name order: the rate window (`watch_rate` in 60 s; the next file pauses the folder for 60 s and raises `watch_flood`), the queue room, then `openat(O_NOFOLLOW | O_NONBLOCK)` relative to the folder's descriptor, `fstat` on the descriptor (same file, size and times as looked at, `file_problem` again), and `WatchEnv::admit`.

`ServiceEnv::admit` runs `Intake::sample_from_file` on the open descriptor (the steps of 4.2: size, type, architecture, library add with origin `Added`, source `Automation`, the folder-relative name, custody actor `auto:policy-<policy>`), then `Store::submit` for the library sample with the caller `auto:policy-<policy>` (scope `submit`, policy list `[<policy>]`) and the folder's `on_duplicate`; the job carries the label `watch=<folder name>`. A rejected sample or job moves the file to `rejected/` (`settle.rs`: `renameat2(RENAME_NOREPLACE)` after checking the name still leads to the file that was read, a copy and unlink across file systems, a sanitised name `<ms>-<name>`, a `.reason` file); an `unavailable`/`quota_exceeded` answer leaves the file and pauses the folder for a minute. `keep`ed and unmovable files are remembered by `(dev, ino, size, mtime)` in `<inbox>/.watch-state.json`.

Tests (`watch/tests.rs`, 27, real folders; `safety.rs`, 9): see ANT-T0383 for the rule-by-rule list.

### Retention (`retention/`, `daemon/housekeeping.rs`, `store/remove.rs`)

`Retention::run(dry_run)` makes one pass over `Store::finished_jobs()` (ended jobs only, oldest first) and returns a `GcReport` (actions, skipped with the reason, errors, bytes). `Runs` is the seam to the recordings: `RealRuns` takes the run's folder from `Job.recording.directory` only when it is a plain folder inside the data folder whose name is the run id, sizes it without following links, reads `artifacts.json` (`RunArtifactState::in_progress`), asks the daemon's `QueryService::run_is_open` (the read leases of 5.12.2), and deletes through `samples::plan_run_deletion` and `samples::delete_run_as` (new in core: `delete_run` with the custody actor as a parameter, `auto:policy-<name>`). The pass: recordings older than `recordings_days` (`keep_failed` exempts a failed job's), then the size cap (oldest first, protected recordings last), then job records older than `jobs_days` (`Store::delete_job`: one transaction over `jobs`, `attempts`, `stages`, `artifacts`, `events`, then the job's folder; a job whose recording cannot go stays), then expired staged uploads and rejected files older than 7 days (plain files only). The daemon's `antinomie-gc` thread runs a pass a minute after the start and hourly; `gc.run` and `job.delete` take the same lock. Without a daemon `auto gc` and `auto delete` take the data folder and use `RealRuns { query: None }`.

### Result files and the hook (`notify/`, `daemon/notify_thread.rs`)

The `antinomie-notify` thread subscribes to the store's events; on `job.finished` it calls `Delivery::deliver`, one job at a time, after a start-up `sweep` of the jobs that ended in the last 24 hours. `notified.json` in the job's folder records `results` and `hook` separately, so a failed drop is made again without running the hook twice. `results::write` builds `<dir>/<date>/.<sha8>-<job>.partial` (0700, files 0600: `job.json` serialised from the store, and each non-sensitive report read through `daemon::artifacts::resolve` and an `O_NOFOLLOW` open), fsyncs it and renames it into place. `hook::run` is `Command::new(argv[0]).args(argv[1..]).env_clear().envs(five variables).current_dir("/").stdin(null).process_group(0)`; output is read by two threads that keep 64 KiB each; past 30 s the process group is killed (`kill_process_group` on the pid it spawned) and the child reaped; the exit code, signal or timeout is logged and the output goes to `job.log` (bounded at 5 MiB, control characters other than newline and tab replaced).

### VM tiers T5 to T8 (`tests/monitor/test-auto-*.py`, 0.9.0)

The tiers T1 to T4 and T9 to T10 of the design run without a VM (`cargo test`, the fuzz targets). T5 to T8 need a VM; each is one script, all four built on `tests/monitor/auto_vm.py`, and `python3 tests/monitor/test-auto-harness.py` checks their pure parts without a VM (in CI with the build-script tests).

```sh
tests/monitor/test-auto-smoke.py     --work DIR --base BASE [--lanes 2] [--strict]        # T5
tests/monitor/test-auto-isolation.py --work DIR --base BASE [--revert snapshot_disk,...]  # T6
tests/monitor/test-auto-faults.py    --work DIR --base BASE [--case qemu-kill,...]        # T7
tests/monitor/test-auto-soak.py      --work DIR --base BASE --duration 24h [--resume | --report]  # T8
```

| Script | What it runs | What it checks |
|---|---|---|
| `test-auto-smoke.py` (T5) | `base install`, `auto init` (and `auto init --lane 2` with `--lanes 2`), `auto daemon`, one job per lane with `demo-recon` from `tests/monitor/behavior-samples` (offline arguments: a closed local port, route `drop`) | The job object (outcome, times, lane, VM, revert, run exit, recording phase and folder, label and basis, host work items and their limits), its events (numbered without a gap, `job.created` first, `job.finished` last, the nine stages finished in order), `auto fetch` of the HTML and JSON reports against the artifact's size and SHA-256, `report.json` (schema 2, the job's run, VM, sample and assessment), `run list --job`, the sample's custody and `custody verify`, the lane free afterwards; with two lanes, one job on each, each run in its own lane folder |
| `test-auto-isolation.py` (T6) | Per strategy three jobs as root: a seed that writes `/tmp/marker`, appends to `/etc/hosts` and creates `/etc/antinomie-t6-new`, then two probes | The probes exit 0 (nothing seen) and not 40 + a bit mask. `snapshot_disk` on the lane `auto init` made; `snapshot_full` after `snapshot create --mode full` of the restored lane VM, with the lane file pointed at that snapshot while the daemon is stopped (`auto init` takes Disk snapshots only); `reset` is checked with `config validate --policy` first and reported BLOCKED when it is refused there (every auto lane has its clean snapshot, and the engine refuses `Reset` on a VM with snapshots). Exit 2 when the only problems are BLOCKED strategies |
| `test-auto-faults.py` (T7) | Five cases, each in its own folder with its own base copy and lane VM: `qemu-kill`, `daemon-kill`, `disk-full`, `guest-panic`, `revert-corrupt` | Each case states its expected job state (the failure matrix of the design) and the script prints a table of expected, observed and whether it held. `disk-full` puts the data folder on a tmpfs of `--quota-mib` in a user and mount namespace of the script (no root), or on `--quota-dir` |
| `test-auto-soak.py` (T8) | One job at a time, alternating `demo-recon` and a shell script, for `--duration`; retention on (`recordings_days = 1`, `max_recordings_gib = --recordings-cap-gib`) | After each job: the daemon's open descriptors, RSS and threads, the lane VM's snapshot nodes and folder size, `service/` size, the recordings kept, above the cap, and those `auto gc --dry-run` would delete. A growth table (first after `--warmup`, last, change, change per 100 jobs, highest; the p95 of each stage over the first and last quarter) and one flat line, no verdict word. A stop (signal, `--max-mem-floor-mb`, the daemon dying) keeps the state in `<work>/soak/` for `--resume`; `--report` prints the table |

Every script uses a private HOME and XDG folders and data folders under `--work`, copies the base there first, makes 512 to 2048 MiB guests (`--ram-mib`, 512 by default), waits for `--mem-gate-mb` (5000) of `MemAvailable` before each VM start and stops the daemon below `--mem-floor-mb` (2500), and deletes all VM data at the end (`--keep` keeps it; the logs stay in `<work>/out/`). `--vm-slot PREFIX` (or `ANTINOMIE_VM_SLOT`) runs the VM part under a command that holds the machine's VM slot. `--dry-run` prepares the folder, builds the programs, checks every CLI command and flag the script uses against `--help` and prints the plan, without a VM. Only recorded processes are signalled: the daemon the script started, and a lane's QEMU through its lane-file record (PID, start time and command line checked first).

Under TCG (no usable `/dev/kvm`, `--accel tcg`) the scripts pass `--tcg` to the CLI and `require_kvm = false` to the daemon, and stretch their own waits by 4 (`--time-factor` or `ANTINOMIE_TEST_TIME_FACTOR`); the engine's guest waits are stretched by the CLI's `--tcg-multiplier`. The design expects these tiers on a KVM machine; a TCG run is slower and its stage times are not comparable with KVM ones.

`tests/ci/nightly-vm.py GUEST_RUN WORK_DIR CLI` (the nightly workflow) also runs one Auto job: `auto init` on the downloaded base and a shell script through every stage in the command itself, which must end `succeeded` (or `partial` for host tools only) with its run and both report files.
