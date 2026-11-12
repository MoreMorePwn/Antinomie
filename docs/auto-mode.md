# Auto mode

[← Back to the overview](../README.md)

Auto mode takes a sample in and gives a report and a label out, without a
window and without a person: the sample runs in a VM that is reverted to a clean
snapshot first, the recording is analysed, and the machine is left clean for the
next job. It is `antinomie-cli auto ...` for one job and `antinomie-cli auto
daemon` for a queue that stays up.

This page is the guide to what Auto mode does and how to keep it running. The
command tables are in the [user guide](usage.md#auto-mode-090), the daemon's files
in [service configuration](service-config.md), the wire contract in the
[job API](job-api-1.md) and the safety notes in
[Unattended use](security.md#unattended-use).

## Set up, in four steps

```text
antinomie-cli doctor --require qemu,qemu-img,bubblewrap,kvm      # the host is ready
antinomie-cli --data-dir ~/auto base install ./bases/busybox     # a base (or: base download)
antinomie-cli --data-dir ~/auto auto init --base busybox         # the lane VM and its clean snapshot
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
```

Use a data folder of its own (`--data-dir`), never the one the window uses: one
process owns a data folder at a time. The last command runs the job in the command
itself and exits with the job's code (see [Exit codes](usage.md#command-line-090)).
For a queue that stays up, run `antinomie-cli --data-dir ~/auto auto daemon`
instead, and the same `auto submit` then talks to it.

## The pipeline

A job moves through nine stages. The VM stages hold the lane; the host stages do
not: once `collect` has finished, the lane releases the VM and starts the next
job, and the job's host work goes to the **host work pool** (see below).

| Stage | Where | What happens | Deadline |
|---|---|---|---|
| `prechecks` | host | The policy still allows the job, the disk, RAM and KVM floors hold, the lane is not quarantined and its clean snapshot is the one recorded | 60 s |
| `provision` | lane | Waits until the VM has no pending disk layer, restores the clean snapshot (a failed restore is tried once more, then the lane is quarantined), cold-boots the VM and waits for the guest | boot 180 s |
| `upload` | lane | Sends the sample from the library into the guest as `/tmp/<sha8>-<name>`; the sample is decrypted in memory and never touches the host's disk | 60 s and 1 s per 10 MiB |
| `launch` | lane | Starts the program in the app terminal with the job's arguments, environment and user | 30 s |
| `run` | lane | Lets it run until it exits or the run limit (the policy's `run.timeout_s`, at most `run.max_run_s`) | the limit |
| `collect` | lane | Waits for the network capture, memory dump and core dump to finish, stops the VM, waits until the recording is saved and the disk layer has settled | collect 300 s, stop 120 s, layer 1800 s |
| `analyse` | host | Static checks of the library copy in bubblewrap, the Triage scan and the detection engines on the recording, the digest and the assessment | per item, 2 x its expected time |
| `report` | host | The report files you asked for | 2 x its expected time |
| `cleanup` | host | Retention, result files and the command hook | 60 s |

### The host work pool

The host work of a job is split into items: `triage` (the Triage scan), one
`static:<tool>` item for each static check (`static:strings+regex`: Regex reads
the strings), `detection` (YARA, Sigma and IDS, after `triage`), `assess` (the
run's digest and the label, after `triage` and `detection`) and `report` (after
all of them). At most `[daemon] host_workers` items run at once (2 by default),
across every job.

A job launches without the guest-side static analysis, so YARA does not wait for
the specimen that analysis keeps (as the window's Detection tab does): it scans
the sample the job ran, read from the library, with the files the run wrote and
the core and memory dumps. The high or critical YARA hit of the default verdict
mapping therefore applies to jobs too.

* **Order: first come, first served by job arrival.** Every item of an older job
  starts before any item of a newer one, so a small item of a newer job never
  goes ahead of a heavy one. A job's items start in the order above; when the
  first one waiting depends on items still running, a later item of the same job
  whose own dependencies have ended starts in its place. While the oldest job
  waits for a worker or for memory, nothing starts.
* **Memory.** An item starts only with at least 2048 MiB of `MemAvailable`;
  below it the head waits (`auto status` says so) and starts when there is room.
* **Time limits.** Each item has an expected time: an estimate from the size of
  the sample (static tools) or of the recording (the others), or its median over
  the last runs on this host (once it ran three times) when that is larger, else
  the stage's fixed limit. A median never lowers the estimate, so a few small
  jobs do not shrink the limits of a large one. It may take
  `[daemon] host_time_factor` (2) times that, and at least 30 seconds. A policy that
  sets `analysis.static_time_limit_min` gives every static tool that fixed limit
  instead. Time spent waiting in the queue, for memory or for the engine to take
  a static analysis does not count. A job's host stages as a whole may take the
  factor times the expected work ahead of it when it arrived plus its own, and
  never less than the factor times the work ahead plus the sum of its own items'
  limits. An item's limit ends at this deadline at the latest. At the deadline
  the job's running items are stopped, nothing more of it starts, and once the
  stopped items have ended the job fails `deadline_exceeded`: what had finished
  is kept, the stopped items are `timed_out` and the queued ones `skipped`, and
  the failure's detail names both.
* **Stopping an item.** An item past its limit (or stopped by its job's
  deadline) is stopped gracefully, as Kubernetes, Slurm and Celery do: SIGTERM to
  its sandboxed tool's process group (the static analysis worker, the detection
  worker), `[daemon] stop_grace_s` (30) seconds to end, then SIGKILL. Only the
  recorded process group of the tool's own sandbox is signalled. Work the daemon
  does in its own process (indexing, the digest, the report) gets its cancel
  flag and stops at its next check.
* **What you see.** `auto status <job>` lists each item with its state
  (`queued`, `running`, `done`, `failed`, `timed_out`, `skipped`), expected time
  and limit; the job's `host_work` member carries the same. `auto status` shows
  the pool's queue length and running items.
* **Cancel, stop and restart.** Cancelling a job skips its queued items and stops
  its running ones at their next wait. At a stop the pool goes on for
  `shutdown_host_grace_s`; what is left stays `running` and is queued again, in
  the same order, at the next start (finished static items are kept).

A run that reaches its limit is not a failure: malware often never exits, and the
job `succeeded` with the run ended at the time limit. A piece of evidence that
finished incomplete makes the job `partial` (exit 11): the recording and the
report are there, with a warning for each missing piece.

## Policies

A policy is a TOML file in `<data>/policies/<name>.toml`; the file name is the
policy name. It says what a job may ask for and what a job gets when it asks for
nothing: which sample types and architectures it accepts, which lane VM and
snapshot it uses, the run limit, the user the program runs as, the routes it may
use, the evidence it keeps (network capture, memory dump, core dump), the static
checks and detection engines, the report formats, how failures are retried and
who may submit. `auto init` writes `default.toml` when the folder has none; a
copy with comments is in `packaging/policies/default.toml.example`.

* **Static checks and required checks.** `analysis.static_checks` (`"triage"`
  by default, `"none"` or a list) runs the library copy's tools before the
  Triage scan. A check that runs out of its time (2 x its expected time, or
  `analysis.static_time_limit_min` when the policy sets it, stretched on a busy
  host like the guest waits) or stops short
  does not fail the job: the job ends `partial` with a `static_check_incomplete`
  warning that names the check. List checks in `analysis.required_checks`
  (default none) to make their timeout, or their being unavailable, a failure of
  the `analyse` stage; with `analysis.required_stages` naming `analyse` that
  ends the job `failed` with `analysis_failed`. A static analysis the engine
  refuses or cannot run at all is a failure of the stage whichever checks are
  required.

* **Dump on suspicious activity.** `evidence.dump_trigger = "off"` (default),
  `"low"`, `"medium"` or `"high"` makes every job under the policy take a dump
  while the program runs, when the live Triage rules match at that tier or above;
  `evidence.dump_trigger_kind` is `"core"` (default; a core of the process that
  made the call, within `evidence.core_max_mib`, needs a revision-16 base, which
  `auto init` asks for), `"memory"` or `"both"`. One dump per run, 30 seconds
  apart, as the window's defaults. The program is not stopped. The job's
  `run.triggers` lists each match (rule, tier, process, call, and the state and
  size of each dump; the path only for a local caller), `run.trigger_notes` says
  when it was armed and nothing matched, and `job.trigger` events report them as
  they are known. A job cannot turn the trigger on or off; only the policy does.
When the guest-side static analysis is still running after the 300 s evidence wait,
the recording is saved without it and the job succeeds; `run.pending` lists
`analysis`.

* **Non-resident pages in trigger cores.** `evidence.core_nonresident = true`
  (default `false`) makes the cores the dump trigger takes also read the pages that
  are not in memory (swapped out, or file pages the kernel dropped), as the window's
  **Read non-resident pages**; slower, bounded by the core budget and deadline. It
  needs a core `dump_trigger` (without one `config validate` warns; an exit core
  always reads resident pages) and a base of guest contract revision 22 (on an older
  one the cores hold resident pages only and the job carries the warning
  `core_nonresident_unsupported`).

* **A job asks within the policy's ceiling.** `--timeout-run`, `--args`,
  `--env`, `--as`, `--route`, `--static`, `--formats` and the other flags of `auto
  submit` can lower or choose among what the policy allows, never exceed it. A
  request the policy forbids is stored as a `rejected` job (exit 13) with
  `policy_denied` and the field to blame. A switch the policy leaves off cannot
  be turned on by a job.
* **A job freezes its policy.** The file's digest and parsed content are stored with
  the job. Editing a policy, or `SIGHUP`, changes only jobs submitted afterwards.
* **Routes.** In 0.9.0 a job may use `drop` (the default: every connection a sample
  tries is captured and dropped) or `inet_sim` (simulated internet services). The
  live routes (`internet`, `tor`, `vpn`, `socks5`) and NAT are refused by `config
  validate`.
* **Accepted samples.** The default policy accepts ELF x86-64 programs only; add
  `"sh"` to `[sample] accept_types` for shell scripts. A script has no
  architecture, so `accept_arch` applies to ELF files only.
* **Duplicates.** `[sample] on_duplicate` is `run` (analyse again; the new job has
  `repeat_of`), `reuse` (return the earlier job) or `reject` (`duplicate_denied`).
* **The label.** A succeeded job has the raw Triage assessment, a label
  (`malicious`, `suspicious`, `clean_observed`, `inconclusive`), an optional score
  and the `basis` sentence that says why. `clean_observed` means nothing was seen
  in this run, not that the sample is clean. `[verdict] mapping = "default"` is the
  built-in mapping; `[[verdict.rule]]` entries replace it.

Check the files without starting anything: `antinomie-cli --data-dir ~/auto
config validate`. It prints `file:line:column: error: message` for each problem
and exits 4 when there is an error. All keys are in
[service configuration](service-config.md).

## Revert: how the lane stays clean

A VM that ran a sample keeps what the sample did, so every job starts from a known
state. The lane VM has a clean Disk snapshot, `auto-clean`, taken by `auto init`
after the guest booted once and finished booting (a guest stopped while its
initramfs still grows the root file system would keep a half-grown one, and every
job's boot from it would crash the guest kernel). Before each job the daemon checks the snapshot is the
one it recorded, restores it and cold-boots (`vm.revert = "snapshot_disk"`, the
default). `vm.revert = "reset"` is not available on Auto lanes, because every lane
keeps its clean snapshot: `config validate` refuses it and points at
`snapshot_disk`, which gives the same clean disk. `snapshot_full`
resumes a booted guest and needs the VM to be created and snapshotted headless,
with a full (memory) snapshot: over the disk-only `auto-clean` it could only boot
cold, so `config validate` refuses it and the daemon does not load that policy.

With `vm.revert_after = true` the lane also reverts right after the job, so no
used disk sits idle; the cost is one more restore per job.

**Quarantine.** A lane stops taking jobs when the restore failed twice, when its
clean snapshot is not the recorded one (somebody used the VM by hand), or after three
starts in a row that did not reach a working guest. Queued jobs stay queued with
`waiting_for: lane_quarantined` and an `engine.alert` is raised. Fix the cause, then:

* `auto lane list` shows whether the lane is quarantined and what keeps it from a
  job;
* `auto lane reset --yes` reverts the VM to its clean snapshot now and lifts the
  quarantine when that works;
* `auto lane unquarantine` lifts it without reverting, when the checks pass.

After a base update make a new lane VM with `auto init --replace`.

With several lanes a quarantine holds only its own lane: the other lanes go on
with the queue, and jobs wait (`waiting_for: lane`) only for what no other lane
can run. `auto lane list` shows every lane; `reset` and `unquarantine` take
`--lane lane-N` (default `lane-1`).

## Several lanes

One lane runs one VM at a time. A machine with the memory for more VMs can run
up to four lanes, each with its own lane VM, so up to four jobs run their VMs
at once. One lane stays the default.

```sh
# with the daemon stopped: lane 2's VM, in <data>/lanes/2/, on an installed base
antinomie-cli --data-dir ~/auto auto init --lane 2 --base busybox --ram-mib 512
# then in <data>/service.toml:
#   [daemon]
#   lanes = 2
antinomie-cli --data-dir ~/auto auto daemon
antinomie-cli --data-dir ~/auto auto status    # lane-1: idle ..., lane-2: idle ...
```

* Lane N's VM is named `auto-N` unless `--name` says otherwise. It is built on a
  base of the data folder; a lane never installs or deletes a base, and the data
  folder refuses to delete a base while a lane's VM uses it or a lane is
  creating a VM from it.
* The lanes share the data folder's bases, library, rules, tools, IOC data,
  engine settings and route settings. The job store, the policies and the host
  work pool are one for all lanes.
* A lane starts when its VM exists and the machine has `MemAvailable` for the
  RAM of every lane VM before it plus this lane's own floor (its VM's RAM plus
  2048 MiB, or `[resources] min_free_ram_mib`). The daemon's log says how many
  lanes started and why the others did not; so does `auto lane list`.
* A job goes to a free lane that can run it (the base of the policy's
  `vm.lane_vm`, and an ELF of the lane's architecture); among several, the
  least recently used, so the jobs spread. A policy whose `vm.lane_vm` is
  `auto-1` therefore runs on every lane built on lane 1's base.
* Every lane's host work goes to the one host work pool, first come, first
  served by job arrival; `[daemon] host_workers` is the total for all lanes.
* A run stays in the folder of the lane that recorded it (`<data>/lanes/N/`
  for lane N). Every read from the data folder finds the runs of all lanes:
  `run list` (`--vm`, `--job`), `run show`, `run export`, `triage`, `detect`,
  `report`, `sample show --runs`, and the `recording.*` operations of the
  daemon, the same through the daemon and with `--direct`. A lane that
  `[daemon] lanes` no longer starts is still read. A run's job shows its lane
  (`auto status JOB`); retention and `auto job delete --with-recording` delete
  the run in its own lane's folder. A lane folder is read only when its
  `lane.json` names its place, never through a link.

All the keys are in [service configuration](service-config.md#several-lanes).

## Watch folders

A folder the daemon polls every two seconds; each file that appears becomes a job.
Configure it in `service.toml`:

```toml
[[inbox.watch]]
path = "/srv/drop/default"       # absolute, owned by the daemon's user
policy = "default"
delete_after = "move"            # "move" (to processed/), "delete" or "keep"
```

The folder must belong to the daemon's user and must not be writable by others
(a group-writable folder needs `allow_group_write = true`). A file is taken only
when its size and time have not changed for three seconds and its name does not
begin with `.` or end in `.part`, `.tmp` or `.crdownload`, so copy a file in under
such a name and rename it when it is whole. A symbolic link, a device, a FIFO, a
file with a second hard link or a file of another user is refused and never
opened. A file the intake rejects (type, architecture, size, duplicate) moves to
`<inbox>/rejected/` with a `<name>.reason` file; it is not retried. More than
`watch_rate` (10) files a minute pauses the folder for a minute and raises
`watch_flood`. There are no per-file settings: a dropped file cannot choose its
own route, only the policy decides. `auto watch list` shows each folder's state
and what was taken or refused; `auto watch scan` scans now.

With the system unit, add the folder to `ReadWritePaths` (see [Run it under
systemd](#run-it-under-systemd)).

## Results and the command hook

Reports are always in the job's folder (`auto artifacts JOB`, `auto fetch JOB
KIND`). Two optional channels deliver a finished job without a client:

* `[results] dir = "/srv/results"` writes `<dir>/<yyyy-mm-dd>/<sha8>-<jobid>/` with
  `job.json` and the non-sensitive reports (not the capture or other sensitive
  files), mode 0600 in 0700 folders.
* `[notify] on_finish = ["/usr/local/bin/hook"]` runs that command when a job ends.
  It is run directly, never through a shell, with an empty environment plus
  `ANTINOMIE_JOB_ID`, `ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and
  `ANTINOMIE_RESULT_JSON` (the path of `job.json`). Nothing a job controls is in its
  arguments or environment. It has 30 s; past that it and what it started are
  killed. Its output goes to the job's `job.log`.

Delivery is at least once and never changes the job: a failure is a log line and
an `engine.alert` (`result_drop_failed`, `hook_failed`).

## Retention and clean-up

| What | Kept for | Setting |
|---|---|---|
| Recordings of auto jobs | 14 days | `[retention] recordings_days` |
| Recordings above the size cap | oldest go first above 200 GiB | `[retention] max_recordings_gib` |
| Recordings of failed jobs | until the job record goes | `[retention] keep_failed` |
| Job records, events and reports | 90 days | `[retention] jobs_days` |
| Staged uploads | 24 hours | fixed |
| `<inbox>/rejected/` files | 7 days | fixed |

The daemon runs a pass an hour (the first one minute after it starts). It never
touches the library, never deletes a sample and never removes a job that has not
ended; a recording that is being read, or whose evidence is still being written,
is skipped and taken in a later pass. A recording goes through the app's own
deletion, which keeps its kept files. A job retried after its launch (a lost
guest, a stop or a restart of the daemon) recorded a run for each such attempt:
retention and `--with-recording` delete all of them, and the job record stays
until they are gone. A recording kept in a VM's recordings folder outside the
data folder is handled the same way; a recording that cannot be read keeps its
job record, so it is never left with nothing naming it. `auto gc --dry-run` prints what a pass would
delete; `auto gc` runs one; `auto delete JOB [--with-recording]` removes one ended
job. Without a daemon these take the data folder for the command.

## Failure codes

A failed job has a `failure` with a code, shown by `auto status JOB`,
`auto result JOB` and the job's `job.finished` event. The exit code of a waited job
is 10 for `failed`, 11 for `partial`, 12 for `cancelled`, 13 for `rejected`.

| Code | Stage | Retried | What it means and what to do |
|---|---|---|---|
| `sample_missing`, `sample_too_large`, `sample_type_denied`, `sample_arch_denied`, `duplicate_denied` | submit | no | The intake refused the file; the size limit is the smallest of 256 MiB, the policy's `max_sample_mib` and a quarter of the lane VM's RAM |
| `policy_denied` | submit, prechecks | no | The policy forbids the request, or it changed or went away after the submit; `field` names the part |
| `quota_exceeded`, `dependency_missing`, `host_resources` | prechecks | waits | The queue is full, a tool is missing (`doctor`), or the disk, RAM or KVM floor is not met. The job waits `queued` for up to the policy's `wait_s` (3600), then fails |
| `no_base`, `no_vm` | provision | no | The lane VM or its base is gone; `auto lane list` says which |
| `vm_start_failed`, `guest_unreachable` | provision, launch | yes | The VM or its guest did not come up, or the guest kernel crashed while it booted (the crash line is the detail); three in a row quarantine the lane |
| `revert_failed`, `lane_changed` | provision | no | The lane is quarantined (see above) |
| `upload_failed` | upload | yes | The sample did not reach the guest |
| `launch_failed` | launch | depends | The program did not start (not executable for the guest, no terminal) |
| `guest_lost` | run, collect | once | The guest or QEMU died. A sample that does that twice ends `failed` |
| `recording_failed` | collect | once | The recording could not be completed |
| `analysis_failed` | analyse, report | yes | Only when the policy marks the stage required (`analysis.required_stages`); otherwise the job is `partial` with a warning. A static check that only timed out or stopped short is not this failure unless it is in `analysis.required_checks` (it is a `static_check_incomplete` warning and the job is `partial`) |
| `deadline_exceeded` | analyse, report | no | The host stages passed their deadline (`host_time_factor` x the expected work, see "Time limits"): the running items were stopped (`timed_out`), the queued ones never started; what finished is kept. A busy host or too low a factor; try again later or raise `host_time_factor` |
| `cancelled` | any | no | Cancelled by request; what was recorded is kept |
| `internal` | any | maybe | A bug, or the watchdog: the whole job ran past `run` plus 30 minutes. `details.log` names the job log |

A retry starts with a full revert. `backoff_s` (30 s, then 120 s) spaces the
attempts and `max_attempts` bounds them.

## Troubleshooting

**Exit 21, "data directory is owned by ...".** The window, the daemon or another
command has the folder. `doctor` shows the owner (`data_dir.owner`). Stop it, or use
another folder. A job submitted with `--daemon` exits 21 when no daemon answers.

**Exit 20, a dependency is missing.** `antinomie-cli doctor` lists each tool. On
Debian or Ubuntu install `qemu-system-x86 qemu-utils qemu-system-gui bubblewrap
util-linux tshark curl`. Bubblewrap must work: on Ubuntu 24.04 an AppArmor setting
(`kernel.apparmor_restrict_unprivileged_userns`) can forbid it; the job then stops
with `dependency_missing` instead of running unsandboxed.

**Jobs stay `queued`.** `auto status JOB` shows `waiting_for`: `lane` (busy),
`resources` (below `min_free_disk_gib` or the RAM floor, the queue pauses),
`dependency`, `quota`, `queue_paused`, `layer_pending` (the previous run's disk is
still being saved, which can take minutes after a run that changed many files),
`backoff` or `lane_quarantined`. A file `<data>/run/PAUSE` pauses admission on
every lane within five seconds, also while other lanes run jobs (a lane running a
job starts no other until it ends); `auto queue resume` or removing the file
continues. Low disk and a missing KVM pause every lane the same way.

**The disk filled up during a job.** The running program is stopped within a
minute and the queue pauses (`low_disk`), also when the job database itself is
too full to record the pause. A job whose end cannot be written yet waits for room
(it shows its last stage meanwhile) and ends as soon as there is; if the recording
could not be finished it ends `recording_failed`, and the lane waits
(`layer_pending`) until the engine has finished the recording, which it tries again
every 30 seconds. Free space under the data folder: the pause lifts by itself.

**No KVM.** With `require_kvm = true` (the default) jobs wait until `/dev/kvm` is
usable; the daemon user must be in the `kvm` group. Set `[resources] require_kvm =
false` to run with TCG, which is slow.

**The daemon does not stop.** On `SIGTERM` it stops the running job through the
engine and finishes in a few minutes at most (`TimeoutStopSec=360` in the unit); a
job that has not left the VM 240 seconds after the stop (a recording that cannot be
saved on a full disk, say) is left for the next start. A
second `SIGTERM` or Ctrl-C within five seconds stops at once with exit 130; the next
start finishes what was left: it removes stale guest RAM files, finishes a pending
disk layer (up to 30 minutes), and puts a job that was running back in the queue
without using an attempt.

**A change to a policy is ignored.** Jobs already queued keep the policy they were
submitted under. Send `SIGHUP` (`systemctl reload antinomie-auto`); a file with an
error keeps the old settings, so run `config validate` first.

**What happened to a job.** `auto events JOB` lists its events; `<data>/service/jobs/<id>/job.log` has its log lines;
`kill -USR1` on the daemon writes the queue's state to its log. Log lines go to
standard error (the journal under systemd), as text or with `--log-format json`;
`[log]` in `service.toml` sets the level, the format and an optional rotating file,
and the flags `-q`, `-v` and `--log-format` win over it
([the keys](service-config.md#the-daemons-keys)).

## Run it under systemd

Two unit files are in `packaging/`, in the repository and in the release archive: `antinomie-auto.service` (a system unit for a dedicated
user on a dedicated host, with a device policy) and `antinomie-auto.user.service`
(a user unit). Both run `antinomie-cli auto daemon`, restart it after a crash, and
give it six minutes to stop.

**The system unit** (as root):

```text
useradd --system --create-home --home-dir /var/lib/antinomie \
        --shell /usr/sbin/nologin --groups kvm antinomie
install -m 0755 antinomie-cli /usr/local/bin/antinomie-cli
install -m 0644 packaging/antinomie-auto.service /etc/systemd/system/
systemctl daemon-reload
# prepare the lane once, as that user, with the daemon not running
sudo -u antinomie -H antinomie-cli --data-dir /var/lib/antinomie base install ./bases/busybox
sudo -u antinomie -H antinomie-cli --data-dir /var/lib/antinomie auto init --base busybox
install -m 0644 -o antinomie packaging/service.toml.example /var/lib/antinomie/service.toml   # optional
systemctl enable --now antinomie-auto.service
sudo -u antinomie -H antinomie-cli --data-dir /var/lib/antinomie auto submit ./sample.elf --wait
```

**The user unit** (as the user who runs it, who must be in the `kvm` group):

```text
./install.sh                       # puts antinomie-cli in ~/.local/bin
install -D -m 0644 packaging/antinomie-auto.user.service ~/.config/systemd/user/antinomie-auto.service
systemctl --user daemon-reload
antinomie-cli --data-dir ~/antinomie-auto base install ./bases/busybox
antinomie-cli --data-dir ~/antinomie-auto auto init --base busybox
systemctl --user enable --now antinomie-auto.service
loginctl enable-linger "$USER"     # keep it running without a login session
```

What the units say:

| Setting | Why |
|---|---|
| `Type=simple`, `Restart=on-failure`, `RestartSec=10`, `StartLimitBurst=5` in 5 minutes | The daemon recovers from a crash at its next start; a crash loop stops instead of spinning. A stop through `systemctl` is not restarted. There is no `sd_notify`: the unit is started when the process runs; ask `doctor` or `auto status` whether the daemon answers |
| `KillMode=mixed`, `TimeoutStopSec=360` | QEMU is a child of the daemon. `systemctl stop` sends `SIGTERM` to the daemon alone, which stops the running job and its VM and exits. Only what is still alive after 360 s (the 120 s VM stop plus up to 120 s for a job already in its host stages and the disk-layer step) gets `SIGKILL`, QEMU included. With `[daemon] shutdown = "drain"` raise it above `drain_timeout_s` |
| `ExecReload` | `systemctl reload` sends `SIGHUP`: policies and `service.toml` are read again |
| `NoNewPrivileges`, `CapabilityBoundingSet=` (empty), `RestrictSUIDSGID`, `LockPersonality`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | The daemon needs no privilege: QEMU opens `/dev/kvm` through the `kvm` group and bubblewrap uses unprivileged user namespaces |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `StateDirectory` | The only writable place is the data folder. Add other folders (a watch folder, `[results] dir`, a log file) with `systemctl edit antinomie-auto` and `ReadWritePaths=` |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces=user mnt pid ipc uts net` | QEMU's user-mode network, the local socket and bubblewrap's namespaces, and nothing else |
| `DevicePolicy=closed` with `/dev/kvm`, `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx` and the pseudo-terminals (system unit) | Not `PrivateDevices`, which would hide `/dev/kvm`. A user manager cannot set a device policy, so the user unit has none |
| No `MemoryDenyWriteExecute`, `ProcSubset` or `SystemCallFilter` | QEMU's TCG and the YARA-X engine generate code at run time, the resource floors read `/proc/meminfo`, and bubblewrap needs mount and namespace calls |

Read the log with `journalctl -u antinomie-auto` (`journalctl --user -u
antinomie-auto`). `systemd-analyze security antinomie-auto.service` scores the
unit. The Docker equivalent of this unit comes with the web interface in 0.9.1.
