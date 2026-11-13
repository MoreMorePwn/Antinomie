# Auto mode

[← Back to the overview](../README.md)

Auto mode takes a sample in and gives a report and a label out, without a
window and without a person: the sample runs in a VM that is reverted to a clean
snapshot first, the recording is analysed, and the machine is left clean for the
next run. It is `antinomie-cli auto ...` for one run and `antinomie-cli auto
daemon` for a queue that stays up.

This page is the guide to what Auto mode does and how to keep it running. The
command tables are in the [user guide](usage.md#auto-mode-090), the daemon's files
in [service configuration](service-config.md), the wire contract in the
[run API](run-api-1.md) and the safety notes in
[Unattended use](security.md#unattended-use).

> **Words on this page.**
>
> | Word | Means |
> |---|---|
> | Run | One analysis of one sample with a preset or Custom options: it waits, runs and ends with a report. Id `r_` and 26 characters |
> | Program | The sample's execution inside a run (`program` of the run) |
> | Attempt | A run that started over because the VM or the guest failed ("attempt 2 of 2") |
> | Recording | What the engine captured while the program ran; `recording list`, `show` and `export` read it |
> | Preset | A named set of run options to start from; a run that changes one is Custom |
> | Job | Work the engine still has to do: the store's queue, a run's host work items, uploads, retention |

## Set up, in four steps

```text
antinomie-cli doctor --require qemu,qemu-img,bubblewrap,kvm      # the host is ready
antinomie-cli --data-dir ~/auto base install ./bases/busybox     # a base (or: base download)
antinomie-cli --data-dir ~/auto auto init --base busybox         # the lane VM and its clean snapshot
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
```

Use a data folder of its own (`--data-dir`), never the one the window uses: one
process owns a data folder at a time. The last command runs the run in the command
itself and exits with the run's code (see [Exit codes](usage.md#command-line-090)).
For a queue that stays up, run `antinomie-cli --data-dir ~/auto auto daemon`
instead, and the same `auto submit` then talks to it.

## The pipeline

A run moves through nine stages. The VM stages hold the lane; the host stages do
not: once `collect` has finished, the lane releases the VM and starts the next
run, and the run's host work goes to the **host work pool** (see below).

| Stage | Where | What happens | Deadline |
|---|---|---|---|
| `prechecks` | host | The caller still holds every permission the run uses, the disk, RAM and KVM floors hold, the lane is not quarantined and its clean snapshot is the one recorded | 60 s |
| `provision` | lane | Waits until the VM has no pending disk layer, restores the clean snapshot (a failed restore is tried once more, then the lane is quarantined), cold-boots the VM and waits for the guest | boot 180 s |
| `upload` | lane | Sends the sample from the library into the guest at the preset's `program.guest_path` (`/tmp/<sha8>-<name>`); the sample is decrypted in memory and never touches the host's disk | 60 s and 1 s per 10 MiB |
| `launch` | lane | Starts the program in the app terminal with the preset's arguments, environment, working directory and user | 30 s |
| `run` | lane | Lets it run until it exits or the run time (the preset's `program.run_time_s`, at most 1800) | the limit |
| `collect` | lane | Waits for the network capture, memory dump and core dump to finish, stops the VM, waits until the recording is saved and the disk layer has settled | collect 300 s, stop 120 s, layer 1800 s |
| `analyse` | host | Static checks of the library copy in bubblewrap, the Triage scan and the detection engines on the recording, the digest and the assessment | per item, 2 x its expected time |
| `report` | host | The report files you asked for | 2 x its expected time |
| `cleanup` | host | Retention, result files and the command hook | 60 s |

### The host work pool

The host work of a run is split into items: `triage` (the Triage scan), one
`static:<tool>` item for each static check (`static:strings+regex`: Regex reads
the strings), `detection` (YARA, Sigma and IDS, after `triage`), `assess` (the
run's digest and the label, after `triage` and `detection`) and `report` (after
all of them). At most `[daemon] host_workers` items run at once (2 by default),
across every run.

A run launches without the guest-side static analysis, so YARA does not wait for
the specimen that analysis keeps (as the window's Detection tab does): it scans
the sample the run ran, read from the library, with the files the run wrote and
the core and memory dumps. The high or critical YARA hit of the default verdict
mapping therefore applies to runs too.

* **Order: first come, first served by run arrival.** Every item of an older run
  starts before any item of a newer one, so a small item of a newer run never
  goes ahead of a heavy one. A run's items start in the order above; when the
  first one waiting depends on items still running, a later item of the same run
  whose own dependencies have ended starts in its place. While the oldest run
  waits for a worker or for memory, nothing starts.
* **Memory.** An item starts only with at least 2048 MiB of `MemAvailable`;
  below it the head waits (`auto status` says so) and starts when there is room.
* **Time limits.** Each item has an expected time: an estimate from the size of
  the sample (static tools) or of the recording (the others), or its median over
  the last runs on this host (once it ran three times) when that is larger, else
  the stage's fixed limit. A median never lowers the estimate, so a few small
  runs do not shrink the limits of a large one. It may take
  `[daemon] host_time_factor` (2) times that, and at least 30 seconds. A preset that
  sets `static_analysis.time_limit_per_tool_min` above 0 gives every static tool
  that fixed limit instead. Time spent waiting in the queue, for memory or for the engine to take
  a static analysis does not count. A run's host stages as a whole may take the
  factor times the expected work ahead of it when it arrived plus its own, and
  never less than the factor times the work ahead plus the sum of its own items'
  limits. An item's limit ends at this deadline at the latest. At the deadline
  the run's running items are stopped, nothing more of it starts, and once the
  stopped items have ended the run fails `deadline_exceeded`: what had finished
  is kept, the stopped items are `timed_out` and the queued ones `skipped`, and
  the failure's detail names both.
* **Stopping an item.** An item past its limit (or stopped by its run's
  deadline) is stopped gracefully, as Kubernetes, Slurm and Celery do: SIGTERM to
  its sandboxed tool's process group (the static analysis worker, the detection
  worker), `[daemon] stop_grace_s` (30) seconds to end, then SIGKILL. Only the
  recorded process group of the tool's own sandbox is signalled. Work the daemon
  does in its own process (indexing, the digest, the report) gets its cancel
  flag and stops at its next check.
* **What you see.** `auto status <run>` lists each item with its state
  (`queued`, `running`, `done`, `failed`, `timed_out`, `skipped`), expected time
  and limit; the run's `host_work` member carries the same. `auto status` shows
  the pool's queue length and running items.
* **Cancel, stop and restart.** Cancelling a run skips its queued items and stops
  its running ones at their next wait. At a stop the pool goes on for
  `shutdown_host_grace_s`; what is left stays `running` and is queued again, in
  the same order, at the next start (finished static items are kept).

A run that reaches its limit is not a failure: malware often never exits, and the
run `succeeded` with the run ended at the time limit. A piece of evidence that
finished incomplete makes the run `partial` (exit 11): the recording and the
report are there, with a warning for each missing piece.

## Presets

A preset is a named set of run options to start from. A preset grants nothing
and locks nothing: only the caller's permissions, what the node has set up and
the caller's limits do. Five presets are built in and always there; more are
TOML files in `<data>/presets/<name>.toml` (the file name is the preset name).
A run that names no preset uses **Standard**. `auto preset list` lists them with
the permissions their options need.

| Option | Standard | Quick look | Deep | Interactive | Live network |
|---|---|---|---|---|---|
| Run time | 5 min | 2 min | 15 min | 10 min | 10 min |
| Route | None (drop) | None (drop) | InetSim | None (drop) | Tor |
| Dumps | none | none | when suspicious from Medium (memory and core), core on exit | none | none |
| Static analysis | 11 Triage checks | metadata, strings, hardening, rules, identification | 11 Triage checks, Disassembly, Decompilation, FLOSS | 11 Triage checks | 11 Triage checks |
| Detection | YARA, Sigma, IDS | YARA | YARA, Sigma, IDS | YARA, Sigma | YARA, IDS |
| Report | HTML, JSON | HTML, JSON | HTML, JSON, PDF, evidence bundle | HTML, JSON | HTML, JSON |
| Needs | nothing | nothing | `evidence.core_dump`, `evidence.memory_dump` | nothing | `route.tor`; not set up on this node before 0.9.1 |

The built-in presets are read-only (a file may not take their names, `standard`,
`quick-look`, `deep`, `interactive`, `live-network`, nor `custom`): copy
`packaging/presets/standard.toml.example`, which is Standard with every key and
a comment naming the app's label, under another name.

The format has one table per part of Submit: `[accepts]` and `[duplicates]`
(what the preset takes), `[program]` (source, guest path, arguments, working
directory, environment, user `normal`, `root`, `nobody` or `custom` with `uid`
and `gid`, run in, run time), `[record]`, `[network]` (capture, route),
`[dumps]` (memory and core dumps on exit, the core budget and deadline, Dump
when suspicious activity is seen with its minimum tier, what it takes, at most
N dumps N seconds apart, non-resident pages), `[vm]` (lane group, keep the VM
after a failure, allow taking control), `[static_analysis]` (the Triage and
deep checks, the time limit per tool, Ghidra for Disassembly, required checks,
the size limits), `[triage]`, `[detection]` (YARA, Sigma, IDS, Check online),
`[report]` (formats, sections, evidence bundle, defang), `[verdict]` and
`[retry]`; `required_stages` stays a top-level key. Every key may be left out:
its default is Standard's. The full list is in
[service configuration](service-config.md).

* **Keys 0.9.0 reserves.** The format is final, so 0.9.1 does not change the
  file. A key the 0.9.0 engine cannot act on yet is accepted at its default
  only; any other value is an error of `config validate` and, in a submit,
  `unsupported` ("arrives with 0.9.1"): `program.source`, `executable`,
  `preload`, `extra_files`, `run_in`, `record.scope`,
  `record.screenshot_every_s`, `network.private_addresses`, `abuse_filter`,
  `dumps.disk_dump`, `static_analysis.rebuilt_*`, `triage.written_*` and
  `earlier_*`, `detection.scan_every_min`, `report.sections`. A live route and
  `vm.keep_on_failure = true` need their permission and are then refused
  `unavailable_on_node`. Deep scans every 2 minutes from 0.9.1; in 0.9.0 its
  `scan_every_min` is 0.

* **The Custom rule.** `auto submit` flags (`--timeout-run`, `--args`, `--env`,
  `--as`, `--route`, `--static`, `--formats` ...) and the `overrides` of a
  submit change the preset's options; `overrides` is a partial preset with the
  same tables and keys as the file (`{"program": {"run_time_s": 600}}`). A run
  whose overrides change a value is **Custom**: it stores the name `custom`,
  `based_on` (the preset's name and digest), the changed keys (`changes`) and
  every resolved option; an override equal to the preset's value leaves the
  run on its preset. Nothing in a preset is a ceiling: arguments, environment,
  the user, the routes, the dumps and the engines can always be changed, within
  the caller's permissions and the node.

* **The order of the checks.** The run, as it will run (the preset's values
  with the overrides), is checked in this order: an unknown preset is
  `preset_denied`; a value out of range is `invalid_argument` and a reserved
  key away from its default `unsupported` (exit 4, nothing stored); each option
  that adds risk has its permission (else `permission_denied`, with every
  missing permission in `details.needs`): a live route its `route.*`, root or an
  id below 1000 `run.as_root`, a core on exit or from the dump trigger
  `evidence.core_dump`, a memory dump `evidence.memory_dump`, Check online
  `lookup.online`, keeping the VM `run.keep_vm`; the node has it (a live route,
  a kept VM or another lane group is `unavailable_on_node`); the priority and
  the run time are within the caller's limits when it has any, and the run
  time, the largest sample and the static size limits within the node
  ceilings (else `limit_exceeded`, `details.source` `caller` or `node`), and so
  is the number of runs of the last 24 hours when the caller has a daily limit
  (none by default; the refusal's `details.next_at_ms` says when the next run
  becomes possible). Each of the last three is stored as a `rejected` run (exit
  13) with the code, the field (a preset key, `network.route`) and the details.

* **Who holds which permission.** The owner on the local socket (the CLI and
  `auto daemon`) holds every permission. A watch folder submits with
  `runs.submit` and the folder's `permissions` in `service.toml` (see
  `service-config.md`), and runs its preset unchanged: a folder whose preset
  takes cores (Deep) needs `permissions = ["evidence.core_dump"]` and more.
  When a run starts, prechecks asks again: a permission taken away while the
  run waited (a reload) ends it `failed` with `permission_denied`.

* **A run freezes its preset.** The name, the digest and every option are
  stored with the run. Editing or removing a preset, or `SIGHUP`, changes only
  runs submitted afterwards: a waiting run keeps the preset it froze. `auto
  retry` of a run of an unchanged preset uses the preset as it is now; of a
  Custom run, its resolved options (it is Custom again).

* **Static checks and required checks.** `[static_analysis]` runs the library
  copy's tools before the Triage scan: `triage_checks` (the eleven by default),
  `deep_checks` (`disassembly`, `decompilation`, `floss`; none by default),
  with `enabled = false` none. A check that runs out of its time (2 x its
  expected time, or `time_limit_per_tool_min` when it is above 0, stretched on a
  busy host like the guest waits) or stops short does not fail the run: the run
  ends `partial` with a `static_check_incomplete` warning that names the check.
  List checks in `static_analysis.required_checks` (default none) to make their
  timeout, or their being unavailable, a failure of the `analyse` stage; with
  `required_stages` naming `analyse` that ends the run `failed` with
  `analysis_failed`. A static analysis the engine refuses or cannot run at all
  is a failure of the stage whichever checks are required. The size limits
  (`[static_analysis.limits]`) and Ghidra for Disassembly are passed to the
  engine.

* **Dump on suspicious activity.** `dumps.dump_when_suspicious = true` makes the
  run take a dump while the program runs, when the live Triage rules match at
  `dumps.minimum_tier` (`low`, `medium`, `high`; default `high`) or above:
  `trigger_core` (default on; a core of the process that made the call, within
  `core_budget_mib` and `core_deadline_ms`, needs a revision-16 base) and
  `trigger_memory_dump` (default off), at most `max_dumps` (1) dumps
  `dumps_apart_s` (30) seconds apart. The program is not stopped. The run's
  `run.triggers` lists each match (rule, tier, process, call, and the state and
  size of each dump; the path only for a local caller), `run.trigger_notes` says
  when it was armed and nothing matched, and `run.trigger` events report them as
  they are known.
When the guest-side static analysis is still running after the 300 s evidence wait,
the recording is saved without it and the run succeeds; `run.pending` lists
`analysis`.

* **Non-resident pages in trigger cores.** `dumps.read_non_resident_pages = true`
  (default `false`) makes the cores the dump trigger takes also read the pages that
  are not in memory (swapped out, or file pages the kernel dropped), as the window's
  **Read non-resident pages**; slower, bounded by the core budget and deadline. It
  needs a trigger core (without one `config validate` warns; an exit core
  always reads resident pages) and a base of guest contract revision 22 (on an older
  one the cores hold resident pages only and the run carries the warning
  `core_nonresident_unsupported`).

* **Routes.** In 0.9.0 a run may use `drop` (the default: every connection a sample
  tries is captured and dropped) or `inet_sim` (simulated internet services); neither
  needs a permission. A run asking for a live route (`internet`, `nat`, `tor`,
  `vpn[:NAME]`, `socks5[:NAME]`) needs its `route.*` permission and is then refused
  `unavailable_on_node`: no live route is set up for the service before 0.9.1. In a
  preset file, a live route is "not set up on this node" for `config validate`.
* **Accepted samples.** `[accepts]` of Standard takes ELF x86-64 programs and
  shell scripts (`types = ["elf", "sh"]`). A script has no architecture, so
  `arch` applies to ELF files only.
* **Duplicates.** `[duplicates] on_duplicate` is `run` (analyse again; the new run has
  `repeat_of`), `reuse` (return the earlier run) or `reject` (`duplicate_denied`).
  `reuse` returns only a run the caller may see (its own, or any with
  `runs.see_all`); otherwise a new run starts.
* **The label.** A succeeded run has the raw Triage assessment, a label
  (`malicious`, `suspicious`, `clean_observed`, `inconclusive`), an optional score
  and the `basis` sentence that says why. `clean_observed` means nothing was seen
  in this run, not that the sample is clean. `[verdict] mapping = "default"` is the
  built-in mapping; `[[verdict.rule]]` entries replace it.

Check the files without starting anything: `antinomie-cli --data-dir ~/auto
config validate`. It prints `file:line:column: error: message` for each problem
and exits 4 when there is an error. All keys are in
[service configuration](service-config.md).

**From 0.9.0 policies.** `<data>/policies/` is not read any more: `config
validate` lists every key of every file there with its new home
(`run.timeout_s` is `program.run_time_s`, `run.allow_root` the permission
`run.as_root`, `[access]` the caller's permissions, `[limits]` limits of the
caller, `[vm] revert` and `revert_to` the `[lanes]` table of `service.toml`, and
so on), and the daemon does not start until the folder is gone.

## Revert: how the lane stays clean

A VM that ran a sample keeps what the sample did, so every run starts from a known
state. The lane VM has a clean Disk snapshot, `auto-clean`, taken by `auto init`
after the guest booted once and finished booting (a guest stopped while its
initramfs still grows the root file system would keep a half-grown one, and every
run's boot from it would crash the guest kernel). Before each run the daemon checks the snapshot is the
one it recorded, restores it and cold-boots (`[lanes] revert = "snapshot_disk"` in
`service.toml`, the default). `revert = "reset"` is not available on Auto lanes, because every lane
keeps its clean snapshot: `config validate` refuses it and points at
`snapshot_disk`, which gives the same clean disk. `snapshot_full`
resumes a booted guest and needs the VM to be created and snapshotted headless,
with a full (memory) snapshot: over the disk-only `auto-clean` it could only boot
cold, so `config validate` refuses it.

A lane is cleaned when the next run starts: after a run its VM stays stopped on
the used disk until then. (A node setting that also reverts right after a run
arrives with 0.9.1.)

**Quarantine.** A lane stops taking runs when the restore failed twice, when its
clean snapshot is not the recorded one (somebody used the VM by hand), or after three
starts in a row that did not reach a working guest. Queued runs stay queued with
`waiting_for: lane_quarantined` and an `engine.alert` is raised. Fix the cause, then:

* `auto lane list` shows whether the lane is quarantined and what keeps it from a
  run;
* `auto lane reset --yes` reverts the VM to its clean snapshot now and lifts the
  quarantine when that works;
* `auto lane unquarantine` lifts it without reverting, when the checks pass.

After a base update make a new lane VM with `auto init --replace`.

With several lanes a quarantine holds only its own lane: the other lanes go on
with the queue, and runs wait (`waiting_for: lane`) only for what no other lane
can run. `auto lane list` shows every lane; `reset` and `unquarantine` take
`--lane lane-N` (default `lane-1`).

## Several lanes

One lane runs one VM at a time. A machine with the memory for more VMs can run
up to four lanes, each with its own lane VM, so up to four runs run their VMs
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
  engine settings and route settings. The job store, the presets and the host
  work pool are one for all lanes.
* A lane starts when its VM exists and the machine has `MemAvailable` for the
  RAM of every lane VM before it plus this lane's own floor (its VM's RAM plus
  2048 MiB, or `[resources] min_free_ram_mib`). The daemon's log says how many
  lanes started and why the others did not; so does `auto lane list`.
* A run goes to a free lane that can run it (the base of `[lanes] vm`, and an
  ELF of the lane's architecture); among several, the least recently used, so
  the runs spread. With `[lanes] vm = "auto-1"` (the default) a run runs on
  every lane built on lane 1's base: 0.9.0 has one lane group.
* Every lane's host work goes to the one host work pool, first come, first
  served by run arrival; `[daemon] host_workers` is the total for all lanes.
* A run stays in the folder of the lane that recorded it (`<data>/lanes/N/`
  for lane N). Every read from the data folder finds the runs of all lanes:
  `recording list` (`--vm`, `--run`), `recording show`, `recording export`, `triage`, `detect`,
  `report`, `sample show --runs`, and the `recording.*` operations of the
  daemon, the same through the daemon and with `--direct`. A lane that
  `[daemon] lanes` no longer starts is still read. A run shows its lane
  (`auto status RUN`); retention and `auto delete --with-recording` delete
  the run in its own lane's folder. A lane folder is read only when its
  `lane.json` names its place, never through a link.

All the keys are in [service configuration](service-config.md#several-lanes).

## Watch folders

A folder the daemon polls every two seconds; each file that appears becomes a run.
Configure it in `service.toml`:

```toml
[[inbox.watch]]
path = "/srv/drop/default"       # absolute, owned by the daemon's user
preset = "standard"              # run unchanged
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
own route, only the preset decides. `auto watch list` shows each folder's state
and what was taken or refused; `auto watch scan` scans now.

With the system unit, add the folder to `ReadWritePaths` (see [Run it under
systemd](#run-it-under-systemd)).

## Results and the command hook

Reports are always in the run's folder (`auto artifacts RUN`, `auto fetch RUN
KIND`). Two optional channels deliver a finished run without a client:

* `[results] dir = "/srv/results"` writes `<dir>/<yyyy-mm-dd>/<sha8>-<runid>/` with
  `job.json` and the non-sensitive reports (not the capture or other sensitive
  files), mode 0600 in 0700 folders.
* `[notify] on_finish = ["/usr/local/bin/hook"]` runs that command when a run ends.
  It is run directly, never through a shell, with an empty environment plus
  `ANTINOMIE_RUN_ID`, `ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and
  `ANTINOMIE_RESULT_JSON` (the path of `job.json`). Nothing a run controls is in its
  arguments or environment. It has 30 s; past that it and what it started are
  killed. Its output goes to the run's `job.log`.

Delivery is at least once and never changes the run: a failure is a log line and
an `engine.alert` (`result_drop_failed`, `hook_failed`).

## Retention and clean-up

| What | Kept for | Setting |
|---|---|---|
| Recordings of auto runs | 14 days | `[retention] recordings_days` |
| Recordings above the size cap | oldest go first above 200 GiB | `[retention] max_recordings_gib` |
| Recordings of failed runs | until the run record goes | `[retention] keep_failed` |
| Run records, events and reports | 90 days | `[retention] jobs_days` |
| Staged uploads | 24 hours | fixed |
| `<inbox>/rejected/` files | 7 days | fixed |

The daemon runs a pass an hour (the first one minute after it starts). It never
touches the library, never deletes a sample and never removes a run that has not
ended; a recording that is being read, or whose evidence is still being written,
is skipped and taken in a later pass. A recording goes through the app's own
deletion, which keeps its kept files. A run retried after its launch (a lost
guest, a stop or a restart of the daemon) recorded a run for each such attempt:
retention and `--with-recording` delete all of them, and the run record stays
until they are gone. A recording kept in a VM's recordings folder outside the
data folder is handled the same way; a recording that cannot be read keeps its
run record, so it is never left with nothing naming it. `auto gc --dry-run` prints what a pass would
delete; `auto gc` runs one; `auto delete RUN [--with-recording]` removes one ended
run. Without a daemon these take the data folder for the command.

## Failure codes

A failed run has a `failure` with a code, shown by `auto status RUN`,
`auto result RUN` and the run's `run.finished` event. The exit code of a waited run
is 10 for `failed`, 11 for `partial`, 12 for `cancelled`, 13 for `rejected`.

| Code | Stage | Retried | What it means and what to do |
|---|---|---|---|
| `sample_missing`, `sample_too_large`, `sample_type_denied`, `sample_arch_denied`, `duplicate_denied` | submit | no | The intake refused the file; the size limit is the smallest of 256 MiB, the preset's `accepts.max_sample_mib` and a quarter of the lane VM's RAM |
| `permission_denied` | submit, prechecks | no | The caller lacks a permission the run uses (`details.needs`), or lost it while the run waited; `field` names the option |
| `preset_denied` | submit | no | There is no such preset (`details.preset`); nothing is stored |
| `limit_exceeded` | submit | no | The priority, the run time or the runs of the last 24 hours are above the caller's limit, or a value is above a node ceiling (`details.field`, `details.limit`, `details.source` `caller` or `node`; `details.next_at_ms` for the daily count); the caller's limits are set in `service.toml` `[limits.local]` and per watch folder `priority_max` |
| `unavailable_on_node` | submit | no | The node does not have it: a live route, keeping the VM after a failure (both arrive with 0.9.1), or another lane group; `details.what` |
| `quota_exceeded`, `dependency_missing`, `host_resources` | prechecks | waits | The queue is full, a tool is missing (`doctor`), or the disk, RAM or KVM floor is not met. The run waits `queued` for up to `[queue] wait_s` (3600), then fails |
| `no_base`, `no_vm` | provision | no | The lane VM or its base is gone; `auto lane list` says which |
| `vm_start_failed`, `guest_unreachable` | provision, launch | yes | The VM or its guest did not come up, or the guest kernel crashed while it booted (the crash line is the detail); three in a row quarantine the lane |
| `revert_failed`, `lane_changed` | provision | no | The lane is quarantined (see above) |
| `upload_failed` | upload | yes | The sample did not reach the guest |
| `launch_failed` | launch | depends | The program did not start (not executable for the guest, no terminal) |
| `guest_lost` | run, collect | once | The guest or QEMU died. A sample that does that twice ends `failed` |
| `recording_failed` | collect | once | The recording could not be completed |
| `analysis_failed` | analyse, report | yes | Only when the preset marks the stage required (`required_stages`); otherwise the run is `partial` with a warning. A static check that only timed out or stopped short is not this failure unless it is in `static_analysis.required_checks` (it is a `static_check_incomplete` warning and the run is `partial`) |
| `deadline_exceeded` | analyse, report | no | The host stages passed their deadline (`host_time_factor` x the expected work, see "Time limits"): the running items were stopped (`timed_out`), the queued ones never started; what finished is kept. A busy host or too low a factor; try again later or raise `host_time_factor` |
| `cancelled` | any | no | Cancelled by request; what was recorded is kept |
| `internal` | any | maybe | A bug, or the watchdog: the whole run ran past `run` plus 30 minutes. `details.log` names the run log |

A retry starts with a full revert. `backoff_s` (30 s, then 120 s) spaces the
attempts and `max_attempts` bounds them: 1 to 10 attempts, at most 10 delays
of 0 to 3600 s each.

## Troubleshooting

**Exit 21, "data directory is owned by ...".** The window, the daemon or another
command has the folder. `doctor` shows the owner (`data_dir.owner`). Stop it, or use
another folder. A run submitted with `--daemon` exits 21 when no daemon answers.

**Exit 20, a dependency is missing.** `antinomie-cli doctor` lists each tool. On
Debian or Ubuntu install `qemu-system-x86 qemu-utils qemu-system-gui bubblewrap
util-linux tshark curl`. Bubblewrap must work: on Ubuntu 24.04 an AppArmor setting
(`kernel.apparmor_restrict_unprivileged_userns`) can forbid it; the run then stops
with `dependency_missing` instead of running unsandboxed.

**Runs stay `queued`.** `auto status RUN` shows `waiting_for`: `lane` (busy),
`resources` (below `min_free_disk_gib` or the RAM floor, the queue pauses),
`dependency`, `quota`, `queue_paused`, `layer_pending` (the previous run's disk is
still being saved, which can take minutes after a run that changed many files),
`backoff` or `lane_quarantined`. A file `<data>/run/PAUSE` pauses admission on
every lane within five seconds, also while other lanes run runs (a lane running a
run starts no other until it ends); `auto queue resume` or removing the file
continues. Low disk and a missing KVM pause every lane the same way.

**The disk filled up during a run.** The running program is stopped within a
minute and the queue pauses (`low_disk`), also when the run database itself is
too full to record the pause. A run whose end cannot be written yet waits for room
(it shows its last stage meanwhile) and ends as soon as there is; if the recording
could not be finished it ends `recording_failed`, and the lane waits
(`layer_pending`) until the engine has finished the recording, which it tries again
every 30 seconds. Free space under the data folder: the pause lifts by itself.

**No KVM.** With `require_kvm = true` (the default) runs wait until `/dev/kvm` is
usable; the daemon user must be in the `kvm` group. Set `[resources] require_kvm =
false` to run with TCG, which is slow.

**The daemon does not stop.** On `SIGTERM` it stops the running run through the
engine and finishes in a few minutes at most (`TimeoutStopSec=360` in the unit); a
run that has not left the VM 240 seconds after the stop (a recording that cannot be
saved on a full disk, say) is left for the next start. A
second `SIGTERM` or Ctrl-C within five seconds stops at once with exit 130; the next
start finishes what was left: it removes stale guest RAM files, finishes a pending
disk layer (up to 30 minutes), and puts a run that was running back in the queue
without using an attempt.

**A change to a preset is ignored.** Runs already queued keep the preset they were
submitted with. Send `SIGHUP` (`systemctl reload antinomie-auto`); a file with an
error keeps the old settings, so run `config validate` first.

**What happened to a run.** `auto events RUN` lists its events; `<data>/service/jobs/<id>/job.log` has its log lines;
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
| `KillMode=mixed`, `TimeoutStopSec=360` | QEMU is a child of the daemon. `systemctl stop` sends `SIGTERM` to the daemon alone, which stops the running run and its VM and exits. Only what is still alive after 360 s (the 120 s VM stop plus up to 120 s for a run already in its host stages and the disk-layer step) gets `SIGKILL`, QEMU included. With `[daemon] shutdown = "drain"` raise it above `drain_timeout_s` |
| `ExecReload` | `systemctl reload` sends `SIGHUP`: presets and `service.toml` are read again |
| `NoNewPrivileges`, `CapabilityBoundingSet=` (empty), `RestrictSUIDSGID`, `LockPersonality`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | The daemon needs no privilege: QEMU opens `/dev/kvm` through the `kvm` group and bubblewrap uses unprivileged user namespaces |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `StateDirectory` | The only writable place is the data folder. Add other folders (a watch folder, `[results] dir`, a log file) with `systemctl edit antinomie-auto` and `ReadWritePaths=` |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces=user mnt pid ipc uts net` | QEMU's user-mode network, the local socket and bubblewrap's namespaces, and nothing else |
| `DevicePolicy=closed` with `/dev/kvm`, `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx` and the pseudo-terminals (system unit) | Not `PrivateDevices`, which would hide `/dev/kvm`. A user manager cannot set a device policy, so the user unit has none |
| No `MemoryDenyWriteExecute`, `ProcSubset` or `SystemCallFilter` | QEMU's TCG and the YARA-X engine generate code at run time, the resource floors read `/proc/meminfo`, and bubblewrap needs mount and namespace calls |

Read the log with `journalctl -u antinomie-auto` (`journalctl --user -u
antinomie-auto`). `systemd-analyze security antinomie-auto.service` scores the
unit. The Docker equivalent of this unit comes with the web interface in 0.9.1.
