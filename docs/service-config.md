# Service configuration and presets

[← Back to the overview](../README.md)

> **Status in 0.9.0.** The files, their keys and `antinomie-cli config validate`
> are checked, and `antinomie-cli auto daemon` acts on all of them: the socket, the
> queue limits, the resource floors, the shutdown keys, the reload on `SIGHUP`, watch
> folders, retention, result files, the `on_finish` command, `[query]`, `[privacy]`
> and `[log]`. Webhooks are not part of 0.9.0: `[[notify.webhooks]]` and a changed
> `[query] scan_cache_mib` are refused by `config validate` and stop the daemon's
> start. [Auto mode](auto-mode.md) explains them.

Headless mode reads two kinds of file from the data directory. A person writes
them; the program never rewrites them.

| File | Purpose |
|---|---|
| `<data>/service.toml` | Daemon behaviour: socket, lanes, queue limits, inbox, retention, notifications, resource floors. Optional: without it every default applies. |
| `<data>/presets/<name>.toml` | A preset: a named set of run options to start from (the program, the network, dumps, static analysis, detection, the report, what it accepts, retries). The file name is the preset name (`[a-z0-9._-]`, not `custom` and not a built-in one). Optional: five presets are built in. |

An unknown key is an error, in both files. Check the files without starting
anything:

```text
antinomie-cli config validate [--preset NAME]
```

Each problem is printed as `file:line:column: error|warning: message`. The exit
code is 0 when there is no error (warnings are listed) and 4 when there is one.
With `-o json` the problems are in `result.problems` (success) or
`error.details.problems` (failure). The command only reads files, so it also
runs while a window or the daemon owns the data directory.

## What is checked

- Keys and types, with the line of the key. A key of a 0.9.0 policy in a preset
  is an error that names its new home (`run.timeout_s`: "presets have
  `program.run_time_s`").
- The node ceilings: `accepts.max_sample_mib` 1 to 256, `program.run_time_s` 5
  to 1800, `dumps.core_budget_mib` 64 to 1024, `dumps.core_deadline_ms` 1 to
  60000, `dumps.max_dumps` 1 to 8, `dumps.dumps_apart_s` 0 to 3600,
  `static_analysis.time_limit_per_tool_min` 0 to 480, each
  `static_analysis.limits.*` within the range of the app's Settings, at most 64
  arguments and 64 `NAME=value` environment entries, absolute
  `program.guest_path` and `program.working_directory`.
- `dumps.dump_when_suspicious` must take something (`trigger_memory_dump` or
  `trigger_core`); `read_non_resident_pages` without a trigger core is a
  warning. `static_analysis.triage_checks` take the eleven Triage checks,
  `deep_checks` only `disassembly`, `decompilation` and `floss`.
- The keys 0.9.0 reserves are accepted at their default only, else an error
  "arrives with 0.9.1": `program.source` (`upload`), `executable` (empty),
  `preload` and `extra_files` (empty), `run_in` (`app_terminal`),
  `record.scope` (`program`), `record.screenshot_every_s` (0),
  `network.private_addresses` (false), `abuse_filter` (true),
  `dumps.disk_dump` (false), `vm.keep_on_failure` (false),
  `static_analysis.rebuilt_file_mib` (16) and `rebuilt_run_mib` (256),
  `triage.written_*` and `earlier_*` (64 and 1024), `detection.scan_every_min`
  (0), `report.sections` (`"all"`).
- A live route (`internet`, `nat`, `tor`, `vpn[:NAME]`, `socks5[:NAME]`) is
  "not set up on this node": no route is set up for the service before 0.9.1.
  `drop` and `inet_sim` need nothing; `inet_sim` needs a routed lane VM.
- `vm.lane_group` must be the node's (`[lanes] group`, default `x86_64`).
- `required_stages` must not name a stage the preset skips.
- The lanes (`[lanes]`, the VM `[lanes] vm` found in the data directory): its
  network must match `[lanes] network`; `reset` is refused when the VM has
  snapshots, which every Auto lane has (use `snapshot_disk`); `snapshot_disk`
  and `snapshot_full` need the snapshot named by `[lanes] revert_to`
  (`snapshot_full` is refused over a disk-only snapshot, from which it could
  only boot cold); `[lanes] stealth` is compared with the VM's profile and
  never applied. NAT is never valid for a lane.
- `service.toml`: `daemon.lanes` 1 to 4 (default 1), no `safety.unsafe_routes_ack`
  (reserved), absolute watch folder paths, watch folders that name a preset that
  exists (`policy` and `policy_by_dir` of 0.9.0 are errors naming `preset` and
  `preset_by_dir`). `[[notify.webhooks]]` is an error ("not supported in 0.9.0"), and so is
  a `[query] scan_cache_mib` other than 1024: the daemon keeps 2 scans in memory
  whatever it says.
- A `policies/` folder (0.9.0 before presets) is an error: each key of each
  file is listed with its new home, and the daemon does not start until the
  folder is gone. No converter ships.

## The daemon's keys

| Key | Default | What the daemon does with it |
|---|---|---|
| `[daemon] socket` | `<data>/run/antinomie.sock` | The local socket (at most 107 bytes). Its folder must be the daemon user's own with mode 0700; the socket is 0600. Not changed by a reload |
| `[daemon] host_workers` | 2 | How many host work items (a static tool, the Triage scan, the detection engines, the assessment, a report) run at once, across every job: the host work pool. 1 to 8 |
| `[daemon] host_time_factor` | 2 | A host work item may take this many times its expected time (the larger of its recent median on this host and an estimate from the sample or recording size, else the stage's fixed limit), at least 30 s; a job's host stages may take this many times the expected work ahead of it plus its own, and never less than this many times the work ahead plus its own items' limits. 1 to 20 |
| `[daemon] stop_grace_s` | 30 | A host work item stopped by its time limit or by its job's host-stage deadline gets SIGTERM (its sandboxed tool's process group; in-process work its cancel flag), then SIGKILL after this many seconds. At the deadline the job fails `deadline_exceeded`; its finished items are kept and the stopped ones are `timed_out`. 0 to 600; 0 kills at once |
| `[daemon] lanes` | 1 | How many lanes (engines, each with its own lane VM) the daemon runs: 1 to 4. See [Several lanes](#several-lanes). Not changed by a reload |
| `[daemon] shutdown` | `cancel` | On the first `SIGTERM`/`SIGINT`: `cancel` sends a job in its lane stages back to the queue (attempt not counted); `drain` lets it run on for up to `drain_timeout_s` first |
| `[daemon] drain_timeout_s` | 600 | See `shutdown = drain` |
| `[daemon] shutdown_host_grace_s` | 120 | The host work pool goes on with the jobs it holds (their `analyse`, `report`, `cleanup` items) for this many seconds at shutdown; past it those jobs are left `running` and go back to the pool on the next start, in the same order (the VM does not run again) |
| `[queue] max_queued`, `per_client_queued` | 1000, 100 | `job.submit` fails `quota_exceeded` above them (the smaller of `per_client_queued` and the caller's `max_queued` limit applies) |
| `[queue] paused_on_start` | false | Start with the queue paused (`queue.resume` starts it) |
| `[queue] wait_s` | 3600 | How long a run may wait `queued` for resources, a dependency or a pending disk layer before it ends `failed` (was a policy's `limits.wait_s`) |
| `[limits.local]` | none set | The limits of the owner on the local socket (`local:<uid>`), every key optional: `priority_max` (0 to 9; a run asking for more is refused `limit_exceeded`, no run is lowered silently), `max_run_s` (5 to 1800), `max_queued` (queued runs of this caller; the smaller of it and `per_client_queued` applies), `max_running` (runs of this caller running at once; its next run waits `queued` with `waiting_for` `quota` while the caller is at the limit, the other callers' runs go on), `max_runs_per_day` (runs accepted in the last 24 hours, refused `limit_exceeded` past it; **not counted unless set**). A key set to 0 fails the load: leave it out for no limit. A reload changes them for the next submit |
| `[lanes] group` | `x86_64` | The lane group of this node: every lane belongs to it, and a preset names it in `vm.lane_group` |
| `[lanes] vm` | `auto-1` | Lane 1's VM: what `config validate` checks, and the base the lane choice compares |
| `[lanes] revert`, `revert_to` | `snapshot_disk`, `auto-clean` | How a lane is made clean when the next run starts (`snapshot_disk`, `snapshot_full` or `reset`) and the clean snapshot |
| `[lanes] stealth`, `network` | unset, `routed` | The profile and the network card the lane VM must have; checked, never applied |
| `[inbox] dir` | `<data>/inbox` | Where uploads are staged (`uploads/`), and where watched files go after intake (`processed/`) or on failure (`rejected/`) |
| `[inbox] processed_keep_days` | 7 | Retention removes the plain files of `<inbox>/processed/` older than this many days (at least 1) |
| `[resources] min_free_disk_gib`, `min_free_ram_mib`, `require_kvm` | 20, VM RAM + 2048, true | The floors of the queue: below one, jobs wait `queued` and the queue pauses (`low_disk`, `no_kvm`); checked every 5 s, and the disk every minute of a run. A `run/PAUSE` file pauses the queue within 5 s |
| `[query] light_concurrency`, `heavy_concurrency` | 16, 2 | Reads of each class in flight at once (the two pools of the query API); one more heavy read fails `quota_exceeded` (`heavy_read_limit`), and `heavy_concurrency` also caps the Triage scans that run at once. They appear in `capabilities.queries.limits` |
| `[query] light_timeout_s`, `heavy_timeout_s` | 10, 60 | The deadline of a light read and of a heavy read page; a read that passes it fails `unavailable` (`read_timeout`). A request's own `deadline_ms` replaces it |
| `[query] scan_cache_mib` | 1024 | The only value accepted in 0.9.0. The daemon keeps 2 Triage scans in memory (least recently used out); a size cap is not built, so another value is refused |
| `[privacy] address_lookup` | `off` | `off`: a Triage scan the daemon runs (a `triage` or report read, a job's host stages) makes no address lookup at all. `tshark`: TShark's installed GeoIP fields fill the country and organization of public addresses. `dig` and `whois` are never used by the daemon |
| `[log] level` | `info` | `error`, `warn`, `info`, `debug` or `trace`: the lines below it are dropped. The daemon's own lines are written at `info`; `error` and `warn` therefore silence them, and the audit lines of sensitive reads (`sensitive read: caller=...`) are written at every level |
| `[log] format` | `text` | `text` or `json`, one line each |
| `[log] file` | standard error | Append to this file (mode 0600, its folder is created) instead of standard error; it rotates at 10 MiB and keeps 5 files (`daemon.log`, `daemon.log.1` to `.4`). A file that cannot be opened stops the start |
| `[[notify.webhooks]]` | none | Not part of 0.9.0: refused by `config validate` and at the daemon's start. Use `[notify] on_finish`, or poll `job.get` / `auto events` |

**Flags and the file.** A command line flag wins over the file: `-q` (errors
only), `-v` and `-vv` (debug, trace) replace `[log] level`, and `--log-format`
replaces `[log] format`; without a flag the file applies, and without a file
the defaults. `[log] file` has no flag. `--socket` likewise replaces
`[daemon] socket`. `[query]`, `[privacy]` and `[log]` are read at the start;
`SIGHUP` does not change them (restart the daemon).

Commands that reach the daemon read `[daemon] socket` from `<data>/service.toml`
the same way, so a configured socket needs no `--socket` on the client side; `--socket`
wins over the file, and a missing or faulty file means the default path.

A second `SIGTERM`/`SIGINT` within 5 s interrupts every wait at once, stops the
VM and exits 130; recovery at the next start finishes the rest. `SIGHUP` reads
`presets/` and `service.toml` again (a file with an error keeps the old set);
`SIGUSR1` writes the queue's state to the log.

## Several lanes

One lane is the default and the right choice for most machines. With
`[daemon] lanes = N` the daemon runs N lanes at once, each an engine of its own
with its own lane VM, so N jobs run their VMs side by side.

| Lane | Data folder | Made by |
|---|---|---|
| `lane-1` | the data folder itself | `antinomie-cli auto init` |
| `lane-N` (2 to 4) | `<data>/lanes/N/` | `antinomie-cli auto init --lane N` (stop the daemon first) |

- **What the lanes share.** Every lane uses the data folder's bases, sample
  library, rules, tools, IOC data, Volatility plugins, engine settings
  (`settings.json`) and route settings (`network/routes.json`); only the data
  folder (lane 1) changes them. A lane keeps its VMs, runs and Tor state in its
  own folder. The job store, `service.toml`, the presets and the lane files
  (`<data>/service/lanes/lane-N.json`) are the data folder's.
- **Which lanes start.** Lane 1 always does. Lane N starts when it has a lane VM
  and when `MemAvailable` covers the RAM of the lane VMs that start before it
  plus its own floor (`[resources] min_free_ram_mib`, default its VM's RAM plus
  2048 MiB). The lanes start in order: the first one refused for memory stops
  the count. The log says how many lanes started and why the others did not
  (`lanes: 2 of 3 started (lane-1, lane-2); lane-3 not started: the RAM floor
  is not met: ...`); `auto lane list` says it per lane.
- **Which lane takes a job.** A free lane that can run it: the lane's base must
  be the base of `[lanes] vm` (when that VM is one of the lanes'),
  and an ELF must be of the lane's architecture (x86-64 also runs i386 programs,
  arm64 32-bit ARM ones). When several such lanes are free the least recently
  used takes it, so jobs spread over the lanes. A job no lane can run goes to a
  free lane as with one lane, and its run says why it failed. The queue order
  (priority, then age) does not change.
- **Each lane on its own.** Each lane has its own floors (its VM's RAM and its
  recording folders), its own quarantine and failure count, and its own revert.
  A quarantined lane takes no job while the others go on; `health` stays ready
  while one lane can take jobs.
- **One host work pool.** The host work of every lane's jobs goes to the one
  pool: `[daemon] host_workers` items at once in total, first come, first served
  by job arrival whatever lane ran the job (inside a job, an item whose
  dependencies have ended may start while an earlier one waits for its own).
- **Recovery.** After a crash every lane's interrupted job goes back to the
  queue, and the jobs that had finished `collect` on any lane go back to the
  host work pool in the order they arrived.
- **One engine stopping** stops the daemon (the unit file restarts it).

## Watch folders

```toml
[[inbox.watch]]
path = "/srv/drop/default"      # absolute; the folder itself must not be a symbolic link
preset = "standard"             # an existing preset, run unchanged
recursive = false               # follow subfolders (8 deep at most)
preset_by_dir = false           # subfolders named after presets pick the preset
delete_after = "move"           # move (to <inbox>/processed/), delete, or keep
on_duplicate = "run"            # optional: replaces the preset's rule for this folder
allow_group_write = false       # see below
watch_rate = 10                 # new jobs a minute before the folder pauses
permissions = []                # held beside runs.submit, e.g. ["evidence.core_dump"]
priority_max = 5                # optional: the highest priority (0 to 9) its runs may ask for
```

A folder submits as the client `auto:policy-<preset>` holding `runs.submit` and
the folder's `permissions` (dotted keys of the permission list; an unknown key
fails the load). A run whose preset options need a permission the folder lacks
is rejected `permission_denied` and the file is counted as rejected: a preset
with `core_dump_on_exit = true` or a trigger core needs `"evidence.core_dump"`
(Deep needs it), a memory dump `"evidence.memory_dump"`, `check_online = true`
`"lookup.online"`. A reload that takes a permission away also refuses the
folder's jobs still waiting (`permission_denied` at prechecks). A folder's runs
ask for the default priority 5, or the folder's `priority_max` when that is
lower (a run is never refused for the default). The folder's client is named
for the preset, so folders of one preset share its queue and daily counts.

The daemon scans each folder every 2 seconds. A file is taken once its size,
modification time and change time have been the same for 3 seconds (so a file
that is still being copied in waits), and never while its name starts with `.` or
ends in `.part`, `.tmp` or `.crdownload`. Files already there at the start are
taken in name order. Nothing in a folder can change the job: there are no
sidecar files, and the preset decides every option.

What is refused, and what happens to it:

| Case | Result |
|---|---|
| The folder is writable by everyone | Not used, ever (`engine.alert` `watch_folder_refused`, shown by `auto watch list`) |
| The folder is writable by its group | Not used unless `allow_group_write = true` |
| The folder belongs to another user | Not used; with `allow_group_write = true` it is used when its group is one the daemon is in |
| A symbolic link, device, FIFO, socket or directory where a file should be | Refused and left alone; never opened. Subfolders that are links are not entered |
| A file with more than one hard link | Refused and left alone (it may be reachable from outside the folder) |
| A file of another user | Refused and left alone; with `allow_group_write = true`, a file of the folder's group (when the daemon is in it) is taken |
| A file intake rejects (type, architecture, size, the duplicate rule) | Moved to `<inbox>/rejected/<time>-<name>` with `<time>-<name>.reason` (the failure code and its words); not tried again |
| The queue is full, or the preset no longer exists | The file stays; the folder waits a minute and tries again |
| More than `watch_rate` files a minute | The folder pauses for a minute, `engine.alert` `watch_flood` |

The job's client and its custody actor are `auto:policy-<preset>`, so the
sample's custody chain shows who brought it. The library records the file's folder-relative name as
the origin, never the host path. A `keep`ed file is remembered by device, inode,
size and modification time in `<inbox>/.watch-state.json`, so a restart does not
take it again; a rewritten file is a new file. `SIGHUP` re-reads the folder list.

## Retention

| Key | Default | What is removed |
|---|---|---|
| `[retention] recordings_days` | 14 | The recordings of a finished job older than this (the run of each attempt that launched, in the data folder or a VM's recordings folder), through the engine's run deletion (the run's record is copied into the sample's record; captures and dumps that belong to the VM stay with it, as when the window deletes a run) |
| `[retention] keep_failed` | true | A failed job's recording is kept until `jobs_days` |
| `[retention] max_recordings_gib` | 200 | Above this the oldest recordings go first (those `keep_failed` protects last). At least 1: 0 is refused, it does not mean "no cap" |
| `[retention] jobs_days` | 90 | A finished job's record, events, artifacts and folder; the job's recordings (one per attempt that launched) go with it, or the job stays; a job whose recording cannot be read stays |

Staged uploads expire after 24 hours and files in `<inbox>/rejected/` after 7
days. Files in `<inbox>/processed/` go after `[inbox] processed_keep_days` (7):
plain files only (a folder or a link there is left alone), by their modification
time, with the same dry run and log lines as every other deletion
(`gc: deleted the processed file ...`). Never removed: a job that has not ended,
a recording with an open read (a client reading it through `recording.*`) or whose
capture, dump or core is still being written, the sample library, its custody
chain. Retention also leaves alone the VM-wide captures and dumps of a run it
deletes (they may hold the traffic or memory of other runs of the VM; they go with
the VM, or when you remove them). Each deletion is logged (`gc: deleted the recording of job=... run=...`). The daemon
runs a pass a minute after its start and then every hour; `antinomie-cli auto gc
--dry-run` prints what a pass would do and `auto gc` runs one now.

## Results and the command hook

```toml
[results]
dir = "/srv/antinomie/results"          # absolute
mode = "private"                        # private (default) or group

[notify]
on_finish = ["/usr/local/bin/antinomie-hook", "--flag"]   # absolute path, then fixed arguments
```

`[results] dir`: a job that ends leaves `<dir>/<yyyy-mm-dd>/<sha8>-<jobid>/`
(UTC date of the end) holding `job.json` and the job's reports (HTML, PDF, JSON,
MISP, STIX, Markdown; never the evidence bundle, a capture, a dump or a core). It
is written under a hidden name and renamed, so a poller never sees a half-written
drop. `[results] mode` sets who may read it: `private` (the default) makes files
0600 and folders 0700, so the consumer runs as the daemon's user or the
administrator gives it access to `dir`; `group` makes files 0640 and folders 0750 so
a consumer in the daemon's group can read them (nothing is ever writable by the
group or others, whatever the umask). Any other value is an error in `config
validate`. A link where `dir` should be is refused.

`[notify] on_finish`: the command is run **directly**, without a shell, with
exactly the arguments you configured; nothing a job controls is in them. Its
environment is empty except:

| Variable | Value |
|---|---|
| `ANTINOMIE_JOB_ID` | the job id |
| `ANTINOMIE_STATE` | `succeeded`, `partial`, `failed`, `cancelled` or `rejected` |
| `ANTINOMIE_LABEL` | `clean_observed`, `suspicious`, `malicious`, `inconclusive`, or empty |
| `ANTINOMIE_SHA256` | the sample's SHA-256, or empty |
| `ANTINOMIE_RESULT_JSON` | the absolute path of the job's `job.json` |

It runs as the daemon's user with `/dev/null` as input and `/` as its working
folder (set your own `PATH` in the command if it needs one). After 30 seconds the
command and what it started (its process group) are killed. Its output (64 KiB of
each stream, control characters replaced) is appended to the job's `job.log`, and
its exit code is logged. A drop or hook that fails raises `engine.alert`
(`result_drop_failed`, `hook_failed`) and never changes the job. Delivery is at
least once: `notified.json` in the job's folder records what was done, and after a
restart the jobs that ended in the last 24 hours and were not delivered are
delivered. **A failed hook is not retried**: once the command has run (it exited
non-zero, was killed after 30 seconds, or could not start) the job is marked as
notified and `hook_failed` is raised, so a hook with a side effect never runs twice
for a failure it caused. The at-least-once delivery covers only a daemon that
stopped before it recorded the hook as run. A hook that must not miss a job should
retry inside itself, or poll `[results] dir`. Webhooks are not part of 0.9.0.

## Verdict keys

`[verdict] mapping` is `default` (the mapping of the design: `malicious`,
`suspicious`, `clean_observed`, `inconclusive`); `[[verdict.rule]]` entries (`when`,
`label`, `score`) replace it with rules over a small field set. `[verdict]
tag_library = true` (default false) tags the library sample with
`auto:label=<label>` and `auto:preset=<name>` when a run of the preset ends
(a Custom run: the preset it was based on), under the custody actor
`auto:policy-<name>`; a tag that cannot be written is a job warning
(`library_tag`), never a failure.

## Presets and running jobs

A job freezes the preset it was submitted with: its name, the digest (SHA-256
of the file, or of the built-in text) and every option are stored with the
job. Editing or removing a preset file, or reloading the daemon (`SIGHUP`),
changes only jobs submitted afterwards: a waiting job keeps its preset. A
reload with an error keeps the old presets.

`overrides` in a submit are a partial preset (the same tables and keys as the
file). An override that changes a value makes the run **Custom**: it stores
the name `custom`, the digest of its resolved options, `based_on` (the
preset's name and digest) and `changes` (the dotted keys it changed); an
override equal to the preset's value changes nothing. A preset grants nothing
and locks nothing: the run is checked as it will run, in this order. An
unknown preset is refused `preset_denied`, a value out of range
`invalid_argument` and a reserved key away from its default `unsupported`
("arrives with 0.9.1"); nothing is stored for them. Then an option the caller
has no permission for (a live route, root or an id below 1000, a core or
memory dump, Check online, keeping the VM) is a `rejected` job with
`permission_denied` naming every missing permission in `details.needs`; a live
route, a kept VM or a lane group other than the node's with
`unavailable_on_node`; a priority or run time above the caller's limit (when
one is set) with `limit_exceeded`.

## Uploads and intake

`upload.begin`, `upload.put` (strictly sequential, at most 1 MiB per call),
`upload.finish` (seals the file and records its SHA-256) stage a sample under
`<data>/inbox/uploads/<upload-id>/` (directory 0700, file 0600, sealed files
0400). A staged upload is deleted after intake or after 24 hours. When the
directory is on a separate volume, the service refuses to start unless that
volume is mounted `noexec`.

At `job.submit` the intake opens the sample without following links, refuses
anything that is not a regular file, checks the size against the smallest of
256 MiB, the preset's `accepts.max_sample_mib` and a quarter of the lane VM's RAM
(`sample_too_large`), then the type and architecture against the preset's
`[accepts]` (`sample_type_denied`, `sample_arch_denied`). Only then is the sample added to
the library (origin: Added, source "Automation", the file name and never the
host path) with the caller as custody actor. A script has no architecture, so
`accepts.arch` applies to ELF files only.

## Job store

`<data>/service/jobs.sqlite` (WAL) holds the queue and every job; each state
change is one transaction that also stores its events. `jobs/<id>/events.ndjson`
mirrors the events and `spec.json` holds the stored spec (the preset's name,
the priority and the changed options). After a crash the
daemon puts a job left `running` back in the queue (once per job without using
an attempt) and repairs the mirror files.

## Custody actors

Every custody entry names who caused it: `app` and `analyst` in the window,
`auto:policy-<name>`, `web:<user>` or `local:<uid>` in headless mode. A job's
entries (`added`, `sent`, `run_started`, `run_ended`, `automation`) name its
caller, on every lane at once; the tags the service sets name
`auto:policy-<preset>`. Entries of kind `automation` record the job, the
preset's name and digest (`custom` and the digest of the resolved options for
a Custom run), the route and the submitter. The
bundled `verify-custody.py` accepts them.

## Privacy, query and log

```toml
[privacy]
address_lookup = "off"          # off (default) or tshark

[query]
light_concurrency = 16
heavy_concurrency = 2
light_timeout_s = 10
heavy_timeout_s = 60
scan_cache_mib = 1024

[log]
level = "info"                  # error, warn, info (default), debug, trace
format = "text"                 # text (default) or json
file = "/var/log/antinomie.log" # optional; default standard error
```

| Key | Default | Meaning |
|---|---|---|
| `[privacy] address_lookup` | `off` | How network views resolve addresses: `off` or `tshark` |
| `[query] light_concurrency`, `heavy_concurrency` | 16, 2 | Light and heavy reads of the query API that run at once |
| `[query] light_timeout_s`, `heavy_timeout_s` | 10, 60 | The deadline of one light or heavy read |
| `[query] scan_cache_mib` | 1024 | Memory of the cache that heavy scans share |
| `[log] level`, `format`, `file` | `info`, `text`, standard error | Daemon log level, line format (`text` or `json`) and file |

In 0.9.0 these three tables are read and checked by `config validate` (a zero
query concurrency, timeout or cache size is an error, and so is a value outside
the lists above), but the daemon does not apply them yet: it runs on the defaults
shown, and its log goes to standard error, set by the command line (`--log-format`,
`--quiet`, `-v`), not by `[log]`.

## Webhooks

`[[notify.webhooks]]` is read and checked by `config validate` (HTTPS or loopback
URL, `secret_file`, `events`, `timeout_s`, `retries`, `allowed_hosts`), but the
daemon does not deliver webhooks in 0.9.0: no request is ever sent. Use
`[notify] on_finish` (above) to react to a finished job.
