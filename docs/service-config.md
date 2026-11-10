# Service configuration and policies

[← Back to the overview](../README.md)

> **Status in 0.9.0.** The files, their keys and `antinomie-cli config validate`
> are checked, and `antinomie-cli auto daemon` acts on all of them: the socket, the
> queue limits, the resource floors, the shutdown keys, the reload on `SIGHUP`, watch
> folders, retention, result files and the `on_finish` command. Webhooks are parsed
> and checked but not built. [Auto mode](auto-mode.md) explains them.

Headless mode reads two kinds of file from the data directory. A person writes
them; the program never rewrites them.

| File | Purpose |
|---|---|
| `<data>/service.toml` | Daemon behaviour: socket, lanes, queue limits, inbox, retention, notifications, resource floors. Optional: without it every default applies. |
| `<data>/policies/<name>.toml` | A class of jobs: what it accepts, how the lane VM is reset, run limits, allowed network routes, reports and retries. The file name is the policy name (`[a-z0-9._-]`). |

An unknown key is an error, in both files. Check the files without starting
anything:

```text
antinomie-cli config validate [--policy NAME]
```

Each problem is printed as `file:line:column: error|warning: message`. The exit
code is 0 when there is no error (warnings are listed) and 4 when there is one.
With `-o json` the problems are in `result.problems` (success) or
`error.details.problems` (failure). The command only reads files, so it also
runs while a window or the daemon owns the data directory.

## What is checked

- Keys and types, with the line of the key.
- Ceilings: `sample.max_sample_mib` 1 to 256, `run.max_run_s` at most 1800,
  `run.timeout_s` between 5 seconds and `max_run_s`, `evidence.core_max_mib` at
  most 1024 (and at least 1 with a core `evidence.dump_trigger`; a
  `dump_trigger_kind` or `core_nonresident` with the trigger off is a warning), `analysis.static_time_limit_min` 0 to 480, `limits.priority_max`
  0 to 9.
- Routes: in version 1 a job may use only `drop` and `inet_sim`. A policy that
  lists `internet`, `tor`, `vpn` or `socks5` fails, as does a default
  `network.route` outside `allowed_routes`. NAT is never valid for a job.
- `run.run_in` must be `app_terminal`; `run.run_as = "root"` needs
  `run.allow_root`.
- `analysis.required_checks` lists static checks (default none) whose timeout fails the `analyse` stage.
- `analysis.required_stages` must not name a stage the policy skips.
- The lane VM (`vm.lane_vm`, found in the data directory): its network must match
  `vm.network`; a policy that allows `inet_sim` needs a routed VM; `reset` is
  refused when the VM has snapshots; `snapshot_disk` and `snapshot_full` need the
  snapshot named by `vm.revert_to`; `vm.stealth` is compared with the VM's
  profile and never applied.
- `service.toml`: one lane (`daemon.lanes = 1`), no `safety.unsafe_routes_ack`
  (reserved), absolute watch folder paths, watch folders that name a policy that
  exists, webhooks over HTTPS or on loopback.

## The daemon's keys

| Key | Default | What the daemon does with it |
|---|---|---|
| `[daemon] socket` | `<data>/run/antinomie.sock` | The local socket (at most 107 bytes). Its folder must be the daemon user's own with mode 0700; the socket is 0600. Not changed by a reload |
| `[daemon] host_workers` | `min(4, cpus/4)`, at least 1 | How many jobs the host stages (`analyse`, `report`, `cleanup`) work on at once; 0 is an error |
| `[daemon] lanes` | 1 | Only 1 is valid in 0.9.0 |
| `[daemon] shutdown` | `cancel` | On the first `SIGTERM`/`SIGINT`: `cancel` sends a job in its lane stages back to the queue (attempt not counted); `drain` lets it run on for up to `drain_timeout_s` first |
| `[daemon] drain_timeout_s` | 600 | See `shutdown = drain` |
| `[daemon] shutdown_host_grace_s` | 120 | A job already in its host stages (`analyse`, `report`, `cleanup`) at shutdown may finish within this many seconds; past it the job is left `running` and resumes at `analyse` on the next start (the VM does not run again) |
| `[queue] max_queued`, `per_client_queued` | 1000, 100 | `job.submit` fails `quota_exceeded` above them (the smaller of `per_client_queued` and the policy's `max_queued_per_client` applies) |
| `[queue] paused_on_start` | false | Start with the queue paused (`queue.resume` starts it) |
| `[inbox] dir` | `<data>/inbox` | Where uploads are staged (`uploads/`), and where watched files go after intake (`processed/`) or on failure (`rejected/`) |
| `[inbox] processed_keep_days` | 7 | Retention removes the plain files of `<inbox>/processed/` older than this many days (at least 1) |
| `[resources] min_free_disk_gib`, `min_free_ram_mib`, `require_kvm` | 20, VM RAM + 2048, true | The floors of the queue: below one, jobs wait `queued` and the queue pauses (`low_disk`, `no_kvm`); checked every 5 s, and the disk every minute of a run. A `run/PAUSE` file pauses the queue within 5 s |

Commands that reach the daemon read `[daemon] socket` from `<data>/service.toml`
the same way, so a configured socket needs no `--socket` on the client side; `--socket`
wins over the file, and a missing or faulty file means the default path.

A second `SIGTERM`/`SIGINT` within 5 s interrupts every wait at once, stops the
VM and exits 130; recovery at the next start finishes the rest. `SIGHUP` reads
`policies/` and `service.toml` again (a file with an error keeps the old set);
`SIGUSR1` writes the queue's state to the log.

## Watch folders

```toml
[[inbox.watch]]
path = "/srv/drop/default"      # absolute; the folder itself must not be a symbolic link
policy = "default"              # an existing policy
recursive = false               # follow subfolders (8 deep at most)
policy_by_dir = false           # subfolders named after policies pick the policy
delete_after = "move"           # move (to <inbox>/processed/), delete, or keep
on_duplicate = "run"            # optional: replaces the policy's rule for this folder
allow_group_write = false       # see below
watch_rate = 10                 # new jobs a minute before the folder pauses
```

The daemon scans each folder every 2 seconds. A file is taken once its size,
modification time and change time have been the same for 3 seconds (so a file
that is still being copied in waits), and never while its name starts with `.` or
ends in `.part`, `.tmp` or `.crdownload`. Files already there at the start are
taken in name order. Nothing in a folder can change the job: there are no
sidecar files, and the policy decides every limit and route.

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
| The queue is full, or the policy does not let `auto:policy-<name>` submit | The file stays; the folder waits a minute and tries again |
| More than `watch_rate` files a minute | The folder pauses for a minute, `engine.alert` `watch_flood` |

The job's client and its custody actor are `auto:policy-<policy>`, so a policy's
`[access] clients` must allow it (the default `*` does) and the sample's custody chain
shows who brought it. The library records the file's folder-relative name as
the origin, never the host path. A `keep`ed file is remembered by device, inode,
size and modification time in `<inbox>/.watch-state.json`, so a restart does not
take it again; a rewritten file is a new file. `SIGHUP` re-reads the folder list.

## Retention

| Key | Default | What is removed |
|---|---|---|
| `[retention] recordings_days` | 14 | The recording of a finished job older than this, through the engine's run deletion (the run's record is copied into the sample's record; captures and dumps that belong to the VM stay with it, as when the window deletes a run) |
| `[retention] keep_failed` | true | A failed job's recording is kept until `jobs_days` |
| `[retention] max_recordings_gib` | 200 | Above this the oldest recordings go first (those `keep_failed` protects last) |
| `[retention] jobs_days` | 90 | A finished job's record, events, artifacts and folder; the job's recording goes with it, or the job stays |

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
`auto:label=<label>` and `auto:policy=<name>` when a job of the policy ends, under
the custody actor `auto:policy-<name>`; a tag that cannot be written is a job
warning (`library_tag`), never a failure.

## Policies and running jobs

A job freezes the policy it was submitted under: the digest (SHA-256 of the
file) and the parsed content are stored with the job. Editing a policy file, or
reloading the daemon (`SIGHUP`), changes only jobs submitted afterwards. A reload
with an error keeps the old policies.

A spec may override a default only within the policy's ceiling. A request the
policy forbids is stored as a `rejected` job with the failure `policy_denied`
and the field to blame. A switch the policy leaves off (`evidence.memory_dump`,
`evidence.core_dump`, `run.allow_keep_on_failure`, a detection engine) cannot be
turned on by a job.

## Uploads and intake

`upload.begin`, `upload.put` (strictly sequential, at most 1 MiB per call),
`upload.finish` (seals the file and records its SHA-256) stage a sample under
`<data>/inbox/uploads/<upload-id>/` (directory 0700, file 0600, sealed files
0400). A staged upload is deleted after intake or after 24 hours. When the
directory is on a separate volume, the service refuses to start unless that
volume is mounted `noexec`.

At `job.submit` the intake opens the sample without following links, refuses
anything that is not a regular file, checks the size against the smallest of
256 MiB, the policy's `max_sample_mib` and a quarter of the lane VM's RAM
(`sample_too_large`), then the type and architecture against the policy
(`sample_type_denied`, `sample_arch_denied`). Only then is the sample added to
the library (origin: Added, source "Automation", the file name and never the
host path) with the caller as custody actor. A script has no architecture, so
`accept_arch` applies to ELF files only.

## Job store

`<data>/service/jobs.sqlite` (WAL) holds the queue and every job; each state
change is one transaction that also stores its events. `jobs/<id>/events.ndjson`
mirrors the events and `spec.json` holds the resolved spec. After a crash the
daemon puts a job left `running` back in the queue (once per job without using
an attempt) and repairs the mirror files.

## Custody actors

Every custody entry names who caused it: `app` and `analyst` in the window,
`auto:policy-<name>`, `web:<user>` or `local:<uid>` in headless mode. Entries of
kind `automation` record the job, policy digest, route and submitter. The
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
