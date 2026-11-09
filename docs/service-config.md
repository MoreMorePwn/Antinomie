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
  most 1024, `analysis.static_time_limit_min` 0 to 480, `limits.priority_max`
  0 to 9.
- Routes: in version 1 a job may use only `drop` and `inet_sim`. A policy that
  lists `internet`, `tor`, `vpn` or `socks5` fails, as does a default
  `network.route` outside `allowed_routes`. NAT is never valid for a job.
- `run.run_in` must be `app_terminal`; `run.run_as = "root"` needs
  `run.allow_root`.
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
| `[daemon] lanes` | 1 | Only 1 is valid in 0.9.0 |
| `[daemon] shutdown` | `cancel` | On the first `SIGTERM`/`SIGINT`: `cancel` sends a job in its lane stages back to the queue (attempt not counted); `drain` lets it run on for up to `drain_timeout_s` first |
| `[daemon] drain_timeout_s` | 600 | See `shutdown = drain` |
| `[daemon] shutdown_host_grace_s` | 120 | A job already in its host stages (`analyse`, `report`, `cleanup`) at shutdown may finish within this many seconds; past it the job is left `running` and resumes at `analyse` on the next start (the VM does not run again) |
| `[queue] max_queued`, `per_client_queued` | 1000, 100 | `job.submit` fails `quota_exceeded` above them (the smaller of `per_client_queued` and the policy's `max_queued_per_client` applies) |
| `[queue] paused_on_start` | false | Start with the queue paused (`queue.resume` starts it) |
| `[inbox] dir` | `<data>/inbox` | Where uploads are staged (`uploads/`) |
| `[resources] min_free_disk_gib`, `min_free_ram_mib`, `require_kvm` | 20, VM RAM + 2048, true | The floors of the queue: below one, jobs wait `queued` and the queue pauses (`low_disk`, `no_kvm`); checked every 5 s, and the disk every minute of a run. A `run/PAUSE` file pauses the queue within 5 s |

A second `SIGTERM`/`SIGINT` within 5 s interrupts every wait at once, stops the
VM and exits 130; recovery at the next start finishes the rest. `SIGHUP` reads
`policies/` and `service.toml` again (a file with an error keeps the old set);
`SIGUSR1` writes the queue's state to the log.

## Watch folders, retention, results and the hook

| Key | Default | What the daemon does with it |
|---|---|---|
| `[[inbox.watch]] path` | none | An absolute folder the daemon polls every 2 s. It must belong to the daemon's user |
| `policy`, `policy_by_dir` | `default`, false | The policy of its files; with `policy_by_dir`, a file in `path/<policy>/` uses that policy and an unknown folder name is ignored |
| `recursive` | false | Also scan subfolders (a symbolic link to a folder is never entered) |
| `delete_after` | `move` | `move` to `processed/`, `delete`, or `keep` (remembered by device, inode, size and time) |
| `on_duplicate` | the policy's | Overrides the policy for this folder |
| `allow_group_write` | false | Allow a folder the daemon's group can write to; one anyone can write to is never used |
| `watch_rate` | 10 | New jobs a minute before the folder pauses for a minute (`watch_flood`) |
| `[retention] jobs_days`, `recordings_days`, `max_recordings_gib`, `keep_failed` | 90, 14, 200, true | The hourly pass and `auto gc` ([retention](auto-mode.md#retention-and-clean-up)) |
| `[results] dir` | none | A copy of `job.json` and the reports of each finished job under `<dir>/<date>/<sha8>-<jobid>/` |
| `[notify] on_finish` | none | A command (argv, no shell) run when a job ends, with `ANTINOMIE_JOB_ID`, `ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and `ANTINOMIE_RESULT_JSON` and a 30 s limit |

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
