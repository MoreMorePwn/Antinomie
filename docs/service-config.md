# Service configuration and policies

[← Back to the overview](../README.md)

> **Status in 0.9.0.** The files, their keys and `antinomie-cli config validate`
> exist and are checked. The daemon that reads them (`antinomie-cli auto ...`,
> its socket, lanes, inbox and watch folders, reload on `SIGHUP`) is not shipped
> yet, so settings that name those only describe what the daemon will do.

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
