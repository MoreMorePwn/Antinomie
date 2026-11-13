# Run API, version 1

[← Back to the overview](../README.md)

This is the contract of the headless run API: the objects, states, events,
operations and errors that the command line (`antinomie-cli`), the local socket
and, later, the web process share. It was the job API until the run rename of
0.9.0 (ANT-T0492); no job API was released, and the old names (`job.*`,
`policy.list`, `recording.run.*`, `job_id`, `run_key`) are not accepted.

> **Words.** A **run** is one analysis of one sample: what a caller submits,
> follows and reads (id `r_<26>`). The **program** is the sample's execution
> inside a run. A **recording** is what the engine captured while the program
> ran; the `recording.*` reads address it by `recording_key`. A **preset** is a
> named set of run options. **Job** is left for work the engine still has to do
> (the store, the host work items of a run, uploads, retention); it is not a
> name of this API. The machine-readable form is
[run-api-1.schema.json](run-api-1.schema.json), generated from the Rust types of
the `antinomie-service` crate (`src/api/`) with `schemars` and checked in; a test
fails when the file is stale. The recording reads (`recording.*`) are in the
second part of this document.

> **Status in 0.9.0.** The types, the schema, the run store, the read-only
> recording queries and the daemon's local socket ship. `antinomie-cli auto daemon`
> serves the operations below on the socket; the `auto` commands of the CLI are its
> client. The web binding (ANT-T0192) is not part of 0.9.0.

Names here are final for version 1. The API changes only additively: a new
optional field does not change the version; a changed meaning or a removed field
does. Clients ignore unknown fields in replies. Requests do not: an unknown field
in a request fails with `invalid_argument` naming the field.

## Conventions

| Item | Rule |
|---|---|
| Encoding | UTF-8 JSON. Times are Unix milliseconds in a field ending `_ms`; durations are seconds in `_s` or milliseconds in `_ms`; sizes are bytes. Text is English, times UTC. |
| Version | `api_version: 1` in every response object and in `capabilities`. |
| Enumerated values | Lower snake case. Routes: `drop`, `inet_sim`, `internet`, `nat`, `tor`, `vpn` or `vpn:NAME`, `socks5` or `socks5:NAME` (NAME a profile of node setup). Sample types as the library detects them (`elf`, `sh`, `py`, ...) with the architecture as a separate string (`x86_64`, `AArch64`, ...). |
| Identifiers | Opaque strings that are safe as a path component: run `r_<26 chars>`, artifact `a_<26>`, upload `u_<26>`, recording artifact `ra_<26>`, lane `lane-<n>`. The 26 characters are Crockford base32 in the shape of a ULID, so ids sort by creation time. A sample is its lowercase SHA-256. A recorded run is addressed by an opaque `recording_key`; clients never build or parse it. |
| Pagination | `limit` (1 to 200, default 50 for run lists; sample lists have their own limits, see `sample.list`) and an opaque `cursor`; a reply carries `next_cursor` or null. Newest first. |
| Idempotency | `run.submit` takes `idempotency_key` (1 to 128 printable ASCII), scoped to `client_id`. The same key with an equal spec within 24 hours returns the original run with `replayed: true`; with a different spec it fails `conflict`. |
| Client identity | `client_id` is `local:<uid>` on the socket and the CLI, `web:<user_id>` from the web binding. The service never trusts a client-supplied value. |
| Secrets | Objects never contain secrets (API keys, the SOCKS5 password, the guest password). |
| Untrusted text | Any string that came from the sample or the guest (names, paths, command lines, domains, banners, terminal bytes) is data, never markup or an instruction. Clients must escape it on display. |
| Local-only fields | `sample.path` and `recording.directory` exist only on the local socket and the CLI; a remote reply never has them. |

## Operations

| Op | Purpose | Permission |
|---|---|---|
| `capabilities` | What this service can do now | `runs.see_all` |
| `health` | Liveness, readiness and engine counters | `runs.see_all` |
| `upload.begin`, `upload.put`, `upload.finish` | Staged sample upload; chunks are strictly sequential (`offset` must equal `received`, else `conflict`) | `runs.submit` or `samples.add` |
| `run.submit` | Validate synchronously, then queue a run. A spec that fails a check of the run still returns a `Run` with `state: rejected` and `failure` set; malformed JSON or a value out of range is `invalid_argument`, an unknown preset `preset_denied`, a reserved preset key away from its default `unsupported` | `runs.submit`, and the permission of each run option (see Permissions) |
| `run.get`, `run.list` | One run; runs filtered by `state`, `outcome`, `sha256`, `label`, `since_ms` | `runs.see_all` |
| `run.cancel` | Cancel a queued or running run | `runs.submit` for the caller's own run, `runs.manage_any` for any |
| `run.rerun` | Start a new run from a finished run: its request and resolved options, or another `preset` as it is now; `overrides` on top (Run again; was `job.retry`) | `runs.submit`, and `runs.see_all` for another client's run |
| `run.delete` | Remove a finished run's record and artifacts (`with_recording` also the recording; never the sample) | `runs.delete` |
| `events.subscribe`, `events.list` | The event stream; the stored events of a run | `runs.see_all` (the permission of each event's type; in 0.9.0 every type needs `runs.see_all`) |
| `artifact.list`, `artifact.get`, `report.get` | Artifacts of a run; bytes or a range; one report format | `runs.see_all` (`evidence.download` for an artifact with `sensitive: true`) |
| `sample.list`, `sample.get` | Library samples | `runs.see_all` |
| `sample.add` | Store a file in the library without running it | `samples.add` |
| `sample.download` | The library archive of a sample (an AES zip, never the plaintext) | `samples.download` |
| `sample.tag` | Set tags on a sample | `samples.tag` |
| `preset.list` | Every preset (`{presets: [{name, title, description, digest, built_in, offered_to, needs, missing, unavailable, usable}]}`): the permissions its options need, the ones the caller lacks, what the node does not have, and whether the caller can run it as it is | `runs.submit` |
| `preset.get` | One preset by `name`: `{name, digest, built_in}` and every key of the preset, with the same tables as its file (`not_found` with `field: "name"` for an unknown name). Preset versions arrive with preset writes (0.9.1) | `runs.submit` |
| `queue.status`, `vm.list`, `base.list` | Queue and lane state; VMs and installed bases | `runs.see_all` |
| `queue.pause`, `queue.resume` | Stop or resume starting new runs | `queue.manage` |
| `custody.verify` | Verify the custody chain of one sample or the whole library | `custody.verify` |

A caller without the permission an operation needs gets `permission_denied`
with `details.needs` listing it.

Not in version 1: live terminal streaming and input, the debugger, snapshot
management, base download or build, VM creation, rule pack management, settings
changes, memory and disk browsing, core reading, and any write to a recording.
The rest of the namespaces `run.*` and `preset.*` (`run.end`, `run.annotate`,
`run.share`, `preset.put`, `preset.retire` arrive with 0.9.1), the namespaces
`terminal.*`, `rule.*`, `settings.*`, write operations of `vm.*` and `base.*`,
and the reserved `recording.*` names are reserved: a binding must not invent
operations in them.

## Run spec

Exactly one of `sample.sha256`, `sample.path` (local-only) or `sample.upload_id`
is set. Every other field is optional. The preset gives every run option;
`overrides` change them.

| Field | Meaning |
|---|---|
| `name` | File name hint, 1 to 128 bytes, no `/`, no NUL |
| `preset` | The preset's name, default `standard`. Five presets are built in: `standard`, `quick-look`, `deep`, `interactive`, `live-network`; more are `<data>/presets/<name>.toml` |
| `priority` | 0 to 9, default 5 (the app's levels: Low 2, Normal 5, Urgent 8); higher starts first, with no ageing; the caller's `priority_max`, when it has one, is a ceiling: a higher value is refused `limit_exceeded`, never lowered (an unset priority becomes the default or the ceiling when that is lower) |
| `labels` | At most 16 pairs; key 1 to 32 bytes of `[a-z0-9._-]`, value up to 128 bytes |
| `idempotency_key` | See conventions |
| `overrides` | A partial preset: the same tables and keys as a preset file, `{"program": {"run_time_s": 600}, "report": {"formats": ["html", "json", "pdf"]}}`. `title`, `description` and `offered_to` are not run options. See below |

The keys of `overrides`, by table (each optional; the full format, defaults and
ranges are in [service configuration](service-config.md)):

| Table | Keys |
|---|---|
| `program` | `run_time_s` (5 to 1800; reaching it ends the run normally, `end_reason: time_limit`), `arguments` and `environment` (at most 64 each; `NAME=value`), `working_directory`, `guest_path` (`{name}` is the sample's file name), `user` (`normal`, `root`, `nobody`, `custom` with `uid` and `gid`), and the reserved `source`, `executable`, `run_in`, `preload`, `extra_files` |
| `network` | `capture`, `route` (`drop`, `inet_sim`, `internet`, `nat`, `tor`, `vpn[:NAME]`, `socks5[:NAME]`), the reserved `private_addresses`, `abuse_filter` |
| `dumps` | `memory_dump_on_exit`, `core_dump_on_exit`, `core_budget_mib` (64 to 1024), `core_deadline_ms`, `dump_when_suspicious`, `minimum_tier`, `trigger_memory_dump`, `trigger_core`, `read_non_resident_pages`, `max_dumps` (1 to 8), `dumps_apart_s` (0 to 3600), the reserved `disk_dump` |
| `static_analysis` | `enabled`, `triage_checks`, `deep_checks`, `time_limit_per_tool_min` (0: each tool's own, up to 480), `ghidra_disassembly`, `required_checks`, `limits.*`, the reserved `rebuilt_file_mib`, `rebuilt_run_mib` |
| `triage`, `detection`, `report` | `triage.enabled`; `detection.yara`, `sigma`, `ids`, `check_online`; `report.formats` (`html`, `pdf`, `json`, `misp`, `stix`, `md`), `bundle`, `defang`; the reserved `triage.written_*`, `earlier_*`, `detection.scan_every_min`, `report.sections` |
| `vm` | `lane_group`, `keep_on_failure` (refused `unavailable_on_node`), `allow_control` |
| `accepts`, `duplicates`, `record`, `verdict`, `retry`, `required_stages` | As in the file (`retry.max_attempts` 1 to 10, each `retry.backoff_s` 0 to 3600, at most 10; `duplicates.on_duplicate = "reuse"` returns only a run the caller may see, else a new run starts) |

**The Custom rule.** An override that changes a value makes the run Custom; an
override equal to the preset's value changes nothing. A Custom run's `preset`
object is `{name: "custom", digest, based_on: {name, digest}, changes: [...]}`
(`digest` is the SHA-256 of its resolved options, `changes` the dotted keys it
changed); a run of an unchanged preset has `{name, digest}`. The stored request
keeps the preset's name and only the changed keys in `overrides`; every
resolved option is frozen with the run. A preset locks nothing: only the
caller's permissions, the node and the caller's limits do (see "How
`run.submit` is checked"). A key 0.9.0 reserves is accepted at its default
only; another value is `unsupported` with `details.reason = "reserved"` and
`field` the key ("arrives with 0.9.1").

The sample size limit is the smallest of the engine's 256 MiB maximum, the
preset's `accepts.max_sample_mib` and a quarter of the lane VM's RAM;
`capabilities.max_sample_bytes` reports it.

## Run states

| State | Terminal | Meaning |
|---|---|---|
| `queued` | no | Accepted and stored; `waiting_for` says what for (`lane`, `resources`, `dependency`, `quota` (a limit of the caller, also: the caller already has `max_running` runs running), `queue_paused`, `layer_pending`, `backoff`, `lane_quarantined`) |
| `running` | no | A lane is working; `stage` says where (`prechecks`, `provision`, `upload`, `launch`, `run`, `collect`, `analyse`, `report`, `cleanup`) |
| `cancelling` | no | Cancel requested; the lane is stopping the run and cleaning up |
| `succeeded` | yes | The run ended, the recording is complete, the requested analysis and reports exist |
| `partial` | yes | A recording and a report exist, but a requested piece is missing or incomplete. `failure` is null; `warnings` list each piece |
| `failed` | yes | No usable recording, or a required stage failed after retries |
| `cancelled` | yes | Stopped by request; whatever was recorded is kept and flagged |
| `rejected` | yes | Refused at submit (a permission, the node, a limit, the sample); consumed no lane time |

`outcome` is null while the run is not terminal and equals `state` afterwards.

`host_work` (0.9.0, ANT-T0454) lists the run's host work items once `collect`
has handed it to the host work pool: `name` (`triage`, `static:<tool>`,
`detection`, `assess`, `report`), `state` (`queued`, `running`, `done`,
`failed`, `timed_out`, `skipped`), `after` (the items it waits for),
`expected_s` and its `basis` (`median`, `estimate`, `fixed`, `preset`: a fixed limit the preset sets),
`limit_s`, `started_ms`, `finished_ms` and `note`. `queue.status` has
`host_pool`: `workers`, `queued` (the pool's queue length), `running`, `runs`
and `waiting_for` (why the head waits, when it waits for memory).

## The run object

`run.get`, `run.submit`, `run.rerun`, `run.cancel` and the items of `run.list`
(`{runs, next_cursor}`) are one object:

| Member | Meaning |
|---|---|
| `api_version`, `id` | `1`; the run id `r_<26>` (a `j_` id of a store written before the rename still resolves) |
| `state`, `stage`, `waiting_for`, `outcome`, `queue_position` | See the states above |
| `created_ms`, `started_ms`, `finished_ms`, `attempt`, `max_attempts` | Times and attempts (a run starts over when the VM or guest failed) |
| `client_id` | Who submitted it (`local:<uid>`, `auto:preset-<name>` for a watch folder) |
| `request` | The `RunRequest` as stored: the preset's name and the priority filled in, `overrides` reduced to the keys that changed a value |
| `preset` | `{name, digest}`, or for a Custom run `{name: "custom", digest, based_on: {name, digest}, changes}` |
| `settings` | Every resolved option of the run: the frozen preset, with the same tables and keys as a preset file |
| `permissions_used` | `[{permission, field, source}]`: each permission the run's options use beside `runs.submit` (`field` the preset key, `source` `caller` in 0.9.0: the caller's permission set; roles and grants arrive with 0.9.1); empty for a run that uses none |
| `sample` | The library sample once archived: `{sha256, size, type, architecture, name}` |
| `lane`, `vm` | The lane and its VM `{id, name, base_identity, revert}` |
| `program` | The sample's execution: `{id, started_ms, ended_ms, end_reason, exit, signal, core_dumped, triggers, trigger_notes, pending}`; `id` is the engine's id of the execution (the recording's `run_id`); `end_reason` is `exited`, `signaled`, `time_limit`, `stopped` or `guest_lost` |
| `recording` | `{vm_id, boot_id, run_id, recording_key, phase, directory?}`: the engine's ids of the recording and the key every `recording.*` read takes |
| `assessment`, `artifacts`, `warnings`, `failure`, `repeat_of`, `labels`, `host_work` | The label and digest; the files; non-fatal notes; why it failed or was refused; the run it repeats; the request's labels; the host work items |

The preset is frozen at submit: a run whose preset changed or went away since
keeps the options it froze. When the run starts, prechecks asks again
whether its client still holds every permission the run uses; one taken away
while the run waited (a watch folder's `permissions` changed by a reload) ends it
`failed` with `permission_denied`.

## Failure codes

| Code | Stage | Retryable |
|---|---|---|
| `sample_missing`, `sample_too_large`, `sample_type_denied`, `sample_arch_denied`, `duplicate_denied` | prechecks | no |
| `permission_denied`, `limit_exceeded`, `unavailable_on_node` | prechecks | no |
| `preset_denied` | prechecks, provision | no |
| `quota_exceeded`, `dependency_missing`, `host_resources` | prechecks | yes, later |
| `no_base`, `no_vm` | provision | no |
| `vm_start_failed` | provision | yes |
| `guest_unreachable` | provision, launch | yes |
| `revert_failed`, `lane_changed` | provision (`revert_failed` also cleanup) | no |
| `upload_failed` | upload | yes |
| `launch_failed` | launch | depends |
| `guest_lost` | run, collect | yes |
| `recording_failed` | collect | yes |
| `analysis_failed` | analyse, report | yes |
| `deadline_exceeded` | analyse, report | maybe |
| `cancelled` | any | no |
| `internal` | any | maybe |

## Events

Every stored event has `seq` (within one run, from 1, or within one service epoch
for engine scope), `gseq` (across the service, persisted, never reused), `ts_ms`,
`scope` (`run` or `engine`), `run_id` (null for engine scope), `type` and `data`.

| Type | `data` |
|---|---|
| `run.created` | `{run}` |
| `run.state` | `{state, stage, waiting_for?, attempt, queue_position?}` |
| `run.stage` | `{stage, status, duration_ms?}`; `status` is `started`, `finished`, `skipped` or `failed` |
| `run.progress` | `{stage, text, fraction?}`. Ephemeral: not stored, no `seq` |
| `run.program` | `{program_id, pid?, route}`: the program started (`program_id` is `program.id` of the run) |
| `run.warning` | `{code, text}` |
| `run.artifact` | `{artifact}` |
| `run.trigger` | `{trigger?, note?}`: the preset's dump trigger took a dump (`trigger`: rule, tier, summary, syscall, pid, at_ms, and the `memory` and `core` dump with state, size, capture_id, error; no host path) or did less than asked (`note`) |
| `run.assessment` | `{assessment}` |
| `run.requeued` | `{attempt, reason}`; a `run.state` event with `state: queued` follows |
| `run.finished` | `{outcome, failure?}`; the last event of a run |
| `lane.state` | `{lane, state, run_id?, reason?}` (engine scope) |
| `engine.alert` | `{code, text}` (engine scope) |
| `run.metrics` | `{stage, vm, run, health}`. Ephemeral |

Stored events are never summarised or dropped. A subscriber that reconnects with
`since_seq` (one run) or `since_gseq` (all runs) receives every stored event after
it, then live ones. `engine.hello` and `engine.ping` are frames, not events.

## Errors

Every failed operation returns `{"error": {"code", "message", "field?", "retryable", "details"}}`.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_argument` | 400 | Malformed or unknown field; `field` names it |
| `unauthenticated` | 401 | Added by the HTTP layer only |
| `forbidden` | 403 | Added by the HTTP layer only |
| `permission_denied` | 403 | The caller lacks a permission; `details.needs` lists it (also inside a rejected run's `failure`) |
| `preset_denied` | 403 | There is no such preset (or, from 0.9.1, it is retired or not offered to the caller's role); `details.preset`. Nothing is stored |
| `limit_exceeded` | 403 | A value above a limit (priority, run time, a node ceiling, runs per day); `details.field`, `details.limit`, `details.source` (`caller` or `node`), and `details.next_at_ms` for runs per day |
| `unavailable_on_node` | 409 | The node does not have what the request needs (a live route, a kept VM); `details.what` |
| `not_found` | 404 | Run, artifact, sample, upload, run or recording missing |
| `conflict` | 409 | Idempotency key reused with another spec; the run is not in a state that allows the op; `details.reason = "cursor_stale"` |
| `precondition_failed` | 412 | For example `run.rerun` of a run that is not terminal; `details.reason = "layer_pending"` or `"recording_open"` |
| `payload_too_large` | 413 | Upload or sample above the limit; a read range above its limit |
| `quota_exceeded` | 429 | Queue full or client quota; `details.retry_after_s`; `details.reason = "heavy_read_limit"` |
| `unavailable` | 503 | Data directory owned by the GUI, service starting or stopping, engine failed; `details.reason = "read_timeout"` |
| `unsupported` | 501 | Not in this build or not in version 1 |
| `internal` | 500 | A bug; `details.log` names the run log |

## Permissions

A caller holds a set of permissions (`Caller.permissions`, by dotted key). The
engine checks 35 of them (the web's own `users.manage` and `audit.read` are not
the engine's); 0.9.0 asks for the ones below, the others are reserved for the
features of 0.9.1 (cases, interactive sessions, presets, kept VMs).

| Permission | Allows in 0.9.0 |
|---|---|
| `runs.see_all` | The read operations above, JSON, MISP and STIX reports, every `recording.*` operation classed normal, the events, `lane.list`, `watch.list` |
| `runs.submit` | `upload.*`, `run.submit`, `run.rerun`, and `run.cancel` of the caller's own runs |
| `samples.add` | `upload.*`, `sample.add` |
| `runs.manage_any` | `run.cancel` of any run |
| `evidence.view` | The sensitive `recording.*` operations (bytes shown, never a file) |
| `evidence.download` | `artifact.get` and `report.get` of an artifact with `sensitive: true` |
| `samples.download` | `sample.download` |
| `samples.tag` | `sample.tag` |
| `runs.delete` | `run.delete`, `gc.run` |
| `queue.manage` | `queue.pause`, `queue.resume`, `watch.scan` |
| `lanes.reset` | `lane.reset`, `lane.unquarantine` |
| `custody.verify` | `custody.verify` |
| `route.internet`, `route.nat`, `route.tor`, `route.vpn`, `route.socks5` | A run on that live route (then refused `unavailable_on_node`: no live route is set up for the service before 0.9.1) |
| `run.as_root` | `program.user` root, or a custom UID or GID below 1000 |
| `evidence.core_dump` | `dumps.core_dump_on_exit`, or a trigger core (`dump_when_suspicious` with `trigger_core`) |
| `evidence.memory_dump` | `dumps.memory_dump_on_exit`, or a trigger memory dump |
| `lookup.online` | `detection.check_online` |
| `run.keep_vm` | `vm.keep_on_failure` (then refused `unavailable_on_node`: keeping a VM arrives with 0.9.1) |

`route.lan` (`network.private_addresses`), `route.unfiltered`
(`network.abuse_filter = false`) and `evidence.disk_dump` (`dumps.disk_dump`)
are checked too, for keys 0.9.0 reserves at their default. Reserved:
`cases.create`, `runs.share`, `cases.join_any`, `runs.annotate`,
`indicators.mark_fp`, `interactive.watch`, `interactive.control`,
`presets.manage`, `lanes.extend_keep`, `node.manage`.

The four scopes of earlier drafts map to permissions as follows: `read` is
`runs.see_all`; `submit` is `samples.add` and `runs.submit`;
`artifacts:sensitive` is `evidence.view`, `evidence.download` and
`samples.download`; `manage` is `runs.manage_any`, `samples.tag`,
`runs.delete`, `queue.manage`, `lanes.reset` and `custody.verify`.

`runs.see_all` sees every run on the node (one trust domain per node).

**How `run.submit` is checked, in order.** The first failing check answers:

1. `runs.submit`, else `permission_denied` (nothing stored);
2. the shape and range of every value, else `invalid_argument` (nothing
   stored);
3. the preset exists, else `preset_denied` (nothing stored). `offered_to`
   names roles, which 0.9.0 callers do not have: it locks nothing;
4. the overrides resolve onto the preset (the Custom rule) and every resolved
   value is in its range, else `invalid_argument` naming the field
   (`overrides.program.run_time_s`); a reserved key away from its default is
   `unsupported` (nothing stored);
5. every run option that adds risk has its permission, on the run as it will
   run (the preset's values included): the route, the user, core and memory
   dumps (also those the dump trigger takes), Check online, keeping the VM.
   Else a rejected run with `permission_denied`, `field` the preset key
   (`network.route`) and `details.needs` listing every missing permission;
6. the node has it (a live route, a kept VM, the lane group), else a rejected
   run with `unavailable_on_node`;
7. the limits: `priority` up to the caller's `priority_max`;
   `program.run_time_s` up to the smaller of the node ceiling (1800 s) and the
   caller's `max_run_s`; `accepts.max_sample_mib` and
   `static_analysis.limits.*` up to their node ceilings; the runs of the last
   24 hours up to `max_runs_per_day` (counted only when the caller has that
   limit, per client, a rejected run not counted). Else a rejected run with
   `limit_exceeded`, `details.source` `caller` or `node` (whose limit is the
   smaller), and for the daily count `details.next_at_ms`, when the next run
   becomes possible. Only the lower bounds (5 s, 1 MiB, ...) are
   `invalid_argument` at step 4. `max_queued` is checked first, at submit
   (`quota_exceeded`); `max_running` holds a queued run back (`waiting_for`
   `quota`) while the caller has that many running;
8. the sample (intake: size, type, architecture against `[accepts]`), else a
   rejected run with the `sample_*` code. Intake comes last because it archives
   the sample: a refused run adds nothing to the library.

## Local socket

`antinomie-cli auto daemon` serves the operations of this document, and the
`recording.*` reads of the second part, on a Unix socket.

| Item | Value |
|---|---|
| Path | `<data dir>/run/antinomie.sock` (or `[daemon] socket` in `service.toml`, or `--socket`); at most 107 bytes |
| Folder | Must be a real directory owned by the daemon's user with mode 0700; the daemon refuses to start otherwise (a symlink, another owner, group or other access) |
| Socket file | Mode 0600, set right after `bind`. An old socket file is replaced (the daemon holds the data-directory lock, so no one else serves it); any other file at the path is left alone and the start fails. The daemon removes its own socket when it stops |
| Who may connect | Peer credentials (`SO_PEERCRED`) are read on accept: only the daemon's own UID. Another UID is closed without a byte, not even the hello |
| Identity | The caller is `local:<uid>` with every permission the engine checks: the socket is the owner's single-user view. Nothing in a request changes it |
| Framing | One JSON object per line, UTF-8, at most 2 MiB per line, both ways. A request is `{"id": N, "op": "...", "params": {...}}` and nothing else: `id` an integer from 0 to 2^53 - 1, `op` 1 to 64 printable ASCII characters, `params` an object (absent or `null` reads as `{}`). Any other member is `invalid_argument` naming it |
| Replies | `{"id": N, "ok": true, "result": ...}` or `{"id": N, "ok": false, "error": {...}}` |
| Hello | The first line of a connection is `{"frame": "engine.hello", "data": {"api_version", "app_version", "owner", "epoch", "gseq", "truncated"}}`, with no `id`. A client that does not know the `api_version` closes |
| Cancel | `{"id": N, "op": "cancel"}` cancels the request `N` in flight; that request answers for itself (a subscription with `{"cancelled": true, ...}`, another request with `unavailable`, reason `cancelled`). A cancel of an id not in flight is `not_found`. Closing the connection cancels everything it had in flight, including a recording read |
| Host paths | `sample.path` is refused on the socket (`invalid_argument`, field `sample.path`): a file arrives with `upload.begin`, `upload.put` and `upload.finish`, so no client makes the daemon open a path of its choosing. `artifact.get` and `report.get` answer with the file's `path` (local-only), resolved inside the run's directory: a recorded location that is absolute, has `..`, or leads through a symlink out of the run directory is not served |

Limits (a refusal is an error reply; the connection stays open unless the table
says it closes):

| Limit | Value | Over it |
|---|---|---|
| Line | 2 MiB | A request line: `payload_too_large`, then the connection closes (the stream cannot be framed again). A reply: replaced by `payload_too_large` for the same `id` (ask for fewer items or a byte range) |
| Requests in flight | 16 per connection, 256 in all | `quota_exceeded`, `details.reason = "too_many_requests"`; an `id` already in flight is `conflict` |
| Request rate | 50 a second per connection with bursts of 100 (500 a second in all) | `quota_exceeded`, reason `rate_limited`, `details.retry_after_s` |
| Connections | 64 | One line `unavailable`, reason `too_many_connections`, then closed |
| Subscriptions | 64 per client, 256 in all | `quota_exceeded`, reason `too_many_subscriptions` |
| Idle connection | 300 s with nothing in flight (a subscription is not idle) | Closed |
| A line begun and not finished | 30 s | Closed |
| Writing one line to the client | 10 s | The client is a slow consumer: closed (a subscription first tries to send `engine.alert` code `slow_consumer`) |
| `upload.put` data | Base64 of at most 1 MiB, strictly sequential (`offset` equal to `received`, else `conflict`) | `payload_too_large` or `invalid_argument` on `data` |
| `artifact.get` range | 1 MiB, answered as Base64 in `range.data` | `payload_too_large` |

**Event streams.** `events.subscribe` answers with the `engine.hello` frame
(carrying the request `id`, the highest stored `gseq` and `truncated`), then event
lines `{"id": N, "event": {...}}`, `{"id": N, "frame": "engine.ping", "data": {}}`
after 15 s without an event, and a last line:

| Stream | Resume | Without a resume point | Ends |
|---|---|---|---|
| One run (`run_id`, `since_seq`) | Every stored event of that run with `seq` above `since_seq`, then live ones; never an event of another run | The run's whole history | After `run.finished` (the run's last event): `{"id": N, "ok": true, "result": {"finished": true, "last_seq": ...}}` |
| All runs and the engine (`since_gseq`) | Every stored event with `gseq` above `since_gseq`, then live ones | From now | On cancel, or when the daemon stops (`unavailable`, reason `service_stopping`) |

There is no gap and no duplicate across the resume: the stream subscribes to the
live events first, then reads the table, then skips what the table gave; the store
publishes events in commit order. A stream whose live buffer overflows (4096
events) reads the table again from the last event it sent, so a burst loses
nothing. `truncated` is true when `since_gseq` is older than the oldest retained
event (engine events are kept 7 days or 100 000 rows) or higher than any `gseq`
this store has stored (another or a restored store); the client re-synchronises
with `run.list`. `since_seq` without `run_id`, `since_gseq` with it, and an
unknown name in `types` are `invalid_argument`; an unknown run is `not_found`.
Ephemeral events (`run.progress`, `run.metrics`) are sent live only.

**Operations served in 0.9.0.** `capabilities`, `health`, `upload.*`,
`run.submit`, `run.get`, `run.list`, `run.cancel`, `run.rerun`, `events.subscribe`,
`events.list`, `artifact.list`, `artifact.get`, `report.get`, `preset.list`,
`queue.status`, `queue.pause`, `queue.resume`, `run.delete`, the `lane.*`, `watch.*` and
`gc.run` operations below,
`sample.list`, `sample.get`, `sample.add`, `sample.download`, `sample.tag`,
`vm.list`, `base.list`, `custody.verify` and every `recording.*` read. Any other name in the
reserved namespaces (`run.`, `preset.`, `terminal.`, `rule.`, `settings.`,
writes of `vm.` and `base.`) is `unsupported`; any other unknown name, the
names of the job API before the rename (`job.submit`, `policy.list`, ...)
included, is `invalid_argument` on `op`. While the
daemon stops, `run.submit`, `run.rerun` and `upload.*` are `unavailable` with
reason `service_stopping`.

**Library, VM and base operations (additions to the table above).** They answer
from the same code direct mode runs, so the CLI prints the same objects either way.

| Operation | Notes |
|---|---|
| `sample.list` | `{samples, next_cursor}`, newest first. Besides `q`, `tag`, `limit` (1 to 1000, default 100) and `cursor`: `tags[]` (more `KIND=VALUE` tags the sample must also have), `all` (include samples whose archive was removed), `custody` (fill `custody_ok`). A tag is `KIND=VALUE` (`verdict`, `category`, `technique`, `custom`); a bare value is a custom tag |
| `sample.get` | The `Sample` object plus `sha1`, `md5`, `description`, `removed_ms` and `custody` (the chain's summary). `origins`, `events` and `runs` (booleans) add those lists |
| `sample.add` | Takes `sample.upload_id` only. `sample.path` and `sample.sha256` are `invalid_argument` on the socket (the daemon opens no path a client names). The type and architecture come from the bytes; no preset applies. The custody entry names the caller (`local:<uid>`). The answer is `sample.get`'s object plus `new` |
| `sample.tag` | Sets the whole tag list (`[{kind, value}]`); the custody entry `edited` (tags) names the caller. The answer is the `Sample` object |
| `sample.download` | `sha256` and an optional `range {offset, len}` (at most 1 MiB; default the first MiB). The answer is `{sha256, format: "zip-aes256", password: "infected", size, range {offset, len, data}}` with `data` Base64 of the AES archive (never the plaintext). The first range (`offset` 0) writes one custody entry `exported`. Needs `samples.download` |
| `vm.list` | `{vms: [{id, name, base_identity, lane}]}` from the engine's latest snapshot; the lane VM carries its lane |
| `base.list` | `{bases: [{identity, name, architecture}]}`; no host path. While the engine still lists them: `unavailable`, `retryable` |
| `custody.verify` | `{ok, head, problems[]}` plus, for one sample, `sha256`, `entries`, `problem`, `summary`; for the library, `index`, `samples[]`, `broken[]`. Needs `custody.verify` |

**Service log for sensitive reads.** Every served read of the sample's own bytes
writes one line to the daemon's service log (`antinomie-cli auto daemon` standard
error, or its log file): `sensitive read: caller=<id> op=<op> recording=<vm:boot:run> size=<bytes>`
for `recording.captured.read`, `recording.files.content`, `recording.network.packet`
and `recording.artifact.get` of a capture, memory dump, core or file copy;
`... op=artifact.get run=<run id> ...` for a run artifact with `sensitive: true`
(`report.get` too); and `... op=sample.download sample=<sha256> ...` for each range
of an archive. `size` is the number of bytes served (the frame length for a packet).
A refused read and a read of rows write nothing, a read that the scan still
builds (`building`) writes nothing yet, and the line never carries the bytes, a
host path or a name from the sample.

**Runs and recordings.** `RecordingInfo.from_run` and the `from_run` filter of
`recording.list` come from the run store: a run records its recording
(`recording`) when its lane stage opens it, and the reads find the newest run
whose recording is that one. The daemon and the CLI's direct mode use the same
index (direct mode opens the store read-only and creates nothing), so both print
the same `from_run`. A recording no run made (the window, `run exec`), and a data
directory with no run store, show `from_run: null`.

**Held recordings (0.9.0).** `RecordingInfo.held` (optional, untrusted text) is present while a
run's tree has ended but the run is held open for a copy of its program running
outside the tree: "Held: persisted copy running (pid 1050, .e)". `state` keeps how
the tree ended; a reader that knows nothing of `held` sees the run as before.

**Reads from the CLI.** With a daemon at the socket `recording list`, `recording show`, `recording
export`, `triage` and the other read commands send these operations; `recording export`
never sends an output path: the command pages through `recording.*` and writes the
files under `--out` itself, and the bytes the sample produced are fetched only with
`--sensitive` (the permission `evidence.view` is checked again by the daemon, and
each read is written to its service log). `sample add FILE` sends the file with
`upload.begin`, `upload.put` and `upload.finish`, then calls `sample.add` with the
`upload_id`. A
page that would not fit a 2 MiB line is `payload_too_large` and the command asks
again for fewer rows.

`run.rerun` makes a new run from a finished one: the request the client first sent,
the sample named by its library hash, no idempotency key, and `repeat_of` set.
A run of an unchanged preset uses the preset as it is now; a Custom run uses
its resolved options as overrides of the preset it was based on (it is Custom
again). The given `overrides` (a partial preset) are merged on top, key by key.
`priority` (0 to 9) replaces the old run's; without it the old run's priority
is kept, lowered to the caller's `priority_max` when above it (an asked
priority above the ceiling is refused `limit_exceeded`). The run must be terminal (`precondition_failed` otherwise); the
caller needs `runs.submit`, and `runs.see_all` for another client's run.

**Lane operations** (an addition of this binding; section 5.3 has none for lanes,
and the CLI's `auto lane` commands need them while a daemon owns the folder):

| Op | Permission | Params | Result |
|---|---|---|---|
| `lane.list` | `runs.see_all` | `lane?` (ignored) | `[{lane, vm_id, vm_name, clean_snapshot_id, base_identity, quarantine, quarantine_detail, failures, busy_with, collected, problems[]}]`; `problems` are the checks of `lane.unquarantine` in words |
| `lane.reset` | `lanes.reset` | `lane?` (default `lane-1`) | The lane after the revert: the clean snapshot restored, the guest answering, the VM stopped and settled; a quarantine is lifted. A failed revert keeps the lane as it was |
| `lane.unquarantine` | `lanes.reset` | `lane?` | The lane with the quarantine lifted when the checks pass (`precondition_failed` naming the failing check otherwise) |

`lane.reset` and `lane.unquarantine` are carried out by the lane's own thread and
only while no run runs: a busy lane answers `conflict` at once (pause the queue
first), and a request not reached within its wait (900 s, 60 s) is dropped, never
run late. Each sends `lane.state` with the reason.

`run.delete` (`runs.delete`) removes an ended run's row, events, artifacts and folder
and answers `{deleted: true}`. A run that has not ended is a `conflict`. With
`with_recording: true` the run's recording is deleted first through the engine's
own run deletion (custody actor `auto:preset-<preset>`); a recording that a
`recording.*` read has open, or whose artifacts are still being written, is a
`precondition_failed` with `details.reason = "recording_open"` and nothing is
removed. Without `with_recording` the recording stays where it is.

**Watch folder and retention operations** (an addition of this binding; the
CLI's `auto watch` and `auto gc`):

| Op | Permission | Params | Result |
|---|---|---|---|
| `watch.list` | `runs.see_all` | none | `{folders: [{path, preset, state, detail, taken, rejected, refused: [{name, reason}], pending, last_scan_ms, paused_until_ms}]}`; `state` is `watching`, `paused`, `held`, `refused` or `error` |
| `watch.scan` | `queue.manage` | none | The same, after a scan made now (waits at most 30 s) |
| `gc.run` | `runs.delete` | `dry_run?` (default false) | `{dry_run, now_ms, actions: [{kind, run, recording, detail, bytes, done}], skipped: [{kind, run, why}], errors[], freed_bytes}`; `kind` is `recording`, `run` (the run's record), `upload` or `rejected_file` |

Watch folders add the events `engine.alert` with `code` `watch_flood` and
`watch_folder_refused`; delivery adds `result_drop_failed` and `hook_failed`.

New `details.reason` values of this binding: `too_many_requests`, `rate_limited`,
`too_many_connections`, `too_many_subscriptions`, `service_stopping`, `cancelled`.

# Recording queries, version 1

The `recording.*` operations read finished or live recordings. They are paged,
bounded, cancellable and read-only: a query never writes into a recording, never
takes the data-directory lock, and never talks to the engine except to learn the
live state of a recording. They work beside a daemon, beside a lane that is
writing, and with no owner at all. The types are in
`antinomie-service/src/query/` and in the same schema file.

## Addressing

A recording is addressed by its `recording_key`: an opaque string produced by
`recording.list` and by `Run.recording.recording_key`. Clients never build or
parse it. (The CLI also accepts `vm:boot:run`, which it turns into a key; the
key is the base64url form of the engine's three ids, and each id must be a
plain file name.) The engine's run id alone is not unique across boots. A
recording is not a run: the window and `run exec` make recordings too, and a
run of Auto mode has one recording per attempt that launched.

The analysis operations take exactly one of `recording_key` (the analysis
linked to a recording) or `run_id` (the host-side analysis of a run). Custody
takes `sha256` instead of a recording.

## Result shapes

Every result is one of two shapes.

| Shape | Members |
|---|---|
| `Page<T>` | `items`, `next_cursor`, `total?`, `total_exact?`, `generation`, `phase`, `partial?`, `building?`, `untrusted?`, `notes?` |
| `Single<T>` | `value?`, `generation`, `phase`, `partial?`, `building?`, `untrusted?` |

`generation` is a decimal string: a token for the recording's content. For a
`complete` recording it is the ETag; for a `live` or `finalizing` one a cache
must not use it. `partial` is true when the recording is `interrupted` or an
engine limit cut the page. `total_exact` is false while the recording or a
packet parse is still growing. `untrusted` is true when rows carry strings that
came from the sample or the guest: escape them. `notes` is on the first page
of `recording.process.tree` (`issues[]`, `truncated`) and on the pages of
`recording.analysis.section` and `.ghidra` (`functions[]` for the source
listings, `sorted`).

`phase` is one of:

| Phase | Meaning |
|---|---|
| `live` | The boot is running or its recording is still being saved. Core reads (class C) work on the indexed prefix; Triage reads (class T) fail `precondition_failed` with `details.reason = "recording_open"` |
| `finalizing` | The recording is saved and final; the earlier-bytes copy or the disk merge is pending. Everything works; file rows carry `earlier: "pending"` and an earlier version fails `layer_pending` |
| `complete` | No layer is pending. Full reads; pages are cacheable by `generation` |
| `interrupted` | The writer is gone. Reads work; pages say `partial: true` |

A read of a recording that is still `live` or `finalizing` answers with its
phase and never claims a final total: `total_exact` is false while it grows. The
phase comes from the engine's list (`Snapshot.disk_layers`) when the service owns
the engine, else from the phase marker `run-layer.json` and the owner test
(design 5.12.2). A `running` run of a live boot is reported `running`; the same
saved state with no pending layer and no writer is `interrupted`.

A class T read whose scan is not cached answers at once with `building` (and no
items, no `next_cursor`, no `total`): a success that a binding maps to HTTP 202
with `Retry-After`. The client polls the same request. Core reads never answer
`building`.

## Operations

Class **C** needs only the engine. Class **T** needs the Triage scan and can answer
`building`. Permission **N** is `runs.see_all`, **S** is `evidence.view`.

| Op | Class | Permission | Request besides `recording_key` | Result |
|---|---|---|---|---|
| `recording.list` | C | N | `vm_id?`, `sample_sha256?`, `from_run?`, `state?`, `since_ms?` | `Page<RecordingInfo>` |
| `recording.get` | C | N | | `Single<RecordingDetail>` |
| `recording.summary` | T | N | | `Single<Summary>` |
| `recording.trace.page` | C | N | `pid?`, `q?`, `hide_groups[]` | `Page<TraceRow>` |
| `recording.trace.get` | C | N | `ref` | `Single<Invocation>` |
| `recording.captured.read` | C | S | `field`, `offset`, `len` (at most 65 536) | bytes |
| `recording.process.tree` | C | N | `root_pid?` | `Page<ProcessNode>` |
| `recording.findings.list` | T | N | `tier?`, `category?`, `rule?`, `pid?`, `q?`, `sort?` | `Page<Finding>` |
| `recording.findings.get` | T | N | `finding_id` | `Single<FindingDetail>` |
| `recording.indicators.list` | T | N | `kind?`, `matched?`, `q?`, `defang?`, `sort?` | `Page<Indicator>` |
| `recording.files.list` | T | N | `tab`, `q?`, `sort?` | `Page<FileRow>` |
| `recording.files.versions` | T | N | `file_id` | `Single<FileVersions>` |
| `recording.files.content` | T | S | `version_id`, `range?` (at most 1 MiB) | bytes |
| `recording.network.summary` | T | N | | `Single<NetworkSummary>` |
| `recording.network.list` | T | N | `tab`, `q?`, `sort?` | `Page<NetworkRow>` |
| `recording.network.captures` | C | N | | `Page<Capture>` |
| `recording.network.packets` | C | N | `capture_id`, `filter?` | `Page<PacketRow>` |
| `recording.network.packet` | C | S | `capture_id`, `n` | `Single<PacketDetail>` |
| `recording.timeline` | T | N | `from_ms?`, `to_ms?`, `kinds[]` | `Page<TimelineEvent>` |
| `recording.cores.list` | C | N | | `Page<CoreInfo>` |
| `recording.analysis.list` | C | N | `recording_key` or `run_id` | `Page<AnalysisSection>` |
| `recording.analysis.section` | C | N | `recording_key` or `run_id`, `kind`, `q?`, `sort?` | `Page<AnalysisRow>` |
| `recording.analysis.ghidra` | C | N | `recording_key` or `run_id`, `q?` | `Page<AnalysisRow>` |
| `recording.custody.list` | C | N | `sha256` or `recording_key` | `Page<CustodyEntry>` |
| `recording.terminal.replay` | C | N | | `Page<TerminalRecord>` |
| `recording.artifact.list` | C | N | | `Page<RecordingArtifact>` |
| `recording.artifact.get` | C | S or N | `artifact_id`, `range?` | bytes |

`recording.network.captures` items carry `link`, which run the segment belongs
to: `certainty` is `exact` (the run started it and lists it), `by_time` or
`vm_wide` or `unknown`, `run_id` names the owner and `live_runs` the other runs
that were live while the segment was written. `recording.network.packets` rows
carry `made_by` when the run's recording can be read: `kind` is `process`,
`background` (the base image's NTP, DHCP or apt traffic) or `unattributed`, with
a `label`, and for a process its `process`, `pid`, `tid` and the `also` that
made a matching call. Both are matched on the host from the run's recorded
network calls (address, protocol and time), so runs recorded earlier have them
too; the first `made_by` read of a run indexes the run once and is a heavy read.

Every list also takes `limit` and `cursor`. `capabilities.queries` lists, for the
build in front of you, every operation with its class, permission, subject, filters,
sortable fields, default order, maximum limit and (for operations with a `tab`) the
columns of each table; clients must read it instead of hard-coding a filter. The
catalogue is generated from the same table the operations are defined by, and a
test fails when an operation takes a filter or a sort the catalogue does not list.

## Identifiers and numbers

Identifiers and counters that can exceed 2^53 (task cookies, stream, call and
object ids, byte offsets of raw files) are decimal strings and are named `*_id`,
`*_cookie` or `*_offset`. Register values and addresses are lower-case hex strings
with `0x`. `*_ms` is host Unix milliseconds; `guest_ns` is the guest monotonic
clock of the recording, never wall time; `*_us` is Unix microseconds of the packet
capture clock. A `ts_ms` beside a `guest_ns` is the host time mapped through the
run's clock anchor, and is absent when the run has none (a run without an anchor
rejects `from_ms` and `to_ms` with `unsupported`).

## Paging, cursors and sorting

| Item | Rule |
|---|---|
| Limits | Row pages: default 100, at most 500 (packets 500, analysis and Ghidra pages 1024, terminal 256). A page is also cut when its encoded size would pass 1 MiB: fewer rows, never a truncated row |
| Cursor | Opaque; binds the offset, the `generation`, the filter and the sort. The trace cursor is a raw-file byte offset, not a row number |
| Stale cursor | A cursor from another generation, filter or sort fails `conflict` with `details.reason = "cursor_stale"`; on a live recording the client restarts from the first page |
| Sorting | A `sort` is `{field, dir}` with `dir` `asc` or `desc`. Only the lists whose catalogue entry has sortable fields accept it (findings, indicators, files, network, and the analysis listing where the engine supports it); a `sort` on any other list is `invalid_argument`. Sorting is over the whole row set before the page is cut |
| Byte reads | At most 65 536 bytes per call for `captured.read`, 1 MiB for `files.content` and `artifact.get`; whole files are streamed by the binding |

## Limits and deadlines

| Limit | Default |
|---|---|
| Light reads in flight (run list, trace pages, custody, artifact, capture and core lists, terminal replay) | 16 |
| Heavy reads in flight (Triage scans, the process tree, the packet filter, analysis listings that sort) | 2 |
| Deadline, light | 10 s |
| Deadline, heavy | 60 s for a page; a Triage scan runs in the background, bounded by 900 s |
| Scan cache | 2 scans in memory, 1 GiB, dropped when the `generation` changes |

Over the limit: `quota_exceeded` with `details.reason = "heavy_read_limit"` and
`retry_after_s`. A deadline: `unavailable` with `details.reason = "read_timeout"`;
the read is cancelled.

## Sensitivity

| Class | What | Rule |
|---|---|---|
| Normal (`runs.see_all`) | Run, process, finding, indicator, file, network and timeline rows; trace rows and calls; analysis rows; custody entries; packet rows; terminal replay | Strings are untrusted text. Indicator values are raw; the row carries the defanged form and `raw_indicators: true` |
| Sensitive (`evidence.view`; `artifact.get` needs `evidence.download`) | Bytes the sample or guest produced: `captured.read`, `files.content`, `network.packet`, and `artifact.get` of a capture, memory dump, core or file copy | Audit-logged: the daemon's service log gets one line per served read |
| Secret | Guest password, API keys, SOCKS password | Never in any result |
| Local | Host paths, `directory` | Local socket and CLI only |

## Read errors

| Condition | Error |
|---|---|
| Unknown or deleted `recording_key`, `file_id`, `capture_id`, `artifact_id`; a `recording_key` of a recording the service cannot reach | `not_found` |
| Cursor from another generation or filter | `conflict`, `reason: cursor_stale` |
| Earlier file bytes while the layer is pending | `precondition_failed`, `reason: layer_pending` |
| A Triage read of a recording that is still being written | `precondition_failed`, `reason: recording_open`, `details.phase` |
| The run never produced the data (no capture, no core) | `not_found`, `details.reason = "not_recorded"` |
| A core needs a newer guest revision | `unsupported`, `details.reason = "guest_revision"` |
| A byte range above its limit | `payload_too_large` |
| Heavy-read limit or deadline | `quota_exceeded` or `unavailable` (see above) |
| The recording is corrupt or the index cannot be built | `internal`, `details.reason = "recording_unreadable"` |
| A scan failed | `internal`, `details.reason = "scan_failed"`; the next call may start it again |

## Reserved

`recording.memory.*`, `recording.disks.*`, `recording.cores.read`,
`recording.cores.disassemble`, `recording.cores.strings`, `recording.screenshot.*`,
`recording.export.*` and every write are reserved; the service answers
`unsupported`.

## Implementation notes (cards Q-2 to Q-5)

- `recording.captured.read` takes the `field` string of an `Invocation` event
  field unchanged. The string is opaque (`<stream>.<task>.<call>.<event_seq>.
  <object_id>:<key>` today): it names the call, so no other state is needed.
- `q` is the Triage filter language of `antinomie-triage` (the one the window's
  tables and trace use). `recording.trace.page` takes the syscall filter
  (`syscall.name == "openat"`, a bare word matches the call text); the Triage
  tables take their own fields. With `q` or `hide_groups`, the `total` of the
  matching calls is counted on the first page, within a quarter of the light
  read deadline, and kept for later pages of the same filter and `generation`;
  a page has no `total` when that count did not finish or a cursor page has
  none kept (the rows are the same). A syntax or unknown-field error is
  `invalid_argument` with `field: "q"` and `details.position` (the 1-based column).
  The fields of each table, and its sortable columns, are the Triage crate's own
  `FieldSpec` names (`finding.rule`, `file.path`, `network.bytes`, `ioc.value`,
  `http.host`, ...), published in `capabilities.queries.ops[].tables`; every
  column of a table is sortable.
- **Triage reads (class T, card Q-4).** The first class T read of a run starts
  its Triage scan on a thread of its own and answers `building` with the
  scan's progress (`progress {done, total}`, `retry_after_ms`); ask again after
  that time. The scan is the index the window makes when the run is selected
  (`SavedRun`), run read-only: it writes no finding journal, no event journal and
  never `triage-digest.json`. Two scans are kept in memory (the least recently
  used goes first) and a scan of a recording whose `generation` changed is dropped;
  `heavy_concurrency` scans run at once, one more is `quota_exceeded`; a scan that
  runs past 900 s is cancelled and the next read starts it again (`scan_failed`).
  Filter, sort and paging run over the whole row set of the scan. A table the scan
  holds only in part (more rows than its page limit, 2 000 by default) says
  `partial: true` and `total_exact: false`. A recording that is `live` is refused
  with `recording_open`; `finalizing` and `interrupted` recordings are read.
- `recording.summary` is the report summary of the export (`Summary` without the
  preset's `label` and `score`): the same builder as `antinomie-cli report`, so the
  counts are the window's. `recording.indicators.list` rows are the report's
  indicators with the dataset verdict; with `defang: true` the `value` is the
  defanged form and `raw_indicators` is false.
- `recording.findings.get` returns the representative call as `evidence_refs[0]`
  and the rest of the folded occurrences as `evidence_omitted`: the scan keeps
  one row per folded finding. `recording.files.list` rows of the `changed` tab
  carry the reconstruction state and the earlier-bytes state; `files.versions`
  gives the earlier version (the recording's `file-before/` copy) and the later
  one (rebuilt from the recorded writes; available only when the writes cover the
  whole file). `recording.timeline` merges process start and exit, findings,
  changed and executed files and network first-seen rows; detection hits carry
  no time and are not part of it; events with no host time (no clock anchor) are
  left out and the page says `partial`. `network.list` `urls` is one row per
  distinct request (method, host, URI).
- Reads run in two pools (light 16, heavy 2 by default). A full heavy pool is
  `quota_exceeded` with `details.reason = "heavy_read_limit"` and
  `retry_after_s`; a read past its deadline (10 s light, 60 s heavy) is
  `unavailable` with `details.reason = "read_timeout"`; a read whose client went
  away is `unavailable` with `details.reason = "cancelled"`.
- A read holds a lease on its run; `QueryService::run_is_open` tells retention to
  skip it.
- `network.packets` pages come from TShark (inside bubblewrap) through the
  engine's packet filter. A display filter TShark rejects is `invalid_argument`
  naming `filter`. The decoded packet (`network.packet`) is sensitive: its tree
  spells payload text and it carries the frame bytes.
- A custody reply carries the file name only in `origin`, `path` and `from` for a
  caller whose `client_id` does not start with `local:`.
