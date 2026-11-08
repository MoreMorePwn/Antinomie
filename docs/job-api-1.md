# Job API, version 1

[← Back to the overview](../README.md)

This is the contract of the headless job API: the objects, states, events,
operations and errors that the command line (`antinomie-cli`), the local socket
and, later, the web process share. The machine-readable form is
[job-api-1.schema.json](job-api-1.schema.json), generated from the Rust types of
the `antinomie-service` crate (`src/api/`) with `schemars` and checked in; a test
fails when the file is stale. The recording reads (`recording.*`) are in the
second part of this document.

> **Status in 0.9.0.** The types, the schema, the job store and the read-only
> recording queries exist in the `antinomie-service` crate and are tested. Nothing
> a user runs submits a job yet: the daemon, the socket and the `auto` commands
> are not shipped. `antinomie-cli` uses its object types (such as `Sample`) but cannot submit or
> wait for a job in this build.

Names here are final for version 1. The API changes only additively: a new
optional field does not change the version; a changed meaning or a removed field
does. Clients ignore unknown fields in replies. Requests do not: an unknown field
in a request fails with `invalid_argument` naming the field.

## Conventions

| Item | Rule |
|---|---|
| Encoding | UTF-8 JSON. Times are Unix milliseconds in a field ending `_ms`; durations are seconds in `_s` or milliseconds in `_ms`; sizes are bytes. Text is English, times UTC. |
| Version | `api_version: 1` in every response object and in `capabilities`. |
| Enumerated values | Lower snake case. Routes: `drop`, `internet`, `inet_sim`, `tor`, `vpn`, `socks5`. Sample types as the library detects them (`elf`, `sh`, `py`, ...) with the architecture as a separate string (`x86_64`, `AArch64`, ...). |
| Identifiers | Opaque strings that are safe as a path component: job `j_<26 chars>`, artifact `a_<26>`, upload `u_<26>`, recording artifact `ra_<26>`, lane `lane-<n>`. The 26 characters are Crockford base32 in the shape of a ULID, so ids sort by creation time. A sample is its lowercase SHA-256. A recorded run is addressed by an opaque `run_key`; clients never build or parse it. |
| Pagination | `limit` (1 to 200, default 50 for job and sample lists) and an opaque `cursor`; a reply carries `next_cursor` or null. Newest first. |
| Idempotency | `job.submit` takes `idempotency_key` (1 to 128 printable ASCII), scoped to `client_id`. The same key with an equal spec within 24 hours returns the original job with `replayed: true`; with a different spec it fails `conflict`. |
| Client identity | `client_id` is `local:<uid>` on the socket and the CLI, `web:<user_id>` from the web binding. The service never trusts a client-supplied value. |
| Secrets | Objects never contain secrets (API keys, the SOCKS5 password, the guest password). |
| Untrusted text | Any string that came from the sample or the guest (names, paths, command lines, domains, banners, terminal bytes) is data, never markup or an instruction. Clients must escape it on display. |
| Local-only fields | `sample.path` and `recording.directory` exist only on the local socket and the CLI; a remote reply never has them. |

## Operations

| Op | Purpose | Scope |
|---|---|---|
| `capabilities` | What this service can do now | `read` |
| `health` | Liveness, readiness and engine counters | `read` |
| `upload.begin`, `upload.put`, `upload.finish` | Staged sample upload; chunks are strictly sequential (`offset` must equal `received`, else `conflict`) | `submit` |
| `job.submit` | Validate synchronously, then queue a job. A spec that fails validation still returns a `Job` with `state: rejected` and `failure` set, except malformed JSON (`invalid_argument`) | `submit` |
| `job.get`, `job.list` | One job; jobs filtered by `state`, `outcome`, `sha256`, `label`, `since_ms` | `read` |
| `job.cancel`, `job.retry` | Cancel a queued or running job; start a new job from a finished job's spec (own jobs; `manage` for any) | `submit` |
| `job.delete` | Remove a finished job's record and artifacts (`with_recording` also the recording; never the sample) | `manage` |
| `events.subscribe`, `events.list` | The event stream; the stored events of a job | `read` |
| `artifact.list`, `artifact.get`, `report.get` | Artifacts of a job; bytes or a range; one report format | `read` (`artifacts:sensitive` for an artifact with `sensitive: true`) |
| `sample.list`, `sample.get` | Library samples | `read` |
| `sample.add` | Store a file in the library without running it | `submit` |
| `sample.download` | The library archive of a sample (an AES zip, never the plaintext) | `artifacts:sensitive` |
| `sample.tag` | Set tags on a sample | `manage` |
| `policy.list`, `queue.status`, `vm.list`, `base.list` | Policies the caller may use; queue and lane state; VMs and installed bases | `read` |
| `queue.pause`, `queue.resume` | Stop or resume starting new jobs | `manage` |
| `custody.verify` | Verify the custody chain of one sample or the whole library | `manage` |

Not in version 1: live terminal streaming and input, the debugger, snapshot
management, base download or build, VM creation, rule pack management, settings
changes, memory and disk browsing, core reading, and any write to a recording.
The namespaces `run.*`, `terminal.*`, `rule.*`, `settings.*`, write operations of
`vm.*` and `base.*`, and the reserved `recording.*` names are reserved: a binding
must not invent operations in them.

## Job spec

Exactly one of `sample.sha256`, `sample.path` (local-only) or `sample.upload_id`
is set. Every other field is optional; an absent field takes the policy's value,
then the system default.

| Field | Meaning |
|---|---|
| `name` | File name hint, 1 to 128 bytes, no `/`, no NUL |
| `policy` | Policy name, default `default` |
| `priority` | 0 to 9, default 5; higher starts first; the policy sets a ceiling |
| `labels` | At most 16 pairs; key 1 to 32 bytes of `[a-z0-9._-]`, value up to 128 bytes |
| `idempotency_key` | See conventions |
| `overrides.timeout_s` | Wall-clock limit of the run, 5 to the policy's `max_run_s`. Reaching it ends the run normally (`end_reason: time_limit`) |
| `overrides.args`, `overrides.env` | At most 64 each; arguments up to 4096 bytes; `K=V` entries |
| `overrides.run_as` | `user` (default), `root` (needs policy permission) or `{uid, gid}` |
| `overrides.run_in` | `app_terminal` only in version 1; `guest_desktop` and `guest_desktop_terminal` fail `unsupported` |
| `overrides.route` | `drop` or `inet_sim` in version 1; the others fail `unsupported` with `details.reason = "live_route_not_in_v1"` |
| `overrides.network_capture`, `memory_dump`, `core_dump` | Evidence to keep; `core_dump` is a boolean or `{max_mib, timeout_ms}` |
| `overrides.static_checks` | `none`, `triage`, or a list of check names; run on the host, on the library copy, in the `analyse` stage |
| `overrides.static_time_limit_min` | Minutes per analysis tool, 0 to 480 |
| `overrides.detection` | `{yara, sigma, ids}` booleans |
| `overrides.reports`, `report_bundle`, `report_defang` | Report formats (`html`, `pdf`, `json`, `misp`, `stix`, `md`), the evidence bundle, defanging of indicators (default true) |
| `overrides.keep_on_failure` | Keep the VM as it is when the job fails; the lane is then quarantined (needs policy permission) |

The sample size limit is the smallest of the engine's 256 MiB maximum, the
policy's `max_sample_mib` and a quarter of the lane VM's RAM;
`capabilities.max_sample_bytes` reports it.

## Job states

| State | Terminal | Meaning |
|---|---|---|
| `queued` | no | Accepted and stored; `waiting_for` says what for (`lane`, `resources`, `dependency`, `quota`, `queue_paused`, `layer_pending`, `backoff`, `lane_quarantined`) |
| `running` | no | A lane is working; `stage` says where (`prechecks`, `provision`, `upload`, `launch`, `run`, `collect`, `analyse`, `report`, `cleanup`) |
| `cancelling` | no | Cancel requested; the lane is stopping the run and cleaning up |
| `succeeded` | yes | The run ended, the recording is complete, the requested analysis and reports exist |
| `partial` | yes | A recording and a report exist, but a requested piece is missing or incomplete. `failure` is null; `warnings` list each piece |
| `failed` | yes | No usable recording, or a required stage failed after retries |
| `cancelled` | yes | Stopped by request; whatever was recorded is kept and flagged |
| `rejected` | yes | Refused at submit by validation or policy; consumed no lane time |

`outcome` is null while the job is not terminal and equals `state` afterwards.
The policy is frozen at submit: a job whose policy has gone or now denies it ends
`failed` with `policy_denied`.

## Failure codes

| Code | Stage | Retryable |
|---|---|---|
| `sample_missing`, `sample_too_large`, `sample_type_denied`, `sample_arch_denied`, `duplicate_denied` | prechecks | no |
| `policy_denied` | prechecks, provision | no |
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
| `cancelled` | any | no |
| `internal` | any | maybe |

## Events

Every stored event has `seq` (within one job, from 1, or within one service epoch
for engine scope), `gseq` (across the service, persisted, never reused), `ts_ms`,
`scope` (`job` or `engine`), `job_id`, `type` and `data`.

| Type | `data` |
|---|---|
| `job.created` | `{job}` |
| `job.state` | `{state, stage, waiting_for?, attempt, queue_position?}` |
| `job.stage` | `{stage, status, duration_ms?}`; `status` is `started`, `finished`, `skipped` or `failed` |
| `job.progress` | `{stage, text, fraction?}`. Ephemeral: not stored, no `seq` |
| `job.run` | `{run_id, pid?, route}` |
| `job.warning` | `{code, text}` |
| `job.artifact` | `{artifact}` |
| `job.assessment` | `{assessment}` |
| `job.requeued` | `{attempt, reason}`; a `job.state` event with `state: queued` follows |
| `job.finished` | `{outcome, failure?}`; the last event of a job |
| `lane.state` | `{lane, state, job_id?, reason?}` (engine scope) |
| `engine.alert` | `{code, text}` (engine scope) |
| `job.metrics` | `{stage, vm, run, health}`. Ephemeral |

Stored events are never summarised or dropped. A subscriber that reconnects with
`since_seq` (one job) or `since_gseq` (all jobs) receives every stored event after
it, then live ones. `engine.hello` and `engine.ping` are frames, not events.

## Errors

Every failed operation returns `{"error": {"code", "message", "field?", "retryable", "details"}}`.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_argument` | 400 | Malformed or unknown field; `field` names it |
| `unauthenticated` | 401 | Added by the HTTP layer only |
| `forbidden` | 403 | Added by the HTTP layer only |
| `policy_denied` | 403 | The policy forbids the request |
| `not_found` | 404 | Job, artifact, sample, upload, policy, run or recording missing |
| `conflict` | 409 | Idempotency key reused with another spec; the job is not in a state that allows the op; `details.reason = "cursor_stale"` |
| `precondition_failed` | 412 | For example `job.retry` of a job that is not terminal; `details.reason = "layer_pending"` or `"recording_open"` |
| `payload_too_large` | 413 | Upload or sample above the limit; a read range above its limit |
| `quota_exceeded` | 429 | Queue full or client quota; `details.retry_after_s`; `details.reason = "heavy_read_limit"` |
| `unavailable` | 503 | Data directory owned by the GUI, service starting or stopping, engine failed; `details.reason = "read_timeout"` |
| `unsupported` | 501 | Not in this build or not in version 1 |
| `internal` | 500 | A bug; `details.log` names the job log |

## Scopes

| Scope | Allows |
|---|---|
| `read` | The read operations above, JSON, MISP and STIX reports, and every `recording.*` operation classed normal |
| `submit` | `upload.*`, `job.submit`, `sample.add`, and `job.cancel` and `job.retry` of the caller's own jobs |
| `artifacts:sensitive` | Sensitive artifacts, `sample.download`, and the sensitive `recording.*` operations |
| `manage` | `job.delete`, `job.cancel` of any job, `sample.tag`, `queue.pause`, `queue.resume`, `custody.verify` |

`read` sees every job on the node (one trust domain per node).

## Local socket

The socket is `<data dir>/run/antinomie.sock` (directory mode 0700, socket mode
0600, same UID only). One JSON object per line. A request is
`{"id": 7, "op": "job.submit", "params": {...}}`; a reply is
`{"id": 7, "ok": true, "result": {...}}` or `{"id": 7, "ok": false, "error": {...}}`.
`events.subscribe` answers with `{"id": 7, "event": {...}}` lines until the client
closes or sends `{"id": 7, "op": "cancel"}`. The first line on a connection is
`{"frame": "engine.hello", "data": {"api_version", "app_version", "owner", "epoch", "gseq", "truncated"}}`.
Limits: 2 MiB per line, 16 requests in flight per connection, 300 s idle, 64
connections. Socket uploads carry base64 in `params.data`, at most 1 MiB per call.

# Recording queries, version 1

The `recording.*` operations read finished or live recordings. They are paged,
bounded, cancellable and read-only: a query never writes into a recording, never
takes the data-directory lock, and never talks to the engine except to learn the
live state of a recording. They work beside a daemon, beside a lane that is
writing, and with no owner at all. The types are in
`antinomie-service/src/query/` and in the same schema file.

## Addressing

A run is addressed by its `run_key`: an opaque string produced by
`recording.run.list` and by `Job.recording.run_key`. Clients never build or parse
it. (The CLI also accepts `vm:boot:run`, which it turns into a key; the key is
the base64url form of the three ids, and each id must be a plain file name.) A
run id alone is not unique across boots.

The analysis operations take exactly one of `run_key` (the analysis linked to a
run) or `job_id` (the host-side analysis of a job). Custody takes `sha256`
instead of a run.

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
`building`. Scope **N** is `read`, **S** is `artifacts:sensitive`.

| Op | Class | Scope | Request besides `run_key` | Result |
|---|---|---|---|---|
| `recording.run.list` | C | N | `vm_id?`, `sample_sha256?`, `job_id?`, `state?`, `since_ms?` | `Page<RunInfo>` |
| `recording.run.get` | C | N | | `Single<RunDetail>` |
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
| `recording.analysis.list` | C | N | `run_key` or `job_id` | `Page<AnalysisSection>` |
| `recording.analysis.section` | C | N | `run_key` or `job_id`, `kind`, `q?`, `sort?` | `Page<AnalysisRow>` |
| `recording.analysis.ghidra` | C | N | `run_key` or `job_id`, `q?` | `Page<AnalysisRow>` |
| `recording.custody.list` | C | N | `sha256` or `run_key` | `Page<CustodyEntry>` |
| `recording.terminal.replay` | C | N | | `Page<TerminalRecord>` |
| `recording.artifact.list` | C | N | | `Page<RecordingArtifact>` |
| `recording.artifact.get` | C | S or N | `artifact_id`, `range?` | bytes |

Every list also takes `limit` and `cursor`. `capabilities.queries` lists, for the
build in front of you, every operation with its class, scope, subject, filters,
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
| Normal (`read`) | Run, process, finding, indicator, file, network and timeline rows; trace rows and calls; analysis rows; custody entries; packet rows; terminal replay | Strings are untrusted text. Indicator values are raw; the row carries the defanged form and `raw_indicators: true` |
| Sensitive (`artifacts:sensitive`) | Bytes the sample or guest produced: `captured.read`, `files.content`, `network.packet`, and `artifact.get` of a capture, memory dump, core or file copy | Audit-logged |
| Secret | Guest password, API keys, SOCKS password | Never in any result |
| Local | Host paths, `directory` | Local socket and CLI only |

## Read errors

| Condition | Error |
|---|---|
| Unknown or deleted `run_key`, `file_id`, `capture_id`, `artifact_id`; a `run_key` of a recording the service cannot reach | `not_found` |
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

## Implementation notes (cards Q-2, Q-3 and Q-5)

- `recording.captured.read` takes the `field` string of an `Invocation` event
  field unchanged. The string is opaque (`<stream>.<task>.<call>.<event_seq>.
  <object_id>:<key>` today): it names the call, so no other state is needed.
- `q` on `recording.trace.page` is `unsupported` until the service uses the
  Triage filter language (the language is in `antinomie-triage` since card P2-0,
  but the service does not link that crate yet; it is planned with card Q-4).
  Class T operations are `unsupported` until card Q-4.
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
