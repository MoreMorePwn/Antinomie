# Job API, version 1

[← Back to the overview](../README.md)

This is the contract of the headless job API: the objects, states, events,
operations and errors that the command line (`antinomie-cli`), the local socket
and, later, the web process share. The machine-readable form is
[job-api-1.schema.json](job-api-1.schema.json), generated from the Rust types of
the `antinomie-service` crate (`src/api/`) with `schemars` and checked in; a test
fails when the file is stale. The recording reads (`recording.*`) are in the
second part of this document.

> **Status in 0.9.0.** The types, the schema, the job store, the read-only
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

`antinomie-cli auto daemon` serves the operations of this document, and the
`recording.*` reads of the second part, on a Unix socket.

| Item | Value |
|---|---|
| Path | `<data dir>/run/antinomie.sock` (or `[daemon] socket` in `service.toml`, or `--socket`); at most 107 bytes |
| Folder | Must be a real directory owned by the daemon's user with mode 0700; the daemon refuses to start otherwise (a symlink, another owner, group or other access) |
| Socket file | Mode 0600, set right after `bind`. An old socket file is replaced (the daemon holds the data-directory lock, so no one else serves it); any other file at the path is left alone and the start fails. The daemon removes its own socket when it stops |
| Who may connect | Peer credentials (`SO_PEERCRED`) are read on accept: only the daemon's own UID. Another UID is closed without a byte, not even the hello |
| Identity | The caller is `local:<uid>` with every scope (`read`, `submit`, `artifacts:sensitive`, `manage`): the socket is the owner's single-user view. Nothing in a request changes it |
| Framing | One JSON object per line, UTF-8, at most 2 MiB per line, both ways. A request is `{"id": N, "op": "...", "params": {...}}` and nothing else: `id` an integer from 0 to 2^53 - 1, `op` 1 to 64 printable ASCII characters, `params` an object (absent or `null` reads as `{}`). Any other member is `invalid_argument` naming it |
| Replies | `{"id": N, "ok": true, "result": ...}` or `{"id": N, "ok": false, "error": {...}}` |
| Hello | The first line of a connection is `{"frame": "engine.hello", "data": {"api_version", "app_version", "owner", "epoch", "gseq", "truncated"}}`, with no `id`. A client that does not know the `api_version` closes |
| Cancel | `{"id": N, "op": "cancel"}` cancels the request `N` in flight; that request answers for itself (a subscription with `{"cancelled": true, ...}`, another request with `unavailable`, reason `cancelled`). A cancel of an id not in flight is `not_found`. Closing the connection cancels everything it had in flight, including a recording read |
| Host paths | `sample.path` is refused on the socket (`invalid_argument`, field `sample.path`): a file arrives with `upload.begin`, `upload.put` and `upload.finish`, so no client makes the daemon open a path of its choosing. `artifact.get` and `report.get` answer with the file's `path` (local-only), resolved inside the job's directory: a recorded location that is absolute, has `..`, or leads through a symlink out of the job directory is not served |

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
| One job (`job_id`, `since_seq`) | Every stored event of that job with `seq` above `since_seq`, then live ones; never an event of another job | The job's whole history | After `job.finished` (the job's last event): `{"id": N, "ok": true, "result": {"finished": true, "last_seq": ...}}` |
| All jobs and the engine (`since_gseq`) | Every stored event with `gseq` above `since_gseq`, then live ones | From now | On cancel, or when the daemon stops (`unavailable`, reason `service_stopping`) |

There is no gap and no duplicate across the resume: the stream subscribes to the
live events first, then reads the table, then skips what the table gave; the store
publishes events in commit order. A stream whose live buffer overflows (4096
events) reads the table again from the last event it sent, so a burst loses
nothing. `truncated` is true when `since_gseq` is older than the oldest retained
event (engine events are kept 7 days or 100 000 rows) or higher than any `gseq`
this store has stored (another or a restored store); the client re-synchronises
with `job.list`. `since_seq` without `job_id`, `since_gseq` with it, and an
unknown name in `types` are `invalid_argument`; an unknown job is `not_found`.
Ephemeral events (`job.progress`, `job.metrics`) are sent live only.

**Operations served in 0.9.0.** `capabilities`, `health`, `upload.*`,
`job.submit`, `job.get`, `job.list`, `job.cancel`, `job.retry`, `events.subscribe`,
`events.list`, `artifact.list`, `artifact.get`, `report.get`, `policy.list`,
`queue.status`, `queue.pause`, `queue.resume`, `job.delete`, the `lane.*`, `watch.*` and
`gc.run` operations below,
`sample.list`, `sample.get`, `sample.add`, `sample.download`, `sample.tag`,
`vm.list`, `base.list`, `custody.verify` and every `recording.*` read. The reserved names of 5.11
(`run.`, `terminal.`, `rule.`, `settings.`, writes of `vm.` and `base.`) are
`unsupported`; any other unknown name is `invalid_argument` on `op`. While the
daemon stops, `job.submit`, `job.retry` and `upload.*` are `unavailable` with
reason `service_stopping`.

**Library, VM and base operations (additions to the table above).** They answer
from the same code direct mode runs, so the CLI prints the same objects either way.

| Operation | Notes |
|---|---|
| `sample.list` | `{samples, next_cursor}`, newest first. Besides `q`, `tag`, `limit` (1 to 1000, default 100) and `cursor`: `tags[]` (more `KIND=VALUE` tags the sample must also have), `all` (include samples whose archive was removed), `custody` (fill `custody_ok`). A tag is `KIND=VALUE` (`verdict`, `category`, `technique`, `custom`); a bare value is a custom tag |
| `sample.get` | The `Sample` object plus `sha1`, `md5`, `description`, `removed_ms` and `custody` (the chain's summary). `origins`, `events` and `runs` (booleans) add those lists |
| `sample.add` | Takes `sample.upload_id` only. `sample.path` and `sample.sha256` are `invalid_argument` on the socket (the daemon opens no path a client names). The type and architecture come from the bytes; no policy applies. The custody entry names the caller (`local:<uid>`). The answer is `sample.get`'s object plus `new` |
| `sample.tag` | Sets the whole tag list (`[{kind, value}]`); the custody entry `edited` (tags) names the caller. The answer is the `Sample` object |
| `sample.download` | `sha256` and an optional `range {offset, len}` (at most 1 MiB; default the first MiB). The answer is `{sha256, format: "zip-aes256", password: "infected", size, range {offset, len, data}}` with `data` Base64 of the AES archive (never the plaintext). The first range (`offset` 0) writes one custody entry `exported`. Needs `artifacts:sensitive` |
| `vm.list` | `{vms: [{id, name, base_identity, lane}]}` from the engine's latest snapshot; the lane VM carries its lane |
| `base.list` | `{bases: [{identity, name, architecture}]}`; no host path. While the engine still lists them: `unavailable`, `retryable` |
| `custody.verify` | `{ok, head, problems[]}` plus, for one sample, `sha256`, `entries`, `problem`, `summary`; for the library, `index`, `samples[]`, `broken[]`. Needs `manage` |

**Service log for sensitive reads.** Every served read of the sample's own bytes
writes one line to the daemon's service log (`antinomie-cli auto daemon` standard
error, or its log file): `sensitive read: caller=<id> op=<op> run=<vm:boot:run> size=<bytes>`
for `recording.captured.read`, `recording.files.content`, `recording.network.packet`
and `recording.artifact.get` of a capture, memory dump, core or file copy;
`... op=artifact.get job=<job id> ...` for a job artifact with `sensitive: true`
(`report.get` too); and `... op=sample.download sample=<sha256> ...` for each range
of an archive. `size` is the number of bytes served (the frame length for a packet).
A refused read and a read of rows write nothing, a read that the scan still
builds (`building`) writes nothing yet, and the line never carries the bytes, a
host path or a name from the sample.

**Runs and jobs.** `RunInfo.job_id` and the `job_id` filter of
`recording.run.list` come from the job store: a job records its run (`recording`)
when its lane stage opens it, and the reads find the newest job whose run is that
one. The daemon and the CLI's direct mode use the same index (direct mode opens the
store read-only and creates nothing), so both print the same `job_id`. A run no job
made, and a data directory with no job store, show `job_id: null`.

**Reads from the CLI.** With a daemon at the socket `run list`, `run show`, `run
export`, `triage` and the other read commands send these operations; `run export`
never sends an output path: the command pages through `recording.*` and writes the
files under `--out` itself, and the bytes the sample produced are fetched only with
`--sensitive` (the scope `artifacts:sensitive` is checked again by the daemon, and
each read is written to its service log). `sample add FILE` sends the file with
`upload.begin`, `upload.put` and `upload.finish`, then calls `sample.add` with the
`upload_id`. A
page that would not fit a 2 MiB line is `payload_too_large` and the command asks
again for fewer rows.

`job.retry` makes a new job from a finished one: the spec the client first sent,
the sample named by its library hash, no idempotency key, the given `overrides`
replacing the original's one field at a time, the current policy, and
`repeat_of` set. The job must be terminal (`precondition_failed` otherwise) and
the caller its owner or a holder of `manage`.

**Lane operations** (an addition of this binding; section 5.3 has none for lanes,
and the CLI's `auto lane` commands need them while a daemon owns the folder):

| Op | Scope | Params | Result |
|---|---|---|---|
| `lane.list` | `read` | `lane?` (ignored) | `[{lane, vm_id, vm_name, clean_snapshot_id, base_identity, quarantine, quarantine_detail, failures, busy_with, collected, problems[]}]`; `problems` are the checks of `lane.unquarantine` in words |
| `lane.reset` | `manage` | `lane?` (default `lane-1`) | The lane after the revert: the clean snapshot restored, the guest answering, the VM stopped and settled; a quarantine is lifted. A failed revert keeps the lane as it was |
| `lane.unquarantine` | `manage` | `lane?` | The lane with the quarantine lifted when the checks pass (`precondition_failed` naming the failing check otherwise) |

`lane.reset` and `lane.unquarantine` are carried out by the lane's own thread and
only while no job runs: a busy lane answers `conflict` at once (pause the queue
first), and a request not reached within its wait (900 s, 60 s) is dropped, never
run late. Each sends `lane.state` with the reason.

`job.delete` (`manage`) removes an ended job's row, events, artifacts and folder
and answers `{deleted: true}`. A job that has not ended is a `conflict`. With
`with_recording: true` the job's recording is deleted first through the engine's
own run deletion (custody actor `auto:policy-<policy>`); a recording that a
`recording.*` read has open, or whose artifacts are still being written, is a
`precondition_failed` with `details.reason = "recording_open"` and nothing is
removed. Without `with_recording` the recording stays where it is.

**Watch folder and retention operations** (an addition of this binding; the
CLI's `auto watch` and `auto gc`):

| Op | Scope | Params | Result |
|---|---|---|---|
| `watch.list` | `read` | none | `{folders: [{path, policy, state, detail, taken, rejected, refused: [{name, reason}], pending, last_scan_ms, paused_until_ms}]}`; `state` is `watching`, `paused`, `held`, `refused` or `error` |
| `watch.scan` | `manage` | none | The same, after a scan made now (waits at most 30 s) |
| `gc.run` | `manage` | `dry_run?` (default false) | `{dry_run, now_ms, actions: [{kind, job, run, detail, bytes, done}], skipped: [{kind, job, why}], errors[], freed_bytes}`; `kind` is `recording`, `job`, `upload` or `rejected_file` |

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
| Sensitive (`artifacts:sensitive`) | Bytes the sample or guest produced: `captured.read`, `files.content`, `network.packet`, and `artifact.get` of a capture, memory dump, core or file copy | Audit-logged: the daemon's service log gets one line per served read |
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

## Implementation notes (cards Q-2 to Q-5)

- `recording.captured.read` takes the `field` string of an `Invocation` event
  field unchanged. The string is opaque (`<stream>.<task>.<call>.<event_seq>.
  <object_id>:<key>` today): it names the call, so no other state is needed.
- `q` is the Triage filter language of `antinomie-triage` (the one the window's
  tables and trace use). `recording.trace.page` takes the syscall filter
  (`syscall.name == "openat"`, a bare word matches the call text); the Triage
  tables take their own fields. A syntax or unknown-field error is
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
  policy `label` and `score`): the same builder as `antinomie-cli report`, so the
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
