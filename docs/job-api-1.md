# Job API, version 1

[← Back to the overview](../README.md)

This is the contract of the headless job API: the objects, states, events,
operations and errors that the command line (`antinomie-cli`), the local socket
and, later, the web process share. The machine-readable form is
[job-api-1.schema.json](job-api-1.schema.json), generated from the Rust types of
the `antinomie-service` crate (`src/api/`) with `schemars` and checked in; a test
fails when the file is stale. The recording reads (`recording.*`) are added by
the query contract.

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
