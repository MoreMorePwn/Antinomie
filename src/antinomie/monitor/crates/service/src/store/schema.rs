// SPDX-License-Identifier: GPL-3.0-only
//! The tables of design 4.3. `schema_version` starts at 1; a newer database
//! refuses to open on an older daemon.

pub const SCHEMA_VERSION: u32 = 1;

/// Columns beyond design 4.3, and why:
/// `terms_json` holds the frozen policy (5.6: "the policy digest and the
/// resolved limits are stored with the job"); `canon_json` the canonical spec
/// as sent, for idempotency (5.2); `wait_s`, `waiting_since_ms`,
/// `not_before_ms` the queue wait and backoff of 4.7; `forgiven` the attempts
/// that do not count (4.7.3); the `host_work` table the items of the host work
/// pool (ANT-T0454, one row per job, added without a version change: it is
/// created when missing); the `job_recordings` table every run a job's
/// attempts recorded, so retention and `run.delete` reach the earlier ones
/// too (added the same way); `cancel_reason`/`cancel_shutdown` the cancel
/// request; the `*_json` columns the parts of the `Run` object (5.4.2) that
/// have no column in the table of 4.3.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY,
    created_ms INTEGER NOT NULL,
    started_ms INTEGER,
    finished_ms INTEGER,
    state TEXT NOT NULL,
    stage TEXT,
    outcome TEXT,
    priority INTEGER NOT NULL,
    waiting_for TEXT,
    waiting_since_ms INTEGER,
    not_before_ms INTEGER,
    wait_s INTEGER NOT NULL,
    policy_name TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    terms_json TEXT NOT NULL,
    sha256 TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    forgiven INTEGER NOT NULL DEFAULT 0,
    lane TEXT,
    vm_id TEXT,
    run_key TEXT,
    idempotency_key TEXT,
    client_id TEXT NOT NULL,
    repeat_of TEXT,
    failure_code TEXT,
    failure_json TEXT,
    cancel_reason TEXT,
    cancel_shutdown INTEGER NOT NULL DEFAULT 0,
    spec_json TEXT NOT NULL,
    canon_json TEXT NOT NULL,
    labels_json TEXT NOT NULL DEFAULT '{}',
    sample_json TEXT,
    vm_json TEXT,
    run_json TEXT,
    recording_json TEXT,
    assessment_json TEXT,
    warnings_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(state, priority DESC, created_ms);
CREATE INDEX IF NOT EXISTS jobs_sha256 ON jobs(sha256);
CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency ON jobs(client_id, idempotency_key);
CREATE INDEX IF NOT EXISTS jobs_finished ON jobs(finished_ms);
CREATE TABLE IF NOT EXISTS attempts(
    job_id TEXT NOT NULL,
    n INTEGER NOT NULL,
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    stage_reached TEXT,
    failure_code TEXT,
    detail TEXT,
    boot_id TEXT,
    run_id TEXT,
    PRIMARY KEY(job_id, n)
);
CREATE TABLE IF NOT EXISTS stages(
    job_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    PRIMARY KEY(job_id, attempt, stage)
);
CREATE TABLE IF NOT EXISTS artifacts(
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sensitive INTEGER NOT NULL,
    raw_indicators INTEGER NOT NULL DEFAULT 0,
    location TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS artifacts_job ON artifacts(job_id, created_ms);
CREATE TABLE IF NOT EXISTS events(
    gseq INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT,
    seq INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    type TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_job ON events(job_id, seq);
CREATE TABLE IF NOT EXISTS host_work(
    job_id TEXT PRIMARY KEY,
    attempt INTEGER NOT NULL,
    items_json TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS job_recordings(
    job_id TEXT NOT NULL,
    run_key TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    lane TEXT,
    recording_json TEXT NOT NULL,
    PRIMARY KEY(job_id, run_key)
);
";
