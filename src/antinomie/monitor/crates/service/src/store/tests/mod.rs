// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the job store (card P3-2): submit and validation, the state
//! machine, events, listing, crash safety and a property test.

mod crash;
mod events;
mod lifecycle;
mod limits;
mod permissions;
mod property;
mod submit;

use super::*;
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        event::EventBody,
        failure::{Failure, FailureCode},
        ids::{LaneId, RunId, Sha256Hex},
        ops::{Caller, Permission},
        run::{Outcome, Run, RunSample, RunState, Stage, Submitted, WaitingFor},
        spec::{RunRequest, SampleSource},
    },
    clock::ManualClock,
    config::{LoadedPreset, Preset, PresetSet, service::OnDuplicate},
    store::submit::SubmitContext,
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

pub(crate) const T0: u64 = 1_794_000_000_000;

pub(crate) fn sha(n: u8) -> Sha256Hex {
    Sha256Hex::try_from(format!("{n:02x}").repeat(32)).unwrap()
}

/// The intake of a test: a table of samples.
pub(crate) struct FakeIntake {
    pub samples: BTreeMap<String, RunSample>,
}

impl SampleAdmission for FakeIntake {
    fn admit(
        &self,
        source: &SampleSource,
        _name: Option<&str>,
        preset: &LoadedPreset,
        _actor: &str,
    ) -> Result<RunSample, IntakeError> {
        let err = |code, message: &str| IntakeError {
            code,
            message: message.into(),
        };
        let sha = source
            .sha256
            .as_ref()
            .ok_or_else(|| err(FailureCode::SampleMissing, "only library samples here"))?;
        let sample = self
            .samples
            .get(sha.as_str())
            .ok_or_else(|| err(FailureCode::SampleMissing, "no such sample"))?;
        if !preset.preset.accepts.types.contains(&sample.kind) {
            return Err(err(FailureCode::SampleTypeDenied, "type not accepted"));
        }
        if sample.size > u64::from(preset.preset.accepts.max_sample_mib) << 20 {
            return Err(err(FailureCode::SampleTooLarge, "too large"));
        }
        Ok(sample.clone())
    }
}

pub(crate) struct Fx {
    pub dir: PathBuf,
    pub store: Store,
    pub clock: Arc<ManualClock>,
    pub policies: PresetSet,
    pub intake: FakeIntake,
    pub limits: SubmitLimits,
}

pub(crate) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A preset of `name`: Standard's options with `edit` applied.
pub(crate) fn policy(name: &str, edit: impl FnOnce(&mut Preset)) -> LoadedPreset {
    let mut preset = Preset::default();
    edit(&mut preset);
    let digest = format!("digest-of-{name}-{}", preset.program.run_time_s);
    LoadedPreset::named(name, digest, preset)
}

impl Fx {
    pub fn new(name: &str) -> Self {
        Self::with_policy(name, |_| {})
    }

    pub fn with_policy(name: &str, edit: impl FnOnce(&mut Preset)) -> Self {
        let dir = scratch(name);
        let clock = Arc::new(ManualClock::new(T0));
        let store = Store::open_with_clock(&dir.join("service"), clock.clone()).unwrap();
        let mut samples = BTreeMap::new();
        for n in 1..=9u8 {
            samples.insert(
                sha(n).to_string(),
                RunSample {
                    sha256: sha(n),
                    size: 4096,
                    kind: "elf".into(),
                    architecture: Some("x86_64".into()),
                    name: format!("sample-{n}"),
                },
            );
        }
        samples.insert(
            sha(20).to_string(),
            RunSample {
                sha256: sha(20),
                size: 10,
                kind: "sh".into(),
                architecture: None,
                name: "script".into(),
            },
        );
        samples.insert(
            sha(21).to_string(),
            RunSample {
                sha256: sha(21),
                size: 70 << 20,
                kind: "elf".into(),
                architecture: Some("x86_64".into()),
                name: "big".into(),
            },
        );
        Self {
            dir,
            store,
            clock,
            policies: PresetSet::single(policy("standard", edit)),
            intake: FakeIntake { samples },
            limits: SubmitLimits::default(),
        }
    }

    pub fn ctx(&self) -> SubmitContext<'_> {
        SubmitContext {
            presets: &self.policies,
            intake: &self.intake,
            limits: self.limits,
            on_duplicate: None,
        }
    }

    pub fn submit(&self, spec: RunRequest) -> Submitted {
        self.store.submit(&caller(1000), spec, &self.ctx()).unwrap()
    }

    pub fn submit_as(&self, who: &Caller, spec: RunRequest) -> R<Submitted> {
        self.store.submit(who, spec, &self.ctx())
    }

    /// A queued job for sample `n`, submitted by the owner (every
    /// permission, so a preset that takes dumps runs).
    pub fn queued(&self, n: u8) -> Run {
        let owner = Caller::with_every_permission("local:1000");
        let submitted = self.submit_as(&owner, spec(n)).unwrap();
        assert_eq!(
            submitted.run.state,
            RunState::Queued,
            "{:?}",
            submitted.run.failure
        );
        submitted.run
    }

    /// A job that is `running` on lane-1.
    pub fn running(&self, n: u8) -> Run {
        let queued = self.queued(n);
        let started = self
            .store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .unwrap();
        assert_eq!(started.id, queued.id);
        started
    }

    pub fn reopen(&mut self) {
        self.store = Store::open_with_clock(&self.dir.join("service"), self.clock.clone()).unwrap();
    }
}

pub(crate) fn lane() -> LaneId {
    LaneId::new(1)
}

/// What the job API 1 scopes `read` and `submit` became.
pub(crate) const READ_SUBMIT: [Permission; 3] = [
    Permission::RunsSeeAll,
    Permission::SamplesAdd,
    Permission::RunsSubmit,
];

/// What `manage` became.
pub(crate) const MANAGE: [Permission; 6] = [
    Permission::RunsManageAny,
    Permission::SamplesTag,
    Permission::RunsDelete,
    Permission::QueueManage,
    Permission::LanesReset,
    Permission::CustodyVerify,
];

/// A caller that sees and submits runs (no run option that adds risk).
pub(crate) fn caller(uid: u32) -> Caller {
    Caller::new(format!("local:{uid}"), &READ_SUBMIT)
}

/// A caller that also manages runs, samples, the queue and the lanes.
pub(crate) fn manager() -> Caller {
    let mut caller = Caller::new("local:0", &READ_SUBMIT);
    caller.permissions.extend(MANAGE);
    caller
}

pub(crate) fn spec(n: u8) -> RunRequest {
    RunRequest {
        sample: SampleSource {
            sha256: Some(sha(n)),
            path: None,
            upload_id: None,
        },
        name: None,
        preset: None,
        priority: None,
        labels: BTreeMap::new(),
        idempotency_key: None,
        overrides: Default::default(),
    }
}

pub(crate) fn keyed(n: u8, key: &str) -> RunRequest {
    RunRequest {
        idempotency_key: Some(key.into()),
        ..spec(n)
    }
}

pub(crate) fn on_dup(preset: &mut Preset, mode: OnDuplicate) {
    preset.duplicates.on_duplicate = mode;
}

/// The event types of a job, in order.
pub(crate) fn kinds(fx: &Fx, job: &RunId) -> Vec<String> {
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let (page, next) = fx.store.events_list(job, after, 1000).unwrap();
        if page.is_empty() {
            break;
        }
        events.extend(page);
        after = next;
    }
    events
        .iter()
        .map(|e| {
            serde_json::to_value(&e.body).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn the_database_is_wal_private_and_versioned() {
    let fx = Fx::new("open");
    let mode: String = fx
        .store
        .conn()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let version: String = fx
        .store
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, "1");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(fx.dir.join("service/jobs.sqlite"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // Every table of design 4.3 exists with its key columns.
    for (table, column) in [
        ("jobs", "waiting_for"),
        ("jobs", "idempotency_key"),
        ("attempts", "boot_id"),
        ("stages", "finished_ms"),
        ("artifacts", "media_type"),
        ("events", "gseq"),
        ("meta", "value"),
    ] {
        let found: u32 = fx
            .store
            .conn()
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "{table}.{column}");
    }
}

#[test]
fn a_newer_database_refuses_to_open_and_a_reader_cannot_write() {
    let fx = Fx::new("version");
    fx.store
        .conn()
        .execute(
            "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    let error = Store::open(&fx.dir.join("service")).err().unwrap();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("newer Antinomie"));
    fx.store
        .conn()
        .execute(
            "UPDATE meta SET value = '1' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();

    let job = fx.queued(1);
    let reader = Store::open_read_only(&fx.dir.join("service")).unwrap();
    assert_eq!(reader.get(&job.id).unwrap().id, job.id);
    assert!(reader.cancel(&job.id, None, &caller(1000)).is_err());
}
