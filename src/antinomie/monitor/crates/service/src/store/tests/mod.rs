// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the job store (card P3-2): submit and validation, the state
//! machine, events, listing, crash safety and a property test.

mod crash;
mod events;
mod lifecycle;
mod permissions;
mod property;
mod submit;

use super::*;
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        event::EventBody,
        failure::{Failure, FailureCode},
        ids::{JobId, LaneId, Sha256Hex},
        job::{Job, JobSample, JobState, Outcome, Stage, Submitted, WaitingFor},
        ops::{Caller, Scope},
        spec::{JobSpec, SampleSource},
    },
    clock::ManualClock,
    config::{LoadedPolicy, Policy, PolicySet, service::OnDuplicate},
    store::submit::SubmitContext,
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

pub(crate) const T0: u64 = 1_794_000_000_000;

pub(crate) fn sha(n: u8) -> Sha256Hex {
    Sha256Hex::try_from(format!("{n:02x}").repeat(32)).unwrap()
}

/// The intake of a test: a table of samples.
pub(crate) struct FakeIntake {
    pub samples: BTreeMap<String, JobSample>,
}

impl SampleAdmission for FakeIntake {
    fn admit(
        &self,
        source: &SampleSource,
        _name: Option<&str>,
        policy: &LoadedPolicy,
        _actor: &str,
    ) -> Result<JobSample, IntakeError> {
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
        if !policy.policy.sample.accept_types.contains(&sample.kind) {
            return Err(err(FailureCode::SampleTypeDenied, "type not accepted"));
        }
        if sample.size > u64::from(policy.policy.sample.max_sample_mib) << 20 {
            return Err(err(FailureCode::SampleTooLarge, "too large"));
        }
        Ok(sample.clone())
    }
}

pub(crate) struct Fx {
    pub dir: PathBuf,
    pub store: Store,
    pub clock: Arc<ManualClock>,
    pub policies: PolicySet,
    pub intake: FakeIntake,
    pub limits: SubmitLimits,
}

pub(crate) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub(crate) fn policy(name: &str, edit: impl FnOnce(&mut Policy)) -> LoadedPolicy {
    let mut policy = Policy::default();
    policy.vm.lane_vm = Some("auto-1".into());
    edit(&mut policy);
    LoadedPolicy {
        name: name.into(),
        digest: format!("digest-of-{name}-{}", policy.run.timeout_s),
        policy,
    }
}

impl Fx {
    pub fn new(name: &str) -> Self {
        Self::with_policy(name, |_| {})
    }

    pub fn with_policy(name: &str, edit: impl FnOnce(&mut Policy)) -> Self {
        let dir = scratch(name);
        let clock = Arc::new(ManualClock::new(T0));
        let store = Store::open_with_clock(&dir.join("service"), clock.clone()).unwrap();
        let mut samples = BTreeMap::new();
        for n in 1..=9u8 {
            samples.insert(
                sha(n).to_string(),
                JobSample {
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
            JobSample {
                sha256: sha(20),
                size: 10,
                kind: "sh".into(),
                architecture: None,
                name: "script".into(),
            },
        );
        samples.insert(
            sha(21).to_string(),
            JobSample {
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
            policies: PolicySet::single(policy("default", edit)),
            intake: FakeIntake { samples },
            limits: SubmitLimits::default(),
        }
    }

    pub fn ctx(&self) -> SubmitContext<'_> {
        SubmitContext {
            policies: &self.policies,
            intake: &self.intake,
            limits: self.limits,
            on_duplicate: None,
        }
    }

    pub fn submit(&self, spec: JobSpec) -> Submitted {
        self.store.submit(&caller(1000), spec, &self.ctx()).unwrap()
    }

    pub fn submit_as(&self, who: &Caller, spec: JobSpec) -> R<Submitted> {
        self.store.submit(who, spec, &self.ctx())
    }

    /// A queued job for sample `n`.
    pub fn queued(&self, n: u8) -> Job {
        let submitted = self.submit(spec(n));
        assert_eq!(
            submitted.job.state,
            JobState::Queued,
            "{:?}",
            submitted.job.failure
        );
        submitted.job
    }

    /// A job that is `running` on lane-1.
    pub fn running(&self, n: u8) -> Job {
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

/// A caller with the permissions of the job API 1 scopes `read` and
/// `submit` (no run option that adds risk).
pub(crate) fn caller(uid: u32) -> Caller {
    Caller::from_scopes(format!("local:{uid}"), &[Scope::Read, Scope::Submit])
}

/// A caller with the permissions of `read`, `submit` and `manage`.
pub(crate) fn manager() -> Caller {
    Caller::from_scopes("local:0", &[Scope::Read, Scope::Submit, Scope::Manage])
}

pub(crate) fn spec(n: u8) -> JobSpec {
    JobSpec {
        sample: SampleSource {
            sha256: Some(sha(n)),
            path: None,
            upload_id: None,
        },
        name: None,
        policy: None,
        priority: None,
        labels: BTreeMap::new(),
        idempotency_key: None,
        overrides: Default::default(),
    }
}

pub(crate) fn keyed(n: u8, key: &str) -> JobSpec {
    JobSpec {
        idempotency_key: Some(key.into()),
        ..spec(n)
    }
}

pub(crate) fn on_dup(policy: &mut Policy, mode: OnDuplicate) {
    policy.sample.on_duplicate = mode;
}

/// The event types of a job, in order.
pub(crate) fn kinds(fx: &Fx, job: &JobId) -> Vec<String> {
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
