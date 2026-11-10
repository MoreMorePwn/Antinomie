// SPDX-License-Identifier: GPL-3.0-only
//! The lane stages `prechecks` to `launch` against a [`FakeEngine`] and a
//! manual clock: no VM, no sleeping. The sequences follow the spike's traces
//! (ANT-T0345): a Disk restore starts the VM itself, the first upload after
//! boot fails once with "read-only file system".

use super::{
    HostChecks, HostProblem, LaneEnv, LaneStages, NoHostChecks, Prepared, Provisioned, StageStop,
    plan,
};
use crate::{
    api::{
        event::{EventBody, LaneState},
        failure::FailureCode,
        ids::JobId,
        job::{Job, JobState, Revert, Stage, WaitingFor},
    },
    clock::Clock,
    engine::{FakeEngine, fake::Unscripted},
    lane::{
        LaneDir, LaneFile,
        state::Checkpoint,
        tests::{CLEAN, Table, VM, file, healthy, layer},
    },
    store::{
        Eligibility,
        tests::{Fx, kinds, lane},
    },
    waiter::{WaitError, Waiter},
};
use antinomie_monitor_core::{
    ExecRequest, GuestKernel, RunSummary, Snapshot, VmLocations, VmState, disk_layers::LayerPhase,
};
use serde_json::json;
use std::{path::PathBuf, time::Duration};

pub(super) const SECOND: Duration = Duration::from_secs(1);
pub(super) const MS: Duration = Duration::from_millis(1);

pub(super) fn run_summary(state: &str) -> RunSummary {
    serde_json::from_value(json!({
        "id": "r1", "vm_id": VM, "boot_id": "b2", "session_id": 1,
        "root_task_cookie": 7, "pid": 750,
        "request": ExecRequest::default(),
        "directory": "/runs/r1", "terminal_eof": false,
        "state": state, "recording_error": null,
    }))
    .expect("a run summary")
}

pub(super) fn kernel(revision: u32) -> GuestKernel {
    GuestKernel {
        revision: Some(revision),
        ..GuestKernel::default()
    }
}

pub(super) type EvidenceFn =
    Box<dyn Fn(&std::path::Path) -> Result<Option<antinomie_monitor_core::RunArtifacts>, String>>;

/// The library tags the service asked for: `(sample sha256, tag)`.
#[derive(Default)]
pub(super) struct TagLog(pub(super) std::sync::Mutex<Vec<(String, String)>>);

impl super::host::SampleTags for TagLog {
    fn add_tag(&self, job: &Job, tag: &str) -> Result<bool, String> {
        let sha = job.sample.as_ref().map(|s| s.sha256.to_string());
        self.0
            .lock()
            .unwrap()
            .push((sha.unwrap_or_default(), tag.to_owned()));
        Ok(true)
    }
}

pub(super) struct W {
    pub(super) fx: Fx,
    pub(super) lanes: LaneDir,
    pub(super) procs: Table,
    pub(super) host: Box<dyn HostChecks>,
    pub(super) evidence: EvidenceFn,
    pub(super) triage: Box<dyn super::host::HostTriage>,
    pub(super) tags: TagLog,
}

impl W {
    pub(super) fn new(name: &str) -> Self {
        Self::with(name, |_| {})
    }

    pub(super) fn with(name: &str, edit: impl FnOnce(&mut crate::config::Policy)) -> Self {
        let fx = Fx::with_policy(name, edit);
        let lanes = LaneDir::new(&fx.dir.join("service"));
        lanes.save(&file()).unwrap();
        Self {
            fx,
            lanes,
            procs: Table::new(),
            host: Box::new(NoHostChecks),
            triage: Box::new(super::host::RealTriage::new(
                antinomie_monitor_core::BackendOptions::default(),
            )),
            tags: TagLog::default(),
            evidence: Box::new(|_| {
                Ok(Some(antinomie_monitor_core::RunArtifacts {
                    network_state: antinomie_monitor_core::RunArtifactState::Complete,
                    memory_state: antinomie_monitor_core::RunArtifactState::Disabled,
                    core_state: antinomie_monitor_core::RunArtifactState::Disabled,
                    ..antinomie_monitor_core::RunArtifacts::default()
                }))
            }),
        }
    }

    pub(super) fn engine(&self, build: impl FnOnce(&mut FakeEngine)) -> Waiter<FakeEngine> {
        let mut fake = FakeEngine::new(self.fx.clock.clone());
        fake.start_with(|s| {
            healthy(s);
            s.vm_locations = vec![VmLocations {
                vm_id: VM.into(),
                disk_directory: PathBuf::from("/d/vms/auto-1"),
                recording_directory: PathBuf::from("/d/vms/auto-1"),
                recording_directories: vec![],
            }];
        });
        fake.unscripted(Unscripted::Fail);
        build(&mut fake);
        let mut waiter = Waiter::new(fake, self.fx.clock.clone());
        waiter.first_snapshot(SECOND).unwrap();
        waiter
    }

    pub(super) fn stages<'a>(
        &'a self,
        waiter: &'a mut Waiter<FakeEngine>,
    ) -> LaneStages<'a, FakeEngine> {
        LaneStages {
            waiter,
            env: LaneEnv {
                store: &self.fx.store,
                lanes: &self.lanes,
                policies: &self.fx.policies,
                procs: &self.procs,
                host: self.host.as_ref(),
                evidence: self.evidence.as_ref(),
                triage: self.triage.as_ref(),
                tags: &self.tags,
            },
            lane: lane(),
        }
    }

    pub(super) fn prepared(&self, job: &Job) -> Prepared {
        let frozen = self.fx.store.frozen_policy(&job.id).unwrap();
        Prepared {
            effective: plan::effective(job, &frozen.policy),
            policy: frozen,
            lane: self.lanes.load(&lane()).unwrap().unwrap(),
        }
    }

    pub(super) fn lane_file(&self) -> LaneFile {
        self.lanes.load(&lane()).unwrap().unwrap()
    }

    pub(super) fn job(&self, id: &JobId) -> Job {
        self.fx.store.get(id).unwrap()
    }

    pub(super) fn engine_events(&self) -> Vec<EventBody> {
        self.fx
            .store
            .events_since(0, 1000)
            .unwrap()
            .into_iter()
            .map(|e| e.body)
            .collect()
    }
}

/// A Disk restore as the spike recorded it: the VM starts inside the command
/// and the guest answers a little later.
pub(super) fn restore_ok(fake: &mut FakeEngine) {
    fake.on("RestoreVmSnapshot")
        .after(2 * SECOND)
        .then(100 * MS, |s| {
            s.state = VmState::Starting;
            s.active_vm = Some(VM.into());
        })
        .then(2 * SECOND, |s| {
            s.state = VmState::Running;
            s.boot_id = Some("b2".into());
        })
        .then(2 * SECOND + 260 * MS, |s| s.guest_kernel = Some(kernel(21)))
        .ok("Snapshot disk restored; guest booted in a new timeline");
}

pub(super) fn upload_ok(fake: &mut FakeEngine) {
    fake.on("UploadSample")
        .after(50 * MS)
        .fail("guest command 0x1001: Read-only file system (os error 30)");
    fake.on("UploadSample")
        .after(60 * MS)
        .ok("uploaded 4096 bytes to /tmp/01010101-sample-1");
}

pub(super) fn execute_ok(fake: &mut FakeEngine) {
    fake.on("Execute")
        .after(SECOND)
        .then(500 * MS, |s| s.runs.push(run_summary("Running")))
        .ok("launched pid 750, terminal session 1");
}

pub(super) fn cycle(fake: &mut FakeEngine) {
    restore_ok(fake);
    upload_ok(fake);
    execute_ok(fake);
}

pub(super) fn code(stop: &StageStop) -> FailureCode {
    stop.failure().unwrap_or_else(|| panic!("{stop:?}")).code
}

// ---- plan ---------------------------------------------------------------

#[test]
fn the_launch_request_is_the_policys_unless_the_spec_overrides_it() {
    let w = W::new("plan");
    let job = w.fx.running(1);
    let policy = crate::config::Policy::default();
    let plain = plan::effective(&job, &policy);
    let r = &plain.request;
    assert_eq!((r.uid, r.gid), (1000, 1000));
    assert_eq!(r.cwd, "/tmp");
    assert!(r.args.is_empty() && r.env == [plan::DEFAULT_PATH]);
    assert!(r.capture_network && !r.memory_dump_on_exit && !r.core_dump_on_exit);
    assert_eq!(
        r.route,
        Some(antinomie_monitor_core::route::RouteKind::Drop)
    );
    assert!(!r.analysis.enabled && !r.debug_on_start && r.host_copy.is_none());
    assert!(r.dump_trigger.is_none(), "the trigger is off by default");
    assert_eq!(plain.run_limit, Duration::from_secs(300));

    let mut job = job;
    job.spec.overrides.timeout_s = Some(30);
    job.spec.overrides.args = Some(vec!["-x".into()]);
    job.spec.overrides.env = Some(vec!["A=1".into(), "PATH=/bin".into()]);
    job.spec.overrides.run_as = Some(crate::api::spec::RunAs::Named(
        crate::api::spec::RunAsName::Root,
    ));
    job.spec.overrides.core_dump = Some(crate::api::spec::CoreDump::Limits(
        crate::api::spec::CoreLimits {
            max_mib: 8,
            timeout_ms: 1234,
        },
    ));
    job.spec.overrides.memory_dump = Some(true);
    job.spec.overrides.network_capture = Some(false);
    job.spec.overrides.route = Some(crate::api::spec::Route::InetSim);
    let set = plan::effective(&job, &policy);
    let r = &set.request;
    assert_eq!(set.run_limit, Duration::from_secs(30));
    assert_eq!((r.uid, r.gid), (0, 0));
    assert_eq!(r.args, ["-x"]);
    assert_eq!(r.env, ["A=1", "PATH=/bin"], "an explicit PATH is kept");
    assert!(r.core_dump_on_exit && r.memory_dump_on_exit && !r.capture_network);
    assert_eq!(
        (r.core_max_size, r.core_timeout_ms),
        (Some(8 << 20), Some(1234))
    );
    assert_eq!(
        r.route,
        Some(antinomie_monitor_core::route::RouteKind::InetSim)
    );
}

#[test]
fn the_policys_dump_trigger_is_in_the_launch_request_with_a_core_budget() {
    use crate::config::policy::{TriggerKind, TriggerSetting};
    use antinomie_monitor_core::dump_trigger::TriggerTier;
    let w = W::new("plan-trigger");
    let job = w.fx.running(1);
    let mut policy = crate::config::Policy::default();
    policy.evidence.dump_trigger = TriggerSetting::High;
    let r = plan::effective(&job, &policy).request;
    let plan = r.dump_trigger.expect("the trigger is armed");
    assert_eq!(plan.min_tier, TriggerTier::High);
    assert!(plan.core && !plan.memory);
    // The core of a trigger has the policy's budget though no exit core is asked.
    assert!(!r.core_dump_on_exit);
    assert_eq!(
        (r.core_max_size, r.core_timeout_ms),
        (Some(64 << 20), Some(plan::CORE_TIMEOUT_MS))
    );
    policy.evidence.dump_trigger_kind = TriggerKind::Memory;
    let r = plan::effective(&job, &policy).request;
    assert!(r.dump_trigger.is_some_and(|plan| plan.memory && !plan.core));
    assert_eq!((r.core_max_size, r.core_timeout_ms), (None, None));
}

#[test]
fn the_guest_path_follows_the_library_rule_in_the_policys_directory() {
    let sha = "ab".repeat(32);
    assert_eq!(
        plan::guest_path("/tmp", &sha, "evil one!.exe"),
        "/tmp/abababab-evil_one_.exe"
    );
    assert_eq!(
        plan::guest_path("/var/tmp/", &sha, ""),
        "/var/tmp/abababab-sample"
    );
    assert!(plan::guest_path("/tmp", &sha, &"n".repeat(100)).len() <= "/tmp/abababab-".len() + 48);
    assert_eq!(plan::upload_wait(0), 60 * SECOND);
    assert_eq!(plan::upload_wait(25 << 20), 62 * SECOND);
}

// ---- prechecks ----------------------------------------------------------

#[test]
fn prechecks_hand_over_the_frozen_policy_the_settings_and_the_lane() {
    let w = W::new("pre-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    let prepared = w.stages(&mut waiter).prechecks(&job).unwrap();
    assert_eq!(prepared.policy.name, "default");
    assert_eq!(prepared.lane.vm_id, VM);
    assert_eq!(prepared.effective.run_limit, Duration::from_secs(300));
    assert!(
        waiter.engine_mut().sent_names().is_empty(),
        "prechecks touch no VM"
    );
}

#[test]
fn a_policy_that_is_gone_or_closed_to_the_client_denies_the_job() {
    let mut w = W::new("pre-policy");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    // Gone.
    w.fx.policies = crate::config::PolicySet::default();
    let stop = w.stages(&mut waiter).prechecks(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::PolicyDenied);
    assert_eq!(stop.failure().unwrap().stage, Stage::Prechecks);
    // Closed to this client.
    w.fx.policies = crate::config::PolicySet::single(crate::store::tests::policy("default", |p| {
        p.access.clients = vec!["web:*".into()];
    }));
    let stop = w.stages(&mut waiter).prechecks(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::PolicyDenied);
}

pub(super) struct Host(pub(super) Option<HostProblem>);

impl HostChecks for Host {
    fn check(&self, _: &Job, _: &crate::config::Policy) -> Result<(), HostProblem> {
        self.0.clone().map_or(Ok(()), Err)
    }
}

#[test]
fn a_host_problem_waits_or_fails_by_what_it_says() {
    let mut w = W::new("pre-host");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    w.host = Box::new(Host(Some(HostProblem::Wait(
        WaitingFor::Resources,
        "RAM".into(),
    ))));
    match w.stages(&mut waiter).prechecks(&job).unwrap_err() {
        StageStop::Wait {
            waiting_for,
            detail,
        } => {
            assert_eq!(
                (waiting_for, detail.as_str()),
                (WaitingFor::Resources, "RAM")
            );
        }
        other => panic!("{other:?}"),
    }
    w.host = Box::new(Host(Some(HostProblem::Fail(
        FailureCode::DependencyMissing,
        "no bwrap".into(),
    ))));
    let stop = w.stages(&mut waiter).prechecks(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::DependencyMissing);
    assert_eq!(stop.failure().unwrap().detail.as_deref(), Some("no bwrap"));
}

#[test]
fn a_quarantined_busy_or_running_lane_makes_the_job_wait() {
    let w = W::new("pre-wait");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    let wait_of = |stop: StageStop| match stop {
        StageStop::Wait { waiting_for, .. } => waiting_for,
        other => panic!("{other:?}"),
    };
    w.lanes
        .update(&lane(), |f| f.quarantine(FailureCode::RevertFailed, "x", 1))
        .unwrap();
    assert_eq!(
        wait_of(w.stages(&mut waiter).prechecks(&job).unwrap_err()),
        WaitingFor::LaneQuarantined
    );
    w.lanes.update(&lane(), |f| f.unquarantine(2)).unwrap();
    let other = JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap();
    w.lanes
        .update(&lane(), |f| f.begin_work(other, 1, 3))
        .unwrap();
    assert_eq!(
        wait_of(w.stages(&mut waiter).prechecks(&job).unwrap_err()),
        WaitingFor::Lane
    );
    w.lanes.update(&lane(), |f| f.end_work(4)).unwrap();
    let mut running = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.state = VmState::Running;
        });
    });
    assert_eq!(
        wait_of(w.stages(&mut running).prechecks(&job).unwrap_err()),
        WaitingFor::Lane
    );
}

#[test]
fn a_missing_lane_or_vm_fails_and_a_changed_snapshot_quarantines() {
    let w = W::new("pre-lane");
    let job = w.fx.running(1);
    // No VM in the engine.
    let mut empty = w.engine(|fake| {
        fake.start_with(|s| *s = Snapshot::default());
    });
    assert_eq!(
        code(&w.stages(&mut empty).prechecks(&job).unwrap_err()),
        FailureCode::NoVm
    );
    // The clean snapshot is gone.
    let mut changed = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.vm_snapshot_trees.get_mut(VM).unwrap().nodes[0].id = "by-hand".into();
        });
    });
    let stop = w.stages(&mut changed).prechecks(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::LaneChanged);
    assert!(w.lane_file().is_quarantined());
    let events = w.engine_events();
    assert!(events.iter().any(|e| matches!(
        e,
        EventBody::LaneState {
            state: LaneState::Quarantined,
            ..
        }
    )));
    assert!(
        events.iter().any(
            |e| matches!(e, EventBody::EngineAlert { code, .. } if code == "lane_quarantined")
        )
    );
    // A lane with no file at all.
    std::fs::remove_file(w.lanes.path(&lane())).unwrap();
    let mut waiter = w.engine(|_| {});
    assert_eq!(
        code(&w.stages(&mut waiter).prechecks(&job).unwrap_err()),
        FailureCode::NoVm
    );
}

#[test]
fn a_pending_layer_does_not_stop_prechecks_provision_waits_for_it() {
    let w = W::new("pre-layer");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.disk_layers = vec![layer(LayerPhase::Finalizing)];
        });
    });
    assert!(w.stages(&mut waiter).prechecks(&job).is_ok());
}

#[test]
fn the_scheduler_asks_the_lane_whether_it_can_take_a_job() {
    let w = W::new("eligible");
    let ask = |w: &W, build: &dyn Fn(&mut FakeEngine)| {
        let mut waiter = w.engine(|f| build(f));
        w.stages(&mut waiter).eligibility()
    };
    assert_eq!(ask(&w, &|_| {}), Eligibility::Ready);
    assert_eq!(
        ask(&w, &|f| {
            f.start_with(|s| {
                healthy(s);
                s.disk_layers = vec![layer(LayerPhase::Saving)];
            });
        }),
        Eligibility::Wait(WaitingFor::LayerPending)
    );
    assert_eq!(
        ask(&w, &|f| {
            f.start_with(|s| {
                healthy(s);
                s.state = VmState::Running;
            });
        }),
        Eligibility::Wait(WaitingFor::Lane)
    );
    w.lanes
        .update(&lane(), |f| f.quarantine(FailureCode::LaneChanged, "x", 1))
        .unwrap();
    assert_eq!(
        ask(&w, &|_| {}),
        Eligibility::Wait(WaitingFor::LaneQuarantined)
    );
    w.lanes
        .update(&lane(), |f| {
            f.unquarantine(2);
            f.begin_work(
                JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
                1,
                3,
            );
        })
        .unwrap();
    assert_eq!(ask(&w, &|_| {}), Eligibility::Wait(WaitingFor::Lane));
    std::fs::remove_file(w.lanes.path(&lane())).unwrap();
    assert_eq!(ask(&w, &|_| {}), Eligibility::Wait(WaitingFor::Lane));
}

// ---- provision ----------------------------------------------------------

fn provision(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> Result<Provisioned, StageStop> {
    let prepared = w.prepared(job);
    w.stages(waiter).provision(job, &prepared)
}

#[test]
fn a_disk_restore_is_the_whole_revert_and_the_job_learns_the_vm() {
    let w = W::new("prov-disk");
    let job = w.fx.running(1);
    w.procs.procs.borrow_mut().insert(
        900,
        crate::lane::process::ProcessInfo {
            argv: vec![
                "/usr/bin/qemu-system-x86_64".into(),
                "-drive".into(),
                "file=/d/vms/auto-1/disk.qcow2".into(),
            ],
            start_ticks: Some(77),
        },
    );
    let mut waiter = w.engine(restore_ok);
    let begin = w.fx.clock.now_ms();
    let provisioned = provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(provisioned.vm_id, VM);
    assert_eq!(provisioned.boot_id.as_deref(), Some("b2"));
    assert_eq!(provisioned.guest_revision, Some(21));
    let sent = waiter.engine_mut().sent();
    assert_eq!(
        sent.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["RestoreVmSnapshot"],
        "no Start after a Disk restore"
    );
    for part in [
        CLEAN,
        "boot_from_disk: true",
        "confirmed: true",
        "save_current: None",
        "switch_profile: false",
    ] {
        assert!(sent[0].detail.contains(part), "{part}: {}", sent[0].detail);
    }
    let took = w.fx.clock.now_ms() - begin;
    assert!((2000..3000).contains(&took), "{took}");
    let stored = w.job(&job.id);
    let vm = stored.vm.unwrap();
    assert_eq!((vm.id.as_str(), vm.revert), (VM, Revert::SnapshotDisk));
    let lane_file = w.lane_file();
    let qemu = lane_file.qemu.unwrap();
    assert_eq!((qemu.pid, qemu.start_ticks), (900, Some(77)));
    assert_eq!(qemu.marker, "/d/vms/auto-1");
}

#[test]
fn snapshot_full_resumes_the_guest_and_reset_restarts_it() {
    let w = W::with("prov-full", |p| {
        p.vm.revert = crate::config::policy::RevertMode::SnapshotFull
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(restore_ok);
    provision(&w, &mut waiter, &job).unwrap();
    assert!(
        waiter.engine_mut().sent()[0]
            .detail
            .contains("boot_from_disk: false")
    );
    assert_eq!(w.job(&job.id).vm.unwrap().revert, Revert::SnapshotFull);

    let w = W::with("prov-reset", |p| {
        p.vm.revert = crate::config::policy::RevertMode::Reset;
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("Reset").after(3 * SECOND).ok("VM reset");
        fake.on("Start")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Running;
                s.active_vm = Some(VM.into());
                s.guest_kernel = Some(kernel(21));
            })
            .ok("VM running");
    });
    provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(waiter.engine_mut().sent_names(), ["Reset", "Start"]);
    assert_eq!(w.job(&job.id).vm.unwrap().revert, Revert::Reset);
}

#[test]
fn a_failed_restore_is_tried_once_more_and_never_falls_back_to_reset() {
    let w = W::new("prov-retry");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot").fail("snapshot busy");
        restore_ok(fake);
    });
    provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(
        waiter.engine_mut().sent_names(),
        ["RestoreVmSnapshot", "RestoreVmSnapshot"]
    );
    assert!(!w.lane_file().is_quarantined());

    let w = W::new("prov-twice");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot").fail("snapshot busy");
        fake.on("RestoreVmSnapshot").fail("snapshot still busy");
    });
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RevertFailed);
    assert_eq!(
        stop.failure().unwrap().detail.as_deref(),
        Some("snapshot still busy")
    );
    assert_eq!(
        waiter.engine_mut().sent_names(),
        ["RestoreVmSnapshot", "RestoreVmSnapshot"],
        "no Reset, no Start"
    );
    let file = w.lane_file();
    assert_eq!(file.quarantine.unwrap().reason, FailureCode::RevertFailed);
    assert!(w.engine_events().iter().any(|e| matches!(e, EventBody::LaneState { state: LaneState::Quarantined, reason: Some(r), .. } if r == "revert_failed")));
}

#[test]
fn a_restore_that_never_finishes_counts_as_failed() {
    let w = W::new("prov-timeout");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot").silent();
        fake.on("RestoreVmSnapshot").silent();
    });
    let begin = w.fx.clock.now_ms();
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RevertFailed);
    assert!(
        w.fx.clock.now_ms() - begin >= 360_000,
        "two boot_s of 180 s"
    );
}

/// A Disk restore on a slow emulated host: the engine starts the VM inside
/// the command, publishes the accelerator and its note, and answers after
/// `answer_s` seconds (the guest is up when it does).
fn slow_restore(fake: &mut FakeEngine, factor: f64, answer_s: u64, note: bool) {
    let mut step = fake.on("RestoreVmSnapshot").after(SECOND * answer_s as u32);
    step = step.then(100 * MS, move |s| {
        s.state = VmState::Starting;
        s.active_vm = Some(VM.into());
        s.accelerator = Some(antinomie_monitor_core::AcceleratorUsed {
            record: "tcg".into(),
            fallback_warning: None,
            guest_wait_factor: factor,
        });
    });
    if note {
        step = step.then(3 * SECOND, |s| {
            s.start_note = Some("Waiting for a slow TCG boot".into());
        });
    }
    step.then(SECOND * answer_s as u32 - 10 * MS, |s| {
        s.start_note = None;
        s.state = VmState::Running;
        s.boot_id = Some("b2".into());
    })
    .then(SECOND * answer_s as u32 - 5 * MS, |s| {
        s.guest_kernel = Some(kernel(21))
    })
    .ok("Snapshot disk restored; guest booted in a new timeline");
}

#[test]
fn a_tcg_restore_that_boots_past_boot_s_is_waited_for_like_a_start() {
    let w = W::new("prov-tcg-restore");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| slow_restore(fake, 12.5, 400, true));
    let provisioned = provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(provisioned.guest_revision, Some(21));
    assert_eq!(waiter.engine_mut().sent_names(), ["RestoreVmSnapshot"]);
    assert!(w.fx.clock.now_ms() >= 400_000);
}

#[test]
fn a_restore_under_kvm_or_without_progress_keeps_boot_s() {
    let w = W::new("prov-tcg-restore-limits");
    let job = w.fx.running(1);
    // KVM (factor 1): the note does not stretch the limit.
    let mut kvm = w.engine(|fake| {
        slow_restore(fake, 1.0, 400, true);
        slow_restore(fake, 1.0, 400, true);
    });
    assert_eq!(
        code(&provision(&w, &mut kvm, &job).unwrap_err()),
        FailureCode::RevertFailed
    );
    // TCG, but no note: a silent restore fails at 180 s, twice.
    let mut silent = w.engine(|fake| {
        slow_restore(fake, 12.5, 400, false);
        slow_restore(fake, 12.5, 400, false);
    });
    let begin = w.fx.clock.now_ms();
    assert_eq!(
        code(&provision(&w, &mut silent, &job).unwrap_err()),
        FailureCode::RevertFailed
    );
    assert!(w.fx.clock.now_ms() - begin >= 360_000);
}

#[test]
fn a_launch_after_a_tcg_restore_gets_the_stretched_silence() {
    let w = W::new("launch-after-tcg-restore");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        slow_restore(fake, 12.5, 200, true);
        // The engine holds Execute for 200 s (a slow boot): 60 s unstretched
        // would give it up as silent.
        fake.on("Execute")
            .after(200 * SECOND)
            .then(200 * SECOND + 500 * MS, |s| {
                s.runs.push(run_summary("Running"))
            })
            .ok("launched pid 750, terminal session 1");
    });
    let provisioned = provision(&w, &mut waiter, &job).unwrap();
    let prepared = w.prepared(&job);
    let launched = w.stages(&mut waiter).launch(&job, &prepared, &provisioned);
    assert!(launched.is_ok(), "{launched:?}");
}

#[test]
fn the_previous_disk_layer_is_waited_for_before_the_revert() {
    let w = W::new("prov-layer");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.disk_layers = vec![layer(LayerPhase::Finalizing)];
        });
        fake.after(Duration::from_secs(240), |s| s.disk_layers.clear());
        restore_ok(fake);
    });
    let begin = w.fx.clock.now_ms();
    provision(&w, &mut waiter, &job).unwrap();
    let took = w.fx.clock.now_ms() - begin;
    assert!(took >= 240_000, "{took}");
    assert!(
        waiter.engine_mut().sent()[0].at_ms - begin >= 240_000,
        "the restore came after the layer"
    );

    let w = W::new("prov-layer-stuck");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.disk_layers = vec![layer(LayerPhase::Saving)];
        });
    });
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::VmStartFailed);
    assert!(waiter.engine_mut().sent().is_empty());
}

#[test]
fn a_vm_that_still_runs_is_stopped_before_the_revert() {
    let w = W::new("prov-running");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.state = VmState::Running;
            s.active_vm = Some(VM.into());
        });
        fake.on("Stop")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
            })
            .ok("VM stopped");
        restore_ok(fake);
    });
    provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(
        waiter.engine_mut().sent_names(),
        ["Stop", "RestoreVmSnapshot"]
    );

    // Another VM is not ours to stop.
    let w = W::new("prov-other-vm");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.state = VmState::Running;
            s.active_vm = Some("someone-elses".into());
        });
    });
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::VmStartFailed);
    assert!(waiter.engine_mut().sent().is_empty());
}

#[test]
fn a_guest_that_never_answers_is_guest_unreachable_and_three_in_a_row_quarantine() {
    let w = W::new("prov-silent");
    let job = w.fx.running(1);
    for round in 1..=3u32 {
        let mut waiter = w.engine(|fake| {
            fake.on("RestoreVmSnapshot")
                .after(SECOND)
                .then(SECOND, |s| {
                    s.state = VmState::Running;
                    s.active_vm = Some(VM.into());
                })
                .ok("restored");
        });
        let begin = w.fx.clock.now_ms();
        let stop = provision(&w, &mut waiter, &job).unwrap_err();
        assert_eq!(code(&stop), FailureCode::GuestUnreachable);
        assert!(w.fx.clock.now_ms() - begin >= 180_000);
        let file = w.lane_file();
        assert_eq!(file.failures, round);
        assert_eq!(file.is_quarantined(), round == 3, "round {round}");
    }
    assert_eq!(
        w.lane_file().quarantine.unwrap().reason,
        FailureCode::GuestUnreachable
    );
    assert!(
        w.engine_events()
            .iter()
            .any(|e| matches!(e, EventBody::EngineAlert { .. }))
    );
}

#[test]
fn a_vm_that_fails_to_start_is_vm_start_failed_and_counts() {
    let w = W::with("prov-start-fails", |p| {
        p.vm.revert = crate::config::policy::RevertMode::Reset
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("Reset").ok("reset");
        fake.on("Start").fail("QEMU exited: no KVM");
    });
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::VmStartFailed);
    assert_eq!(
        stop.failure().unwrap().detail.as_deref(),
        Some("QEMU exited: no KVM")
    );
    assert_eq!(w.lane_file().failures, 1);

    let w = W::new("prov-failed-state");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot")
            .after(SECOND)
            .then(SECOND, |s| {
                s.state = VmState::Failed;
                s.last_error = Some("qemu died".into());
            })
            .ok("restored");
    });
    let begin = w.fx.clock.now_ms();
    let stop = provision(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::VmStartFailed);
    assert_eq!(stop.failure().unwrap().detail.as_deref(), Some("qemu died"));
    assert!(
        w.fx.clock.now_ms() - begin < 10_000,
        "no waiting out boot_s"
    );
}

#[test]
fn a_core_dump_needs_a_guest_of_revision_15() {
    let w = W::with("prov-core", |p| p.evidence.core_dump = true);
    let job = w.fx.running(1);
    let mut old = w.engine(|fake| {
        fake.on("RestoreVmSnapshot")
            .after(SECOND)
            .then(SECOND, |s| {
                s.state = VmState::Running;
                s.active_vm = Some(VM.into());
                s.guest_kernel = Some(kernel(14));
            })
            .ok("restored");
    });
    let stop = provision(&w, &mut old, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::DependencyMissing);
    assert!(
        stop.failure()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("revision 14")
    );
    let mut new = w.engine(restore_ok);
    assert!(provision(&w, &mut new, &job).is_ok());
}

#[test]
fn an_unclear_qemu_process_is_a_warning_and_clears_the_record() {
    let w = W::new("prov-qemu-unknown");
    let job = w.fx.running(1);
    w.lanes
        .update(&lane(), |f| {
            f.set_qemu(crate::lane::QemuRecord {
                pid: 5,
                start_ticks: None,
                marker: "old".into(),
                recorded_ms: 1,
            });
        })
        .unwrap();
    let mut waiter = w.engine(restore_ok);
    provision(&w, &mut waiter, &job).unwrap();
    assert_eq!(w.lane_file().qemu, None);
    assert!(
        w.job(&job.id)
            .warnings
            .iter()
            .any(|x| x.code == "qemu_pid_unknown")
    );
}

#[test]
fn a_dead_engine_aborts_instead_of_failing_the_job() {
    let w = W::new("prov-dead");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot").die();
    });
    match provision(&w, &mut waiter, &job).unwrap_err() {
        StageStop::Abort(WaitError::Disconnected(_)) => {}
        other => panic!("{other:?}"),
    }
    assert!(!w.lane_file().is_quarantined());
}

// ---- upload -------------------------------------------------------------

fn upload(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> Result<(), StageStop> {
    let prepared = w.prepared(job);
    w.stages(waiter).upload(job, &prepared)
}

#[test]
fn the_first_upload_after_boot_is_tried_again() {
    let w = W::new("up-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(upload_ok);
    upload(&w, &mut waiter, &job).unwrap();
    let sent = waiter.engine_mut().sent();
    assert_eq!(sent.len(), 2);
    let sha = job.sample.as_ref().unwrap().sha256.to_string();
    for one in &sent {
        assert!(
            one.detail.contains(&sha) && one.detail.contains("/tmp/01010101-sample-1"),
            "{}",
            one.detail
        );
        assert!(one.detail.contains("executable: true"));
    }
    assert!(
        sent[1].at_ms > sent[0].at_ms,
        "a second passed between the tries"
    );
}

#[test]
fn an_upload_that_the_guest_refuses_fails_with_the_guests_words() {
    let w = W::new("up-fail");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("UploadSample")
            .fail("guest command 0x1001: No space left on device (os error 28)");
    });
    let stop = upload(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::UploadFailed);
    assert!(
        stop.failure()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("No space left")
    );
    assert_eq!(
        waiter.engine_mut().sent().len(),
        1,
        "no retry of a real error"
    );
}

#[test]
fn a_guest_that_stays_read_only_runs_out_of_upload_s() {
    let w = W::new("up-readonly");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("UploadSample")
            .forever()
            .fail("guest command 0x1001: Read-only file system (os error 30)");
    });
    let begin = w.fx.clock.now_ms();
    let stop = upload(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::UploadFailed);
    let took = w.fx.clock.now_ms() - begin;
    assert!((60_000..70_000).contains(&took), "{took}");
}

#[test]
fn a_silent_engine_and_a_wrong_size_are_told_apart() {
    let w = W::new("up-odd");
    let job = w.fx.running(1);
    let mut silent = w.engine(|fake| {
        fake.on("UploadSample").silent();
    });
    assert_eq!(
        code(&upload(&w, &mut silent, &job).unwrap_err()),
        FailureCode::Internal
    );
    let mut short = w.engine(|fake| {
        fake.on("UploadSample").ok("uploaded 100 bytes to /tmp/x");
    });
    let stop = upload(&w, &mut short, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::UploadFailed);
    assert!(
        stop.failure()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("4096")
    );
    let mut odd = w.engine(|fake| {
        fake.on("UploadSample").ok("done");
    });
    assert!(
        upload(&w, &mut odd, &job).is_ok(),
        "a message the size cannot be read from passes"
    );
}

// ---- launch -------------------------------------------------------------

fn launch(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> Result<super::Launched, StageStop> {
    let prepared = w.prepared(job);
    let provisioned = Provisioned {
        vm_id: VM.into(),
        boot_id: Some("b2".into()),
        guest_revision: Some(21),
    };
    w.stages(waiter).launch(job, &prepared, &provisioned)
}

#[test]
fn launch_sends_the_exact_request_and_records_the_run() {
    let w = W::new("launch-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(execute_ok);
    let launched = launch(&w, &mut waiter, &job).unwrap();
    assert_eq!(launched.run.id, "r1");
    assert_eq!(launched.guest_path, "/tmp/01010101-sample-1");
    let sent = waiter.engine_mut().sent();
    assert_eq!(sent.len(), 1);
    let detail = &sent[0].detail;
    for part in [
        "path: \"/tmp/01010101-sample-1\"",
        "cwd: \"/tmp\"",
        "uid: 1000",
        "gid: 1000",
        "capture_network: true",
        "memory_dump_on_exit: false",
        "core_dump_on_exit: false",
        "debug_on_start: false",
        "route: Some(Drop)",
        "run_in: AppTerminal",
        "host_copy: None",
        "name: \"sample-1\"",
        "PATH=",
    ] {
        assert!(detail.contains(part), "{part} not in {detail}");
    }
    assert!(!detail.contains("analysis: AnalysisSelection { enabled: true"));
    let stored = w.job(&job.id);
    assert_eq!(stored.run.unwrap().run_id, "r1");
    let recording = stored.recording.unwrap();
    assert_eq!(
        (recording.vm_id.as_str(), recording.boot_id.as_str()),
        (VM, "b2")
    );
    assert!(kinds(&w.fx, &job.id).contains(&"job.run".to_owned()));
}

#[test]
fn a_refused_unanswered_or_vanished_launch_fails_with_launch_failed() {
    let w = W::new("launch-bad");
    let job = w.fx.running(1);
    let mut refused = w.engine(|fake| {
        fake.on("Execute")
            .fail("Guest desktop needs a VM with a graphical base");
    });
    let stop = launch(&w, &mut refused, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::LaunchFailed);
    assert_eq!(stop.failure().unwrap().stage, Stage::Launch);

    let mut never = w.engine(|fake| {
        fake.on("Execute").after(SECOND).ok("launched");
    });
    let begin = w.fx.clock.now_ms();
    assert_eq!(
        code(&launch(&w, &mut never, &job).unwrap_err()),
        FailureCode::LaunchFailed
    );
    let took = w.fx.clock.now_ms() - begin;
    assert!((30_000..35_000).contains(&took), "launch_s is 30: {took}");

    let mut silent = w.engine(|fake| {
        fake.on("Execute").silent();
    });
    assert_eq!(
        code(&launch(&w, &mut silent, &job).unwrap_err()),
        FailureCode::Internal
    );

    let mut failed = w.engine(|fake| {
        fake.on("Execute")
            .after(SECOND)
            .then(SECOND, |s| s.runs.push(run_summary("FailedToStart")))
            .ok("launched");
    });
    assert_eq!(
        code(&launch(&w, &mut failed, &job).unwrap_err()),
        FailureCode::LaunchFailed
    );
}

#[test]
fn a_core_dump_in_a_desktop_run_is_refused_before_the_engine_is_asked() {
    let w = W::with("launch-desktop-core", |p| {
        p.evidence.core_dump = true;
    });
    let mut job = w.fx.running(1);
    job.spec.overrides.run_in = Some(crate::api::spec::RunIn::GuestDesktop);
    let mut waiter = w.engine(execute_ok);
    let stop = launch(&w, &mut waiter, &job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::LaunchFailed);
    assert!(waiter.engine_mut().sent().is_empty());
}

// ---- the driver ---------------------------------------------------------

#[test]
fn the_five_stages_run_in_order_with_their_records() {
    let w = W::new("drive-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(cycle);
    let launched = w.stages(&mut waiter).run_to_launch(&job).unwrap();
    assert_eq!(launched.run.id, "r1");
    assert_eq!(
        waiter.engine_mut().sent_names(),
        [
            "RestoreVmSnapshot",
            "UploadSample",
            "UploadSample",
            "Execute"
        ]
    );
    // The store: stage events in order, the job still running at launch.
    let kinds = kinds(&w.fx, &job.id);
    let stage_events = kinds.iter().filter(|k| *k == "job.stage").count();
    assert!(stage_events >= 8, "the stage records: {stage_events}");
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Running);
    assert_eq!(stored.stage, Some(Stage::Launch));
    assert_eq!(stored.vm.as_ref().unwrap().id, VM);
    // The lane file: this job, at launch, finished.
    let work = w.lane_file().current.unwrap();
    assert_eq!(
        (work.job_id, work.stage, work.checkpoint),
        (job.id.clone(), Stage::Launch, Checkpoint::Finished)
    );
    assert!(w.engine_events().iter().any(|e| matches!(e, EventBody::LaneState { state: LaneState::Busy, job_id: Some(id), .. } if *id == job.id)));
}

#[test]
fn a_failed_stage_is_recorded_failed_and_the_lane_remembers_where() {
    let w = W::new("drive-upload-fails");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        fake.on("UploadSample").fail("disk full");
    });
    let stop = w.stages(&mut waiter).run_to_launch(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::UploadFailed);
    let work = w.lane_file().current.unwrap();
    assert_eq!(
        (work.stage, work.checkpoint),
        (Stage::Upload, Checkpoint::Started)
    );
    assert_eq!(
        w.job(&job.id).state,
        JobState::Running,
        "ending or retrying the job is the caller's"
    );
    assert!(
        !waiter
            .engine_mut()
            .sent_names()
            .contains(&"Execute".to_owned())
    );
}

#[test]
fn a_cancel_between_stages_stops_before_the_next_one() {
    let w = W::new("drive-cancel");
    let job = w.fx.running(1);
    w.fx.store
        .cancel(
            &job.id,
            Some("changed my mind"),
            &crate::store::tests::manager(),
        )
        .unwrap();
    let mut waiter = w.engine(cycle);
    let stop = w.stages(&mut waiter).run_to_launch(&job).unwrap_err();
    assert!(matches!(stop, StageStop::Cancelled), "{stop:?}");
    assert!(
        waiter.engine_mut().sent().is_empty(),
        "no engine command after the cancel"
    );
}

#[test]
fn a_waiting_precheck_leaves_the_stage_open_for_the_caller() {
    let mut w = W::new("drive-wait");
    w.host = Box::new(Host(Some(HostProblem::Wait(
        WaitingFor::Resources,
        "disk".into(),
    ))));
    let job = w.fx.running(1);
    let mut waiter = w.engine(cycle);
    let stop = w.stages(&mut waiter).run_to_launch(&job).unwrap_err();
    assert!(matches!(
        stop,
        StageStop::Wait {
            waiting_for: WaitingFor::Resources,
            ..
        }
    ));
    assert_eq!(w.lane_file().current, None, "the lane was not taken");
    assert!(waiter.engine_mut().sent().is_empty());
}

#[test]
fn a_crash_in_the_middle_of_a_cycle_is_one_recovery_puts_right() {
    let mut w = W::new("drive-crash");
    let job = w.fx.running(1);
    w.procs.procs.borrow_mut().insert(
        900,
        crate::lane::process::ProcessInfo {
            argv: vec![
                "qemu-system-x86_64".into(),
                "file=/d/vms/auto-1/disk".into(),
            ],
            start_ticks: Some(5),
        },
    );
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        fake.on("UploadSample").die();
    });
    let stop = w.stages(&mut waiter).run_to_launch(&job).unwrap_err();
    assert!(matches!(stop, StageStop::Abort(_)));
    assert!(w.lane_file().qemu.is_some(), "recorded at provision");
    // The service restarts.
    w.fx.reopen();
    let mut fresh = w.engine(|_| {});
    let report = crate::lane::recover_startup(
        &w.fx.store,
        &w.lanes,
        &mut fresh,
        &w.procs,
        &crate::lane::RecoverOptions::default(),
    )
    .unwrap();
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job.id));
    assert_eq!(w.job(&job.id).state, JobState::Queued);
    let lane_report = &report.lanes[0];
    assert_eq!(lane_report.qemu, crate::lane::QemuOutcome::Killed(900));
    let work = lane_report.interrupted.as_ref().unwrap();
    assert_eq!(
        (work.stage, work.checkpoint),
        (Stage::Upload, Checkpoint::Started)
    );
    assert_eq!(w.procs.killed.borrow().as_slice(), [900]);
    assert_eq!(w.lane_file().current, None);
}
