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
        ids::RunId,
        run::{Revert, Run, RunState, Stage, WaitingFor},
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
    fn add_tag(&self, job: &Run, tag: &str) -> Result<bool, String> {
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
    pub(super) callers: Box<dyn crate::config::callers::CallerLookup>,
    /// `[lanes] revert` of the node.
    pub(super) revert: crate::config::service::RevertMode,
}

impl W {
    /// A world whose lanes revert with `revert`.
    pub(super) fn reverting(name: &str, revert: crate::config::service::RevertMode) -> Self {
        Self {
            revert,
            ..Self::new(name)
        }
    }

    pub(super) fn new(name: &str) -> Self {
        Self::with(name, |_| {})
    }

    pub(super) fn with(name: &str, edit: impl FnOnce(&mut crate::config::Preset)) -> Self {
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
            callers: Box::new(crate::config::callers::LocalOnly),
            revert: Default::default(),
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
                revert: self.revert,
                callers: self.callers.as_ref(),
                procs: &self.procs,
                host: self.host.as_ref(),
                evidence: self.evidence.as_ref(),
                triage: self.triage.as_ref(),
                tags: &self.tags,
                data_dir: std::path::Path::new("/nonexistent-antinomie-data"),
            },
            lane: lane(),
        }
    }

    pub(super) fn prepared(&self, job: &Run) -> Prepared {
        let frozen = self.fx.store.frozen_preset(&job.id).unwrap();
        Prepared {
            effective: plan::effective(&frozen.preset, self.revert),
            preset: frozen,
            lane: self.lanes.load(&lane()).unwrap().unwrap(),
        }
    }

    pub(super) fn lane_file(&self) -> LaneFile {
        self.lanes.load(&lane()).unwrap().unwrap()
    }

    pub(super) fn job(&self, id: &RunId) -> Run {
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
fn the_launch_request_is_the_presets() {
    use crate::config::{preset::User, service::RevertMode};
    let preset = crate::config::Preset::default();
    let plain = plan::effective(&preset, RevertMode::SnapshotDisk);
    let r = &plain.request;
    assert_eq!((r.uid, r.gid), (1000, 1000));
    assert_eq!(r.cwd, "/tmp");
    assert!(r.args.is_empty());
    assert_eq!(r.env, ["PATH=/bin:/sbin:/usr/bin:/usr/sbin", "TERM=xterm"]);
    assert!(r.capture_network && !r.memory_dump_on_exit && !r.core_dump_on_exit);
    assert_eq!(
        r.route,
        Some(antinomie_monitor_core::route::RouteKind::Drop)
    );
    assert!(!r.analysis.enabled && !r.debug_on_start && r.host_copy.is_none());
    assert!(r.dump_trigger.is_none(), "the trigger is off by default");
    assert_eq!(plain.run_limit, Duration::from_secs(300));
    assert_eq!(plain.revert, RevertMode::SnapshotDisk);
    assert_eq!(plain.guest_path, "/tmp/{name}");

    let mut custom = preset.clone();
    let p = &mut custom.program;
    p.run_time_s = 30;
    p.arguments = vec!["-x".into()];
    p.environment = vec!["A=1".into()];
    p.working_directory = "/var/tmp".into();
    p.user = User::Root;
    custom.dumps.core_dump_on_exit = true;
    custom.dumps.core_budget_mib = 128;
    custom.dumps.core_deadline_ms = 1234;
    custom.dumps.memory_dump_on_exit = true;
    custom.network.capture = false;
    custom.network.route = crate::api::spec::Route::InetSim;
    let set = plan::effective(&custom, RevertMode::Reset);
    let r = &set.request;
    assert_eq!(set.run_limit, Duration::from_secs(30));
    assert_eq!(set.revert, RevertMode::Reset);
    assert_eq!((r.uid, r.gid), (0, 0));
    assert_eq!(r.args, ["-x"]);
    assert_eq!(r.cwd, "/var/tmp", "the preset's working directory");
    assert_eq!(r.env, ["A=1", plan::DEFAULT_PATH], "a PATH is added");
    assert!(r.core_dump_on_exit && r.memory_dump_on_exit && !r.capture_network);
    assert_eq!(
        (r.core_max_size, r.core_timeout_ms),
        (Some(128 << 20), Some(1234))
    );
    assert_eq!(
        r.route,
        Some(antinomie_monitor_core::route::RouteKind::InetSim)
    );
    custom.program.user = User::Nobody;
    let r = plan::effective(&custom, RevertMode::Reset).request;
    assert_eq!((r.uid, r.gid), (65534, 65534));
    custom.program.user = User::Custom;
    custom.program.uid = 1234;
    custom.program.gid = 1500;
    let r = plan::effective(&custom, RevertMode::Reset).request;
    assert_eq!((r.uid, r.gid), (1234, 1500));
}

#[test]
fn the_presets_dump_trigger_is_in_the_launch_request_with_its_limits() {
    use antinomie_monitor_core::dump_trigger::TriggerTier;
    let revert = crate::config::service::RevertMode::SnapshotDisk;
    let mut preset = crate::config::Preset::default();
    preset.dumps.dump_when_suspicious = true;
    preset.dumps.max_dumps = 4;
    preset.dumps.dumps_apart_s = 90;
    let r = plan::effective(&preset, revert).request;
    let plan = r.dump_trigger.expect("the trigger is armed");
    assert_eq!(plan.min_tier, TriggerTier::High);
    assert!(plan.core && !plan.memory);
    assert_eq!((plan.max_dumps, plan.cooldown_secs), (4, 90));
    // The core of a trigger has the preset's budget though no exit core is asked.
    assert!(!r.core_dump_on_exit);
    assert_eq!(
        (r.core_max_size, r.core_timeout_ms),
        (Some(256 << 20), Some(5000))
    );
    preset.dumps.trigger_core = false;
    preset.dumps.trigger_memory_dump = true;
    let r = plan::effective(&preset, revert).request;
    assert!(r.dump_trigger.is_some_and(|plan| plan.memory && !plan.core));
    assert_eq!((r.core_max_size, r.core_timeout_ms), (None, None));
}

#[test]
fn non_resident_pages_are_asked_only_for_the_cores_of_a_trigger() {
    let revert = crate::config::service::RevertMode::SnapshotDisk;
    let mut preset = crate::config::Preset::default();
    preset.dumps.read_non_resident_pages = true;
    assert!(!plan::effective(&preset, revert).request.core_nonresident);
    preset.dumps.core_dump_on_exit = true;
    assert!(!plan::effective(&preset, revert).request.core_nonresident);
    preset.dumps.dump_when_suspicious = true;
    assert!(plan::effective(&preset, revert).request.core_nonresident);
    preset.dumps.read_non_resident_pages = false;
    assert!(!plan::effective(&preset, revert).request.core_nonresident);
}

#[test]
fn the_host_stages_take_the_presets_checks_limits_and_ghidra_choice() {
    use antinomie_monitor_core::analysis::AnalysisKind;
    let mut preset = crate::config::Preset::default();
    let plan = plan::hosted(&preset);
    assert_eq!(plan.static_checks, AnalysisKind::TRIAGE);
    assert_eq!(plan.static_limit_min, None, "0 is each tool's own limit");
    assert!(!plan.static_limits.ghidra_disassembly);
    assert_eq!(plan.static_limits.rows, 2048);
    preset.static_analysis.deep_checks = vec![crate::api::spec::StaticCheck::Floss];
    preset.static_analysis.time_limit_per_tool_min = 7;
    preset.static_analysis.ghidra_disassembly = true;
    preset.static_analysis.limits.rows_per_check = 4096;
    preset.detection.sigma = false;
    let plan = plan::hosted(&preset);
    assert_eq!(plan.static_checks.len(), 12);
    assert_eq!(plan.static_checks.last(), Some(&AnalysisKind::Floss));
    assert_eq!(plan.static_limit_min, Some(7));
    assert!(plan.static_limits.ghidra_disassembly);
    assert_eq!(plan.static_limits.rows, 4096);
    assert_eq!(plan.engines.len(), 2);
    preset.static_analysis.enabled = false;
    assert!(plan::hosted(&preset).static_checks.is_empty());
}

#[test]
fn the_guest_path_puts_the_library_name_for_name_in_the_presets_path() {
    let sha = "ab".repeat(32);
    assert_eq!(
        plan::guest_path("/tmp/{name}", &sha, "evil one!.exe"),
        "/tmp/abababab-evil_one_.exe"
    );
    assert_eq!(
        plan::guest_path("/var/tmp/{name}", &sha, ""),
        "/var/tmp/abababab-sample"
    );
    assert_eq!(plan::guest_path("/opt/run.bin", &sha, "x"), "/opt/run.bin");
    assert!(
        plan::guest_path("/tmp/{name}", &sha, &"n".repeat(100)).len()
            <= "/tmp/abababab-".len() + 48
    );
    assert_eq!(plan::upload_wait(0), 60 * SECOND);
    assert_eq!(plan::upload_wait(25 << 20), 62 * SECOND);
}

// ---- prechecks ----------------------------------------------------------

#[test]
fn prechecks_hand_over_the_frozen_preset_the_settings_and_the_lane() {
    let w = W::new("pre-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    let prepared = w.stages(&mut waiter).prechecks(&job).unwrap();
    assert_eq!(prepared.preset.name, "standard");
    assert_eq!(prepared.lane.vm_id, VM);
    assert_eq!(prepared.effective.run_limit, Duration::from_secs(300));
    assert!(
        waiter.engine_mut().sent_names().is_empty(),
        "prechecks touch no VM"
    );
}

#[test]
fn a_waiting_run_keeps_its_preset_when_the_preset_changes_or_goes() {
    let mut w = W::new("pre-preset");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    // Gone from the files (retired): the run keeps what it froze.
    w.fx.policies = crate::config::PresetSet::default();
    let prepared = w.stages(&mut waiter).prechecks(&job).unwrap();
    assert_eq!(prepared.preset.name, "standard");
    assert_eq!(prepared.effective.run_limit, Duration::from_secs(300));
    // Changed: still the frozen options.
    w.fx.policies =
        crate::config::PresetSet::single(crate::store::tests::policy("standard", |p| {
            p.program.run_time_s = 60;
        }));
    let prepared = w.stages(&mut waiter).prechecks(&job).unwrap();
    assert_eq!(prepared.effective.run_limit, Duration::from_secs(300));
}

/// What a client holds now, as a reloaded `service.toml` would say.
struct Holds(Option<std::collections::BTreeSet<crate::api::ops::Permission>>);

impl crate::config::callers::CallerLookup for Holds {
    fn permissions_now(
        &self,
        _: &str,
        _: &crate::config::callers::Labels,
    ) -> Option<std::collections::BTreeSet<crate::api::ops::Permission>> {
        self.0.clone()
    }
}

#[test]
fn prechecks_refuse_a_run_whose_client_lost_a_permission_it_uses() {
    use crate::api::ops::Permission;
    let mut w = W::with("pre-perm", |p| p.dumps.core_dump_on_exit = true);
    let mut who = crate::store::tests::caller(1000);
    who.permissions.insert(Permission::EvidenceCoreDump);
    let queued =
        w.fx.submit_as(&who, crate::store::tests::spec(1))
            .unwrap()
            .run;
    assert_eq!(
        queued.state,
        crate::api::run::RunState::Queued,
        "{:?}",
        queued.failure
    );
    let job =
        w.fx.store
            .claim_next(&lane(), &mut |_| crate::store::Eligibility::Ready)
            .unwrap()
            .unwrap();
    let mut waiter = w.engine(|_| {});
    // Still held: the run goes on.
    w.callers = Box::new(Holds(Some(
        [Permission::RunsSubmit, Permission::EvidenceCoreDump].into(),
    )));
    assert!(w.stages(&mut waiter).prechecks(&job).is_ok());
    // A client the service does not configure keeps what it was admitted with.
    w.callers = Box::new(Holds(None));
    assert!(w.stages(&mut waiter).prechecks(&job).is_ok());
    // The core dump permission was taken away while the run waited.
    w.callers = Box::new(Holds(Some([Permission::RunsSubmit].into())));
    let stop = w.stages(&mut waiter).prechecks(&job).unwrap_err();
    let failure = stop.failure().unwrap();
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.stage, Stage::Prechecks);
    assert_eq!(
        failure.details["needs"],
        serde_json::json!(["evidence.core_dump"])
    );
    assert!(failure.message.contains("no longer holds"), "{failure:?}");
    // runs.submit itself is used by every run.
    w.callers = Box::new(Holds(Some([Permission::EvidenceCoreDump].into())));
    let stop = w.stages(&mut waiter).prechecks(&job).unwrap_err();
    assert_eq!(
        stop.failure().unwrap().details["needs"],
        serde_json::json!(["runs.submit"])
    );
}

pub(super) struct Host(pub(super) Option<HostProblem>);

impl HostChecks for Host {
    fn check(&self, _: &Run, _: &crate::config::Preset) -> Result<(), HostProblem> {
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
    let other = RunId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap();
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

/// ANT-T0474 (P3): a daemon that just started took the requeued job before
/// its engine had listed the lane VM's snapshots. `prechecks` asks for the
/// list and checks against it; without a list the job waits, and the lane
/// is not quarantined.
#[test]
fn prechecks_wait_for_the_engine_to_list_the_lane_vms_snapshots() {
    let w = W::new("pre-tree");
    let job = w.fx.running(1);
    let unlisted = |s: &mut Snapshot| {
        healthy(s);
        s.vm_snapshot_trees.clear();
    };
    // The list comes with the refresh: the job goes on.
    let mut waiter = w.engine(|fake| {
        fake.start_with(unlisted);
        fake.on("RefreshVmSnapshots")
            .then(100 * MS, healthy)
            .after(150 * MS)
            .ok("Snapshots refreshed");
    });
    assert!(w.stages(&mut waiter).prechecks(&job).is_ok());
    assert_eq!(waiter.engine_mut().sent_names(), ["RefreshVmSnapshots"]);
    // No list at all: the job waits for the lane.
    let mut waiter = w.engine(|fake| {
        fake.start_with(unlisted);
        fake.on("RefreshVmSnapshots").fail("the engine is busy");
    });
    match w.stages(&mut waiter).prechecks(&job).unwrap_err() {
        StageStop::Wait {
            waiting_for,
            detail,
        } => {
            assert_eq!(waiting_for, WaitingFor::Lane);
            assert!(detail.contains("has not listed the snapshots"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!w.lane_file().is_quarantined());
    // A listed tree without the clean snapshot still fails at once.
    let mut changed = w.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.vm_snapshot_trees.get_mut(VM).unwrap().nodes[0].id = "by-hand".into();
        });
    });
    let stop = w.stages(&mut changed).prechecks(&job).unwrap_err();
    assert_eq!(code(&stop), FailureCode::LaneChanged);
    assert!(changed.engine_mut().sent_names().is_empty());
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
                RunId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
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

fn provision(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Run) -> Result<Provisioned, StageStop> {
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
    let w = W::reverting(
        "prov-full",
        crate::config::service::RevertMode::SnapshotFull,
    );
    let job = w.fx.running(1);
    let mut waiter = w.engine(restore_ok);
    provision(&w, &mut waiter, &job).unwrap();
    assert!(
        waiter.engine_mut().sent()[0]
            .detail
            .contains("boot_from_disk: false")
    );
    assert_eq!(w.job(&job.id).vm.unwrap().revert, Revert::SnapshotFull);

    let w = W::reverting("prov-reset", crate::config::service::RevertMode::Reset);
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
    let w = W::reverting(
        "prov-start-fails",
        crate::config::service::RevertMode::Reset,
    );
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
    let w = W::with("prov-core", |p| p.dumps.core_dump_on_exit = true);
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

fn upload(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Run) -> Result<(), StageStop> {
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

fn launch(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Run) -> Result<super::Launched, StageStop> {
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
    assert_eq!(stored.program.unwrap().id, "r1");
    let recording = stored.recording.unwrap();
    assert_eq!(
        (recording.vm_id.as_str(), recording.boot_id.as_str()),
        (VM, "b2")
    );
    assert!(kinds(&w.fx, &job.id).contains(&"run.program".to_owned()));
}

/// ANT-T0476 (P5): a guest whose kernel crashed while it booted (a clean
/// snapshot with a half-grown file system) still answers; the program is
/// not started in it and the job says why.
#[test]
fn a_guest_kernel_that_crashed_while_booting_fails_the_launch() {
    let w = W::new("launch-crash");
    let job = w.fx.running(1);
    let console = w.fx.dir.join("serial.log");
    std::fs::write(
        &console,
        "[    3.665615] EXT4-fs (sda): resizing filesystem from 393217 to 4194304 blocks\n\
         [    3.668595] kernel BUG at ../source/linux-6.12.94/fs/ext4/resize.c:547!\n\
         Guest filesystem resize failed\nBusyBox guest ready\n",
    )
    .unwrap();
    let path = console.clone();
    let mut waiter = w.engine(move |fake| {
        let path = path.clone();
        fake.start_with(move |s| {
            healthy(s);
            s.serial_log = Some(path.clone());
        });
    });
    let stop = launch(&w, &mut waiter, &job).unwrap_err();
    let failure = stop.failure().unwrap();
    assert_eq!(
        (failure.code, failure.stage),
        (FailureCode::GuestUnreachable, Stage::Launch)
    );
    assert!(failure.retryable);
    assert!(failure.message.contains("guest kernel crashed"));
    assert_eq!(
        failure.detail.as_deref(),
        Some("kernel BUG at ../source/linux-6.12.94/fs/ext4/resize.c:547!")
    );
    assert!(
        waiter.engine_mut().sent().is_empty(),
        "nothing was launched"
    );
    // A clean boot's console launches.
    std::fs::write(&console, "BusyBox guest ready\n").unwrap();
    let mut clean = w.engine(|fake| {
        execute_ok(fake);
        let path = console.clone();
        fake.after(MS, move |s| s.serial_log = Some(path.clone()));
    });
    clean.pump(10 * MS).unwrap();
    assert!(launch(&w, &mut clean, &job).is_ok());
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
    // A desktop run is a reserved preset value (refused at submit); the
    // launch still refuses the pair if a request carried it.
    let w = W::with("launch-desktop-core", |p| p.dumps.core_dump_on_exit = true);
    let job = w.fx.running(1);
    let mut prepared = w.prepared(&job);
    prepared.effective.request.run_in = antinomie_monitor_core::RunIn::GuestDesktop;
    let provisioned = Provisioned {
        vm_id: VM.into(),
        boot_id: Some("b2".into()),
        guest_revision: Some(21),
    };
    let mut waiter = w.engine(execute_ok);
    let stop = w
        .stages(&mut waiter)
        .launch(&job, &prepared, &provisioned)
        .unwrap_err();
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
    let stage_events = kinds.iter().filter(|k| *k == "run.stage").count();
    assert!(stage_events >= 8, "the stage records: {stage_events}");
    let stored = w.job(&job.id);
    assert_eq!(stored.state, RunState::Running);
    assert_eq!(stored.stage, Some(Stage::Launch));
    assert_eq!(stored.vm.as_ref().unwrap().id, VM);
    // The lane file: this job, at launch, finished.
    let work = w.lane_file().current.unwrap();
    assert_eq!(
        (work.job_id, work.stage, work.checkpoint),
        (job.id.clone(), Stage::Launch, Checkpoint::Finished)
    );
    assert!(w.engine_events().iter().any(|e| matches!(e, EventBody::LaneState { state: LaneState::Busy, run_id: Some(id), .. } if *id == job.id)));
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
        RunState::Running,
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
    assert_eq!(w.job(&job.id).state, RunState::Queued);
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
