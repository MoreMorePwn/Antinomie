// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the lane state file, the lane checks and startup recovery (card
//! P3-4a). Recovery is run against a [`FakeEngine`] and a table of processes,
//! after a "crash" at every stage boundary of a lane job.

use super::{
    check::{LaneProblem, check_lane},
    process::{ProcessInfo, Processes},
    recover::{FileState, QemuOutcome, RecoverOptions, recover_startup},
    state::{
        Checkpoint, LANE_FILE_VERSION, LaneDir, LaneFile, LaneStateError, QUARANTINE_AFTER,
        QemuRecord, WriteFault,
    },
};
use crate::{
    api::{
        event::{EventBody, LaneState},
        failure::FailureCode,
        ids::{JobId, LaneId},
        job::{Job, JobState, Stage},
    },
    clock::{Clock, ManualClock},
    engine::FakeEngine,
    store::tests::{Fx, T0, kinds, lane},
    waiter::Waiter,
};
use antinomie_monitor_core::{
    Snapshot, VmCheckpoint, VmConfig, VmSnapshotConsistency, VmSnapshotMode, VmSnapshotTree,
    VmState,
    disk_layers::{DiskLayer, LayerPhase},
};
use std::{
    cell::RefCell, collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc,
    time::Duration,
};

pub(crate) const VM: &str = "auto-1";
pub(crate) const CLEAN: &str = "snap-clean";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-lane-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub(crate) fn file() -> LaneFile {
    LaneFile::new(lane(), VM, CLEAN, "busybox-r21", T0)
}

// ---- the state file -----------------------------------------------------

#[test]
fn a_lane_file_round_trips_and_is_private() {
    let dir = LaneDir::new(&scratch("roundtrip"));
    assert_eq!(dir.load(&lane()).unwrap(), None);
    let mut lane_file = file();
    lane_file.begin_work(
        JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
        2,
        T0 + 5,
    );
    lane_file.set_qemu(QemuRecord {
        pid: 4242,
        start_ticks: Some(99),
        marker: VM.into(),
        recorded_ms: T0 + 6,
    });
    dir.save(&lane_file).unwrap();
    assert_eq!(dir.load(&lane()).unwrap(), Some(lane_file));
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir.path(&lane())), 0o600);
    assert_eq!(mode(dir.dir()), 0o700);
    let text = std::fs::read_to_string(dir.path(&lane())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["version"], LANE_FILE_VERSION);
    assert_eq!(value["current"]["stage"], "provision");
    assert_eq!(value["current"]["checkpoint"], "started");
    assert_eq!(value["qemu"]["pid"], 4242);
}

#[test]
fn a_write_killed_at_any_point_leaves_the_old_file_or_the_new_one() {
    for (fault, new_is_visible) in [
        (WriteFault::DuringTemp, false),
        (WriteFault::BeforeRename, false),
        (WriteFault::AfterRename, true),
    ] {
        let dir = LaneDir::new(&scratch(&format!("torn-{fault:?}")));
        let old = file();
        dir.save(&old).unwrap();
        let mut new = old.clone();
        new.quarantine(FailureCode::RevertFailed, "restore failed", T0 + 9);
        dir.inject_fault(fault);
        assert!(dir.save(&new).is_err());
        // A restart: the file reads as one of the two, whole.
        let read = dir.load(&lane()).unwrap().unwrap();
        assert_eq!(
            read,
            if new_is_visible {
                new.clone()
            } else {
                old.clone()
            },
            "{fault:?}"
        );
        // The temporary file is ignored by readers and swept by the next start.
        let leftovers = std::fs::read_dir(dir.dir())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(dir.sweep_temp(), leftovers);
        assert_eq!(dir.lanes().unwrap(), [lane()]);
        // And writing works again.
        dir.save(&new).unwrap();
        assert_eq!(dir.load(&lane()).unwrap(), Some(new));
    }
}

#[test]
fn a_damaged_or_foreign_file_is_refused_and_left_alone() {
    let dir = LaneDir::new(&scratch("damaged"));
    dir.save(&file()).unwrap();
    let path = dir.path(&lane());
    let good = std::fs::read_to_string(&path).unwrap();
    let mut cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("truncated", good[..good.len() / 2].to_owned()),
        ("not an object", "[1, 2]".into()),
        ("no version", good.replace("\"version\"", "\"edition\"")),
        ("unknown field", good.replacen('{', "{\"surprise\": 1,", 1)),
        ("another lane", good.replace("lane-1", "lane-2")),
    ];
    cases.push((
        "wrong type",
        good.replacen("\"vm_id\": \"auto-1\"", "\"vm_id\": 7", 1),
    ));
    for (name, text) in cases {
        std::fs::write(&path, &text).unwrap();
        match dir.load(&lane()) {
            Err(LaneStateError::Corrupt { .. }) => {}
            other => panic!("{name}: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            text,
            "{name}: left as it is"
        );
    }
    let newer = good.replace("\"version\": 1", "\"version\": 2");
    std::fs::write(&path, &newer).unwrap();
    assert!(matches!(
        dir.load(&lane()),
        Err(LaneStateError::TooNew { found: 2, .. })
    ));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), newer);
}

#[test]
fn update_changes_one_lane_and_refuses_a_missing_one() {
    let dir = LaneDir::new(&scratch("update"));
    assert!(matches!(
        dir.update(&lane(), |_| ()),
        Err(LaneStateError::Missing(_))
    ));
    dir.save(&file()).unwrap();
    dir.save(&LaneFile::new(LaneId::new(2), "auto-2", "s", "b", T0))
        .unwrap();
    dir.update(&lane(), |f| {
        f.note_start_failure(FailureCode::VmStartFailed, "x", T0 + 1)
    })
    .unwrap();
    assert_eq!(dir.load(&lane()).unwrap().unwrap().failures, 1);
    assert_eq!(dir.load(&LaneId::new(2)).unwrap().unwrap().failures, 0);
    assert_eq!(dir.lanes().unwrap(), [lane(), LaneId::new(2)]);
}

#[test]
fn work_moves_through_checkpoints_to_collected_and_is_released() {
    let mut f = file();
    let job = JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap();
    assert!(
        !f.checkpoint(Stage::Upload, Checkpoint::Started, T0),
        "no work yet"
    );
    assert!(!f.collected(T0));
    f.begin_work(job.clone(), 1, T0);
    f.set_qemu(QemuRecord {
        pid: 7,
        start_ticks: None,
        marker: VM.into(),
        recorded_ms: T0,
    });
    assert!(f.checkpoint(Stage::Collect, Checkpoint::Started, T0 + 1));
    assert!(f.collected(T0 + 2));
    assert_eq!(f.current, None);
    assert_eq!(f.qemu, None, "the VM is stopped when collect finished");
    assert_eq!(f.collected[0].job_id, job);
    f.release(&job, T0 + 3);
    assert!(f.collected.is_empty());
}

#[test]
fn three_failures_in_a_row_quarantine_and_a_success_resets_the_count() {
    let mut f = file();
    assert!(!f.note_start_failure(FailureCode::VmStartFailed, "a", T0));
    f.note_start_success(T0);
    for n in 1..QUARANTINE_AFTER {
        assert!(
            !f.note_start_failure(FailureCode::GuestUnreachable, "b", T0),
            "{n}"
        );
    }
    assert!(f.note_start_failure(FailureCode::GuestUnreachable, "third", T0 + 7));
    let q = f.quarantine.clone().unwrap();
    assert_eq!(
        (q.reason, q.detail.as_str(), q.since_ms),
        (FailureCode::GuestUnreachable, "third", T0 + 7)
    );
    // A second reason does not replace the first.
    f.quarantine(FailureCode::LaneChanged, "later", T0 + 9);
    assert_eq!(f.quarantine.unwrap().reason, FailureCode::GuestUnreachable);
    let mut g = file();
    g.quarantine(FailureCode::RevertFailed, "x", T0);
    g.failures = 2;
    g.unquarantine(T0 + 1);
    assert!(!g.is_quarantined() && g.failures == 0);
}

// ---- the checks ---------------------------------------------------------

pub(crate) fn vm_config(id: &str) -> VmConfig {
    VmConfig {
        id: id.into(),
        ..VmConfig::default()
    }
}

fn checkpoint(id: &str) -> VmCheckpoint {
    VmCheckpoint {
        id: id.into(),
        parent_id: None,
        name: "auto-clean".into(),
        description: String::new(),
        created_unix_ms: 0,
        mode: VmSnapshotMode::Disk,
        consistency: VmSnapshotConsistency::Stopped,
        config: vm_config(VM),
        disk_size: 0,
        memory_size: 0,
        compatible: true,
        compatibility_note: None,
        deleted: false,
        stealth: None,
        profile: Default::default(),
    }
}

/// A snapshot with the lane VM and its clean snapshot, stopped and settled.
pub(crate) fn healthy(snapshot: &mut Snapshot) {
    snapshot.state = VmState::Stopped;
    snapshot.vms = vec![vm_config(VM)];
    snapshot.vm_snapshot_trees.insert(
        VM.into(),
        VmSnapshotTree {
            vm_id: VM.into(),
            nodes: vec![checkpoint(CLEAN)],
            active_parent_id: None,
            recovery_note: None,
            capabilities: Default::default(),
        },
    );
}

pub(crate) fn layer(phase: LayerPhase) -> DiskLayer {
    DiskLayer {
        vm_id: VM.into(),
        boot_id: "boot".into(),
        phase,
        started_ms: 0,
        phase_ms: 0,
    }
}

#[test]
fn a_healthy_stopped_lane_has_no_problems() {
    let mut snapshot = Snapshot::default();
    healthy(&mut snapshot);
    assert_eq!(check_lane(&file(), &snapshot), []);
}

#[test]
fn each_problem_is_named_with_its_code_or_its_wait() {
    let mut snapshot = Snapshot::default();
    healthy(&mut snapshot);
    snapshot.state = VmState::Running;
    snapshot.disk_layers = vec![layer(LayerPhase::Finalizing)];
    let mut f = file();
    f.quarantine(FailureCode::RevertFailed, "x", T0);
    let problems = check_lane(&f, &snapshot);
    assert_eq!(
        problems,
        [
            LaneProblem::Quarantined(FailureCode::RevertFailed),
            LaneProblem::NotStopped("Running".into()),
            LaneProblem::LayerPending,
        ]
    );
    assert_eq!(
        problems[2].waiting_for(),
        Some(crate::api::job::WaitingFor::LayerPending)
    );
    assert_eq!(
        problems[0].waiting_for(),
        Some(crate::api::job::WaitingFor::LaneQuarantined)
    );

    let mut gone = Snapshot::default();
    healthy(&mut gone);
    gone.vm_snapshot_trees.get_mut(VM).unwrap().nodes[0].id = "another".into();
    let problems = check_lane(&file(), &gone);
    assert_eq!(
        problems,
        [LaneProblem::SnapshotMissing {
            id: CLEAN.into(),
            verifiable: true
        }]
    );
    assert_eq!(problems[0].failure_code(), Some(FailureCode::LaneChanged));

    let none = Snapshot::default();
    assert_eq!(check_lane(&file(), &none), [LaneProblem::NoVm]);
    assert_eq!(LaneProblem::NoVm.failure_code(), Some(FailureCode::NoVm));
}

#[test]
fn a_recording_flush_counts_as_a_pending_layer() {
    let mut snapshot = Snapshot::default();
    healthy(&mut snapshot);
    snapshot.recording_flush = Some(Default::default());
    assert_eq!(check_lane(&file(), &snapshot), [LaneProblem::LayerPending]);
}

// ---- recovery -----------------------------------------------------------

/// A table of processes; kills are recorded.
pub(crate) struct Table {
    pub(crate) procs: RefCell<BTreeMap<u32, ProcessInfo>>,
    pub(crate) killed: RefCell<Vec<u32>>,
    pub(crate) refuse: bool,
}

impl Table {
    pub(crate) fn new() -> Self {
        Self {
            procs: RefCell::default(),
            killed: RefCell::default(),
            refuse: false,
        }
    }
    pub(crate) fn with(self, pid: u32, argv: &[&str], ticks: u64) -> Self {
        self.procs.borrow_mut().insert(
            pid,
            ProcessInfo {
                argv: argv.iter().map(|s| (*s).to_owned()).collect(),
                start_ticks: Some(ticks),
            },
        );
        self
    }
    pub(crate) fn qemu(self, pid: u32) -> Self {
        self.with(
            pid,
            &[
                "/usr/bin/qemu-system-x86_64",
                "-drive",
                &format!("file=/d/vms/{VM}/disk"),
            ],
            500,
        )
    }
}

impl Processes for Table {
    fn info(&self, pid: u32) -> Option<ProcessInfo> {
        self.procs.borrow().get(&pid).cloned()
    }
    fn find_qemu(&self, marker: &str) -> Vec<(u32, ProcessInfo)> {
        self.procs
            .borrow()
            .iter()
            .filter(|(_, info)| super::process::is_qemu_with(info, marker))
            .map(|(pid, info)| (*pid, info.clone()))
            .collect()
    }
    fn kill(&self, pid: u32) -> Result<(), String> {
        if self.refuse {
            return Err("operation not permitted".into());
        }
        self.killed.borrow_mut().push(pid);
        self.procs.borrow_mut().remove(&pid);
        Ok(())
    }
}

struct World {
    fx: Fx,
    lanes: LaneDir,
}

impl World {
    fn new(name: &str) -> Self {
        let fx = Fx::new(name);
        let lanes = LaneDir::new(&fx.dir.join("service"));
        Self { fx, lanes }
    }

    /// The service restarts: a new store connection on the same files.
    fn restart(&mut self) {
        self.fx.reopen();
    }

    fn engine(&self, build: impl FnOnce(&mut FakeEngine)) -> Waiter<FakeEngine> {
        let mut fake = FakeEngine::new(self.fx.clock.clone());
        fake.start_with(healthy);
        build(&mut fake);
        let clock: Arc<ManualClock> = self.fx.clock.clone();
        let mut waiter = Waiter::new(fake, clock);
        waiter.first_snapshot(Duration::from_secs(1)).unwrap();
        waiter
    }

    fn recover(
        &self,
        waiter: &mut Waiter<FakeEngine>,
        procs: &Table,
    ) -> super::recover::StartupRecovery {
        recover_startup(
            &self.fx.store,
            &self.lanes,
            waiter,
            procs,
            &RecoverOptions::default(),
        )
        .unwrap()
    }

    fn job(&self, id: &JobId) -> Job {
        self.fx.store.get(id).unwrap()
    }
}

/// A job `running` at `stage`, with the lane file saying the lane is on it.
fn crashed_at(world: &World, stage: Stage, checkpoint: Checkpoint) -> (JobId, LaneFile) {
    let job = world.fx.running(1);
    // The store's stages begin at prechecks; the lane stages follow.
    for next in [
        Stage::Provision,
        Stage::Upload,
        Stage::Launch,
        Stage::Run,
        Stage::Collect,
    ] {
        if next > stage {
            break;
        }
        world.fx.store.begin_stage(&job.id, next).unwrap();
    }
    let mut f = file();
    f.begin_work(job.id.clone(), job.attempt, T0);
    f.checkpoint(stage, checkpoint, T0 + 1);
    f.set_qemu(QemuRecord {
        pid: 321,
        start_ticks: Some(500),
        marker: VM.into(),
        recorded_ms: T0,
    });
    world.lanes.save(&f).unwrap();
    (job.id, f)
}

const LANE_STAGES: [Stage; 5] = [
    Stage::Provision,
    Stage::Upload,
    Stage::Launch,
    Stage::Run,
    Stage::Collect,
];

#[test]
fn a_crash_at_every_stage_boundary_requeues_the_job_and_frees_the_lane() {
    for stage in LANE_STAGES {
        for checkpoint in [Checkpoint::Started, Checkpoint::Finished] {
            let mut world =
                World::new(&format!("boundary-{stage:?}-{checkpoint:?}").to_lowercase());
            let (job, _) = crashed_at(&world, stage, checkpoint);
            // The VM still runs under the dead process.
            let procs = Table::new().qemu(321);
            world.restart();
            let mut waiter = world.engine(|_| {});

            let report = world.recover(&mut waiter, &procs);
            let at = format!("{stage:?}/{checkpoint:?}");
            // The job: a new attempt, by the state machine's edge running -> queued.
            assert_eq!(report.jobs.requeued, std::slice::from_ref(&job), "{at}");
            assert_eq!(world.job(&job).state, JobState::Queued, "{at}");
            assert!(
                kinds(&world.fx, &job).contains(&"job.requeued".to_owned()),
                "{at}"
            );
            // The lane: the process is gone, the work is cleared, the file is whole.
            let lane_report = &report.lanes[0];
            assert_eq!(lane_report.file, FileState::Recovered, "{at}");
            assert_eq!(lane_report.qemu, QemuOutcome::Killed(321), "{at}");
            assert_eq!(procs.killed.borrow().as_slice(), [321], "{at}");
            let work = lane_report.interrupted.as_ref().unwrap();
            assert_eq!((work.stage, work.checkpoint), (stage, checkpoint), "{at}");
            assert!(
                lane_report.resume.is_empty() && lane_report.quarantined.is_none(),
                "{at}"
            );
            assert_eq!(lane_report.problems, [], "{at}");
            let stored = world.lanes.load(&lane()).unwrap().unwrap();
            assert_eq!(
                (stored.current, stored.qemu, stored.failures),
                (None, None, 0),
                "{at}"
            );
            assert_eq!(stored.clean_snapshot_id, CLEAN, "{at}");
            // The engine was not asked to do anything: it is stopped already.
            assert_eq!(
                waiter.engine_mut().sent_names(),
                Vec::<String>::new(),
                "{at}"
            );

            // Recovery is repeatable: a second start finds nothing.
            world.restart();
            let mut waiter = world.engine(|_| {});
            let again = world.recover(&mut waiter, &Table::new());
            assert_eq!(again.jobs.requeued, [], "{at}");
            assert_eq!(again.lanes[0].interrupted, None, "{at}");
            assert_eq!(again.lanes[0].qemu, QemuOutcome::NotRecorded, "{at}");
            assert_eq!(world.job(&job).state, JobState::Queued, "{at}");
        }
    }
}

#[test]
fn a_crash_before_the_first_checkpoint_of_a_new_job_is_the_same() {
    let mut world = World::new("before-checkpoint");
    let job = world.fx.running(2);
    let mut f = file();
    f.begin_work(job.id.clone(), job.attempt, T0);
    world.lanes.save(&f).unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job.id));
    assert_eq!(
        report.lanes[0].interrupted.as_ref().unwrap().stage,
        Stage::Provision
    );
    assert_eq!(world.job(&job.id).state, JobState::Queued);
}

#[test]
fn a_job_whose_collect_finished_resumes_at_analyse_and_the_vm_is_not_run_again() {
    let mut world = World::new("collected");
    let (job, mut f) = crashed_at(&world, Stage::Collect, Checkpoint::Finished);
    assert!(f.collected(T0 + 2));
    world.lanes.save(&f).unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.jobs.requeued, []);
    assert_eq!(report.jobs.kept, std::slice::from_ref(&job));
    let lane_report = &report.lanes[0];
    assert_eq!(lane_report.resume, std::slice::from_ref(&job));
    assert_eq!(lane_report.interrupted, None);
    // Still running, so the host worker can move it to analyse.
    assert_eq!(world.job(&job).state, JobState::Running);
    world.fx.store.begin_stage(&job, Stage::Analyse).unwrap();
    // The entry stays until the host stage releases it.
    assert_eq!(
        world.lanes.load(&lane()).unwrap().unwrap().collected.len(),
        1
    );
    world
        .lanes
        .update(&lane(), |f| f.release(&job, T0 + 9))
        .unwrap();
    // After release a later crash would requeue it like any running job.
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job));
    assert_eq!(world.job(&job).state, JobState::Queued);
}

#[test]
fn a_collected_entry_for_a_job_that_moved_on_is_dropped_not_resumed() {
    let mut world = World::new("collected-stale");
    let (job, mut f) = crashed_at(&world, Stage::Collect, Checkpoint::Finished);
    f.collected(T0 + 2);
    // The job ended some other way before the crash.
    world
        .fx
        .store
        .cancel(&job, None, &crate::store::tests::manager())
        .unwrap();
    world.lanes.save(&f).unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.jobs.kept, []);
    assert_eq!(report.lanes[0].resume, []);
    assert_eq!(report.lanes[0].dropped, std::slice::from_ref(&job));
    assert_eq!(world.job(&job).state, JobState::Cancelled);
    assert!(
        world
            .lanes
            .load(&lane())
            .unwrap()
            .unwrap()
            .collected
            .is_empty()
    );
}

#[test]
fn a_second_crash_of_the_same_job_counts_against_its_attempts() {
    let mut world = World::new("second-crash");
    let (job, _) = crashed_at(&world, Stage::Run, Checkpoint::Started);
    world.restart();
    let mut waiter = world.engine(|_| {});
    world.recover(&mut waiter, &Table::new());
    // The job is claimed again, the lane crashes again.
    let started = world
        .fx
        .store
        .claim_next(&lane(), &mut |_| crate::store::Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(started.id, job);
    world.fx.store.begin_stage(&job, Stage::Provision).unwrap();
    let mut f = file();
    f.begin_work(job.clone(), started.attempt, T0);
    world.lanes.save(&f).unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    // Not free this time: a requeue by retry, or the end if no attempt is left.
    assert!(report.jobs.requeued.contains(&job) || report.jobs.failed.contains(&job));
    assert_ne!(world.job(&job).state, JobState::Running);
}

#[test]
fn a_job_the_user_cancelled_during_the_crash_ends_cancelled() {
    let mut world = World::new("cancelling");
    let (job, _) = crashed_at(&world, Stage::Run, Checkpoint::Started);
    world
        .fx
        .store
        .cancel(
            &job,
            Some("no longer wanted"),
            &crate::store::tests::manager(),
        )
        .unwrap();
    assert_eq!(world.job(&job).state, JobState::Cancelling);
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new().qemu(321));
    assert_eq!(report.jobs.cancelled, std::slice::from_ref(&job));
    assert_eq!(world.job(&job).state, JobState::Cancelled);
    assert_eq!(report.lanes[0].qemu, QemuOutcome::Killed(321));
}

// ---- the recorded QEMU process -----------------------------------------

#[test]
fn a_process_that_is_gone_is_just_forgotten() {
    let mut world = World::new("qemu-gone");
    crashed_at(&world, Stage::Run, Checkpoint::Started);
    world.restart();
    let mut waiter = world.engine(|_| {});
    let procs = Table::new();
    let report = world.recover(&mut waiter, &procs);
    assert_eq!(report.lanes[0].qemu, QemuOutcome::Gone(321));
    assert!(procs.killed.borrow().is_empty());
    assert_eq!(world.lanes.load(&lane()).unwrap().unwrap().qemu, None);
}

#[test]
fn a_reused_pid_is_never_killed() {
    for other in [
        // Another program entirely.
        Table::new().with(321, &["/usr/bin/vim", "notes.txt"], 500),
        // Another VM's QEMU.
        Table::new().with(
            321,
            &["qemu-system-x86_64", "-drive", "file=/d/vms/other/disk"],
            500,
        ),
        // The same command line but started later: the number was reused.
        Table::new().with(
            321,
            &["qemu-system-x86_64", &format!("file=/d/vms/{VM}/disk")],
            777,
        ),
    ] {
        let mut world = World::new("qemu-reused");
        crashed_at(&world, Stage::Run, Checkpoint::Started);
        world.restart();
        let mut waiter = world.engine(|_| {});
        let report = world.recover(&mut waiter, &other);
        assert_eq!(report.lanes[0].qemu, QemuOutcome::NotOurs(321));
        assert!(other.killed.borrow().is_empty());
        assert!(report.lanes[0].quarantined.is_none());
    }
}

#[test]
fn a_qemu_that_will_not_end_quarantines_the_lane_and_keeps_the_record() {
    let mut world = World::new("qemu-stuck");
    crashed_at(&world, Stage::Run, Checkpoint::Started);
    world.restart();
    let mut waiter = world.engine(|_| {});
    let mut procs = Table::new().qemu(321);
    procs.refuse = true;
    let report = world.recover(&mut waiter, &procs);
    assert!(matches!(
        report.lanes[0].qemu,
        QemuOutcome::KillFailed(321, _)
    ));
    assert_eq!(report.lanes[0].quarantined, Some(FailureCode::LaneChanged));
    let stored = world.lanes.load(&lane()).unwrap().unwrap();
    assert!(stored.qemu.is_some(), "the next start tries again");
    assert!(stored.is_quarantined());
}

// ---- the engine side ---------------------------------------------------

#[test]
fn a_vm_the_engine_reports_running_is_stopped_before_the_lane_is_free() {
    let mut world = World::new("running-vm");
    crashed_at(&world, Stage::Run, Checkpoint::Started);
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| {
            s.state = VmState::Running;
            s.active_vm = Some(VM.into());
        });
        fake.on("Stop")
            .after(Duration::from_secs(2))
            .then(Duration::from_secs(2), |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
            })
            .ok("VM stopped");
    });
    let report = world.recover(&mut waiter, &Table::new());
    assert!(report.lanes[0].stopped_vm);
    assert_eq!(waiter.engine_mut().sent_names(), ["Stop"]);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    assert_eq!(report.lanes[0].problems, []);
}

#[test]
fn a_pending_layer_is_waited_for_on_the_fake_clock() {
    let mut world = World::new("layer-wait");
    crashed_at(&world, Stage::Collect, Checkpoint::Started);
    world.restart();
    let begin = world.fx.clock.now_ms();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| s.disk_layers = vec![layer(LayerPhase::Finalizing)]);
        // The engine finishes the layer five minutes after start.
        fake.after(Duration::from_secs(300), |s| s.disk_layers.clear());
    });
    let report = world.recover(&mut waiter, &Table::new());
    assert!(!report.lanes[0].layer_pending, "{:?}", report.lanes[0]);
    assert_eq!(report.lanes[0].problems, []);
    let waited = world.fx.clock.now_ms() - begin;
    assert!(
        (300_000..320_000).contains(&waited),
        "waited {waited} ms of fake time"
    );
    assert_eq!(waiter.engine_mut().sent_names(), Vec::<String>::new());
}

#[test]
fn a_layer_that_never_settles_is_reported_pending_after_layer_s() {
    let mut world = World::new("layer-stuck");
    crashed_at(&world, Stage::Collect, Checkpoint::Started);
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| s.disk_layers = vec![layer(LayerPhase::Saving)]);
    });
    let begin = world.fx.clock.now_ms();
    let options = RecoverOptions {
        layer_wait: Duration::from_secs(1800),
        ..RecoverOptions::default()
    };
    let report = recover_startup(
        &world.fx.store,
        &world.lanes,
        &mut waiter,
        &Table::new(),
        &options,
    )
    .unwrap();
    assert!(report.lanes[0].layer_pending);
    assert!(
        report.lanes[0]
            .problems
            .contains(&LaneProblem::LayerPending)
    );
    assert!(
        world.fx.clock.now_ms() - begin >= 1_800_000,
        "waited the full layer_s"
    );
    assert_eq!(
        report.lanes[0].quarantined, None,
        "a slow copier is not a fault"
    );
}

#[test]
fn a_clean_snapshot_that_is_gone_quarantines_the_lane_once_with_events() {
    let mut world = World::new("lane-changed");
    world.lanes.save(&file()).unwrap();
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.vm_snapshot_trees.get_mut(VM).unwrap().nodes[0].id = "made-by-hand".into();
        });
    });
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.lanes[0].quarantined, Some(FailureCode::LaneChanged));
    let stored = world.lanes.load(&lane()).unwrap().unwrap();
    assert!(stored.quarantine.unwrap().detail.contains(CLEAN));
    let engine_events = |world: &World| -> Vec<EventBody> {
        world
            .fx
            .store
            .events_since(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.body)
            .collect()
    };
    let events = engine_events(&world);
    assert!(events.iter().any(|e| matches!(e, EventBody::LaneState { state: LaneState::Quarantined, reason: Some(r), .. } if r == "lane_changed")));
    assert!(
        events.iter().any(
            |e| matches!(e, EventBody::EngineAlert { code, .. } if code == "lane_quarantined")
        )
    );
    // A second start does not announce it again.
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.vm_snapshot_trees.get_mut(VM).unwrap().nodes[0].id = "made-by-hand".into();
        });
    });
    world.recover(&mut waiter, &Table::new());
    assert_eq!(engine_events(&world).len(), events.len());
}

#[test]
fn a_vm_with_no_listed_snapshots_is_a_problem_but_not_a_quarantine() {
    let mut world = World::new("unverifiable");
    world.lanes.save(&file()).unwrap();
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| {
            healthy(s);
            s.vm_snapshot_trees.clear();
        });
    });
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.lanes[0].quarantined, None);
    assert!(matches!(
        report.lanes[0].problems.as_slice(),
        [LaneProblem::SnapshotMissing {
            verifiable: false,
            ..
        }]
    ));
}

#[test]
fn an_existing_quarantine_survives_recovery_untouched() {
    let mut world = World::new("stays-quarantined");
    let mut f = file();
    f.quarantine(FailureCode::RevertFailed, "restore failed twice", T0);
    f.failures = 2;
    world.lanes.save(&f).unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.lanes[0].quarantined, Some(FailureCode::RevertFailed));
    let stored = world.lanes.load(&lane()).unwrap().unwrap();
    assert_eq!(
        stored.quarantine.as_ref().unwrap().detail,
        "restore failed twice"
    );
    assert_eq!(stored.failures, 2, "a crash is not a start failure");
    assert!(
        world.fx.store.events_since(0, 100).unwrap().is_empty(),
        "nothing new to announce"
    );
}

#[test]
fn an_unreadable_lane_file_stops_that_lane_only() {
    let mut world = World::new("unreadable");
    let two = LaneId::new(2);
    let mut f2 = LaneFile::new(two.clone(), "auto-2", CLEAN, "b", T0);
    f2.begin_work(
        JobId::try_from("j_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned()).unwrap(),
        1,
        T0,
    );
    world.lanes.save(&file()).unwrap();
    world.lanes.save(&f2).unwrap();
    std::fs::write(world.lanes.path(&lane()), "{ torn").unwrap();
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.lanes.len(), 2);
    assert!(matches!(&report.lanes[0].file, FileState::Unreadable(m) if m.contains("damaged")));
    assert_eq!(report.lanes[1].file, FileState::Recovered);
    assert_eq!(
        std::fs::read_to_string(world.lanes.path(&lane())).unwrap(),
        "{ torn"
    );
}

#[test]
fn a_service_with_no_lanes_recovers_its_jobs_and_nothing_else() {
    let mut world = World::new("no-lanes");
    let job = world.fx.running(1);
    world.restart();
    let mut waiter = world.engine(|_| {});
    let report = world.recover(&mut waiter, &Table::new());
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job.id));
    assert!(report.lanes.is_empty());
}

#[test]
fn an_engine_that_dies_during_recovery_is_an_error_and_the_file_is_not_rewritten() {
    let mut world = World::new("engine-dies");
    crashed_at(&world, Stage::Run, Checkpoint::Started);
    let before = std::fs::read_to_string(world.lanes.path(&lane())).unwrap();
    world.restart();
    let mut waiter = world.engine(|fake| {
        fake.start_with(|s| {
            s.state = VmState::Running;
            s.active_vm = Some(VM.into());
        });
        fake.on("Stop").die();
    });
    let result = recover_startup(
        &world.fx.store,
        &world.lanes,
        &mut waiter,
        &Table::new(),
        &RecoverOptions {
            stop_wait: Duration::from_secs(5),
            ..RecoverOptions::default()
        },
    );
    assert!(
        matches!(result, Err(super::recover::RecoverError::Engine(_))),
        "{result:?}"
    );
    assert_eq!(
        std::fs::read_to_string(world.lanes.path(&lane())).unwrap(),
        before
    );
    // The job was put right by the store already; the next start repeats the rest.
    assert_eq!(
        world
            .job(&world.fx.store.list(&Default::default(), None).unwrap().jobs[0].id)
            .state,
        JobState::Queued
    );
}

#[test]
fn recovery_sweeps_a_temporary_file_a_killed_writer_left() {
    let mut world = World::new("sweep");
    world.lanes.save(&file()).unwrap();
    world.lanes.inject_fault(WriteFault::BeforeRename);
    assert!(world.lanes.save(&file()).is_err());
    let dir = world.lanes.dir().to_owned();
    let tmp_count = || {
        std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count()
    };
    assert_eq!(tmp_count(), 1);
    world.restart();
    let mut waiter = world.engine(|_| {});
    world.recover(&mut waiter, &Table::new());
    assert_eq!(tmp_count(), 0);
}

// ---- lane reset ---------------------------------------------------------

fn failing_lane_with_qemu(name: &str) -> LaneDir {
    let dir = LaneDir::new(&scratch(name));
    let mut f = file();
    f.failures = 2;
    f.set_qemu(QemuRecord {
        pid: 321,
        start_ticks: Some(500),
        marker: VM.into(),
        recorded_ms: T0,
    });
    dir.save(&f).unwrap();
    dir
}

#[test]
fn a_reset_clears_the_failures_and_the_record_once_qemu_is_gone() {
    use super::reset::{Cleared, clear_for_reset};
    let dir = failing_lane_with_qemu("reset-gone");
    let cleared = clear_for_reset(&dir, &lane(), &Table::new(), T0 + 5).unwrap();
    assert_eq!(
        cleared,
        Cleared {
            qemu: Some(321),
            failures: 2
        }
    );
    let f = dir.load(&lane()).unwrap().unwrap();
    assert_eq!((f.failures, f.qemu), (0, None));
    // Nothing recorded, nothing to confirm.
    assert_eq!(
        clear_for_reset(&dir, &lane(), &Table::new(), T0 + 6).unwrap(),
        Cleared {
            qemu: None,
            failures: 0
        }
    );
}

#[test]
fn a_reset_is_refused_while_the_recorded_qemu_still_runs() {
    use super::reset::{ResetRefused, clear_for_reset};
    let dir = failing_lane_with_qemu("reset-alive");
    let before = std::fs::read_to_string(dir.path(&lane())).unwrap();
    let alive = Table::new().qemu(321);
    assert!(matches!(
        clear_for_reset(&dir, &lane(), &alive, T0 + 5),
        Err(ResetRefused::QemuAlive(321))
    ));
    assert_eq!(
        std::fs::read_to_string(dir.path(&lane())).unwrap(),
        before,
        "nothing changed"
    );
    // The same pid under another start time is a different process: not ours.
    let reused = Table::new().with(
        321,
        &["qemu-system-x86_64", &format!("file=/d/vms/{VM}/disk")],
        777,
    );
    assert!(clear_for_reset(&dir, &lane(), &reused, T0 + 5).is_ok());
}

#[test]
fn a_reset_of_a_lane_with_no_file_says_so() {
    use super::reset::{ResetRefused, clear_for_reset};
    let dir = LaneDir::new(&scratch("reset-missing"));
    assert!(matches!(
        clear_for_reset(&dir, &lane(), &Table::new(), 0),
        Err(ResetRefused::State(LaneStateError::Missing(_)))
    ));
}
