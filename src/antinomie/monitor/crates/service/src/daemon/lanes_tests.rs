// SPDX-License-Identifier: GPL-3.0-only
//! Several lanes in one daemon (ANT-T0455 card C), with one `FakeEngine` per
//! lane: which lanes start (the RAM floor), the lane choice (jobs spread over
//! the free lanes, least recently used first; a lane that cannot run a job
//! leaves it to one that can; a quarantined lane holds nobody back), the
//! daemon with two and three engines (a thread, a slot and a status per
//! lane; lane commands reach the lane's own engine; every engine is handed
//! back), recovery with jobs on several lanes, and one lane as before.
use super::{
    Controls, Daemon, LaneEngine, NoSignals, Phase, Setup,
    board::{LaneBoard, LaneProfile, runs},
    lane::{JobEnd, LaneCommand, LaneLoop, LaneRunner, Periods},
    lanes::{LeftOut, lane_data_dir, lane_number, lane_options, plan_lanes},
    runner::profile_of,
};
use crate::{
    api::{
        error::ApiError,
        event::EventBody,
        ids::{JobId, LaneId},
        job::{Job, JobState, Outcome, Stage, WaitingFor},
        status::Owner,
    },
    clock::{ManualClock, SystemClock},
    config::ServiceConfig,
    engine::{FakeEngine, fake::Unscripted},
    lane::{
        LaneDir, LaneFile,
        state::{Checkpoint, LaneWork},
        tests::CLEAN,
    },
    server::{CallContext, Handler, Transport, limits::Limits, local_caller},
    stages::prechecks::lane_eligibility,
    store::{
        Eligibility, Store,
        tests::{Fx, T0},
    },
    waiter::Waiter,
};
use antinomie_monitor_core::{
    BackendOptions, BaseSummary, Command, GuestArch, Snapshot, VmConfig, VmSnapshotTree,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

const X86_BASE: &str = "base-x86";
const ARM_BASE: &str = "base-arm";

fn vm_of(n: u32) -> String {
    format!("vm-{n}")
}

fn lane_file(n: u32, base: &str) -> LaneFile {
    LaneFile::new(LaneId::new(n), &vm_of(n), CLEAN, base, T0)
}

fn base(id: &str, arch: GuestArch) -> BaseSummary {
    BaseSummary {
        id: id.into(),
        label: id.into(),
        directory: "/never/shown".into(),
        guest: None,
        min_ram_mib: 128,
        min_disk_gib: 1,
        fixed_display: false,
        arch,
        size_bytes: 1 << 20,
        revision: Some(22),
        min_app_version: None,
        built_with: None,
        stealth_support: Vec::new(),
    }
}

/// Lane `n`'s engine: its VM (stopped, with its clean snapshot) and the
/// bases. Every command it is sent is answered and logged.
fn fake(n: u32, lane_base: &str) -> FakeEngine {
    let mut fake = FakeEngine::new(Arc::new(ManualClock::new(T0)));
    let base_id = lane_base.to_owned();
    fake.start_with(move |s: &mut Snapshot| {
        s.state = antinomie_monitor_core::VmState::Stopped;
        s.vms = vec![VmConfig {
            id: vm_of(n),
            name: format!("auto-{n}"),
            base_identity: Some(base_id.clone()),
            ram_mib: 512,
            ..VmConfig::default()
        }];
        s.vm_snapshot_trees.insert(
            vm_of(n),
            VmSnapshotTree {
                vm_id: vm_of(n),
                nodes: vec![crate::lane::tests::checkpoint(CLEAN)],
                active_parent_id: None,
                recovery_note: None,
                capabilities: Default::default(),
            },
        );
        s.bases = vec![
            base(X86_BASE, GuestArch::X86_64),
            base(ARM_BASE, GuestArch::AARCH64),
        ];
    });
    fake.unscripted(Unscripted::Ok);
    fake
}

// ---- which lanes start ----------------------------------------------------

/// A data folder with lane files and lane VMs of `ram` MiB for lanes 1..=n.
fn lane_tree(name: &str, n: u32, ram: u32) -> (std::path::PathBuf, LaneDir) {
    let root = crate::store::tests::scratch(name);
    let root = std::fs::canonicalize(&root).unwrap();
    let lanes = LaneDir::new(&root.join("service"));
    for lane in 1..=n {
        let id = LaneId::new(lane);
        lanes.save(&lane_file(lane, X86_BASE)).unwrap();
        let vm_dir = lane_data_dir(&root, &id).join("vms").join(vm_of(lane));
        std::fs::create_dir_all(&vm_dir).unwrap();
        let vm = VmConfig {
            id: vm_of(lane),
            name: format!("auto-{lane}"),
            ram_mib: ram,
            ..VmConfig::default()
        };
        std::fs::write(vm_dir.join("config.json"), serde_json::to_vec(&vm).unwrap()).unwrap();
    }
    (root, lanes)
}

fn config(lanes: u32) -> ServiceConfig {
    let mut config = ServiceConfig::default();
    config.daemon.lanes = lanes;
    config
}

fn first_options(root: &Path) -> BackendOptions {
    BackendOptions {
        data_dir: root.to_path_buf(),
        ..BackendOptions::default()
    }
}

#[test]
fn lane_n_is_its_own_folder_and_engine_and_lane_1_is_the_data_folder() {
    let root = Path::new("/srv/antinomie");
    let first = first_options(root);
    assert_eq!(lane_data_dir(root, &LaneId::new(1)), root);
    assert_eq!(
        lane_data_dir(root, &LaneId::new(3)),
        root.join("lanes").join("3")
    );
    assert_eq!(lane_number(&LaneId::new(4)), Some(4));
    let three = lane_options(&first, &LaneId::new(3));
    assert_eq!(three.data_dir, root.join("lanes").join("3"));
    assert_eq!(three.shared_root.as_deref(), Some(root));
    assert_eq!(three.owner.lane, Some(3));
    let one = lane_options(&first, &LaneId::new(1));
    assert_eq!(
        (one.data_dir, one.shared_root, one.owner.lane),
        (root.to_path_buf(), None, None)
    );
}

#[test]
fn every_lane_starts_when_the_ram_floor_of_every_lane_is_met() {
    let (root, lanes) = lane_tree("lanes-plan-all", 3, 512);
    // 3 x 512 MiB of lane VMs plus the last lane's 2048 MiB of headroom.
    let plan = plan_lanes(&config(3), &first_options(&root), &lanes, Some(3584));
    let started: Vec<&str> = plan.start.iter().map(|l| l.lane.as_str()).collect();
    assert_eq!(started, ["lane-1", "lane-2", "lane-3"]);
    assert!(plan.left.is_empty(), "{:?}", plan.left);
    assert_eq!(plan.start[2].options.data_dir, root.join("lanes").join("3"));
    assert_eq!(plan.start[2].ram_mib, Some(512));
    assert_eq!(
        plan.summary(3),
        "lanes: 3 of 3 started (lane-1, lane-2, lane-3)"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn lanes_beyond_the_ram_floor_are_refused_and_named_with_the_reason() {
    let (root, lanes) = lane_tree("lanes-plan-ram", 3, 512);
    // Lane 2 needs 512 + 512 + 2048 = 3072 MiB; 3000 are available.
    let plan = plan_lanes(&config(3), &first_options(&root), &lanes, Some(3000));
    let started: Vec<&str> = plan.start.iter().map(|l| l.lane.as_str()).collect();
    assert_eq!(started, ["lane-1"]);
    assert_eq!(plan.left.len(), 2);
    assert_eq!(plan.left[0].lane, LaneId::new(2));
    assert!(
        plan.left[0].reason.contains("RAM floor")
            && plan.left[0].reason.contains("3072 MiB")
            && plan.left[0].reason.contains("3000 MiB"),
        "{}",
        plan.left[0].reason
    );
    assert!(plan.left[1].reason.contains("lanes start in order"));
    let summary = plan.summary(3);
    assert!(
        summary.starts_with("lanes: 1 of 3 started (lane-1); lane-2 not started: the RAM floor")
    );
    // With room for two, the third is refused.
    let plan = plan_lanes(&config(3), &first_options(&root), &lanes, Some(3100));
    assert_eq!(plan.start.len(), 2);
    assert_eq!(plan.left[0].lane, LaneId::new(3));
    // A configured floor replaces each lane's own (VM RAM + 2048).
    let mut floor = config(3);
    floor.resources.min_free_ram_mib = Some(1024);
    let plan = plan_lanes(&floor, &first_options(&root), &lanes, Some(2048));
    assert_eq!(plan.start.len(), 3, "{:?}", plan.left);
    // MemAvailable that cannot be read starts lane 1 only.
    let plan = plan_lanes(&config(2), &first_options(&root), &lanes, None);
    assert_eq!(plan.start.len(), 1);
    assert!(plan.left[0].reason.contains("MemAvailable"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_lane_without_a_lane_vm_is_left_out_with_the_command_that_makes_it() {
    let (root, lanes) = lane_tree("lanes-plan-missing", 1, 512);
    // Lane 3 exists, lane 2 was never made.
    lanes.save(&lane_file(3, X86_BASE)).unwrap();
    let vm_dir = root.join("lanes").join("3").join(vm_of(3));
    std::fs::create_dir_all(&vm_dir).unwrap();
    let vm = VmConfig {
        id: vm_of(3),
        ram_mib: 256,
        ..VmConfig::default()
    };
    std::fs::write(vm_dir.join("config.json"), serde_json::to_vec(&vm).unwrap()).unwrap();
    let plan = plan_lanes(&config(3), &first_options(&root), &lanes, Some(16_000));
    let started: Vec<&str> = plan.start.iter().map(|l| l.lane.as_str()).collect();
    assert_eq!(started, ["lane-1", "lane-3"]);
    assert_eq!(
        plan.left,
        [LeftOut {
            lane: LaneId::new(2),
            reason: "it has no lane VM; run `antinomie-cli auto init --lane 2`".into(),
        }]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn one_lane_starts_only_lane_1_whatever_lane_files_exist() {
    let (root, lanes) = lane_tree("lanes-plan-one", 3, 512);
    let plan = plan_lanes(&config(1), &first_options(&root), &lanes, Some(64_000));
    assert_eq!(plan.start.len(), 1);
    assert_eq!(plan.start[0].lane, LaneId::new(1));
    assert_eq!(plan.start[0].options.data_dir, root);
    assert!(plan.left.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

// ---- the lane choice ------------------------------------------------------

/// A fixture whose policy also accepts shell scripts (sample 20); the
/// shipped policy takes ELF files only.
fn scripts_too(name: &str) -> Fx {
    Fx::with_policy(name, |policy| policy.sample.accept_types.push("sh".into()))
}

fn profile(n: u32, base_id: &str, arch: GuestArch) -> LaneProfile {
    LaneProfile {
        vm_id: vm_of(n),
        vm_name: Some(format!("auto-{n}")),
        base_identity: base_id.into(),
        arch: Some(arch),
    }
}

#[test]
fn a_guest_runs_the_programs_of_its_architecture() {
    assert!(runs(GuestArch::X86_64, "x86_64") && runs(GuestArch::X86_64, "x86"));
    assert!(runs(GuestArch::AARCH64, "AArch64") && runs(GuestArch::AARCH64, "ARM"));
    assert!(!runs(GuestArch::X86_64, "AArch64") && !runs(GuestArch::AARCH64, "x86_64"));
}

#[test]
fn the_least_recently_used_free_lane_takes_the_job_and_a_busy_one_waits() {
    let fx = Fx::new("lanes-board-lru");
    let job = fx.queued(1);
    let board = LaneBoard::default();
    let (tx, rx) = mpsc::channel();
    for n in 1..=3 {
        board.join(&LaneId::new(n), tx.clone());
        board.post(
            &LaneId::new(n),
            Eligibility::Ready,
            Some(profile(n, X86_BASE, GuestArch::X86_64)),
            1_000,
        );
    }
    // All free and never used: lane 1 first; the others leave it to lane 1.
    assert_eq!(
        board.decide(&LaneId::new(1), &job, None, 1_000),
        Eligibility::Ready
    );
    assert_eq!(
        board.decide(&LaneId::new(3), &job, None, 1_000),
        Eligibility::Skip
    );
    assert!(
        rx.try_recv().is_ok(),
        "the lane the job is left for is woken"
    );
    board.claimed(&LaneId::new(1), 1_001);
    board.claimed(&LaneId::new(2), 1_002);
    // Lane 1 is free again but was used before lane 2: lane 3 (never used)
    // goes first, then lane 1.
    board.post(
        &LaneId::new(1),
        Eligibility::Ready,
        Some(profile(1, X86_BASE, GuestArch::X86_64)),
        1_100,
    );
    assert_eq!(
        board.decide(&LaneId::new(1), &job, None, 1_100),
        Eligibility::Skip
    );
    assert_eq!(
        board.decide(&LaneId::new(3), &job, None, 1_100),
        Eligibility::Ready
    );
    board.claimed(&LaneId::new(3), 1_101);
    assert_eq!(
        board.decide(&LaneId::new(1), &job, None, 1_200),
        Eligibility::Ready
    );
    // A post older than the freshness window holds nobody back.
    board.post(&LaneId::new(2), Eligibility::Ready, None, 1_000);
    board.post(&LaneId::new(3), Eligibility::Ready, None, 1_000);
    assert_eq!(
        board.decide(
            &LaneId::new(1),
            &job,
            None,
            1_000 + super::board::FRESH_MS + 1
        ),
        Eligibility::Ready
    );
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn a_lane_that_cannot_run_the_job_leaves_it_to_one_that_can() {
    let fx = scripts_too("lanes-board-fit");
    // Sample 1 is an x86-64 ELF, sample 20 a shell script.
    let elf = fx.queued(1);
    let script = fx.queued(20);
    let board = LaneBoard::default();
    let (tx, _rx) = mpsc::channel();
    let (x86, arm) = (LaneId::new(1), LaneId::new(2));
    board.join(&x86, tx.clone());
    board.join(&arm, tx);
    board.post(
        &x86,
        Eligibility::Wait(WaitingFor::Lane),
        Some(profile(1, X86_BASE, GuestArch::X86_64)),
        10,
    );
    board.post(
        &arm,
        Eligibility::Ready,
        Some(profile(2, ARM_BASE, GuestArch::AARCH64)),
        10,
    );
    // The free arm64 lane does not take the ELF: it waits for the x86 lane.
    assert_eq!(
        board.decide(&arm, &elf, None, 10),
        Eligibility::Wait(WaitingFor::Lane)
    );
    assert_eq!(board.decide(&arm, &script, None, 10), Eligibility::Ready);
    // The policy's lane VM names lane 1's VM: its base decides, so the
    // arm64 lane does not take the script either.
    assert_eq!(
        board.decide(&arm, &script, Some("auto-1"), 10),
        Eligibility::Wait(WaitingFor::Lane)
    );
    // A lane VM that is none of the lanes' imposes nothing.
    assert_eq!(
        board.decide(&arm, &script, Some("elsewhere"), 10),
        Eligibility::Ready
    );
    // A job no lane can run is taken as with one lane (the run says why).
    let fx2 = Fx::new("lanes-board-none");
    let lonely = LaneBoard::default();
    let (tx, _rx2) = mpsc::channel();
    lonely.join(&arm, tx);
    lonely.post(
        &arm,
        Eligibility::Ready,
        Some(profile(2, ARM_BASE, GuestArch::AARCH64)),
        10,
    );
    assert_eq!(
        lonely.decide(&arm, &fx2.queued(1), None, 10),
        Eligibility::Ready
    );
    let _ = std::fs::remove_dir_all(&fx.dir);
    let _ = std::fs::remove_dir_all(&fx2.dir);
}

#[test]
fn when_no_lane_is_free_the_first_lane_writes_the_least_lasting_reason() {
    let board = LaneBoard::default();
    let (tx, _rx) = mpsc::channel();
    for n in 1..=3 {
        board.join(&LaneId::new(n), tx.clone());
    }
    board.post(
        &LaneId::new(1),
        Eligibility::Wait(WaitingFor::LaneQuarantined),
        None,
        10,
    );
    board.post(
        &LaneId::new(2),
        Eligibility::Wait(WaitingFor::Lane),
        None,
        10,
    );
    board.post(
        &LaneId::new(3),
        Eligibility::Wait(WaitingFor::Resources),
        None,
        10,
    );
    assert_eq!(
        board.report(&LaneId::new(1), WaitingFor::LaneQuarantined, 10),
        Some(WaitingFor::Lane)
    );
    assert_eq!(board.report(&LaneId::new(2), WaitingFor::Lane, 10), None);
    // A free lane writes nothing for the others.
    board.post(&LaneId::new(3), Eligibility::Ready, None, 10);
    assert_eq!(
        board.report(&LaneId::new(1), WaitingFor::LaneQuarantined, 10),
        None
    );
}

// ---- lane loops on their own engines -------------------------------------

/// A lane on its own `FakeEngine`: the real lane eligibility (its file and
/// its engine's snapshot) and profile; a job is one command to its engine,
/// held for `hold`, then ended.
struct EngineLane<'a> {
    lane: LaneId,
    waiter: Waiter<FakeEngine>,
    lanes: &'a LaneDir,
    store: &'a Store,
    hold: Duration,
    ran: &'a Mutex<Vec<(LaneId, JobId)>>,
    lane_vm: Option<String>,
}

impl LaneRunner for EngineLane<'_> {
    fn tick(&mut self) -> Result<(), String> {
        self.waiter.drain().map_err(|e| e.to_string())
    }
    fn eligibility(&mut self) -> Eligibility {
        match self.lanes.load(&self.lane) {
            Ok(Some(file)) => lane_eligibility(&file, self.waiter.snapshot()),
            _ => Eligibility::Wait(WaitingFor::Lane),
        }
    }
    fn run_job(&mut self, job: &Job, _: &mut dyn FnMut()) -> JobEnd {
        let vm_id = self.lanes.load(&self.lane).unwrap().unwrap().vm_id;
        self.lanes
            .update(&self.lane, |f| f.begin_work(job.id.clone(), job.attempt, 1))
            .unwrap();
        self.ran
            .lock()
            .unwrap()
            .push((self.lane.clone(), job.id.clone()));
        self.waiter
            .command(Command::Start { vm_id }, Some(Duration::from_secs(5)))
            .unwrap();
        std::thread::sleep(self.hold);
        self.lanes.update(&self.lane, |f| f.end_work(2)).unwrap();
        self.store
            .finish(&job.id, Outcome::Succeeded, None)
            .unwrap();
        JobEnd::Done
    }
    fn resume(&mut self, _: &Job) -> JobEnd {
        JobEnd::Done
    }
    fn govern(&mut self, _: u64) {}
    fn command(&mut self, op: &str, _: Value) -> Result<Value, ApiError> {
        Ok(json!({ "op": op }))
    }
    fn profile(&mut self) -> Option<LaneProfile> {
        profile_of(self.lanes, &self.lane, self.waiter.snapshot())
    }
    fn lane_vm(&self, _: &Job) -> Option<String> {
        self.lane_vm.clone()
    }
}

/// `n` lanes, each a loop on its own engine (`bases[i]` is lane i+1's base),
/// over `fx`'s store. `body` runs while the loops run, with the board (to
/// wake them) and the log of which lane ran which job.
fn with_lanes(
    fx: &Fx,
    bases: &[&str],
    hold: Duration,
    lane_vm: Option<&str>,
    body: impl FnOnce(&LaneBoard, &Mutex<Vec<(LaneId, JobId)>>),
) -> (Vec<(LaneId, JobId)>, Vec<Vec<String>>) {
    let lanes = LaneDir::new(&fx.dir.join("service"));
    let board = LaneBoard::default();
    let controls = Controls::default();
    let ran = Mutex::new(Vec::new());
    let mut sent = Vec::new();
    let mut parts = Vec::new();
    for (index, base_id) in bases.iter().enumerate() {
        let n = index as u32 + 1;
        if lanes.load(&LaneId::new(n)).unwrap().is_none() {
            lanes.save(&lane_file(n, base_id)).unwrap();
        }
        let engine = fake(n, base_id);
        sent.push(engine.sent_log());
        let mut waiter = Waiter::new(engine, Arc::new(ManualClock::new(T0)));
        waiter.first_snapshot(Duration::from_secs(1)).unwrap();
        let (wake_tx, wake_rx) = mpsc::channel();
        let (_commands_tx, commands_rx) = mpsc::channel::<LaneCommand>();
        board.join(&LaneId::new(n), wake_tx);
        parts.push((n, waiter, wake_rx, commands_rx, _commands_tx));
    }
    std::thread::scope(|scope| {
        for (n, waiter, wake_rx, commands_rx, commands_tx) in parts {
            let (lanes, board, controls, ran, store) = (&lanes, &board, &controls, &ran, &fx.store);
            let lane_vm = lane_vm.map(str::to_owned);
            scope.spawn(move || {
                let _keep = commands_tx;
                let phase = Mutex::new(Phase::Idle);
                let mut janitor = || {};
                let log = |_: &str| {};
                let mut runner = EngineLane {
                    lane: LaneId::new(n),
                    waiter,
                    lanes,
                    store,
                    hold,
                    ran,
                    lane_vm,
                };
                let mut lane_loop = LaneLoop {
                    lane: LaneId::new(n),
                    store,
                    controls,
                    phase: &phase,
                    wake: &wake_rx,
                    commands: &commands_rx,
                    clock: Arc::new(SystemClock),
                    periods: Periods {
                        idle_wait: Duration::from_millis(20),
                        ..Periods::default()
                    },
                    janitor: &mut janitor,
                    log: &log,
                    board: Some(board),
                    upkeep: n == 1,
                };
                lane_loop.run(&mut runner, &[]);
                board.leave(&LaneId::new(n));
            });
        }
        // Every lane has posted at least once before the jobs come.
        std::thread::sleep(Duration::from_millis(200));
        // A failed check still stops the lanes, so the test fails instead of
        // waiting for their threads.
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&board, &ran)));
        controls.begin_stop();
        board.wake_all();
        if let Err(panic) = checked {
            std::panic::resume_unwind(panic);
        }
    });
    let sent = sent
        .iter()
        .map(|log| log.lock().unwrap().iter().map(|s| s.name.clone()).collect())
        .collect();
    (ran.into_inner().unwrap(), sent)
}

fn until(what: &str, done: impl Fn() -> bool) {
    let began = Instant::now();
    while !done() {
        assert!(
            began.elapsed() < Duration::from_secs(60),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn all_done(fx: &Fx, jobs: &[Job]) -> bool {
    jobs.iter()
        .all(|job| fx.store.get(&job.id).unwrap().state == JobState::Succeeded)
}

fn spread(lanes: u32) {
    let fx = Fx::new(&format!("lanes-spread-{lanes}"));
    let bases = vec![X86_BASE; lanes as usize];
    let (ran, sent) = with_lanes(
        &fx,
        &bases,
        Duration::from_millis(300),
        None,
        |board, ran| {
            // As many jobs at once as there are lanes: each goes to another lane.
            let burst: Vec<Job> = (1..=lanes as u8).map(|n| fx.queued(n)).collect();
            board.wake_all();
            until("the burst", || all_done(&fx, &burst));
            let first: Vec<LaneId> = ran.lock().unwrap().iter().map(|(l, _)| l.clone()).collect();
            let mut distinct = first.clone();
            distinct.sort();
            distinct.dedup();
            assert_eq!(distinct.len(), lanes as usize, "{first:?}");
            // One job at a time: the least recently used lane takes each, so
            // they go round the lanes.
            for n in 0..2 * lanes {
                let job = fx.queued(1 + (n % 9) as u8);
                board.wake_all();
                until("one job", || all_done(&fx, std::slice::from_ref(&job)));
            }
        },
    );
    let order: Vec<&LaneId> = ran.iter().skip(lanes as usize).map(|(l, _)| l).collect();
    for window in order.windows(lanes as usize) {
        let mut seen: Vec<&LaneId> = window.to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), lanes as usize, "not round the lanes: {order:?}");
    }
    // Each job's command went to the engine of the lane that ran it.
    for (index, log) in sent.iter().enumerate() {
        let lane = LaneId::new(index as u32 + 1);
        let jobs = ran.iter().filter(|(l, _)| *l == lane).count();
        let starts = log.iter().filter(|name| *name == "Start").count();
        assert_eq!(starts, jobs, "{lane}");
        assert_eq!(jobs, 3, "{lane} ran {jobs} of {} jobs: {ran:?}", ran.len());
    }
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn jobs_spread_over_two_lanes_on_their_own_engines() {
    spread(2);
}

#[test]
fn jobs_spread_over_three_lanes_on_their_own_engines() {
    spread(3);
}

#[test]
fn a_quarantined_lane_takes_nothing_and_the_others_go_on() {
    let fx = Fx::new("lanes-quarantine-3");
    let lanes = LaneDir::new(&fx.dir.join("service"));
    let mut two = lane_file(2, X86_BASE);
    two.quarantine(
        crate::api::failure::FailureCode::RevertFailed,
        "the revert failed twice",
        T0,
    );
    lanes.save(&two).unwrap();
    let (ran, _) = with_lanes(
        &fx,
        &[X86_BASE, X86_BASE, X86_BASE],
        Duration::from_millis(100),
        None,
        |board, _| {
            let batch: Vec<Job> = (1..=6).map(|n| fx.queued(n)).collect();
            board.wake_all();
            until("every job", || all_done(&fx, &batch));
        },
    );
    assert_eq!(ran.len(), 6);
    assert!(
        ran.iter().all(|(lane, _)| *lane != LaneId::new(2)),
        "{ran:?}"
    );
    for lane in [1, 3] {
        assert!(
            ran.iter().any(|(l, _)| *l == LaneId::new(lane)),
            "{lane}: {ran:?}"
        );
    }
    // The quarantine of one lane is never what a job is said to wait for
    // while another lane can take it.
    let quarantined = fx
        .store
        .events_since(0, 10_000)
        .unwrap()
        .into_iter()
        .any(|event| {
            matches!(
                event.body,
                EventBody::JobState {
                    waiting_for: Some(WaitingFor::LaneQuarantined),
                    ..
                }
            )
        });
    assert!(!quarantined);
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn an_arm64_lane_leaves_x86_programs_to_the_x86_lane_and_takes_the_scripts() {
    let fx = scripts_too("lanes-fit-2");
    let (ran, _) = with_lanes(
        &fx,
        &[X86_BASE, ARM_BASE],
        Duration::from_millis(150),
        None,
        |board, _| {
            let mut batch: Vec<Job> = (1..=4).map(|n| fx.queued(n)).collect();
            batch.push(fx.queued(20));
            batch.push(fx.queued(20));
            board.wake_all();
            until("every job", || all_done(&fx, &batch));
        },
    );
    let elves: Vec<&(LaneId, JobId)> = ran
        .iter()
        .filter(|(_, id)| {
            fx.store
                .get(id)
                .unwrap()
                .sample
                .is_some_and(|s| s.architecture.is_some())
        })
        .collect();
    assert_eq!(elves.len(), 4);
    assert!(
        elves.iter().all(|(lane, _)| *lane == LaneId::new(1)),
        "{ran:?}"
    );
    assert!(
        ran.iter().any(|(lane, _)| *lane == LaneId::new(2)),
        "{ran:?}"
    );
    let _ = std::fs::remove_dir_all(&fx.dir);
}

// ---- the daemon with several engines --------------------------------------

/// The commands a fake engine was sent.
type SentLog = Arc<Mutex<Vec<crate::engine::fake::Sent>>>;

struct Rig {
    fx: Fx,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Rig {
    fn new(name: &str) -> Self {
        Self {
            fx: Fx::new(name),
            lines: Arc::default(),
        }
    }

    fn setup(&self, lanes: u32) -> Setup {
        let mut config = config(lanes);
        // No job is started: the tests look at the lanes, not at runs.
        config.queue.paused_on_start = true;
        let lines = Arc::clone(&self.lines);
        Setup {
            options: first_options(&self.fx.dir),
            config,
            socket: None,
            owner: Owner::Daemon,
            host_grace: Duration::from_secs(5),
            limits: Limits::default(),
            log: Arc::new(move |line: &str| lines.lock().unwrap().push(line.to_owned())),
        }
    }

    fn engines(&self, n: u32) -> (Vec<LaneEngine<FakeEngine>>, Vec<SentLog>) {
        let first = first_options(&self.fx.dir);
        let mut engines = Vec::new();
        let mut logs = Vec::new();
        for lane in 1..=n {
            let engine = fake(lane, X86_BASE);
            logs.push(engine.sent_log());
            engines.push(LaneEngine {
                lane: LaneId::new(lane),
                options: lane_options(&first, &LaneId::new(lane)),
                engine,
            });
        }
        (engines, logs)
    }

    fn log_has(&self, text: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(text))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.fx.dir);
    }
}

fn op(daemon: &Daemon<FakeEngine>, name: &str, params: Value) -> Result<Value, ApiError> {
    let ctx = CallContext {
        caller: local_caller(rustix::process::geteuid().as_raw()),
        cancel: Default::default(),
        transport: Transport::Socket,
    };
    daemon.service().call(name, params, &ctx)
}

fn stop(mut daemon: Daemon<FakeEngine>) -> Vec<(LaneId, FakeEngine)> {
    daemon.supervise(&NoSignals, &|_| true);
    daemon.finish_lanes().unwrap()
}

fn several_engines(n: u32) {
    let rig = Rig::new(&format!("lanes-daemon-{n}"));
    let lanes = LaneDir::new(&rig.fx.dir.join("service"));
    for lane in 1..=n {
        lanes.save(&lane_file(lane, X86_BASE)).unwrap();
    }
    let mut two = lane_file(2, X86_BASE);
    two.quarantine(
        crate::api::failure::FailureCode::LaneChanged,
        "used by hand",
        T0,
    );
    lanes.save(&two).unwrap();
    let (engines, logs) = rig.engines(n);
    let daemon = Daemon::start_lanes(rig.setup(n), engines, Vec::new()).unwrap();
    let service = Arc::clone(daemon.service());
    assert_eq!(service.slots.len(), n as usize);
    assert!(rig.log_has(&format!("lanes: {n} of {n} started")));
    assert_eq!(
        op(&daemon, "capabilities", json!({})).unwrap()["lanes"],
        json!(n)
    );
    let status = op(&daemon, "queue.status", json!({})).unwrap();
    assert_eq!(status["limits"]["max_concurrent"], json!(n));
    let states: Vec<(String, String, String)> = status["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["lane"].as_str().unwrap().to_owned(),
                l["state"].as_str().unwrap().to_owned(),
                l["vm_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(states.len(), n as usize);
    assert_eq!(
        states[1],
        ("lane-2".into(), "quarantined".into(), "vm-2".into())
    );
    for (index, (lane, state, vm)) in states.iter().enumerate() {
        assert_eq!(*lane, format!("lane-{}", index + 1));
        assert_eq!(*vm, vm_of(index as u32 + 1));
        if index != 1 {
            assert_eq!(state, "idle");
        }
    }
    // One quarantined lane of several keeps the node ready.
    let health = op(&daemon, "health", json!({})).unwrap();
    assert!(
        !health["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().contains("quarantined")),
        "{health}"
    );
    // Each lane is checked against its own engine: every lane's VM is found.
    let list = op(&daemon, "lane.list", json!({})).unwrap();
    for lane in list.as_array().unwrap() {
        assert_eq!(lane["problems"], json!([]), "{lane}");
        assert!(lane["vm_name"].as_str().unwrap().starts_with("auto-"));
    }
    // vm.list has every lane's VM with its lane.
    let vms = op(&daemon, "vm.list", json!({})).unwrap();
    assert_eq!(vms["vms"].as_array().unwrap().len(), n as usize);
    assert_eq!(vms["vms"][1]["lane"], json!("lane-2"));
    // `lane.unquarantine` of lane 2 runs on lane 2's engine only.
    let lifted = op(&daemon, "lane.unquarantine", json!({"lane": "lane-2"})).unwrap();
    assert_eq!(lifted["quarantine"], Value::Null, "{lifted}");
    assert!(
        !lanes
            .load(&LaneId::new(2))
            .unwrap()
            .unwrap()
            .is_quarantined()
    );
    // A lane that does not run here is named.
    let error = op(&daemon, "lane.reset", json!({"lane": "lane-4"})).unwrap_err();
    assert!(
        error.message.contains("lane-4 does not run in this daemon"),
        "{}",
        error.message
    );
    let engines = stop(daemon);
    let names: Vec<&str> = engines.iter().map(|(l, _)| l.as_str()).collect();
    let expected: Vec<String> = (1..=n).map(|l| format!("lane-{l}")).collect();
    assert_eq!(names, expected);
    for (index, log) in logs.iter().enumerate() {
        let refreshes = log
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.name == "RefreshVmSnapshots")
            .count();
        assert_eq!(refreshes, usize::from(index == 1), "lane-{}", index + 1);
    }
}

#[test]
fn a_daemon_with_two_engines_runs_and_shows_two_lanes() {
    several_engines(2);
}

#[test]
fn a_daemon_with_three_engines_runs_and_shows_three_lanes() {
    several_engines(3);
}

#[test]
fn lanes_left_out_at_start_are_shown_with_their_reason() {
    let rig = Rig::new("lanes-daemon-left");
    let lanes = LaneDir::new(&rig.fx.dir.join("service"));
    for lane in 1..=3 {
        lanes.save(&lane_file(lane, X86_BASE)).unwrap();
    }
    let (mut engines, _) = rig.engines(2);
    engines.truncate(2);
    let left = vec![LeftOut {
        lane: LaneId::new(3),
        reason: "the RAM floor is not met".into(),
    }];
    let daemon = Daemon::start_lanes(rig.setup(3), engines, left).unwrap();
    assert!(
        rig.log_has("lanes: 2 of 3 started (lane-1, lane-2); lane-3 not started: the RAM floor")
    );
    let list = op(&daemon, "lane.list", json!({})).unwrap();
    assert_eq!(
        list[2]["problems"],
        json!(["not started: the RAM floor is not met"])
    );
    let status = op(&daemon, "queue.status", json!({})).unwrap();
    assert_eq!(status["lanes"][2]["state"], json!("stopped"));
    let error = op(&daemon, "lane.unquarantine", json!({"lane": "lane-3"})).unwrap_err();
    assert!(error.message.contains("the RAM floor"), "{}", error.message);
    stop(daemon);
}

/// A job claimed by `lane` and brought to `stage`.
fn on_lane(fx: &Fx, n: u8, lane: u32, stage: Stage) -> Job {
    fx.clock.advance(1);
    let queued = fx.queued(n);
    let job = fx
        .store
        .claim_next(&LaneId::new(lane), &mut |job| {
            if job.id == queued.id {
                Eligibility::Ready
            } else {
                Eligibility::Skip
            }
        })
        .unwrap()
        .unwrap();
    assert_eq!(job.id, queued.id);
    fx.store.begin_stage(&job.id, stage).unwrap();
    fx.store.get(&job.id).unwrap()
}

#[test]
fn recovery_puts_every_lanes_jobs_back_and_resumes_the_collected_ones_in_arrival_order() {
    let rig = Rig::new("lanes-daemon-recover");
    let fx = &rig.fx;
    let lanes = LaneDir::new(&fx.dir.join("service"));
    // Collected first on lane 3, then on lane 1; a job interrupted in its run
    // on lane 2; a job interrupted on lane 4, which does not start.
    let older = on_lane(fx, 1, 3, Stage::Collect);
    let newer = on_lane(fx, 2, 1, Stage::Collect);
    let interrupted = on_lane(fx, 3, 2, Stage::Run);
    let stranded = on_lane(fx, 4, 4, Stage::Run);
    for (lane, collected) in [(1, Some(&newer)), (2, None), (3, Some(&older)), (4, None)] {
        let mut file = lane_file(lane, X86_BASE);
        if let Some(job) = collected {
            file.begin_work(job.id.clone(), job.attempt, T0);
            file.collected(T0 + 1);
        }
        lanes.save(&file).unwrap();
    }
    for (lane, job) in [(2, &interrupted), (4, &stranded)] {
        lanes
            .update(&LaneId::new(lane), |file| {
                file.current = Some(LaneWork {
                    job_id: job.id.clone(),
                    attempt: job.attempt,
                    stage: Stage::Run,
                    checkpoint: Checkpoint::Started,
                    updated_ms: T0,
                });
            })
            .unwrap();
    }
    let (engines, _) = rig.engines(3);
    let left = vec![LeftOut {
        lane: LaneId::new(4),
        reason: "the RAM floor is not met".into(),
    }];
    let daemon = Daemon::start_lanes(rig.setup(4), engines, left).unwrap();
    // The interrupted jobs are queued again, whatever lane had them, and
    // every lane file is without the dead process's work.
    for job in [&interrupted, &stranded] {
        assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Queued);
    }
    for lane in 1..=4 {
        assert_eq!(
            lanes.load(&LaneId::new(lane)).unwrap().unwrap().current,
            None,
            "lane-{lane}"
        );
    }
    // The collected jobs go back to the one host work pool in the order
    // they arrived (lane 3's first), not lane by lane.
    until("both jobs to resume", || {
        rig.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains("resuming in the host pool"))
            .count()
            == 2
    });
    let resumed: Vec<String> = rig
        .lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("resuming in the host pool"))
        .cloned()
        .collect();
    assert!(resumed[0].contains(older.id.as_str()), "{resumed:?}");
    assert!(resumed[1].contains(newer.id.as_str()), "{resumed:?}");
    assert!(rig.log_has("recovery: 2 job(s) back in the queue, 2 to resume at analyse"));
    stop(daemon);
}

#[test]
fn one_lane_runs_as_before_beside_the_files_of_other_lanes() {
    let rig = Rig::new("lanes-daemon-one");
    let lanes = LaneDir::new(&rig.fx.dir.join("service"));
    for lane in 1..=2 {
        lanes.save(&lane_file(lane, X86_BASE)).unwrap();
    }
    let (mut engines, _) = rig.engines(1);
    let engine = engines.remove(0).engine;
    let daemon = Daemon::start(rig.setup(1), engine).unwrap();
    assert_eq!(daemon.service().slots.len(), 1);
    assert!(!rig.log_has("lanes:"), "one lane says nothing new");
    assert_eq!(
        op(&daemon, "capabilities", json!({})).unwrap()["lanes"],
        json!(1)
    );
    let status = op(&daemon, "queue.status", json!({})).unwrap();
    assert_eq!(status["limits"]["max_concurrent"], json!(1));
    assert_eq!(status["lanes"][0]["state"], json!("idle"));
    assert_eq!(status["lanes"][1]["state"], json!("stopped"));
    let list = op(&daemon, "lane.list", json!({})).unwrap();
    assert_eq!(list[0]["problems"], json!([]));
    assert_eq!(
        list[1]["problems"],
        json!(["not started: beyond daemon.lanes"])
    );
    let engines = stop(daemon);
    assert_eq!(engines.len(), 1);
}
