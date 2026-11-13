// SPDX-License-Identifier: GPL-3.0-only
//! Resource floors and the queue pause (card P3-5c) with injected probes.
use crate::{
    api::{
        event::EventBody,
        failure::FailureCode,
        run::{EndReason, Outcome, Run, RunState, WaitingFor},
        status::PauseReason,
    },
    config::{Preset, service::Resources},
    lane::tests::VM,
    resources::{Floors, Governor, LOW_MEMORY_ALERT_EVERY_MS, Probes, ResourceChecks, Shortage},
    stages::{
        Driven, HostChecks, HostProblem,
        run_tests::{execute_run, stop_ok, stop_run_ok},
        tests::{SECOND, W, restore_ok, upload_ok},
    },
    store::{
        Eligibility,
        tests::{Fx, lane, manager},
    },
};
use antinomie_monitor_core::{
    VmState,
    disk_layers::{DiskLayer, LayerPhase},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Probes the test moves.
#[derive(Default)]
struct Machine {
    mem_mib: Mutex<Option<u64>>,
    free_gib: Mutex<std::collections::BTreeMap<PathBuf, u64>>,
    kvm: AtomicBool,
    pause_file: AtomicBool,
}

impl Machine {
    fn healthy() -> Arc<Self> {
        let machine = Arc::new(Self::default());
        *machine.mem_mib.lock().unwrap() = Some(16_384);
        machine.free_gib.lock().unwrap().insert("/data".into(), 500);
        machine.free_gib.lock().unwrap().insert("/rec".into(), 500);
        machine.kvm.store(true, Ordering::SeqCst);
        machine
    }

    fn disk(&self, path: &str, gib: u64) {
        self.free_gib.lock().unwrap().insert(path.into(), gib);
    }
}

impl Probes for Arc<Machine> {
    fn mem_available_mib(&self) -> Option<u64> {
        *self.mem_mib.lock().unwrap()
    }
    fn free_gib(&self, path: &Path) -> Option<u64> {
        self.free_gib.lock().unwrap().get(path).copied()
    }
    fn kvm_usable(&self) -> bool {
        self.kvm.load(Ordering::SeqCst)
    }
    fn pause_file(&self) -> bool {
        self.pause_file.load(Ordering::SeqCst)
    }
}

fn floors(require_kvm: bool) -> Floors {
    Floors::of(
        &Resources {
            min_free_disk_gib: 20,
            min_free_ram_mib: None,
            require_kvm,
        },
        1024,
        vec!["/data".into(), "/rec".into()],
        4 << 30,
    )
}

fn checks(machine: &Arc<Machine>, require_kvm: bool) -> ResourceChecks<'static> {
    // The probes live as long as the test: leak the Arc for a 'static borrow.
    let probes: &'static Arc<Machine> = Box::leak(Box::new(machine.clone()));
    ResourceChecks {
        floors: floors(require_kvm),
        probes,
    }
}

fn job(fx: &Fx) -> Run {
    fx.queued(1)
}

fn wait_of(result: Result<(), HostProblem>) -> (WaitingFor, String) {
    match result {
        Err(HostProblem::Wait(why, text)) => (why, text),
        other => panic!("{other:?}"),
    }
}

// ---- the floors ---------------------------------------------------------

#[test]
fn the_floors_come_from_the_configuration_and_the_lane_vm() {
    let f = floors(true);
    assert_eq!(
        f.min_free_ram_mib,
        1024 + 2048,
        "the VM's RAM plus 2048 MiB"
    );
    assert_eq!(
        (f.min_free_disk_gib, f.quota_gib, f.vm_ram_mib),
        (20, 4, 1024)
    );
    let own = Floors::of(
        &Resources {
            min_free_disk_gib: 5,
            min_free_ram_mib: Some(8000),
            require_kvm: false,
        },
        4096,
        Vec::new(),
        (3 << 30) + 1,
    );
    assert_eq!(
        (own.min_free_ram_mib, own.quota_gib),
        (8000, 4),
        "rounded up"
    );
}

#[test]
fn memory_below_the_floor_makes_a_job_wait_for_resources() {
    let machine = Machine::healthy();
    let fx = Fx::new("res-mem");
    let job = job(&fx);
    let policy = Preset::default();
    let c = checks(&machine, true);
    assert_eq!(c.check(&job, &policy), Ok(()));
    *machine.mem_mib.lock().unwrap() = Some(3071);
    let (why, text) = wait_of(c.check(&job, &policy));
    assert_eq!(why, WaitingFor::Resources);
    assert!(text.contains("3071") && text.contains("3072"), "{text}");
    *machine.mem_mib.lock().unwrap() = Some(3072);
    assert_eq!(
        c.check(&job, &policy),
        Ok(()),
        "exactly the floor is enough"
    );
    // An unreadable /proc/meminfo is not a shortage.
    *machine.mem_mib.lock().unwrap() = None;
    assert_eq!(c.check(&job, &policy), Ok(()));
}

#[test]
fn disk_must_hold_the_floor_and_the_jobs_estimate_on_every_path() {
    let machine = Machine::healthy();
    let fx = Fx::new("res-disk");
    let job = job(&fx);
    let policy = Preset::default();
    let c = checks(&machine, true);
    // 20 GiB floor + 4 GiB capture quota.
    machine.disk("/data", 23);
    let (why, text) = wait_of(c.check(&job, &policy));
    assert_eq!(why, WaitingFor::Resources);
    assert!(
        text.contains("/data") && text.contains("23") && text.contains("24"),
        "{text}"
    );
    machine.disk("/data", 24);
    assert_eq!(c.check(&job, &policy), Ok(()));
    // Every recording root counts, and the message names the one that is short.
    machine.disk("/rec", 10);
    let (_, text) = wait_of(c.check(&job, &policy));
    assert!(text.contains("/rec"), "{text}");
    machine.disk("/rec", 500);
    // A memory dump adds the VM's RAM (1 GiB here).
    let mut dumping = Preset::default();
    dumping.dumps.memory_dump_on_exit = true;
    machine.disk("/data", 24);
    assert!(c.check(&job, &dumping).is_err());
    machine.disk("/data", 25);
    assert_eq!(c.check(&job, &dumping), Ok(()));
}

#[test]
fn kvm_is_a_dependency_when_it_is_required() {
    let machine = Machine::healthy();
    machine.kvm.store(false, Ordering::SeqCst);
    let fx = Fx::new("res-kvm");
    let job = job(&fx);
    let policy = Preset::default();
    let (why, text) = wait_of(checks(&machine, true).check(&job, &policy));
    assert_eq!(why, WaitingFor::Dependency);
    assert!(text.contains("/dev/kvm"));
    assert_eq!(
        checks(&machine, false).check(&job, &policy),
        Ok(()),
        "without require_kvm the job runs under TCG"
    );
}

#[test]
fn admission_names_the_first_thing_that_is_short() {
    let machine = Machine::healthy();
    let c = checks(&machine, true);
    assert_eq!(c.admission(), None);
    assert_eq!(c.low_disk(), None);
    machine.disk("/data", 21);
    // 21 GiB is above the 20 GiB floor: a run goes on, a new job waits.
    assert_eq!(c.low_disk(), None);
    assert_eq!(c.admission().unwrap().0, WaitingFor::Resources);
    machine.disk("/data", 19);
    assert!(c.low_disk().unwrap().contains("19"));
    machine.kvm.store(false, Ordering::SeqCst);
    assert_eq!(
        c.admission().unwrap().0,
        WaitingFor::Dependency,
        "KVM first"
    );
    assert_eq!(
        Shortage::NoKvm.words(),
        "/dev/kvm cannot be opened for reading and writing"
    );
}

// ---- the governor and the pause ----------------------------------------

fn alerts(fx: &Fx) -> Vec<String> {
    fx.store
        .events_since(0, 1000)
        .unwrap()
        .into_iter()
        .filter_map(|e| match e.body {
            EventBody::EngineAlert { code, .. } => Some(code),
            _ => None,
        })
        .collect()
}

#[test]
fn the_pause_file_pauses_within_one_tick_and_lifts_when_it_goes() {
    let machine = Machine::healthy();
    let fx = Fx::new("gov-file");
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    governor.tick(0).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), None);
    assert!(alerts(&fx).is_empty());

    machine.pause_file.store(true, Ordering::SeqCst);
    governor.tick(5_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::File));
    governor.tick(10_000).unwrap();
    assert_eq!(alerts(&fx), ["queue_paused"], "one alert, not one per tick");

    machine.pause_file.store(false, Ordering::SeqCst);
    governor.tick(15_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), None);
    assert_eq!(alerts(&fx), ["queue_paused", "queue_resumed"]);
}

#[test]
fn low_disk_and_no_kvm_pause_with_their_reasons_and_lift_when_the_machine_recovers() {
    let machine = Machine::healthy();
    let fx = Fx::new("gov-disk");
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    machine.disk("/rec", 19);
    governor.tick(0).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::LowDisk));
    machine.disk("/rec", 500);
    governor.tick(5_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), None);

    machine.kvm.store(false, Ordering::SeqCst);
    governor.tick(10_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::NoKvm));
    // The file outranks the others: it is the operator's.
    machine.pause_file.store(true, Ordering::SeqCst);
    governor.tick(15_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::File));
    machine.pause_file.store(false, Ordering::SeqCst);
    machine.kvm.store(true, Ordering::SeqCst);
    governor.tick(20_000).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), None);
    let codes = alerts(&fx);
    assert!(
        codes.contains(&"low_disk".to_owned()) && codes.contains(&"no_kvm".to_owned()),
        "{codes:?}"
    );
}

#[test]
fn a_pause_the_operator_set_is_never_replaced_or_lifted() {
    let machine = Machine::healthy();
    let fx = Fx::new("gov-operator");
    fx.store.set_pause(Some(PauseReason::Operator)).unwrap();
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    machine.disk("/data", 1);
    machine.pause_file.store(true, Ordering::SeqCst);
    governor.tick(0).unwrap();
    assert_eq!(
        fx.store.pause_reason().unwrap(),
        Some(PauseReason::Operator)
    );
    machine.disk("/data", 500);
    machine.pause_file.store(false, Ordering::SeqCst);
    governor.tick(5_000).unwrap();
    assert_eq!(
        fx.store.pause_reason().unwrap(),
        Some(PauseReason::Operator)
    );
    assert!(alerts(&fx).is_empty());
    // Nor a quarantined lane's.
    fx.store
        .set_pause(Some(PauseReason::LaneQuarantined))
        .unwrap();
    governor.tick(10_000).unwrap();
    assert_eq!(
        fx.store.pause_reason().unwrap(),
        Some(PauseReason::LaneQuarantined)
    );
}

#[test]
fn low_memory_is_alerted_once_an_hour_and_never_pauses() {
    let machine = Machine::healthy();
    let fx = Fx::new("gov-mem");
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    *machine.mem_mib.lock().unwrap() = Some(100);
    governor.tick(0).unwrap();
    governor.tick(60_000).unwrap();
    governor.tick(LOW_MEMORY_ALERT_EVERY_MS - 1).unwrap();
    assert_eq!(alerts(&fx), ["low_memory"]);
    governor.tick(LOW_MEMORY_ALERT_EVERY_MS).unwrap();
    assert_eq!(alerts(&fx), ["low_memory", "low_memory"]);
    assert_eq!(fx.store.pause_reason().unwrap(), None, "jobs just wait");
    // Recovered, then short again: a new alert at once.
    *machine.mem_mib.lock().unwrap() = Some(16_000);
    governor.tick(LOW_MEMORY_ALERT_EVERY_MS + 1).unwrap();
    *machine.mem_mib.lock().unwrap() = Some(100);
    governor.tick(LOW_MEMORY_ALERT_EVERY_MS + 2).unwrap();
    assert_eq!(alerts(&fx).len(), 3);
}

#[test]
fn the_pause_file_is_read_from_the_disk() {
    let dir = crate::store::tests::scratch("res-file");
    let probes = crate::resources::SystemProbes {
        pause_file: dir.join("PAUSE"),
    };
    assert!(!probes.pause_file());
    std::fs::write(dir.join("PAUSE"), "").unwrap();
    assert!(probes.pause_file());
    // A dangling symlink is still the operator's file.
    std::fs::remove_file(dir.join("PAUSE")).unwrap();
    std::os::unix::fs::symlink("/nonexistent", dir.join("PAUSE")).unwrap();
    assert!(probes.pause_file());
    // The real probes answer for the machine they run on.
    assert!(probes.mem_available_mib().is_some_and(|m| m > 0));
    assert!(probes.free_gib(&dir).is_some());
}

// ---- jobs below a floor stay queued ------------------------------------

#[test]
fn a_job_below_a_floor_stays_queued_with_its_reason_and_runs_when_the_floor_is_met() {
    let machine = Machine::healthy();
    let mut w = W::new("res-queue");
    let job = w.fx.queued(1);
    *machine.mem_mib.lock().unwrap() = Some(100);
    w.host = Box::new(checks(&machine, true));
    let mut waiter = w.engine(|_| {});
    // The scheduler asks the lane, which asks the host before the lane.
    let mut stages = w.stages(&mut waiter);
    let eligibility = stages.eligibility();
    assert_eq!(eligibility, Eligibility::Wait(WaitingFor::Resources));
    let claimed =
        w.fx.store
            .claim_next(&lane(), &mut |_| eligibility)
            .unwrap();
    assert!(claimed.is_none());
    let stored = w.fx.store.get(&job.id).unwrap();
    assert_eq!(
        (stored.state, stored.waiting_for),
        (RunState::Queued, Some(WaitingFor::Resources))
    );
    assert_eq!(stored.attempt, 0, "no attempt was used");
    // The memory comes back: the same job is claimed.
    *machine.mem_mib.lock().unwrap() = Some(16_000);
    let mut stages = w.stages(&mut waiter);
    let eligibility = stages.eligibility();
    assert_eq!(eligibility, Eligibility::Ready);
    assert!(
        w.fx.store
            .claim_next(&lane(), &mut |_| eligibility)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_paused_queue_keeps_jobs_queued_with_queue_paused_and_resumes_them() {
    let machine = Machine::healthy();
    let fx = Fx::new("res-paused");
    let job = fx.queued(1);
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    machine.pause_file.store(true, Ordering::SeqCst);
    governor.tick(0).unwrap();
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fx.store.get(&job.id).unwrap().waiting_for,
        Some(WaitingFor::QueuePaused)
    );
    machine.pause_file.store(false, Ordering::SeqCst);
    governor.tick(5_000).unwrap();
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_floor_that_fails_after_the_claim_sends_the_job_back_to_the_queue() {
    let machine = Machine::healthy();
    let mut w = W::new("res-prechecks");
    let job = w.fx.running(1);
    machine.disk("/data", 3);
    w.host = Box::new(checks(&machine, true));
    let mut waiter = w.engine(|_| {});
    let driven = w.stages(&mut waiter).drive(&job);
    match driven {
        Driven::Waiting {
            waiting_for,
            detail,
        } => {
            assert_eq!(waiting_for, WaitingFor::Resources);
            assert!(detail.contains("/data"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    let stored = w.fx.store.get(&job.id).unwrap();
    assert_eq!(stored.state, RunState::Queued);
    assert_eq!(stored.waiting_for, Some(WaitingFor::Resources));
    assert!(
        waiter.engine_mut().sent_names().is_empty(),
        "no VM was touched"
    );
}

// ---- the floor during a run --------------------------------------------

/// A host whose disk drops below the floor when the test says so.
struct Draining(Arc<AtomicBool>);

impl HostChecks for Draining {
    fn check(&self, _: &Run, _: &Preset) -> Result<(), HostProblem> {
        Ok(())
    }
    fn low_disk(&self) -> Option<String> {
        self.0
            .load(Ordering::SeqCst)
            .then(|| "/data has 3 GiB free, 20 GiB are needed".to_owned())
    }
}

#[test]
fn a_disk_that_falls_below_the_floor_stops_the_run_pauses_the_queue_and_ends_the_job_partial() {
    let mut w = W::new("res-run");
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Draining(low.clone()));
    let job = w.fx.running(1);
    let flag = low.clone();
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        // A program that would run for good.
        execute_run(fake, None);
        stop_run_ok(fake);
        stop_ok(fake);
        fake.call_after(100 * SECOND, move || flag.store(true, Ordering::SeqCst));
    });
    let began = crate::clock::Clock::now_ms(&*w.fx.clock);
    let driven = w.stages(&mut waiter).drive(&job);
    let Driven::Collected(end) = driven else {
        panic!("{driven:?}");
    };
    assert_eq!(end.outcome, Outcome::Partial);
    let stored = w.fx.store.get(&job.id).unwrap();
    let run = stored.program.unwrap();
    assert_eq!(
        run.end_reason,
        Some(EndReason::Stopped),
        "stopped, not a time limit"
    );
    assert!(
        stored
            .warnings
            .iter()
            .any(|x| x.code == "low_disk" && x.text.contains("3 GiB"))
    );
    assert_eq!(
        w.fx.store.pause_reason().unwrap(),
        Some(PauseReason::LowDisk)
    );
    assert!(alerts(&w.fx).contains(&"low_disk".to_owned()));
    // It was noticed at the next minute mark, long before the 300 s limit.
    let took = (crate::clock::Clock::now_ms(&*w.fx.clock) - began) / 1000;
    assert!((100..200).contains(&took), "{took} s");
    assert!(
        waiter
            .engine_mut()
            .sent_names()
            .iter()
            .any(|n| n == "StopRun")
    );
    // The recording is complete and the lane free for when the queue resumes.
    let file = w.lane_file();
    assert!(file.current.is_none() && file.quarantine.is_none());
    let _ = manager();
}

// ---- a full disk in the run stage (T7 disk-full (b), ANT-T0475) ---------

/// The disk is full from `full_at` until `back_at`: the floor fails, the job
/// store and the lane file cannot be written.
fn full_disk(
    w: &W,
    fake: &mut crate::engine::FakeEngine,
    low: &Arc<AtomicBool>,
    full_at: u32,
    back_at: Option<u32>,
) {
    let switches = (
        low.clone(),
        w.fx.store.disk_full_switch(),
        w.lanes.no_space_switch(),
    );
    let set = move |on: bool| {
        let (low, store, lanes) = switches.clone();
        move || {
            low.store(on, Ordering::SeqCst);
            store.store(on, Ordering::SeqCst);
            lanes.store(on, Ordering::SeqCst);
        }
    };
    fake.call_after(SECOND * full_at, set(true));
    if let Some(back_at) = back_at {
        fake.call_after(SECOND * back_at, set(false));
    }
}

#[test]
fn a_full_disk_in_the_run_stage_pauses_the_queue_and_the_job_ends_partial_when_room_is_back() {
    // Before ANT-T0475 the run's end could not be written: the job failed
    // `internal`, the pause was lost with the write, and the lane waited.
    let mut w = W::new("res-full");
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Draining(low.clone()));
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_run_ok(fake);
        stop_ok(fake);
    });
    // Full at 100 s (the floor is seen at the next minute mark), room again
    // at 300 s.
    full_disk(&w, waiter.engine_mut(), &low, 100, Some(300));
    let began = crate::clock::Clock::now_ms(&*w.fx.clock);
    let driven = w.stages(&mut waiter).drive(&job);
    let took = (crate::clock::Clock::now_ms(&*w.fx.clock) - began) / 1000;
    let Driven::Collected(end) = driven else {
        panic!("{driven:?}");
    };
    assert_eq!(end.outcome, Outcome::Partial);
    assert!((300..400).contains(&took), "{took} s");
    let stored = w.fx.store.get(&job.id).unwrap();
    assert_eq!(stored.program.unwrap().end_reason, Some(EndReason::Stopped));
    assert!(
        stored.warnings.iter().any(|x| x.code == "low_disk"),
        "{:?}",
        stored.warnings
    );
    // The pause could not be written when the floor was hit; it held all
    // the same, until the governor lifts it.
    assert_eq!(
        w.fx.store.pause_reason().unwrap(),
        Some(PauseReason::LowDisk)
    );
    let file = w.lane_file();
    assert!(file.quarantine.is_none());
}

#[test]
fn a_recording_the_engine_cannot_finish_on_a_full_disk_does_not_hold_the_lane_for_the_layer_wait() {
    // The engine cannot finish the disk layer while the disk is full: the
    // settle wait used to run its whole 1800 s, twice, then quarantine the
    // lane, with the job `running` all along (ANT-T0475).
    let mut w = W::new("res-layer");
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Draining(low.clone()));
    let job = w.fx.running(1);
    let flag = low.clone();
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_run_ok(fake);
        fake.on("Stop")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
                s.disk_layers.push(DiskLayer {
                    vm_id: VM.into(),
                    boot_id: "b1".into(),
                    phase: LayerPhase::Finalizing,
                    started_ms: 0,
                    phase_ms: 0,
                });
            })
            .ok("VM stopped");
        fake.call_after(100 * SECOND, move || flag.store(true, Ordering::SeqCst));
    });
    let began = crate::clock::Clock::now_ms(&*w.fx.clock);
    let driven = w.stages(&mut waiter).drive(&job);
    let took = (crate::clock::Clock::now_ms(&*w.fx.clock) - began) / 1000;
    assert!(took < 600, "{took} s");
    // `recording_failed` is retried when the policy lists it (not by default).
    let (Driven::Retried { failure, .. } | Driven::Failed(failure)) = driven else {
        panic!("{driven:?}");
    };
    assert_eq!(failure.code, FailureCode::RecordingFailed);
    assert!(failure.message.contains("below its floor"), "{failure:?}");
    // Not quarantined: the lane waits for the layer (layer_pending), which
    // the engine finishes when the disk has room again.
    let file = w.lane_file();
    assert!(file.quarantine.is_none(), "{:?}", file.quarantine);
    assert!(file.current.is_none() && file.qemu.is_none());
    assert!(matches!(
        w.job(&job.id).state,
        RunState::Queued | RunState::Failed
    ));
    assert_eq!(
        crate::stages::prechecks::lane_eligibility(&file, waiter.snapshot()),
        Eligibility::Wait(WaitingFor::LayerPending)
    );
}

#[test]
fn a_full_disk_at_the_end_of_a_job_waits_for_room_instead_of_leaving_it_running() {
    // The job fails while the disk is full: its end and the lane file's end
    // of work are written once there is room, not lost (the lane would stay
    // busy and the job `running` for good).
    let mut w = W::new("res-end");
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Draining(low.clone()));
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    // Full from the start (the lane file's begin of work fails), room again
    // at 120 s.
    full_disk(&w, waiter.engine_mut(), &low, 0, Some(120));
    low.store(true, Ordering::SeqCst);
    w.fx.store.inject_disk_full(true);
    w.lanes.inject_no_space(true);
    let driven = w.stages(&mut waiter).drive(&job);
    assert!(
        matches!(driven, Driven::Failed(_) | Driven::Retried { .. }),
        "{driven:?}"
    );
    let stored = w.job(&job.id);
    assert!(
        matches!(stored.state, RunState::Failed | RunState::Queued),
        "{:?}",
        stored.state
    );
    assert_eq!(stored.failure.unwrap().code, FailureCode::Internal);
    let file = w.lane_file();
    assert!(file.current.is_none(), "{:?}", file.current);
}

#[test]
fn a_pause_the_database_cannot_take_holds_in_memory_until_one_is_written() {
    let fx = Fx::new("pause-held");
    fx.store.inject_disk_full(true);
    let refused = fx.store.set_pause(Some(PauseReason::LowDisk)).unwrap_err();
    assert!(
        crate::resources::disk_full(&refused.to_string()),
        "{refused}"
    );
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::LowDisk));
    // It holds when the database takes writes again, until a pause is
    // written: the governor lifts it once the disk has room.
    fx.store.inject_disk_full(false);
    assert_eq!(fx.store.pause_reason().unwrap(), Some(PauseReason::LowDisk));
    let machine = Machine::healthy();
    let mut governor = Governor::new(checks(&machine, true), &fx.store);
    governor.tick(0).unwrap();
    assert_eq!(fx.store.pause_reason().unwrap(), None);
}

#[test]
fn the_words_of_a_full_disk_are_known_and_others_are_not() {
    for words in [
        "job store: database or disk is full",
        "/d/service/lanes/.lane-1.json.1.2.tmp: No space left on device (os error 28)",
        "Disk quota exceeded (os error 122)",
    ] {
        assert!(crate::resources::disk_full(words), "{words}");
    }
    for words in [
        "job store: database is locked",
        "Permission denied (os error 13)",
        "os error 280)",
    ] {
        assert!(!crate::resources::disk_full(words), "{words}");
    }
}
