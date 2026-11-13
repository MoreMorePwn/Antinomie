// SPDX-License-Identifier: GPL-3.0-only
//! The host work pool with its workers (ANT-T0454): real Triage over the
//! recording fixture, a `FakeEngine` behind the multiplexed connection, a
//! manual clock. Order, the pool limit, the memory wait, cancel and restart
//! mid host work, and the item limits (an item at 1.5 x its estimate
//! finishes, one at 2.1 x is stopped; queue time does not count), and jobs
//! of several lanes in one pool, in arrival order (ANT-T0455 card C).
use super::{
    host_tests::{Hooked, attach_on, collected, real, recording, world, world_with},
    items::{ItemKind, JobWork},
    tests::{SECOND, W},
    timing::{Inputs, Timing},
};
use crate::{
    api::{
        ids::LaneId,
        run::{EndReason, HostItemState, Outcome, Run, RunState},
    },
    clock::Clock,
    daemon::Controls,
    engine::{FakeEngine, Mux, fake::Unscripted},
    lane::LaneDir,
    pool::{HostPool, PoolEnv},
    resources::Probes,
    store::{Eligibility, Store, tests::manager},
    waiter::Waiter,
};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

struct Memory(AtomicU64);

impl Probes for Memory {
    fn mem_available_mib(&self) -> Option<u64> {
        Some(self.0.load(Ordering::SeqCst))
    }
    fn free_gib(&self, _: &Path) -> Option<u64> {
        Some(1000)
    }
    fn kvm_usable(&self) -> bool {
        true
    }
    fn pause_file(&self) -> bool {
        false
    }
}

struct Rig {
    pool: Arc<HostPool>,
    store: Arc<Store>,
    controls: Arc<Controls>,
    memory: Arc<Memory>,
    threads: Vec<JoinHandle<()>>,
    /// The engine and the workers to start ([`Rig::start`]).
    held: Option<(Arc<Mux<FakeEngine>>, u32, Arc<crate::clock::ManualClock>)>,
}

fn make_rig(w: &W, workers: u32, triage: Hooked) -> Rig {
    let mut rig = make_held_rig(w, workers, triage);
    rig.start();
    rig
}

/// A pool whose workers have not started: jobs handed to it first are all
/// queued before any item runs.
fn make_held_rig(w: &W, workers: u32, triage: Hooked) -> Rig {
    make_logged_rig(w, workers, triage, Arc::new(|_| {}))
}

/// [`make_held_rig`] whose pool log lines go to `log`.
fn make_logged_rig(
    w: &W,
    workers: u32,
    triage: Hooked,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Rig {
    let store =
        Arc::new(Store::open_with_clock(&w.fx.dir.join("service"), w.fx.clock.clone()).unwrap());
    let controls = Arc::new(Controls::default());
    let memory = Arc::new(Memory(AtomicU64::new(8192)));
    let pool = HostPool::new(PoolEnv {
        store: Arc::clone(&store),
        lanes: LaneDir::new(&w.fx.dir.join("service")),
        triage: Arc::new(triage),
        tags: Arc::new(crate::stages::host::NoTags),
        evidence: crate::waiter::load_artifacts,
        data_dir: w.fx.dir.join("data"),
        probes: Arc::clone(&memory) as Arc<dyn Probes>,
        floor_mib: 2048,
        controls: Arc::clone(&controls),
        clock: w.fx.clock.clone(),
        log,
        workers,
        timing: Timing::default(),
    });
    let mut fake = FakeEngine::new(w.fx.clock.clone());
    fake.unscripted(Unscripted::Ok);
    let mux = Mux::new(fake);
    Rig {
        pool,
        store,
        controls,
        memory,
        threads: Vec::new(),
        held: Some((mux, workers, w.fx.clock.clone())),
    }
}

impl Rig {
    fn start(&mut self) {
        let Some((mux, workers, clock)) = self.held.take() else {
            return;
        };
        for _ in 0..workers {
            let mut waiter = Waiter::new(mux.handle(), clock.clone());
            let flag = Arc::clone(&self.controls);
            waiter.interrupt_when(move || flag.interrupted());
            let pool = Arc::clone(&self.pool);
            self.threads
                .push(std::thread::spawn(move || pool.work(&mut waiter)));
        }
    }

    fn until(&self, what: &str, done: impl Fn(&Rig) -> bool) {
        let began = Instant::now();
        while !done(self) {
            assert!(
                began.elapsed() < Duration::from_secs(120),
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn job(&self, job: &Run) -> Run {
        self.store.get(&job.id).unwrap()
    }

    fn terminal(&self, job: &Run) -> bool {
        self.job(job).state.is_terminal()
    }

    fn stop(mut self) {
        self.controls.begin_stop();
        self.pool.poke();
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

/// A collected job that arrived 1 ms after the one before it: arrival
/// (`created_ms`) is the pool's order, and the fixture's clock stands still.
fn arrived(w: &W, n: u8) -> Run {
    w.fx.clock.advance(1);
    collected(w, n)
}

fn hooked(w: &W) -> Hooked {
    Hooked {
        real: Some(real(w)),
        ..Hooked::default()
    }
}

#[test]
fn queued_jobs_go_through_the_pool_oldest_first_and_every_item_is_shown() {
    let w = world("pool-order");
    let first = arrived(&w, 1);
    let second = arrived(&w, 2);
    let mut rig = make_held_rig(&w, 2, hooked(&w));
    // The newer job is handed over first; arrival still decides.
    rig.pool.admit(&second, Outcome::Succeeded);
    rig.pool.admit(&first, Outcome::Succeeded);
    rig.start();
    rig.until("both jobs to end", |r| {
        r.terminal(&first) && r.terminal(&second)
    });
    let a = rig.job(&first);
    let b = rig.job(&second);
    assert_eq!(a.state, RunState::Succeeded, "{:?}", a.warnings);
    assert_eq!(b.state, RunState::Succeeded, "{:?}", b.warnings);
    for job in [&a, &b] {
        let names: Vec<&str> = job.host_work.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["triage", "assess", "report"]);
        assert!(job.host_work.iter().all(|i| i.state == HostItemState::Done));
        assert!(job.host_work.iter().all(|i| i.limit_s >= i.expected_s));
        assert_eq!(job.artifacts.len(), 2);
    }
    // Every item of the older job started before any of the newer one.
    let last_a = a
        .host_work
        .iter()
        .filter_map(|i| i.started_ms)
        .max()
        .unwrap();
    let first_b = b
        .host_work
        .iter()
        .filter_map(|i| i.started_ms)
        .min()
        .unwrap();
    assert!(last_a <= first_b, "{last_a} > {first_b}");
    // A job is terminal in the store a moment before it leaves the pool.
    rig.until("both jobs to leave the pool", |r| r.pool.status().runs == 0);
    rig.stop();
}

/// A collected job of lane `n`, 1 ms after the one before it; lane `n` has
/// its own lane file with the entry `collect` leaves (several lanes, ANT-T0455
/// card C).
fn arrived_on(w: &W, job: u8, n: u32) -> Run {
    let on = LaneId::new(n);
    if w.lanes.load(&on).unwrap().is_none() {
        let mut file = crate::lane::tests::file();
        file.lane = on.clone();
        file.vm_id = format!("auto-{n}");
        w.lanes.save(&file).unwrap();
    }
    w.fx.clock.advance(1);
    let queued = w.fx.queued(job);
    let claimed =
        w.fx.store
            .claim_next(&on, &mut |_| Eligibility::Ready)
            .unwrap()
            .unwrap();
    assert_eq!(claimed.id, queued.id);
    assert_eq!(claimed.lane.as_ref(), Some(&on));
    let dir = recording(w, claimed.sample.as_ref().unwrap().sha256.as_str(), true);
    attach_on(w, &claimed, &dir, EndReason::Exited, &on);
    claimed
}

#[test]
fn jobs_of_several_lanes_share_one_pool_in_arrival_order() {
    let w = world("pool-lanes");
    // Arrival: lane 2's job, then lane 1's, then lane 3's.
    let jobs = [
        arrived_on(&w, 1, 2),
        arrived_on(&w, 2, 1),
        arrived_on(&w, 3, 3),
    ];
    let opened = Arc::new(Mutex::new(Vec::new()));
    let triage = Hooked {
        opened: Some(Arc::clone(&opened)),
        ..hooked(&w)
    };
    // One worker, so the order the runs are opened in is the order the items
    // start in. The lanes hand their jobs over out of arrival order.
    let mut rig = make_held_rig(&w, 1, triage);
    for index in [2, 0, 1] {
        rig.pool.admit(&jobs[index], Outcome::Succeeded);
    }
    assert_eq!(rig.pool.status().runs, 3);
    rig.start();
    rig.until("the jobs to end", |r| jobs.iter().all(|j| r.terminal(j)));
    for job in &jobs {
        let done = rig.job(job);
        assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
        assert_eq!(done.lane, job.lane, "a job keeps its lane");
        assert!(
            done.host_work
                .iter()
                .all(|i| i.state == HostItemState::Done)
        );
    }
    // Every item of an older job started before any item of a newer one,
    // whatever lane each came from.
    let mut order: Vec<_> = opened.lock().unwrap().clone();
    assert!(!order.is_empty());
    order.dedup();
    let arrival: Vec<_> = jobs.iter().map(|j| j.id.clone()).collect();
    assert_eq!(order, arrival, "grouped by job, in arrival order");
    // Each lane's file lets its own job go.
    rig.until("every lane file to let its job go", |_| {
        (1..=3).all(|n| {
            w.lanes
                .load(&LaneId::new(n))
                .unwrap()
                .unwrap()
                .collected
                .is_empty()
        })
    });
    rig.until("the jobs to leave the pool", |r| r.pool.status().runs == 0);
    rig.stop();
}

#[test]
fn no_more_items_run_than_the_pool_has_workers() {
    let w = world("pool-limit");
    let jobs: Vec<Run> = (1..=3).map(|n| arrived(&w, n)).collect();
    let mut triage = hooked(&w);
    let running = Arc::new(AtomicU64::new(0));
    let most = Arc::new(AtomicU64::new(0));
    let (r, m) = (Arc::clone(&running), Arc::clone(&most));
    triage.index = Some(Box::new(move |_| {
        let now = r.fetch_add(1, Ordering::SeqCst) + 1;
        m.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        r.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }));
    let rig = make_rig(&w, 1, triage);
    for job in &jobs {
        rig.pool.admit(job, Outcome::Succeeded);
    }
    assert!(rig.pool.status().workers == 1);
    rig.until("the jobs to end", |r| jobs.iter().all(|j| r.terminal(j)));
    assert_eq!(most.load(Ordering::SeqCst), 1);
    rig.stop();
}

#[test]
fn the_head_waits_for_memory_and_starts_when_there_is_room() {
    let w = world("pool-memory");
    let job = arrived(&w, 1);
    let rig = make_rig(&w, 2, hooked(&w));
    rig.memory.0.store(1000, Ordering::SeqCst);
    rig.pool.admit(&job, Outcome::Succeeded);
    rig.until("the wait to show", |r| {
        r.pool.status().waiting_for.is_some()
    });
    std::thread::sleep(Duration::from_millis(100));
    let waiting = rig.job(&job);
    assert_eq!(waiting.state, RunState::Running);
    assert!(
        waiting
            .host_work
            .iter()
            .all(|i| i.state == HostItemState::Queued),
        "nothing started below the floor"
    );
    assert_eq!(rig.pool.status().queued, 3);
    rig.memory.0.store(4096, Ordering::SeqCst);
    rig.until("the job to end", |r| r.terminal(&job));
    assert_eq!(rig.job(&job).state, RunState::Succeeded);
    rig.stop();
}

#[test]
fn a_cancel_mid_host_work_ends_the_job_cancelled_and_skips_the_rest() {
    let w = world("pool-cancel");
    let job = arrived(&w, 1);
    let started = Arc::new(AtomicBool::new(false));
    let mut triage = hooked(&w);
    let seen = Arc::clone(&started);
    triage.index = Some(Box::new(move |cancel| {
        seen.store(true, Ordering::SeqCst);
        let began = Instant::now();
        while !cancel.load(Ordering::SeqCst) && began.elapsed() < Duration::from_secs(60) {
            std::thread::sleep(Duration::from_millis(2));
        }
        Err("cancelled".into())
    }));
    let rig = make_rig(&w, 2, triage);
    rig.pool.admit(&job, Outcome::Succeeded);
    rig.until("triage to start", |_| started.load(Ordering::SeqCst));
    rig.store.cancel(&job.id, Some("test"), &manager()).unwrap();
    rig.until("the job to end", |r| r.terminal(&job));
    let done = rig.job(&job);
    assert_eq!(done.state, RunState::Cancelled);
    assert!(done.artifacts.is_empty());
    assert!(
        done.host_work[1..]
            .iter()
            .all(|i| i.state == HostItemState::Skipped),
        "{:?}",
        done.host_work
    );
    // The lane file lets a job go a moment after it is terminal in the store.
    rig.until("the lane file to let the jobs go", |_| {
        w.lane_file().collected.is_empty()
    });
    rig.stop();
}

#[test]
fn a_stop_mid_host_work_leaves_the_jobs_and_a_restart_resumes_them_in_order() {
    let w = world("pool-restart");
    let first = arrived(&w, 1);
    let second = arrived(&w, 2);
    let started = Arc::new(AtomicBool::new(false));
    let mut triage = hooked(&w);
    let seen = Arc::clone(&started);
    triage.index = Some(Box::new(move |cancel| {
        seen.store(true, Ordering::SeqCst);
        while !cancel.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        Err("stopped".into())
    }));
    let rig = make_rig(&w, 1, triage);
    rig.pool.admit(&first, Outcome::Succeeded);
    rig.pool.admit(&second, Outcome::Succeeded);
    rig.until("triage to start", |_| started.load(Ordering::SeqCst));
    // The second signal: every wait ends now.
    rig.controls.interrupt();
    rig.pool.poke();
    let store = Arc::clone(&rig.store);
    rig.stop();
    for job in [&first, &second] {
        let left = store.get(&job.id).unwrap();
        assert_eq!(left.state, RunState::Running, "left for the next start");
    }
    assert_eq!(w.lane_file().collected.len(), 2, "the entries stay");
    let queued = store.get(&second.id).unwrap();
    assert!(
        queued
            .host_work
            .iter()
            .all(|i| i.state == HostItemState::Queued),
        "{:?}",
        queued.host_work
    );

    // The next start: recovery hands both back, the newer one first.
    let mut rig = make_held_rig(&w, 1, hooked(&w));
    let mut fake = FakeEngine::new(w.fx.clock.clone());
    fake.unscripted(Unscripted::Ok);
    let mut waiter = Waiter::new(fake, w.fx.clock.clone());
    rig.pool
        .resume(&rig.store.get(&second.id).unwrap(), &mut waiter);
    rig.pool
        .resume(&rig.store.get(&first.id).unwrap(), &mut waiter);
    assert_eq!(rig.pool.jobs(), [first.id.clone(), second.id.clone()]);
    rig.start();
    rig.until("both jobs to end", |r| {
        r.terminal(&first) && r.terminal(&second)
    });
    let a = rig.job(&first);
    let b = rig.job(&second);
    assert_eq!(
        (a.state, b.state),
        (RunState::Succeeded, RunState::Succeeded)
    );
    let last_a = a
        .host_work
        .iter()
        .filter_map(|i| i.started_ms)
        .max()
        .unwrap();
    let first_b = b
        .host_work
        .iter()
        .filter_map(|i| i.started_ms)
        .min()
        .unwrap();
    assert!(last_a <= first_b);
    // The lane file lets a job go a moment after it is terminal in the store.
    rig.until("the lane file to let the jobs go", |_| {
        w.lane_file().collected.is_empty()
    });
    rig.stop();
}

// ---- item limits: 2 x the expected time, queue time not counted ---------

fn triage_plan() -> super::plan::HostPlan {
    super::plan::HostPlan {
        static_checks: Vec::new(),
        static_limit_min: None,
        static_limits: Default::default(),
        required_checks: Vec::new(),
        triage: true,
        engines: Vec::new(),
        online: false,
        formats: Vec::new(),
        bundle: false,
        defang: true,
        required: Vec::new(),
        retry_analysis: false,
        max_attempts: 1,
    }
}

/// Run the Triage item with an index that takes `took` of the fake clock,
/// under the limit the rules give for an expected time of `expected`.
fn triage_taking(name: &str, expected: u64, took: Duration) -> (HostItemState, u64) {
    let mut w = world(name);
    let job = arrived(&w, 1);
    let clock = w.fx.clock.clone();
    let start = Arc::new(AtomicU64::new(0));
    let mark = Arc::clone(&start);
    let mut triage = hooked(&w);
    triage.index = Some(Box::new(move |cancel| {
        mark.store(clock.now_ms(), Ordering::SeqCst);
        let until = clock.now_ms() + took.as_millis() as u64;
        while clock.now_ms() < until {
            if cancel.load(Ordering::SeqCst) {
                return Err("stopped".into());
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        Ok(())
    }));
    w.triage = Box::new(triage);
    // The estimate of `triage` is 20 s + 10 s a MiB of recording.
    let timing = Timing::default();
    let plan = triage_plan();
    let inputs = Inputs {
        sample_bytes: None,
        recording_bytes: Some(((expected - 20) << 20) / 10),
        load: 1.0,
    };
    let time = timing.of(&ItemKind::Triage, &plan, &inputs);
    assert_eq!(time.expected_s, expected);
    assert_eq!(
        time.limit_s,
        2 * expected,
        "the limit is twice the estimate"
    );
    let work = Mutex::new(JobWork::new(plan, Outcome::Succeeded));
    let mut waiter = w.engine(|_| {});
    let fresh = w.job(&job.id);
    let began = w.fx.clock.now_ms();
    let end = w
        .stages(&mut waiter)
        .run_item(
            &fresh,
            &work,
            &ItemKind::Triage,
            Duration::from_secs(time.limit_s),
        )
        .unwrap();
    assert!(start.load(Ordering::SeqCst) >= began);
    // The item's own time, from the moment it began.
    (end.state, (w.fx.clock.now_ms() - began) / 1000)
}

#[test]
fn an_item_at_one_and_a_half_times_its_estimate_is_not_stopped() {
    let (state, took) = triage_taking("pool-1-5x", 30, Duration::from_secs(45));
    assert_eq!(state, HostItemState::Done);
    assert!((45..60).contains(&took), "{took}");
}

#[test]
fn an_item_at_two_point_one_times_its_estimate_is_stopped_at_twice() {
    let (state, took) = triage_taking("pool-2-1x", 30, Duration::from_secs(63));
    assert_eq!(state, HostItemState::TimedOut);
    assert!((60..63).contains(&took), "{took}");
}

#[test]
fn time_in_the_engine_queue_does_not_count_against_a_static_item() {
    let w = world_with("pool-static-queue", |p| {
        p.static_analysis.triage_checks = vec![crate::api::spec::StaticCheck::Metadata];
        p.required_stages = Vec::new();
    });
    let job = arrived(&w, 1);
    let entry = |state: &str| -> antinomie_monitor_core::analysis::AnalysisReport {
        serde_json::from_value(serde_json::json!({
            "id": "rep-q", "state": state, "source_path": "sample:x", "sections": [],
        }))
        .unwrap()
    };
    let (queued, running, complete) = (entry("queued"), entry("running"), entry("complete"));
    // 500 s queued in the engine, then 45 s running: well past a 60 s limit
    // in all, but only 45 s of its own.
    let mut waiter = w.engine(move |fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, move |s| s.analysis_reports = vec![queued.clone()])
            .then(501 * SECOND, move |s| {
                s.analysis_reports = vec![running.clone()]
            })
            .then(546 * SECOND, move |s| {
                s.analysis_reports = vec![complete.clone()]
            })
            .ok("rep-q");
    });
    let fresh = w.job(&job.id);
    let frozen = w.fx.store.frozen_preset(&job.id).unwrap();
    let plan = super::plan::hosted(&frozen.preset);
    let work = Mutex::new(JobWork::new(plan, Outcome::Succeeded));
    let kind = ItemKind::Static(vec![
        antinomie_monitor_core::analysis::AnalysisKind::Metadata,
    ]);
    let end = w
        .stages(&mut waiter)
        .run_item(&fresh, &work, &kind, Duration::from_secs(60))
        .unwrap();
    assert_eq!(end.state, HostItemState::Done, "{:?}", end.note);
}

/// ANT-T0471: a static item whose job deadline (`until`) comes before its own
/// limit is stopped at the deadline: it asks the engine to stop the analysis
/// (the engine sends its worker SIGTERM, then SIGKILL after the grace) and
/// ends only once the analysis has ended, `timed_out`.
#[test]
fn t0471_a_static_item_is_stopped_at_the_deadline_and_waits_for_the_stop() {
    let w = world_with("pool-static-deadline", |p| {
        p.static_analysis.triage_checks = vec![crate::api::spec::StaticCheck::Metadata];
        p.required_stages = Vec::new();
    });
    let job = arrived(&w, 1);
    let entry = |state: &str| -> antinomie_monitor_core::analysis::AnalysisReport {
        serde_json::from_value(serde_json::json!({
            "id": "rep-d", "state": state, "source_path": "sample:x", "sections": [],
        }))
        .unwrap()
    };
    let (running, cancelled) = (entry("running"), entry("cancelled"));
    let log = Arc::new(Mutex::new(None));
    let keep = Arc::clone(&log);
    let mut waiter = w.engine(move |fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, move |s| s.analysis_reports = vec![running.clone()])
            .ok("rep-d");
        // The worker takes 3 s to end after its SIGTERM.
        fake.on("CancelAnalysis")
            .then(3 * SECOND, move |s| {
                s.analysis_reports = vec![cancelled.clone()]
            })
            .ok("");
        *keep.lock().unwrap() = Some(fake.sent_log());
    });
    let fresh = w.job(&job.id);
    let frozen = w.fx.store.frozen_preset(&job.id).unwrap();
    let plan = super::plan::hosted(&frozen.preset);
    let work = Mutex::new(JobWork::new(plan, Outcome::Succeeded));
    let kind = ItemKind::Static(vec![
        antinomie_monitor_core::analysis::AnalysisKind::Metadata,
    ]);
    let began = w.fx.clock.now_ms();
    let end = w
        .stages(&mut waiter)
        .run_item_until(
            &fresh,
            &work,
            &kind,
            Duration::from_secs(600),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(end.state, HostItemState::TimedOut, "{:?}", end.note);
    let sent = log.lock().unwrap().clone().unwrap();
    let sent = sent.lock().unwrap().clone();
    let cancel = sent
        .iter()
        .find(|s| s.name == "CancelAnalysis")
        .expect("the analysis is stopped");
    // Asked at the deadline, not at the item's own 600 s limit ...
    assert!(
        (30_000..32_000).contains(&(cancel.at_ms - began)),
        "{}",
        cancel.at_ms - began
    );
    // ... and the item ended once the stopped analysis had ended.
    let ended = w.fx.clock.now_ms() - began;
    assert!((33_000..40_000).contains(&ended), "{ended}");
}

// ---- Check online (ANT-T0548 F2) -----------------------------------------

#[test]
fn the_online_item_runs_before_assess_and_shows_its_account() {
    use super::online_tests::{FAKE_KEY, FakeAbuse, assert_no_key, online_world};
    use crate::api::run::OnlineStatus;
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world("pool-online", true, true, &fake);
    let job = arrived(&w, 1);
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&lines);
    // The pool's own triage double: the world's, with the same seams.
    let mut triage = hooked(&w);
    triage.ioc = Some(super::online_tests::indicators(0));
    triage.transport =
        Some(fake.clone() as Arc<dyn antinomie_monitor_core::ioc::online::Transport + Send + Sync>);
    let mut rig = make_logged_rig(
        &w,
        2,
        triage,
        Arc::new(move |line| sink.lock().unwrap().push(line.to_owned())),
    );
    rig.pool.admit(&job, Outcome::Succeeded);
    rig.start();
    rig.until("the job to end", |r| r.terminal(&job));
    let done = rig.job(&job);
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    let names: Vec<&str> = done.host_work.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["triage", "online", "assess", "report"]);
    let online = &done.host_work[1];
    assert_eq!(online.after, ["triage"]);
    assert!(done.host_work[2].after.contains(&"online".to_owned()));
    assert_eq!(online.state, HostItemState::Done, "{:?}", online.note);
    assert_eq!(online.limit_s, super::plan::ONLINE_WAIT.as_secs());
    let account = online.online.as_ref().expect("the account");
    assert_eq!(
        (
            account.status,
            account.reason,
            account.asked,
            account.found,
            account.left_out
        ),
        (OnlineStatus::Done, None, 2, 1, 0)
    );
    assert_eq!(fake.sent.lock().unwrap().len(), 4);
    rig.until("the job to leave the pool", |r| r.pool.status().runs == 0);
    rig.stop();
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|l| l.contains("item=online")), "{lines:?}");
    assert!(lines.iter().all(|l| !l.contains(FAKE_KEY)));
    assert_no_key(&w, &job);
}

#[test]
fn without_a_key_the_online_item_is_skipped_with_no_key() {
    use super::online_tests::{FakeAbuse, online_world};
    use crate::api::run::{OnlineReason, OnlineStatus};
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world("pool-online-nokey", true, false, &fake);
    let job = arrived(&w, 1);
    let mut triage = hooked(&w);
    triage.ioc = Some(super::online_tests::indicators(0));
    triage.transport =
        Some(fake.clone() as Arc<dyn antinomie_monitor_core::ioc::online::Transport + Send + Sync>);
    let rig = make_rig(&w, 1, triage);
    rig.pool.admit(&job, Outcome::Succeeded);
    rig.until("the job to end", |r| r.terminal(&job));
    let done = rig.job(&job);
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    let online = done
        .host_work
        .iter()
        .find(|i| i.name == "online")
        .expect("the item");
    assert_eq!(online.state, HostItemState::Skipped);
    let account = online.online.as_ref().unwrap();
    assert_eq!(
        (account.status, account.reason),
        (OnlineStatus::Skipped, Some(OnlineReason::NoKey))
    );
    assert!(fake.sent.lock().unwrap().is_empty());
    rig.until("the job to leave the pool", |r| r.pool.status().runs == 0);
    rig.stop();
}
