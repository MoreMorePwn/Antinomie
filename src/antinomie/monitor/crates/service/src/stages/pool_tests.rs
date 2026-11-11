// SPDX-License-Identifier: GPL-3.0-only
//! The host work pool with its workers (ANT-T0454): real Triage over the
//! recording fixture, a `FakeEngine` behind the multiplexed connection, a
//! manual clock. Order, the pool limit, the memory wait, cancel and restart
//! mid host work, and the item limits (an item at 1.5 x its estimate
//! finishes, one at 2.1 x is stopped; queue time does not count).
use super::{
    host_tests::{Hooked, collected, real, world, world_with},
    items::{ItemKind, JobWork},
    tests::{SECOND, W},
    timing::{Inputs, Timing},
};
use crate::{
    api::job::{HostItemState, Job, JobState, Outcome},
    clock::Clock,
    daemon::Controls,
    engine::{FakeEngine, Mux, fake::Unscripted},
    lane::LaneDir,
    pool::{HostPool, PoolEnv},
    resources::Probes,
    store::{Store, tests::manager},
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
    let store =
        Arc::new(Store::open_with_clock(&w.fx.dir.join("service"), w.fx.clock.clone()).unwrap());
    let controls = Arc::new(Controls::default());
    let memory = Arc::new(Memory(AtomicU64::new(8192)));
    let pool = HostPool::new(PoolEnv {
        store: Arc::clone(&store),
        lanes: LaneDir::new(&w.fx.dir.join("service")),
        policies: Arc::new(w.fx.policies.clone()),
        triage: Arc::new(triage),
        tags: Arc::new(crate::stages::host::NoTags),
        evidence: crate::waiter::load_artifacts,
        data_dir: w.fx.dir.join("data"),
        probes: Arc::clone(&memory) as Arc<dyn Probes>,
        floor_mib: 2048,
        controls: Arc::clone(&controls),
        clock: w.fx.clock.clone(),
        log: Arc::new(|_| {}),
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

    fn job(&self, job: &Job) -> Job {
        self.store.get(&job.id).unwrap()
    }

    fn terminal(&self, job: &Job) -> bool {
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
fn arrived(w: &W, n: u8) -> Job {
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
    assert_eq!(a.state, JobState::Succeeded, "{:?}", a.warnings);
    assert_eq!(b.state, JobState::Succeeded, "{:?}", b.warnings);
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
    rig.until("both jobs to leave the pool", |r| r.pool.status().jobs == 0);
    rig.stop();
}

#[test]
fn no_more_items_run_than_the_pool_has_workers() {
    let w = world("pool-limit");
    let jobs: Vec<Job> = (1..=3).map(|n| arrived(&w, n)).collect();
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
    assert_eq!(waiting.state, JobState::Running);
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
    assert_eq!(rig.job(&job).state, JobState::Succeeded);
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
    assert_eq!(done.state, JobState::Cancelled);
    assert!(done.artifacts.is_empty());
    assert!(
        done.host_work[1..]
            .iter()
            .all(|i| i.state == HostItemState::Skipped),
        "{:?}",
        done.host_work
    );
    assert!(w.lane_file().collected.is_empty());
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
        assert_eq!(left.state, JobState::Running, "left for the next start");
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
        (JobState::Succeeded, JobState::Succeeded)
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
    assert!(w.lane_file().collected.is_empty());
    rig.stop();
}

// ---- item limits: 2 x the expected time, queue time not counted ---------

fn triage_plan() -> super::plan::HostPlan {
    super::plan::HostPlan {
        static_checks: Vec::new(),
        static_limit_min: None,
        required_checks: Vec::new(),
        triage: true,
        engines: Vec::new(),
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
        p.analysis.static_checks =
            crate::api::spec::StaticChecks::Names(vec![crate::api::spec::StaticCheck::Metadata]);
        p.analysis.required_stages = Vec::new();
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
    let frozen = w.fx.store.frozen_policy(&job.id).unwrap();
    let plan = super::plan::hosted(&fresh, &frozen.policy);
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
