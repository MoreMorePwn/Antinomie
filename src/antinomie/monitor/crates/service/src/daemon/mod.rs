// SPDX-License-Identifier: GPL-3.0-only
//! The daemon (design 2.2 option C, 2.7; card P3-6a): it owns the data
//! directory, runs the queue on its lane, and serves the local socket.
//!
//! Start (2.7): the caller has already taken the data directory (the engine
//! is started with the owner claim `daemon` and the socket path, so
//! `run/owner.json` names both; another daemon or the window is refused
//! there with the owner named). Then: the first engine snapshot, the job
//! store, `service.toml` and the policies, recovery (4.7.3, 4.8, including
//! jobs that resume at `analyse`), the staging store and its `noexec` check,
//! the lane's thread, and last the socket.
//!
//! Several lanes (`daemon.lanes`, ANT-T0455 card C; [`lanes`]): the caller
//! starts lane 1's engine first (it owns the folders the lanes share), then
//! one engine per lane the plan lets start ([`lanes::plan_lanes`]), and hands
//! them all to [`Daemon::start_lanes`]. Each lane has its own thread and
//! [`LaneLoop`]; the lanes share the job store, the policies, the socket and
//! one host work pool (first come, first served by job arrival over every
//! lane; its workers use lane 1's engine). The recovery of the store is done
//! once, then each lane's own on its engine; the jobs to resume at `analyse`
//! go back to the pool in arrival order, whatever lane collected them. One
//! lane whose engine stops stops the daemon (its unit restarts it).
//!
//! Signals (2.7), as the supervisor sees them through [`Signals`]:
//!
//! | Signal | What happens |
//! |---|---|
//! | first `SIGTERM`/`SIGINT` | No new submissions (`unavailable`, reason `service_stopping`); queued jobs stay queued. A job in its lane stages is cancelled for shutdown and goes back to the queue with the attempt not counted (`shutdown = drain`: after `drain_timeout_s`). The host work pool goes on with the jobs it holds (their `analyse`, `report`, `cleanup` items) for up to `shutdown_host_grace_s` (120 s); past that its waits are interrupted and recovery hands those jobs back to the pool on the next start, their items queued in the same order. |
//! | a second one within 5 s | Every wait is interrupted now; the engine stops the VM; exit 130. Recovery finishes the rest. |
//! | `SIGHUP` | `policies/` and `service.toml` are read again (the socket stays); a failing reload keeps the old set. Running and queued jobs keep the policy they were frozen with. |
//! | `SIGUSR1` | The queue's state is written to the log. |

pub mod artifacts;
pub mod board;
mod housekeeping;
pub mod lane;
mod lane_ops;
pub mod lanes;
#[cfg(test)]
mod lanes_tests;
mod library_ops;
mod notify_thread;
#[cfg(test)]
mod p4_tests;
#[cfg(test)]
mod read_tests;
pub mod runner;
pub mod service;
#[cfg(test)]
mod t9_tests;
#[cfg(test)]
mod tests;
mod watch_env;

use crate::{
    api::{
        error::ApiError,
        ids::{JobId, LaneId},
        status::{Accelerator, Owner, ReadGaps},
    },
    clock::{Clock, SystemClock},
    config::{DiskVms, PolicySet, ServiceConfig, SharedPolicies, service::Shutdown},
    engine::{Engine, Handle, Mux},
    intake::{Intake, staging::StagingStore},
    lane::{
        LaneDir, ProcFs,
        recover::{RecoverOptions, recover_lane_with, recover_store, recover_unstarted},
    },
    pool::{HostPool, ITEM_FLOOR_MIB, PoolEnv},
    query::{QueryService, phase::LayerSource},
    resources::{Floors, Governor, GovernorShare, ResourceChecks, SystemProbes},
    server::{Handler, Server, StopHandle, limits::Limits},
    stages::{
        host::{LibraryTags, RealTriage},
        timing::{Medians, Timing},
    },
    store::Store,
    waiter::Waiter,
};
use antinomie_monitor_core::{BackendOptions, Snapshot, disk_layers::DiskLayer};
use lane::{LaneLoop, Periods};
use runner::{RunnerEnv, StagesRunner};
use service::Service;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// What the lane is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    /// `prechecks` to `collect`: the VM is in use.
    Lane(JobId),
    /// `analyse` to `cleanup` on the lane's own thread (the sequential form,
    /// without a host work pool).
    Host(JobId),
    /// A lane command (`lane.reset`, ...).
    Command(String),
}

/// The flags the supervisor sets and the lane's thread reads.
#[derive(Debug, Default)]
pub struct Controls {
    stop: AtomicBool,
    interrupt: AtomicBool,
    engine_lost: AtomicBool,
    lane_ended: AtomicBool,
}

impl Controls {
    pub fn begin_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
    /// End every wait of the lane now (the job is left for recovery).
    pub fn interrupt(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.interrupt.store(true, Ordering::SeqCst);
    }
    pub fn interrupted(&self) -> bool {
        self.interrupt.load(Ordering::SeqCst)
    }
    pub fn engine_lost(&self) {
        self.engine_lost.store(true, Ordering::SeqCst);
    }
    /// The lane's thread has ended: nothing more will finish.
    pub fn lane_ended(&self) {
        self.lane_ended.store(true, Ordering::SeqCst);
    }
    pub fn lane_has_ended(&self) -> bool {
        self.lane_ended.load(Ordering::SeqCst)
    }
    pub fn engine_is_lost(&self) -> bool {
        self.engine_lost.load(Ordering::SeqCst)
    }
}

/// What the engine's latest snapshot says, for `health`, `queue.status` and
/// the recording reads (numbers and enums only).
#[derive(Clone, Debug, Default)]
pub struct EngineView {
    pub ui_dropped: u64,
    pub shedding: bool,
    pub reply_stalls: u64,
    pub read_gaps: ReadGaps,
    pub disk_layers: Vec<DiskLayer>,
    pub since_ms: u64,
    /// The parts of the snapshot the lane checks read (`lane.list`): the
    /// VMs, their snapshot trees, the VM state, the recording flush, the
    /// installed bases (`vm.list`, `base.list`).
    pub lanes: Snapshot,
}

fn update_view(view: &Mutex<EngineView>, snapshot: &Snapshot, now_ms: u64) {
    let mut view = crate::store::lock(view);
    let health = &snapshot.health;
    view.ui_dropped = health.ui_dropped;
    view.shedding = health.shedding;
    view.reply_stalls = health.reply_stalls;
    view.read_gaps = ReadGaps {
        count: health.read_gaps.count,
        total_ns: health.read_gaps.total_ns,
        longest_ns: health.read_gaps.longest_ns,
    };
    if view.disk_layers != snapshot.disk_layers || view.since_ms == 0 {
        view.since_ms = now_ms;
    }
    view.disk_layers = snapshot.disk_layers.clone();
    view.lanes = Snapshot {
        vms: snapshot.vms.clone(),
        vm_snapshot_trees: snapshot.vm_snapshot_trees.clone(),
        state: snapshot.state.clone(),
        active_vm: snapshot.active_vm.clone(),
        recording_flush: snapshot.recording_flush.clone(),
        disk_layers: snapshot.disk_layers.clone(),
        bases: snapshot.bases.clone(),
        bases_checking: snapshot.bases_checking,
        ..Snapshot::default()
    };
}

/// The engines' disk layers for the recording reads (5.12.2), every lane's.
struct ViewLayers(Vec<Arc<Mutex<EngineView>>>);

impl LayerSource for ViewLayers {
    fn layers(&self) -> Vec<DiskLayer> {
        self.0
            .iter()
            .flat_map(|view| crate::store::lock(view).disk_layers.clone())
            .collect()
    }
}

/// A signal the supervisor acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Stop,
    Reload,
    Status,
}

/// Where the supervisor learns of signals (the CLI's handlers, or a test).
pub trait Signals {
    fn take(&self) -> Vec<Signal>;
}

/// No signals.
pub struct NoSignals;

impl Signals for NoSignals {
    fn take(&self) -> Vec<Signal> {
        Vec::new()
    }
}

/// Everything the daemon needs besides the engine.
pub struct Setup {
    /// The engine options (`data_dir` among them), for Triage and the reads.
    pub options: BackendOptions,
    pub config: ServiceConfig,
    /// `None`: no socket (direct mode runs the queue in the command itself).
    pub socket: Option<PathBuf>,
    pub owner: Owner,
    /// How long jobs in their host stages may run on at shutdown.
    pub host_grace: Duration,
    pub limits: Limits,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// How the daemon ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// A clean stop.
    Clean,
    /// A second signal: waits were interrupted (exit 130).
    Hurried,
    /// The engine stopped under the daemon.
    EngineLost,
}

/// A running daemon.
pub struct Daemon<E: Engine + Send + 'static> {
    service: Arc<Service>,
    /// Each lane's thread, lane 1 first; it hands its engine connection back.
    lanes: Vec<(LaneId, JoinHandle<Waiter<Handle<E>>>)>,
    /// The host work pool's workers (ANT-T0454).
    workers: Vec<JoinHandle<()>>,
    server: Option<(StopHandle, JoinHandle<()>)>,
    /// The watcher, retention and delivery threads; they end on the stop flag.
    helpers: Vec<JoinHandle<()>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    host_grace: Duration,
}

/// The shutdown in progress.
#[derive(Debug, Default)]
pub struct Stopping {
    pub since: Option<Instant>,
    pub cancelled: HashSet<JobId>,
    pub interrupted: bool,
}

/// One step of the shutdown (see the module text). Returns a line for the
/// log when it did something.
pub fn shutdown_step(
    service: &Service,
    state: &mut Stopping,
    host_grace: Duration,
    now: Instant,
) -> Option<String> {
    let since = *state.since.get_or_insert(now);
    let (mode, drain) = {
        let config = service.config.read().unwrap_or_else(|p| p.into_inner());
        (
            config.daemon.shutdown,
            Duration::from_secs(u64::from(config.daemon.drain_timeout_s)),
        )
    };
    let limit = match mode {
        Shutdown::Drain => host_grace.max(drain),
        Shutdown::Cancel => host_grace,
    };
    let pooled = service.pool.as_ref().is_some_and(|pool| pool.busy());
    if pooled && !state.interrupted && now.duration_since(since) >= limit {
        state.interrupted = true;
        service.controls.interrupt();
        if let Some(pool) = &service.pool {
            pool.poke();
        }
        return Some(format!(
            "the host work pool did not finish within {} s; its jobs resume on the next start",
            limit.as_secs()
        ));
    }
    let mut lines = Vec::new();
    for (_, phase) in service.phases() {
        match &phase {
            Phase::Lane(job) if !state.cancelled.contains(job) => {
                if mode == Shutdown::Drain && now.duration_since(since) < drain {
                    continue;
                }
                state.cancelled.insert(job.clone());
                lines.push(match service.store.cancel_for_shutdown(job) {
                    Ok(_) => format!(
                        "job={job} is in its lane stages: cancelled for shutdown, it goes back to the queue"
                    ),
                    Err(error) => format!("job={job}: cancel for shutdown: {error}"),
                });
            }
            Phase::Host(job) if !state.interrupted => {
                if now.duration_since(since) < limit {
                    continue;
                }
                state.interrupted = true;
                service.controls.interrupt();
                lines.push(format!(
                    "job={job} did not finish its host stages within {} s; it resumes at analyse on the next start",
                    limit.as_secs()
                ));
            }
            _ => {}
        }
    }
    (!lines.is_empty()).then(|| lines.join("; "))
}

/// The lane VM's RAM and recording root, from the engine's VM list.
fn lane_vm(lanes: &LaneDir, lane: &LaneId, snapshot: &Snapshot) -> (Option<u32>, Vec<PathBuf>) {
    let vm_id = lanes.load(lane).ok().flatten().map(|file| file.vm_id);
    let vm = vm_id.and_then(|id| snapshot.vms.iter().find(|vm| vm.id == id));
    match vm {
        Some(vm) => (
            Some(vm.ram_mib),
            vm.recording_root.iter().cloned().collect(),
        ),
        None => (None, Vec::new()),
    }
}

/// One lane's engine, as the caller started it.
pub struct LaneEngine<E> {
    pub lane: LaneId,
    /// The options the engine was started with (its data folder among them).
    pub options: BackendOptions,
    pub engine: E,
}

/// A lane being started: its engine connection and what its thread needs.
struct Starting<E: Engine> {
    lane: LaneId,
    options: BackendOptions,
    mux: Arc<Mux<E>>,
    waiter: Waiter<Handle<E>>,
    view: Arc<Mutex<EngineView>>,
}

impl<E: Engine + Send + 'static> Daemon<E> {
    /// Start everything with one lane (see the module text). The engine must
    /// own the data directory already.
    pub fn start(setup: Setup, engine: E) -> Result<Self, String> {
        let options = setup.options.clone();
        Self::start_lanes(
            setup,
            vec![LaneEngine {
                lane: LaneId::new(1),
                options,
                engine,
            }],
            Vec::new(),
        )
    }

    /// Start everything with the lanes the caller started engines for, lane
    /// 1 first (see the module text). `left_out` are the lanes `daemon.lanes`
    /// asked for that did not start, with why; they are logged and shown.
    pub fn start_lanes(
        setup: Setup,
        engines: Vec<LaneEngine<E>>,
        left_out: Vec<lanes::LeftOut>,
    ) -> Result<Self, String> {
        if !setup.config.notify.webhooks.is_empty() {
            return Err(crate::config::validate::WEBHOOKS_UNSUPPORTED.into());
        }
        if engines
            .first()
            .is_none_or(|first| first.lane != LaneId::new(1))
        {
            return Err("lane-1's engine must come first".into());
        }
        let log = Arc::clone(&setup.log);
        let data_dir = setup.options.data_dir.clone();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let controls = Arc::new(Controls::default());
        // One engine per lane. Lane 1's is shared by the lane and the host
        // workers (addendum card A): the lane's connection is made first, so
        // terminal output and results of no known command go to it.
        let mut starting = Vec::new();
        for LaneEngine {
            lane,
            options,
            engine,
        } in engines
        {
            let view = Arc::new(Mutex::new(EngineView::default()));
            let mux = Mux::new(engine);
            let mut waiter = Waiter::new(mux.handle(), Arc::clone(&clock));
            {
                let view = Arc::clone(&view);
                let clock = Arc::clone(&clock);
                waiter.observe(move |snapshot| update_view(&view, snapshot, clock.now_ms()));
                let controls = Arc::clone(&controls);
                waiter.interrupt_when(move || controls.interrupted());
            }
            waiter
                .first_snapshot(Duration::from_secs(30))
                .map_err(|e| format!("the engine of {lane} did not start: {e}"))?;
            update_view(&view, waiter.snapshot(), clock.now_ms());
            starting.push(Starting {
                lane,
                options,
                mux,
                waiter,
                view,
            });
        }

        let service_dir = data_dir.join("service");
        let store = Arc::new(Store::open(&service_dir).map_err(|e| e.message)?);
        let lanes = LaneDir::new(&service_dir);
        let report = crate::config::validate::load(&data_dir, &DiskVms::open(&data_dir), None);
        for problem in &report.problems {
            log(&format!(
                "config {:?}: {}:{} {}",
                problem.severity,
                problem.file,
                problem.line.unwrap_or(0),
                problem.message
            ));
        }
        let policies = Arc::new(SharedPolicies::new(PolicySet::new(report.policies)));
        if starting.len() > 1 || !left_out.is_empty() {
            let started: Vec<&str> = starting.iter().map(|s| s.lane.as_str()).collect();
            let mut line = format!(
                "lanes: {} of {} started ({})",
                starting.len(),
                setup.config.daemon.lanes,
                started.join(", ")
            );
            for left in &left_out {
                line.push_str(&format!("; {} not started: {}", left.lane, left.reason));
            }
            log(&line);
        }

        // Recovery: the store once, then each lane on its own engine; a lane
        // with a file that does not start gets the part that needs no engine.
        let recovered =
            recover_store(&store, &lanes).map_err(|e| format!("recovery failed: {e}"))?;
        let mut resume_ids = Vec::new();
        for pending in recovered.pending {
            let lane = match starting.iter_mut().find(|s| s.lane == pending.lane) {
                Some(lane) => recover_lane_with(
                    &store,
                    &lanes,
                    &mut lane.waiter,
                    &ProcFs,
                    &RecoverOptions::default(),
                    pending,
                ),
                None => recover_unstarted(&store, &lanes, &ProcFs, pending, clock.now_ms()),
            }
            .map_err(|e| format!("recovery failed: {e}"))?;
            if let Some(lane) = lane {
                resume_ids.extend(lane.resume);
            }
        }
        let mut resume = Vec::new();
        for id in &resume_ids {
            if let Ok(job) = store.get(id) {
                resume.push(job);
            }
        }
        // They go back to the host work pool in the order they arrived (first
        // come, first served), whatever lane collected them.
        resume.sort_by(|a, b| (a.created_ms, &a.id).cmp(&(b.created_ms, &b.id)));
        log(&format!(
            "recovery: {} job(s) back in the queue, {} to resume at analyse",
            recovered.jobs.requeued.len() + recovered.jobs.failed.len(),
            resume.len()
        ));

        // Each lane's VM: its RAM (the floors, the intake's estimate) and its
        // recording roots.
        let mut vms = Vec::new();
        for lane in &starting {
            vms.push(lane_vm(&lanes, &lane.lane, lane.waiter.snapshot()));
        }
        let lane_ram = vms.iter().filter_map(|(ram, _)| *ram).max();
        let (staging, _) = StagingStore::open(
            &setup.config.inbox_dir(&data_dir),
            &data_dir,
            Arc::clone(&clock),
            antinomie_monitor_core::samples::MAX_SAMPLE,
        )?;
        let staging = Arc::new(staging);
        let intake = Arc::new(Intake::new(&data_dir, Arc::clone(&staging), lane_ram));
        let query = QueryService::with_settings(
            setup.options.clone(),
            crate::query::limits::QuerySettings::from_config(&setup.config),
        )
        .with_layers(Arc::new(ViewLayers(
            starting.iter().map(|s| Arc::clone(&s.view)).collect(),
        )))
        .with_jobs(Arc::new(crate::store::job_index::StoreJobIndex::new(
            Arc::clone(&store),
        )))
        .with_audit(Arc::clone(&log));
        if setup.config.queue.paused_on_start {
            store
                .set_pause(Some(crate::api::status::PauseReason::Operator))
                .map_err(|e| e.message)?;
        }
        let kvm = rustix::fs::access(
            "/dev/kvm",
            rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
        )
        .is_ok();
        let address_lookup = setup.config.privacy.address_lookup.triage_mode();
        let lane_options: Vec<(LaneId, BackendOptions)> = starting
            .iter()
            .map(|s| (s.lane.clone(), s.options.clone()))
            .collect();
        let pool = HostPool::new(PoolEnv {
            store: Arc::clone(&store),
            lanes: LaneDir::new(&service_dir),
            policies: Arc::clone(&policies) as Arc<dyn crate::config::PolicyLookup>,
            triage: Arc::new(
                RealTriage::new(setup.options.clone())
                    .with_address_lookup(address_lookup)
                    .with_lanes(lane_options.clone()),
            ),
            tags: Arc::new(LibraryTags {
                data_dir: data_dir.clone(),
            }),
            evidence: crate::waiter::load_artifacts,
            data_dir: data_dir.clone(),
            probes: Arc::new(SystemProbes {
                pause_file: data_dir.join("run").join("PAUSE"),
            }),
            floor_mib: ITEM_FLOOR_MIB,
            controls: Arc::clone(&controls),
            clock: Arc::clone(&clock),
            log: Arc::clone(&log),
            workers: setup.config.host_workers(),
            timing: Timing {
                factor: setup.config.host_time_factor(),
                medians: Medians::load(&service_dir.join("host-times.json")),
            },
        });
        // Each lane's own floors (4.6.3): its VM's RAM plus the headroom, the
        // data folder and its recording roots.
        let mut receivers = Vec::new();
        let mut slots = Vec::new();
        let board = Arc::new(board::LaneBoard::default());
        for (lane, (ram, roots)) in starting.iter().zip(&vms) {
            let (wake_tx, wake_rx) = mpsc::channel();
            let (command_tx, command_rx) = mpsc::channel();
            board.join(&lane.lane, wake_tx.clone());
            let floors = Floors::of(
                &setup.config.resources,
                ram.unwrap_or(0),
                std::iter::once(data_dir.clone())
                    .chain(roots.iter().cloned())
                    .collect(),
                setup.options.capture_quota_size,
            );
            receivers.push((wake_rx, command_rx, floors));
            let mut slot = service::LaneSlot::new(
                lane.lane.clone(),
                lane.options.data_dir.clone(),
                wake_tx,
                command_tx,
            );
            slot.view = Arc::clone(&lane.view);
            slots.push(slot);
        }
        // The governor pauses the whole queue (disk, KVM, the PAUSE file),
        // watching every lane's disks. Every lane's loop runs one before it
        // claims a job, so a busy lane 1 does not keep the other lanes from
        // seeing a pause or its end; they take turns through one share.
        let all_disks: Vec<PathBuf> = {
            let mut all: Vec<PathBuf> = Vec::new();
            for (_, _, floors) in &receivers {
                for path in &floors.disk_paths {
                    if !all.contains(path) {
                        all.push(path.clone());
                    }
                }
            }
            all
        };
        let several = slots.len() > 1;
        let service = Arc::new(Service {
            data_dir: data_dir.clone(),
            options: setup.options.clone(),
            config: RwLock::new(setup.config.clone()),
            store: Arc::clone(&store),
            policies,
            intake,
            lanes,
            query,
            owner: setup.owner,
            slots,
            board: Arc::clone(&board),
            left_out,
            controls,
            accelerator: if kvm && !setup.options.force_tcg {
                Accelerator::Kvm
            } else {
                Accelerator::Tcg
            },
            watch: Default::default(),
            gc_lock: Mutex::new(()),
            log: Arc::clone(&log),
            pool: Some(Arc::clone(&pool)),
        });

        // The socket is bound before the lanes start, so a socket that cannot
        // be served stops the start with nothing running.
        let server = match &setup.socket {
            Some(path) => {
                let handler: Arc<dyn Handler> = Arc::clone(&service) as Arc<dyn Handler>;
                Some(
                    Server::bind(path, handler, setup.limits.clone())
                        .map_err(|e| format!("the socket cannot be served: {e}"))?,
                )
            }
            None => None,
        };

        let mut lane_threads = Vec::new();
        let mut first_mux = None;
        let governor_share = GovernorShare::default();
        let mut resume = Some(resume);
        for (index, (lane, (wake_rx, command_rx, floors))) in
            starting.into_iter().zip(receivers).enumerate()
        {
            let first = index == 0;
            let mut whole = floors.clone();
            whole.disk_paths = all_disks.clone();
            let governor_floors = Some(whole);
            if first {
                first_mux = Some(Arc::clone(&lane.mux));
            }
            let governor_share = Arc::clone(&governor_share);
            let service = Arc::clone(&service);
            let log = Arc::clone(&log);
            let jobs = if first {
                resume.take().unwrap_or_default()
            } else {
                Vec::new()
            };
            let Starting {
                lane: id,
                options,
                waiter,
                ..
            } = lane;
            let name = id.to_string();
            let lane_id = id.clone();
            let thread = std::thread::Builder::new()
                .name(format!("antinomie-{name}"))
                .spawn(move || {
                    let run = LaneRun {
                        lane: id,
                        data_dir: options.data_dir.clone(),
                        options,
                        floors,
                        governor: governor_floors,
                        governor_share,
                        upkeep: first,
                        several,
                    };
                    lane_main(&service, waiter, run, &jobs, &wake_rx, &command_rx, &*log)
                })
                .map_err(|e| format!("no thread for {name}: {e}"))?;
            lane_threads.push((lane_id, thread));
        }
        let first_mux = first_mux.expect("lane-1 comes first");
        let mut workers = Vec::new();
        for index in 0..pool.workers() {
            let mut waiter = Waiter::new(first_mux.handle(), Arc::clone(&clock));
            let controls = Arc::clone(&service.controls);
            waiter.interrupt_when(move || controls.interrupted());
            let pool = Arc::clone(&pool);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("antinomie-host-{index}"))
                    .spawn(move || pool.work(&mut waiter))
                    .map_err(|e| format!("no thread for a host worker: {e}"))?,
            );
        }
        // Each engine comes back through its lane's connection once every
        // other connection is closed (`finish`).
        drop(first_mux);
        let server = server.map(|server| {
            let handle = server.stop_handle();
            let thread = std::thread::spawn(move || server.serve());
            (handle, thread)
        });
        let mut helpers = Vec::new();
        // Direct mode runs one job in the command itself: it takes no files
        // from watch folders and cleans nothing up.
        if setup.socket.is_some() {
            let watch = Arc::clone(&service);
            helpers.push(
                std::thread::Builder::new()
                    .name("antinomie-watch".into())
                    .spawn(move || watch_env::run(watch))
                    .map_err(|e| format!("no thread for the watch folders: {e}"))?,
            );
            let gc = Arc::clone(&service);
            helpers.push(
                std::thread::Builder::new()
                    .name("antinomie-gc".into())
                    .spawn(move || housekeeping::run(gc))
                    .map_err(|e| format!("no thread for retention: {e}"))?,
            );
        }
        let notify = Arc::clone(&service);
        helpers.push(
            std::thread::Builder::new()
                .name("antinomie-notify".into())
                .spawn(move || notify_thread::run(notify))
                .map_err(|e| format!("no thread for delivery: {e}"))?,
        );
        log(&format!(
            "daemon ready: data {} socket {}",
            data_dir.display(),
            setup
                .socket
                .as_ref()
                .map_or("none".into(), |p| p.display().to_string())
        ));
        Ok(Self {
            service,
            lanes: lane_threads,
            workers,
            server,
            helpers,
            log,
            host_grace: setup.host_grace,
        })
    }

    pub fn service(&self) -> &Arc<Service> {
        &self.service
    }

    /// Run until a stop (a signal, or `until` turning true) has been carried
    /// through and the lane's thread has ended.
    pub fn supervise(&mut self, signals: &dyn Signals, until: &dyn Fn(&Service) -> bool) -> Exit {
        let service = Arc::clone(&self.service);
        let mut stopping = Stopping::default();
        let mut hurried = false;
        let mut first_stop: Option<Instant> = None;
        loop {
            let now = Instant::now();
            for signal in signals.take() {
                match signal {
                    Signal::Stop => match first_stop {
                        Some(at) if now.duration_since(at) < Duration::from_secs(5) => {
                            (self.log)("second stop signal: interrupting now");
                            hurried = true;
                            service.controls.interrupt();
                        }
                        Some(_) => {}
                        None => {
                            (self.log)("stopping: no new jobs; queued jobs stay queued");
                            first_stop = Some(now);
                            service.controls.begin_stop();
                        }
                    },
                    Signal::Reload => self.reload(),
                    Signal::Status => match service.queue_status() {
                        Ok(status) => (self.log)(&format!(
                            "status: {}",
                            serde_json::to_string(&status).unwrap_or_default()
                        )),
                        Err(error) => (self.log)(&format!("status: {error}")),
                    },
                }
            }
            if !service.controls.stopping() && until(&service) {
                service.controls.begin_stop();
            }
            if service.controls.stopping()
                && !hurried
                && let Some(line) = shutdown_step(&service, &mut stopping, self.host_grace, now)
            {
                (self.log)(&line);
            }
            // One lane's engine gone stops the daemon: the others finish what
            // they can, and the unit starts the daemon again (recovery).
            if self.lanes.len() > 1
                && service.controls.engine_is_lost()
                && !service.controls.stopping()
            {
                (self.log)("an engine has stopped: stopping the daemon");
                service.controls.begin_stop();
            }
            if self.lanes.iter().all(|(_, t)| t.is_finished())
                && self.workers.iter().all(|t| t.is_finished())
            {
                break;
            }
            // Wake the lanes so an idle one sees the stop at once.
            if service.controls.stopping() {
                service.wake_lane();
                if let Some(pool) = &service.pool {
                    pool.poke();
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if hurried {
            Exit::Hurried
        } else if service.controls.engine_is_lost() {
            Exit::EngineLost
        } else {
            Exit::Clean
        }
    }

    fn reload(&self) {
        let service = &self.service;
        match service
            .policies
            .reload(&service.data_dir, &DiskVms::open(&service.data_dir))
        {
            Ok(count) => (self.log)(&format!("reload: {count} polic(ies) loaded")),
            Err(problems) => (self.log)(&format!(
                "reload refused, the old policies stay: {}",
                problems
                    .iter()
                    .map(|p| format!("{}: {}", p.file, p.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            )),
        }
        let path = service.data_dir.join("service.toml");
        if let Ok(text) = std::fs::read_to_string(&path) {
            match crate::config::validate::parse_service("service.toml", &text) {
                (Some(mut config), problems)
                    if !problems
                        .iter()
                        .any(|p| p.severity == crate::config::Severity::Error) =>
                {
                    let mut current = service.config.write().unwrap_or_else(|p| p.into_inner());
                    // The socket is not changed by a reload (2.7).
                    config.daemon.socket = current.daemon.socket.clone();
                    *current = config;
                    (self.log)("reload: service.toml read again");
                }
                _ => (self.log)("reload: service.toml has errors; the old settings stay"),
            }
        }
    }

    /// Stop the socket, join the lane, and hand the engine back for its
    /// shutdown (which stops a running VM and releases the data directory).
    /// With several lanes the other lanes' engines are dropped; a front end
    /// that started them uses [`finish_lanes`](Self::finish_lanes).
    pub fn finish(self) -> Result<E, ApiError> {
        self.finish_lanes()?
            .into_iter()
            .next()
            .map(|(_, engine)| engine)
            .ok_or_else(|| ApiError::new(crate::api::error::ErrorCode::Internal, "no lane"))
    }

    /// Stop the socket, join every lane, and hand every lane's engine back
    /// for its shutdown, lane 1 first.
    pub fn finish_lanes(mut self) -> Result<Vec<(LaneId, E)>, ApiError> {
        if let Some((handle, thread)) = self.server.take() {
            handle.stop();
            let _ = thread.join();
        }
        self.service.controls.begin_stop();
        self.service.wake_lane();
        let mut waiters = Vec::new();
        for (lane, thread) in self.lanes.drain(..) {
            waiters.push((lane, thread.join()));
        }
        if let Some(pool) = &self.service.pool {
            pool.poke();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        // Nothing more can finish; the helpers end (delivery after it has
        // handled what the lanes' last jobs produced).
        self.service.controls.lane_ended();
        for helper in self.helpers.drain(..) {
            let _ = helper.join();
        }
        let mut engines = Vec::new();
        let mut failed = None;
        for (lane, waiter) in waiters {
            match waiter {
                Ok(waiter) => match waiter.into_engine().into_engine() {
                    Ok(engine) => engines.push((lane, engine)),
                    Err(error) => failed = Some(format!("{lane}: {error}")),
                },
                Err(_) => failed = Some(format!("the thread of {lane} panicked")),
            }
        }
        (self.log)("daemon stopped");
        match failed {
            Some(error) if engines.is_empty() => {
                Err(ApiError::new(crate::api::error::ErrorCode::Internal, error))
            }
            Some(error) => {
                (self.log)(&format!("an engine was not handed back: {error}"));
                Ok(engines)
            }
            None => Ok(engines),
        }
    }
}

/// What one lane's thread runs with.
struct LaneRun {
    lane: LaneId,
    /// The lane's data folder (the library its launch stages a host copy
    /// from resolves into lane 1's).
    data_dir: PathBuf,
    options: BackendOptions,
    floors: Floors,
    /// The governor's floors (every lane's disks).
    governor: Option<Floors>,
    /// What the lanes' governors share (their turns, the last alert).
    governor_share: GovernorShare,
    /// The wait expiry and the janitor run here (the first lane).
    upkeep: bool,
    /// The daemon runs more than one lane: the lanes choose on the board.
    several: bool,
}

fn lane_main<E: Engine>(
    service: &Service,
    waiter: Waiter<E>,
    run: LaneRun,
    resume: &[crate::api::job::Job],
    wake: &mpsc::Receiver<()>,
    commands: &mpsc::Receiver<lane::LaneCommand>,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Waiter<E> {
    let LaneRun {
        lane,
        data_dir,
        options,
        floors,
        governor,
        governor_share,
        upkeep,
        several,
    } = run;
    let Some(slot) = service.slot(&lane) else {
        return waiter;
    };
    let probes = SystemProbes {
        pause_file: service.data_dir.join("run").join("PAUSE"),
    };
    let host = ResourceChecks {
        floors,
        probes: &probes,
    };
    let governor = governor.map(|floors| {
        Governor::new(
            ResourceChecks {
                floors,
                probes: &probes,
            },
            &service.store,
        )
        .shared(governor_share)
    });
    let address_lookup = service
        .config
        .read()
        .map(|config| config.privacy.address_lookup.triage_mode())
        .unwrap_or_default();
    let triage = RealTriage::new(service.options.clone())
        .with_address_lookup(address_lookup)
        .with_lanes(vec![(lane.clone(), options)]);
    let tags = LibraryTags {
        data_dir: service.data_dir.clone(),
    };
    let procs = ProcFs;
    let mut runner = StagesRunner {
        waiter,
        env: RunnerEnv {
            store: &service.store,
            lanes: &service.lanes,
            policies: &*service.policies,
            procs: &procs,
            host: &host,
            triage: &triage,
            tags: &tags,
            data_dir: &data_dir,
        },
        lane: lane.clone(),
        governor,
        log,
        pool: service.pool.as_deref(),
    };
    let staging = Arc::clone(&service.intake);
    let store = Arc::clone(&service.store);
    let mut janitor = move || {
        staging.staging().expire();
        let _ = store.expire_idempotency_keys();
        let _ = store.prune_engine_events();
    };
    let mut lane_loop = LaneLoop {
        lane: lane.clone(),
        store: &service.store,
        controls: &service.controls,
        phase: &slot.phase,
        wake,
        commands,
        clock: Arc::new(SystemClock),
        periods: Periods::default(),
        janitor: &mut janitor,
        log,
        board: several.then_some(&*service.board),
        upkeep,
    };
    lane_loop.run(&mut runner, resume);
    service.board.leave(&lane);
    runner.into_waiter()
}
