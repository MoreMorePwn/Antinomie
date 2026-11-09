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
//! Signals (2.7), as the supervisor sees them through [`Signals`]:
//!
//! | Signal | What happens |
//! |---|---|
//! | first `SIGTERM`/`SIGINT` | No new submissions (`unavailable`, reason `service_stopping`); queued jobs stay queued. A job in its lane stages is cancelled for shutdown and goes back to the queue with the attempt not counted (`shutdown = drain`: after `drain_timeout_s`). A job in its host stages (`analyse`, `report`, `cleanup`) is let finish for up to `shutdown_host_grace_s` (120 s); past that its waits are interrupted and recovery resumes it at `analyse` on the next start. |
//! | a second one within 5 s | Every wait is interrupted now; the engine stops the VM; exit 130. Recovery finishes the rest. |
//! | `SIGHUP` | `policies/` and `service.toml` are read again (the socket stays); a failing reload keeps the old set. Running and queued jobs keep the policy they were frozen with. |
//! | `SIGUSR1` | The queue's state is written to the log. |

pub mod artifacts;
mod housekeeping;
pub mod lane;
mod lane_ops;
mod notify_thread;
#[cfg(test)]
mod p4_tests;
pub mod runner;
pub mod service;
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
    engine::Engine,
    intake::{Intake, staging::StagingStore},
    lane::{
        LaneDir, ProcFs,
        recover::{RecoverOptions, recover_startup},
    },
    query::{QueryService, phase::LayerSource},
    resources::{Floors, Governor, ResourceChecks, SystemProbes},
    server::{Handler, Server, StopHandle, limits::Limits},
    stages::host::{LibraryTags, RealTriage},
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
    /// `analyse` to `cleanup`: host work only.
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
    /// VMs, their snapshot trees, the VM state, the recording flush.
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
        ..Snapshot::default()
    };
}

/// The engine's disk layers for the recording reads (5.12.2).
struct ViewLayers(Arc<Mutex<EngineView>>);

impl LayerSource for ViewLayers {
    fn layers(&self) -> Vec<DiskLayer> {
        crate::store::lock(&self.0).disk_layers.clone()
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
    lane: Option<JoinHandle<Waiter<E>>>,
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
    let phase = crate::store::lock(&service.phase);
    match &*phase {
        Phase::Lane(job) if !state.cancelled.contains(job) => {
            if mode == Shutdown::Drain && now.duration_since(since) < drain {
                return None;
            }
            state.cancelled.insert(job.clone());
            match service.store.cancel_for_shutdown(job) {
                Ok(_) => Some(format!(
                    "job={job} is in its lane stages: cancelled for shutdown, it goes back to the queue"
                )),
                Err(error) => Some(format!("job={job}: cancel for shutdown: {error}")),
            }
        }
        Phase::Host(job) if !state.interrupted => {
            let limit = match mode {
                Shutdown::Drain => host_grace.max(drain),
                Shutdown::Cancel => host_grace,
            };
            if now.duration_since(since) < limit {
                return None;
            }
            state.interrupted = true;
            service.controls.interrupt();
            Some(format!(
                "job={job} did not finish its host stages within {} s; it resumes at analyse on the next start",
                limit.as_secs()
            ))
        }
        _ => None,
    }
}

fn first_lane(lanes: &LaneDir) -> LaneId {
    lanes
        .lanes()
        .ok()
        .and_then(|list| list.into_iter().next())
        .unwrap_or_else(|| LaneId::new(1))
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

impl<E: Engine + Send + 'static> Daemon<E> {
    /// Start everything (see the module text). The engine must own the data
    /// directory already.
    pub fn start(setup: Setup, engine: E) -> Result<Self, String> {
        let log = Arc::clone(&setup.log);
        let data_dir = setup.options.data_dir.clone();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let controls = Arc::new(Controls::default());
        let view = Arc::new(Mutex::new(EngineView::default()));
        let mut waiter = Waiter::new(engine, Arc::clone(&clock));
        {
            let view = Arc::clone(&view);
            let clock = Arc::clone(&clock);
            waiter.observe(move |snapshot| update_view(&view, snapshot, clock.now_ms()));
            let controls = Arc::clone(&controls);
            waiter.interrupt_when(move || controls.interrupted());
        }
        waiter
            .first_snapshot(Duration::from_secs(30))
            .map_err(|e| format!("the engine did not start: {e}"))?;
        update_view(&view, waiter.snapshot(), clock.now_ms());

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

        let recovery = recover_startup(
            &store,
            &lanes,
            &mut waiter,
            &ProcFs,
            &RecoverOptions::default(),
        )
        .map_err(|e| format!("recovery failed: {e}"))?;
        let mut resume = Vec::new();
        for lane in &recovery.lanes {
            for id in &lane.resume {
                if let Ok(job) = store.get(id) {
                    resume.push(job);
                }
            }
        }
        log(&format!(
            "recovery: {} job(s) back in the queue, {} to resume at analyse",
            recovery.jobs.requeued.len() + recovery.jobs.failed.len(),
            resume.len()
        ));

        let lane = first_lane(&lanes);
        let (lane_ram, recording_roots) = lane_vm(&lanes, &lane, waiter.snapshot());
        let (staging, _) = StagingStore::open(
            &setup.config.inbox_dir(&data_dir),
            &data_dir,
            Arc::clone(&clock),
            antinomie_monitor_core::samples::MAX_SAMPLE,
        )?;
        let staging = Arc::new(staging);
        let intake = Arc::new(Intake::new(&data_dir, Arc::clone(&staging), lane_ram));
        let query = QueryService::new(setup.options.clone())
            .with_layers(Arc::new(ViewLayers(Arc::clone(&view))));
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
        let (wake_tx, wake_rx) = mpsc::channel();
        let (command_tx, command_rx) = mpsc::channel();
        let floors = Floors::of(
            &setup.config.resources,
            lane_ram.unwrap_or(0),
            std::iter::once(data_dir.clone())
                .chain(recording_roots)
                .collect(),
            setup.options.capture_quota_size,
        );
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
            view,
            phase: Arc::new(Mutex::new(Phase::Idle)),
            controls,
            wake: Mutex::new(wake_tx),
            commands: Mutex::new(command_tx),
            accelerator: if kvm && !setup.options.force_tcg {
                Accelerator::Kvm
            } else {
                Accelerator::Tcg
            },
            watch: Default::default(),
            gc_lock: Mutex::new(()),
            log: Arc::clone(&log),
        });

        // The socket is bound before the lane starts, so a socket that cannot
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

        let lane_thread = {
            let service = Arc::clone(&service);
            let log = Arc::clone(&log);
            std::thread::Builder::new()
                .name("antinomie-lane".into())
                .spawn(move || {
                    lane_main(
                        &service,
                        waiter,
                        lane,
                        floors,
                        &resume,
                        &wake_rx,
                        &command_rx,
                        &*log,
                    )
                })
                .map_err(|e| format!("no thread for the lane: {e}"))?
        };
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
            lane: Some(lane_thread),
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
            if self.lane.as_ref().is_none_or(|t| t.is_finished()) {
                break;
            }
            // Wake the lane so an idle one sees the stop at once.
            if service.controls.stopping() {
                let _ = crate::store::lock(&service.wake).send(());
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
    pub fn finish(mut self) -> Result<E, ApiError> {
        if let Some((handle, thread)) = self.server.take() {
            handle.stop();
            let _ = thread.join();
        }
        self.service.controls.begin_stop();
        let _ = crate::store::lock(&self.service.wake).send(());
        let thread = self.lane.take().expect("the lane thread is joined once");
        let waiter = thread.join();
        // Nothing more can finish; the helpers end (delivery after it has
        // handled what the lane's last jobs produced).
        self.service.controls.lane_ended();
        for helper in self.helpers.drain(..) {
            let _ = helper.join();
        }
        let waiter = waiter.map_err(|_| {
            ApiError::new(
                crate::api::error::ErrorCode::Internal,
                "the lane thread panicked",
            )
        })?;
        (self.log)("daemon stopped");
        Ok(waiter.into_engine())
    }
}

#[allow(clippy::too_many_arguments)]
fn lane_main<E: Engine>(
    service: &Service,
    waiter: Waiter<E>,
    lane: LaneId,
    floors: Floors,
    resume: &[crate::api::job::Job],
    wake: &mpsc::Receiver<()>,
    commands: &mpsc::Receiver<lane::LaneCommand>,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Waiter<E> {
    let probes = SystemProbes {
        pause_file: service.data_dir.join("run").join("PAUSE"),
    };
    let host = ResourceChecks {
        floors: floors.clone(),
        probes: &probes,
    };
    let governor = Governor::new(
        ResourceChecks {
            floors,
            probes: &probes,
        },
        &service.store,
    );
    let triage = RealTriage::new(service.options.clone());
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
        },
        lane: lane.clone(),
        governor: Some(governor),
        log,
    };
    let staging = Arc::clone(&service.intake);
    let store = Arc::clone(&service.store);
    let mut janitor = move || {
        staging.staging().expire();
        let _ = store.expire_idempotency_keys();
        let _ = store.prune_engine_events();
    };
    let mut lane_loop = LaneLoop {
        lane,
        store: &service.store,
        controls: &service.controls,
        phase: &service.phase,
        wake,
        commands,
        clock: Arc::new(SystemClock),
        periods: Periods::default(),
        janitor: &mut janitor,
        log,
    };
    lane_loop.run(&mut runner, resume);
    runner.into_waiter()
}
