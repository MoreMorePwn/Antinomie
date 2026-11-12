// SPDX-License-Identifier: GPL-3.0-only
//! The operations of design 5.3 as the daemon serves them: the
//! [`Handler`](crate::server::Handler) behind the socket, and what direct
//! mode calls in-process.
//!
//! Every request is parsed with the contract's own types (unknown members are
//! refused, with the member named), checked against the op's scope (5.8),
//! then served from the job store, the staging store, the policies, the lane
//! and the recording reads. `sample.path` is honoured only for a caller in
//! the same process: over the socket a file arrives through `upload.*`, so no
//! client can make the daemon open a path of its choosing.

use super::{Controls, EngineView, Phase, artifacts, lane::LaneCommand};
use crate::api::ids::LaneId;
use crate::{
    api::{
        error::{ApiError, ErrorCode, ErrorReason},
        event::{Hello, HelloOwner, LaneState},
        ops::*,
        spec::{JobSpec, ReportFormat, Route, StaticCheck},
        status::*,
    },
    config::{ServiceConfig, SharedPolicies},
    intake::Intake,
    lane::LaneDir,
    query::{QueryApi, QueryService, context::ReadContext, request::RecordingRead},
    server::{CallContext, Handler, Transport, b64},
    store::{Store, SubmitContext, SubmitLimits},
};
use antinomie_monitor_core::BackendOptions;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, RwLock, mpsc},
    time::Duration,
};

/// One lane the daemon runs: its engine's view, what it is doing, and how
/// to reach its thread (ANT-T0455 card C: one per lane).
pub struct LaneSlot {
    pub lane: LaneId,
    /// The lane's data folder (lane 1's for `lane-1`, `<data>/lanes/N/` for
    /// `lane-N`).
    pub data_dir: PathBuf,
    pub view: Arc<Mutex<EngineView>>,
    pub phase: Arc<Mutex<Phase>>,
    pub wake: Mutex<mpsc::Sender<()>>,
    pub commands: Mutex<mpsc::Sender<LaneCommand>>,
}

impl LaneSlot {
    pub fn new(
        lane: LaneId,
        data_dir: PathBuf,
        wake: mpsc::Sender<()>,
        commands: mpsc::Sender<LaneCommand>,
    ) -> Self {
        Self {
            lane,
            data_dir,
            view: Arc::new(Mutex::new(EngineView::default())),
            phase: Arc::new(Mutex::new(Phase::Idle)),
            wake: Mutex::new(wake),
            commands: Mutex::new(commands),
        }
    }
}

/// The daemon's state, shared by the socket threads and the supervisor.
pub struct Service {
    pub data_dir: PathBuf,
    pub options: BackendOptions,
    pub config: RwLock<ServiceConfig>,
    pub store: Arc<Store>,
    pub policies: Arc<SharedPolicies>,
    pub intake: Arc<Intake>,
    pub lanes: LaneDir,
    pub query: QueryService,
    pub owner: Owner,
    /// The lanes that run, lane 1 first (one unless `daemon.lanes` asks for
    /// more).
    pub slots: Vec<LaneSlot>,
    /// The lane choice between the lanes.
    pub board: Arc<super::board::LaneBoard>,
    /// The lanes `daemon.lanes` asked for that did not start, and why.
    pub left_out: Vec<super::lanes::LeftOut>,
    pub controls: Arc<Controls>,
    pub accelerator: Accelerator,
    pub watch: crate::watch::WatchHub,
    /// One retention pass or `job.delete` at a time.
    pub gc_lock: Mutex<()>,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
    /// The host work pool (ANT-T0454); `None` in tests that run no lane.
    pub pool: Option<Arc<crate::pool::HostPool>>,
}

/// Parse the parameters of an op; an unknown member is named in `field`.
pub(crate) fn params<T: DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|error| {
        let text = error.to_string();
        let field = text
            .split_once("unknown field `")
            .and_then(|(_, rest)| rest.split_once('`'))
            .map(|(name, _)| name.to_owned())
            .or_else(|| {
                text.split_once("missing field `")
                    .and_then(|(_, rest)| rest.split_once('`'))
                    .map(|(name, _)| name.to_owned())
            })
            .unwrap_or_else(|| "params".into());
        ApiError::invalid_argument(&field, text)
    })
}

pub(crate) fn to_value(value: &impl Serialize) -> Result<Value, ApiError> {
    serde_json::to_value(value)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reply: {e}")))
}

fn forbidden(scope: Scope) -> ApiError {
    let name = to_value(&scope)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned));
    ApiError::new(
        ErrorCode::Forbidden,
        format!(
            "this operation needs the {} scope",
            name.unwrap_or_default()
        ),
    )
}

/// The names 5.11 reserves for a later contract version.
fn reserved(op: &str) -> bool {
    ["run.", "terminal.", "rule.", "settings.", "vm.", "base."]
        .iter()
        .any(|prefix| op.starts_with(prefix))
        && !matches!(op, "vm.list" | "base.list")
}

/// Ops that start work: refused while the daemon stops.
fn starts_work(op: Op) -> bool {
    matches!(
        op,
        Op::JobSubmit | Op::JobRetry | Op::UploadBegin | Op::UploadPut | Op::UploadFinish
    )
}

impl Service {
    /// Wake every lane's loop.
    pub(super) fn wake_lane(&self) {
        for slot in &self.slots {
            let _ = crate::store::lock(&slot.wake).send(());
        }
    }

    /// The lane that runs as `lane`.
    pub fn slot(&self, lane: &LaneId) -> Option<&LaneSlot> {
        self.slots.iter().find(|slot| &slot.lane == lane)
    }

    /// The first lane's engine view (lane 1's: the shared bases, the
    /// accelerator).
    pub fn first_view(&self) -> EngineView {
        self.slots
            .first()
            .map(|slot| crate::store::lock(&slot.view).clone())
            .unwrap_or_default()
    }

    /// The VMs of every lane's engine, lane 1's first.
    pub(super) fn all_vms(&self) -> Vec<antinomie_monitor_core::VmConfig> {
        let mut vms: Vec<antinomie_monitor_core::VmConfig> = Vec::new();
        for slot in &self.slots {
            for vm in &crate::store::lock(&slot.view).lanes.vms {
                if !vms.iter().any(|known| known.id == vm.id) {
                    vms.push(vm.clone());
                }
            }
        }
        vms
    }

    /// The jobs the lanes are on now (lane or host stages, lane order).
    pub(super) fn phases(&self) -> Vec<(LaneId, Phase)> {
        self.slots
            .iter()
            .map(|slot| (slot.lane.clone(), crate::store::lock(&slot.phase).clone()))
            .collect()
    }

    pub(super) fn submit_context<'a>(
        &'a self,
        policies: &'a crate::config::PolicySet,
    ) -> SubmitContext<'a> {
        let config = self.config.read().unwrap_or_else(|p| p.into_inner());
        SubmitContext {
            policies,
            intake: &*self.intake,
            limits: SubmitLimits {
                max_queued: config.queue.max_queued,
                per_client_queued: config.queue.per_client_queued,
            },
            on_duplicate: None,
        }
    }

    fn submit(&self, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let spec: JobSpec = params(value)?;
        if spec.sample.path.is_some() && ctx.transport == Transport::Socket {
            return Err(ApiError::invalid_argument(
                "sample.path",
                "the daemon does not open files a client names; send the file with upload.begin, upload.put and upload.finish, then submit sample.upload_id",
            ));
        }
        let policies = self.policies.snapshot();
        let submitted = self
            .store
            .submit(&ctx.caller, spec, &self.submit_context(&policies))?;
        self.wake_lane();
        to_value(&submitted)
    }

    fn retry(&self, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let request: JobRetryParams = params(value)?;
        let policies = self.policies.snapshot();
        let submitted = self.store.retry(
            &ctx.caller,
            &request.job_id,
            request.overrides.as_ref(),
            &self.submit_context(&policies),
        )?;
        self.wake_lane();
        to_value(&submitted)
    }

    fn upload_put(&self, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let request: UploadPutParams = params(value)?;
        let bytes = b64::decode(
            request.data.as_bytes(),
            crate::intake::staging::MAX_CHUNK as usize,
        )
        .map_err(|e| match e {
            b64::DecodeError::TooLarge => {
                ApiError::payload_too_large(crate::intake::staging::MAX_CHUNK).with_field("data")
            }
            other => ApiError::invalid_argument("data", format!("not Base64: {other}")),
        })?;
        let received = self.intake.staging().put(
            &ctx.caller.client_id,
            &request.upload_id,
            request.offset,
            &bytes,
        )?;
        to_value(&received)
    }

    pub(super) fn lane_statuses(&self) -> Vec<LaneStatus> {
        let first = self.first_view();
        let mut out = Vec::new();
        for lane in self.lanes.lanes().unwrap_or_default() {
            let file = self.lanes.load(&lane).ok().flatten();
            let slot = self.slot(&lane);
            let view = slot.map_or_else(
                || first.clone(),
                |slot| crate::store::lock(&slot.view).clone(),
            );
            // A lane that has a file but does not run in this daemon (beyond
            // `daemon.lanes`, or left out at start) is stopped.
            let phase = slot.map(|slot| crate::store::lock(&slot.phase).clone());
            let (state, job_id) = match (&file, &phase) {
                (Some(file), _) if file.is_quarantined() => (LaneState::Quarantined, None),
                (None, _) | (_, None) => (LaneState::Stopped, None),
                (_, Some(phase)) => match phase {
                    Phase::Lane(job) | Phase::Host(job) => (LaneState::Busy, Some(job.clone())),
                    Phase::Command(_) => (LaneState::Starting, None),
                    Phase::Idle if self.controls.stopping() => (LaneState::Stopped, None),
                    Phase::Idle => (LaneState::Idle, None),
                },
            };
            let vm_id = file.as_ref().map(|f| f.vm_id.clone());
            let pending = vm_id
                .as_ref()
                .is_some_and(|vm| view.disk_layers.iter().any(|l| &l.vm_id == vm));
            out.push(LaneStatus {
                lane,
                state,
                job_id,
                vm_id,
                since_ms: view.since_ms,
                disk_layer: if pending {
                    DiskLayer::Pending
                } else {
                    DiskLayer::None
                },
            });
        }
        out
    }

    pub fn queue_status(&self) -> Result<QueueStatus, ApiError> {
        let counts = self.store.counts()?;
        let pause_reason = self.store.pause_reason()?;
        let config = self.config.read().unwrap_or_else(|p| p.into_inner());
        Ok(QueueStatus {
            paused: pause_reason.is_some(),
            pause_reason,
            queued: counts.queued,
            running: counts.running,
            lanes: self.lane_statuses(),
            limits: QueueLimits {
                max_queue: config.queue.max_queued,
                max_concurrent: self.slots.len().max(1) as u32,
                per_client_queued: config.queue.per_client_queued,
            },
            owner: self.owner,
            host_pool: self
                .pool
                .as_ref()
                .map(|pool| pool.status())
                .unwrap_or_default(),
        })
    }

    pub fn health(&self) -> Result<HealthStatus, ApiError> {
        // The engines' counters, summed over the lanes.
        let mut view = EngineView::default();
        for slot in &self.slots {
            let lane = crate::store::lock(&slot.view);
            view.ui_dropped += lane.ui_dropped;
            view.shedding |= lane.shedding;
            view.reply_stalls += lane.reply_stalls;
            view.read_gaps.count += lane.read_gaps.count;
            view.read_gaps.total_ns += lane.read_gaps.total_ns;
            view.read_gaps.longest_ns = view.read_gaps.longest_ns.max(lane.read_gaps.longest_ns);
        }
        let lanes = self.lane_statuses();
        let counts = self.store.counts()?;
        let mut reasons = Vec::new();
        if self.controls.engine_is_lost() {
            reasons.push("the engine has stopped".to_owned());
        }
        if self.controls.stopping() {
            reasons.push("the daemon is stopping".to_owned());
        }
        if lanes.is_empty() {
            reasons.push("no lane is set up; run `antinomie-cli auto init`".to_owned());
        }
        // With several lanes a quarantined one keeps the node ready while
        // another running lane can take jobs; `lane_states` shows it.
        let running: Vec<&LaneStatus> = lanes
            .iter()
            .filter(|l| self.slot(&l.lane).is_some())
            .collect();
        if !running.is_empty() && running.iter().all(|l| l.state == LaneState::Quarantined) {
            reasons.push(if running.len() == 1 {
                "a lane is quarantined".to_owned()
            } else {
                "every lane is quarantined".to_owned()
            });
        }
        if let Some(reason) = self.store.pause_reason()? {
            reasons.push(format!("the queue is paused ({})", wire(&reason)));
        }
        let probes = crate::resources::SystemProbes {
            pause_file: self.data_dir.join("run").join("PAUSE"),
        };
        use crate::resources::Probes;
        let ok = !self.controls.engine_is_lost();
        Ok(HealthStatus {
            ok,
            ready: ok && reasons.is_empty(),
            owner: self.owner,
            reasons,
            engine: EngineHealth {
                ui_dropped: view.ui_dropped,
                shedding: view.shedding,
                reply_stalls: view.reply_stalls,
                read_gaps: view.read_gaps.clone(),
                lane_states: lanes.iter().map(|l| l.state).collect(),
                queue_depth: counts.queued,
                disk_free_gib: probes.free_gib(&self.data_dir).unwrap_or(0),
                ram_free_mib: probes.mem_available_mib().unwrap_or(0),
                accelerator: self.accelerator,
            },
        })
    }

    pub fn capabilities(&self, caller: &Caller) -> Capabilities {
        let set = self.policies.snapshot();
        let mut caps = Capabilities {
            api_version: crate::API_VERSION,
            app_version: antinomie_monitor_core::api::APP_VERSION.into(),
            app_revision: antinomie_monitor_core::api::APP_REVISION,
            lanes: self.slots.len().max(1) as u32,
            max_sample_bytes: 0,
            accept_types: Vec::new(),
            accept_arch: Vec::new(),
            routes: Vec::new(),
            report_formats: vec![
                ReportFormat::Html,
                ReportFormat::Pdf,
                ReportFormat::Json,
                ReportFormat::Misp,
                ReportFormat::Stix,
                ReportFormat::Md,
            ],
            static_checks: vec![
                StaticCheck::Metadata,
                StaticCheck::Structures,
                StaticCheck::Strings,
                StaticCheck::Regex,
                StaticCheck::Entropy,
                StaticCheck::Hardening,
                StaticCheck::Rules,
                StaticCheck::Identification,
                StaticCheck::Capabilities,
                StaticCheck::Disassembly,
                StaticCheck::Decompilation,
                StaticCheck::Embedded,
                StaticCheck::Floss,
                StaticCheck::Unpacking,
            ],
            detection: DetectionCaps {
                yara: true,
                sigma: true,
                ids: true,
            },
            ioc_datasets: antinomie_monitor_core::ioc::feeds::status(&self.data_dir)
                .into_iter()
                .filter(|feed| feed.usable())
                .map(|feed| IocDataset {
                    name: feed.feed.id.to_owned(),
                    entries: feed.meta.map_or(0, |meta| meta.records),
                })
                .collect(),
            accelerator: self.accelerator,
            queries: crate::query::ops::catalogue(self.query.limits()),
            features: vec![
                "upload.chunked".into(),
                "events.resume".into(),
                "recording.query".into(),
                "library.read".into(),
            ],
        };
        for name in set.names() {
            let Some(policy) = crate::config::PolicyLookup::get(&*set, name) else {
                continue;
            };
            if !policy.allows(&caller.client_id, Scope::Submit) {
                continue;
            }
            caps.max_sample_bytes = caps
                .max_sample_bytes
                .max(self.intake.max_sample_bytes(&policy));
            for kind in &policy.policy.sample.accept_types {
                if !caps.accept_types.contains(kind) {
                    caps.accept_types.push(kind.clone());
                }
            }
            for arch in &policy.policy.sample.accept_arch {
                if !caps.accept_arch.contains(arch) {
                    caps.accept_arch.push(arch.clone());
                }
            }
            for route in &policy.policy.network.allowed_routes {
                if matches!(route, Route::Drop | Route::InetSim) && !caps.routes.contains(route) {
                    caps.routes.push(*route);
                }
            }
        }
        caps
    }

    fn queue_pause(&self, pause: bool) -> Result<Value, ApiError> {
        if pause {
            self.store.set_pause(Some(PauseReason::Operator))?;
        } else if self.store.pause_reason()?.is_some() {
            // The governor pauses again within 5 s if a floor is still not met.
            self.store.set_pause(None)?;
            self.wake_lane();
        }
        to_value(&self.queue_status()?)
    }

    fn recording(&self, op: &str, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let request = RecordingRead::parse(op, value)?;
        let read = ReadContext {
            caller: ctx.caller.clone(),
            cancel: Arc::clone(&ctx.cancel),
            deadline: None,
        };
        let reply = self.query.read(request, &read)?;
        to_value(&reply)
    }

    /// A lane op: sent to the lane's thread (it owns the lane's engine) and
    /// answered when the lane is idle; a lane that stays busy answers
    /// `conflict`. `params.lane` picks the lane (default lane 1).
    pub fn lane_op(&self, op: &str, value: Value, wait: Duration) -> Result<Value, ApiError> {
        let request: super::lane_ops::LaneParams = params(value.clone())?;
        let lane = request.lane.unwrap_or_else(|| LaneId::new(1));
        let Some(slot) = self.slot(&lane) else {
            let why = self
                .left_out
                .iter()
                .find(|left| left.lane == lane)
                .map(|left| format!(": {}", left.reason))
                .unwrap_or_else(|| {
                    format!(
                        " (the daemon runs {} lane(s); daemon.lanes in service.toml)",
                        self.slots.len()
                    )
                });
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                format!("{lane} does not run in this daemon{why}"),
            )
            .with_field("lane"));
        };
        if let Phase::Lane(job) | Phase::Host(job) = &*crate::store::lock(&slot.phase) {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!(
                    "{lane} is busy with job {job}; try again when it is idle (or pause the queue first)"
                ),
            ));
        }
        let (reply, answer) = mpsc::channel();
        crate::store::lock(&slot.commands)
            .send(LaneCommand {
                op: op.to_owned(),
                params: value,
                reply,
                deadline: std::time::Instant::now() + wait,
            })
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "the lane has stopped"))?;
        let _ = crate::store::lock(&slot.wake).send(());
        answer.recv_timeout(wait).unwrap_or_else(|_| {
            Err(ApiError::new(
                ErrorCode::Conflict,
                "the lane is busy with a job; try again when it is idle",
            ))
        })
    }

    fn dispatch(&self, op: Op, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let caller = &ctx.caller;
        match op {
            Op::Capabilities => to_value(&self.capabilities(caller)),
            Op::Health => to_value(&self.health()?),
            Op::UploadBegin => {
                let request: UploadBeginParams = params(value)?;
                to_value(&self.intake.staging().begin(&caller.client_id, &request)?)
            }
            Op::UploadPut => self.upload_put(value, ctx),
            Op::UploadFinish => {
                let request: UploadFinishParams = params(value)?;
                to_value(
                    &self
                        .intake
                        .staging()
                        .finish(&caller.client_id, &request.upload_id)?,
                )
            }
            Op::JobSubmit => self.submit(value, ctx),
            Op::JobGet => {
                let request: JobIdParams = params(value)?;
                to_value(&self.store.get(&request.job_id)?)
            }
            Op::JobList => {
                let request: JobListParams = params(value)?;
                to_value(&self.store.list(&request, None)?)
            }
            Op::JobCancel => {
                let request: JobCancelParams = params(value)?;
                let job = self
                    .store
                    .cancel(&request.job_id, request.reason.as_deref(), caller)?;
                to_value(&job)
            }
            Op::JobRetry => self.retry(value, ctx),
            Op::EventsList => {
                let request: EventsListParams = params(value)?;
                let (events, next_seq) = self.store.events_list(
                    &request.job_id,
                    request.after_seq,
                    request.limit.unwrap_or(500).clamp(1, 1000),
                )?;
                to_value(&EventList { events, next_seq })
            }
            Op::EventsSubscribe => Err(ApiError::invalid_argument(
                "op",
                "events.subscribe is a stream; it is served on the socket only",
            )),
            Op::ArtifactList => {
                let request: JobIdParams = params(value)?;
                to_value(&ArtifactList {
                    artifacts: self.store.artifacts(&request.job_id)?,
                })
            }
            Op::ArtifactGet => {
                let request: ArtifactGetParams = params(value)?;
                artifacts::get(self, &request.artifact_id, request.range, caller)
            }
            Op::ReportGet => {
                let request: ReportGetParams = params(value)?;
                artifacts::report(self, &request, caller)
            }
            Op::PolicyList => to_value(&PolicyList {
                policies: self.policies.snapshot().list_for(caller),
            }),
            Op::QueueStatus => to_value(&self.queue_status()?),
            Op::QueuePause => self.queue_pause(true),
            Op::QueueResume => self.queue_pause(false),
            Op::JobDelete => self.job_delete(value),
            Op::SampleList
            | Op::SampleGet
            | Op::SampleAdd
            | Op::SampleDownload
            | Op::SampleTag
            | Op::CustodyVerify => self.library_op(op, value, ctx),
            Op::VmList => self.vm_list(),
            Op::BaseList => self.base_list(),
        }
    }
}

fn wire(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Handler for Service {
    fn hello(&self) -> Hello {
        Hello {
            api_version: crate::API_VERSION,
            app_version: antinomie_monitor_core::api::APP_VERSION.into(),
            owner: HelloOwner::Daemon,
            epoch: self.store.epoch().to_owned(),
            gseq: self.store.highest_gseq().unwrap_or(0),
            truncated: false,
        }
    }

    fn call(&self, op: &str, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        if op.starts_with("recording.") {
            if !ctx.caller.has(Scope::Read) {
                return Err(forbidden(Scope::Read));
            }
            return self.recording(op, value, ctx);
        }
        if let Some(answer) = super::lane_ops::call(self, op, value.clone(), ctx) {
            return answer;
        }
        if let Some(answer) = super::housekeeping::call(self, op, value.clone(), ctx) {
            return answer;
        }
        if reserved(op) {
            return Err(ApiError::new(
                ErrorCode::Unsupported,
                format!("{op} is reserved for a later version of the contract"),
            )
            .with_field("op"));
        }
        let parsed: Op = serde_json::from_value(Value::String(op.to_owned()))
            .map_err(|_| ApiError::invalid_argument("op", format!("unknown operation {op:?}")))?;
        if !ctx.caller.has(parsed.scope()) {
            return Err(forbidden(parsed.scope()));
        }
        if starts_work(parsed) && self.controls.stopping() {
            return Err(
                ApiError::new(ErrorCode::Unavailable, "the daemon is stopping")
                    .with_reason(ErrorReason::ServiceStopping),
            );
        }
        self.dispatch(parsed, value, ctx)
    }

    fn store(&self) -> &Store {
        &self.store
    }
}
