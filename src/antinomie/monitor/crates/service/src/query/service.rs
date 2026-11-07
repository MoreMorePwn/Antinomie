// SPDX-License-Identifier: GPL-3.0-only
//! `QueryApi` and the service that implements it (design 5.12.1): the
//! read-only recording queries over a data directory, without its lock and
//! without writing into any recording (2.3, 5.12.2).
//!
//! Class C operations need only the engine (cards Q-2, Q-3, Q-5). Class T
//! operations need the Triage scan and arrive with card Q-4; until then they
//! answer `unsupported`.

use super::{
    context::ReadContext,
    cursor::{CursorBinding, Generation, stable_hash},
    generation::generation_of,
    key::RunKey,
    limits::QuerySettings,
    page::{Page, Single},
    phase::{LayerSource, PhaseInfo, detect},
    pool::{Lease, Leases, ReadClass, ReadPool},
    request::*,
    scrub::Scrub,
    types::*,
};
use crate::api::{
    error::{ApiError, ErrorCode},
    ids::JobId,
    job::RecordingPhase,
    ops::Scope,
};
use antinomie_monitor_core::{
    BackendOptions, RunState, RunSummary, VmLocations,
    recording::{find_run_read_only, read_only_locations},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// What the job store tells the reads. The store is another card's; a service
/// without one answers `not_found` for a `job_id` and lists runs without jobs.
pub trait JobIndex: Send + Sync {
    /// The job of this service that made the run.
    fn job_of_run(&self, vm_id: &str, boot_id: &str, run_id: &str) -> Option<JobId>;
    /// The folder of the host-side analysis of a job (`<data>/analyses/<id>`).
    fn analysis_directory(&self, job: &JobId) -> Option<PathBuf>;
}

/// The read-only recording queries.
pub trait QueryApi: Send + Sync {
    /// One operation of 5.12.3.
    fn read(&self, request: RecordingRead, ctx: &ReadContext) -> Result<RecordingReply, ApiError>;

    /// `recording.run.list`.
    fn run_list(&self, filter: RunFilter, ctx: &ReadContext) -> Result<Page<RunInfo>, ApiError> {
        match self.read(RecordingRead::RunList(filter), ctx)? {
            RecordingReply::Runs(page) => Ok(page),
            _ => Err(ApiError::new(ErrorCode::Internal, "unexpected reply shape")),
        }
    }

    /// `recording.run.get`.
    fn run_get(&self, run: &RunKey, ctx: &ReadContext) -> Result<Single<RunDetail>, ApiError> {
        let request = RecordingRead::RunGet(RunParams {
            run_key: run.clone(),
        });
        match self.read(request, ctx)? {
            RecordingReply::Run(single) => Ok(single),
            _ => Err(ApiError::new(ErrorCode::Internal, "unexpected reply shape")),
        }
    }
}

/// The service: a data directory, the settings, the pools and the leases.
pub struct QueryService {
    pub(super) options: BackendOptions,
    pub(super) settings: QuerySettings,
    pub(super) pool: ReadPool,
    pub(super) leases: Arc<Leases>,
    pub(super) layers: Option<Arc<dyn LayerSource>>,
    pub(super) jobs: Option<Arc<dyn JobIndex>>,
    pub(super) scrub: Scrub,
    pub(super) trees: Mutex<super::process::TreeCache>,
}

impl QueryService {
    /// A service over the data directory of `options`. Only `data_dir` is read.
    pub fn new(options: BackendOptions) -> Self {
        Self::with_settings(options, QuerySettings::default())
    }

    pub fn with_settings(options: BackendOptions, settings: QuerySettings) -> Self {
        Self {
            scrub: Scrub::new(&options.data_dir, &[]),
            pool: ReadPool::new(&settings),
            options,
            settings,
            leases: Arc::new(Leases::default()),
            layers: None,
            jobs: None,
            trees: Mutex::new(super::process::TreeCache::default()),
        }
    }

    /// The engine's own `Snapshot.disk_layers`: it wins over the marker.
    pub fn with_layers(mut self, layers: Arc<dyn LayerSource>) -> Self {
        self.layers = Some(layers);
        self
    }

    pub fn with_jobs(mut self, jobs: Arc<dyn JobIndex>) -> Self {
        self.jobs = Some(jobs);
        self
    }

    /// Whether a read of the run is open now. Retention (`auto gc`) and
    /// `job.delete --with-recording` skip such a run.
    pub fn run_is_open(&self, run: &RunKey) -> bool {
        self.leases.held(run)
    }

    /// `(light, heavy)` reads in flight.
    pub fn reads_in_flight(&self) -> (usize, usize) {
        self.pool.in_flight()
    }

    pub fn settings(&self) -> &QuerySettings {
        &self.settings
    }

    pub(super) fn snapshot(&self) -> Option<Vec<antinomie_monitor_core::disk_layers::DiskLayer>> {
        self.layers.as_ref().map(|source| source.layers())
    }

    /// Every VM of the data directory.
    pub(super) fn locations(&self) -> Result<Vec<VmLocations>, ApiError> {
        read_only_locations(&self.options)
            .map_err(|e| super::errors::recording_error(&e, &self.scrub))
    }

    /// The run `key` names, its phase and its generation, with a lease held
    /// for as long as the result lives.
    pub(super) fn open_run(&self, key: &RunKey) -> Result<Opened, ApiError> {
        let (vm_id, boot_id, run_id) = key.parts();
        let location = self
            .locations()?
            .into_iter()
            .find(|location| location.vm_id == vm_id)
            .ok_or_else(|| ApiError::not_found("run"))?;
        let run = find_run_read_only(&location, &boot_id, &run_id)
            .map_err(|e| super::errors::recording_error(&e, &self.scrub))?
            .ok_or_else(|| ApiError::not_found("run"))?;
        // Open once, canonical: every later file is opened under this path.
        let dir = std::fs::canonicalize(&run.directory).map_err(|_| ApiError::not_found("run"))?;
        let snapshot = self.snapshot();
        let phase = detect(
            &location.disk_directory,
            &vm_id,
            &boot_id,
            run.state == RunState::Interrupted,
            snapshot.as_deref(),
        );
        Ok(Opened {
            generation: generation_of(&dir),
            lease: self.leases.take(key),
            key: key.clone(),
            run,
            location,
            dir,
            phase,
        })
    }

    pub(super) fn engine_error(
        &self,
        error: &antinomie_monitor_core::recording::RecordingError,
    ) -> ApiError {
        super::errors::recording_error(error, &self.scrub)
    }
}

/// One opened run: what every operation on it needs.
pub struct Opened {
    pub key: RunKey,
    pub run: RunSummary,
    pub location: VmLocations,
    /// The canonical run folder.
    pub dir: PathBuf,
    pub phase: PhaseInfo,
    pub generation: Generation,
    #[allow(dead_code)]
    lease: Lease,
}

impl Opened {
    /// The cursor binding of a walk over `filter` (and `sort`) of this run at
    /// this generation.
    pub fn binding<F: serde::Serialize, S: serde::Serialize>(
        &self,
        filter: &F,
        sort: &S,
    ) -> CursorBinding {
        CursorBinding {
            generation: self.generation,
            filter_hash: stable_hash(&(self.key.as_str(), filter)),
            sort_hash: stable_hash(sort),
        }
    }

    /// A page of this run: generation, phase, `partial` for an interrupted
    /// recording and `untrusted` for rows that carry sample text.
    pub fn page<T>(&self, items: Vec<T>, untrusted: bool) -> Page<T> {
        let mut page = Page::new(items, self.generation, self.phase.phase);
        page.partial = self.phase.partial().then_some(true);
        page.untrusted = untrusted.then_some(true);
        page
    }

    /// A page with an exact-or-not total: not exact while the recording grows.
    pub fn counted_page<T>(&self, items: Vec<T>, total: u64, untrusted: bool) -> Page<T> {
        let mut page = self.page(items, untrusted);
        page.total = Some(total);
        page.total_exact = Some(!self.phase.growing());
        page
    }

    pub fn single<T>(&self, value: T, untrusted: bool) -> Single<T> {
        let mut single = Single::new(value, self.generation, self.phase.phase);
        single.partial = self.phase.partial().then_some(true);
        single.untrusted = untrusted.then_some(true);
        single
    }

    /// The host time of a guest time through the run's clock anchor.
    pub fn ts_ms(&self, guest_ns: u64) -> Option<u64> {
        self.run
            .clock_anchor
            .and_then(|anchor| anchor.host_us(guest_ns))
            .map(|us| us / 1000)
    }

    /// The saved state as a reader reports it: a run of a live recording is
    /// still `running`, not the `interrupted` a saved `running` settles to.
    pub fn state(&self) -> RunStateName {
        let state = state_name(&self.run.state);
        if state == RunStateName::Interrupted && self.phase.phase == RecordingPhase::Live {
            RunStateName::Running
        } else {
            state
        }
    }
}

pub(super) fn state_name(state: &RunState) -> RunStateName {
    match state {
        RunState::Unknown => RunStateName::Unknown,
        RunState::Running => RunStateName::Running,
        RunState::StopRequested => RunStateName::StopRequested,
        RunState::Finished => RunStateName::Finished,
        RunState::Stopped => RunStateName::Stopped,
        RunState::TerminalClosed => RunStateName::TerminalClosed,
        RunState::Finalized => RunStateName::Finalized,
        RunState::FailedToStart => RunStateName::FailedToStart,
        RunState::LaunchUnconfirmed => RunStateName::LaunchUnconfirmed,
        RunState::Interrupted => RunStateName::Interrupted,
    }
}

impl QueryApi for QueryService {
    fn read(&self, request: RecordingRead, ctx: &ReadContext) -> Result<RecordingReply, ApiError> {
        use RecordingRead as R;
        use RecordingReply as P;
        let light = ReadClass::Light;
        let heavy = ReadClass::Heavy;
        match request {
            R::RunList(p) => self
                .pool
                .run(light, ctx, |_| self.run_list_page(&p))
                .map(P::Runs),
            R::RunGet(p) => self
                .pool
                .run(light, ctx, |_| self.run_detail(&p))
                .map(P::Run),
            R::TracePage(p) => self
                .pool
                .run(light, ctx, |c| self.trace_page(&p, c))
                .map(P::Trace),
            R::TraceGet(p) => self
                .pool
                .run(light, ctx, |c| self.trace_get(&p, c))
                .map(P::Invocation),
            R::CapturedRead(p) => {
                ctx.require(Scope::ArtifactsSensitive)?;
                self.pool
                    .run(light, ctx, |c| self.captured_read(&p, c))
                    .map(P::Bytes)
            }
            R::ProcessTree(p) => self
                .pool
                .run(heavy, ctx, |c| self.process_tree(&p, c))
                .map(P::Processes),
            R::NetworkCaptures(p) => self
                .pool
                .run(light, ctx, |_| self.network_captures(&p))
                .map(P::Captures),
            R::CoresList(p) => self
                .pool
                .run(light, ctx, |_| self.cores_list(&p))
                .map(P::Cores),
            R::AnalysisList(p) => self
                .pool
                .run(light, ctx, |_| self.analysis_list(&p))
                .map(P::AnalysisSections),
            R::AnalysisSection(p) => {
                let class = if p.q.is_some() || p.sort.is_some() {
                    heavy
                } else {
                    light
                };
                self.pool
                    .run(class, ctx, |_| self.analysis_section(&p))
                    .map(P::AnalysisRows)
            }
            R::AnalysisGhidra(p) => {
                let class = if p.q.is_some() { heavy } else { light };
                self.pool
                    .run(class, ctx, |_| self.analysis_ghidra(&p))
                    .map(P::AnalysisRows)
            }
            R::CustodyList(p) => self
                .pool
                .run(light, ctx, |_| self.custody_list(&p, ctx))
                .map(P::Custody),
            R::TerminalReplay(p) => self
                .pool
                .run(light, ctx, |_| self.terminal_replay(&p))
                .map(P::Terminal),
            R::ArtifactList(p) => self
                .pool
                .run(light, ctx, |_| self.artifact_list(&p))
                .map(P::Artifacts),
            R::ArtifactGet(p) => self
                .pool
                .run(light, ctx, |_| self.artifact_get(&p, ctx))
                .map(P::Bytes),
            R::NetworkPackets(p) => self
                .pool
                .run(heavy, ctx, |c| self.network_packets(&p, c))
                .map(P::Packets),
            R::NetworkPacket(p) => {
                ctx.require(Scope::ArtifactsSensitive)?;
                self.pool
                    .run(heavy, ctx, |c| self.network_packet(&p, c))
                    .map(P::Packet)
            }
            // Class T: the Triage scan (card Q-4).
            other @ (R::Summary(_)
            | R::FindingsList(_)
            | R::FindingsGet(_)
            | R::IndicatorsList(_)
            | R::FilesList(_)
            | R::FilesVersions(_)
            | R::FilesContent(_)
            | R::NetworkSummary(_)
            | R::NetworkList(_)
            | R::Timeline(_)) => Err(ApiError::new(
                ErrorCode::Unsupported,
                format!(
                    "{} needs the Triage scan, which this build does not have yet",
                    other.op()
                ),
            )
            .with_detail("class", serde_json::json!("T"))),
        }
    }
}
