// SPDX-License-Identifier: GPL-3.0-only
//! What a job runs, read from its frozen preset (every option resolved,
//! design 4.1 `launch`): the numbers every stage uses and the exact
//! `ExecRequest` of audit G7.
use crate::{
    api::{
        failure::FailureCode,
        run::Stage,
        spec::{ReportFormat, Route, RunIn},
    },
    config::{Preset, preset::kind_of, service::RevertMode},
};
use antinomie_monitor_core::{
    ExecRequest, RunIn as CoreRunIn,
    analysis::{
        AnalysisKind, AnalysisLimits, AnalysisSelection, detection::Engine as DetectionEngine,
    },
    report::Format as ReportEngineFormat,
    route::RouteKind,
};
use std::time::Duration;

/// The PATH a run gets when the preset's environment has none (as `run
/// exec`).
pub const DEFAULT_PATH: &str = "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Guest revision that takes a core dump on exit (`worker_guest.rs:170-180`).
pub const CORE_REVISION: u32 = 15;

/// Guest revision that takes a core when the live rules match
/// (`worker_launch.rs`, the dump trigger's core).
pub const TRIGGER_CORE_REVISION: u32 = 16;

/// Guest revision that reads non-resident pages into a core on request.
pub const NONRESIDENT_REVISION: u32 = 22;

/// The job's settings: its preset's options and the lane's revert.
#[derive(Clone, Debug)]
pub struct Effective {
    /// The run limit (`program.run_time_s`).
    pub run_limit: Duration,
    /// How the lane is made clean (`[lanes] revert` of service.toml).
    pub revert: RevertMode,
    /// The launch, without `path` and `sample`.
    pub request: ExecRequest,
    /// Where the sample lands (`program.guest_path`, `{name}` the sample's
    /// file name).
    pub guest_path: String,
}

fn core_kind(route: &Route) -> RouteKind {
    match route {
        Route::Drop => RouteKind::Drop,
        Route::Internet => RouteKind::Internet,
        Route::InetSim => RouteKind::InetSim,
        Route::Tor => RouteKind::Tor,
        Route::Vpn(_) => RouteKind::Vpn,
        Route::Socks5(_) => RouteKind::Socks5,
        // Refused at submit (no NAT lane before 0.9.1): never planned.
        Route::Nat => RouteKind::Drop,
    }
}

fn core_run_in(run_in: RunIn) -> CoreRunIn {
    match run_in {
        RunIn::AppTerminal => CoreRunIn::AppTerminal,
        RunIn::GuestDesktop => CoreRunIn::GuestDesktop,
        RunIn::GuestDesktopTerminal => CoreRunIn::GuestDesktopTerminal,
    }
}

/// The settings of a run of `preset` (the job's frozen preset) on a lane
/// that reverts with `revert`.
pub fn effective(preset: &Preset, revert: RevertMode) -> Effective {
    let program = &preset.program;
    let dumps = &preset.dumps;
    let (uid, gid) = program.ids();
    let mut env = program.environment.clone();
    if !env.iter().any(|item| item.starts_with("PATH=")) {
        env.push(DEFAULT_PATH.into());
    }
    let trigger = dumps.trigger();
    let trigger_core = trigger.as_ref().is_some_and(|plan| plan.core);
    let core = dumps.core_dump_on_exit;
    let request = ExecRequest {
        path: String::new(),
        args: program.arguments.clone(),
        cwd: program.working_directory.clone(),
        env,
        uid,
        gid,
        // Guest-side static analysis is not run in jobs (4.1, `analyse`).
        analysis: AnalysisSelection::default(),
        run_in: core_run_in(program.run_in),
        capture_network: preset.network.capture,
        memory_dump_on_exit: dumps.memory_dump_on_exit,
        core_dump_on_exit: core,
        core_max_size: (core || trigger_core)
            .then(|| dumps.core_budget_mib.saturating_mul(1 << 20)),
        core_timeout_ms: (core || trigger_core).then_some(dumps.core_deadline_ms),
        dump_trigger: trigger,
        core_nonresident: dumps.read_non_resident_pages && trigger_core,
        debug_on_start: false,
        route: Some(core_kind(&preset.network.route)),
        host_copy: None,
        sample: None,
        preloaded: Vec::new(),
    };
    Effective {
        run_limit: Duration::from_secs(u64::from(program.run_time_s)),
        revert,
        request,
        guest_path: program.guest_path.clone(),
    }
}

/// Where the sample lands in the guest: the library's file name of the sample
/// (`<sha8>-<name>`, 48 characters of a safe name) for `{name}` in the
/// preset's `program.guest_path`.
pub fn guest_path(template: &str, sha256: &str, name: &str) -> String {
    crate::config::preset::Program {
        guest_path: template.to_owned(),
        ..Default::default()
    }
    .sample_path(sha256, name)
}

/// `upload_s` (4.1): 60 seconds plus one second per 10 MiB.
pub fn upload_wait(size: u64) -> Duration {
    Duration::from_secs(60 + size / (10 << 20))
}

/// `analyse_s` (design 4.1): the Triage scan and the detection engines.
pub const ANALYSE_WAIT: Duration = Duration::from_secs(900);
/// The budgeted digest build of a run the scan left none for: its own time
/// budget (20 minutes) and a minute to finish.
pub const DIGEST_WAIT: Duration = Duration::from_secs(21 * 60);
/// `report_s` (design 4.1).
pub const REPORT_WAIT: Duration = Duration::from_secs(300);
/// `cleanup_s` (design 4.1).
pub const CLEANUP_WAIT: Duration = Duration::from_secs(60);
/// The time a static tool may take when the limit is 0 ("each tool's own
/// limit"): the engine's own bound is not published, so the stage assumes this.
pub const TOOL_OWN_LIMIT_MIN: u32 = 5;

/// What the host stages do for a job, from its frozen preset.
#[derive(Clone, Debug)]
pub struct HostPlan {
    /// The static checks of the host-side analysis; empty: none.
    pub static_checks: Vec<AnalysisKind>,
    /// A fixed limit in minutes for every tool, when the preset sets one;
    /// `None`: each tool's limit comes from its expected time.
    pub static_limit_min: Option<u32>,
    /// The engine's size limits and the Ghidra choice
    /// (`static_analysis.limits`, `ghidra_disassembly`).
    pub static_limits: AnalysisLimits,
    /// Checks whose timeout fails the stage (`static_analysis.required_checks`).
    pub required_checks: Vec<AnalysisKind>,
    pub triage: bool,
    pub engines: Vec<DetectionEngine>,
    pub formats: Vec<ReportFormat>,
    pub bundle: bool,
    pub defang: bool,
    /// Stages whose failure fails the job (`required_stages`).
    pub required: Vec<Stage>,
    pub retry_analysis: bool,
    pub max_attempts: u32,
}

impl HostPlan {
    /// Nothing for `analyse` to do.
    pub fn analyse_skipped(&self) -> bool {
        self.static_checks.is_empty() && !self.triage && self.engines.is_empty()
    }

    /// Nothing for `report` to write.
    pub fn report_skipped(&self) -> bool {
        self.formats.is_empty() && !self.bundle
    }

    pub fn requires(&self, stage: Stage) -> bool {
        self.required.contains(&stage)
    }
}

/// The report format of the run API as the report builder names it.
pub fn format_of(format: ReportFormat) -> ReportEngineFormat {
    match format {
        ReportFormat::Html => ReportEngineFormat::Html,
        ReportFormat::Pdf => ReportEngineFormat::Pdf,
        ReportFormat::Json => ReportEngineFormat::Json,
        ReportFormat::Misp => ReportEngineFormat::Misp,
        ReportFormat::Stix => ReportEngineFormat::Stix,
        ReportFormat::Md => ReportEngineFormat::Markdown,
    }
}

/// The host stages of a run of `preset` (the job's frozen preset).
pub fn hosted(preset: &Preset) -> HostPlan {
    let s = &preset.static_analysis;
    let detection = &preset.detection;
    let mut engines = Vec::new();
    for (engine, on) in [
        (DetectionEngine::Yara, detection.yara),
        (DetectionEngine::Ids, detection.ids),
        (DetectionEngine::Sigma, detection.sigma),
    ] {
        if on {
            engines.push(engine);
        }
    }
    HostPlan {
        static_checks: s.checks().into_iter().map(kind_of).collect(),
        static_limit_min: s.fixed_limit_min(),
        static_limits: s.engine_limits(),
        required_checks: s.required_checks.iter().map(|c| kind_of(*c)).collect(),
        triage: preset.triage.enabled,
        engines,
        formats: preset.report.formats.clone(),
        bundle: preset.report.bundle,
        defang: preset.report.defang,
        required: preset.required_stages.clone(),
        retry_analysis: preset.retry.retry_on.contains(&FailureCode::AnalysisFailed),
        max_attempts: preset.retry.max_attempts,
    }
}
