// SPDX-License-Identifier: GPL-3.0-only
//! What a job asks for, settled against its frozen policy (design 4.4, 4.1
//! `launch`): the numbers every stage uses and the exact `ExecRequest` of
//! audit G7.
use crate::{
    api::{
        failure::FailureCode,
        job::{Job, Stage},
        spec::{
            CoreDump, ReportFormat, Route, RunAs, RunAsName, RunIn, StaticCheck, StaticChecks,
            StaticPreset,
        },
    },
    config::{Policy, policy::RevertMode},
};
use antinomie_monitor_core::{
    ExecRequest, RunIn as CoreRunIn,
    analysis::{AnalysisKind, AnalysisSelection, detection::Engine as DetectionEngine},
    report::Format as ReportEngineFormat,
    route::RouteKind,
    samples::guest_path_of,
};
use std::time::Duration;

/// The default PATH `run exec` also adds when the spec has none.
pub const DEFAULT_PATH: &str = "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// `core_timeout_ms` when nothing else says (the engine's default, 5 s).
pub const CORE_TIMEOUT_MS: u32 = 5000;

/// Guest revision that takes a core dump on exit (`worker_guest.rs:170-180`).
pub const CORE_REVISION: u32 = 15;

/// Guest revision that takes a core when the live rules match
/// (`worker_launch.rs`, the dump trigger's core).
pub const TRIGGER_CORE_REVISION: u32 = 16;

/// The job's settings after the spec's overrides met the policy.
#[derive(Clone, Debug)]
pub struct Effective {
    /// The run limit (`run_s`).
    pub run_limit: Duration,
    pub revert: RevertMode,
    pub revert_after: bool,
    /// The launch, without `path` and `sample`.
    pub request: ExecRequest,
    /// A guest directory for the sample (`run.guest_dir`).
    pub guest_dir: String,
}

fn core_kind(route: Route) -> RouteKind {
    match route {
        Route::Drop => RouteKind::Drop,
        Route::Internet => RouteKind::Internet,
        Route::InetSim => RouteKind::InetSim,
        Route::Tor => RouteKind::Tor,
        Route::Vpn => RouteKind::Vpn,
        Route::Socks5 => RouteKind::Socks5,
    }
}

fn core_run_in(run_in: RunIn) -> CoreRunIn {
    match run_in {
        RunIn::AppTerminal => CoreRunIn::AppTerminal,
        RunIn::GuestDesktop => CoreRunIn::GuestDesktop,
        RunIn::GuestDesktopTerminal => CoreRunIn::GuestDesktopTerminal,
    }
}

/// Settle `job`'s spec against `policy` (the policy the job froze).
pub fn effective(job: &Job, policy: &Policy) -> Effective {
    let o = &job.spec.overrides;
    let run_as = o.run_as.clone().unwrap_or(RunAs::Named(policy.run.run_as));
    let (uid, gid) = match run_as {
        RunAs::Named(RunAsName::User) => (1000, 1000),
        RunAs::Named(RunAsName::Root) => (0, 0),
        RunAs::Ids(ids) => (ids.uid, ids.gid),
    };
    let mut env = o.env.clone().unwrap_or_default();
    if !env.iter().any(|item| item.starts_with("PATH=")) {
        env.push(DEFAULT_PATH.into());
    }
    let (core, core_max_mib, core_timeout_ms) = match o.core_dump {
        None => (
            policy.evidence.core_dump,
            policy.evidence.core_max_mib,
            CORE_TIMEOUT_MS,
        ),
        Some(CoreDump::Switch(on)) => (on, policy.evidence.core_max_mib, CORE_TIMEOUT_MS),
        Some(CoreDump::Limits(limits)) => (true, limits.max_mib, limits.timeout_ms),
    };
    let trigger = policy.evidence.trigger();
    let trigger_core = trigger.as_ref().is_some_and(|plan| plan.core);
    let request = ExecRequest {
        path: String::new(),
        args: o.args.clone().unwrap_or_default(),
        cwd: policy.run.guest_dir.clone(),
        env,
        uid,
        gid,
        // Guest-side static analysis is not run in jobs (4.1, `analyse`).
        analysis: AnalysisSelection::default(),
        run_in: core_run_in(o.run_in.unwrap_or(policy.run.run_in)),
        capture_network: o.network_capture.unwrap_or(policy.network.capture),
        memory_dump_on_exit: o.memory_dump.unwrap_or(policy.evidence.memory_dump),
        core_dump_on_exit: core,
        core_max_size: (core || trigger_core).then(|| core_max_mib.saturating_mul(1 << 20)),
        core_timeout_ms: (core || trigger_core).then_some(core_timeout_ms),
        dump_trigger: trigger,
        core_nonresident: false,
        debug_on_start: false,
        route: Some(core_kind(o.route.unwrap_or(policy.network.route))),
        host_copy: None,
        sample: None,
        preloaded: Vec::new(),
    };
    Effective {
        run_limit: Duration::from_secs(u64::from(o.timeout_s.unwrap_or(policy.run.timeout_s))),
        revert: policy.vm.revert,
        revert_after: policy.vm.revert_after,
        request,
        guest_dir: policy.run.guest_dir.clone(),
    }
}

/// Where the sample lands in the guest: the library rule (`/tmp/<sha8>-<name>`,
/// 48 characters of a safe name) in the policy's directory.
pub fn guest_path(guest_dir: &str, sha256: &str, name: &str) -> String {
    let default = guest_path_of(sha256, name);
    let leaf = default.rsplit('/').next().unwrap_or("sample");
    format!("{}/{leaf}", guest_dir.trim_end_matches('/'))
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

/// What the host stages do for a job, settled against its frozen policy.
#[derive(Clone, Debug)]
pub struct HostPlan {
    /// The static checks of the host-side analysis; empty: none.
    pub static_checks: Vec<AnalysisKind>,
    pub static_limit_min: u32,
    /// Checks whose timeout fails the stage (`analysis.required_checks`).
    pub required_checks: Vec<AnalysisKind>,
    pub triage: bool,
    pub engines: Vec<DetectionEngine>,
    pub formats: Vec<ReportFormat>,
    pub bundle: bool,
    pub defang: bool,
    /// Stages whose failure fails the job (`analysis.required_stages`).
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

    /// `static_s` = tools x limit x 60 + 60 (design 4.1).
    pub fn static_wait(&self) -> Duration {
        let minutes = if self.static_limit_min == 0 {
            TOOL_OWN_LIMIT_MIN
        } else {
            self.static_limit_min
        };
        Duration::from_secs(self.static_checks.len() as u64 * u64::from(minutes) * 60 + 60)
    }

    pub fn requires(&self, stage: Stage) -> bool {
        self.required.contains(&stage)
    }
}

fn kind_of(check: StaticCheck) -> AnalysisKind {
    match check {
        StaticCheck::Metadata => AnalysisKind::Metadata,
        StaticCheck::Structures => AnalysisKind::Structures,
        StaticCheck::Strings => AnalysisKind::Strings,
        StaticCheck::Regex => AnalysisKind::Regex,
        StaticCheck::Entropy => AnalysisKind::Entropy,
        StaticCheck::Hardening => AnalysisKind::Hardening,
        StaticCheck::Rules => AnalysisKind::Rules,
        StaticCheck::Identification => AnalysisKind::Identification,
        StaticCheck::Capabilities => AnalysisKind::Capabilities,
        StaticCheck::Disassembly => AnalysisKind::Disassembly,
        StaticCheck::Decompilation => AnalysisKind::Decompilation,
        StaticCheck::Embedded => AnalysisKind::Embedded,
        StaticCheck::Floss => AnalysisKind::Floss,
        StaticCheck::Unpacking => AnalysisKind::Unpacking,
    }
}

/// The report format of the job API as the report builder names it.
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

/// Settle the host stages of `job` against `policy` (the policy it froze).
pub fn hosted(job: &Job, policy: &Policy) -> HostPlan {
    let o = &job.spec.overrides;
    let checks = o
        .static_checks
        .clone()
        .unwrap_or_else(|| policy.analysis.static_checks.clone());
    let static_checks = match checks {
        StaticChecks::Preset(StaticPreset::None) => Vec::new(),
        StaticChecks::Preset(StaticPreset::Triage) => AnalysisKind::TRIAGE.to_vec(),
        StaticChecks::Names(names) => names.into_iter().map(kind_of).collect(),
    };
    let wanted = o.detection.unwrap_or_default();
    let detection = &policy.analysis.detection;
    let mut engines = Vec::new();
    for (engine, asked, allowed) in [
        (DetectionEngine::Yara, wanted.yara, detection.yara),
        (DetectionEngine::Ids, wanted.ids, detection.ids),
        (DetectionEngine::Sigma, wanted.sigma, detection.sigma),
    ] {
        if asked.unwrap_or(allowed) {
            engines.push(engine);
        }
    }
    HostPlan {
        static_checks,
        static_limit_min: o
            .static_time_limit_min
            .unwrap_or(policy.analysis.static_time_limit_min),
        required_checks: policy
            .analysis
            .required_checks
            .iter()
            .map(|c| kind_of(*c))
            .collect(),
        triage: policy.analysis.triage,
        engines,
        formats: o
            .reports
            .clone()
            .unwrap_or_else(|| policy.report.formats.clone()),
        bundle: o.report_bundle.unwrap_or(policy.report.bundle),
        defang: o.report_defang.unwrap_or(policy.report.defang),
        required: policy.analysis.required_stages.clone(),
        retry_analysis: policy.retry.retry_on.contains(&FailureCode::AnalysisFailed),
        max_attempts: policy.retry.max_attempts,
    }
}
