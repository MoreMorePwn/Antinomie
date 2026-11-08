// SPDX-License-Identifier: GPL-3.0-only
//! What a job asks for, settled against its frozen policy (design 4.4, 4.1
//! `launch`): the numbers every stage uses and the exact `ExecRequest` of
//! audit G7.
use crate::{
    api::{
        job::Job,
        spec::{CoreDump, Route, RunAs, RunAsName, RunIn},
    },
    config::{Policy, policy::RevertMode},
};
use antinomie_monitor_core::{
    ExecRequest, RunIn as CoreRunIn, analysis::AnalysisSelection, route::RouteKind,
    samples::guest_path_of,
};
use std::time::Duration;

/// The default PATH `run exec` also adds when the spec has none.
pub const DEFAULT_PATH: &str = "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// `core_timeout_ms` when nothing else says (the engine's default, 5 s).
pub const CORE_TIMEOUT_MS: u32 = 5000;

/// Guest revision that takes a core dump on exit (`worker_guest.rs:170-180`).
pub const CORE_REVISION: u32 = 15;

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
        core_max_size: core.then(|| core_max_mib.saturating_mul(1 << 20)),
        core_timeout_ms: core.then_some(core_timeout_ms),
        dump_trigger: None,
        debug_on_start: false,
        route: Some(core_kind(o.route.unwrap_or(policy.network.route))),
        host_copy: None,
        sample: None,
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
