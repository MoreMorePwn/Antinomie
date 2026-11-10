// SPDX-License-Identifier: GPL-3.0-only
//! Parsing and checking `service.toml` and `policies/*.toml` (design 2.4.2,
//! 4.4). Every problem names the file, the line and the key.

use super::{
    catalog::{VmCatalog, VmFacts, VmNet},
    locate::Locator,
    policy::{LoadedPolicy, Policy, RevertMode, TriggerKind, TriggerSetting},
    service::ServiceConfig,
};
use crate::api::{
    job::Stage,
    spec::{RunAsName, RunIn},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

/// One thing wrong (or suspicious) in a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub severity: Severity,
    /// File name relative to the data directory (`service.toml`,
    /// `policies/default.toml`).
    pub file: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    /// Dotted key path, when one is to blame.
    pub key: Option<String>,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{}", self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
            if let Some(column) = self.column {
                write!(f, ":{column}")?;
            }
        }
        write!(f, ": {severity}: ")?;
        // Name the key unless the message already does.
        match &self.key {
            Some(key) if !self.message.contains(key.as_str()) => write!(f, "{key}: ")?,
            _ => {}
        }
        write!(f, "{}", self.message)
    }
}

/// The highest ceilings the engine and the contract allow.
pub const MAX_RUN_S: u32 = 1800;
pub const MAX_CORE_MIB: u32 = 1024;
pub const MAX_STATIC_MINUTES: u32 = 480;
pub const MAX_SAMPLE_MIB: u32 = 256;

/// The values of `samples::detect_type`.
pub const SAMPLE_TYPES: [&str; 11] = [
    "elf", "sh", "py", "pl", "script", "exe", "zip", "gz", "bz2", "xz", "data",
];
/// The architectures `detect_type` can return.
pub const SAMPLE_ARCHES: [&str; 11] = [
    "x86_64", "x86", "ARM", "AArch64", "MIPS", "PowerPC", "SPARC", "RISC-V", "SuperH", "m68k",
    "other",
];

struct Sink<'a> {
    file: &'a str,
    locator: &'a Locator,
    problems: Vec<Problem>,
}

impl Sink<'_> {
    fn at(&mut self, severity: Severity, key: &str, message: impl Into<String>) {
        let (line, column) = self.locator.find(key);
        self.problems.push(Problem {
            severity,
            file: self.file.to_owned(),
            line: Some(line),
            column: Some(column),
            key: Some(key.to_owned()),
            message: message.into(),
        });
    }
    fn error(&mut self, key: &str, message: impl Into<String>) {
        self.at(Severity::Error, key, message);
    }
    fn warn(&mut self, key: &str, message: impl Into<String>) {
        self.at(Severity::Warning, key, message);
    }
}

fn parse_failure<T>(
    file: &str,
    text: &str,
    result: Result<T, toml::de::Error>,
) -> Result<T, Vec<Problem>> {
    result.map_err(|error| {
        let locator = Locator::new(text);
        let (line, column) = match error.span() {
            Some(span) => locator.line_col(span.start),
            None => (1, 1),
        };
        vec![Problem {
            severity: Severity::Error,
            file: file.to_owned(),
            line: Some(line),
            column: Some(column),
            key: None,
            message: error.message().trim().to_owned(),
        }]
    })
}

/// Parse `service.toml` and run the checks that need no other file.
pub fn parse_service(file: &str, text: &str) -> (Option<ServiceConfig>, Vec<Problem>) {
    let config = match parse_failure(file, text, toml::from_str::<ServiceConfig>(text)) {
        Ok(config) => config,
        Err(problems) => return (None, problems),
    };
    let locator = Locator::new(text);
    let mut sink = Sink {
        file,
        locator: &locator,
        problems: Vec::new(),
    };
    check_service(&config, &mut sink);
    (Some(config), sink.problems)
}

fn check_service(config: &ServiceConfig, sink: &mut Sink<'_>) {
    if config.daemon.lanes != 1 {
        sink.error(
            "daemon.lanes",
            "unsupported: one lane per node (decided D4); values above 1 are not available",
        );
    }
    if config.daemon.host_workers == Some(0) {
        sink.error("daemon.host_workers", "must be at least 1");
    }
    if config.daemon.drain_timeout_s == 0 {
        sink.error("daemon.drain_timeout_s", "must be at least 1");
    }
    if config.queue.max_queued == 0 {
        sink.error("queue.max_queued", "must be at least 1");
    }
    if config.queue.per_client_queued == 0 {
        sink.error("queue.per_client_queued", "must be at least 1");
    }
    if config.queue.per_client_queued > config.queue.max_queued {
        sink.warn(
            "queue.per_client_queued",
            "above queue.max_queued, so it never applies",
        );
    }
    if config.safety.unsafe_routes_ack.is_some() {
        sink.error(
            "safety.unsafe_routes_ack",
            "reserved: live routes are not in v1 (decided D6)",
        );
    }
    for (name, value) in [
        ("query.light_concurrency", config.query.light_concurrency),
        ("query.heavy_concurrency", config.query.heavy_concurrency),
        ("query.light_timeout_s", config.query.light_timeout_s),
        ("query.heavy_timeout_s", config.query.heavy_timeout_s),
        ("query.scan_cache_mib", config.query.scan_cache_mib),
    ] {
        if value == 0 {
            sink.error(name, "must be at least 1");
        }
    }
    if config.retention.jobs_days == 0 || config.retention.recordings_days == 0 {
        sink.error("retention", "the retention periods must be at least 1 day");
    }
    if config.inbox.processed_keep_days == 0 {
        sink.error("inbox.processed_keep_days", "must be at least 1 day");
    }
    let mut watched = Vec::new();
    for (index, watch) in config.inbox.watch.iter().enumerate() {
        let key = |name: &str| format!("inbox.watch.{index}.{name}");
        if !watch.path.is_absolute() {
            sink.error(&key("path"), "a watch folder must be an absolute path");
        }
        if watched.contains(&&watch.path) {
            sink.error(&key("path"), "this folder is watched twice");
        }
        watched.push(&watch.path);
        if watch.watch_rate == 0 {
            sink.error(&key("watch_rate"), "must be at least 1");
        }
    }
    for dir in [
        &config.inbox.dir,
        &config.results.dir,
        &config.daemon.socket,
    ]
    .into_iter()
    .flatten()
    {
        if !dir.is_absolute() {
            sink.error(
                "inbox",
                format!("{} is not an absolute path", dir.display()),
            );
        }
    }
    if let Some(command) = config.notify.on_finish.first()
        && !Path::new(command).is_absolute()
    {
        sink.error("notify.on_finish", "the command must be an absolute path");
    }
    for (index, hook) in config.notify.webhooks.iter().enumerate() {
        let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|prefix| hook.url.starts_with(prefix));
        if !hook.url.starts_with("https://") && !local {
            sink.error(
                &format!("notify.webhooks.{index}.url"),
                "HTTPS only, unless the host is loopback",
            );
        }
    }
}

/// The name a policy file stands for: `[a-z0-9._-]`, 1 to 64 bytes, not
/// starting with a dot.
pub fn valid_policy_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// Parse one policy file and run the checks of design 4.4. `catalog` answers
/// the questions about the lane VM.
pub fn parse_policy(
    name: &str,
    file: &str,
    text: &str,
    catalog: &dyn VmCatalog,
) -> (Option<LoadedPolicy>, Vec<Problem>) {
    let policy = match parse_failure(file, text, toml::from_str::<Policy>(text)) {
        Ok(policy) => policy,
        Err(problems) => return (None, problems),
    };
    let locator = Locator::new(text);
    let mut sink = Sink {
        file,
        locator: &locator,
        problems: Vec::new(),
    };
    if !valid_policy_name(name) {
        sink.error("description", "the file name is not a valid policy name");
    }
    check_policy(&policy, catalog, &mut sink);
    let digest = Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (
        Some(LoadedPolicy {
            name: name.to_owned(),
            digest,
            policy,
        }),
        sink.problems,
    )
}

fn check_policy(policy: &Policy, catalog: &dyn VmCatalog, sink: &mut Sink<'_>) {
    let sample = &policy.sample;
    if !(1..=MAX_SAMPLE_MIB).contains(&sample.max_sample_mib) {
        sink.error(
            "sample.max_sample_mib",
            format!("must be 1 to {MAX_SAMPLE_MIB}"),
        );
    }
    if sample.accept_types.is_empty() {
        sink.error("sample.accept_types", "must name at least one type");
    }
    for kind in &sample.accept_types {
        if kind != "any" && !SAMPLE_TYPES.contains(&kind.as_str()) {
            sink.error(
                "sample.accept_types",
                format!(
                    "unknown type `{kind}`; the types are {}",
                    SAMPLE_TYPES.join(", ")
                ),
            );
        }
    }
    if sample.accept_arch.is_empty() {
        sink.error("sample.accept_arch", "must name at least one architecture");
    }
    for arch in &sample.accept_arch {
        if arch != "any" && !SAMPLE_ARCHES.contains(&arch.as_str()) {
            sink.error(
                "sample.accept_arch",
                format!(
                    "unknown architecture `{arch}`; the values are {}",
                    SAMPLE_ARCHES.join(", ")
                ),
            );
        }
    }

    let run = &policy.run;
    if run.timeout_s < 5 {
        sink.error("run.timeout_s", "at least 5 seconds");
    }
    if run.max_run_s > MAX_RUN_S {
        sink.error(
            "run.max_run_s",
            format!("above the {MAX_RUN_S} second maximum (decided B-H14)"),
        );
    }
    if run.timeout_s > run.max_run_s {
        sink.error("run.timeout_s", "above run.max_run_s");
    }
    if run.run_as == RunAsName::Root && !run.allow_root {
        sink.error("run.run_as", "root needs run.allow_root = true");
    }
    if run.run_in != RunIn::AppTerminal {
        sink.error(
            "run.run_in",
            "v1 supports app_terminal only (decided B-H24)",
        );
    }
    if !run.guest_dir.starts_with('/') || run.guest_dir.contains('\0') {
        sink.error("run.guest_dir", "must be an absolute path");
    }

    let network = &policy.network;
    if network.allowed_routes.is_empty() {
        sink.error("network.allowed_routes", "must name at least one route");
    }
    for route in &network.allowed_routes {
        if !route.allowed_in_v1() {
            sink.error(
                "network.allowed_routes",
                format!(
                    "route {} is not in v1: only drop and inet_sim are allowed (decided D6)",
                    route_name(*route)
                ),
            );
        }
    }
    if !network.route.allowed_in_v1() {
        sink.error(
            "network.route",
            format!(
                "route {} is not in v1 (decided D6)",
                route_name(network.route)
            ),
        );
    } else if !network.allowed_routes.contains(&network.route) {
        sink.error(
            "network.route",
            format!(
                "route {} is not in network.allowed_routes",
                route_name(network.route)
            ),
        );
    }

    if policy.evidence.core_max_mib > MAX_CORE_MIB {
        sink.error(
            "evidence.core_max_mib",
            format!("above the engine maximum of {MAX_CORE_MIB} MiB"),
        );
    }
    let trigger_core = policy.evidence.trigger().is_some_and(|plan| plan.core);
    if policy.evidence.core_max_mib == 0 && (policy.evidence.core_dump || trigger_core) {
        sink.error(
            "evidence.core_max_mib",
            "must be at least 1 with core_dump or a core dump_trigger",
        );
    }
    if policy.evidence.core_nonresident && !trigger_core {
        sink.warn(
            "evidence.core_nonresident",
            "has no effect without a core dump_trigger (an exit core reads resident pages only)",
        );
    }
    if policy.evidence.dump_trigger == TriggerSetting::Off
        && policy.evidence.dump_trigger_kind != TriggerKind::default()
    {
        sink.warn(
            "evidence.dump_trigger_kind",
            "has no effect while evidence.dump_trigger is off",
        );
    }
    if policy.analysis.static_time_limit_min > MAX_STATIC_MINUTES {
        sink.error(
            "analysis.static_time_limit_min",
            format!("0 to {MAX_STATIC_MINUTES}"),
        );
    }
    for stage in &policy.analysis.required_stages {
        let skipped = match stage {
            Stage::Analyse => policy.analysis.analyse_skipped(),
            Stage::Report => policy.report.formats.is_empty(),
            _ => false,
        };
        if skipped {
            sink.error(
                "analysis.required_stages",
                format!("the {stage:?} stage is required but this policy skips it").to_lowercase(),
            );
        }
    }
    if let Err(error) = crate::verdict::Mapping::compile(&policy.verdict) {
        sink.error(&error.key(), error.to_string());
    }
    if policy.report.formats.is_empty() && !policy.report.bundle {
        sink.warn("report.formats", "no report is produced");
    }
    if policy.retry.max_attempts == 0 {
        sink.error("retry.max_attempts", "must be at least 1");
    }
    if policy.retry.max_attempts > 1 && policy.retry.backoff_s.is_empty() {
        sink.error("retry.backoff_s", "needs at least one delay when retrying");
    }
    if policy.access.scopes.is_empty() {
        sink.error("access.scopes", "must name at least one scope");
    }
    if policy.access.clients.is_empty() {
        sink.error("access.clients", "must name at least one pattern");
    }
    let limits = &policy.limits;
    if limits.priority_max > 9 {
        sink.error("limits.priority_max", "0 to 9");
    }
    for (key, value) in [
        ("limits.max_queued_per_client", limits.max_queued_per_client),
        ("limits.max_jobs_per_day", limits.max_jobs_per_day),
        ("limits.max_concurrent", limits.max_concurrent),
        ("limits.wait_s", limits.wait_s),
    ] {
        if value == 0 {
            sink.error(key, "must be at least 1");
        }
    }
    if limits.max_concurrent > 1 {
        sink.error(
            "limits.max_concurrent",
            "unsupported: one lane per node (decided D4)",
        );
    }

    check_vm(policy, catalog, sink);
}

fn route_name(route: crate::api::spec::Route) -> String {
    serde_json::to_value(route)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn check_vm(policy: &Policy, catalog: &dyn VmCatalog, sink: &mut Sink<'_>) {
    let vm = &policy.vm;
    match vm.network.as_str() {
        "routed" | "isolated" | "disconnected" => {}
        "nat" => sink.error(
            "vm.network",
            "nat is never valid for jobs: NAT lets the guest reach host services",
        ),
        other => sink.error(
            "vm.network",
            format!("`{other}` is not routed, isolated or disconnected"),
        ),
    }
    if vm.revert.needs_snapshot() && vm.revert_to.is_empty() {
        sink.error("vm.revert_to", "must name a snapshot");
    }
    let Some(lane_vm) = &vm.lane_vm else {
        sink.error("vm", "vm.lane_vm is required");
        return;
    };
    let non_drop = policy
        .network
        .allowed_routes
        .iter()
        .any(|route| *route != crate::api::spec::Route::Drop);
    let Some(facts) = catalog.find(lane_vm) else {
        sink.warn(
            "vm.lane_vm",
            format!("VM `{lane_vm}` was not found in this data directory"),
        );
        return;
    };
    check_vm_facts(policy, &facts, non_drop, sink);
}

fn check_vm_facts(policy: &Policy, facts: &VmFacts, non_drop: bool, sink: &mut Sink<'_>) {
    let vm = &policy.vm;
    if facts.network == VmNet::Nat {
        sink.error(
            "vm.lane_vm",
            format!(
                "VM `{}` uses NAT, which is never valid for jobs",
                facts.name
            ),
        );
    } else if facts.network.as_str() != vm.network && vm.network != "nat" {
        sink.error(
            "vm.network",
            format!(
                "VM `{}` is {}, the policy requires {}",
                facts.name,
                facts.network.as_str(),
                vm.network
            ),
        );
    }
    if non_drop && facts.network != VmNet::Routed {
        sink.error(
            "network.allowed_routes",
            format!(
                "VM `{}` is not routed, so only drop is possible",
                facts.name
            ),
        );
    }
    match vm.revert {
        RevertMode::Reset if !facts.snapshots.is_empty() => sink.error(
            "vm.revert",
            format!(
                "reset is refused by the engine on VM `{}`, which has snapshots",
                facts.name
            ),
        ),
        RevertMode::SnapshotDisk | RevertMode::SnapshotFull
            if !facts.snapshots.contains(&vm.revert_to) =>
        {
            sink.error(
                "vm.revert_to",
                format!(
                    "VM `{}` has no snapshot named `{}`",
                    facts.name, vm.revert_to
                ),
            );
        }
        _ => {}
    }
    if let (Some(want), Some(have)) = (&vm.stealth, &facts.stealth)
        && want != have
    {
        sink.error(
            "vm.stealth",
            format!(
                "VM `{}` has the profile `{have}`, the policy expects `{want}`",
                facts.name
            ),
        );
    }
    if let (Some(want), Some(have)) = (&vm.base, &facts.base_identity)
        && want != have
    {
        sink.warn(
            "vm.base",
            format!(
                "VM `{}` was made from base `{have}`, not `{want}`",
                facts.name
            ),
        );
    }
}

/// Everything read from a data directory.
#[derive(Debug, Default)]
pub struct ConfigReport {
    /// `None` when `service.toml` exists and does not parse.
    pub service: Option<ServiceConfig>,
    pub policies: BTreeMap<String, Arc<LoadedPolicy>>,
    pub problems: Vec<Problem>,
}

impl ConfigReport {
    pub fn errors(&self) -> impl Iterator<Item = &Problem> {
        self.problems
            .iter()
            .filter(|problem| problem.severity == Severity::Error)
    }

    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }
}

fn read(path: &Path, shown: &str, problems: &mut Vec<Problem>) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            problems.push(Problem {
                severity: Severity::Error,
                file: shown.to_owned(),
                line: None,
                column: None,
                key: None,
                message: format!("cannot read the file: {error}"),
            });
            None
        }
    }
}

/// Read and check `<data>/service.toml` and `<data>/policies/*.toml`. A
/// missing `service.toml` is the defaults; a missing policy directory is no
/// policy. `only_policy` limits the policy checks to one file.
pub fn load(data_dir: &Path, catalog: &dyn VmCatalog, only_policy: Option<&str>) -> ConfigReport {
    let mut report = ConfigReport::default();
    let service_path = data_dir.join("service.toml");
    if service_path.exists() {
        if let Some(text) = read(&service_path, "service.toml", &mut report.problems) {
            let (config, problems) = parse_service("service.toml", &text);
            report.service = config;
            report.problems.extend(problems);
        }
    } else {
        report.service = Some(ServiceConfig::default());
    }

    let dir = data_dir.join("policies");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let mut found_only = only_policy.is_none();
    for path in files {
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if only_policy.is_some_and(|only| only != name) {
            continue;
        }
        found_only = true;
        let shown = format!("policies/{name}.toml");
        let Some(text) = read(&path, &shown, &mut report.problems) else {
            continue;
        };
        let (policy, problems) = parse_policy(name, &shown, &text, catalog);
        let failed = problems.iter().any(|p| p.severity == Severity::Error);
        report.problems.extend(problems);
        if let (Some(policy), false) = (policy, failed) {
            report.policies.insert(name.to_owned(), Arc::new(policy));
        }
    }
    if !found_only {
        report.problems.push(Problem {
            severity: Severity::Error,
            file: format!("policies/{}.toml", only_policy.unwrap_or_default()),
            line: None,
            column: None,
            key: None,
            message: "no such policy".into(),
        });
    }
    if only_policy.is_none() && report.policies.is_empty() && !report.has_errors() {
        report.problems.push(Problem {
            severity: Severity::Warning,
            file: "policies".into(),
            line: None,
            column: None,
            key: None,
            message: "no policy is defined, so no job can be submitted".into(),
        });
    }

    // Cross-file: a watch folder names a policy that exists.
    if let (Some(service), None) = (&report.service, only_policy) {
        let mut cross = Vec::new();
        if service_path.exists()
            && let Ok(text) = std::fs::read_to_string(&service_path)
        {
            let locator = Locator::new(&text);
            for (index, watch) in service.inbox.watch.iter().enumerate() {
                if !report.policies.contains_key(&watch.policy)
                    && !report
                        .problems
                        .iter()
                        .any(|p| p.file.contains(&watch.policy))
                {
                    let key = format!("inbox.watch.{index}.policy");
                    let (line, column) = locator.find(&key);
                    cross.push(Problem {
                        severity: Severity::Error,
                        file: "service.toml".into(),
                        line: Some(line),
                        column: Some(column),
                        key: Some(key),
                        message: format!("policy `{}` does not exist", watch.policy),
                    });
                }
            }
        }
        report.problems.extend(cross);
    }
    report
}
