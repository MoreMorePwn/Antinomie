// SPDX-License-Identifier: GPL-3.0-only
//! Parsing and checking `service.toml` and the presets (the built-in ones and
//! `presets/*.toml`). Every problem names the file, the line and the key. A
//! `policies/` folder of 0.9.0 is refused, each old key named with its new
//! home (`migrate.rs`).

use super::{
    builtin,
    catalog::{VmCatalog, VmFacts, VmNet},
    locate::Locator,
    migrate,
    preset::{self, LoadedPreset, Preset},
    service::{Lanes, RevertMode, ServiceConfig},
};
use crate::api::run::Stage;
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};

mod programs;
mod reserved;

use programs::{check_dumps, check_program, check_static};
pub use reserved::{AboveCeiling, Reserved, above_node_ceilings, check_options, reserved};

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
    /// `presets/triage.toml`; `built-in/<name>` for a built-in preset).
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

/// The node ceilings: the highest values the engine and the contract allow.
pub const MAX_RUN_S: u32 = 1800;
pub const MIN_RUN_S: u32 = 5;
pub const MIN_CORE_MIB: u32 = 64;
pub const MAX_CORE_MIB: u32 = 1024;
pub const MAX_STATIC_MINUTES: u32 = 480;
pub const MAX_SAMPLE_MIB: u32 = 256;
/// `record.screenshot_every_s`: 0 is off, else 1 to this many seconds (999),
/// with no node minimum (the user's decision of 2026-11-13, ANT-T0548 F3);
/// checked in `check_preset`. It is the engine's own bound, so every value a
/// preset may hold is one `ExecRequest::validate` takes.
pub const MAX_SCREENSHOT_EVERY_S: u32 = antinomie_monitor_core::timed_shots::MAX_INTERVAL_S;
/// `[retry]`: attempts of a run and the longest wait between two.
pub const MAX_ATTEMPTS: u32 = 10;
pub const MAX_BACKOFF_S: u32 = 3600;

/// The values of `samples::detect_type`.
pub const SAMPLE_TYPES: [&str; 12] = [
    "elf",
    "elf_library",
    "sh",
    "py",
    "pl",
    "script",
    "exe",
    "zip",
    "gz",
    "bz2",
    "xz",
    "data",
];
/// The architectures a preset accepts, in the one spelling (`crate::arch`;
/// the old spellings are read as these).
pub const SAMPLE_ARCHES: [&str; 11] = crate::arch::ARCHES;

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
    if !(1..=super::service::MAX_LANES).contains(&config.daemon.lanes) {
        sink.error(
            "daemon.lanes",
            format!(
                "must be 1 to {} (each lane runs its own VM; 1 is the default)",
                super::service::MAX_LANES
            ),
        );
    }
    if let Some(workers) = config.daemon.host_workers
        && !(1..=super::service::MAX_HOST_WORKERS).contains(&workers)
    {
        sink.error(
            "daemon.host_workers",
            format!("must be 1 to {}", super::service::MAX_HOST_WORKERS),
        );
    }
    if let Some(factor) = config.daemon.host_time_factor
        && !(factor.is_finite() && (1.0..=super::service::MAX_HOST_TIME_FACTOR).contains(&factor))
    {
        sink.error(
            "daemon.host_time_factor",
            format!(
                "must be 1 to {} (times the expected time of an item)",
                super::service::MAX_HOST_TIME_FACTOR
            ),
        );
    }
    if config.daemon.stop_grace_s > super::service::MAX_STOP_GRACE_S {
        sink.error(
            "daemon.stop_grace_s",
            format!(
                "must be 0 to {} (seconds between SIGTERM and SIGKILL)",
                super::service::MAX_STOP_GRACE_S
            ),
        );
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
    if config.queue.wait_s == 0 {
        sink.error("queue.wait_s", "must be at least 1");
    }
    let cap = config.resources.trace_cap_mib;
    if cap != 0 && cap < super::service::MIN_TRACE_CAP_MIB {
        sink.error(
            "resources.trace_cap_mib",
            format!(
                "must be 0 (no cap) or at least {}",
                super::service::MIN_TRACE_CAP_MIB
            ),
        );
    }
    if config.safety.unsafe_routes_ack.is_some() {
        sink.error(
            "safety.unsafe_routes_ack",
            "reserved: no live route is set up on this node in this version",
        );
    }
    check_lanes(&config.lanes, sink);
    if config.query.scan_cache_mib != crate::query::catalogue::QueryLimits::default().scan_cache_mib
    {
        sink.error(
            "query.scan_cache_mib",
            "not supported in this version: the daemon keeps 2 scans in memory; remove the key",
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
    if config.retention.max_recordings_gib == 0 {
        // A cap of 0 bytes would delete every finished job's recording at
        // each pass; 0 is not "no cap".
        sink.error(
            "retention.max_recordings_gib",
            "must be at least 1 (GiB); 0 would delete every recording at each pass",
        );
    }
    if config.inbox.processed_keep_days == 0 {
        sink.error("inbox.processed_keep_days", "must be at least 1 day");
    }
    check_limits(&config.limits.local, "limits.local", sink);
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
        if let Some(most) = watch.priority_max
            && most > MAX_PRIORITY
        {
            sink.error(
                &key("priority_max"),
                format!("0 to {MAX_PRIORITY} (a run's priority)"),
            );
        }
        if watch.policy.is_some() {
            sink.error(&key("policy"), "renamed `preset` (policies became presets)");
        }
        if watch.policy_by_dir.is_some() {
            sink.error(&key("policy_by_dir"), "renamed `preset_by_dir`");
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
    if !config.notify.webhooks.is_empty() {
        sink.error("notify.webhooks", WEBHOOKS_UNSUPPORTED);
    }
}

/// Why `[[notify.webhooks]]` is refused.
pub const WEBHOOKS_UNSUPPORTED: &str = "not supported in this version: webhooks are not delivered; use notify.on_finish or poll the run API";

/// The highest priority a run can have.
pub const MAX_PRIORITY: u8 = 9;

/// A caller's limits (`[limits.local]`): each is checked only when set;
/// `max_runs_per_day` unset is no daily limit.
fn check_limits(limits: &crate::api::ops::Limits, table: &str, sink: &mut Sink<'_>) {
    if let Some(most) = limits.priority_max
        && most > MAX_PRIORITY
    {
        sink.error(
            &format!("{table}.priority_max"),
            format!("0 to {MAX_PRIORITY} (a run's priority)"),
        );
    }
    if let Some(longest) = limits.max_run_s
        && !(MIN_RUN_S..=MAX_RUN_S).contains(&longest)
    {
        sink.error(
            &format!("{table}.max_run_s"),
            format!("{MIN_RUN_S} to {MAX_RUN_S} seconds (the node ceiling)"),
        );
    }
    for (name, value) in [
        ("max_queued", limits.max_queued),
        ("max_running", limits.max_running),
        ("max_runs_per_day", limits.max_runs_per_day),
    ] {
        if value == Some(0) {
            sink.error(
                &format!("{table}.{name}"),
                "must be at least 1; leave it out for no limit",
            );
        }
    }
}

/// The name a preset file stands for: `[a-z0-9._-]`, 1 to 64 bytes, not
/// starting with a dot, and not `custom` (the name of a Custom run).
pub fn valid_preset_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && name != preset::CUSTOM
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// A role name in `offered_to`: `[a-z0-9_-]`, 1 to 32 bytes.
fn valid_role(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

/// Parse one preset file and run the checks that need only the file. A key
/// of a 0.9.0 policy is named with its new home.
pub fn parse_preset(name: &str, file: &str, text: &str) -> (Option<LoadedPreset>, Vec<Problem>) {
    let locator = Locator::new(text);
    let mut sink = Sink {
        file,
        locator: &locator,
        problems: Vec::new(),
    };
    if let Ok(value) = toml::from_str::<toml::Value>(text) {
        for (key, home) in migrate::old_keys(&value) {
            sink.error(&key, migrate::message(home));
        }
        if !sink.problems.is_empty() {
            return (None, sink.problems);
        }
    }
    let preset = match parse_failure(file, text, toml::from_str::<Preset>(text)) {
        Ok(preset) => preset,
        Err(problems) => return (None, problems),
    };
    if !valid_preset_name(name) {
        sink.error(
            "title",
            "the file name is not a valid preset name ([a-z0-9._-], not `custom`)",
        );
    }
    if builtin::is_built_in(name) {
        sink.error(
            "title",
            format!("`{name}` is a built-in preset and read-only; copy it under another name"),
        );
    }
    check_preset(&preset, &mut sink);
    for (key, message) in reserved(&preset) {
        sink.error(key, message);
    }
    if preset.vm.keep_on_failure {
        sink.error(
            "vm.keep_on_failure",
            "keeping a VM arrives in a later version",
        );
    }
    if preset.network.route.is_live() {
        sink.error(
            "network.route",
            format!(
                "route {} is not set up on this node; live routes arrives in a later version",
                preset.network.route
            ),
        );
    }
    (
        Some(LoadedPreset {
            name: name.to_owned(),
            digest: preset::sha256_hex(text.as_bytes()),
            based_on: None,
            changes: Vec::new(),
            built_in: false,
            preset,
        }),
        sink.problems,
    )
}

/// The six built-in presets, parsed. They are checked by the tests; a
/// built-in that does not parse is left out.
pub fn built_in_presets() -> BTreeMap<String, Arc<LoadedPreset>> {
    builtin::BUILT_IN
        .iter()
        .filter_map(|(name, text)| {
            let preset: Preset = toml::from_str(text).ok()?;
            Some((
                (*name).to_owned(),
                Arc::new(LoadedPreset {
                    name: (*name).to_owned(),
                    digest: preset::sha256_hex(text.as_bytes()),
                    based_on: None,
                    changes: Vec::new(),
                    built_in: true,
                    preset,
                }),
            ))
        })
        .collect()
}

/// The six built-in presets on a node whose lane group is `group`
/// (`[lanes] group`, which `auto init` sets from the lane base's
/// architecture). They take the node's lane group, so one of them runs with
/// no file after `auto init`; a group named after an architecture
/// (`arm64`, any spelling of `crate::arch`) makes them accept that
/// architecture instead of x86_64. Their digest then names the group too.
pub fn built_in_presets_for(group: &str) -> BTreeMap<String, Arc<LoadedPreset>> {
    let mut presets = built_in_presets();
    if group == preset::DEFAULT_LANE_GROUP {
        return presets;
    }
    for loaded in presets.values_mut() {
        let mut node = (**loaded).clone();
        node.preset.vm.lane_group = group.to_owned();
        if let Some(arch) = crate::arch::canonical(group) {
            node.preset.accepts.arch = vec![arch.to_owned()];
        }
        node.digest =
            preset::sha256_hex(format!("{}\nlane group {group}\n", node.digest).as_bytes());
        *loaded = Arc::new(node);
    }
    presets
}

/// The checks of one preset's values: ranges, the node ceilings, keys that
/// contradict each other.
fn check_preset(preset: &Preset, sink: &mut Sink<'_>) {
    if preset.title.len() > 64 {
        sink.error("title", "at most 64 bytes");
    }
    if preset.description.len() > 512 {
        sink.error("description", "at most 512 bytes");
    }
    for role in &preset.offered_to {
        if !valid_role(role) {
            sink.error(
                "offered_to",
                format!("`{role}` is not a role name ([a-z0-9_-], 1 to 32 bytes)"),
            );
        }
    }
    let accepts = &preset.accepts;
    if !(1..=MAX_SAMPLE_MIB).contains(&accepts.max_sample_mib) {
        sink.error(
            "accepts.max_sample_mib",
            format!("must be 1 to {MAX_SAMPLE_MIB} (the node ceiling)"),
        );
    }
    if accepts.types.is_empty() {
        sink.error("accepts.types", "must name at least one type");
    }
    for kind in &accepts.types {
        if kind != "any" && !SAMPLE_TYPES.contains(&kind.as_str()) {
            sink.error(
                "accepts.types",
                format!(
                    "unknown type `{kind}`; the types are {}",
                    SAMPLE_TYPES.join(", ")
                ),
            );
        }
    }
    if accepts.arch.is_empty() {
        sink.error("accepts.arch", "must name at least one architecture");
    }
    for arch in &accepts.arch {
        if arch != "any" && !SAMPLE_ARCHES.contains(&arch.as_str()) {
            sink.error(
                "accepts.arch",
                format!(
                    "unknown architecture `{arch}`; the values are {}",
                    SAMPLE_ARCHES.join(", ")
                ),
            );
        }
    }
    check_program(&preset.program, sink);
    check_dumps(preset, sink);
    if preset.record.screenshot_every_s > MAX_SCREENSHOT_EVERY_S {
        sink.error(
            "record.screenshot_every_s",
            format!("must be 0 (off) or 1 to {MAX_SCREENSHOT_EVERY_S} seconds"),
        );
    }
    if !valid_lane_group(&preset.vm.lane_group) {
        sink.error("vm.lane_group", "1 to 64 bytes of [A-Za-z0-9._-]");
    }
    check_static(preset, sink);
    for stage in &preset.required_stages {
        let skipped = match stage {
            Stage::Analyse => preset.analyse_skipped(),
            Stage::Report => preset.report.formats.is_empty(),
            _ => false,
        };
        if skipped {
            sink.error(
                "required_stages",
                format!("the {stage:?} stage is required but this preset skips it").to_lowercase(),
            );
        }
    }
    if let Err(error) = crate::verdict::Mapping::compile(&preset.verdict) {
        sink.error(&error.key(), error.to_string());
    }
    if preset.report.formats.is_empty() && !preset.report.bundle {
        sink.warn("report.formats", "no report is produced");
    }
    let retry = &preset.retry;
    if !(1..=MAX_ATTEMPTS).contains(&retry.max_attempts) {
        sink.error("retry.max_attempts", format!("1 to {MAX_ATTEMPTS}"));
    }
    if retry.max_attempts > 1 && retry.backoff_s.is_empty() {
        sink.error("retry.backoff_s", "needs at least one delay when retrying");
    }
    if retry.backoff_s.len() > MAX_ATTEMPTS as usize
        || retry.backoff_s.iter().any(|&s| s > MAX_BACKOFF_S)
    {
        sink.error(
            "retry.backoff_s",
            format!("at most {MAX_ATTEMPTS} delays of 0 to {MAX_BACKOFF_S} seconds"),
        );
    }
}

/// not parse counts as having it (nothing is added to a broken file).
pub fn has_table(text: &str, name: &str) -> bool {
    toml::from_str::<toml::Table>(text).map_or(true, |table| table.contains_key(name))
}

/// A lane group's name: 1 to 64 bytes of `[A-Za-z0-9._-]`.
pub fn valid_lane_group(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn check_lanes(lanes: &Lanes, sink: &mut Sink<'_>) {
    if !valid_lane_group(&lanes.group) {
        sink.error("lanes.group", "1 to 64 bytes of [A-Za-z0-9._-]");
    }
    if lanes.vm.is_empty() {
        sink.error("lanes.vm", "must name the lane VM");
    }
    match lanes.network.as_str() {
        "routed" | "isolated" | "disconnected" => {}
        "nat" => sink.error(
            "lanes.network",
            "nat is never valid for a lane: NAT lets the guest reach host services",
        ),
        other => sink.error(
            "lanes.network",
            format!("`{other}` is not routed, isolated or disconnected"),
        ),
    }
    if lanes.revert.needs_snapshot() && lanes.revert_to.is_empty() {
        sink.error("lanes.revert_to", "must name a snapshot");
    }
}

/// The lane VM against `[lanes]`; a VM not made yet is a warning.
fn check_lane_vm(lanes: &Lanes, catalog: &dyn VmCatalog, sink: &mut Sink<'_>) -> Option<VmFacts> {
    let Some(facts) = catalog.find(&lanes.vm) else {
        sink.warn(
            "lanes.vm",
            format!(
                "VM `{}` was not found in this data directory; `auto init` makes it",
                lanes.vm
            ),
        );
        return None;
    };
    if facts.network == VmNet::Nat {
        sink.error(
            "lanes.vm",
            format!(
                "VM `{}` uses NAT, which is never valid for a lane",
                facts.name
            ),
        );
    } else if facts.network.as_str() != lanes.network && lanes.network != "nat" {
        sink.error(
            "lanes.network",
            format!(
                "VM `{}` is {}, the lanes require {}",
                facts.name,
                facts.network.as_str(),
                lanes.network
            ),
        );
    }
    match lanes.revert {
        RevertMode::Reset if !facts.snapshots.is_empty() => sink.error(
            "lanes.revert",
            format!(
                "reset is refused on VM `{}`, which has snapshots (every Auto lane keeps \
                 its clean snapshot): use `revert = \"snapshot_disk\"`, which gives the \
                 same clean disk",
                facts.name
            ),
        ),
        RevertMode::SnapshotDisk | RevertMode::SnapshotFull
            if !facts.snapshots.contains(&lanes.revert_to) =>
        {
            sink.error(
                "lanes.revert_to",
                format!(
                    "VM `{}` has no snapshot named `{}`",
                    facts.name, lanes.revert_to
                ),
            );
        }
        // ANT-T0465 (user decision 2026-11-12): refused, not a warning.
        RevertMode::SnapshotFull if facts.disk_snapshots.contains(&lanes.revert_to) => sink.error(
            "lanes.revert",
            format!(
                "snapshot `{}` of VM `{}` holds the disk only, so snapshot_full cannot \
                 resume a running guest from it; use snapshot_disk, or take a full \
                 snapshot (with memory)",
                lanes.revert_to, facts.name
            ),
        ),
        _ => {}
    }
    if let (Some(want), Some(have)) = (&lanes.stealth, &facts.stealth)
        && want != have
    {
        sink.error(
            "lanes.stealth",
            format!(
                "VM `{}` has the profile `{have}`, the lanes expect `{want}`",
                facts.name
            ),
        );
    }
    Some(facts)
}

/// Everything read from a data directory.
#[derive(Debug, Default)]
pub struct ConfigReport {
    /// `None` when `service.toml` exists and does not parse.
    pub service: Option<ServiceConfig>,
    /// The built-in presets and the files without errors.
    pub presets: BTreeMap<String, Arc<LoadedPreset>>,
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

    /// The presets as a running service holds them.
    pub fn preset_set(&self) -> super::PresetSet {
        let group = self
            .service
            .as_ref()
            .map_or(preset::DEFAULT_LANE_GROUP, |s| s.lanes.group.as_str());
        super::PresetSet::new(self.presets.clone()).with_lane_group(group)
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

fn file_problem(severity: Severity, file: &str, message: impl Into<String>) -> Problem {
    Problem {
        severity,
        file: file.to_owned(),
        line: None,
        column: None,
        key: None,
        message: message.into(),
    }
}

fn toml_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// A `policies/` folder of 0.9.0: refused, with every old key's new home.
fn refuse_policies(data_dir: &Path, problems: &mut Vec<Problem>) {
    let dir = data_dir.join("policies");
    if !dir.is_dir() {
        return;
    }
    problems.push(file_problem(
        Severity::Error,
        "policies",
        "policies/ is replaced by presets/: write each policy as \
         presets/<name>.toml with the keys below (default is now the built-in \
         preset standard), then remove policies/",
    ));
    for path in toml_files(&dir) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let shown = format!("policies/{name}");
        let Some(text) = read(&path, &shown, problems) else {
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        let locator = Locator::new(&text);
        let mut sink = Sink {
            file: &shown,
            locator: &locator,
            problems: Vec::new(),
        };
        for (key, home) in migrate::old_keys(&value) {
            sink.error(&key, migrate::message(home));
        }
        problems.extend(sink.problems);
    }
}

/// Read and check `<data>/service.toml` and `<data>/presets/*.toml`. A
/// missing `service.toml` is the defaults; a missing preset directory is the
/// built-in presets alone. `only_preset` limits the preset checks to one file
/// (or one built-in preset).
pub fn load(data_dir: &Path, catalog: &dyn VmCatalog, only_preset: Option<&str>) -> ConfigReport {
    let mut report = ConfigReport::default();
    let service_path = data_dir.join("service.toml");
    let service_text = if service_path.exists() {
        read(&service_path, "service.toml", &mut report.problems)
    } else {
        None
    };
    match &service_text {
        Some(text) => {
            let (config, problems) = parse_service("service.toml", text);
            report.service = config;
            report.problems.extend(problems);
        }
        None if !service_path.exists() => report.service = Some(ServiceConfig::default()),
        None => {}
    }
    let service_locator = Locator::new(service_text.as_deref().unwrap_or(""));
    let mut service_sink = Sink {
        file: "service.toml",
        locator: &service_locator,
        problems: Vec::new(),
    };
    let lanes = report.service.as_ref().map(|s| s.lanes.clone());
    let facts = lanes
        .as_ref()
        .and_then(|lanes| check_lane_vm(lanes, catalog, &mut service_sink));
    report.problems.extend(service_sink.problems);
    refuse_policies(data_dir, &mut report.problems);

    let mut found_only = only_preset.is_none_or(builtin::is_built_in);
    let group = lanes
        .as_ref()
        .map_or(preset::DEFAULT_LANE_GROUP, |lanes| lanes.group.as_str());
    for (name, loaded) in built_in_presets_for(group) {
        if only_preset.is_none_or(|only| only == name) {
            report.presets.insert(name, loaded);
        }
    }
    for path in toml_files(&data_dir.join("presets")) {
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if only_preset.is_some_and(|only| only != name) {
            continue;
        }
        found_only = true;
        let shown = format!("presets/{name}.toml");
        let Some(text) = read(&path, &shown, &mut report.problems) else {
            continue;
        };
        let (preset, problems) = parse_preset(name, &shown, &text);
        let failed = problems.iter().any(|p| p.severity == Severity::Error);
        report.problems.extend(problems);
        if let (Some(preset), false) = (preset, failed) {
            if let Some(problem) = node_problem(&preset, &shown, lanes.as_ref(), facts.as_ref()) {
                report.problems.push(problem);
                continue;
            }
            report.presets.insert(name.to_owned(), Arc::new(preset));
        }
    }
    if !found_only {
        report.problems.push(file_problem(
            Severity::Error,
            &format!("presets/{}.toml", only_preset.unwrap_or_default()),
            "no such preset",
        ));
    }

    // Cross-file: a watch folder names a preset that exists.
    if let (Some(service), None, Some(text)) = (&report.service, only_preset, &service_text) {
        let locator = Locator::new(text);
        let mut sink = Sink {
            file: "service.toml",
            locator: &locator,
            problems: Vec::new(),
        };
        for (index, watch) in service.inbox.watch.iter().enumerate() {
            if !report.presets.contains_key(&watch.preset)
                && !report
                    .problems
                    .iter()
                    .any(|p| p.file.contains(&watch.preset))
            {
                sink.error(
                    &format!("inbox.watch.{index}.preset"),
                    format!("preset `{}` does not exist", watch.preset),
                );
            }
        }
        report.problems.extend(sink.problems);
    }
    report
}

/// A preset file against the node: its lane group exists, and a route other
/// than drop has a routed lane VM.
fn node_problem(
    preset: &LoadedPreset,
    shown: &str,
    lanes: Option<&Lanes>,
    facts: Option<&VmFacts>,
) -> Option<Problem> {
    let lanes = lanes?;
    let problem = |key: &str, message: String| Problem {
        severity: Severity::Error,
        file: shown.to_owned(),
        line: None,
        column: None,
        key: Some(key.to_owned()),
        message,
    };
    if preset.preset.vm.lane_group != lanes.group {
        return Some(problem(
            "vm.lane_group",
            format!(
                "lane group `{}` is not set up on this node (service.toml [lanes] group is `{}`)",
                preset.preset.vm.lane_group, lanes.group
            ),
        ));
    }
    if let Some(facts) = facts
        && preset.preset.network.route != crate::api::spec::Route::Drop
        && facts.network != VmNet::Routed
    {
        return Some(problem(
            "network.route",
            format!(
                "VM `{}` is not routed, so only drop is possible",
                facts.name
            ),
        ));
    }
    None
}
