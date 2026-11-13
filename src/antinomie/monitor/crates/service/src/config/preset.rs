// SPDX-License-Identifier: GPL-3.0-only
//! `presets/<name>.toml`: a named set of run options to start from (the
//! presets specification, "The format"). Every key may be left out and takes
//! the default below; unknown keys are errors. A preset grants nothing and
//! locks nothing: permissions, node setup and the caller's limits do.
//!
//! The checks that need the file or the node are in `validate.rs`; the
//! Custom rule (overrides onto a preset) is [`LoadedPreset::apply`].

use super::service::OnDuplicate;
use crate::api::{
    assessment::Label,
    failure::FailureCode,
    run::{PresetBase, Stage},
    spec::{ReportFormat, Route, RunIn, StaticCheck},
};
use antinomie_monitor_core::{
    analysis::{AnalysisKind, AnalysisLimits},
    dump_trigger::{DumpTrigger, TriggerTier},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The name a Custom run stores instead of a preset's (never a file name).
pub const CUSTOM: &str = "custom";

/// `[accepts]` (Auto only): the samples a run of this preset takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Accepts {
    /// Values of `samples::detect_type` plus `"any"`.
    pub types: Vec<String>,
    /// Architectures of `detect_type` plus `"any"`.
    pub arch: Vec<String>,
    /// At most the node ceiling (256 MiB).
    pub max_sample_mib: u32,
}

impl Default for Accepts {
    fn default() -> Self {
        Self {
            types: vec!["elf".into(), "sh".into()],
            arch: vec!["x86_64".into()],
            max_sample_mib: 64,
        }
    }
}

/// `[duplicates]` (Auto only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Duplicates {
    pub on_duplicate: OnDuplicate,
    /// `reuse` also returns a run of another preset (or of another digest).
    pub reuse_across_presets: bool,
}

/// Run program › Source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramSource {
    #[default]
    Upload,
    /// A program already in the base (reserved: 0.9.1).
    GuestPath,
}

/// Run program › User.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum User {
    /// UID and GID 1000.
    #[default]
    Normal,
    /// Needs `run.as_root`.
    Root,
    /// UID and GID 65534.
    Nobody,
    /// `uid` and `gid`; an id below 1000 needs `run.as_root`.
    Custom,
}

/// The id of `nobody` in the guest bases.
pub const NOBODY_ID: u32 = 65534;

/// How a library sample is loaded into the program (reserved: 0.9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreloadHow {
    LdPreload,
    LdAudit,
    Argument,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preload {
    pub sample: String,
    pub how: PreloadHow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraFile {
    pub sample: String,
    pub guest_path: String,
}

/// `[program]`: Run program (Program, Arguments, Session).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Program {
    pub source: ProgramSource,
    pub executable: String,
    /// Upload › Guest path; `{name}` is the sample's file name as the library
    /// puts it in the guest (`<sha8>-<name>`, safe characters).
    pub guest_path: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    /// `NAME=value` entries.
    pub environment: Vec<String>,
    pub user: User,
    /// With `user = "custom"`.
    pub uid: u32,
    pub gid: u32,
    pub run_in: RunIn,
    /// Run time in seconds: 5 up to the node ceiling (and the caller's limit).
    pub run_time_s: u32,
    pub preload: Vec<Preload>,
    pub extra_files: Vec<ExtraFile>,
}

impl Default for Program {
    fn default() -> Self {
        Self {
            source: ProgramSource::Upload,
            executable: String::new(),
            guest_path: "/tmp/{name}".into(),
            arguments: Vec::new(),
            working_directory: "/tmp".into(),
            environment: vec![
                "PATH=/bin:/sbin:/usr/bin:/usr/sbin".into(),
                "TERM=xterm".into(),
            ],
            user: User::Normal,
            uid: 1000,
            gid: 1000,
            run_in: RunIn::AppTerminal,
            run_time_s: 300,
            preload: Vec::new(),
            extra_files: Vec::new(),
        }
    }
}

impl Program {
    /// The UID and GID the program runs as.
    pub fn ids(&self) -> (u32, u32) {
        match self.user {
            User::Normal => (1000, 1000),
            User::Root => (0, 0),
            User::Nobody => (NOBODY_ID, NOBODY_ID),
            User::Custom => (self.uid, self.gid),
        }
    }

    /// Root, or an id below 1000: needs `run.as_root`.
    pub fn privileged(&self) -> bool {
        let (uid, gid) = self.ids();
        uid < 1000 || gid < 1000
    }

    /// Where the sample lands in the guest.
    pub fn sample_path(&self, sha256: &str, name: &str) -> String {
        let default = antinomie_monitor_core::samples::guest_path_of(sha256, name);
        let leaf = default.rsplit('/').next().unwrap_or("sample");
        self.guest_path.replace("{name}", leaf)
    }
}

/// `[record] scope` (Capture all).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordScope {
    #[default]
    Program,
    WholeVm,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Record {
    pub scope: RecordScope,
    /// Screenshot every N seconds, 1 to 999 (`MAX_SCREENSHOT_EVERY_S`); 0 is
    /// off (reserved at 0 here; the engine side is ANT-T0487).
    pub screenshot_every_s: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    pub capture: bool,
    pub route: Route,
    /// Allow private network addresses (needs `route.lan`; reserved).
    pub private_addresses: bool,
    /// Off needs `route.unfiltered` (reserved).
    pub abuse_filter: bool,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            capture: true,
            route: Route::Drop,
            private_addresses: false,
            abuse_filter: true,
        }
    }
}

/// `[dumps]`: Memory dump, Core dump and Dump when suspicious activity is seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Dumps {
    pub memory_dump_on_exit: bool,
    pub core_dump_on_exit: bool,
    /// 64 to 1024 MiB; also the budget of a core the trigger takes.
    pub core_budget_mib: u32,
    pub core_deadline_ms: u32,
    pub dump_when_suspicious: bool,
    pub minimum_tier: TriggerTier,
    pub trigger_memory_dump: bool,
    pub trigger_core: bool,
    /// Trigger cores also read the pages not in memory (guest revision 22).
    pub read_non_resident_pages: bool,
    /// 1 to 8.
    pub max_dumps: u32,
    /// 0 to 3600.
    pub dumps_apart_s: u32,
    /// Reserved (0.9.1).
    pub disk_dump: bool,
}

impl Default for Dumps {
    fn default() -> Self {
        Self {
            memory_dump_on_exit: false,
            core_dump_on_exit: false,
            core_budget_mib: antinomie_monitor_core::core_limits::CORE_DEFAULT_BUDGET_MIB,
            core_deadline_ms: antinomie_monitor_core::core_limits::CORE_LEGACY_TIMEOUT_MS,
            dump_when_suspicious: false,
            minimum_tier: TriggerTier::High,
            trigger_memory_dump: false,
            trigger_core: true,
            read_non_resident_pages: false,
            max_dumps: 1,
            dumps_apart_s: 30,
            disk_dump: false,
        }
    }
}

impl Dumps {
    /// The dump trigger of a run, `None` when it is off or takes nothing.
    pub fn trigger(&self) -> Option<DumpTrigger> {
        (self.dump_when_suspicious && (self.trigger_memory_dump || self.trigger_core)).then(|| {
            DumpTrigger {
                min_tier: self.minimum_tier,
                memory: self.trigger_memory_dump,
                core: self.trigger_core,
                max_dumps: self.max_dumps,
                cooldown_secs: self.dumps_apart_s,
                ..DumpTrigger::default()
            }
        })
    }

    /// Whether the run takes a core (on exit or by the trigger).
    pub fn takes_core(&self) -> bool {
        self.core_dump_on_exit || self.trigger().is_some_and(|t| t.core)
    }

    /// Whether the run takes a memory dump (on exit or by the trigger).
    pub fn takes_memory(&self) -> bool {
        self.memory_dump_on_exit || self.trigger().is_some_and(|t| t.memory)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Vm {
    /// A lane group of node setup (`[lanes] group` in service.toml).
    pub lane_group: String,
    /// Keep the VM after a failure (needs `run.keep_vm`; arrives with 0.9.1).
    pub keep_on_failure: bool,
    /// Allow taking control (0.9.1 interactive sessions; nothing to take in
    /// 0.9.0).
    pub allow_control: bool,
}

impl Default for Vm {
    fn default() -> Self {
        Self {
            lane_group: DEFAULT_LANE_GROUP.into(),
            keep_on_failure: false,
            allow_control: true,
        }
    }
}

/// The lane group a preset uses when it names none.
pub const DEFAULT_LANE_GROUP: &str = "x86_64";

/// `[static_analysis.limits]`: Size limits, each within the engine's range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SizeLimits {
    pub rows_per_check: u32,
    pub listing_mib: u32,
    pub ghidra_disassembly_mib: u32,
    pub text_per_value_bytes: u32,
    pub local_tool_output_mib: u32,
    pub capa_floss_output_mib: u32,
    pub floss_strings: u32,
    pub floss_largest_file_mib: u32,
}

impl Default for SizeLimits {
    fn default() -> Self {
        let d = AnalysisLimits::DEFAULT;
        Self {
            rows_per_check: d.rows,
            listing_mib: d.listing_mib,
            ghidra_disassembly_mib: d.ghidra_listing_mib,
            text_per_value_bytes: d.value_bytes,
            local_tool_output_mib: d.tool_output_mib,
            capa_floss_output_mib: d.large_output_mib,
            floss_strings: d.floss_strings,
            floss_largest_file_mib: d.floss_file_mib,
        }
    }
}

impl SizeLimits {
    /// Each key with the engine's setting it sets.
    pub fn entries(
        &self,
    ) -> [(
        &'static str,
        antinomie_monitor_core::analysis::LimitSetting,
        u32,
    ); 8] {
        use antinomie_monitor_core::analysis::LimitSetting as S;
        [
            ("rows_per_check", S::Rows, self.rows_per_check),
            ("listing_mib", S::Listing, self.listing_mib),
            (
                "ghidra_disassembly_mib",
                S::GhidraListing,
                self.ghidra_disassembly_mib,
            ),
            ("text_per_value_bytes", S::Value, self.text_per_value_bytes),
            (
                "local_tool_output_mib",
                S::ToolOutput,
                self.local_tool_output_mib,
            ),
            (
                "capa_floss_output_mib",
                S::LargeOutput,
                self.capa_floss_output_mib,
            ),
            ("floss_strings", S::FlossStrings, self.floss_strings),
            (
                "floss_largest_file_mib",
                S::FlossFile,
                self.floss_largest_file_mib,
            ),
        ]
    }
}

/// The eleven Triage checks (`AnalysisKind::TRIAGE`).
pub const TRIAGE_CHECKS: [StaticCheck; 11] = [
    StaticCheck::Metadata,
    StaticCheck::Structures,
    StaticCheck::Strings,
    StaticCheck::Regex,
    StaticCheck::Entropy,
    StaticCheck::Hardening,
    StaticCheck::Rules,
    StaticCheck::Identification,
    StaticCheck::Capabilities,
    StaticCheck::Embedded,
    StaticCheck::Unpacking,
];

/// Deep analysis: Disassembly, Decompilation, FLOSS strings.
pub const DEEP_CHECKS: [StaticCheck; 3] = [
    StaticCheck::Disassembly,
    StaticCheck::Decompilation,
    StaticCheck::Floss,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StaticAnalysis {
    pub enabled: bool,
    pub triage_checks: Vec<StaticCheck>,
    pub deep_checks: Vec<StaticCheck>,
    /// 0: each tool's own limit (the host's expected time of the tool); 1 to
    /// 480 minutes: that fixed limit for every tool.
    pub time_limit_per_tool_min: u32,
    pub ghidra_disassembly: bool,
    /// Checks whose timing out or stopping short fails the `analyse` stage.
    pub required_checks: Vec<StaticCheck>,
    /// Reserved (0.9.1).
    pub rebuilt_file_mib: u32,
    /// Reserved (0.9.1).
    pub rebuilt_run_mib: u32,
    pub limits: SizeLimits,
}

impl Default for StaticAnalysis {
    fn default() -> Self {
        Self {
            enabled: true,
            triage_checks: TRIAGE_CHECKS.to_vec(),
            deep_checks: Vec::new(),
            time_limit_per_tool_min: 0,
            ghidra_disassembly: false,
            required_checks: Vec::new(),
            rebuilt_file_mib: 16,
            rebuilt_run_mib: 256,
            limits: SizeLimits::default(),
        }
    }
}

impl StaticAnalysis {
    /// The checks the run asks for, Triage checks first; none when off.
    pub fn checks(&self) -> Vec<StaticCheck> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out: Vec<StaticCheck> = Vec::new();
        for check in self.triage_checks.iter().chain(&self.deep_checks) {
            if !out.contains(check) {
                out.push(*check);
            }
        }
        out
    }

    /// The fixed per-tool limit, `None` for each tool's own.
    pub fn fixed_limit_min(&self) -> Option<u32> {
        (self.time_limit_per_tool_min > 0).then_some(self.time_limit_per_tool_min)
    }

    /// The engine's size limits and the Ghidra choice of this preset.
    pub fn engine_limits(&self) -> AnalysisLimits {
        let mut limits = AnalysisLimits::DEFAULT;
        for (_, setting, value) in self.limits.entries() {
            limits.set(setting, value);
        }
        limits.ghidra_disassembly = self.ghidra_disassembly;
        limits
    }
}

/// The engine's kind of a check.
pub fn kind_of(check: StaticCheck) -> AnalysisKind {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Triage {
    pub enabled: bool,
    /// File activity: written content kept, per file and per run (reserved).
    pub written_per_file_mib: u32,
    pub written_per_run_mib: u32,
    /// File activity: earlier bytes kept, per file and per run (reserved).
    pub earlier_per_file_mib: u32,
    pub earlier_per_run_mib: u32,
}

impl Default for Triage {
    fn default() -> Self {
        Self {
            enabled: true,
            written_per_file_mib: 64,
            written_per_run_mib: 1024,
            earlier_per_file_mib: 64,
            earlier_per_run_mib: 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Detection {
    pub yara: bool,
    pub sigma: bool,
    pub ids: bool,
    /// Scan every N minutes while the program runs; 0 is off (reserved).
    pub scan_every_min: u32,
    /// Check online (needs `lookup.online`).
    pub check_online: bool,
}

impl Default for Detection {
    fn default() -> Self {
        Self {
            yara: true,
            sigma: true,
            ids: true,
            scan_every_min: 0,
            check_online: false,
        }
    }
}

/// One of the report's eleven sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSection {
    Summary,
    Indicators,
    Attack,
    Processes,
    SuspiciousActivity,
    Files,
    FileActivity,
    Network,
    Detection,
    Evidence,
    Custody,
}

/// `report.sections`: `"all"` or a list of sections (reserved: `"all"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReportSections {
    Name(String),
    List(Vec<ReportSection>),
}

impl Default for ReportSections {
    fn default() -> Self {
        Self::Name("all".into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Report {
    pub formats: Vec<ReportFormat>,
    pub sections: ReportSections,
    pub bundle: bool,
    pub defang: bool,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            formats: vec![ReportFormat::Html, ReportFormat::Json],
            sections: ReportSections::default(),
            bundle: false,
            defang: true,
        }
    }
}

/// `verdict.mapping`: the name `default`. (A table is refused by `config
/// validate`; custom rules are `[[verdict.rule]]`.)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerdictMapping {
    Name(String),
    Table(BTreeMap<String, toml::Value>),
}

/// One `[[verdict.rule]]` (design 4.9.2): the first rule whose `when` holds
/// gives the label; `score` is the largest score of the rules that hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictRule {
    /// An expression of `crate::verdict::expr` over a closed set of fields.
    pub when: String,
    pub label: Label,
    /// 0 to 100.
    #[serde(default)]
    pub score: Option<u8>,
}

/// `[verdict]` (Auto only).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct VerdictSettings {
    pub mapping: VerdictMapping,
    /// A custom mapping; with none, the default mapping of 4.9.2 applies.
    pub rule: Vec<VerdictRule>,
    /// Tag the library sample with `auto:label=<label>` and
    /// `auto:preset=<preset>` when a run of this preset ends (4.9.3).
    pub tag_library: bool,
}

impl Default for VerdictSettings {
    fn default() -> Self {
        Self {
            mapping: VerdictMapping::Name("default".into()),
            rule: Vec::new(),
            tag_library: false,
        }
    }
}

/// `[retry]` (Auto only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retry {
    pub max_attempts: u32,
    pub backoff_s: Vec<u32>,
    pub retry_on: Vec<FailureCode>,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            backoff_s: vec![30, 120],
            retry_on: vec![
                FailureCode::VmStartFailed,
                FailureCode::GuestUnreachable,
                FailureCode::UploadFailed,
                FailureCode::GuestLost,
            ],
        }
    }
}

/// The roles a preset is offered to when it names none.
pub fn default_offered_to() -> Vec<String> {
    vec!["analyst".into(), "lead".into(), "admin".into()]
}

/// One preset as parsed from its file. Every table is optional; an absent key
/// takes its default (Standard is all defaults).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Preset {
    /// The name on Submit; the file name when empty.
    pub title: String,
    pub description: String,
    /// The roles that see it on Submit: a list, not a lock.
    pub offered_to: Vec<String>,
    /// Stages whose failure fails the run (Auto only); the others make it
    /// `partial`.
    pub required_stages: Vec<Stage>,
    pub accepts: Accepts,
    pub duplicates: Duplicates,
    pub program: Program,
    pub record: Record,
    pub network: Network,
    pub dumps: Dumps,
    pub vm: Vm,
    pub static_analysis: StaticAnalysis,
    pub triage: Triage,
    pub detection: Detection,
    pub report: Report,
    pub verdict: VerdictSettings,
    pub retry: Retry,
}

impl Default for Preset {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            offered_to: default_offered_to(),
            required_stages: vec![Stage::Analyse],
            accepts: Accepts::default(),
            duplicates: Duplicates::default(),
            program: Program::default(),
            record: Record::default(),
            network: Network::default(),
            dumps: Dumps::default(),
            vm: Vm::default(),
            static_analysis: StaticAnalysis::default(),
            triage: Triage::default(),
            detection: Detection::default(),
            report: Report::default(),
            verdict: VerdictSettings::default(),
            retry: Retry::default(),
        }
    }
}

impl Preset {
    /// Whether the `analyse` stage has nothing to do.
    pub fn analyse_skipped(&self) -> bool {
        let d = &self.detection;
        self.static_analysis.checks().is_empty()
            && !self.triage.enabled
            && !(d.yara || d.sigma || d.ids)
    }

    /// Every key as JSON, the form overrides are merged into.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// The keys of a preset that are not run options: an override may not set
/// them.
pub const NOT_RUN_OPTIONS: [&str; 3] = ["title", "description", "offered_to"];

/// A preset as the service holds it, and as a run freezes it: the name (the
/// file stem, or [`CUSTOM`]), the SHA-256 of the file (of the resolved options
/// for a Custom run), and the options.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadedPreset {
    pub name: String,
    pub digest: String,
    /// A Custom run: the preset it started from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub based_on: Option<PresetBase>,
    /// A Custom run: the dotted keys it changed (`program.run_time_s`), in
    /// the order of their names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
    /// One of the five presets that ship with the service.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub built_in: bool,
    pub preset: Preset,
}

/// An override that does not fit the preset: the request field and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideError {
    pub field: String,
    pub message: String,
}

fn override_error(field: impl Into<String>, message: impl Into<String>) -> OverrideError {
    OverrideError {
        field: field.into(),
        message: message.into(),
    }
}

/// The SHA-256 of `bytes` in lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl LoadedPreset {
    /// A preset of `name` with its digest (from a file: not built in, not
    /// Custom).
    pub fn named(name: impl Into<String>, digest: impl Into<String>, preset: Preset) -> Self {
        Self {
            name: name.into(),
            digest: digest.into(),
            based_on: None,
            changes: Vec::new(),
            built_in: false,
            preset,
        }
    }

    /// The display name: the title, else the file name.
    pub fn title(&self) -> &str {
        if self.preset.title.is_empty() {
            &self.name
        } else {
            &self.preset.title
        }
    }

    /// The Custom rule: `overrides` (a partial preset, the same tables and
    /// keys as the file) resolved onto this preset. An override that changes
    /// no value leaves the preset as it is; any change makes the result
    /// Custom, `based_on` this preset, with the changed keys listed.
    pub fn apply(&self, overrides: &Map<String, Value>) -> Result<LoadedPreset, OverrideError> {
        let base = self.preset.to_json();
        check_keys(&base, overrides, "")?;
        let mut merged = base.clone();
        merge(&mut merged, overrides);
        let resolved: Preset = serde_json::from_value(merged)
            .map_err(|e| override_error("overrides", e.to_string()))?;
        let after = resolved.to_json();
        let mut changes = Vec::new();
        diff(&base, &after, "", &mut changes);
        changes.sort();
        if changes.is_empty() {
            return Ok(self.clone());
        }
        let text = serde_json::to_string(&after).unwrap_or_default();
        Ok(LoadedPreset {
            name: CUSTOM.into(),
            digest: sha256_hex(text.as_bytes()),
            based_on: Some(PresetBase {
                name: self.name.clone(),
                digest: self.digest.clone(),
            }),
            changes,
            built_in: false,
            preset: resolved,
        })
    }

    /// The preset a Custom run was based on, else this one's name.
    pub fn base_name(&self) -> &str {
        self.based_on.as_ref().map_or(&self.name, |base| &base.name)
    }

    /// What a run records of its preset.
    pub fn reference(&self) -> crate::api::run::PresetRef {
        crate::api::run::PresetRef {
            name: self.name.clone(),
            digest: self.digest.clone(),
            based_on: self.based_on.clone(),
            changes: self.changes.clone(),
        }
    }
}

/// The changed keys of `after` against `base` as a partial preset (the form a
/// stored run keeps in `spec.overrides`).
pub fn changed_options(base: &Preset, after: &Preset) -> Map<String, Value> {
    fn walk(base: &Value, after: &Value, out: &mut Map<String, Value>) {
        let (Some(b), Some(a)) = (base.as_object(), after.as_object()) else {
            return;
        };
        for (key, value) in a {
            match (b.get(key), value) {
                (Some(old), Value::Object(_)) if old.is_object() => {
                    let mut inner = Map::new();
                    walk(old, value, &mut inner);
                    if !inner.is_empty() {
                        out.insert(key.clone(), Value::Object(inner));
                    }
                }
                (Some(old), _) if old == value => {}
                _ => {
                    out.insert(key.clone(), value.clone());
                }
            }
        }
    }
    let mut out = Map::new();
    walk(&base.to_json(), &after.to_json(), &mut out);
    out
}

/// Every key of `overrides` must be a key of the preset; a table stays a
/// table.
fn check_keys(
    base: &Value,
    overrides: &Map<String, Value>,
    prefix: &str,
) -> Result<(), OverrideError> {
    for (key, value) in overrides {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if prefix.is_empty() && NOT_RUN_OPTIONS.contains(&key.as_str()) {
            return Err(override_error(
                format!("overrides.{path}"),
                "not a run option; only a preset file sets it",
            ));
        }
        let Some(known) = base.get(key) else {
            return Err(override_error(
                format!("overrides.{path}"),
                "unknown key; overrides take the tables and keys of a preset file",
            ));
        };
        match (known, value) {
            (Value::Object(_), Value::Object(inner)) => check_keys(known, inner, &path)?,
            (Value::Object(_), _) => {
                return Err(override_error(
                    format!("overrides.{path}"),
                    "a table of the preset; give its keys",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Tables merge key by key; any other value replaces.
fn merge(base: &mut Value, overrides: &Map<String, Value>) {
    let Some(target) = base.as_object_mut() else {
        return;
    };
    for (key, value) in overrides {
        match (target.get_mut(key), value) {
            (Some(slot @ Value::Object(_)), Value::Object(inner)) => merge(slot, inner),
            _ => {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

/// The dotted keys whose value differs (a list is one value).
fn diff(base: &Value, after: &Value, prefix: &str, out: &mut Vec<String>) {
    match (base, after) {
        (Value::Object(b), Value::Object(a)) => {
            for (key, value) in a {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match b.get(key) {
                    Some(old) => diff(old, value, &path, out),
                    None => out.push(path),
                }
            }
        }
        _ if base != after => out.push(prefix.to_owned()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn standard() -> LoadedPreset {
        LoadedPreset {
            name: "standard".into(),
            digest: "d".into(),
            based_on: None,
            changes: Vec::new(),
            built_in: true,
            preset: Preset::default(),
        }
    }

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn the_defaults_are_the_format_of_the_specification() {
        let p = Preset::default();
        assert_eq!(p.offered_to, ["analyst", "lead", "admin"]);
        assert_eq!(p.accepts.types, ["elf", "sh"]);
        assert_eq!(p.program.guest_path, "/tmp/{name}");
        assert_eq!(p.program.working_directory, "/tmp");
        assert_eq!(p.program.run_time_s, 300);
        assert_eq!(p.program.ids(), (1000, 1000));
        assert_eq!(p.dumps.core_budget_mib, 256);
        assert_eq!(p.dumps.core_deadline_ms, 5000);
        assert_eq!((p.dumps.max_dumps, p.dumps.dumps_apart_s), (1, 30));
        assert_eq!(p.vm.lane_group, "x86_64");
        assert_eq!(p.static_analysis.checks().len(), 11);
        assert_eq!(p.static_analysis.fixed_limit_min(), None);
        assert!(!p.static_analysis.engine_limits().ghidra_disassembly);
        assert_eq!(p.report.formats, [ReportFormat::Html, ReportFormat::Json]);
        assert_eq!(p.report.sections, ReportSections::Name("all".into()));
        assert!(!p.analyse_skipped());
        assert!(p.dumps.trigger().is_none());
    }

    #[test]
    fn the_users_and_their_ids() {
        let mut program = Program::default();
        for (user, ids, privileged) in [
            (User::Normal, (1000, 1000), false),
            (User::Root, (0, 0), true),
            (User::Nobody, (65534, 65534), false),
        ] {
            program.user = user;
            assert_eq!((program.ids(), program.privileged()), (ids, privileged));
        }
        program.user = User::Custom;
        program.uid = 1001;
        program.gid = 999;
        assert!(program.privileged());
        assert_eq!(
            program.sample_path(&"ab".repeat(32), "x y"),
            "/tmp/abababab-x_y"
        );
    }

    #[test]
    fn an_override_that_changes_nothing_keeps_the_preset() {
        let base = standard();
        let same = base
            .apply(&map(json!({"program": {"run_time_s": 300}})))
            .unwrap();
        assert_eq!(same, base);
        assert_eq!(base.apply(&Map::new()).unwrap(), base);
    }

    #[test]
    fn a_change_makes_the_run_custom_based_on_the_preset() {
        let base = standard();
        let custom = base
            .apply(&map(json!({
                "program": {"run_time_s": 600, "arguments": ["-v"]},
                "report": {"formats": ["html", "json", "pdf"]},
                "dumps": {"core_dump_on_exit": true}
            })))
            .unwrap();
        assert_eq!(custom.name, CUSTOM);
        assert_eq!(
            custom.based_on,
            Some(PresetBase {
                name: "standard".into(),
                digest: "d".into()
            })
        );
        let mut changes = custom.changes.clone();
        changes.sort();
        assert_eq!(
            changes,
            [
                "dumps.core_dump_on_exit",
                "program.arguments",
                "program.run_time_s",
                "report.formats"
            ]
        );
        assert_eq!(custom.preset.program.run_time_s, 600);
        assert_eq!(custom.digest.len(), 64);
        assert_eq!(
            Value::Object(changed_options(&base.preset, &custom.preset)),
            json!({
                "program": {"run_time_s": 600, "arguments": ["-v"]},
                "report": {"formats": ["html", "json", "pdf"]},
                "dumps": {"core_dump_on_exit": true}
            })
        );
    }

    #[test]
    fn overrides_take_only_the_keys_of_a_preset() {
        let base = standard();
        for (overrides, field) in [
            (
                json!({"program": {"timeout_s": 5}}),
                "overrides.program.timeout_s",
            ),
            (json!({"run": {"timeout_s": 5}}), "overrides.run"),
            (json!({"title": "x"}), "overrides.title"),
            (json!({"offered_to": []}), "overrides.offered_to"),
            (json!({"program": 5}), "overrides.program"),
        ] {
            assert_eq!(base.apply(&map(overrides)).unwrap_err().field, field);
        }
        let wrong = base
            .apply(&map(json!({"program": {"run_time_s": "long"}})))
            .unwrap_err();
        assert_eq!(wrong.field, "overrides");
    }

    #[test]
    fn the_trigger_follows_its_switches() {
        let mut dumps = Dumps {
            dump_when_suspicious: true,
            minimum_tier: TriggerTier::Medium,
            trigger_memory_dump: true,
            max_dumps: 3,
            dumps_apart_s: 60,
            ..Dumps::default()
        };
        let trigger = dumps.trigger().unwrap();
        assert!(trigger.memory && trigger.core);
        assert_eq!((trigger.max_dumps, trigger.cooldown_secs), (3, 60));
        assert!(dumps.takes_core() && dumps.takes_memory());
        dumps.trigger_core = false;
        dumps.trigger_memory_dump = false;
        assert!(dumps.trigger().is_none());
        assert!(!dumps.takes_core());
    }
}
