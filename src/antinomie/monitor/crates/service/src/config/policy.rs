// SPDX-License-Identifier: GPL-3.0-only
//! `policies/<name>.toml` (design 4.4): the defaults and ceilings of a class of
//! jobs. Unknown keys are errors. The checks that need the file, the other
//! files or the lane VM are in `validate.rs`.

use super::service::OnDuplicate;
use crate::api::{
    failure::FailureCode,
    job::Stage,
    ops::Scope,
    spec::{ReportFormat, Route, RunAsName, RunIn, StaticChecks, StaticPreset},
};
use antinomie_monitor_core::dump_trigger::{DumpTrigger, TriggerTier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SamplePolicy {
    /// Values of `samples::detect_type` plus `"any"`.
    pub accept_types: Vec<String>,
    /// Architectures of `detect_type` plus `"any"`.
    pub accept_arch: Vec<String>,
    pub max_sample_mib: u32,
    pub on_duplicate: OnDuplicate,
    /// `reuse` across policies (4.2.2).
    pub reuse_across_policies: bool,
}

impl Default for SamplePolicy {
    fn default() -> Self {
        Self {
            accept_types: vec!["elf".into()],
            accept_arch: vec!["x86_64".into()],
            max_sample_mib: 64,
            on_duplicate: OnDuplicate::Run,
            reuse_across_policies: false,
        }
    }
}

/// How the lane VM is made clean before a job (design 4.5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertMode {
    SnapshotDisk,
    SnapshotFull,
    Reset,
}

impl RevertMode {
    pub fn needs_snapshot(self) -> bool {
        !matches!(self, Self::Reset)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct VmPolicy {
    /// Required; the VM the lane uses.
    pub lane_vm: Option<String>,
    pub base: Option<String>,
    pub revert: RevertMode,
    pub revert_to: String,
    /// Checked against the lane VM, never applied per job.
    pub stealth: Option<String>,
    /// `routed`, `isolated` or `disconnected`. A string so that `nat` gets its
    /// own message.
    pub network: String,
    pub revert_after: bool,
}

impl Default for VmPolicy {
    fn default() -> Self {
        Self {
            lane_vm: None,
            base: None,
            revert: RevertMode::SnapshotDisk,
            revert_to: "auto-clean".into(),
            stealth: None,
            network: "routed".into(),
            revert_after: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RunPolicy {
    pub timeout_s: u32,
    pub max_run_s: u32,
    pub run_as: RunAsName,
    pub allow_root: bool,
    pub run_in: RunIn,
    pub guest_dir: String,
    pub args_allowed: bool,
    pub env_allowed: bool,
    /// Whether a spec may ask to keep the VM as it is after a failure
    /// (`overrides.keep_on_failure`, 5.4.1: "needs the policy to allow it").
    pub allow_keep_on_failure: bool,
}

impl Default for RunPolicy {
    fn default() -> Self {
        Self {
            timeout_s: 300,
            max_run_s: 1800,
            run_as: RunAsName::User,
            allow_root: false,
            run_in: RunIn::AppTerminal,
            guest_dir: "/tmp".into(),
            args_allowed: true,
            env_allowed: false,
            allow_keep_on_failure: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkPolicy {
    pub route: Route,
    /// The ceiling. v1 accepts only `drop` and `inet_sim` (decided D6).
    pub allowed_routes: Vec<Route>,
    pub capture: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            route: Route::Drop,
            allowed_routes: vec![Route::Drop, Route::InetSim],
            capture: true,
        }
    }
}

/// Whether a run takes a dump when the live Triage rules match, and from
/// which tier (the UI's "Dump when suspicious activity is seen"). Off by
/// default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerSetting {
    #[default]
    Off,
    Low,
    Medium,
    High,
}

impl TriggerSetting {
    pub const NAMES: &'static str = "off, low, medium or high";

    pub fn parse(text: &str) -> Option<Self> {
        if text.trim().eq_ignore_ascii_case("off") {
            return Some(Self::Off);
        }
        TriggerTier::from_name(text).map(|tier| match tier {
            TriggerTier::Low => Self::Low,
            TriggerTier::Medium => Self::Medium,
            TriggerTier::High => Self::High,
        })
    }

    pub fn tier(self) -> Option<TriggerTier> {
        match self {
            Self::Off => None,
            Self::Low => Some(TriggerTier::Low),
            Self::Medium => Some(TriggerTier::Medium),
            Self::High => Some(TriggerTier::High),
        }
    }
}

/// What the trigger takes: a core of the process that made the call, the
/// VM's memory, or both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    #[default]
    Core,
    Memory,
    Both,
}

impl TriggerKind {
    pub const NAMES: &'static str = "core, memory or both";

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "core" => Some(Self::Core),
            "memory" => Some(Self::Memory),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// The dump trigger a setting and a kind ask for; `None` when it is off. The
/// other limits are the UI's defaults (one dump, 30 s apart, memory only on a
/// VM of at most 4 GiB).
pub fn trigger_plan(setting: TriggerSetting, kind: TriggerKind) -> Option<DumpTrigger> {
    Some(DumpTrigger {
        min_tier: setting.tier()?,
        memory: matches!(kind, TriggerKind::Memory | TriggerKind::Both),
        core: matches!(kind, TriggerKind::Core | TriggerKind::Both),
        ..DumpTrigger::default()
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvidencePolicy {
    pub memory_dump: bool,
    pub core_dump: bool,
    /// The engine maximum is 1024. Also the budget of a core the trigger takes.
    pub core_max_mib: u32,
    /// Take a dump when the live Triage rules match at this tier or above
    /// (`off`, `low`, `medium`, `high`).
    pub dump_trigger: TriggerSetting,
    /// What the trigger takes: `core`, `memory` or `both`.
    pub dump_trigger_kind: TriggerKind,
}

impl Default for EvidencePolicy {
    fn default() -> Self {
        Self {
            memory_dump: false,
            core_dump: false,
            core_max_mib: 64,
            dump_trigger: TriggerSetting::Off,
            dump_trigger_kind: TriggerKind::Core,
        }
    }
}

impl EvidencePolicy {
    /// The trigger of a job under this policy, `None` when off.
    pub fn trigger(&self) -> Option<DumpTrigger> {
        trigger_plan(self.dump_trigger, self.dump_trigger_kind)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Detection {
    pub yara: bool,
    pub sigma: bool,
    pub ids: bool,
}

impl Default for Detection {
    fn default() -> Self {
        Self {
            yara: true,
            sigma: true,
            ids: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnalysisPolicy {
    pub static_checks: StaticChecks,
    pub static_time_limit_min: u32,
    pub triage: bool,
    pub detection: Detection,
    pub required_stages: Vec<Stage>,
    pub online_ioc: bool,
}

impl Default for AnalysisPolicy {
    fn default() -> Self {
        Self {
            static_checks: StaticChecks::Preset(StaticPreset::Triage),
            static_time_limit_min: 2,
            triage: true,
            detection: Detection::default(),
            required_stages: vec![Stage::Analyse],
            online_ioc: false,
        }
    }
}

impl AnalysisPolicy {
    /// Whether the `analyse` stage has nothing to do.
    pub fn analyse_skipped(&self) -> bool {
        let no_checks = match &self.static_checks {
            StaticChecks::Preset(StaticPreset::None) => true,
            StaticChecks::Preset(StaticPreset::Triage) => false,
            StaticChecks::Names(names) => names.is_empty(),
        };
        no_checks
            && !self.triage
            && !(self.detection.yara || self.detection.sigma || self.detection.ids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ReportPolicy {
    pub formats: Vec<ReportFormat>,
    pub bundle: bool,
    pub defang: bool,
}

impl Default for ReportPolicy {
    fn default() -> Self {
        Self {
            formats: vec![ReportFormat::Html, ReportFormat::Json],
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
    pub label: crate::api::assessment::Label,
    /// 0 to 100.
    #[serde(default)]
    pub score: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct VerdictPolicy {
    pub mapping: VerdictMapping,
    /// A custom mapping; with none, the default mapping of 4.9.2 applies.
    pub rule: Vec<VerdictRule>,
    /// Tag the library sample with `auto:label=<label>` and
    /// `auto:policy=<name>` when a job of this policy ends (4.9.3).
    pub tag_library: bool,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            mapping: VerdictMapping::Name("default".into()),
            rule: Vec::new(),
            tag_library: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_s: Vec<u32>,
    pub retry_on: Vec<FailureCode>,
}

impl Default for RetryPolicy {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccessPolicy {
    pub scopes: Vec<Scope>,
    /// Glob patterns over `client_id`.
    pub clients: Vec<String>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            scopes: vec![Scope::Submit],
            clients: vec!["*".into()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsPolicy {
    pub max_queued_per_client: u32,
    pub max_jobs_per_day: u32,
    pub max_concurrent: u32,
    pub priority_max: u8,
    /// How long a job may wait `queued` for resources, a dependency, quota or
    /// a pending disk layer before it ends `failed` (5.6).
    pub wait_s: u32,
}

impl Default for LimitsPolicy {
    fn default() -> Self {
        Self {
            max_queued_per_client: 50,
            max_jobs_per_day: 500,
            max_concurrent: 1,
            priority_max: 5,
            wait_s: 3600,
        }
    }
}

/// One policy as parsed from its file. Every table is optional; an absent key
/// takes the default of the table in design 4.4.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub description: String,
    pub sample: SamplePolicy,
    pub vm: VmPolicy,
    pub run: RunPolicy,
    pub network: NetworkPolicy,
    pub evidence: EvidencePolicy,
    pub analysis: AnalysisPolicy,
    pub report: ReportPolicy,
    pub verdict: VerdictPolicy,
    pub retry: RetryPolicy,
    pub access: AccessPolicy,
    pub limits: LimitsPolicy,
}

/// A policy as the service holds it: its name (the file stem), the SHA-256 of
/// the file (recorded in every job, design 2) and the parsed content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadedPolicy {
    pub name: String,
    pub digest: String,
    pub policy: Policy,
}

impl LoadedPolicy {
    /// Whether `client_id` matches one of `access.clients` (glob patterns with
    /// `*`) and the policy grants `scope`.
    pub fn allows(&self, client_id: &str, scope: Scope) -> bool {
        self.policy.access.scopes.contains(&scope)
            && self
                .policy
                .access
                .clients
                .iter()
                .any(|pattern| glob(pattern, client_id))
    }
}

/// A glob with `*` for any run of characters (and nothing else special).
pub fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    for (index, part) in parts.iter().enumerate() {
        if index == 0 {
            match rest.strip_prefix(part) {
                Some(after) => rest = after,
                None => return false,
            }
        } else if index == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_client_ids() {
        assert!(glob("*", "local:1000"));
        assert!(glob("local:*", "local:1000"));
        assert!(!glob("local:*", "web:7"));
        assert!(glob("web:*:ci", "web:7:ci"));
        assert!(!glob("web:*:ci", "web:7:cx"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("a*b*c", "aXbYc"));
    }

    #[test]
    fn defaults_match_the_design_table() {
        let policy = Policy::default();
        assert_eq!(policy.sample.accept_types, ["elf"]);
        assert_eq!(policy.sample.accept_arch, ["x86_64"]);
        assert_eq!(policy.run.timeout_s, 300);
        assert_eq!(policy.network.allowed_routes, [Route::Drop, Route::InetSim]);
        assert_eq!(policy.limits.priority_max, 5);
        assert_eq!(policy.limits.wait_s, 3600);
        assert!(!policy.analysis.analyse_skipped());
    }
}
