// SPDX-License-Identifier: GPL-3.0-only
//! `JobSpec` (design 5.4.1): what a caller asks for. Every field but the
//! sample is optional; an absent field takes the policy's value, then the
//! system default. An unknown field fails (`deny_unknown_fields`), as the
//! contract says: no silent ignore.

use super::ids::{Sha256Hex, UploadId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The sample of a job. Exactly one member is set ([`SampleSource::validate`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleSource {
    /// A sample already in the library.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hex>,
    /// Local-only: a regular file on the host, read once and archived into
    /// the library. Never present in a remote reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// A finished staged upload (sealed, hashed); expires after 24 hours unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<UploadId>,
}

impl SampleSource {
    /// `Err` names the field the caller got wrong.
    pub fn validate(&self) -> Result<(), SpecError> {
        let set = [
            self.sha256.is_some(),
            self.path.is_some(),
            self.upload_id.is_some(),
        ]
        .into_iter()
        .filter(|set| *set)
        .count();
        if set == 1 {
            Ok(())
        } else {
            Err(SpecError {
                field: "sample".into(),
                message:
                    "exactly one of sample.sha256, sample.path or sample.upload_id is required"
                        .into(),
            })
        }
    }
}

/// A validation failure of a spec: the field and one sentence. The service
/// maps it to `invalid_argument` with `field` set.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {message}")]
pub struct SpecError {
    pub field: String,
    pub message: String,
}

/// A network route by the engine's own serde spelling (`RouteKind`). `drop`
/// and `inet_sim` need no permission; a live route needs its `route.*`
/// permission and is then refused `unavailable_on_node` (no route is set up
/// for the service before 0.9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Drop,
    Internet,
    InetSim,
    Tor,
    Vpn,
    Socks5,
}

impl Route {
    /// Whether a v1 job may use the route (decided D6).
    pub fn allowed_in_v1(self) -> bool {
        matches!(self, Self::Drop | Self::InetSim)
    }
}

/// How the program is run in the guest. v1 supports `app_terminal` only
/// (decided B-H24); the other two are reserved and fail `unsupported`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunIn {
    AppTerminal,
    GuestDesktop,
    GuestDesktopTerminal,
}

/// A guest identity: `user` (UID/GID 1000, the default), `root` (needs the
/// `run.as_root` permission, as does an id below 1000) or explicit ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RunAs {
    Named(RunAsName),
    Ids(RunAsIds),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunAsName {
    User,
    Root,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunAsIds {
    pub uid: u32,
    pub gid: u32,
}

/// A process core on exit: a switch, or its limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum CoreDump {
    Switch(bool),
    Limits(CoreLimits),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreLimits {
    pub max_mib: u32,
    pub timeout_ms: u32,
}

/// The names of `AnalysisKind` in lower snake case (`analysis/types.rs:7`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheck {
    Metadata,
    Structures,
    Strings,
    Regex,
    Entropy,
    Hardening,
    Rules,
    Identification,
    Capabilities,
    Disassembly,
    Decompilation,
    Embedded,
    Floss,
    Unpacking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticPreset {
    None,
    Triage,
}

/// Host-side static analysis of the library copy, run in the `analyse` stage:
/// `none`, `triage` (the engine's eleven-tool set) or a list of checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StaticChecks {
    Preset(StaticPreset),
    Names(Vec<StaticCheck>),
}

/// Which detection engines run on the evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectionSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yara: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigma: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<bool>,
}

/// A report format (`report.get`, `overrides.reports`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Html,
    Pdf,
    Json,
    Misp,
    Stix,
    Md,
}

/// The per-job overrides of the policy (design 5.4.1). `overrides.base` and
/// `overrides.stealth` of revision 1 are removed: the lane VM fixes both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    /// Wall-clock limit of the run in seconds, 5 to the policy `max_run_s`
    /// (default policy 300, maximum 1800). Reaching it ends the run normally
    /// (`end_reason: time_limit`); it is not a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_s: Option<u32>,
    /// Program arguments, at most 64, each at most 4096 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// `K=V` entries, at most 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<RunAs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_in: Option<RunIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,
    /// Packet capture for the run; default true on a VM with a network card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_capture: Option<bool>,
    /// VM memory after the run's tree ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_dump: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_dump: Option<CoreDump>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_checks: Option<StaticChecks>,
    /// Minutes per analysis tool, 0 to 480 (`TIME_LIMIT_MAX_MINUTES`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_time_limit_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<ReportFormat>>,
    /// Evidence bundle zip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_bundle: Option<bool>,
    /// Defang indicators in HTML, PDF and Markdown; default true (B-W10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_defang: Option<bool>,
    /// Leave the VM as the failed run left it, for inspection. Needs the
    /// `run.keep_vm` permission; `true` is refused `unavailable_on_node`:
    /// keeping a VM arrives with 0.9.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_on_failure: Option<bool>,
}

/// What a caller submits with `job.submit`, and the resolved form a [`Job`]
/// carries (policy defaults filled in; `sample.path` removed for remote
/// callers; `sample.sha256` always set after prechecks).
///
/// [`Job`]: super::job::Job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub sample: SampleSource,
    /// File name hint, 1 to 128 bytes, no `/`, no NUL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Policy name; default `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// 0 to 9, higher starts first; default 5; the policy sets a ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// At most 16 pairs; key 1 to 32 bytes `[a-z0-9._-]`, value up to 128 bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// 1 to 128 printable ASCII; scoped to `client_id` (5.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Overrides::is_empty")]
    pub overrides: Overrides,
}

impl Overrides {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A part of the spec that v1 does not offer: the field, and the
/// `details.reason` of the `unsupported` error (design 5.4.1, decided D6 and
/// B-H24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsupported {
    pub field: &'static str,
    pub reason: &'static str,
}

fn bad(field: &str, message: &str) -> SpecError {
    SpecError {
        field: field.into(),
        message: message.into(),
    }
}

impl JobSpec {
    /// The checks of 5.4.1 that need no policy: shape and bounds. A failure
    /// is `invalid_argument` naming the field. Ceilings, presence of the
    /// sample, quotas and the policy itself are the service's checks.
    pub fn validate_shape(&self) -> Result<(), SpecError> {
        self.sample.validate()?;
        if let Some(name) = &self.name
            && (name.is_empty() || name.len() > 128 || name.contains(['/', '\0']))
        {
            return Err(bad("name", "1 to 128 bytes, no `/`, no NUL"));
        }
        if self.priority.is_some_and(|p| p > 9) {
            return Err(bad("priority", "0 to 9"));
        }
        if self.labels.len() > 16 {
            return Err(bad("labels", "at most 16 pairs"));
        }
        for (key, value) in &self.labels {
            let key_ok = (1..=32).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
            if !key_ok {
                return Err(bad("labels", "a key is 1 to 32 bytes of [a-z0-9._-]"));
            }
            if value.len() > 128 {
                return Err(bad("labels", "a value is at most 128 bytes"));
            }
        }
        if let Some(key) = &self.idempotency_key
            && (key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|b| (0x20..0x7f).contains(&b)))
        {
            return Err(bad("idempotency_key", "1 to 128 printable ASCII"));
        }
        let o = &self.overrides;
        if o.timeout_s.is_some_and(|t| t < 5) {
            return Err(bad("overrides.timeout_s", "at least 5 seconds"));
        }
        if let Some(args) = &o.args
            && (args.len() > 64 || args.iter().any(|a| a.len() > 4096))
        {
            return Err(bad("overrides.args", "at most 64 arguments of 4096 bytes"));
        }
        if let Some(env) = &o.env
            && (env.len() > 64 || env.iter().any(|e| !e.contains('=')))
        {
            return Err(bad("overrides.env", "at most 64 entries of the form K=V"));
        }
        if o.static_time_limit_min.is_some_and(|m| m > 480) {
            return Err(bad("overrides.static_time_limit_min", "0 to 480"));
        }
        Ok(())
    }

    /// The first part of the spec that is a valid spelling but not offered in
    /// v1: a desktop run mode. (A live route is checked by admission: its
    /// `route.*` permission, then `unavailable_on_node`.)
    pub fn v1_unsupported(&self) -> Option<Unsupported> {
        let o = &self.overrides;
        if o.run_in.is_some_and(|r| r != RunIn::AppTerminal) {
            return Some(Unsupported {
                field: "overrides.run_in",
                reason: "run_mode_not_in_v1",
            });
        }
        None
    }
}
