// SPDX-License-Identifier: GPL-3.0-only
//! `RunRequest` (design 5.4.1): what a caller asks for. Every field but the
//! sample is optional; the preset (default `standard`) gives every run
//! option, and `overrides` (a partial preset) changes them. An unknown field fails (`deny_unknown_fields`), as the
//! contract says: no silent ignore.

use super::ids::{Sha256Hex, UploadId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The sample of a run. Exactly one member is set ([`SampleSource::validate`]).
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

/// A network route, spelled as in a preset file: `drop`, `inet_sim`,
/// `internet`, `nat`, `tor`, `vpn[:NAME]`, `socks5[:NAME]` (NAME a profile of
/// node setup). `drop` and `inet_sim` need no permission; a live route needs
/// its `route.*` permission and is then refused `unavailable_on_node` (no
/// route is set up for the service before 0.9.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Route {
    #[default]
    Drop,
    InetSim,
    Internet,
    Nat,
    Tor,
    Vpn(Option<String>),
    Socks5(Option<String>),
}

/// The spellings a route takes, for messages.
pub const ROUTE_NAMES: &str = "drop, inet_sim, internet, nat, tor, vpn[:NAME] or socks5[:NAME]";

fn profile_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Route {
    pub fn parse(text: &str) -> Option<Self> {
        let (kind, profile) = match text.split_once(':') {
            Some((kind, name)) => (kind, Some(name)),
            None => (text, None),
        };
        if profile.is_some_and(|name| !profile_name(name)) {
            return None;
        }
        let profile = profile.map(str::to_owned);
        match (kind, profile) {
            ("drop", None) => Some(Self::Drop),
            ("inet_sim", None) => Some(Self::InetSim),
            ("internet", None) => Some(Self::Internet),
            ("nat", None) => Some(Self::Nat),
            ("tor", None) => Some(Self::Tor),
            ("vpn", profile) => Some(Self::Vpn(profile)),
            ("socks5", profile) => Some(Self::Socks5(profile)),
            _ => None,
        }
    }

    /// The route's kind without a profile (`vpn`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::InetSim => "inet_sim",
            Self::Internet => "internet",
            Self::Nat => "nat",
            Self::Tor => "tor",
            Self::Vpn(_) => "vpn",
            Self::Socks5(_) => "socks5",
        }
    }

    /// Whether traffic leaves the lab (every route but `drop` and `inet_sim`).
    pub fn is_live(&self) -> bool {
        !matches!(self, Self::Drop | Self::InetSim)
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vpn(Some(name)) | Self::Socks5(Some(name)) => write!(f, "{}:{name}", self.kind()),
            _ => f.write_str(self.kind()),
        }
    }
}

impl Serialize for Route {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Route {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown route `{text}`; the routes are {ROUTE_NAMES}"
            ))
        })
    }
}

impl JsonSchema for Route {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Route")
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string",
            "pattern": "^(drop|inet_sim|internet|nat|tor|(vpn|socks5)(:[A-Za-z0-9._-]{1,64})?)$",
            "description": "A network route: drop, inet_sim, internet, nat, tor, vpn[:NAME], socks5[:NAME]."})
    }
}

/// How the program is run in the guest. 0.9.0 runs `app_terminal` only; the
/// other two are reserved preset values (refused `unsupported`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunIn {
    #[default]
    AppTerminal,
    GuestDesktop,
    GuestDesktopTerminal,
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

/// The per-run overrides: a partial preset, with the same tables and keys as
/// a preset file (`{"program": {"run_time_s": 600}}`). Any override that
/// changes a value makes the run Custom (the presets specification, "The
/// Custom rule"); a stored run keeps the changed keys only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Overrides(pub Map<String, Value>);

impl Overrides {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a caller submits with `run.submit`, and the form a [`Run`] carries
/// (the preset's name and the priority filled in, `overrides` reduced to the
/// keys that changed a value; `sample.path` removed for remote callers;
/// `sample.sha256` always set after prechecks). The run's resolved options
/// are its frozen preset.
///
/// [`Run`]: super::run::Run
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub sample: SampleSource,
    /// File name hint, 1 to 128 bytes, no `/`, no NUL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The preset's name; default `standard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// 0 to 9, higher starts first; default 5; the caller's limit sets a
    /// ceiling.
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

/// The keys of a preset that are not tables.
const TOP_LEVEL_KEYS: [&str; 4] = ["title", "description", "offered_to", "required_stages"];

fn bad(field: &str, message: &str) -> SpecError {
    SpecError {
        field: field.into(),
        message: message.into(),
    }
}

impl RunRequest {
    /// The checks of 5.4.1 that need no preset: shape and bounds. A failure
    /// is `invalid_argument` naming the field. Ceilings, presence of the
    /// sample, quotas and the preset itself are the service's checks.
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
        if self
            .overrides
            .0
            .iter()
            .any(|(key, value)| !value.is_object() && !TOP_LEVEL_KEYS.contains(&key.as_str()))
        {
            return Err(bad(
                "overrides",
                "a partial preset: tables of keys, as in a preset file",
            ));
        }
        Ok(())
    }
}
