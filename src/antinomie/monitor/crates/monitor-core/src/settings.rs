// SPDX-License-Identifier: GPL-3.0-only
//! The engine settings shared by every front end: `<data>/settings.json`.
//!
//! The window kept these in eframe's storage, where nothing else can read
//! them. A headless process (`antinomie-cli`, the daemon, a web layer) needs the
//! same values, so they live in the data directory. The file is program
//! written (0600, atomic replace) and only by the process that holds the data
//! lock; a field that is absent reads as its default; fields this version
//! does not know are kept when the file is rewritten; a file that cannot be
//! read is an error and is never silently replaced by defaults.
use crate::{
    TIME_LIMIT_MAX_MINUTES,
    analysis::{AnalysisLimits, detection},
    core_limits::CORE_DEFAULT_BUDGET_MIB,
    data_owner, file_writes, report, storage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// The layout of the file. A version the reader does not know is refused for
/// writing, so an older program never rewrites a newer file.
pub const SETTINGS_VERSION: u32 = 1;

/// The file name inside the data directory.
pub const FILE: &str = "settings.json";

/// How a public destination receives a country and organization.
/// Local addresses are never queried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AddressLookup {
    /// No lookup at all, not even TShark's local GeoIP fields. Set by a
    /// daemon's `service.toml [privacy] address_lookup = "off"`; the window's
    /// settings do not offer it.
    Off,
    /// Installed TShark GeoIP fields only.
    #[default]
    Tshark,
    /// `dig` and `whois` on this machine. TShark GeoIP fields are not requested.
    Whois,
    /// TShark GeoIP first. `dig` and `whois` fill a missing country or organization.
    TsharkThenWhois,
}

/// The Disks tab's limits and toggles (serde-default, so older files load).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskSettings {
    /// Largest file extracted without asking, in MiB.
    pub extract_cap_mib: u32,
    /// Largest file hashed on demand, in MiB.
    pub hash_cap_mib: u32,
    pub hide_dotfiles: bool,
    /// Show modes as octal numbers instead of `rwx`.
    pub numeric_modes: bool,
    /// Compute the SHA-256 of a disk dump (views are never hashed).
    pub dump_hash: bool,
    /// Also record the SHA-256 of every layer of the chain a dump was read
    /// from: doubles the time of a dump, for evidence-grade provenance.
    pub source_digests: bool,
}

impl Default for DiskSettings {
    fn default() -> Self {
        Self {
            extract_cap_mib: 256,
            hash_cap_mib: 64,
            hide_dotfiles: false,
            numeric_modes: false,
            dump_hash: true,
            source_digests: false,
        }
    }
}

impl DiskSettings {
    pub fn extract_cap(&self) -> u64 {
        u64::from(self.extract_cap_mib) * 1024 * 1024
    }

    pub fn hash_cap(&self) -> u64 {
        u64::from(self.hash_cap_mib) * 1024 * 1024
    }
}

/// The settings of `settings.json` (design 2.4.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineSettings {
    pub settings_version: u32,
    /// Rule paths, Sigma Python, scan memory and scan recovered.
    pub triage_detection: detection::Settings,
    /// The most disk space the recordings may use, GiB (1 to 4096).
    pub quota_gib: u32,
    /// Seconds a VM is given to shut down (1 to 120).
    pub shutdown_timeout_s: u64,
    /// Default stored-byte budget of a process core, MiB (1 to 1024).
    pub core_budget_mib: u32,
    /// Minutes each analysis tool may run; 0 leaves each its own limit.
    pub analysis_time_limit_minutes: u32,
    /// File activity: written content kept, per file and per run, MiB.
    pub file_write_file_mib: u32,
    pub file_write_run_mib: u32,
    /// File activity: earlier bytes copied into a recording, per file and per run, MiB.
    pub file_before_file_mib: u32,
    pub file_before_run_mib: u32,
    /// Scan retained evidence when it becomes ready.
    pub automatic_detection: bool,
    /// Allow the rule catalog check and rule-pack downloads.
    pub outbound_catalog: bool,
    /// Public destination country and organization lookups.
    pub address_lookup: AddressLookup,
    /// The sections, formats and options of the last report export.
    pub report_export: report::Choices,
    /// The folder new VMs take their bases from; empty is the default
    /// (`ANTINOMIE_BUNDLE`, else `images`).
    pub bundle: String,
    /// The sizes and counts a static analysis check may reach.
    pub analysis_limits: AnalysisLimits,
    /// Look up symbol tables online for memory dumps without one. A daemon or
    /// container forces this off ([`EngineSettings::for_daemon`]).
    pub memory_online_symbols: bool,
    /// Ask MalwareBazaar for the record of a sample imported from a file,
    /// sending its SHA-256 with the user's own abuse.ch key. Off by default; a
    /// daemon or container forces it off.
    pub sample_hash_lookup: bool,
    /// The Disks tab's settings.
    pub disks: DiskSettings,
    /// How long a VM start and a launch wait (the boot wait, the TCG
    /// multiplier; Tools > Settings > Advanced). Absent in a file no front end
    /// has written them to: the defaults apply, and the window keeps its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<crate::api::StartSettings>,
    /// Fields a newer version wrote; kept when the file is rewritten.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            settings_version: SETTINGS_VERSION,
            triage_detection: Default::default(),
            quota_gib: 4,
            shutdown_timeout_s: 10,
            core_budget_mib: CORE_DEFAULT_BUDGET_MIB,
            analysis_time_limit_minutes: 0,
            file_write_file_mib: (file_writes::DEFAULT_PER_FILE >> 20) as u32,
            file_write_run_mib: (file_writes::DEFAULT_PER_RUN >> 20) as u32,
            file_before_file_mib: (file_writes::DEFAULT_PER_FILE >> 20) as u32,
            file_before_run_mib: (file_writes::DEFAULT_PER_RUN >> 20) as u32,
            automatic_detection: true,
            outbound_catalog: false,
            address_lookup: AddressLookup::default(),
            report_export: Default::default(),
            bundle: String::new(),
            analysis_limits: AnalysisLimits::default(),
            memory_online_symbols: true,
            sample_hash_lookup: false,
            disks: DiskSettings::default(),
            start: None,
            extra: Map::new(),
        }
    }
}

impl EngineSettings {
    /// Refuse a value outside the range the window's editor accepts.
    pub fn validate(&self) -> Result<(), String> {
        fn within<T: PartialOrd + std::fmt::Display>(
            name: &str,
            value: T,
            low: T,
            high: T,
        ) -> Result<(), String> {
            if value < low || value > high {
                return Err(format!("{name} must be {low} to {high}, not {value}"));
            }
            Ok(())
        }
        within("quota_gib", self.quota_gib, 1, 4096)?;
        within("shutdown_timeout_s", self.shutdown_timeout_s, 1, 120)?;
        within("core_budget_mib", self.core_budget_mib, 1, 1024)?;
        within(
            "analysis_time_limit_minutes",
            self.analysis_time_limit_minutes,
            0,
            TIME_LIMIT_MAX_MINUTES,
        )?;
        within("file_write_file_mib", self.file_write_file_mib, 1, 65_536)?;
        within("file_write_run_mib", self.file_write_run_mib, 1, 1_048_576)?;
        within("file_before_file_mib", self.file_before_file_mib, 1, 65_536)?;
        within(
            "file_before_run_mib",
            self.file_before_run_mib,
            1,
            1_048_576,
        )?;
        if let Some(start) = &self.start {
            start
                .validate()
                .map_err(|error| format!("start: {error}"))?;
        }
        Ok(())
    }

    /// The start settings in force: the file's, else the defaults.
    pub fn start(&self) -> crate::api::StartSettings {
        self.start.unwrap_or_default()
    }

    /// The settings a daemon or container runs with: no automatic outbound
    /// traffic, whatever the file says (decided B-H16).
    pub fn for_daemon(mut self) -> Self {
        self.memory_online_symbols = false;
        self.sample_hash_lookup = false;
        self
    }

    /// The caps on the file write content File activity keeps.
    pub fn write_limits(&self) -> file_writes::Limits {
        file_writes::Limits {
            per_file: u64::from(self.file_write_file_mib) << 20,
            per_run: u64::from(self.file_write_run_mib) << 20,
        }
    }

    /// The caps on the earlier file bytes copied into a recording.
    pub fn before_limits(&self) -> file_writes::Limits {
        file_writes::Limits {
            per_file: u64::from(self.file_before_file_mib) << 20,
            per_run: u64::from(self.file_before_run_mib) << 20,
        }
    }

    /// Put the settings that are `BackendOptions` fields into `options`.
    pub fn apply_to(&self, options: &mut crate::BackendOptions) {
        options.capture_quota_size = u64::from(self.quota_gib) * 1024 * 1024 * 1024;
        options.shutdown_timeout = std::time::Duration::from_secs(self.shutdown_timeout_s);
        options.start = self.start();
    }

    /// The settings as a JSON object, keys as in the file.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// [`to_value`](Self::to_value) with the start settings in force shown
    /// even when the file has none, so `start.*` can be read and set.
    fn view(&self) -> Value {
        let mut shown = self.clone();
        shown.start = Some(self.start());
        shown.to_value()
    }

    /// One setting, or all of them for an empty key. A dotted key reaches
    /// into an object (`disks.hide_dotfiles`).
    pub fn get(&self, key: &str) -> Result<Value, String> {
        let root = self.view();
        if key.is_empty() {
            return Ok(root);
        }
        let mut at = &root;
        for part in key.split('.') {
            at = at
                .get(part)
                .ok_or_else(|| format!("no setting named {key}"))?;
        }
        Ok(at.clone())
    }

    /// Set one setting from text: JSON when it parses (`true`, `12`,
    /// `{"a":1}`), else a string. The result must still be a valid
    /// settings object, so a value of the wrong type or range is refused and
    /// nothing changes. Only a key the settings already have may be set.
    pub fn set(&mut self, key: &str, text: &str) -> Result<(), String> {
        let value =
            serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.into()));
        let mut root = self.view();
        let mut parts: Vec<&str> = key.split('.').collect();
        let last = parts
            .pop()
            .filter(|part| !part.is_empty())
            .ok_or("empty setting name")?;
        let mut at = &mut root;
        for part in &parts {
            at = at
                .get_mut(*part)
                .ok_or_else(|| format!("no setting named {key}"))?;
        }
        let object = at
            .as_object_mut()
            .ok_or_else(|| format!("no setting named {key}"))?;
        if !object.contains_key(last) {
            return Err(format!("no setting named {key}"));
        }
        if key == "settings_version" {
            return Err("settings_version is written by the program".into());
        }
        object.insert(last.into(), value);
        let changed: Self =
            serde_json::from_value(root).map_err(|error| format!("{key}: {error}"))?;
        changed.validate()?;
        *self = changed;
        Ok(())
    }
}

/// `<data>/settings.json`; a lane's data folder reads lane 0's
/// ([`crate::lanes`]: the lanes of a daemon share one set of engine settings).
pub fn path(data_dir: &Path) -> PathBuf {
    crate::lanes::shared_root(data_dir).join(FILE)
}

/// The saved settings. `Ok(None)` when no file exists (the first start of a
/// front end that then migrates its own copy). A file that exists but cannot
/// be read or parsed is an error, never the defaults.
pub fn load(data_dir: &Path) -> Result<Option<EngineSettings>, String> {
    let path = path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
        Ok(_) => {}
    }
    let settings: EngineSettings = storage::read_json(&path)?;
    if settings.settings_version > SETTINGS_VERSION {
        return Err(format!(
            "{}: written by a newer version (settings_version {}); this version reads {}",
            path.display(),
            settings.settings_version,
            SETTINGS_VERSION
        ));
    }
    settings
        .validate()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(Some(settings))
}

/// Whether this process holds the lock of `data_dir` (its owner record names
/// this pid while the lock is held).
pub fn holds_data_lock(data_dir: &Path) -> bool {
    matches!(
        data_owner::current_owner(data_dir),
        Ok(Some(data_owner::DataOwner { record: Some(record) })) if record.pid == std::process::id()
    )
}

/// Write the settings: atomic, 0600, and only by the process that holds the
/// data lock. The unknown fields in `settings.extra` are kept.
pub fn save(data_dir: &Path, settings: &EngineSettings) -> Result<(), String> {
    crate::lanes::refuse_in_lane(data_dir, crate::lanes::SharedWrite::EngineSettings)?;
    if !holds_data_lock(data_dir) {
        return Err(
            "settings.json is written only by the process that holds the data folder lock".into(),
        );
    }
    settings.validate()?;
    let mut settings = settings.clone();
    settings.settings_version = SETTINGS_VERSION;
    storage::atomic_json(&path(data_dir), &settings)
}

#[cfg(test)]
mod tests;
