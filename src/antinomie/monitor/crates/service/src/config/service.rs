// SPDX-License-Identifier: GPL-3.0-only
//! `service.toml` (design 2.4.2): daemon behaviour. Unknown keys are errors.

use crate::api::ops::Permission;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The most lanes `daemon.lanes` may ask for (ANT-T0455 card C). Each lane
/// is an engine with its own VM; one is the default.
pub const MAX_LANES: u32 = 4;
/// `daemon.host_workers` when it is not set.
pub const DEFAULT_HOST_WORKERS: u32 = 2;
/// The most `daemon.host_workers` may be: the engine keeps eight standalone
/// static analyses in its snapshot, and every static item is one of them.
pub const MAX_HOST_WORKERS: u32 = 8;
/// `daemon.host_time_factor` when it is not set.
pub const DEFAULT_HOST_TIME_FACTOR: f64 = 2.0;
/// The largest `daemon.host_time_factor`.
pub const MAX_HOST_TIME_FACTOR: f64 = 20.0;
/// `daemon.stop_grace_s` when it is not set (ANT-T0471).
pub const DEFAULT_STOP_GRACE_S: u32 = 30;
/// The largest `daemon.stop_grace_s`.
pub const MAX_STOP_GRACE_S: u32 = 600;

/// What the daemon does on SIGTERM.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shutdown {
    /// Stop the running job and requeue it.
    #[default]
    Cancel,
    /// Finish the current jobs first, bounded by `drain_timeout_s`.
    Drain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Daemon {
    /// Default `<data>/run/antinomie.sock`.
    pub socket: Option<PathBuf>,
    /// The lanes (engines, each with its own lane VM) the daemon runs: 1 (the
    /// default) to [`MAX_LANES`]. Lane 1 is the data folder itself, lane N
    /// is `<data>/lanes/N/` (made by `auto init --lane N`). A lane starts only
    /// when its lane VM exists and the machine has the RAM for it beside the
    /// lanes before it.
    pub lanes: u32,
    /// Host work items run at once, across every job and lane (the host work
    /// pool, ANT-T0454). Default 2; 1 to [`MAX_HOST_WORKERS`].
    pub host_workers: Option<u32>,
    /// A host work item's time limit is this many times its expected time;
    /// the job's host-stage deadline is this many times the expected work
    /// ahead of it plus its own. Default 2, at least 1.
    pub host_time_factor: Option<f64>,
    /// A host work item stopped by its time limit or by its job's
    /// host-stage deadline gets a graceful stop (SIGTERM to its sandboxed
    /// tool, the cancel flag of in-process work), then SIGKILL after this
    /// many seconds (ANT-T0471). Default 30; 0 to [`MAX_STOP_GRACE_S`], 0
    /// kills at once.
    pub stop_grace_s: u32,
    pub shutdown: Shutdown,
    pub drain_timeout_s: u32,
    /// At shutdown, how long a job already in its host stages (`analyse`,
    /// `report`, `cleanup`) may run on before its waits are interrupted (it
    /// then resumes at `analyse` on the next start).
    pub shutdown_host_grace_s: u32,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            socket: None,
            lanes: 1,
            host_workers: None,
            host_time_factor: None,
            stop_grace_s: DEFAULT_STOP_GRACE_S,
            shutdown: Shutdown::Cancel,
            drain_timeout_s: 600,
            shutdown_host_grace_s: 120,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Queue {
    pub max_queued: u32,
    /// Node-wide cap of queued runs per `client_id`.
    pub per_client_queued: u32,
    pub paused_on_start: bool,
    /// How long a run may wait `queued` for resources, a dependency or a
    /// pending disk layer before it ends `failed` (was the policy's
    /// `limits.wait_s`).
    pub wait_s: u32,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            max_queued: 1000,
            per_client_queued: 100,
            paused_on_start: false,
            wait_s: 3600,
        }
    }
}

/// How the lane VM is made clean before a run (design 4.5.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertMode {
    #[default]
    SnapshotDisk,
    SnapshotFull,
    Reset,
}

impl RevertMode {
    pub fn needs_snapshot(self) -> bool {
        !matches!(self, Self::Reset)
    }
}

/// `[lanes]`: the lanes of this node, the properties 0.9.0 policies held in
/// `[vm]`. 0.9.0 has one lane group: every lane belongs to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Lanes {
    /// The lane group's name, the one presets name in `vm.lane_group`.
    pub group: String,
    /// The lane VM (lane 1's, in the data folder): what `config validate`
    /// checks and the base the lane choice compares.
    pub vm: String,
    pub revert: RevertMode,
    /// The clean snapshot.
    pub revert_to: String,
    /// The stealth profile the lane VM must have; unset: any.
    pub stealth: Option<String>,
    /// `routed`, `isolated` or `disconnected`. A string so that `nat` gets
    /// its own message.
    pub network: String,
}

impl Default for Lanes {
    fn default() -> Self {
        Self {
            group: super::preset::DEFAULT_LANE_GROUP.into(),
            vm: "auto-1".into(),
            revert: RevertMode::SnapshotDisk,
            revert_to: crate::lane::provision::CLEAN_SNAPSHOT.into(),
            stealth: None,
            network: "routed".into(),
        }
    }
}

/// What happens to a watched file after intake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteAfter {
    /// Move to `inbox/processed/`.
    #[default]
    Move,
    Delete,
    Keep,
}

/// `on_duplicate` of a preset or a watch folder (design 4.2.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDuplicate {
    /// Analyse again; the new job has `repeat_of` set.
    #[default]
    Run,
    /// Return the earlier job as the result.
    Reuse,
    /// Fail `duplicate_denied`.
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub path: PathBuf,
    /// The preset its runs use, unchanged.
    #[serde(default = "default_preset_name")]
    pub preset: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub delete_after: DeleteAfter,
    /// Overrides the preset's `on_duplicate` for files of this folder.
    #[serde(default)]
    pub on_duplicate: Option<OnDuplicate>,
    /// Subfolders named after presets select the preset (4.2.1).
    #[serde(default)]
    pub preset_by_dir: bool,
    #[serde(default)]
    pub allow_group_write: bool,
    /// New jobs per minute per folder before the folder pauses.
    #[serde(default = "default_watch_rate")]
    pub watch_rate: u32,
    /// The permissions the folder's runs hold beside `runs.submit` (for
    /// example `["evidence.core_dump"]` for a preset that takes cores). A run
    /// whose options need a permission the folder lacks is rejected
    /// `permission_denied`.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// The 0.9.0 key, renamed `preset`: refused by `config validate` with
    /// that word.
    #[serde(default, skip_serializing)]
    pub policy: Option<String>,
    /// The 0.9.0 key, renamed `preset_by_dir`.
    #[serde(default, skip_serializing)]
    pub policy_by_dir: Option<bool>,
}

impl Watch {
    /// The folder's last component as the `watch` label of its jobs shows it
    /// (control characters as spaces).
    pub fn label(&self) -> String {
        String::from_utf8_lossy(
            self.path
                .file_name()
                .map_or(&b"watch"[..], |n| n.as_encoded_bytes()),
        )
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
    }
}

fn default_preset_name() -> String {
    super::builtin::DEFAULT_PRESET.into()
}

fn default_watch_rate() -> u32 {
    10
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Inbox {
    /// Default `<data>/inbox`.
    pub dir: Option<PathBuf>,
    pub watch: Vec<Watch>,
    /// Days the files of `inbox/processed/` stay before retention removes
    /// them (default 7).
    pub processed_keep_days: u32,
}

impl Default for Inbox {
    fn default() -> Self {
        Self {
            dir: None,
            watch: Vec::new(),
            processed_keep_days: 7,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Resources {
    pub min_free_disk_gib: u32,
    /// Default: the lane VM's RAM plus 2048.
    pub min_free_ram_mib: Option<u32>,
    pub require_kvm: bool,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            min_free_disk_gib: 20,
            min_free_ram_mib: None,
            require_kvm: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    pub jobs_days: u32,
    pub recordings_days: u32,
    pub max_recordings_gib: u32,
    pub keep_failed: bool,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            jobs_days: 90,
            recordings_days: 14,
            max_recordings_gib: 200,
            keep_failed: true,
        }
    }
}

/// Who may read the result drops (`[results] mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultsMode {
    /// Files 0600, folders 0700: the daemon's user only.
    #[default]
    Private,
    /// Files 0640, folders 0750: the daemon's group may read.
    Group,
}

impl ResultsMode {
    pub fn file_mode(self) -> u32 {
        match self {
            Self::Private => 0o600,
            Self::Group => 0o640,
        }
    }

    pub fn dir_mode(self) -> u32 {
        match self {
            Self::Private => 0o700,
            Self::Group => 0o750,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Results {
    pub dir: Option<PathBuf>,
    pub mode: ResultsMode,
}

/// Reserved: no live route is set up for the service in 0.9.0 (a job asking
/// for one is refused `unavailable_on_node`); the key is parsed and refused
/// until the per-route acknowledgement of 0.9.1's node route setup.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Safety {
    pub unsafe_routes_ack: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressLookup {
    #[default]
    Off,
    Tshark,
}

impl AddressLookup {
    /// The mode the Triage scan runs with.
    pub fn triage_mode(self) -> antinomie_monitor_core::settings::AddressLookup {
        use antinomie_monitor_core::settings::AddressLookup as Mode;
        match self {
            Self::Off => Mode::Off,
            Self::Tshark => Mode::Tshark,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    pub address_lookup: AddressLookup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Query {
    pub light_concurrency: u32,
    pub heavy_concurrency: u32,
    pub light_timeout_s: u32,
    pub heavy_timeout_s: u32,
    pub scan_cache_mib: u32,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            light_concurrency: 16,
            heavy_concurrency: 2,
            light_timeout_s: 10,
            heavy_timeout_s: 60,
            scan_cache_mib: 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub url: String,
    pub secret_file: PathBuf,
    #[serde(default = "default_webhook_events")]
    pub events: Vec<String>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_s: u32,
    #[serde(default = "default_webhook_retries")]
    pub retries: u32,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_webhook_events() -> Vec<String> {
    vec!["job.finished".into()]
}
fn default_webhook_timeout() -> u32 {
    10
}
fn default_webhook_retries() -> u32 {
    3
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Notify {
    pub webhooks: Vec<Webhook>,
    /// An argv, never run through a shell.
    pub on_finish: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub level: LogLevel,
    pub format: LogFormat,
    /// Default: stderr.
    pub file: Option<PathBuf>,
}

/// The whole of `service.toml`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServiceConfig {
    pub daemon: Daemon,
    pub queue: Queue,
    pub lanes: Lanes,
    pub inbox: Inbox,
    pub resources: Resources,
    pub retention: Retention,
    pub results: Results,
    pub safety: Safety,
    pub privacy: Privacy,
    pub query: Query,
    pub notify: Notify,
    pub log: Log,
}

impl ServiceConfig {
    /// The socket path: the configured one, else `<data>/run/antinomie.sock`.
    pub fn socket_path(&self, data_dir: &Path) -> PathBuf {
        self.daemon
            .socket
            .clone()
            .unwrap_or_else(|| data_dir.join("run").join("antinomie.sock"))
    }

    /// The inbox root: the configured one, else `<data>/inbox`.
    pub fn inbox_dir(&self, data_dir: &Path) -> PathBuf {
        self.inbox
            .dir
            .clone()
            .unwrap_or_else(|| data_dir.join("inbox"))
    }

    /// Host work items at once: the configured number, else
    /// [`DEFAULT_HOST_WORKERS`] (user decision 2026-11-11).
    pub fn host_workers(&self) -> u32 {
        self.daemon
            .host_workers
            .unwrap_or(DEFAULT_HOST_WORKERS)
            .clamp(1, MAX_HOST_WORKERS)
    }

    /// `daemon.host_time_factor`, else [`DEFAULT_HOST_TIME_FACTOR`].
    pub fn host_time_factor(&self) -> f64 {
        self.daemon
            .host_time_factor
            .filter(|f| f.is_finite() && *f >= 1.0)
            .unwrap_or(DEFAULT_HOST_TIME_FACTOR)
    }

    /// The free-RAM floor for a lane VM with `vm_ram_mib`: the configured
    /// number, else the VM's RAM plus 2048.
    pub fn min_free_ram_mib(&self, vm_ram_mib: u32) -> u32 {
        self.resources
            .min_free_ram_mib
            .unwrap_or(vm_ram_mib.saturating_add(2048))
    }
}
