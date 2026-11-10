// SPDX-License-Identifier: GPL-3.0-only
//! `service.toml` (design 2.4.2): daemon behaviour. Unknown keys are errors.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Daemon {
    /// Default `<data>/run/antinomie.sock`.
    pub socket: Option<PathBuf>,
    /// Values above 1 fail `unsupported` (decided D4).
    pub lanes: u32,
    /// Default `min(4, cpus/4)`, at least 1.
    pub host_workers: Option<u32>,
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
    /// Node-wide cap per `client_id`; a policy's `limits.max_queued_per_client`
    /// is a lower ceiling and the smaller of the two applies.
    pub per_client_queued: u32,
    pub paused_on_start: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            max_queued: 1000,
            per_client_queued: 100,
            paused_on_start: false,
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

/// `on_duplicate` of a policy or a watch folder (design 4.2.2).
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
    #[serde(default = "default_policy_name")]
    pub policy: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub delete_after: DeleteAfter,
    /// Overrides the policy's `on_duplicate` for files of this folder.
    #[serde(default)]
    pub on_duplicate: Option<OnDuplicate>,
    /// Subfolders named after policies select the policy (4.2.1).
    #[serde(default)]
    pub policy_by_dir: bool,
    #[serde(default)]
    pub allow_group_write: bool,
    /// New jobs per minute per folder before the folder pauses.
    #[serde(default = "default_watch_rate")]
    pub watch_rate: u32,
}

fn default_policy_name() -> String {
    "default".into()
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

/// Reserved: live routes are not in v1 (decided D6); the key is parsed and
/// rejected until the later contract version.
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServiceConfig {
    pub daemon: Daemon,
    pub queue: Queue,
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

    /// Parallel host workers: the configured number, else `min(4, cpus/4)`,
    /// at least 1.
    pub fn host_workers(&self, cpus: usize) -> u32 {
        self.daemon
            .host_workers
            .unwrap_or_else(|| (cpus / 4).clamp(1, 4) as u32)
    }

    /// The free-RAM floor for a lane VM with `vm_ram_mib`: the configured
    /// number, else the VM's RAM plus 2048.
    pub fn min_free_ram_mib(&self, vm_ram_mib: u32) -> u32 {
        self.resources
            .min_free_ram_mib
            .unwrap_or(vm_ram_mib.saturating_add(2048))
    }
}
