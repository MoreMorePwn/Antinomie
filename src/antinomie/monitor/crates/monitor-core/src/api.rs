use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestProfile {
    pub id: String,
    pub label: String,
    pub min_ram_mib: u32,
    pub min_disk_gib: u32,
    pub requires_credentials: bool,
    pub graphical: bool,
}
impl GuestProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err("invalid guest profile id".into());
        }
        if self.label.trim().is_empty()
            || self.label.len() > 128
            || self.label.chars().any(char::is_control)
        {
            return Err("invalid guest profile label".into());
        }
        if !(256..=3072).contains(&self.min_ram_mib) || !(1..=2048).contains(&self.min_disk_gib) {
            return Err("guest profile resource minima exceed supported limits".into());
        }
        Ok(())
    }
}

/// Transient login input. Passwords are deliberately excluded from serialization.
#[derive(Clone)]
pub struct GuestCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
}
impl GuestCredentials {
    pub fn new(username: String, password: String) -> Result<Self, String> {
        validate_guest_username(&username)?;
        if !(8..=128).contains(&password.len())
            || password.bytes().any(|c| matches!(c, 0 | b'\r' | b'\n'))
        {
            return Err("password must be 8..128 UTF-8 bytes without NUL, CR or LF".into());
        }
        Ok(Self { username, password })
    }
}
impl std::fmt::Debug for GuestCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
pub(crate) fn validate_guest_username(username: &str) -> Result<(), String> {
    let mut bytes = username.bytes();
    if username.len() > 32
        || !bytes
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == b'_')
        || !bytes.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        || username == "root"
    {
        return Err("username must be a non-root Linux account name of 1..32 bytes".into());
    }
    Ok(())
}

#[cfg(test)]
mod guest_tests {
    use super::*;
    #[test]
    fn credentials_validate_and_redact_through_command_debug() {
        let secret = "a-very-private-password";
        let credentials = GuestCredentials::new("analyst".into(), secret.into()).unwrap();
        let command = Command::CreateWithCredentials {
            vm: VmConfig::default(),
            credentials: credentials.clone(),
        };
        assert!(!format!("{command:?}").contains(secret));
        for username in ["", "root", "Alice", "a:b", "-flag", "space name", "a\n"] {
            assert!(GuestCredentials::new(username.into(), secret.into()).is_err());
        }
        for password in ["short", "eight\nchars", "eight\rchars", "eight\0chars"] {
            assert!(GuestCredentials::new("analyst".into(), password.into()).is_err());
        }
        assert!(GuestCredentials::new("analyst".into(), "x".repeat(128)).is_ok());
        assert!(GuestCredentials::new("analyst".into(), "x".repeat(129)).is_err());
        assert!(GuestCredentials::new("analyst".into(), "é".repeat(64)).is_ok());
        assert!(GuestCredentials::new("analyst".into(), "é".repeat(65)).is_err());
    }
    #[test]
    fn profile_bounds_and_legacy_config() {
        let mut profile = GuestProfile {
            id: "debian-xfce".into(),
            label: "Debian 13 (Xfce)".into(),
            min_ram_mib: 2048,
            min_disk_gib: 8,
            requires_credentials: true,
            graphical: true,
        };
        assert!(profile.validate().is_ok());
        profile.min_ram_mib = 4096;
        assert!(profile.validate().is_err());
        let vm: VmConfig = serde_json::from_str(
            r#"{"id":"legacy","name":"legacy","cpus":4,"ram_mib":2048,"disk_gib":8,"nat":false}"#,
        )
        .unwrap();
        assert_eq!(vm.base_identity, None);
        assert!(!serde_json::to_string(&vm).unwrap().contains("password"));
    }
}

/// Fixed guest scanout presets; Auto preserves the base's display behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayResolution {
    #[default]
    Auto,
    R800x600,
    R1024x768,
    R1280x720,
    R1280x800,
    R1600x900,
    R1920x1080,
    R2560x1440,
}
impl DisplayResolution {
    pub const ALL: &'static [Self] = &[
        Self::Auto,
        Self::R800x600,
        Self::R1024x768,
        Self::R1280x720,
        Self::R1280x800,
        Self::R1600x900,
        Self::R1920x1080,
        Self::R2560x1440,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::R800x600 => "800 x 600",
            Self::R1024x768 => "1024 x 768",
            Self::R1280x720 => "1280 x 720",
            Self::R1280x800 => "1280 x 800",
            Self::R1600x900 => "1600 x 900",
            Self::R1920x1080 => "1920 x 1080",
            Self::R2560x1440 => "2560 x 1440",
        }
    }

    /// Width and height in pixels, or None for the base's default mode.
    pub fn dimensions(self) -> Option<(u16, u16)> {
        match self {
            Self::Auto => None,
            Self::R800x600 => Some((800, 600)),
            Self::R1024x768 => Some((1024, 768)),
            Self::R1280x720 => Some((1280, 720)),
            Self::R1280x800 => Some((1280, 800)),
            Self::R1600x900 => Some((1600, 900)),
            Self::R1920x1080 => Some((1920, 1080)),
            Self::R2560x1440 => Some((2560, 1440)),
        }
    }
}

/// Per-VM accelerator preference; the application's force_tcg override wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmAcceleration {
    #[default]
    Default,
    Kvm,
    Tcg,
}
impl VmAcceleration {
    pub const ALL: &'static [Self] = &[Self::Default, Self::Kvm, Self::Tcg];

    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Kvm => "KVM",
            Self::Tcg => "TCG",
        }
    }
}

/// Bounded QEMU CPU models; Default leaves QEMU's model selection unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmCpuModel {
    #[default]
    Default,
    Qemu64,
    Host,
    Max,
}
impl VmCpuModel {
    pub const ALL: &'static [Self] = &[Self::Default, Self::Qemu64, Self::Host, Self::Max];

    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Qemu64 => "qemu64",
            Self::Host => "host",
            Self::Max => "max",
        }
    }
}

/// Launch preferences applied on the next boot, never to a running VM.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VmLaunchOptions {
    #[serde(default)]
    pub resolution: DisplayResolution,
    #[serde(default)]
    pub fullscreen: bool,
    #[serde(default)]
    pub fit_to_window: bool,
    #[serde(default)]
    pub acceleration: VmAcceleration,
    #[serde(default)]
    pub cpu_model: VmCpuModel,
}
impl VmLaunchOptions {
    /// Reject CPU models incompatible with the explicit accelerator preference.
    pub fn validate(&self) -> Result<(), String> {
        if self.cpu_model == VmCpuModel::Host && self.acceleration == VmAcceleration::Tcg {
            return Err("host CPU model requires KVM acceleration".into());
        }
        Ok(())
    }

    /// Also account for application overrides when checking accelerator support.
    pub fn validate_for(&self, options: &BackendOptions) -> Result<(), String> {
        self.validate()?;
        if self.cpu_model == VmCpuModel::Host && options.force_tcg {
            return Err("host CPU model requires KVM; force_tcg is enabled".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VmConfig {
    pub id: String,
    pub name: String,
    pub cpus: u16,
    pub ram_mib: u32,
    pub disk_gib: u32,
    pub nat: bool,
    /// Host parent for newly created VM disk directories; None uses data_dir.
    #[serde(default)]
    pub disk_root: Option<PathBuf>,
    /// Host parent for future recording directories; existing archives are retained.
    #[serde(default)]
    pub recording_root: Option<PathBuf>,
    /// Installed immutable boot bundle identity; existing disk backings stay pinned.
    #[serde(default)]
    pub base_identity: Option<String>,
    #[serde(default)]
    pub launch: VmLaunchOptions,
}
impl Default for VmConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: "New VM".into(),
            cpus: 4,
            ram_mib: 2048,
            disk_gib: 8,
            nat: false,
            disk_root: None,
            recording_root: None,
            base_identity: None,
            launch: VmLaunchOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BackendOptions {
    pub data_dir: PathBuf,
    pub bundle_dir: PathBuf,
    pub qemu: PathBuf,
    pub qemu_img: PathBuf,
    /// Shared quota for raw packets, assembled fields and terminal artifacts, in bytes.
    pub capture_quota_size: u64,
    pub shutdown_timeout: Duration,
    pub bootstrap_gpa: Option<u64>,
    pub force_tcg: bool,
    pub headless: bool,
}
impl Default for BackendOptions {
    fn default() -> Self {
        let data = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        Self {
            data_dir: data.join("antinomie"),
            bundle_dir: std::env::var_os("ANTINOMIE_BUNDLE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("images")),
            qemu: "qemu-system-x86_64".into(),
            qemu_img: "qemu-img".into(),
            capture_quota_size: 4 * 1024 * 1024 * 1024,
            shutdown_timeout: Duration::from_secs(10),
            bootstrap_gpa: None,
            force_tcg: false,
            headless: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecRequest {
    pub path: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: Vec<String>,
    pub uid: u32,
    pub gid: u32,
}

/// Identity is persistent and boot-scoped; PID is descriptive, never an owner key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSummary {
    pub id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub session_id: u64,
    pub root_task_cookie: u64,
    pub pid: u32,
    pub request: ExecRequest,
    pub directory: PathBuf,
    pub terminal_eof: bool,
    pub state: RunState,
    pub recording_error: Option<String>,
    #[serde(default)]
    pub execution: Option<RunExecution>,
}

/// Authoritative boot-scoped guest status, independent of archive/terminal state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunExecution {
    pub generation: u64,
    pub live_task_count: u64,
    pub pending_async_count: u64,
    pub flags: u32,
    pub root_wait_status: Option<i32>,
    pub root_exit: Option<WaitStatus>,
    pub async_loss_count: u64,
    pub total_task_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WaitStatus {
    Exited { code: u8 },
    Signaled { signal: u8, core_dumped: bool },
}

#[derive(Clone, Debug)]
pub struct BaseSummary {
    pub id: String,
    pub label: String,
    pub directory: PathBuf,
    pub guest: Option<GuestProfile>,
    pub min_ram_mib: u32,
    pub min_disk_gib: u32,
    pub fixed_display: bool,
}

#[derive(Clone, Debug)]
pub struct VmLocations {
    pub vm_id: String,
    pub disk_directory: PathBuf,
    pub recording_directory: PathBuf,
    pub recording_directories: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunState {
    Unknown,
    Running,
    StopRequested,
    Finished,
    Stopped,
    /// PTY EOF does not prove all traced descendants have exited.
    TerminalClosed,
    Finalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvocationSummary {
    pub stream_id: u64,
    pub task_cookie: u64,
    pub call_id: u64,
    pub entry: Option<EventSummary>,
    pub exit: Option<EventSummary>,
    /// Correlated async observations; capped at 256 records per invocation.
    pub async_events: Vec<EventSummary>,
}

#[derive(Clone, Debug)]
pub struct InvocationPage {
    pub invocations: Vec<InvocationSummary>,
    pub next_offset: Option<u64>,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum TerminalRecord {
    Output(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Eof,
}

#[derive(Clone, Debug)]
pub struct TerminalPage {
    pub records: Vec<TerminalRecord>,
    pub next_offset: Option<u64>,
}
impl Default for ExecRequest {
    fn default() -> Self {
        Self {
            path: "/bin/sh".into(),
            args: vec![],
            cwd: "/tmp".into(),
            env: vec![
                "PATH=/bin:/sbin:/usr/bin:/usr/sbin".into(),
                "TERM=xterm".into(),
            ],
            uid: 1000,
            gid: 1000,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Command {
    Create(VmConfig),
    /// Hashing has a 15-second tool deadline; offline provisioning has 180 seconds.
    /// Failure cleans unpublished state and never reports credential tool output.
    CreateWithCredentials {
        vm: VmConfig,
        credentials: GuestCredentials,
    },
    ImportBase {
        directory: PathBuf,
    },
    Save(VmConfig),
    Rename {
        vm_id: String,
        name: String,
    },
    Duplicate {
        vm_id: String,
        name: String,
    },
    Start {
        vm_id: String,
    },
    Reset {
        vm_id: String,
        confirmed: bool,
    },
    Delete {
        vm_id: String,
        confirmed: bool,
    },
    UpdateOptions {
        bundle_dir: PathBuf,
        capture_quota_size: u64,
        shutdown_timeout_secs: u64,
    },
    Upload {
        source: PathBuf,
        destination: String,
        overwrite: bool,
        executable: bool,
    },
    Execute(ExecRequest),
    TerminalInput {
        run_id: String,
        data: Vec<u8>,
    },
    TerminalRead {
        run_id: String,
    },
    TerminalSnapshot {
        run_id: String,
    },
    TerminalResize {
        run_id: String,
        rows: u16,
        cols: u16,
    },
    Signal {
        run_id: String,
        signal: u32,
    },
    StopRun {
        run_id: String,
    },
    RecorderStats,
    OpenRecording {
        directory: PathBuf,
    },
    Stop,
    Close,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Health {
    pub attempted: u64,
    pub dropped: u64,
    pub bad_commands: u64,
    pub reply_stalls: u64,
    pub transport_health: u32,
    pub parser_errors: u64,
    pub parser_evicted_count: u64,
    pub ui_dropped: u64,
    pub persisted_packets: u64,
    /// Packets actually dequeued by ant_read, independent of attempted sends.
    pub received_packets: u64,
    /// Dequeued packets rejected by the raw recording writer.
    pub storage_dropped_packets: u64,
    pub persisted_len: u64,
    pub persistence_error: Option<String>,
    pub recorder_stats: Option<[u64; 10]>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub enum VmState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub vms: Vec<VmConfig>,
    pub bases: Vec<BaseSummary>,
    pub vm_locations: Vec<VmLocations>,
    pub active_vm: Option<String>,
    pub state: VmState,
    pub health: Health,
    pub events: Vec<EventSummary>,
    pub runs: Vec<RunSummary>,
    pub capture_dir: Option<PathBuf>,
    pub serial_log: Option<PathBuf>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSummary {
    #[serde(default)]
    pub root_task_cookie: u64,
    pub stream_id: u64,
    pub task_cookie: u64,
    pub call_id: u64,
    pub event_seq: u64,
    pub phase: u8,
    pub syscall_nr: u64,
    pub syscall_name: String,
    pub tid: u32,
    pub cpu: u32,
    pub timestamp_ns: u64,
    pub args: Option<[u64; 6]>,
    pub result: Option<i64>,
    pub complete: bool,
    pub issues: Vec<String>,
    pub fields: Vec<FieldSummary>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldSummary {
    pub object_id: u32,
    pub key: String,
    pub layout: String,
    pub logical_len: Option<u64>,
    pub captured_len: u64,
    pub status: Option<u32>,
    pub capture_error: i32,
    pub complete: bool,
    pub preview: Vec<u8>,
    pub raw_path: Option<PathBuf>,
    pub ranges: Vec<(u64, u64)>,
}
#[derive(Clone, Debug)]
// Snapshots use a single coalesced slot, so this variant does not multiply queued payloads.
#[allow(clippy::large_enum_variant)]
pub enum Notification {
    Snapshot(Snapshot),
    CommandResult {
        id: u64,
        success: bool,
        message: String,
    },
    RunStarted(RunSummary),
    Terminal {
        run_id: String,
        sequence: u64,
        data: Vec<u8>,
        eof: bool,
    },
    TerminalScreen {
        run_id: String,
        sequence: u64,
        rows: u16,
        cols: u16,
        data: Vec<u8>,
    },
}

/// Bounded live pairing uses stream/task/call identity, retaining missing phases.
pub fn pair_events(events: &[EventSummary]) -> Vec<InvocationSummary> {
    let mut rows = Vec::<InvocationSummary>::new();
    let mut indexes = std::collections::BTreeMap::new();
    for event in events {
        if !matches!(event.phase, 1 | 2) {
            continue;
        }
        let key = (event.stream_id, event.task_cookie, event.call_id);
        let index = *indexes.entry(key).or_insert_with(|| {
            rows.push(InvocationSummary {
                stream_id: key.0,
                task_cookie: key.1,
                call_id: key.2,
                entry: None,
                exit: None,
                async_events: Vec::new(),
            });
            rows.len() - 1
        });
        if event.phase == 2 {
            rows[index].exit = Some(event.clone());
        } else {
            rows[index].entry = Some(event.clone());
        }
    }
    for event in events.iter().filter(|event| {
        event.phase == 3
            && event.call_id != 0
            && event
                .fields
                .iter()
                .any(|field| field.key.starts_with("async."))
            || (event.phase == 3
                && event.call_id != 0
                && !event.complete
                && !event
                    .fields
                    .iter()
                    .any(|field| field.key.starts_with("lifecycle.")))
    }) {
        let key = (event.stream_id, event.task_cookie, event.call_id);
        let index = *indexes.entry(key).or_insert_with(|| {
            rows.push(InvocationSummary {
                stream_id: key.0,
                task_cookie: key.1,
                call_id: key.2,
                entry: None,
                exit: None,
                async_events: Vec::new(),
            });
            rows.len() - 1
        });
        if rows[index].async_events.len() < 256 {
            rows[index].async_events.push(event.clone());
        } else if let Some(last) = rows[index].async_events.last_mut() {
            let issue =
                "additional async observations exceed bounded preview; raw records retained";
            if !last.issues.iter().any(|existing| existing == issue) {
                last.issues.push(issue.into());
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_cannot_replace_syscall_entry_or_invent_missing_entry() {
        let entry = EventSummary {
            root_task_cookie: 99,
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            event_seq: 4,
            phase: 1,
            syscall_nr: 59,
            syscall_name: "execve".into(),
            tid: 5,
            cpu: 0,
            timestamp_ns: 6,
            args: Some([7; 6]),
            result: None,
            complete: true,
            issues: vec![],
            fields: vec![],
        };
        let mut lifecycle = entry.clone();
        lifecycle.phase = 3;
        lifecycle.args = Some([8; 6]);
        let rows = pair_events(&[entry.clone(), lifecycle.clone()]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.as_ref().unwrap().args, entry.args);
        let mut exit = entry;
        exit.phase = 2;
        exit.args = None;
        exit.result = Some(0);
        let rows = pair_events(&[exit, lifecycle]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].entry.is_none());
        assert!(rows[0].exit.is_some());
    }
    #[test]
    fn older_recording_health_defaults_new_loss_counters() {
        let health: Health =
            serde_json::from_str(r#"{"attempted":20,"dropped":3,"persisted_packets":17}"#).unwrap();
        assert_eq!(health.attempted, 20);
        assert_eq!(health.dropped, 3);
        assert_eq!(health.persisted_packets, 17);
        assert_eq!(health.received_packets, 0);
        assert_eq!(health.storage_dropped_packets, 0);
    }
    #[test]
    fn old_vm_config_defaults_independent_storage_fields() {
        let vm: VmConfig = serde_json::from_str(
            r#"{"id":"old","name":"Old VM","cpus":4,"ram_mib":2048,"disk_gib":8,"nat":false}"#,
        )
        .unwrap();
        assert!(vm.disk_root.is_none());
        assert!(vm.recording_root.is_none());
        assert!(vm.base_identity.is_none());
        assert_eq!(vm.launch, VmLaunchOptions::default());
    }
    #[test]
    fn launch_fields_default_independently_and_round_trip_all_presets() {
        assert_eq!(
            serde_json::from_str::<VmLaunchOptions>("{}").unwrap(),
            VmLaunchOptions::default()
        );
        assert_eq!(
            serde_json::from_str::<VmLaunchOptions>(r#"{"fullscreen":true}"#).unwrap(),
            VmLaunchOptions {
                fullscreen: true,
                ..VmLaunchOptions::default()
            }
        );
        for &resolution in DisplayResolution::ALL {
            for &acceleration in VmAcceleration::ALL {
                for &cpu_model in VmCpuModel::ALL {
                    for (fullscreen, fit_to_window) in
                        [(false, false), (true, false), (false, true), (true, true)]
                    {
                        let vm = VmConfig {
                            launch: VmLaunchOptions {
                                resolution,
                                acceleration,
                                cpu_model,
                                fullscreen,
                                fit_to_window,
                            },
                            ..VmConfig::default()
                        };
                        let json = serde_json::to_string(&vm).unwrap();
                        assert_eq!(serde_json::from_str::<VmConfig>(&json).unwrap(), vm);
                    }
                }
            }
        }
        assert_eq!(
            serde_json::to_string(&DisplayResolution::R1920x1080).unwrap(),
            r#""r1920x1080""#
        );
        assert_eq!(
            serde_json::to_string(&VmAcceleration::Kvm).unwrap(),
            r#""kvm""#
        );
        assert_eq!(
            serde_json::to_string(&VmCpuModel::Qemu64).unwrap(),
            r#""qemu64""#
        );
        assert!(serde_json::from_str::<VmLaunchOptions>(r#"{"cpu_model":"arbitrary"}"#).is_err());
        assert!(serde_json::from_str::<VmLaunchOptions>(r#"{"resolution":"r9000x9000"}"#).is_err());
    }

    #[test]
    fn host_cpu_model_requires_effective_kvm() {
        for &acceleration in VmAcceleration::ALL {
            for &cpu_model in VmCpuModel::ALL {
                let launch = VmLaunchOptions {
                    acceleration,
                    cpu_model,
                    ..VmLaunchOptions::default()
                };
                let valid = cpu_model != VmCpuModel::Host || acceleration != VmAcceleration::Tcg;
                assert_eq!(launch.validate().is_ok(), valid);
                for force_tcg in [false, true] {
                    let options = BackendOptions {
                        force_tcg,
                        ..BackendOptions::default()
                    };
                    assert_eq!(
                        launch.validate_for(&options).is_ok(),
                        valid && !(cpu_model == VmCpuModel::Host && force_tcg)
                    );
                }
            }
        }
    }
    #[test]
    fn async_pairing_is_bounded_and_does_not_invent_unknown_parents() {
        let entry = EventSummary {
            root_task_cookie: 99,
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            event_seq: 4,
            phase: 1,
            syscall_nr: 426,
            syscall_name: "io_uring_enter".into(),
            tid: 5,
            cpu: 0,
            timestamp_ns: 6,
            args: Some([0; 6]),
            result: None,
            complete: true,
            issues: vec![],
            fields: vec![],
        };
        let mut async_event = entry.clone();
        async_event.phase = 3;
        async_event.fields.push(FieldSummary {
            object_id: 1,
            key: "async.request_id".into(),
            layout: "u64".into(),
            logical_len: Some(8),
            captured_len: 8,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: vec![0; 8],
            raw_path: None,
            ranges: vec![(0, 8)],
        });
        let mut events = vec![entry];
        for event_seq in 0..260 {
            let mut event = async_event.clone();
            event.event_seq = event_seq;
            events.push(event);
        }
        let mut missing = async_event.clone();
        missing.call_id = 900;
        missing.fields[0].key = "async.stage".into();
        events.push(missing);
        let mut orphan = async_event.clone();
        orphan.call_id = 901;
        orphan.complete = false;
        orphan.fields.clear();
        orphan.issues.push("missing field metadata".into());
        events.push(orphan);
        let mut unknown = async_event;
        unknown.call_id = 0;
        events.push(unknown);
        let rows = pair_events(&events);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1].call_id, 900);
        assert!(rows[1].entry.is_none());
        assert!(rows[1].exit.is_none());
        assert_eq!(rows[1].async_events.len(), 1);
        assert_eq!(rows[2].call_id, 901);
        assert!(rows[2].entry.is_none());
        assert_eq!(rows[2].async_events.len(), 1);
        assert_eq!(rows[0].async_events.len(), 256);
        assert!(
            rows[0].async_events[255]
                .issues
                .iter()
                .any(|issue| issue.contains("bounded preview"))
        );
    }
}
