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
        if !(crate::storage::MIN_RAM_MIB..=crate::storage::MAX_RAM_MIB).contains(&self.min_ram_mib)
            || !(1..=2048).contains(&self.min_disk_gib)
        {
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
        profile.min_ram_mib = 8192;
        assert!(profile.validate().is_ok());
        profile.min_ram_mib = 8193;
        assert!(profile.validate().is_err());
        let vm: VmConfig = serde_json::from_str(
            r#"{"id":"legacy","name":"legacy","cpus":4,"ram_mib":2048,"disk_gib":8,"nat":false}"#,
        )
        .unwrap();
        assert_eq!(vm.base_identity, None);
        assert!(!vm.isolated_network);
        let request: ExecRequest = serde_json::from_str(
            r#"{"path":"/bin/sh","args":[],"cwd":"/tmp","env":[],"uid":1000,"gid":1000}"#,
        )
        .unwrap();
        assert!(
            !request.capture_network && !request.memory_dump_on_exit && !request.core_dump_on_exit
        );
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
    /// User-mode networking without routes to the host or external networks.
    /// Takes precedence over `nat` when both are enabled.
    #[serde(default)]
    pub isolated_network: bool,
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
    #[serde(default)]
    pub transport: TransportSettings,
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
            isolated_network: false,
            disk_root: None,
            recording_root: None,
            base_identity: None,
            launch: VmLaunchOptions::default(),
            transport: TransportSettings::default(),
        }
    }
}

/// Telemetry transport tuning (VM settings > Advanced). Bases for Antinomie
/// 0.2.0 and older always use 256 KiB rings and cannot wait.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TransportSettings {
    /// Guest telemetry ring per vCPU, KiB: a power of two, 256..=4096.
    pub ring_kib: u32,
    /// Never drop: a guest send waits up to `max_wait_ms` for room in a full
    /// ring instead of dropping, which slows the guest under heavy load.
    pub lossless: bool,
    /// Longest one send may wait in lossless mode, 1..=10000 ms.
    pub max_wait_ms: u32,
    /// Host table of events still being assembled, 2048..=131072.
    pub event_table: u32,
}
impl TransportSettings {
    pub const RING_KIB: [u32; 5] = [256, 512, 1024, 2048, 4096];
    pub const EVENT_TABLE: std::ops::RangeInclusive<u32> = 2048..=131_072;
    pub fn validate(&self) -> Result<(), String> {
        if !Self::RING_KIB.contains(&self.ring_kib) {
            return Err("transport ring must be 256, 512, 1024, 2048 or 4096 KiB".into());
        }
        if !(1..=10_000).contains(&self.max_wait_ms) {
            return Err("never-drop wait must be 1..10000 ms".into());
        }
        if !Self::EVENT_TABLE.contains(&self.event_table) {
            return Err("event table must hold 2048..131072 events".into());
        }
        Ok(())
    }
    /// Guest send wait to publish, in microseconds (0 drops).
    pub fn send_wait_us(&self) -> u32 {
        if self.lossless {
            self.max_wait_ms * 1000
        } else {
            0
        }
    }
}
impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            ring_kib: 1024,
            // GNOME start-up under Capture All overflows any ring: dropping
            // lost 52-80 %, waiting lost nothing.
            lossless: true,
            max_wait_ms: 5000,
            event_table: 16_384,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BackendOptions {
    pub data_dir: PathBuf,
    pub bundle_dir: PathBuf,
    pub qemu: PathBuf,
    pub qemu_img: PathBuf,
    /// External downloader used for the public base bucket (detect-and-alert).
    pub curl: PathBuf,
    /// Anonymous base bucket file endpoint (`.../resolve`).
    pub remote_base: String,
    /// Product repository checkout used for local base builds (host Linux).
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
            curl: "curl".into(),
            remote_base: crate::distribution::DEFAULT_REMOTE_BASE.to_string(),
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
    #[serde(default)]
    pub analysis: crate::analysis::AnalysisSelection,
    /// Where the program runs; runs saved before this choice existed ran in
    /// the app terminal.
    #[serde(default)]
    pub run_in: RunIn,
    /// Capture VM-wide network traffic for this run until its entire tree ends.
    #[serde(default)]
    pub capture_network: bool,
    /// Take VM RAM after authoritative tree completion (not a process core).
    #[serde(default)]
    pub memory_dump_on_exit: bool,
    /// Capture the native x86-64 root process group before its address space exits.
    #[serde(default)]
    pub core_dump_on_exit: bool,
}

/// Persisted `artifacts.json` in a run directory links independently retained evidence.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RunArtifacts {
    pub run_id: String,
    pub vm_id: String,
    pub boot_id: String,
    /// VM-wide packet captures; snapshot boundaries start new segments.
    pub network_captures: Vec<PathBuf>,
    pub network_state: RunArtifactState,
    /// Directory containing `dump.json` and the post-exit VM `memory.elf`.
    pub memory_dump: Option<PathBuf>,
    pub memory_state: RunArtifactState,
    /// ELF core file; partial captures retain their available prefix.
    pub core_dump: Option<PathBuf>,
    pub core_state: RunArtifactState,
    pub issues: Vec<String>,
}

impl RunArtifacts {
    /// Load retained sidecar evidence. Older runs have no sidecar and return None.
    /// Reject oversized/malformed metadata instead of allocating unbounded input.
    pub fn load(directory: &std::path::Path) -> Result<Option<Self>, String> {
        use std::io::Read;
        let file = match crate::archive_io::open_regular(
            directory,
            std::path::Path::new("artifacts.json"),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("run artifacts: {error}")),
        };
        const METADATA_LIMIT: u64 = 256 * 1024;
        let mut data = Vec::new();
        file.take(METADATA_LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|error| format!("run artifacts: {error}"))?;
        if data.len() as u64 > METADATA_LIMIT {
            return Err("run artifacts exceed the metadata size limit".into());
        }
        let artifacts: Self =
            serde_json::from_slice(&data).map_err(|error| format!("run artifacts: {error}"))?;
        if artifacts.network_captures.len() > 256
            || artifacts.issues.len() > 16
            || [&artifacts.run_id, &artifacts.vm_id, &artifacts.boot_id]
                .iter()
                .any(|id| id.len() > 128)
        {
            return Err("run artifacts exceed the metadata item limits".into());
        }
        Ok(Some(artifacts))
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunArtifactState {
    #[default]
    Disabled,
    WaitingForTreeExit,
    WaitingForRootExit,
    Recording,
    Queued,
    InProgress,
    Complete,
    Partial,
    Interrupted,
    Failed,
}

/// Where a launched program runs. The guest desktop choices need a graphical
/// base and a user logged in on the VM display; the guest has no helper, so
/// the program is started through a `/bin/sh` wrapper that joins that session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunIn {
    /// The program's terminal is a window of this app.
    #[default]
    AppTerminal,
    /// The program joins the guest's graphical session, so its windows appear
    /// on the guest screen; its terminal output stays in this app.
    GuestDesktop,
    /// A terminal window on the guest desktop runs the program.
    GuestDesktopTerminal,
}
impl RunIn {
    pub const ALL: [Self; 3] = [
        Self::AppTerminal,
        Self::GuestDesktop,
        Self::GuestDesktopTerminal,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::AppTerminal => "App terminal",
            Self::GuestDesktop => "Guest desktop",
            Self::GuestDesktopTerminal => "Guest desktop terminal",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::AppTerminal => "The program's terminal opens in a window of this app.",
            Self::GuestDesktop => {
                "The program joins the logged-in graphical session, so its windows appear on the guest screen. Its terminal output stays in this app."
            }
            Self::GuestDesktopTerminal => {
                "A terminal window on the guest desktop runs the program. This app's terminal shows only launch messages. The run's exit code is the terminal launcher's; the program's own status appears in the guest terminal."
            }
        }
    }
    /// True when the program runs in the guest's graphical session.
    pub fn guest_desktop(self) -> bool {
        self != Self::AppTerminal
    }
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
    #[serde(default)]
    pub analysis: Option<crate::analysis::AnalysisReport>,
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

impl WaitStatus {
    /// Decode a wait status as the kernel keeps it (`task->exit_code`):
    /// the exit code in bits 8..16, or the fatal signal in the low 7 bits
    /// with bit 7 set when it dumped core.
    pub fn from_raw(raw: u64) -> Option<Self> {
        if raw > 0xffff {
            return None;
        }
        let low = (raw & 127) as u8;
        if low == 0 && raw & 128 == 0 {
            return Some(Self::Exited {
                code: (raw >> 8) as u8,
            });
        }
        ((1..=64).contains(&low) && raw & !255 == 0).then_some(Self::Signaled {
            signal: low,
            core_dumped: raw & 128 != 0,
        })
    }
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
    /// Size of the base disk image on disk, in bytes.
    pub size_bytes: u64,
    /// Antinomie patch revision the base's kernel was built from.
    pub revision: Option<u32>,
    /// Oldest Antinomie version that can run the base, when recorded.
    pub min_app_version: Option<String>,
    /// Antinomie version that built the base, when recorded.
    pub built_with: Option<String>,
}

/// Guest contract revision this app implements.
pub const APP_REVISION: u32 = crate::control::REVISION;

/// This app's version (semantic versioning: a fix bumps the patch number, a
/// feature the minor number, the first release is 1.0.0).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A parsed `major.minor.patch` version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);
impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.');
        let mut next = || -> Option<u32> {
            let part = parts.next()?;
            (!part.is_empty()
                && part.len() <= 9
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == "0" || !part.starts_with('0')))
            .then(|| part.parse().ok())
            .flatten()
        };
        let version = Self(next()?, next()?, next()?);
        parts.next().is_none().then_some(version)
    }
    pub fn app() -> Self {
        Self::parse(APP_VERSION).expect("workspace version is major.minor.patch")
    }
}
impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `protocol/revisions.json`: each guest contract revision and the first app
/// version that shipped it. The build recipes read the same file.
const REVISION_TABLE: &str = include_str!("../../../protocol/revisions.json");

/// (revision, first app version), oldest first.
pub fn revision_history() -> Vec<(u32, Version)> {
    #[derive(Deserialize)]
    struct Table {
        revisions: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        revision: u32,
        first_app_version: String,
    }
    let table: Table = serde_json::from_str(REVISION_TABLE).expect("revisions.json is valid");
    table
        .revisions
        .into_iter()
        .map(|entry| {
            let version = Version::parse(&entry.first_app_version)
                .expect("revisions.json versions are major.minor.patch");
            (entry.revision, version)
        })
        .collect()
}

/// The first app version that can run a kernel of `revision`, if known.
pub fn first_app_version(revision: u32) -> Option<Version> {
    revision_history()
        .into_iter()
        .find(|(known, _)| *known == revision)
        .map(|(_, version)| version)
}

/// The Antinomie version a base is for: its recorded minimum app version,
/// or the first version of its kernel's revision.
///
/// | Argument / return | Meaning |
/// |---|---|
/// | `revision` | Recorded guest contract revision, if available. |
/// | `min_app_version` | Recorded minimum app version, preferred when valid. |
/// | Return | Version for the label; `None` when neither source is known. |
pub fn base_app_version(revision: Option<u32>, min_app_version: Option<&str>) -> Option<Version> {
    min_app_version
        .and_then(Version::parse)
        .or_else(|| revision.and_then(first_app_version))
}

/// Split a `CONFIG_ANTINOMIE_SOURCE_ID` value, `"<revision>:<series sha256>"`.
pub fn parse_source_id(value: &str) -> Option<(u32, String)> {
    let (revision, series) = value.split_once(':')?;
    let revision = (!revision.starts_with('0') && revision.len() <= 9)
        .then(|| revision.parse::<u32>().ok())
        .flatten()?;
    (series.len() == 64
        && series
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| (revision, series.to_string()))
}

/// How a base's or kernel's patch revision relates to this app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevisionStatus {
    /// Built from this app's patch revision.
    Current,
    /// Built from an earlier revision; it works but lacks later behaviour.
    Outdated,
    /// Built from a later revision than this app understands.
    NeedsNewerApp,
    /// Built before revisions were recorded (revision 8 or earlier).
    Legacy,
}
impl RevisionStatus {
    pub fn of(revision: Option<u32>) -> Self {
        match revision {
            None => Self::Legacy,
            Some(revision) if revision == APP_REVISION => Self::Current,
            Some(revision) if revision < APP_REVISION => Self::Outdated,
            Some(_) => Self::NeedsNewerApp,
        }
    }
    /// Short text for lists, in app versions: "for Antinomie 0.1.0",
    /// "for Antinomie 0.1.0, outdated", "needs Antinomie 0.2.0 or newer".
    /// `min_app_version` is the base's record; without it the revision table
    /// is used, and a revision this app does not know is a newer one.
    pub fn describe(revision: Option<u32>, min_app_version: Option<&str>) -> String {
        let version = min_app_version
            .and_then(Version::parse)
            .or_else(|| revision.and_then(first_app_version));
        let version = |fallback: String| version.map_or(fallback, |v| format!("Antinomie {v}"));
        match (Self::of_base(revision, min_app_version), revision) {
            (Self::Current, Some(_)) => {
                format!("for {}", version("this Antinomie".into()))
            }
            (Self::Outdated, Some(_)) => {
                format!("for {}, outdated", version("an earlier Antinomie".into()))
            }
            (Self::NeedsNewerApp, revision) => {
                match (min_app_version.and_then(Version::parse), revision) {
                    (Some(needed), _) => format!("needs Antinomie {needed} or newer"),
                    (None, Some(revision)) => match first_app_version(revision) {
                        Some(needed) => format!("needs Antinomie {needed} or newer"),
                        None => "needs a newer Antinomie".into(),
                    },
                    (None, None) => "needs a newer Antinomie".into(),
                }
            }
            _ => "built before versioning".into(),
        }
    }
    /// Like `of`, but a recorded minimum app version newer than this app also
    /// means the base needs a newer app.
    pub fn of_base(revision: Option<u32>, min_app_version: Option<&str>) -> Self {
        if min_app_version
            .and_then(Version::parse)
            .is_some_and(|needed| needed > Version::app())
        {
            return Self::NeedsNewerApp;
        }
        Self::of(revision)
    }
}
/// Refuse a base this app cannot fully interpret: one that names a newer
/// minimum app version, or (older records) a newer kernel revision.
pub(crate) fn require_supported(
    revision: Option<u32>,
    min_app_version: Option<&str>,
) -> Result<(), String> {
    if let Some(needed) = min_app_version.and_then(Version::parse)
        && needed > Version::app()
    {
        return Err(format!(
            "this base needs Antinomie {needed} or newer; this is Antinomie {APP_VERSION}; \
             update Antinomie first"
        ));
    }
    match revision {
        Some(revision) if revision > APP_REVISION => Err(format!(
            "this base is for a newer Antinomie than this one ({APP_VERSION}); update \
             Antinomie first"
        )),
        _ => Ok(()),
    }
}

/// The running guest kernel as reported over the control channel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestKernel {
    /// `None`: the kernel predates the INFO command (revision 8 or earlier).
    pub revision: Option<u32>,
    /// Patch-series SHA-256; `None` for a development or legacy kernel.
    pub source: Option<String>,
    pub release: Option<String>,
}

/// One base advertised by the remote catalog, flattened for the UI.
#[derive(Clone, Debug, Default)]
pub struct RemoteBase {
    pub identity: String,
    pub label: String,
    pub kind: String,
    pub kernel_version: String,
    pub fixed_display: bool,
    pub min_ram_mib: u32,
    pub min_disk_gib: u32,
    pub total_size: u64,
    pub revision: Option<u32>,
    pub min_app_version: Option<String>,
    pub built_with: Option<String>,
}

/// Progress of the single active remote base download.
#[derive(Clone, Debug, Default)]
pub struct DownloadStatus {
    pub identity: String,
    pub label: String,
    pub received: u64,
    pub total: u64,
    /// Download and verification finished; publishing the installed base.
    /// This phase must finish atomically and cannot be cancelled.
    pub installing: bool,
    pub finished: bool,
    pub error: Option<String>,
}

/// Progress and log tail of the single active local build.
#[derive(Clone, Debug, Default)]
pub struct BuildStatus {
    pub profile: String,
    pub label: String,
    /// Where the build runs (never `Automatic` once started).
    pub mode: crate::build::BuildMode,
    /// Current stage: `prepare`, `builder`, `source`, `kernel`, `image`,
    /// `install` or `done`.
    pub stage: String,
    /// Bounded tail of the combined build output.
    pub log: Vec<String>,
    /// Full build log, kept after the build.
    pub log_path: Option<PathBuf>,
    pub finished: bool,
    pub error: Option<String>,
}

impl From<&crate::distribution::CatalogBase> for RemoteBase {
    fn from(base: &crate::distribution::CatalogBase) -> Self {
        Self {
            identity: base.identity.clone(),
            label: base.label.clone(),
            kind: base.kind.clone(),
            kernel_version: base.kernel_version.clone(),
            fixed_display: base.fixed_display,
            min_ram_mib: base.min_ram_mib,
            min_disk_gib: base.min_disk_gib,
            total_size: base.total_size,
            revision: base.antinomie_revision,
            min_app_version: base.min_app_version.clone(),
            built_with: base.built_with.clone(),
        }
    }
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
    /// The kernel's record that the calling task ended inside this call:
    /// `exit` and `exit_group`, which never return, or a fatal signal that
    /// arrived while the call was blocked. Its `lifecycle.task_exit` field
    /// holds the wait status.
    #[serde(default)]
    pub task_exit: Option<EventSummary>,
}

impl InvocationSummary {
    /// How the calling task ended inside this call, when it did.
    pub fn task_exit_status(&self) -> Option<WaitStatus> {
        let field = self
            .task_exit
            .as_ref()?
            .fields
            .iter()
            .find(|field| field.key == "lifecycle.task_exit")?;
        WaitStatus::from_raw(u64::from_le_bytes(field.preview.get(..8)?.try_into().ok()?))
    }
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
            analysis: crate::analysis::AnalysisSelection::default(),
            run_in: RunIn::default(),
            capture_network: false,
            memory_dump_on_exit: false,
            core_dump_on_exit: false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Command {
    RefreshVmSnapshots {
        vm_id: String,
    },
    CreateVmSnapshot {
        vm_id: String,
        request: SnapshotRequest,
    },
    RestoreVmSnapshot {
        vm_id: String,
        snapshot_id: String,
        boot_from_disk: bool,
        save_current: Option<SnapshotRequest>,
        confirmed: bool,
    },
    RenameVmSnapshot {
        vm_id: String,
        snapshot_id: String,
        name: String,
    },
    DeleteVmSnapshot {
        vm_id: String,
        snapshot_id: String,
        confirmed: bool,
    },
    ReconnectTransport,
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
    /// Fetch the remote base catalog from the public bucket (`curl`).
    RefreshRemoteBases,
    /// Download, verify and install one advertised base.
    DownloadBase {
        identity: String,
    },
    /// Stop the running base download; finished files stay for a resume.
    CancelDownload,
    /// Build a base with the app's kit, natively or in the QEMU builder VM.
    BuildBase {
        request: crate::build::BuildRequest,
    },
    /// Cancel the running base build.
    CancelBuild,
    /// Download and install an optional analysis tool (capa, Detect It Easy,
    /// Ghidra) under `<data>/tools`.
    InstallTool {
        id: String,
    },
    /// Cancel the running tool installation.
    CancelToolInstall,
    /// Remove an analysis tool Antinomie installed.
    RemoveTool {
        id: String,
    },
    /// Delete an installed base; blocked while any VM references it.
    DeleteBase {
        identity: String,
        confirmed: bool,
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
    /// Send a downloaded malware sample into the guest: decrypted in memory
    /// from its archive (never written on the host) into a new guest file.
    UploadSample {
        sha256: String,
        destination: String,
        executable: bool,
    },
    Execute(ExecRequest),
    /// Cancel acquisition for a run without stopping the specimen.
    CancelProcessCore {
        run_id: String,
    },
    AnalyzeOnly {
        path: String,
        uid: u32,
        gid: u32,
        analysis: crate::analysis::AnalysisSelection,
    },
    CancelAnalysis {
        analysis_id: String,
    },
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
    ListProcesses {
        after_pid: u32,
    },
    AttachProcess {
        identity: crate::observation::GuestProcessIdentity,
    },
    CaptureAll,
    StopCapture {
        capture_id: String,
    },
    /// Record the running VM's network traffic (NAT VMs) into a new capture
    /// of the boot recording, until `StopNetworkCapture` or the VM stops.
    StartNetworkCapture,
    StopNetworkCapture,
    /// Dump the running VM's RAM (QEMU pauses the guest while it writes)
    /// into a new memory dump of its recordings, for the Memory tab.
    DumpMemory,
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
    /// Guest sends that found their ring full and waited (never-drop mode),
    /// and their total wait.
    #[serde(default)]
    pub transport_waits: u64,
    #[serde(default)]
    pub transport_wait_ns: u64,
    /// Per-vCPU guest ring bytes and the published send wait.
    #[serde(default)]
    pub ring_size: u32,
    #[serde(default)]
    pub send_wait_us: u32,
    /// Recording bytes queued for the disk writer thread.
    #[serde(default)]
    pub write_backlog: u64,
    /// Capture All is dropping telemetry because the host is behind; the
    /// guest would otherwise wait on every traced syscall.
    #[serde(default)]
    pub shedding: bool,
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

/// VM checkpoint content; full restores require a resume-capable guest.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmSnapshotMode {
    Disk,
    Full,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmSnapshotConsistency {
    Stopped,
    CrashConsistent,
    Paused,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub name: String,
    pub description: String,
    pub mode: VmSnapshotMode,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmCheckpoint {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub description: String,
    pub created_unix_ms: u64,
    pub mode: VmSnapshotMode,
    pub consistency: VmSnapshotConsistency,
    pub config: VmConfig,
    /// Allocated bytes in this checkpoint's frozen disk layer.
    pub disk_size: u64,
    /// Bytes in the serialized CPU/RAM/device artifact.
    pub memory_size: u64,
    pub compatible: bool,
    pub compatibility_note: Option<String>,
    /// Hidden checkpoint whose files are retained for dependencies.
    pub deleted: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmSnapshotCapabilities {
    pub can_create_disk: bool,
    pub can_create_full: bool,
    pub can_restore: bool,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmSnapshotTree {
    pub vm_id: String,
    pub nodes: Vec<VmCheckpoint>,
    pub active_parent_id: Option<String>,
    pub recovery_note: Option<String>,
    #[serde(default)]
    pub capabilities: VmSnapshotCapabilities,
}
#[derive(Clone, Debug)]
pub struct VmSnapshotProgress {
    pub vm_id: String,
    pub stage: String,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Host measurements for the active QEMU process, refreshed once a second.
    pub vm_resources: Option<VmResources>,
    pub vm_snapshot_trees: std::collections::BTreeMap<String, VmSnapshotTree>,
    pub vm_snapshot_progress: Option<VmSnapshotProgress>,
    /// The running VM's network capture, while one runs.
    pub network_capture: Option<crate::network::NetworkCapture>,
    /// The memory dump QEMU is writing, while it writes.
    pub memory_dump: Option<crate::memory::DumpProgress>,
    /// Process trees of this boot's captures that are still open, by capture id.
    pub capture_processes:
        std::collections::BTreeMap<String, Vec<crate::capture_processes::CaptureProcess>>,
    pub vms: Vec<VmConfig>,
    pub bases: Vec<BaseSummary>,
    /// The installed bases are still being listed (and, the first time,
    /// checked); `bases` is empty until then.
    pub bases_checking: bool,
    /// Bases advertised by the remote catalog, if it has been fetched.
    pub remote_bases: Vec<RemoteBase>,
    /// Last remote catalog error (tool alert or fetch failure).
    pub remote_error: Option<String>,
    pub remote_refreshing: bool,
    /// Progress of the single active remote download, if any.
    pub download: Option<DownloadStatus>,
    /// Progress and log tail of the single active local build, if any.
    pub build: Option<BuildStatus>,
    /// Optional static-analysis tools: on the system, installed by
    /// Antinomie, or missing.
    pub analysis_tools: Vec<crate::analysis_tools::ToolStatus>,
    /// Progress of the single active tool installation, if any.
    pub tool_install: Option<crate::analysis_tools::ToolInstall>,
    pub vm_locations: Vec<VmLocations>,
    pub active_vm: Option<String>,
    pub state: VmState,
    pub health: Health,
    pub events: Vec<EventSummary>,
    pub runs: Vec<RunSummary>,
    pub analysis_reports: Vec<crate::analysis::AnalysisReport>,
    pub captures: Vec<crate::observation::CaptureSummary>,
    /// At most the active/latest observer preview; older captures use archive paging.
    pub capture_events: std::collections::BTreeMap<String, Vec<EventSummary>>,
    pub boot_id: Option<String>,
    pub process_page: Option<crate::observation::GuestProcessPage>,
    pub capture_dir: Option<PathBuf>,
    pub serial_log: Option<PathBuf>,
    /// The running guest kernel, once it has answered the INFO probe.
    pub guest_kernel: Option<GuestKernel>,
    pub last_error: Option<String>,
}

/// Configured guest capacities remain in VmConfig; these are host measurements.
#[derive(Clone, Debug, Default)]
pub struct VmResources {
    pub vm_id: String,
    /// Elapsed host time since this QEMU process started, including pauses.
    pub uptime_ms: Option<u64>,
    /// CPU usage across QEMU threads; 100 percent represents one host CPU.
    pub qemu_cpu_percent: Option<f64>,
    /// Resident host memory; does not represent guest RAM utilization.
    pub qemu_resident_size: Option<u64>,
    /// Space available to this user on the data-directory filesystem.
    pub data_disk_available_size: Option<u64>,
    pub sample_error: Option<String>,
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
    /// Thread group (process) ID; 0 in summaries saved before 0.3.0.
    #[serde(default)]
    pub pid: u32,
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
    AnalysisUpdated {
        run_id: Option<String>,
        report: crate::analysis::AnalysisReport,
    },
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
                task_exit: None,
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
                task_exit: None,
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
    // A task's end belongs to the call it ended in; one without a captured
    // call (its records were lost) has no row to show it on.
    for event in events.iter().filter(|event| {
        event.phase == 3
            && event.call_id != 0
            && event
                .fields
                .iter()
                .any(|field| field.key == "lifecycle.task_exit")
    }) {
        if let Some(&index) = indexes.get(&(event.stream_id, event.task_cookie, event.call_id)) {
            rows[index].task_exit = Some(event.clone());
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_ids_and_revision_status() {
        let series = "0f".repeat(32);
        assert_eq!(
            parse_source_id(&format!("9:{series}")),
            Some((9, series.clone()))
        );
        for bad in [
            String::new(),
            series.clone(),
            format!("0:{series}"),
            format!("09:{series}"),
            format!("-9:{series}"),
            format!("9:{}", series.to_uppercase()),
            format!("9:{}", &series[1..]),
            format!("9:{series}0"),
            format!("1234567890:{series}"),
        ] {
            assert_eq!(parse_source_id(&bad), None, "{bad}");
        }
        assert_eq!(RevisionStatus::of(None), RevisionStatus::Legacy);
        assert_eq!(
            RevisionStatus::of(Some(APP_REVISION)),
            RevisionStatus::Current
        );
        assert_eq!(
            RevisionStatus::of(Some(APP_REVISION - 1)),
            RevisionStatus::Outdated
        );
        assert_eq!(
            RevisionStatus::of(Some(APP_REVISION + 1)),
            RevisionStatus::NeedsNewerApp
        );
        assert!(require_supported(None, None).is_ok());
        assert!(require_supported(Some(APP_REVISION), Some(APP_VERSION)).is_ok());
        let error = require_supported(Some(APP_REVISION + 1), None).unwrap_err();
        assert!(error.contains("update Antinomie"), "{error}");
        let app = Version::app();
        let newer = Version(app.0, app.1 + 1, 0).to_string();
        let error = require_supported(Some(APP_REVISION), Some(&newer)).unwrap_err();
        assert!(
            error.contains(&format!("needs Antinomie {newer}")),
            "{error}"
        );
        assert_eq!(
            RevisionStatus::of_base(Some(APP_REVISION), Some(&newer)),
            RevisionStatus::NeedsNewerApp
        );
    }
    #[test]
    fn versions_parse_compare_and_describe_bases() {
        assert_eq!(Version::parse("0.1.0"), Some(Version(0, 1, 0)));
        assert_eq!(Version::parse("1.10.2"), Some(Version(1, 10, 2)));
        for bad in [
            "", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "v1.2.3", "1.2.-3",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        assert!(Version(1, 0, 0) > Version(0, 99, 99));
        assert_eq!(Version::app().to_string(), APP_VERSION);
        let current = first_app_version(APP_REVISION).unwrap().to_string();
        assert_eq!(
            RevisionStatus::describe(Some(APP_REVISION), None),
            format!("for Antinomie {current}")
        );
        assert_eq!(
            RevisionStatus::describe(Some(APP_REVISION + 1), None),
            "needs a newer Antinomie".to_string()
        );
        assert_eq!(
            RevisionStatus::describe(Some(APP_REVISION + 1), Some("9.0.0")),
            "needs Antinomie 9.0.0 or newer"
        );
        assert_eq!(
            RevisionStatus::describe(None, None),
            "built before versioning"
        );
    }
    #[test]
    fn revision_changes_only_with_feature_or_major_releases() {
        let history = revision_history();
        assert!(!history.is_empty());
        for pair in history.windows(2) {
            assert!(pair[1].0 > pair[0].0 && pair[1].1 > pair[0].1, "{pair:?}");
        }
        for (revision, version) in &history {
            // A revision ships with x.y.0, never with a fix release.
            assert_eq!(version.2, 0, "revision {revision} introduced by {version}");
        }
        let (latest, introduced) = *history.last().unwrap();
        assert_eq!(
            latest, APP_REVISION,
            "add ANTC_REVISION {APP_REVISION} to protocol/revisions.json with its release"
        );
        assert!(
            introduced <= Version::app(),
            "revision {latest} is recorded for {introduced}, newer than this app ({APP_VERSION})"
        );
    }
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
            pid: 5,
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
    fn a_task_exit_belongs_to_the_call_it_ended_in() {
        let entry = EventSummary {
            root_task_cookie: 1,
            stream_id: 1,
            task_cookie: 2,
            call_id: 3,
            event_seq: 4,
            phase: 1,
            syscall_nr: 231,
            syscall_name: "exit_group".into(),
            pid: 5,
            tid: 5,
            cpu: 0,
            timestamp_ns: 6,
            args: Some([1, 0, 0, 0, 0, 0]),
            result: None,
            complete: true,
            issues: vec![],
            fields: vec![],
        };
        let ended = |call_id, raw: u64| {
            let mut event = entry.clone();
            event.phase = 3;
            event.call_id = call_id;
            event.event_seq = 5;
            event.fields = vec![FieldSummary {
                object_id: 1,
                key: "lifecycle.task_exit".into(),
                layout: String::new(),
                logical_len: Some(8),
                captured_len: 8,
                status: Some(0),
                capture_error: 0,
                complete: true,
                preview: raw.to_le_bytes().to_vec(),
                raw_path: None,
                ranges: vec![(0, 8)],
            }];
            event
        };
        // exit_group(1): the kernel keeps the wait status 1 << 8.
        let rows = pair_events(&[entry.clone(), ended(3, 0x100)]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].exit.is_none() && rows[0].async_events.is_empty());
        assert_eq!(rows[0].task_exit.as_ref().unwrap().event_seq, 5);
        assert_eq!(
            rows[0].task_exit_status(),
            Some(WaitStatus::Exited { code: 1 })
        );
        // Killed while blocked; a task end with no captured call has no row.
        let rows = pair_events(&[entry.clone(), ended(3, 9), ended(8, 0)]);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].task_exit_status(),
            Some(WaitStatus::Signaled {
                signal: 9,
                core_dumped: false
            })
        );
    }
    #[test]
    fn wait_statuses_decode_exits_and_fatal_signals() {
        assert_eq!(
            WaitStatus::from_raw(0),
            Some(WaitStatus::Exited { code: 0 })
        );
        assert_eq!(
            WaitStatus::from_raw(0xff00),
            Some(WaitStatus::Exited { code: 255 })
        );
        assert_eq!(
            WaitStatus::from_raw(0x8b),
            Some(WaitStatus::Signaled {
                signal: 11,
                core_dumped: true
            })
        );
        // Stopped (0x7f), exit code with a signal, out of range.
        for raw in [0x7f, 0x17f, 0x109, 0x10000] {
            assert_eq!(WaitStatus::from_raw(raw), None, "{raw:#x}");
        }
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
            pid: 5,
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
