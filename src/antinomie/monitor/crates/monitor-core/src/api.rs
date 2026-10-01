use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VmConfig {
    pub id: String,
    pub name: String,
    pub cpus: u16,
    pub ram_mib: u32,
    pub disk_gib: u32,
    pub nat: bool,
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
        }
    }
}

#[derive(Clone, Debug)]
pub struct BackendOptions {
    pub data_dir: PathBuf,
    pub bundle_dir: PathBuf,
    pub qemu: PathBuf,
    pub qemu_img: PathBuf,
    /// Shared payload quota for raw packets and assembled fields, in bytes.
    /// Bounded event indexes, manifests, VM disks, and imported bases are separate.
    pub capture_quota_size: u64,
    pub shutdown_timeout: Duration,
    pub bootstrap_gpa: Option<u64>,
    pub force_tcg: bool,
    pub headless: bool,
}
impl Default for BackendOptions {
    fn default() -> Self {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
            });
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

#[derive(Clone, Debug)]
pub struct ExecRequest {
    pub path: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: Vec<String>,
    pub uid: u32,
    pub gid: u32,
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
    Save(VmConfig),
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
    TerminalInput(Vec<u8>),
    TerminalRead,
    TerminalResize {
        rows: u16,
        cols: u16,
    },
    Signal {
        pid: u32,
        signal: u32,
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
    pub active_vm: Option<String>,
    pub state: VmState,
    pub health: Health,
    pub events: Vec<EventSummary>,
    pub capture_dir: Option<PathBuf>,
    pub serial_log: Option<PathBuf>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSummary {
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
    Terminal(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
