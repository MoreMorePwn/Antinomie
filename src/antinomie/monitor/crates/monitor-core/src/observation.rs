//! Guest process selection and independent, non-terminating telemetry captures.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PROCESS_PAGE_MAX_COUNT: u32 = 64;
/// Captures per boot on guests before revision 12, which never reuse a slot.
pub const OBSERVATION_MAX_COUNT: usize = 64;
/// Capture archives kept open per boot for late tails; matches the guest's
/// retained capture records (revision 12 recycles them, IDs never repeat).
pub const OBSERVATION_RETAINED: usize = 64;
/// First guest revision without a per-boot capture limit.
pub const UNLIMITED_CAPTURE_REVISION: u32 = 12;

/// Boot and task identity own selection; PID alone never authorizes attachment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestProcessIdentity {
    pub boot_id: String,
    pub task_cookie: u64,
    pub tgid: u32,
    pub start_boot_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestProcess {
    pub identity: GuestProcessIdentity,
    pub parent_tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub thread_count: u32,
    pub command: String,
}

#[derive(Clone, Debug, Default)]
pub struct GuestProcessPage {
    pub boot_id: String,
    pub after_pid: u32,
    /// Zero ends the non-atomic live enumeration; refresh may change the list.
    pub next_pid: u32,
    pub processes: Vec<GuestProcess>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaptureScope {
    Process { root: GuestProcessIdentity },
    AllUserspace,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaptureState {
    /// No successful acknowledgement; admission outcome may be unknown.
    Unknown,
    Active,
    /// Admission stopped; already admitted observation tails may still arrive.
    Stopped,
    /// Archive closed, not proof that every observation was delivered.
    Finalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub capture_cookie: u64,
    pub scope: CaptureScope,
    pub directory: PathBuf,
    pub state: CaptureState,
    pub recording_error: Option<String>,
    pub start_ns: Option<u64>,
    pub stop_ns: Option<u64>,
    /// Observation predates attach, loss, or pending tails must not appear complete.
    pub incomplete_reason: Option<String>,
}
