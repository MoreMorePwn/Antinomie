// SPDX-License-Identifier: MIT
//! The architecture-neutral view of a debuggable target. Everything the RSP
//! server needs is expressed here, so the Linux kernel engine and a future
//! QEMU-gdbstub backend are interchangeable.
use super::regs::TargetDescription;
use std::fmt;

/// Architecture tag carried on every debug message: the ELF `e_machine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchTag {
    X86_64,
}
impl ArchTag {
    pub fn from_e_machine(value: u32) -> Option<Self> {
        match value {
            62 => Some(Self::X86_64),
            _ => None,
        }
    }
    pub fn e_machine(self) -> u32 {
        match self {
            Self::X86_64 => 62,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
        }
    }
    /// The register file this architecture's debuggers see.
    pub fn description(self) -> &'static TargetDescription {
        match self {
            Self::X86_64 => super::amd64::description(),
        }
    }
}

/// A register set the guest can transfer, tagged with its ELF note type
/// (`NT_PRSTATUS` = 1, `NT_PRFPREG` = 2, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegsetInfo {
    pub nt_type: u32,
    /// Largest blob in bytes; 0 means it depends on the task.
    pub max_size: u32,
    pub writable: bool,
}

/// What the guest engine can do, reported at attach. Anything not advertised
/// here is never offered to a debugger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugCaps {
    pub abi: u32,
    pub arch: ArchTag,
    pub software_breakpoints: bool,
    pub hardware_single_step: bool,
    pub shadow_reads: bool,
    pub multi_thread: bool,
    pub hardware_breakpoints: u32,
    pub hardware_watchpoints: u32,
    /// Bit `n - 1` set: a software breakpoint of `n` bytes is supported.
    pub breakpoint_len_mask: u32,
    pub watch_len_mask: u32,
    pub max_threads: u32,
    /// Largest memory transfer in one request.
    pub max_transfer: u32,
    pub regsets: Vec<RegsetInfo>,
}
impl DebugCaps {
    pub fn supports_breakpoint_len(&self, len: u32) -> bool {
        (1..=32).contains(&len) && self.breakpoint_len_mask & (1 << (len - 1)) != 0
    }
    pub fn regset(&self, nt_type: u32) -> Option<&RegsetInfo> {
        self.regsets.iter().find(|regset| regset.nt_type == nt_type)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegsetBlob {
    pub nt_type: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    /// Resume every thread.
    Continue,
    /// Execute one user instruction of one thread; the others stay stopped.
    Step { tid: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopKind {
    /// Stopped because the debugger asked.
    Interrupt,
    Breakpoint {
        addr: u64,
    },
    Step,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopEvent {
    /// Increases with every new stop; a repeated poll returns the same value.
    pub sequence: u32,
    pub kind: StopKind,
    pub tid: u32,
    pub pc: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetState {
    Running,
    /// Stopping or resuming: the group is between states.
    Transition,
    Stopped(StopEvent),
    /// The process ended; the value is its wait status.
    Exited {
        wait_status: u32,
    },
    /// The process executed a new image; the session no longer applies.
    Replaced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadInfo {
    pub tid: u32,
    pub stopped: bool,
    pub pc: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachMode {
    /// Remove breakpoints and let the process run on.
    Resume,
    /// Kill the process.
    Kill,
}

/// A request to the guest could not be completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkError {
    pub errno: Option<i32>,
    pub message: String,
    pub outcome_unknown: bool,
}
impl LinkError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            errno: None,
            message: message.into(),
            outcome_unknown: false,
        }
    }
}

/// The path to the guest: one control request, one reply. The app's worker
/// thread owns the transport, so a backend running on another thread uses an
/// implementation that forwards to it.
pub trait GuestLink {
    fn request(&mut self, opcode: u32, args: &[u8]) -> Result<Vec<u8>, LinkError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugError {
    /// The guest or architecture cannot do this.
    Unsupported(String),
    /// The target is not stopped, or a transition is under way.
    Busy,
    /// The stop the request was made against is over.
    Stale,
    /// No such thread or process.
    Gone,
    /// The address is not readable or writable.
    Fault,
    Invalid(String),
    Guest {
        errno: i32,
        message: String,
    },
    Transport(String),
}
impl fmt::Display for DebugError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(formatter, "unsupported: {what}"),
            Self::Busy => write!(formatter, "the process is not stopped"),
            Self::Stale => write!(formatter, "the process resumed since that stop"),
            Self::Gone => write!(formatter, "no such thread or process"),
            Self::Fault => write!(formatter, "address not accessible"),
            Self::Invalid(what) => write!(formatter, "invalid request: {what}"),
            Self::Guest { errno, message } => write!(formatter, "guest error {errno}: {message}"),
            Self::Transport(what) => write!(formatter, "transport: {what}"),
        }
    }
}
impl std::error::Error for DebugError {}

/// One debuggable process. All-stop: `resume` runs every thread (or steps one),
/// `state` reports when the group stopped again, `interrupt` asks it to.
pub trait DebugBackend: Send {
    fn caps(&self) -> &DebugCaps;
    fn state(&mut self) -> Result<TargetState, DebugError>;
    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError>;
    fn interrupt(&mut self) -> Result<(), DebugError>;
    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError>;
    fn read_regset(&mut self, tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError>;
    fn write_regset(&mut self, tid: u32, blob: &RegsetBlob) -> Result<(), DebugError>;
    /// Short reads end at the first unreadable byte; none readable is `Fault`.
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, DebugError>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), DebugError>;
    fn set_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError>;
    fn clear_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError>;
    fn detach(&mut self, mode: DetachMode) -> Result<(), DebugError>;
    /// Why the last stop or resume request did not take effect, once: for
    /// example a thread that could not be stopped in time.
    fn take_failure(&mut self) -> Option<String> {
        None
    }
}
