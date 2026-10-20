// SPDX-License-Identifier: MIT
//! What the in-app debugger shows, as plain data. The controller that owns the
//! debug engine for the app (`ui_control`) fills a [`DebugView`]; the UI only
//! reads it and sends [`DebugRequest`]s. Nothing here talks to the guest.
//!
//! The types are shaped for what the engine will grow: a breakpoint has a kind
//! (software today, hardware and watchpoints later), a stop has a reason with
//! signal and watchpoint variants, and a request names the stop it was made
//! against so a reply to a stop that is over is dropped, never applied.
use super::{
    regs::RegKind,
    signal_policy::{SignalAction, SignalNote, SignalTable},
    target::StopKind,
};
use std::fmt;

/// Who drives the process. One at a time: a debugger client connecting over
/// the RSP socket takes control and the app's own panel becomes read-only until
/// the client leaves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Controller {
    /// The in-app panel (the default, and again once a client has left).
    #[default]
    App,
    /// An external debugger (gdb, IDA, Ghidra, radare2) is connected.
    Gdb,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WatchAccess {
    Write,
    Read,
    Access,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BreakpointKind {
    Software,
    /// Debug-register execute breakpoint (debugger Phase 2).
    Hardware,
    /// Debug-register data breakpoint (debugger Phase 2).
    Watch(WatchAccess),
}
impl BreakpointKind {
    /// Uses a debug register, and so one of the few slots.
    pub fn is_hardware(self) -> bool {
        self != Self::Software
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Software => "sw",
            Self::Hardware => "hw",
            Self::Watch(WatchAccess::Write) => "watch w",
            Self::Watch(WatchAccess::Read) => "watch r",
            Self::Watch(WatchAccess::Access) => "watch rw",
        }
    }
}

/// Why the process is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// The debugger asked for the stop.
    Interrupt,
    Breakpoint {
        addr: u64,
        kind: BreakpointKind,
    },
    Watchpoint {
        addr: u64,
        access: WatchAccess,
    },
    /// One instruction was executed.
    Step,
    /// The process received a signal (debugger Phase 2).
    Signal {
        number: u8,
    },
    /// Stopped before its first instruction (debug on start, Phase 2).
    Entry,
    /// The thread made a process with fork (debugger Phase 3).
    Fork {
        child: u32,
    },
    /// The thread is in vfork; the child shares its memory.
    Vfork {
        child: u32,
    },
    /// The vfork child let go of the memory (exec or exit).
    VforkDone,
    /// The process executed a new program and the session continues in it.
    Exec,
}
impl StopReason {
    pub fn from_kind(kind: StopKind) -> Self {
        match kind {
            StopKind::Interrupt => Self::Interrupt,
            StopKind::Breakpoint { addr } => Self::Breakpoint {
                addr,
                kind: BreakpointKind::Software,
            },
            StopKind::HardwareBreakpoint { addr } => Self::Breakpoint {
                addr,
                kind: BreakpointKind::Hardware,
            },
            StopKind::Watchpoint { addr, access } => Self::Watchpoint { addr, access },
            StopKind::Step => Self::Step,
            // The Linux number; only the signals 1..=64 exist.
            StopKind::Signal { signal } => Self::Signal {
                number: u8::try_from(signal).unwrap_or(0),
            },
            StopKind::Entry => Self::Entry,
            StopKind::Fork { child } => Self::Fork { child: child.tgid },
            StopKind::Vfork { child } => Self::Vfork { child: child.tgid },
            StopKind::VforkDone { .. } => Self::VforkDone,
            StopKind::Exec => Self::Exec,
        }
    }
}
impl fmt::Display for StopReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupt => write!(formatter, "interrupted"),
            Self::Breakpoint { kind, .. } => match kind {
                BreakpointKind::Software => write!(formatter, "swbreak"),
                _ => write!(formatter, "hwbreak"),
            },
            Self::Watchpoint { addr, access } => {
                write!(formatter, "watch ({}) {addr:#x}", access_name(*access))
            }
            Self::Step => write!(formatter, "step"),
            Self::Signal { number } => write!(formatter, "signal {number}"),
            Self::Entry => write!(formatter, "entry"),
            Self::Fork { child } => write!(formatter, "fork (child {child})"),
            Self::Vfork { child } => write!(formatter, "vfork (child {child})"),
            Self::VforkDone => write!(formatter, "vfork done"),
            Self::Exec => write!(formatter, "exec"),
        }
    }
}
fn access_name(access: WatchAccess) -> &'static str {
    match access {
        WatchAccess::Write => "write",
        WatchAccess::Read => "read",
        WatchAccess::Access => "access",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunState {
    /// The panel has not heard from the engine yet.
    Unknown,
    Stopped {
        reason: StopReason,
        tid: u32,
        pc: u64,
        /// Identifies this stop: requests name it, and a reply made against
        /// another one is dropped.
        sequence: u32,
    },
    /// Continuing, or between states. `Step`/`Stop` requests are in flight when
    /// `pending` says so.
    Running { pending: Pending },
    /// The process ended; the value is its wait status.
    Exited { wait_status: u32 },
    /// The process executed a new image; the session no longer applies.
    Replaced,
}

/// What the panel is waiting for while the process is not stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Running freely.
    Nothing,
    /// A stop was requested_size and has not happened yet.
    Stopping,
    /// A single step was requested_size and has not completed yet.
    Stepping,
}

impl RunState {
    pub fn stopped_sequence(&self) -> Option<u32> {
        match self {
            Self::Stopped { sequence, .. } => Some(*sequence),
            _ => None,
        }
    }
    pub fn is_over(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Replaced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugThread {
    pub tid: u32,
    pub stopped: bool,
    pub pc: u64,
    /// The Linux signal a stopped thread has not yet received, else 0.
    pub signal: u32,
}

/// Where one process of the session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferiorState {
    Running,
    Stopped(StopReason),
    /// A child the guest holds where the fork put it, not yet chosen to run.
    Held,
    /// The process ended; the value is its wait status.
    Exited(u32),
}

/// One process of the session: the program, and every child of a fork the panel
/// has taken hold of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InferiorView {
    pub pid: u32,
    pub parent: Option<u32>,
    /// The panel's registers, memory and breakpoints are about this process.
    pub selected: bool,
    /// A vfork child, sharing its parent's memory until it execs.
    pub vfork: bool,
    pub state: InferiorState,
}

/// What the panel does when the program forks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FollowMode {
    /// A forked child runs free and is not debugged (the Phase 2 behavior).
    Off,
    /// Stay with the parent.
    #[default]
    Parent,
    /// Go with the child.
    Child,
    /// Stop at the fork and let the user choose.
    Ask,
}
impl FollowMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Do not follow",
            Self::Parent => "Follow the parent",
            Self::Child => "Follow the child",
            Self::Ask => "Ask at each fork",
        }
    }
}

/// gdb's `follow-fork-mode` and `detach-on-fork` for the panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkPolicy {
    pub follow: FollowMode,
    /// Let the process that is not followed run free. Off: it is kept stopped,
    /// listed under Processes, until the user chooses.
    pub detach_other: bool,
}
impl Default for ForkPolicy {
    fn default() -> Self {
        Self {
            follow: FollowMode::default(),
            detach_other: true,
        }
    }
}

/// Which process of a fork to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkChoice {
    Parent,
    Child,
}

/// The program forked and the panel is waiting for the user (`FollowMode::Ask`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkPrompt {
    pub parent: u32,
    pub child: u32,
    pub vfork: bool,
}

/// One register of the stopped thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterEntry {
    pub name: &'static str,
    pub value: u64,
    pub kind: RegKind,
}

/// The registers of one thread at one stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterSnapshot {
    pub tid: u32,
    pub sequence: u32,
    pub entries: Vec<RegisterEntry>,
}
impl RegisterSnapshot {
    pub fn get(&self, name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.value)
    }
}

/// Which pane a memory window feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind {
    /// Around the instruction pointer.
    Code,
    /// From the stack pointer up.
    Stack,
    /// A range the user asked for.
    Memory,
}

/// A bounded range of the process's memory read at one stop. `bytes` may be
/// shorter than requested_size (unreadable beyond), and `error` says why nothing
/// could be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryWindow {
    pub kind: WindowKind,
    pub sequence: u32,
    pub address: u64,
    pub requested_size: usize,
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

/// A breakpoint in the panel's list. `enabled` ones are registered with the
/// guest (a breakpoint the guest refuses is never added).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakpointEntry {
    pub addr: u64,
    pub kind: BreakpointKind,
    pub enabled: bool,
}

/// The breakpoints the panel manages. Pure bookkeeping; the controller applies
/// the changes to the guest and records the outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BreakpointList {
    entries: Vec<BreakpointEntry>,
}
impl BreakpointList {
    /// Most breakpoints the panel keeps (the guest has its own, lower, limit).
    pub const LIMIT: usize = 64;

    pub fn entries(&self) -> &[BreakpointEntry] {
        &self.entries
    }
    pub fn get(&self, addr: u64) -> Option<&BreakpointEntry> {
        self.entries.iter().find(|entry| entry.addr == addr)
    }
    pub fn get_mut(&mut self, addr: u64) -> Option<&mut BreakpointEntry> {
        self.entries.iter_mut().find(|entry| entry.addr == addr)
    }
    /// Add an enabled breakpoint. A second one at the same address is refused.
    pub fn add(&mut self, addr: u64, kind: BreakpointKind) -> Result<(), String> {
        if self.get(addr).is_some() {
            return Err(format!("there is already a breakpoint at {addr:#x}"));
        }
        if self.entries.len() >= Self::LIMIT {
            return Err(format!("at most {} breakpoints", Self::LIMIT));
        }
        self.entries.push(BreakpointEntry {
            addr,
            kind,
            enabled: true,
        });
        self.entries.sort_by_key(|entry| (entry.addr, entry.kind));
        Ok(())
    }
    pub fn remove(&mut self, addr: u64) -> Option<BreakpointEntry> {
        let index = self.entries.iter().position(|entry| entry.addr == addr)?;
        Some(self.entries.remove(index))
    }
    pub fn set_enabled(&mut self, addr: u64, enabled: bool) -> bool {
        match self.get_mut(addr) {
            Some(entry) => {
                entry.enabled = enabled;
                true
            }
            None => false,
        }
    }
}

/// What the guest engine offers, for greying out what is not available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewCaps {
    pub software_breakpoints: bool,
    pub single_step: bool,
    pub hardware_breakpoints: u32,
    pub hardware_watchpoints: u32,
    /// The guest can follow forks and execs.
    pub follow: bool,
}

/// Everything the debugger panel shows. Replaced as a whole whenever any part
/// changes; `epoch` increases with every replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugView {
    pub epoch: u64,
    pub controller: Controller,
    pub run: RunState,
    pub caps: ViewCaps,
    /// Highest request id the controller has handled (applied or dropped).
    pub handled: u64,
    /// The stop's data is still being fetched (threads, registers, memory).
    pub loading: bool,
    pub selected_tid: Option<u32>,
    pub threads: Vec<DebugThread>,
    pub registers: Option<RegisterSnapshot>,
    pub code: Option<MemoryWindow>,
    pub stack: Option<MemoryWindow>,
    pub memory: Option<MemoryWindow>,
    pub breakpoints: Vec<BreakpointEntry>,
    /// Every process of the session, parent first.
    pub inferiors: Vec<InferiorView>,
    pub selected_pid: u32,
    pub fork_prompt: Option<ForkPrompt>,
    pub fork_policy: ForkPolicy,
    /// The panel's `handle` table.
    pub signals: SignalTable,
    /// The latest signals the table let through or stopped on (bounded).
    pub signal_log: Vec<SignalNote>,
    /// The latest thing that did not work, until the next request.
    pub notice: Option<String>,
}
impl DebugView {
    pub fn new(caps: ViewCaps) -> Self {
        Self {
            epoch: 0,
            controller: Controller::App,
            run: RunState::Unknown,
            caps,
            handled: 0,
            loading: false,
            selected_tid: None,
            threads: Vec::new(),
            registers: None,
            code: None,
            stack: None,
            memory: None,
            breakpoints: Vec::new(),
            inferiors: Vec::new(),
            selected_pid: 0,
            fork_prompt: None,
            fork_policy: ForkPolicy::default(),
            signals: SignalTable::default(),
            signal_log: Vec::new(),
            notice: None,
        }
    }
    /// Whether the panel may send commands that move or change the process.
    pub fn app_controls(&self) -> bool {
        self.controller == Controller::App
    }
    /// The window for `kind`, only if it belongs to the current stop.
    pub fn window(&self, kind: WindowKind) -> Option<&MemoryWindow> {
        let sequence = self.run.stopped_sequence()?;
        match kind {
            WindowKind::Code => self.code.as_ref(),
            WindowKind::Stack => self.stack.as_ref(),
            WindowKind::Memory => self.memory.as_ref(),
        }
        .filter(|window| window.sequence == sequence)
    }
}

/// What the panel asks the controller to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugAction {
    /// Resume every thread.
    Continue,
    /// Execute one instruction of `tid`; the other threads stay stopped.
    Step {
        tid: u32,
    },
    /// Ask the running process to stop.
    Stop,
    /// Read the stop's data again.
    Refresh,
    /// Show another thread of the stopped process.
    SelectThread {
        tid: u32,
    },
    AddBreakpoint {
        addr: u64,
        kind: BreakpointKind,
    },
    RemoveBreakpoint {
        addr: u64,
    },
    SetBreakpointEnabled {
        addr: u64,
        enabled: bool,
    },
    /// Read `size` bytes (at most [`MAX_READ_SIZE`]) for the memory pane.
    ReadMemory {
        addr: u64,
        size: usize,
    },
    /// Show another process of the session.
    SelectInferior {
        pid: u32,
    },
    /// The program forked and the panel asked: follow one, and say what becomes of
    /// the other.
    ForkDecision {
        follow: ForkChoice,
        detach_other: bool,
    },
    /// Let a process go (a held child, or one that is no longer wanted).
    DetachInferior {
        pid: u32,
    },
    SetForkPolicy(ForkPolicy),
    /// One signal's `stop print pass`.
    SetSignalPolicy {
        signal: u8,
        action: SignalAction,
    },
    /// The whole table (the one the app remembered), or gdb's defaults.
    SetSignalTable(SignalTable),
}
impl DebugAction {
    /// Whether the action only makes sense against the stop the panel saw.
    pub fn needs_stop(&self) -> bool {
        !matches!(
            self,
            Self::Stop
                | Self::AddBreakpoint { .. }
                | Self::RemoveBreakpoint { .. }
                | Self::SetBreakpointEnabled { .. }
                | Self::SelectInferior { .. }
                | Self::DetachInferior { .. }
                | Self::SetForkPolicy(_)
                | Self::SetSignalPolicy { .. }
                | Self::SetSignalTable(_)
        )
    }
}

/// One request from the panel. `id` increases per panel; `sequence` is the
/// stop the panel was showing (0 when it showed none): a request that needs a
/// stop is dropped when the process is no longer stopped at that one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRequest {
    pub id: u64,
    pub sequence: u32,
    pub action: DebugAction,
}

/// Largest memory range one request reads (the bounded Stack/Memory pane).
pub const MAX_READ_SIZE: usize = 4096;

/// Instruction-pointer window: bytes before and after `rip` that are read to
/// disassemble around it.
pub const CODE_BEFORE_SIZE: usize = 48;
pub const CODE_AFTER_SIZE: usize = 208;
/// Bytes of stack shown from the stack pointer.
pub const STACK_WINDOW_SIZE: usize = 256;

/// The flags of an x86 `rflags` value, in bit order, as the names a debugger
/// prints. `IOPL` carries its two-bit level.
pub fn decode_rflags(value: u64) -> Vec<String> {
    const BITS: [(u32, &str); 16] = [
        (0, "CF"),
        (2, "PF"),
        (4, "AF"),
        (6, "ZF"),
        (7, "SF"),
        (8, "TF"),
        (9, "IF"),
        (10, "DF"),
        (11, "OF"),
        (14, "NT"),
        (16, "RF"),
        (17, "VM"),
        (18, "AC"),
        (19, "VIF"),
        (20, "VIP"),
        (21, "ID"),
    ];
    let iopl = (value >> 12) & 3;
    let mut flags = Vec::new();
    for (bit, name) in BITS {
        // The two-bit privilege level sits between OF (11) and NT (14).
        if bit == 14 && iopl != 0 {
            flags.push(format!("IOPL={iopl}"));
        }
        if value & (1 << bit) != 0 {
            flags.push(name.to_string());
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rflags_decode_names_the_set_bits_in_order() {
        // Reserved bit 1 is always set and is not a flag.
        assert_eq!(decode_rflags(0x2), Vec::<String>::new());
        assert_eq!(decode_rflags(0x246), ["PF", "ZF", "IF"]);
        assert_eq!(decode_rflags(0x203), ["CF", "IF"]);
        assert_eq!(
            decode_rflags(0x0020_0cd5),
            ["CF", "PF", "AF", "ZF", "SF", "DF", "OF", "ID"]
        );
        assert_eq!(decode_rflags(0x1_3000 | 0x100), ["TF", "IOPL=3", "RF"]);
        assert_eq!(decode_rflags(0x3000 | 0x2), ["IOPL=3"]);
        assert_eq!(decode_rflags(0x1000), ["IOPL=1"]);
        assert_eq!(decode_rflags(0x100 | 0x4000), ["TF", "NT"]);
        assert_eq!(
            decode_rflags(u64::MAX).last().map(String::as_str),
            Some("ID")
        );
    }

    #[test]
    fn the_breakpoint_list_keeps_unique_sorted_addresses() {
        let mut list = BreakpointList::default();
        list.add(0x2000, BreakpointKind::Software).unwrap();
        list.add(0x1000, BreakpointKind::Software).unwrap();
        let error = list.add(0x1000, BreakpointKind::Hardware).unwrap_err();
        assert!(error.contains("already"), "{error}");
        let addresses: Vec<u64> = list.entries().iter().map(|entry| entry.addr).collect();
        assert_eq!(addresses, [0x1000, 0x2000]);
        assert!(list.set_enabled(0x1000, false));
        assert!(!list.get(0x1000).unwrap().enabled);
        assert!(!list.set_enabled(0x3000, true));
        assert_eq!(list.remove(0x2000).map(|entry| entry.addr), Some(0x2000));
        assert!(list.remove(0x2000).is_none());
        assert_eq!(list.entries().len(), 1);
    }

    #[test]
    fn the_breakpoint_list_is_bounded() {
        let mut list = BreakpointList::default();
        for index in 0..BreakpointList::LIMIT as u64 {
            list.add(0x1000 + index, BreakpointKind::Software).unwrap();
        }
        assert!(list.add(0x9000, BreakpointKind::Software).is_err());
    }

    #[test]
    fn stop_reasons_cover_what_the_engine_reports_today_and_later() {
        assert_eq!(StopReason::from_kind(StopKind::Step), StopReason::Step);
        assert_eq!(
            StopReason::from_kind(StopKind::Breakpoint { addr: 0x40 }),
            StopReason::Breakpoint {
                addr: 0x40,
                kind: BreakpointKind::Software
            }
        );
        assert_eq!(StopReason::Signal { number: 11 }.to_string(), "signal 11");
        assert_eq!(
            StopReason::Breakpoint {
                addr: 0,
                kind: BreakpointKind::Software
            }
            .to_string(),
            "swbreak"
        );
        assert_eq!(
            StopReason::Breakpoint {
                addr: 0,
                kind: BreakpointKind::Hardware
            }
            .to_string(),
            "hwbreak"
        );
        assert_eq!(BreakpointKind::Watch(WatchAccess::Read).label(), "watch r");
    }

    #[test]
    fn only_requests_tied_to_a_stop_name_one() {
        assert!(DebugAction::Continue.needs_stop());
        assert!(DebugAction::Step { tid: 1 }.needs_stop());
        assert!(DebugAction::ReadMemory { addr: 0, size: 1 }.needs_stop());
        assert!(!DebugAction::Stop.needs_stop());
        assert!(
            !DebugAction::AddBreakpoint {
                addr: 1,
                kind: BreakpointKind::Software
            }
            .needs_stop()
        );
    }
}
