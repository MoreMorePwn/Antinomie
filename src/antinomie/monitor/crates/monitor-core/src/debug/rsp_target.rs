// SPDX-License-Identifier: MIT
//! The gdbstub `Target`: translates RSP requests into `DebugBackend` calls.
//! All-stop, one process. Breakpoints are reference-counted here (a debugger
//! may ask for the same address twice) and live in the guest only while the
//! group runs, so memory read while stopped is always the sample's own bytes.
//! The in-app panel shares the guest's breakpoint table: an address stays
//! registered while either a connected debugger or the panel wants it.
use super::{
    amd64::{Amd64, BreakpointLen},
    regs::{RegisterFile, TargetDescription},
    signals::{gdb_to_linux, linux_to_gdb},
    target::{DebugBackend, DebugError, ResumeAction, StopEvent, StopKind, TargetState},
    view::{BreakpointKind, WatchAccess},
};
use gdbstub::{
    common::{Signal, Tid},
    stub::MultiThreadStopReason,
    target::{
        Target, TargetError, TargetResult,
        ext::{
            auxv::{Auxv, AuxvOps},
            base::{
                BaseOps,
                multithread::{
                    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps,
                    MultiThreadSchedulerLocking, MultiThreadSchedulerLockingOps,
                    MultiThreadSingleStep, MultiThreadSingleStepOps,
                },
            },
            breakpoints::{
                Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, HwWatchpoint,
                HwWatchpointOps, SwBreakpoint, SwBreakpointOps, WatchKind,
            },
        },
    },
};
use std::{collections::BTreeMap, num::NonZeroUsize};

/// The packet size advertised to the client: reads and writes of this order fit
/// a guest request, larger ones are split by the backend.
pub(super) const PACKET_BUFFER: usize = 0x4000;

fn tid_of(tid: Tid) -> u32 {
    u32::try_from(tid.get()).unwrap_or(0)
}

/// A backend error as the RSP target reports it: transport trouble ends the
/// session, anything else is an error reply the client shows to its user.
fn report(error: DebugError) -> TargetError<DebugError> {
    match error {
        DebugError::Fault => TargetError::Errno(14),
        DebugError::Busy => TargetError::Errno(16),
        DebugError::NoSlots => TargetError::Errno(28),
        DebugError::Gone => TargetError::Errno(3),
        DebugError::Stale => TargetError::Errno(116),
        DebugError::Unsupported(_) | DebugError::Invalid(_) => TargetError::Errno(22),
        error @ (DebugError::Transport(_) | DebugError::Guest { .. }) => TargetError::Fatal(error),
    }
}

/// GDB's number for a signal it has no name for.
const GDB_SIGNAL_UNKNOWN: u8 = 143;

fn gdb_signal(linux: u32) -> Signal {
    Signal(linux_to_gdb(linux).unwrap_or(GDB_SIGNAL_UNKNOWN))
}

#[derive(Default)]
struct Actions {
    step: Option<u32>,
    /// The thread and Linux signal number a resume delivers.
    signal: Option<(u32, u32)>,
}

/// Who wants a breakpoint at one address: the RSP client (counted, it may ask
/// twice) and the in-app panel (once).
#[derive(Default)]
struct Wanted {
    client: u32,
    panel: bool,
}
impl Wanted {
    fn none(&self) -> bool {
        self.client == 0 && !self.panel
    }
}

pub(super) struct RspTarget {
    backend: Box<dyn DebugBackend>,
    description: &'static TargetDescription,
    actions: Actions,
    breakpoints: BTreeMap<u64, Wanted>,
    /// Hardware breakpoints and watchpoints held, by the debug-register request
    /// they became, with who wants each (the same ownership as `breakpoints`).
    hardware: BTreeMap<(BreakpointKind, u64, u32), Wanted>,
    registers: Option<(u32, RegisterFile)>,
    /// The program's auxiliary vector, read at a stop after it was last empty.
    auxv: Option<Vec<u8>>,
    stop: Option<StopEvent>,
    last_sequence: Option<u32>,
    running: bool,
}

impl RspTarget {
    pub(super) fn new(backend: Box<dyn DebugBackend>) -> Self {
        let description = backend.caps().arch.description();
        Self {
            backend,
            description,
            actions: Actions::default(),
            breakpoints: BTreeMap::new(),
            hardware: BTreeMap::new(),
            registers: None,
            auxv: None,
            stop: None,
            last_sequence: None,
            running: false,
        }
    }
    pub(super) fn backend(&mut self) -> &mut dyn DebugBackend {
        self.backend.as_mut()
    }
    pub(super) fn is_running(&self) -> bool {
        self.running
    }
    /// A new client: learn the target's current state without assuming it.
    pub(super) fn adopt(&mut self) -> Result<TargetState, DebugError> {
        self.registers = None;
        let state = self.backend.state()?;
        match state {
            TargetState::Stopped(event) => {
                self.stop = Some(event);
                self.last_sequence = Some(event.sequence);
                self.running = false;
                self.refresh_auxv();
            }
            _ => self.running = true,
        }
        Ok(state)
    }
    /// Drop every breakpoint the RSP client set (the target must be stopped).
    /// The panel's own stay registered.
    pub(super) fn clear_client_breakpoints(&mut self) {
        let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
        for address in addresses {
            if let Some(wanted) = self.breakpoints.get_mut(&address) {
                wanted.client = 0;
                if wanted.none() {
                    let _ = self.backend.clear_breakpoint(address, 1);
                    self.breakpoints.remove(&address);
                }
            }
        }
        let keys: Vec<_> = self.hardware.keys().copied().collect();
        for key in keys {
            if let Some(wanted) = self.hardware.get_mut(&key) {
                wanted.client = 0;
                if wanted.none() {
                    let _ = self.backend.remove_breakpoint(key.0, key.1, key.2);
                    self.hardware.remove(&key);
                }
            }
        }
    }
    /// The panel's interest in a hardware breakpoint or watchpoint, like
    /// `panel_breakpoint`. A watch region the debug registers cannot take as one
    /// is split into aligned pieces, all held or none.
    pub(super) fn panel_hardware(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u64,
        on: bool,
    ) -> Result<(), DebugError> {
        let pieces = hardware_pieces(kind, addr, len);
        if !on {
            for (start, size) in pieces {
                if let Some(wanted) = self.hardware.get_mut(&(kind, start, size)) {
                    wanted.panel = false;
                    if wanted.none() {
                        self.backend.remove_breakpoint(kind, start, size)?;
                        self.hardware.remove(&(kind, start, size));
                    }
                }
            }
            return Ok(());
        }
        let mut added = Vec::new();
        for (start, size) in &pieces {
            let key = (kind, *start, *size);
            if let Some(wanted) = self.hardware.get_mut(&key) {
                if !wanted.panel {
                    wanted.panel = true;
                    added.push((key, false));
                }
                continue;
            }
            if let Err(error) = self.backend.insert_breakpoint(kind, *start, *size) {
                self.undo_panel_hardware(&added);
                return Err(error);
            }
            self.hardware.insert(
                key,
                Wanted {
                    client: 0,
                    panel: true,
                },
            );
            added.push((key, true));
        }
        Ok(())
    }
    fn undo_panel_hardware(&mut self, added: &[((BreakpointKind, u64, u32), bool)]) {
        for (key, fresh) in added {
            if let Some(wanted) = self.hardware.get_mut(key) {
                wanted.panel = false;
                if *fresh && wanted.none() {
                    let _ = self.backend.remove_breakpoint(key.0, key.1, key.2);
                    self.hardware.remove(key);
                }
            }
        }
    }
    /// Register (or release) the panel's interest in a breakpoint at `addr`;
    /// the guest is asked only when nobody else already holds the address.
    /// The target must be stopped.
    pub(super) fn panel_breakpoint(&mut self, addr: u64, on: bool) -> Result<(), DebugError> {
        if on {
            if self
                .breakpoints
                .get(&addr)
                .is_some_and(|wanted| wanted.panel)
            {
                return Ok(());
            }
            if !self.breakpoints.contains_key(&addr) {
                self.backend.set_breakpoint(addr, 1)?;
            }
            self.breakpoints.entry(addr).or_default().panel = true;
            return Ok(());
        }
        let Some(wanted) = self.breakpoints.get_mut(&addr) else {
            return Ok(());
        };
        if !wanted.panel {
            return Ok(());
        }
        wanted.panel = false;
        if wanted.none() {
            self.backend.clear_breakpoint(addr, 1)?;
            self.breakpoints.remove(&addr);
        }
        Ok(())
    }
    pub(super) fn resume_plain(&mut self) -> Result<(), DebugError> {
        self.registers = None;
        self.running = true;
        self.backend.resume(ResumeAction::Continue)
    }
    /// The panel resumed the process (it is running, its registers are stale).
    pub(super) fn note_resumed(&mut self) {
        self.registers = None;
        self.running = true;
    }
    /// The panel saw the process stop.
    pub(super) fn note_stopped(&mut self) {
        self.registers = None;
        self.running = false;
    }
    pub(super) fn interrupt(&mut self) -> Result<(), DebugError> {
        self.backend.interrupt()
    }

    /// Read the auxiliary vector once per process (it is fixed at exec).
    fn refresh_auxv(&mut self) {
        if self.auxv.is_none() && self.backend.caps().auxv {
            self.auxv = self.backend.auxv().ok();
        }
    }

    /// The next stop of a running target, if it has happened.
    pub(super) fn poll(&mut self) -> Result<Option<MultiThreadStopReason<u64>>, DebugError> {
        let state = self.backend.state()?;
        Ok(match state {
            TargetState::Running | TargetState::Transition => None,
            TargetState::Stopped(event) => {
                self.last_sequence = Some(event.sequence);
                self.stop = Some(event);
                self.running = false;
                self.registers = None;
                self.refresh_auxv();
                let tid = NonZeroUsize::new(event.tid as usize);
                Some(match (event.kind, tid) {
                    (StopKind::Breakpoint { .. }, Some(tid)) => MultiThreadStopReason::SwBreak(tid),
                    (StopKind::Step | StopKind::Entry, Some(tid)) => {
                        MultiThreadStopReason::SignalWithThread {
                            tid,
                            signal: Signal::SIGTRAP,
                        }
                    }
                    (StopKind::HardwareBreakpoint { .. }, Some(tid)) => {
                        MultiThreadStopReason::HwBreak(tid)
                    }
                    (StopKind::Watchpoint { addr, access }, Some(tid)) => {
                        MultiThreadStopReason::Watch {
                            tid,
                            kind: if access == WatchAccess::Write {
                                WatchKind::Write
                            } else {
                                WatchKind::ReadWrite
                            },
                            addr,
                        }
                    }
                    (StopKind::Signal { signal }, Some(tid)) => {
                        MultiThreadStopReason::SignalWithThread {
                            tid,
                            signal: gdb_signal(signal),
                        }
                    }
                    (_, Some(tid)) => MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGINT,
                    },
                    (_, None) => MultiThreadStopReason::Signal(Signal::SIGINT),
                })
            }
            TargetState::Exited { wait_status } => {
                self.running = false;
                if wait_status & 0x7f == 0 {
                    Some(MultiThreadStopReason::Exited(
                        ((wait_status >> 8) & 0xff) as u8,
                    ))
                } else {
                    Some(MultiThreadStopReason::Terminated(gdb_signal(
                        wait_status & 0x7f,
                    )))
                }
            }
            TargetState::Replaced => {
                self.running = false;
                self.auxv = None;
                Some(MultiThreadStopReason::Exited(0))
            }
        })
    }
    /// The signal a client passes on a resume: GDB's number becomes Linux's; one
    /// the guest has no name for is not passed.
    fn note_signal(&mut self, tid: Tid, signal: Option<Signal>) {
        if let Some(linux) = signal.and_then(|signal| gdb_to_linux(signal.0)) {
            self.actions.signal = Some((tid_of(tid), linux));
        }
    }
    fn load(&mut self, tid: u32) -> Result<&RegisterFile, DebugError> {
        if self
            .registers
            .as_ref()
            .is_none_or(|(cached, _)| *cached != tid)
        {
            let mut file = RegisterFile::new();
            for blob in self.backend.read_regsets(tid, &self.description.regsets)? {
                file.insert(blob);
            }
            self.registers = Some((tid, file));
        }
        Ok(&self
            .registers
            .as_ref()
            .expect("registers were just loaded")
            .1)
    }
}

impl Target for RspTarget {
    type Arch = Amd64;
    type Error = DebugError;
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
    fn support_auxv(&mut self) -> Option<AuxvOps<'_, Self>> {
        self.backend.caps().auxv.then_some(self)
    }
}

impl Auxv for RspTarget {
    /// gdb relocates a position independent program from AT_PHDR and AT_ENTRY.
    /// The vector is read at the stop (the request itself cannot ask the guest).
    fn get_auxv(&self, offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let Some(data) = self.auxv.as_deref() else {
            return Ok(0);
        };
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let count = length.min(buf.len()).min(data.len() - start);
        buf[..count].copy_from_slice(&data[start..start + count]);
        Ok(count)
    }
}

impl MultiThreadBase for RspTarget {
    fn read_registers(
        &mut self,
        regs: &mut super::amd64::Amd64Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let description = self.description;
        let file = self.load(tid_of(tid)).map_err(report)?;
        regs.image = description.serialize(file);
        Ok(())
    }
    fn write_registers(
        &mut self,
        regs: &super::amd64::Amd64Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let tid = tid_of(tid);
        let description = self.description;
        let mut file = self.load(tid).map_err(report)?.clone();
        let changed = description
            .deserialize(&regs.image, &mut file)
            .map_err(|_| TargetError::Errno(22))?;
        for nt_type in changed {
            let data = file.get(nt_type).expect("changed set exists").to_vec();
            self.backend
                .write_regset(tid, &super::target::RegsetBlob { nt_type, data })
                .map_err(report)?;
        }
        self.registers = None;
        Ok(())
    }
    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        let bytes = self
            .backend
            .read_memory(start_addr, data.len())
            .map_err(report)?;
        data[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        self.backend
            .write_memory(start_addr, data)
            .map_err(report)?;
        self.registers = None;
        Ok(())
    }
    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), DebugError> {
        for thread in self.backend.threads()? {
            if let Some(tid) = NonZeroUsize::new(thread.tid as usize) {
                thread_is_active(tid);
            }
        }
        Ok(())
    }
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadResume for RspTarget {
    fn resume(&mut self) -> Result<(), DebugError> {
        self.registers = None;
        self.running = true;
        let signal = self
            .actions
            .signal
            .take()
            .filter(|_| self.backend.caps().signals);
        let action = match (self.actions.step.take(), signal) {
            (Some(tid), Some((signal_tid, signal))) if signal_tid == tid => {
                ResumeAction::StepSignal { tid, signal }
            }
            (Some(tid), _) => ResumeAction::Step { tid },
            (None, Some((tid, signal))) => ResumeAction::ContinueSignal { tid, signal },
            (None, None) => ResumeAction::Continue,
        };
        self.backend.resume(action)
    }
    fn clear_resume_actions(&mut self) -> Result<(), DebugError> {
        self.actions = Actions::default();
        Ok(())
    }
    // Every thread resumes together; the signal a client passes goes to the
    // thread it names (the one that stopped on it).
    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), DebugError> {
        self.note_signal(tid, signal);
        Ok(())
    }
    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        self.backend.caps().hardware_single_step.then_some(self)
    }
    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}
impl MultiThreadSingleStep for RspTarget {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), DebugError> {
        self.actions.step = Some(tid_of(tid));
        self.note_signal(tid, signal);
        Ok(())
    }
}
impl MultiThreadSchedulerLocking for RspTarget {
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), DebugError> {
        // Only the stepped thread runs: that is what the engine does for a step.
        Ok(())
    }
}

impl Breakpoints for RspTarget {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        self.backend.caps().software_breakpoints.then_some(self)
    }
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        (self.backend.caps().hardware_breakpoints > 0).then_some(self)
    }
    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        (self.backend.caps().hardware_watchpoints > 0).then_some(self)
    }
}

/// A watched region as the aligned pieces of 1, 2, 4 or 8 bytes the debug
/// registers take, largest first at each step; an instruction breakpoint is one
/// piece of one byte.
fn watch_pieces(mut addr: u64, mut len: u64) -> Vec<(u64, u32)> {
    let mut pieces = Vec::new();
    while len > 0 {
        let size = [8u64, 4, 2, 1]
            .into_iter()
            .find(|size| *size <= len && addr.is_multiple_of(*size))
            .unwrap_or(1);
        pieces.push((addr, size as u32));
        addr += size;
        len -= size;
    }
    pieces
}
fn hardware_pieces(kind: BreakpointKind, addr: u64, len: u64) -> Vec<(u64, u32)> {
    match kind {
        BreakpointKind::Software | BreakpointKind::Hardware => vec![(addr, 1)],
        BreakpointKind::Watch(_) => watch_pieces(addr, len.min(4096)),
    }
}

impl RspTarget {
    /// One logical request in the debug registers; asked twice, held once.
    fn hardware_add(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if let Some(wanted) = self.hardware.get_mut(&(kind, addr, len)) {
            wanted.client += 1;
            return Ok(());
        }
        self.backend.insert_breakpoint(kind, addr, len)?;
        self.hardware.insert(
            (kind, addr, len),
            Wanted {
                client: 1,
                panel: false,
            },
        );
        Ok(())
    }
    fn hardware_remove(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<bool, DebugError> {
        let Some(wanted) = self.hardware.get_mut(&(kind, addr, len)) else {
            return Ok(false);
        };
        if wanted.client == 0 {
            return Ok(false);
        }
        wanted.client -= 1;
        if wanted.none() {
            self.backend.remove_breakpoint(kind, addr, len)?;
            self.hardware.remove(&(kind, addr, len));
        }
        Ok(true)
    }
}
impl HwBreakpoint for RspTarget {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: BreakpointLen) -> TargetResult<bool, Self> {
        self.hardware_add(BreakpointKind::Hardware, addr, 1)
            .map_err(report)?;
        Ok(true)
    }
    fn remove_hw_breakpoint(
        &mut self,
        addr: u64,
        _kind: BreakpointLen,
    ) -> TargetResult<bool, Self> {
        self.hardware_remove(BreakpointKind::Hardware, addr, 1)
            .map_err(report)
    }
}
impl HwWatchpoint for RspTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let kind = match kind {
            WatchKind::Write => BreakpointKind::Watch(WatchAccess::Write),
            WatchKind::ReadWrite => BreakpointKind::Watch(WatchAccess::Access),
            // The debug registers cannot watch for reads alone.
            WatchKind::Read => return Ok(false),
        };
        if len == 0 || len > 4096 {
            return Err(TargetError::Errno(22));
        }
        let pieces = watch_pieces(addr, len);
        for (done, (start, size)) in pieces.iter().enumerate() {
            if let Err(error) = self.hardware_add(kind, *start, *size) {
                for (start, size) in &pieces[..done] {
                    let _ = self.hardware_remove(kind, *start, *size);
                }
                return Err(report(error));
            }
        }
        Ok(true)
    }
    fn remove_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let kind = match kind {
            WatchKind::Write => BreakpointKind::Watch(WatchAccess::Write),
            WatchKind::ReadWrite => BreakpointKind::Watch(WatchAccess::Access),
            WatchKind::Read => return Ok(false),
        };
        let mut found = false;
        for (start, size) in watch_pieces(addr, len) {
            found |= self.hardware_remove(kind, start, size).map_err(report)?;
        }
        Ok(found)
    }
}
impl SwBreakpoint for RspTarget {
    fn add_sw_breakpoint(&mut self, addr: u64, kind: BreakpointLen) -> TargetResult<bool, Self> {
        let len = u32::try_from(kind.0).map_err(|_| TargetError::Errno(22))?;
        if let Some(wanted) = self.breakpoints.get_mut(&addr) {
            wanted.client += 1;
            return Ok(true);
        }
        self.backend.set_breakpoint(addr, len).map_err(report)?;
        self.breakpoints.insert(
            addr,
            Wanted {
                client: 1,
                panel: false,
            },
        );
        Ok(true)
    }
    fn remove_sw_breakpoint(&mut self, addr: u64, kind: BreakpointLen) -> TargetResult<bool, Self> {
        let len = u32::try_from(kind.0).map_err(|_| TargetError::Errno(22))?;
        let Some(wanted) = self.breakpoints.get_mut(&addr) else {
            return Ok(false);
        };
        if wanted.client == 0 {
            return Ok(false);
        }
        wanted.client -= 1;
        if wanted.none() {
            self.backend.clear_breakpoint(addr, len).map_err(report)?;
            self.breakpoints.remove(&addr);
        }
        Ok(true)
    }
}
