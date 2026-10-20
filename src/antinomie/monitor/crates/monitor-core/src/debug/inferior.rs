// SPDX-License-Identifier: MIT
//! One debugged process of the guest: its backend (a guest session), the
//! breakpoints the debuggers asked for, a cache of the registers read at the
//! current stop, and where it stands (running, stopped at an event, gone).
//! A debugger session is a set of these (`debugger.rs`).
//!
//! Breakpoints are reference-counted here (a debugger may ask for the same
//! address twice) and shared with the in-app panel: an address stays registered
//! while either wants it. A vfork child shares its parent's registry, as it shares
//! its memory.
use super::{
    regs::{RegisterFile, TargetDescription},
    target::{DebugBackend, DebugError, RegsetBlob, StopEvent, ThreadInfo},
    view::BreakpointKind,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

/// Who wants a breakpoint at one address: the RSP client (counted, it may ask
/// twice) and the in-app panel (once).
#[derive(Default)]
pub(super) struct Wanted {
    pub client: u32,
    pub panel: bool,
}
impl Wanted {
    fn none(&self) -> bool {
        self.client == 0 && !self.panel
    }
}

type HardwareKey = (BreakpointKind, u64, u32);

#[derive(Default)]
pub(super) struct Registry {
    breakpoints: BTreeMap<u64, Wanted>,
    /// Hardware breakpoints and watchpoints held, by the debug-register request
    /// they became, with who wants each.
    hardware: BTreeMap<HardwareKey, Wanted>,
}

/// A watched region as the aligned pieces of 1, 2, 4 or 8 bytes the debug
/// registers take, largest first at each step.
pub(super) fn watch_pieces(mut addr: u64, mut len: u64) -> Vec<(u64, u32)> {
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
pub(super) fn hardware_pieces(kind: BreakpointKind, addr: u64, len: u64) -> Vec<(u64, u32)> {
    match kind {
        BreakpointKind::Software | BreakpointKind::Hardware => vec![(addr, 1)],
        BreakpointKind::Watch(_) => watch_pieces(addr, len.min(4096)),
    }
}

impl Registry {
    // ---- the RSP client ------------------------------------------------------

    pub(super) fn client_add_sw(
        &mut self,
        backend: &mut dyn DebugBackend,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if let Some(wanted) = self.breakpoints.get_mut(&addr) {
            wanted.client += 1;
            return Ok(());
        }
        backend.set_breakpoint(addr, len)?;
        self.breakpoints.insert(
            addr,
            Wanted {
                client: 1,
                panel: false,
            },
        );
        Ok(())
    }
    pub(super) fn client_remove_sw(
        &mut self,
        backend: &mut dyn DebugBackend,
        addr: u64,
        len: u32,
    ) -> Result<bool, DebugError> {
        let Some(wanted) = self.breakpoints.get_mut(&addr) else {
            return Ok(false);
        };
        if wanted.client == 0 {
            return Ok(false);
        }
        wanted.client -= 1;
        if wanted.none() {
            backend.clear_breakpoint(addr, len)?;
            self.breakpoints.remove(&addr);
        }
        Ok(true)
    }
    /// One logical request in the debug registers; asked twice, held once.
    pub(super) fn client_add_hw(
        &mut self,
        backend: &mut dyn DebugBackend,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if let Some(wanted) = self.hardware.get_mut(&(kind, addr, len)) {
            wanted.client += 1;
            return Ok(());
        }
        backend.insert_breakpoint(kind, addr, len)?;
        self.hardware.insert(
            (kind, addr, len),
            Wanted {
                client: 1,
                panel: false,
            },
        );
        Ok(())
    }
    pub(super) fn client_remove_hw(
        &mut self,
        backend: &mut dyn DebugBackend,
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
            backend.remove_breakpoint(kind, addr, len)?;
            self.hardware.remove(&(kind, addr, len));
        }
        Ok(true)
    }
    /// Drop every breakpoint the RSP client set (the target must be stopped, or
    /// non-stop). The panel's own stay registered.
    pub(super) fn clear_client(&mut self, backend: &mut dyn DebugBackend) {
        let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
        for address in addresses {
            if let Some(wanted) = self.breakpoints.get_mut(&address) {
                wanted.client = 0;
                if wanted.none() {
                    let _ = backend.clear_breakpoint(address, 1);
                    self.breakpoints.remove(&address);
                }
            }
        }
        let keys: Vec<HardwareKey> = self.hardware.keys().copied().collect();
        for key in keys {
            if let Some(wanted) = self.hardware.get_mut(&key) {
                wanted.client = 0;
                if wanted.none() {
                    let _ = backend.remove_breakpoint(key.0, key.1, key.2);
                    self.hardware.remove(&key);
                }
            }
        }
    }

    // ---- the panel -----------------------------------------------------------

    /// Register (or release) the panel's interest in a breakpoint at `addr`;
    /// the guest is asked only when nobody else already holds the address.
    pub(super) fn panel_breakpoint(
        &mut self,
        backend: &mut dyn DebugBackend,
        addr: u64,
        on: bool,
    ) -> Result<(), DebugError> {
        if on {
            if self
                .breakpoints
                .get(&addr)
                .is_some_and(|wanted| wanted.panel)
            {
                return Ok(());
            }
            if !self.breakpoints.contains_key(&addr) {
                backend.set_breakpoint(addr, 1)?;
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
            backend.clear_breakpoint(addr, 1)?;
            self.breakpoints.remove(&addr);
        }
        Ok(())
    }
    /// The panel's interest in a hardware breakpoint or watchpoint. A watch
    /// region the debug registers cannot take as one is split into aligned
    /// pieces, all held or none.
    pub(super) fn panel_hardware(
        &mut self,
        backend: &mut dyn DebugBackend,
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
                        backend.remove_breakpoint(kind, start, size)?;
                        self.hardware.remove(&(kind, start, size));
                    }
                }
            }
            return Ok(());
        }
        let mut added: Vec<(HardwareKey, bool)> = Vec::new();
        for (start, size) in &pieces {
            let key = (kind, *start, *size);
            if let Some(wanted) = self.hardware.get_mut(&key) {
                if !wanted.panel {
                    wanted.panel = true;
                    added.push((key, false));
                }
                continue;
            }
            if let Err(error) = backend.insert_breakpoint(kind, *start, *size) {
                for (key, fresh) in &added {
                    if let Some(wanted) = self.hardware.get_mut(key) {
                        wanted.panel = false;
                        if *fresh && wanted.none() {
                            let _ = backend.remove_breakpoint(key.0, key.1, key.2);
                            self.hardware.remove(key);
                        }
                    }
                }
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

    // ---- guest state changes ---------------------------------------------------

    /// The guest dropped everything (the program executed a new image).
    pub(super) fn forget(&mut self) {
        self.breakpoints.clear();
        self.hardware.clear();
    }
    /// What this side believes the guest holds.
    fn believed(&self) -> (Vec<u64>, Vec<HardwareKey>) {
        (
            self.breakpoints.keys().copied().collect(),
            self.hardware.keys().copied().collect(),
        )
    }
    /// After the guest's state may have moved under us (a restored snapshot, a
    /// reconnect that lost a reply): make the guest hold what is registered, and
    /// nothing else. Needs the group stopped (or non-stop). Returns what it had to
    /// fix, for the log.
    pub(super) fn reconcile(
        &mut self,
        backend: &mut dyn DebugBackend,
    ) -> Result<String, DebugError> {
        let held = backend.guest_breakpoints()?;
        let (software, hardware) = self.believed();
        let mut notes = Vec::new();
        for addr in &software {
            if !held
                .iter()
                .any(|b| b.kind == BreakpointKind::Software && b.addr == *addr)
            {
                backend.set_breakpoint(*addr, 1)?;
                notes.push(format!("software breakpoint {addr:#x} set again"));
            }
        }
        for (kind, addr, len) in &hardware {
            if !held
                .iter()
                .any(|b| b.kind == *kind && b.addr == *addr && b.len == *len)
            {
                backend.insert_breakpoint(*kind, *addr, *len)?;
                notes.push(format!("{} {addr:#x} set again", kind.label()));
            }
        }
        for stranger in &held {
            let known = match stranger.kind {
                BreakpointKind::Software => software.contains(&stranger.addr),
                kind => hardware.contains(&(kind, stranger.addr, stranger.len)),
            };
            if !known {
                backend.remove_breakpoint(stranger.kind, stranger.addr, stranger.len)?;
                notes.push(format!(
                    "{} {:#x} removed (not ours)",
                    stranger.kind.label(),
                    stranger.addr
                ));
            }
        }
        Ok(notes.join("; "))
    }
    /// Adopt the breakpoints the guest holds as the panel's (a debugger that
    /// found a session it did not make).
    pub(super) fn adopt_guest(&mut self, held: &[super::target::GuestBreakpoint]) {
        for breakpoint in held {
            match breakpoint.kind {
                BreakpointKind::Software => {
                    self.breakpoints.entry(breakpoint.addr).or_default().panel = true;
                }
                kind => {
                    self.hardware
                        .entry((kind, breakpoint.addr, breakpoint.len))
                        .or_default()
                        .panel = true;
                }
            }
        }
    }
    /// The panel's own software breakpoints and watch pieces, to put on a
    /// program that continues in another process.
    pub(super) fn panel_items(&self) -> Vec<(BreakpointKind, u64, u32)> {
        let mut items: Vec<_> = self
            .breakpoints
            .iter()
            .filter(|(_, wanted)| wanted.panel)
            .map(|(addr, _)| (BreakpointKind::Software, *addr, 1))
            .collect();
        items.extend(
            self.hardware
                .iter()
                .filter(|(_, wanted)| wanted.panel)
                .map(|((kind, addr, len), _)| (*kind, *addr, *len)),
        );
        items
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RunState {
    /// Running, or in a transition the guest has not finished.
    Running,
    /// All-stop: the group is stopped at this event. In non-stop the state of
    /// each thread comes from the thread list.
    Stopped(StopEvent),
    /// The process ended; the value is its wait status.
    Exited(u32),
}

pub(super) struct Inferior {
    pub pid: u32,
    pub backend: Box<dyn DebugBackend>,
    /// The process that forked it, when it came from a fork.
    pub parent: Option<u32>,
    /// A vfork child, sharing its parent's memory until it execs.
    pub shared_memory: bool,
    pub registry: Rc<RefCell<Registry>>,
    registers: Option<(u32, RegisterFile)>,
    pub auxv: Option<Vec<u8>>,
    pub run: RunState,
    /// The current stop has not been reported to a debugger yet.
    pub unreported: bool,
    pub last_sequence: Option<u32>,
    pub nonstop: bool,
    /// Non-stop: events up to this sequence number are acknowledged.
    pub acknowledged: u32,
    /// Non-stop: the newest event handed to a controller.
    pub reported_sequence: u32,
    /// The thread of the last stop, the default thread for requests.
    pub current_tid: u32,
    pub exec_path: Option<String>,
    description: &'static TargetDescription,
}

impl Inferior {
    pub(super) fn new(
        pid: u32,
        backend: Box<dyn DebugBackend>,
        parent: Option<u32>,
        shared_memory: bool,
        registry: Rc<RefCell<Registry>>,
    ) -> Self {
        let description = backend.caps().arch.description();
        Self {
            pid,
            backend,
            parent,
            shared_memory,
            registry,
            registers: None,
            auxv: None,
            run: RunState::Running,
            unreported: false,
            last_sequence: None,
            nonstop: false,
            acknowledged: 0,
            reported_sequence: 0,
            current_tid: pid,
            exec_path: None,
            description,
        }
    }
    pub(super) fn description(&self) -> &'static TargetDescription {
        self.description
    }
    pub(super) fn is_running(&self) -> bool {
        matches!(self.run, RunState::Running)
    }
    pub(super) fn is_stopped(&self) -> bool {
        matches!(self.run, RunState::Stopped(_))
    }
    pub(super) fn is_live(&self) -> bool {
        matches!(self.run, RunState::Running | RunState::Stopped(_))
    }
    pub(super) fn invalidate(&mut self) {
        self.registers = None;
    }
    /// The process was resumed (its registers are stale).
    pub(super) fn note_resumed(&mut self) {
        self.registers = None;
        self.run = RunState::Running;
        self.unreported = false;
    }
    pub(super) fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        self.backend.threads()
    }
    /// The registers of one thread, read once per stop.
    pub(super) fn load(&mut self, tid: u32) -> Result<&RegisterFile, DebugError> {
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
    /// The `g` image of one thread.
    pub(super) fn register_image(&mut self, tid: u32) -> Result<Vec<u8>, DebugError> {
        let description = self.description;
        let file = self.load(tid)?;
        Ok(description.serialize(file))
    }
    /// Apply a `G` image: only the register sets that changed are written back.
    pub(super) fn write_register_image(
        &mut self,
        tid: u32,
        image: &[u8],
    ) -> Result<(), DebugError> {
        let description = self.description;
        let mut file = self.load(tid)?.clone();
        let changed = description
            .deserialize(image, &mut file)
            .map_err(DebugError::Invalid)?;
        for nt_type in changed {
            let data = file.get(nt_type).expect("changed set exists").to_vec();
            self.backend
                .write_regset(tid, &RegsetBlob { nt_type, data })?;
        }
        self.registers = None;
        Ok(())
    }
    /// Read the auxiliary vector once per image (it is fixed at exec).
    pub(super) fn refresh_auxv(&mut self) {
        if self.auxv.is_none() && self.backend.caps().auxv {
            self.auxv = self.backend.auxv().ok();
        }
    }
    /// The guest dropped the breakpoints, debug registers and the vector of the
    /// old image: so do we.
    pub(super) fn image_replaced(&mut self) {
        self.auxv = None;
        self.registers = None;
        let path = self.backend.exec_path();
        self.exec_path = path;
        if !self.shared_memory || self.parent.is_none() {
            self.registry.borrow_mut().forget();
        } else {
            // A vfork child leaves its parent's memory: its own table, empty.
            self.registry = Rc::new(RefCell::new(Registry::default()));
            self.shared_memory = false;
        }
    }
    /// Run `f` on the registry with this inferior's backend.
    pub(super) fn with_registry<R>(
        &mut self,
        f: impl FnOnce(&mut Registry, &mut dyn DebugBackend) -> R,
    ) -> R {
        let registry = self.registry.clone();
        let mut registry = registry.borrow_mut();
        f(&mut registry, self.backend.as_mut())
    }
}
