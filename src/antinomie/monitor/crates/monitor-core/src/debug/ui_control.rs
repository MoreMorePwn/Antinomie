// SPDX-License-Identifier: MIT
//! The in-app debugger's controller. It runs on the RSP server thread and uses
//! the same `RspTarget` (so the same backend, guest link and breakpoint table)
//! an external debugger does; the panel never connects to our own socket.
//!
//! One controller at a time. While no RSP client is connected the panel drives
//! the process. When a client connects it takes control: the process is stopped
//! (as the client expects), queued panel requests are dropped, and the panel's
//! view turns read-only ("controlled by gdb") until the client leaves, after
//! which the client's usual detach leaves the process running and the panel
//! reads the state again. The panel's breakpoints stay registered across a
//! client's session; the client's own are removed when it leaves.
//!
//! Guest requests cost about 22 ms each, so the controller fetches only when the
//! process stops or the user asks, in bounded ranges, and publishes the view
//! after each step of the fetch so the panel fills in progressively. Every
//! request names the stop it was made against; one that no longer matches is
//! dropped and reported through `DebugView::handled`.
use super::{
    regs::{RegKind, RegisterFile},
    rsp_target::RspTarget,
    target::{DebugCaps, DebugError, ResumeAction, StopEvent, TargetState},
    view::{
        BreakpointKind, BreakpointList, CODE_AFTER_SIZE, CODE_BEFORE_SIZE, Controller, DebugAction,
        DebugRequest, DebugThread, DebugView, MAX_READ_SIZE, MemoryWindow, Pending, RegisterEntry,
        RegisterSnapshot, RunState, STACK_WINDOW_SIZE, StopReason, ViewCaps, WindowKind,
    },
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Requests the panel may have queued at once; further ones are refused.
const QUEUE_LIMIT: usize = 32;
/// How often a freely running process is checked for a stop.
const RUNNING_POLL: Duration = Duration::from_millis(100);
/// How often a process that was asked to stop or step is checked.
const MOVING_POLL: Duration = Duration::from_millis(10);
/// How long a stop or a step may take before the panel says it is slow.
const MOVE_DEADLINE: Duration = Duration::from_secs(5);

/// The state shared between the panel (through the app's worker) and the
/// controller on the server thread.
pub(super) struct PanelShared {
    requests: Mutex<VecDeque<DebugRequest>>,
    view: Mutex<Arc<DebugView>>,
    epoch: AtomicU64,
    /// An RSP client holds the process.
    client: AtomicBool,
}

/// The panel's handle to the controller: submit requests, read the view.
#[derive(Clone)]
pub struct PanelHandle(Arc<PanelShared>);
impl PanelHandle {
    /// Queue a request. Refused while an external debugger controls the
    /// process, or when too many requests are waiting.
    pub fn submit(&self, request: DebugRequest) -> Result<(), String> {
        if self.0.client.load(Ordering::Acquire) {
            return Err(
                "An external debugger controls the process; the panel is read-only until it disconnects."
                    .into(),
            );
        }
        let mut queue = self.0.requests.lock().map_err(|_| "debugger busy")?;
        if queue.len() >= QUEUE_LIMIT {
            return Err("The debugger is busy; try again in a moment.".into());
        }
        queue.push_back(request);
        Ok(())
    }
    /// The latest view.
    pub fn view(&self) -> Arc<DebugView> {
        self.0
            .view
            .lock()
            .map(|view| view.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }
    /// Increases whenever the view changes: a cheap way to notice.
    pub fn epoch(&self) -> u64 {
        self.0.epoch.load(Ordering::Acquire)
    }
    /// Whether an external debugger controls the process.
    pub fn client_connected(&self) -> bool {
        self.0.client.load(Ordering::Acquire)
    }
}

/// What a pump of the controller found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Pump {
    Idle,
    /// The process is gone (exited or replaced) or the session ended: the
    /// server has nothing more to serve.
    Ended(String),
}

enum Phase {
    /// The state of the process is not known yet (just attached, or an
    /// external debugger has just left).
    Unsynced,
    Stopped,
    Moving {
        pending: Pending,
        deadline: Option<Instant>,
        next_poll: Instant,
        /// The stop the move started from: a state report of it is not news.
        from: Option<u32>,
    },
    Over,
}

pub(super) struct PanelControl {
    shared: Arc<PanelShared>,
    view: DebugView,
    caps: DebugCaps,
    phase: Phase,
    list: BreakpointList,
    /// The user's memory range, read again at every stop.
    memory: Option<(u64, usize)>,
    /// Latest stop sequence seen, to ignore a repeated report of it.
    last_stop: Option<u32>,
    running_poll: Duration,
    moving_poll: Duration,
    move_deadline: Duration,
}

impl PanelControl {
    pub(super) fn new(caps: &DebugCaps) -> (Self, PanelHandle) {
        let view_caps = ViewCaps {
            software_breakpoints: caps.software_breakpoints,
            single_step: caps.hardware_single_step,
            hardware_breakpoints: caps.hardware_breakpoints,
            hardware_watchpoints: caps.hardware_watchpoints,
        };
        let view = DebugView::new(view_caps);
        let shared = Arc::new(PanelShared {
            requests: Mutex::new(VecDeque::new()),
            view: Mutex::new(Arc::new(view.clone())),
            epoch: AtomicU64::new(0),
            client: AtomicBool::new(false),
        });
        let control = Self {
            shared: shared.clone(),
            view,
            caps: caps.clone(),
            phase: Phase::Unsynced,
            list: BreakpointList::default(),
            memory: None,
            last_stop: None,
            running_poll: RUNNING_POLL,
            moving_poll: MOVING_POLL,
            move_deadline: MOVE_DEADLINE,
        };
        (control, PanelHandle(shared))
    }

    #[cfg(test)]
    pub(super) fn timing(&mut self, running: Duration, moving: Duration, deadline: Duration) {
        self.running_poll = running;
        self.moving_poll = moving;
        self.move_deadline = deadline;
    }

    fn publish(&mut self) {
        self.view.epoch += 1;
        self.view.breakpoints = self.list.entries().to_vec();
        if let Ok(mut slot) = self.shared.view.lock() {
            *slot = Arc::new(self.view.clone());
        }
        self.shared.epoch.store(self.view.epoch, Ordering::Release);
    }

    /// An RSP client has connected and takes control.
    pub(super) fn client_arrived(&mut self) {
        self.shared.client.store(true, Ordering::Release);
        self.drop_queued();
        self.view.controller = Controller::Gdb;
        self.view.run = RunState::Unknown;
        self.view.loading = false;
        self.clear_stop_data();
        self.phase = Phase::Unsynced;
        self.publish();
    }

    /// The RSP client has left; the panel takes control again and reads the
    /// state afresh on the next pump.
    pub(super) fn client_left(&mut self) {
        self.shared.client.store(false, Ordering::Release);
        self.view.controller = Controller::App;
        self.phase = Phase::Unsynced;
        self.publish();
    }

    /// Drop every queued request, as handled (and unapplied).
    fn drop_queued(&mut self) {
        if let Ok(mut queue) = self.shared.requests.lock() {
            if let Some(last) = queue.iter().map(|request| request.id).max() {
                self.view.handled = self.view.handled.max(last);
            }
            queue.clear();
        }
    }

    fn clear_stop_data(&mut self) {
        self.view.threads.clear();
        self.view.registers = None;
        self.view.code = None;
        self.view.stack = None;
        self.view.memory = None;
    }

    /// Do whatever is due: read the state once after attach or after a client,
    /// handle queued requests, and follow a moving process.
    pub(super) fn pump(&mut self, target: &mut RspTarget) -> Pump {
        if self.shared.client.load(Ordering::Acquire) || matches!(self.phase, Phase::Over) {
            return Pump::Idle;
        }
        let ended = self.pump_inner(target);
        match ended {
            Ok(()) => Pump::Idle,
            Err(why) => {
                self.phase = Phase::Over;
                self.publish();
                Pump::Ended(why)
            }
        }
    }

    fn pump_inner(&mut self, target: &mut RspTarget) -> Result<(), String> {
        if matches!(self.phase, Phase::Unsynced) {
            self.resync(target)?;
        }
        for _ in 0..QUEUE_LIMIT {
            let request = self
                .shared
                .requests
                .lock()
                .ok()
                .and_then(|mut queue| queue.pop_front());
            let Some(request) = request else { break };
            self.handle(target, request)?;
            if self.shared.client.load(Ordering::Acquire) {
                break;
            }
        }
        self.follow(target)
    }

    /// Learn what the process is doing without assuming it.
    fn resync(&mut self, target: &mut RspTarget) -> Result<(), String> {
        match target.backend().state() {
            Ok(TargetState::Stopped(event)) => {
                self.stopped(target, event)?;
            }
            Ok(TargetState::Running | TargetState::Transition) => {
                self.view.run = RunState::Running {
                    pending: Pending::Nothing,
                };
                self.phase = Phase::Moving {
                    pending: Pending::Nothing,
                    deadline: None,
                    next_poll: Instant::now() + self.running_poll,
                    from: self.last_stop,
                };
                self.publish();
            }
            Ok(TargetState::Exited { wait_status }) => return Err(self.exited(wait_status)),
            Ok(TargetState::Replaced) => return Err(self.replaced()),
            Err(error) => return self.fail(error),
        }
        Ok(())
    }

    fn exited(&mut self, wait_status: u32) -> String {
        self.view.run = RunState::Exited { wait_status };
        self.view.loading = false;
        self.clear_stop_data();
        if wait_status & 0x7f == 0 {
            format!(
                "the process exited with status {}",
                (wait_status >> 8) & 0xff
            )
        } else {
            format!("the process was killed by signal {}", wait_status & 0x7f)
        }
    }
    fn replaced(&mut self) -> String {
        self.view.run = RunState::Replaced;
        self.view.loading = false;
        self.clear_stop_data();
        "the process executed a new program".into()
    }

    /// An error from the engine: the session being gone ends the controller,
    /// anything else is shown as a notice.
    fn fail(&mut self, error: DebugError) -> Result<(), String> {
        if error == DebugError::Gone {
            self.view.run = RunState::Unknown;
            self.view.loading = false;
            return Err("the guest ended the debug session".into());
        }
        self.view.notice = Some(error.to_string());
        Ok(())
    }

    /// The process is stopped at `event`: show it and fetch its data.
    fn stopped(&mut self, target: &mut RspTarget, event: StopEvent) -> Result<(), String> {
        target.note_stopped();
        self.last_stop = Some(event.sequence);
        self.phase = Phase::Stopped;
        self.view.run = RunState::Stopped {
            reason: StopReason::from_kind(event.kind),
            tid: event.tid,
            pc: event.pc,
            sequence: event.sequence,
        };
        self.view.selected_tid = Some(event.tid);
        self.view.loading = true;
        self.clear_stop_data();
        self.publish();
        self.fetch(target, event.sequence, event.tid, true)
    }

    /// Fetch the stop's data, publishing after each part so the panel fills in
    /// as it arrives.
    fn fetch(
        &mut self,
        target: &mut RspTarget,
        sequence: u32,
        tid: u32,
        with_threads: bool,
    ) -> Result<(), String> {
        let result = self.fetch_parts(target, sequence, tid, with_threads);
        self.view.loading = false;
        self.publish();
        result
    }

    fn fetch_parts(
        &mut self,
        target: &mut RspTarget,
        sequence: u32,
        tid: u32,
        with_threads: bool,
    ) -> Result<(), String> {
        if with_threads {
            match target.backend().threads() {
                Ok(threads) => {
                    self.view.threads = threads
                        .into_iter()
                        .map(|thread| DebugThread {
                            tid: thread.tid,
                            stopped: thread.stopped,
                            pc: thread.pc,
                        })
                        .collect();
                    self.publish();
                }
                Err(error) => self.fail(error)?,
            }
        }
        let description = self.caps.arch.description();
        let mut file = RegisterFile::new();
        let mut registers = Ok(());
        if let Some(nt_type) = description.regsets.first() {
            match target.backend().read_regset(tid, *nt_type) {
                Ok(blob) => file.insert(blob),
                Err(error) => registers = Err(error),
            }
        }
        if let Err(error) = registers {
            self.view.registers = None;
            return self.fail(error);
        }
        let entries: Vec<RegisterEntry> = description
            .view(&file)
            .into_iter()
            .filter(|register| {
                matches!(
                    register.kind,
                    RegKind::General
                        | RegKind::CodePointer
                        | RegKind::DataPointer
                        | RegKind::Flags
                        | RegKind::Segment
                        | RegKind::System
                )
            })
            .map(|register| {
                let mut value = [0u8; 8];
                let len = register.bytes.len().min(8);
                value[..len].copy_from_slice(&register.bytes[..len]);
                RegisterEntry {
                    name: register.name,
                    value: u64::from_le_bytes(value),
                    kind: register.kind,
                }
            })
            .collect();
        let snapshot = RegisterSnapshot {
            tid,
            sequence,
            entries,
        };
        let pc = snapshot
            .entries
            .iter()
            .find(|entry| entry.kind == RegKind::CodePointer)
            .map(|entry| entry.value);
        let sp = snapshot.get("rsp");
        self.view.registers = Some(snapshot);
        self.publish();

        if let Some(pc) = pc {
            let window = self.read_code(target, sequence, pc)?;
            self.view.code = Some(window);
            self.publish();
        }
        if let Some(sp) = sp {
            let window =
                self.read_window(target, WindowKind::Stack, sequence, sp, STACK_WINDOW_SIZE)?;
            self.view.stack = Some(window);
            self.publish();
        }
        if let Some((addr, len)) = self.memory {
            let window = self.read_window(target, WindowKind::Memory, sequence, addr, len)?;
            self.view.memory = Some(window);
        }
        Ok(())
    }

    /// The bytes around `pc`: some before it for context, the rest after. When
    /// the part before is not mapped the window starts at `pc`.
    fn read_code(
        &mut self,
        target: &mut RspTarget,
        sequence: u32,
        pc: u64,
    ) -> Result<MemoryWindow, String> {
        let before = pc.min(CODE_BEFORE_SIZE as u64);
        if before > 0 {
            let window = self.read_window(
                target,
                WindowKind::Code,
                sequence,
                pc - before,
                before as usize + CODE_AFTER_SIZE,
            )?;
            if window.error.is_none() && window.bytes.len() > before as usize {
                return Ok(window);
            }
        }
        self.read_window(target, WindowKind::Code, sequence, pc, CODE_AFTER_SIZE)
    }

    fn read_window(
        &mut self,
        target: &mut RspTarget,
        kind: WindowKind,
        sequence: u32,
        address: u64,
        requested_size: usize,
    ) -> Result<MemoryWindow, String> {
        let (bytes, error) = match target.backend().read_memory(address, requested_size) {
            Ok(bytes) => (bytes, None),
            Err(DebugError::Fault) => (Vec::new(), Some("address not accessible".to_string())),
            Err(DebugError::Gone) => return Err("the guest ended the debug session".into()),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        Ok(MemoryWindow {
            kind,
            sequence,
            address,
            requested_size,
            bytes,
            error,
        })
    }

    /// Follow a process that was resumed, stepped or asked to stop.
    fn follow(&mut self, target: &mut RspTarget) -> Result<(), String> {
        let Phase::Moving {
            pending,
            deadline,
            next_poll,
            from,
        } = self.phase
        else {
            return Ok(());
        };
        let now = Instant::now();
        if now < next_poll {
            return Ok(());
        }
        let state = match target.backend().state() {
            Ok(state) => state,
            Err(error) => {
                self.phase = Phase::Moving {
                    pending,
                    deadline,
                    next_poll: now + self.running_poll,
                    from,
                };
                return self.fail(error).map(|()| self.publish());
            }
        };
        match state {
            TargetState::Stopped(event) if Some(event.sequence) != from => {
                self.stopped(target, event)
            }
            TargetState::Exited { wait_status } => Err(self.exited(wait_status)),
            TargetState::Replaced => Err(self.replaced()),
            TargetState::Stopped(_) | TargetState::Running | TargetState::Transition => {
                let mut pending = pending;
                let mut deadline = deadline;
                if deadline.is_some_and(|limit| now >= limit) {
                    // Slow, not failed: the guest decides. Say why, once.
                    let why = target
                        .backend()
                        .take_failure()
                        .unwrap_or_else(|| "the process has not stopped yet".into());
                    self.view.notice = Some(why);
                    pending = Pending::Nothing;
                    deadline = None;
                    self.view.run = RunState::Running { pending };
                    self.publish();
                }
                let interval = if pending == Pending::Nothing {
                    self.running_poll
                } else {
                    self.moving_poll
                };
                self.phase = Phase::Moving {
                    pending,
                    deadline,
                    next_poll: now + interval,
                    from,
                };
                Ok(())
            }
        }
    }

    fn handle(&mut self, target: &mut RspTarget, request: DebugRequest) -> Result<(), String> {
        self.view.notice = None;
        let result = self.apply(target, &request);
        self.view.handled = self.view.handled.max(request.id);
        self.publish();
        result
    }

    fn apply(&mut self, target: &mut RspTarget, request: &DebugRequest) -> Result<(), String> {
        let stopped = self.view.run.stopped_sequence();
        if request.action.needs_stop() && stopped != Some(request.sequence) {
            self.view.notice = Some(
                "Dropped a request made for a stop that is over; the process has moved on.".into(),
            );
            return Ok(());
        }
        match &request.action {
            DebugAction::Continue => self.resume(target, ResumeAction::Continue, Pending::Nothing),
            DebugAction::Step { tid } => {
                if !self.caps.hardware_single_step {
                    self.view.notice = Some("This guest cannot single-step.".into());
                    return Ok(());
                }
                self.resume(target, ResumeAction::Step { tid: *tid }, Pending::Stepping)
            }
            DebugAction::Stop => self.stop(target),
            DebugAction::Refresh => {
                let (Some(sequence), Some(tid)) = (stopped, self.view.selected_tid) else {
                    return Ok(());
                };
                self.view.loading = true;
                self.publish();
                self.fetch(target, sequence, tid, true)
            }
            DebugAction::SelectThread { tid } => {
                let Some(sequence) = stopped else {
                    return Ok(());
                };
                if !self.view.threads.iter().any(|thread| thread.tid == *tid) {
                    self.view.notice = Some(format!("thread {tid} is not in the list"));
                    return Ok(());
                }
                self.view.selected_tid = Some(*tid);
                self.view.loading = true;
                self.clear_stop_data();
                self.publish();
                self.fetch(target, sequence, *tid, false)
            }
            DebugAction::AddBreakpoint { addr, kind } => self.add_breakpoint(target, *addr, *kind),
            DebugAction::RemoveBreakpoint { addr } => self.remove_breakpoint(target, *addr),
            DebugAction::SetBreakpointEnabled { addr, enabled } => {
                self.enable_breakpoint(target, *addr, *enabled)
            }
            DebugAction::ReadMemory { addr, size } => {
                let Some(sequence) = stopped else {
                    return Ok(());
                };
                if *size == 0 || *size > MAX_READ_SIZE {
                    self.view.notice = Some(format!("read between 1 and {MAX_READ_SIZE} bytes"));
                    return Ok(());
                }
                self.memory = Some((*addr, *size));
                let window =
                    self.read_window(target, WindowKind::Memory, sequence, *addr, *size)?;
                self.view.memory = Some(window);
                Ok(())
            }
        }
    }

    fn resume(
        &mut self,
        target: &mut RspTarget,
        action: ResumeAction,
        pending: Pending,
    ) -> Result<(), String> {
        target.note_resumed();
        if let Err(error) = target.backend().resume(action) {
            target.note_stopped();
            return self.fail(error);
        }
        self.view.run = RunState::Running { pending };
        self.view.loading = false;
        self.clear_stop_data();
        let now = Instant::now();
        self.phase = Phase::Moving {
            pending,
            deadline: (pending != Pending::Nothing).then(|| now + self.move_deadline),
            next_poll: now
                + if pending == Pending::Nothing {
                    self.running_poll
                } else {
                    self.moving_poll
                },
            from: self.last_stop,
        };
        Ok(())
    }

    fn stop(&mut self, target: &mut RspTarget) -> Result<(), String> {
        let Phase::Moving { from, .. } = self.phase else {
            return Ok(());
        };
        if let Err(error) = target.backend().interrupt() {
            return self.fail(error);
        }
        self.view.run = RunState::Running {
            pending: Pending::Stopping,
        };
        self.phase = Phase::Moving {
            pending: Pending::Stopping,
            deadline: Some(Instant::now() + self.move_deadline),
            next_poll: Instant::now(),
            from,
        };
        Ok(())
    }

    /// Breakpoints can only change while the guest is stopped.
    fn require_stopped(&mut self) -> bool {
        if matches!(self.phase, Phase::Stopped) {
            true
        } else {
            self.view.notice = Some("Stop the process to change breakpoints.".into());
            false
        }
    }

    fn add_breakpoint(
        &mut self,
        target: &mut RspTarget,
        addr: u64,
        kind: BreakpointKind,
    ) -> Result<(), String> {
        if kind != BreakpointKind::Software || !self.caps.software_breakpoints {
            self.view.notice = Some(format!(
                "{} breakpoints are not available in this guest yet.",
                kind.label()
            ));
            return Ok(());
        }
        if !self.require_stopped() {
            return Ok(());
        }
        if let Err(message) = self.list.add(addr, kind) {
            self.view.notice = Some(message);
            return Ok(());
        }
        if let Err(error) = target.panel_breakpoint(addr, true) {
            self.list.remove(addr);
            self.view.notice = Some(format!("cannot set a breakpoint at {addr:#x}: {error}"));
            return self.gone_only(error);
        }
        Ok(())
    }

    fn remove_breakpoint(&mut self, target: &mut RspTarget, addr: u64) -> Result<(), String> {
        if !self.require_stopped() {
            return Ok(());
        }
        if self.list.get(addr).is_none() {
            return Ok(());
        }
        if let Err(error) = target.panel_breakpoint(addr, false) {
            self.view.notice = Some(format!("cannot clear the breakpoint at {addr:#x}: {error}"));
            return self.gone_only(error);
        }
        self.list.remove(addr);
        Ok(())
    }

    fn enable_breakpoint(
        &mut self,
        target: &mut RspTarget,
        addr: u64,
        enabled: bool,
    ) -> Result<(), String> {
        if !self.require_stopped() {
            return Ok(());
        }
        if self.list.get(addr).is_none() {
            return Ok(());
        }
        if let Err(error) = target.panel_breakpoint(addr, enabled) {
            self.view.notice = Some(format!(
                "cannot change the breakpoint at {addr:#x}: {error}"
            ));
            return self.gone_only(error);
        }
        self.list.set_enabled(addr, enabled);
        Ok(())
    }

    /// After a notice was set for `error`: only a vanished session is fatal.
    fn gone_only(&mut self, error: DebugError) -> Result<(), String> {
        if error == DebugError::Gone {
            Err("the guest ended the debug session".into())
        } else {
            Ok(())
        }
    }
}
