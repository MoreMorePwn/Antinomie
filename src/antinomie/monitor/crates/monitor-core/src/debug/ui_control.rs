// SPDX-License-Identifier: GPL-3.0-only
//! The in-app debugger's controller. It runs on the RSP server thread and uses
//! the same `Debugger` (so the same backends, guest link and breakpoint tables)
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
    debugger::{Debugger, Happening},
    inferior::Inferior,
    regs::{RegKind, RegisterFile},
    signal_policy::SignalTable,
    target::{DebugCaps, DebugError, ResumeAction, StopEvent},
    view::{
        BreakpointKind, BreakpointList, CODE_AFTER_SIZE, CODE_BEFORE_SIZE, Controller, DebugAction,
        DebugRequest, DebugThread, DebugView, ForkPolicy, ForkPrompt, MAX_READ_SIZE, MemoryWindow,
        Pending, RegisterEntry, RegisterSnapshot, RunState, STACK_WINDOW_SIZE, StopReason,
        ViewCaps, WatchAccess, WindowKind,
    },
};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Bytes a panel watchpoint covers from its address.
const WATCH_SIZE: u64 = 8;
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

#[derive(Clone, Copy)]
pub(super) enum Phase {
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
    pub(super) shared: Arc<PanelShared>,
    pub(super) view: DebugView,
    pub(super) caps: DebugCaps,
    pub(super) phase: Phase,
    pub(super) list: BreakpointList,
    /// The user's memory range, read again at every stop.
    pub(super) memory: Option<(u64, usize)>,
    /// Latest stop sequence seen, to ignore a repeated report of it.
    pub(super) last_stop: Option<u32>,
    pub(super) running_poll: Duration,
    pub(super) moving_poll: Duration,
    pub(super) move_deadline: Duration,
    /// The process the panel shows (a pid of the session).
    pub(super) selected: u32,
    pub(super) policy: ForkPolicy,
    pub(super) signals: SignalTable,
    /// Children taken hold of and not yet decided about.
    pub(super) undecided: BTreeSet<u32>,
    /// A fork waits for the user (`FollowMode::Ask`).
    pub(super) prompt: Option<ForkPrompt>,
    /// Fork following has been asked of the guest.
    pub(super) following: Option<bool>,
    /// The last time the process list was refreshed for a gdb-controlled view.
    pub(super) observed: Option<Instant>,
}

impl PanelControl {
    pub(super) fn new(caps: &DebugCaps) -> (Self, PanelHandle) {
        let view_caps = ViewCaps {
            software_breakpoints: caps.software_breakpoints,
            single_step: caps.hardware_single_step,
            hardware_breakpoints: caps.hardware_breakpoints,
            hardware_watchpoints: caps.hardware_watchpoints,
            follow: caps.follow,
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
            selected: 0,
            policy: ForkPolicy::default(),
            signals: SignalTable::default(),
            undecided: BTreeSet::new(),
            prompt: None,
            following: None,
            observed: None,
        };
        (control, PanelHandle(shared))
    }

    #[cfg(test)]
    pub(super) fn timing(&mut self, running: Duration, moving: Duration, deadline: Duration) {
        self.running_poll = running;
        self.moving_poll = moving;
        self.move_deadline = deadline;
    }

    pub(super) fn publish(&mut self) {
        self.view.epoch += 1;
        self.view.breakpoints = self.list.entries().to_vec();
        self.view.selected_pid = self.selected;
        self.view.fork_prompt = self.prompt;
        self.view.fork_policy = self.policy;
        self.view.signals = self.signals.clone();
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
        self.prompt = None;
        self.clear_stop_data();
        self.phase = Phase::Unsynced;
        self.following = None;
        self.observed = None;
        self.publish();
    }

    /// The RSP client has left; the panel takes control again and reads the
    /// state afresh on the next pump. The client's processes may have changed.
    pub(super) fn client_left(&mut self, debugger: &mut Debugger) {
        self.shared.client.store(false, Ordering::Release);
        self.view.controller = Controller::App;
        self.phase = Phase::Unsynced;
        self.following = None;
        self.undecided.clear();
        self.sync_inferiors(debugger);
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

    pub(super) fn clear_stop_data(&mut self) {
        self.view.threads.clear();
        self.view.registers = None;
        self.view.code = None;
        self.view.stack = None;
        self.view.memory = None;
    }

    /// The selected process, if the session still has it.
    pub(super) fn inferior<'a>(
        &self,
        debugger: &'a mut Debugger,
    ) -> Result<&'a mut Inferior, String> {
        debugger
            .get(self.selected)
            .ok_or_else(|| "the guest ended the debug session".to_string())
    }

    /// The guest's state moved under us: read it all again at the next pump.
    pub(super) fn invalidate(&mut self, debugger: &mut Debugger) {
        self.phase = Phase::Unsynced;
        self.following = None;
        self.prompt = None;
        self.sync_inferiors(debugger);
        self.publish();
    }

    /// While a gdb client has the processes the panel only looks: the process
    /// list and the threads with their run state, a few times a second.
    pub(super) fn observe(&mut self, debugger: &mut Debugger) {
        if !self.shared.client.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        if self
            .observed
            .is_some_and(|at| now.duration_since(at) < Duration::from_millis(250))
        {
            return;
        }
        self.observed = Some(now);
        if !debugger.inferiors.contains_key(&self.selected) {
            self.selected = debugger.current;
        }
        self.sync_inferiors(debugger);
        let threads = debugger
            .get(debugger.current)
            .filter(|inferior| inferior.is_live())
            .and_then(|inferior| inferior.threads().ok());
        if let Some(threads) = threads {
            self.view.threads = threads
                .into_iter()
                .map(|thread| DebugThread {
                    tid: thread.tid,
                    stopped: thread.stopped,
                    pc: if thread.stopped { thread.pc } else { 0 },
                    signal: thread.signal,
                })
                .collect();
        }
        self.publish();
    }

    /// Do whatever is due: read the state once after attach or after a client,
    /// handle queued requests, and follow a moving process.
    pub(super) fn pump(&mut self, debugger: &mut Debugger) -> Pump {
        if self.shared.client.load(Ordering::Acquire) || matches!(self.phase, Phase::Over) {
            return Pump::Idle;
        }
        let ended = self.pump_inner(debugger);
        match ended {
            Ok(()) => Pump::Idle,
            Err(why) => {
                self.phase = Phase::Over;
                self.publish();
                Pump::Ended(why)
            }
        }
    }

    fn pump_inner(&mut self, debugger: &mut Debugger) -> Result<(), String> {
        if matches!(self.phase, Phase::Unsynced) {
            self.resync(debugger)?;
        }
        for _ in 0..QUEUE_LIMIT {
            let request = self
                .shared
                .requests
                .lock()
                .ok()
                .and_then(|mut queue| queue.pop_front());
            let Some(request) = request else { break };
            self.handle(debugger, request)?;
            if self.shared.client.load(Ordering::Acquire) {
                break;
            }
        }
        self.follow(debugger)
    }

    /// Learn what the processes are doing without assuming it.
    fn resync(&mut self, debugger: &mut Debugger) -> Result<(), String> {
        self.apply_follow_option(debugger);
        if !debugger.inferiors.contains_key(&self.selected) {
            self.selected = if debugger.inferiors.contains_key(&debugger.root) {
                debugger.root
            } else {
                debugger.current
            };
        }
        let selected = self.selected;
        // Breakpoints the guest held for a session found again are the panel's.
        let held = debugger
            .get(selected)
            .map(|inferior| inferior.registry.borrow().panel_items())
            .unwrap_or_default();
        for (kind, addr, _) in held {
            if self.list.get(addr).is_none() {
                let _ = self.list.add(addr, kind);
            }
        }
        let state = match debugger.get(selected) {
            Some(inferior) => inferior.backend.state(),
            None => return Err("the guest ended the debug session".into()),
        };
        match state {
            Ok(super::target::TargetState::Stopped(event)) => {
                if let Some(inferior) = debugger.get(selected) {
                    inferior.run = super::inferior::RunState::Stopped(event);
                    inferior.current_tid = event.tid;
                }
                self.stopped(debugger, event)?;
            }
            Ok(super::target::TargetState::Running | super::target::TargetState::Transition) => {
                if let Some(inferior) = debugger.get(selected) {
                    inferior.run = super::inferior::RunState::Running;
                }
                self.view.run = RunState::Running {
                    pending: Pending::Nothing,
                };
                self.phase = Phase::Moving {
                    pending: Pending::Nothing,
                    deadline: None,
                    next_poll: Instant::now() + self.running_poll,
                    from: self.last_stop,
                };
                self.sync_inferiors(debugger);
                self.publish();
            }
            Ok(super::target::TargetState::Exited { wait_status }) => {
                return Err(self.exited(wait_status));
            }
            Ok(super::target::TargetState::Replaced) => return Err(self.replaced()),
            Err(error) => return self.fail(error),
        }
        Ok(())
    }

    pub(super) fn exited(&mut self, wait_status: u32) -> String {
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
    pub(super) fn replaced(&mut self) -> String {
        self.view.run = RunState::Replaced;
        self.view.loading = false;
        self.clear_stop_data();
        "the process executed a new program".into()
    }

    /// An error from the engine: the session being gone ends the controller,
    /// anything else is shown as a notice.
    pub(super) fn fail(&mut self, error: DebugError) -> Result<(), String> {
        if error == DebugError::Gone {
            self.view.run = RunState::Unknown;
            self.view.loading = false;
            return Err("the guest ended the debug session".into());
        }
        self.view.notice = Some(error.to_string());
        Ok(())
    }

    /// The process is stopped at `event`: show it and fetch its data.
    pub(super) fn stopped(
        &mut self,
        debugger: &mut Debugger,
        event: StopEvent,
    ) -> Result<(), String> {
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
        self.sync_inferiors(debugger);
        self.publish();
        self.fetch(debugger, event.sequence, event.tid, true)
    }

    /// Fetch the stop's data, publishing after each part so the panel fills in
    /// as it arrives.
    fn fetch(
        &mut self,
        debugger: &mut Debugger,
        sequence: u32,
        tid: u32,
        with_threads: bool,
    ) -> Result<(), String> {
        let result = self.fetch_parts(debugger, sequence, tid, with_threads);
        self.view.loading = false;
        self.publish();
        result
    }

    fn fetch_parts(
        &mut self,
        debugger: &mut Debugger,
        sequence: u32,
        tid: u32,
        with_threads: bool,
    ) -> Result<(), String> {
        if with_threads {
            match self.inferior(debugger)?.backend.threads() {
                Ok(threads) => {
                    self.view.threads = threads
                        .into_iter()
                        .map(|thread| DebugThread {
                            tid: thread.tid,
                            stopped: thread.stopped,
                            pc: thread.pc,
                            signal: thread.signal,
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
            // The general registers with the floating-point set in the same
            // request when the guest can (one round trip, not two).
            let wanted: &[u32] = if self.caps.batch_regs {
                &description.regsets
            } else {
                std::slice::from_ref(nt_type)
            };
            match self.inferior(debugger)?.backend.read_regsets(tid, wanted) {
                Ok(blobs) => blobs.into_iter().for_each(|blob| file.insert(blob)),
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
            let window = self.read_code(debugger, sequence, pc)?;
            self.view.code = Some(window);
            self.publish();
        }
        if let Some(sp) = sp {
            let window =
                self.read_window(debugger, WindowKind::Stack, sequence, sp, STACK_WINDOW_SIZE)?;
            self.view.stack = Some(window);
            self.publish();
        }
        if let Some((addr, len)) = self.memory {
            let window = self.read_window(debugger, WindowKind::Memory, sequence, addr, len)?;
            self.view.memory = Some(window);
        }
        Ok(())
    }

    /// The bytes around `pc`: some before it for context, the rest after. When
    /// the part before is not mapped the window starts at `pc`.
    fn read_code(
        &mut self,
        debugger: &mut Debugger,
        sequence: u32,
        pc: u64,
    ) -> Result<MemoryWindow, String> {
        let before = pc.min(CODE_BEFORE_SIZE as u64);
        if before > 0 {
            let window = self.read_window(
                debugger,
                WindowKind::Code,
                sequence,
                pc - before,
                before as usize + CODE_AFTER_SIZE,
            )?;
            if window.error.is_none() && window.bytes.len() > before as usize {
                return Ok(window);
            }
        }
        self.read_window(debugger, WindowKind::Code, sequence, pc, CODE_AFTER_SIZE)
    }

    fn read_window(
        &mut self,
        debugger: &mut Debugger,
        kind: WindowKind,
        sequence: u32,
        address: u64,
        requested_size: usize,
    ) -> Result<MemoryWindow, String> {
        let (bytes, error) = match self
            .inferior(debugger)?
            .backend
            .read_memory(address, requested_size)
        {
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

    /// Follow the processes while any runs: a process that was resumed, stepped
    /// or asked to stop.
    fn follow(&mut self, debugger: &mut Debugger) -> Result<(), String> {
        let Phase::Moving {
            pending,
            deadline,
            next_poll,
            from,
        } = self.phase
        else {
            // The selected process sits stopped; others may still run.
            return self.follow_others(debugger);
        };
        let now = Instant::now();
        if now < next_poll {
            return Ok(());
        }
        let happenings = match debugger.poll() {
            Ok(happenings) => happenings,
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
        for happening in happenings {
            match self.happened(debugger, happening, from)? {
                Flow::Handled => {}
                Flow::Stay => {}
            }
        }
        // Still moving? Then say when to look again, and whether it is slow.
        if let Phase::Moving { .. } = self.phase {
            let mut pending = pending;
            let mut deadline = deadline;
            if deadline.is_some_and(|limit| now >= limit) {
                // Slow, not failed: the guest decides. Say why, once.
                let why = self
                    .inferior(debugger)
                    .ok()
                    .and_then(|inferior| inferior.backend.take_failure())
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
            if let Phase::Moving { from, .. } = self.phase {
                self.phase = Phase::Moving {
                    pending,
                    deadline,
                    next_poll: now + interval,
                    from,
                };
            }
        }
        Ok(())
    }

    /// Something changed in a process the panel is not showing.
    fn follow_others(&mut self, debugger: &mut Debugger) -> Result<(), String> {
        if !debugger.any_running() {
            return Ok(());
        }
        let now = Instant::now();
        if self
            .observed
            .is_some_and(|at| now.duration_since(at) < self.running_poll)
        {
            return Ok(());
        }
        self.observed = Some(now);
        let happenings = match debugger.poll() {
            Ok(happenings) => happenings,
            Err(error) => return self.fail(error),
        };
        for happening in happenings {
            self.happened(debugger, happening, self.last_stop)?;
        }
        Ok(())
    }

    /// Take in one event of the session.
    pub(super) fn happened(
        &mut self,
        debugger: &mut Debugger,
        happening: Happening,
        from: Option<u32>,
    ) -> Result<Flow, String> {
        match happening {
            Happening::Exited { pid, wait_status } => {
                self.process_exited(debugger, pid, wait_status)
            }
            Happening::Stopped { pid, event } => {
                if pid == self.selected && Some(event.sequence) == from {
                    // A report of the stop the move started from is not news.
                    return Ok(Flow::Handled);
                }
                self.process_stopped(debugger, pid, event)
            }
        }
    }

    fn handle(&mut self, debugger: &mut Debugger, request: DebugRequest) -> Result<(), String> {
        self.view.notice = None;
        let result = self.apply(debugger, &request);
        self.view.handled = self.view.handled.max(request.id);
        self.sync_inferiors(debugger);
        self.publish();
        result
    }

    fn apply(&mut self, debugger: &mut Debugger, request: &DebugRequest) -> Result<(), String> {
        let stopped = self.view.run.stopped_sequence();
        if request.action.needs_stop() && stopped != Some(request.sequence) {
            self.view.notice = Some(
                "Dropped a request made for a stop that is over; the process has moved on.".into(),
            );
            return Ok(());
        }
        match &request.action {
            DebugAction::Continue => {
                self.prompt = None;
                let action = match self.stopped_signal() {
                    Some((tid, signal)) => ResumeAction::ContinueSignal { tid, signal },
                    None => ResumeAction::Continue,
                };
                self.resume(debugger, action, Pending::Nothing)
            }
            DebugAction::Step { tid } => {
                if !self.caps.hardware_single_step {
                    self.view.notice = Some("This guest cannot single-step.".into());
                    return Ok(());
                }
                self.prompt = None;
                // A thread stopped on a signal receives it, as under gdb: the
                // step then ends at the handler's first instruction.
                let action = match self.stopped_signal() {
                    Some((signal_tid, signal)) if signal_tid == *tid => {
                        ResumeAction::StepSignal { tid: *tid, signal }
                    }
                    _ => ResumeAction::Step { tid: *tid },
                };
                self.resume(debugger, action, Pending::Stepping)
            }
            DebugAction::Stop => self.stop(debugger),
            DebugAction::Refresh => {
                let (Some(sequence), Some(tid)) = (stopped, self.view.selected_tid) else {
                    return Ok(());
                };
                self.view.loading = true;
                self.publish();
                self.fetch(debugger, sequence, tid, true)
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
                self.fetch(debugger, sequence, *tid, false)
            }
            DebugAction::AddBreakpoint { addr, kind } => {
                self.add_breakpoint(debugger, *addr, *kind)
            }
            DebugAction::RemoveBreakpoint { addr } => self.remove_breakpoint(debugger, *addr),
            DebugAction::SetBreakpointEnabled { addr, enabled } => {
                self.enable_breakpoint(debugger, *addr, *enabled)
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
                    self.read_window(debugger, WindowKind::Memory, sequence, *addr, *size)?;
                self.view.memory = Some(window);
                Ok(())
            }
            DebugAction::SelectInferior { pid } => self.select_inferior(debugger, *pid),
            DebugAction::ForkDecision {
                follow,
                detach_other,
            } => self.decide_fork(debugger, *follow, *detach_other),
            DebugAction::DetachInferior { pid } => self.detach_inferior(debugger, *pid),
            DebugAction::SetForkPolicy(policy) => {
                self.policy = *policy;
                self.following = None;
                self.apply_follow_option(debugger);
                Ok(())
            }
            DebugAction::SetSignalPolicy { signal, action } => {
                self.signals.set(*signal, *action);
                Ok(())
            }
            DebugAction::SetSignalTable(table) => {
                self.signals = table.clone().sanitized();
                Ok(())
            }
        }
    }

    /// The signal the stopped thread has not yet received, to pass on a resume,
    /// when the panel's table says to pass it.
    fn stopped_signal(&self) -> Option<(u32, u32)> {
        if !self.caps.signals {
            return None;
        }
        match self.view.run {
            RunState::Stopped {
                reason: StopReason::Signal { number },
                tid,
                ..
            } if number != 0 && self.signals.action(number).pass => Some((tid, u32::from(number))),
            _ => None,
        }
    }

    pub(super) fn resume(
        &mut self,
        debugger: &mut Debugger,
        action: ResumeAction,
        pending: Pending,
    ) -> Result<(), String> {
        let selected = self.selected;
        if let Err(error) = debugger.resume(selected, action) {
            // Still stopped where it was.
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

    fn stop(&mut self, debugger: &mut Debugger) -> Result<(), String> {
        let Phase::Moving { from, .. } = self.phase else {
            return Ok(());
        };
        let running: Vec<u32> = debugger
            .inferiors
            .iter()
            .filter(|(_, inferior)| inferior.is_running())
            .map(|(pid, _)| *pid)
            .collect();
        for pid in running {
            if let Some(inferior) = debugger.get(pid)
                && let Err(error) = inferior.backend.interrupt()
            {
                return self.fail(error);
            }
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
        debugger: &mut Debugger,
        addr: u64,
        kind: BreakpointKind,
    ) -> Result<(), String> {
        let offered = match kind {
            BreakpointKind::Software => self.caps.software_breakpoints,
            BreakpointKind::Hardware => self.caps.hardware_breakpoints > 0,
            BreakpointKind::Watch(_) => self.caps.hardware_watchpoints > 0,
        };
        if !offered {
            self.view.notice = Some(format!(
                "{} breakpoints are not available in this guest.",
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
        if let Err(error) = self.panel_apply(debugger, addr, kind, true) {
            self.list.remove(addr);
            self.view.notice = Some(format!("cannot set a breakpoint at {addr:#x}: {error}"));
            return self.gone_only(error);
        }
        Ok(())
    }

    /// Register or release one list entry with the guest. A watchpoint covers
    /// eight bytes from its address (split into aligned pieces); a read watch
    /// is an access watch, the debug registers having no read-only mode.
    pub(super) fn panel_apply(
        &mut self,
        debugger: &mut Debugger,
        addr: u64,
        kind: BreakpointKind,
        on: bool,
    ) -> Result<(), DebugError> {
        let Some(inferior) = debugger.get(self.selected) else {
            return Err(DebugError::Gone);
        };
        inferior.with_registry(|registry, backend| match kind {
            BreakpointKind::Software => registry.panel_breakpoint(backend, addr, on),
            BreakpointKind::Hardware => registry.panel_hardware(backend, kind, addr, 1, on),
            BreakpointKind::Watch(WatchAccess::Write) => {
                registry.panel_hardware(backend, kind, addr, WATCH_SIZE, on)
            }
            BreakpointKind::Watch(_) => registry.panel_hardware(
                backend,
                BreakpointKind::Watch(WatchAccess::Access),
                addr,
                WATCH_SIZE,
                on,
            ),
        })
    }

    fn remove_breakpoint(&mut self, debugger: &mut Debugger, addr: u64) -> Result<(), String> {
        if !self.require_stopped() {
            return Ok(());
        }
        let Some(kind) = self.list.get(addr).map(|entry| entry.kind) else {
            return Ok(());
        };
        if let Err(error) = self.panel_apply(debugger, addr, kind, false) {
            self.view.notice = Some(format!("cannot clear the breakpoint at {addr:#x}: {error}"));
            return self.gone_only(error);
        }
        self.list.remove(addr);
        Ok(())
    }

    fn enable_breakpoint(
        &mut self,
        debugger: &mut Debugger,
        addr: u64,
        enabled: bool,
    ) -> Result<(), String> {
        if !self.require_stopped() {
            return Ok(());
        }
        let Some(kind) = self.list.get(addr).map(|entry| entry.kind) else {
            return Ok(());
        };
        if let Err(error) = self.panel_apply(debugger, addr, kind, enabled) {
            self.view.notice = Some(format!(
                "cannot change the breakpoint at {addr:#x}: {error}"
            ));
            return self.gone_only(error);
        }
        self.list.set_enabled(addr, enabled);
        Ok(())
    }

    /// After a notice was set for `error`: only a vanished session is fatal.
    pub(super) fn gone_only(&mut self, error: DebugError) -> Result<(), String> {
        if error == DebugError::Gone {
            Err("the guest ended the debug session".into())
        } else {
            Ok(())
        }
    }
}

/// What taking in an event did to the panel's phase.
pub(super) enum Flow {
    /// The event was dealt with; keep following.
    Handled,
    /// The panel is now showing a stop (or something else that ends the move).
    Stay,
}
