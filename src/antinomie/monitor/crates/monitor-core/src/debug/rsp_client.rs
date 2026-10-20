// SPDX-License-Identifier: MIT
//! One RSP client (gdb, IDA, Ghidra, radare2) served against a [`Debugger`]:
//! packet dispatch, thread ids with process ids (multiprocess), all-stop and
//! non-stop, fork, vfork and exec events, `%Stop` notifications. The wire (a
//! socket) is behind [`Wire`], so the whole protocol runs in tests without one.
//!
//! The protocol follows GDB's documentation; where gdb's behavior decides a
//! corner (what `?` answers in non-stop, that `D;pid` detaches one process) it is
//! noted at the code.
use super::{
    debugger::{Debugger, Happening},
    inferior::{Inferior, RunState},
    rsp_packet::{Framer, Incoming, encode, encode_notification, parse_hex, to_hex},
    signals::{gdb_to_linux, linux_to_gdb},
    target::{DebugError, DetachMode, ResumeAction, StopKind, ThreadAction},
    view::WatchAccess,
};
use std::{
    collections::VecDeque,
    io,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

/// The packet size advertised to the client: reads and writes of this order fit
/// a guest request, larger ones are split by the backend.
pub(super) const PACKET_BUFFER: usize = 0x4000;
const INTERRUPT_DEADLINE: Duration = Duration::from_secs(5);
const IDLE_POLL: Duration = Duration::from_millis(50);
const RUNNING_POLL: Duration = Duration::from_millis(2);
/// GDB's number for a signal it has no name for.
const GDB_SIGNAL_UNKNOWN: u8 = 143;

/// The client's side of the connection.
pub(super) trait Wire {
    /// The next byte, waiting up to `timeout`; `Ok(None)` is a timeout, `Err` a
    /// closed or broken connection.
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>>;
    fn send(&mut self, data: &[u8]) -> io::Result<()>;
}

/// How the session with this client ended.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The client left; the processes live on.
    ClientGone(String),
    /// The target ended or the client killed it: nothing more to debug.
    TargetGone(String),
    Shutdown,
}

/// What a handler wants done after it.
pub(super) enum Reply {
    Packet(Vec<u8>),
    /// Nothing to say now (the target runs; its stop reply comes later).
    Later,
    /// Say this, then end the session with this outcome.
    Then(Vec<u8>, Outcome),
}
pub(super) fn text(payload: impl Into<Vec<u8>>) -> Reply {
    Reply::Packet(payload.into())
}
pub(super) fn ok() -> Reply {
    text("OK")
}
pub(super) fn unsupported() -> Reply {
    text("")
}
pub(super) fn errno(code: u8) -> Reply {
    Reply::Packet(format!("E{code:02x}").into_bytes())
}

/// A backend error as the client sees it: transport trouble ends the session,
/// anything else is an error reply the client shows to its user.
pub(super) fn report(error: DebugError) -> Result<Reply, DebugError> {
    match error {
        DebugError::Fault => Ok(errno(14)),
        DebugError::Busy => Ok(errno(16)),
        DebugError::NoSlots => Ok(errno(28)),
        DebugError::Gone => Ok(errno(3)),
        DebugError::Stale => Ok(errno(116)),
        DebugError::Unsupported(_) | DebugError::Invalid(_) => Ok(errno(22)),
        error @ (DebugError::Transport(_) | DebugError::Guest { .. }) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TidSel {
    Any,
    All,
    One(u32),
}
/// A thread id as the client wrote it: `p<pid>.<tid>`, a bare `<tid>`, `-1`, `0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sel {
    /// `None`: no process named. `Some(u32::MAX)`: every process.
    pub(super) pid: Option<u32>,
    pub(super) tid: TidSel,
}
pub(super) const ALL_PROCESSES: u32 = u32::MAX;
impl Sel {
    const NONE: Self = Self {
        pid: None,
        tid: TidSel::Any,
    };
}
fn parse_tid(text: &[u8]) -> Option<TidSel> {
    Some(match text {
        b"-1" => TidSel::All,
        b"0" => TidSel::Any,
        other => TidSel::One(u32::try_from(parse_hex(other)?).ok()?),
    })
}
pub(super) fn parse_sel(text: &[u8]) -> Option<Sel> {
    if let Some(rest) = text.strip_prefix(b"p") {
        let (pid, tid) = match rest.iter().position(|byte| *byte == b'.') {
            Some(dot) => (&rest[..dot], parse_tid(&rest[dot + 1..])?),
            None => (rest, TidSel::All),
        };
        let pid = if pid == b"-1" {
            Some(ALL_PROCESSES)
        } else {
            // Process 0 is "any process" (gdb's `Hgp0.0`).
            Some(u32::try_from(parse_hex(pid)?).ok()?).filter(|pid| *pid != 0)
        };
        return Some(Sel { pid, tid });
    }
    Some(Sel {
        pid: None,
        tid: parse_tid(text)?,
    })
}

/// Hexadecimal with an even number of digits, as gdbstub wrote ids and as gdb
/// reads them.
pub(super) fn hex_id(value: u32) -> String {
    let digits = format!("{value:x}");
    if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionKind {
    Continue(Option<u8>),
    Step(Option<u8>),
    Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Action {
    kind: ActionKind,
    sel: Option<Sel>,
}
fn parse_vcont(list: &[u8]) -> Option<Vec<Action>> {
    let mut actions = Vec::new();
    for part in list
        .split(|byte| *byte == b';')
        .filter(|part| !part.is_empty())
    {
        let (head, sel) = match part.iter().position(|byte| *byte == b':') {
            Some(colon) => (&part[..colon], Some(parse_sel(&part[colon + 1..])?)),
            None => (part, None),
        };
        let signal = |digits: &[u8]| -> Option<Option<u8>> {
            Some(Some(u8::try_from(parse_hex(digits)?).ok()?))
        };
        let kind = match head {
            b"c" => ActionKind::Continue(None),
            b"s" => ActionKind::Step(None),
            b"t" => ActionKind::Stop,
            [b'C', digits @ ..] => ActionKind::Continue(signal(digits)?),
            [b'S', digits @ ..] => ActionKind::Step(signal(digits)?),
            _ => return None,
        };
        actions.push(Action { kind, sel });
    }
    Some(actions)
}

/// Whether an action applies to the process `pid`.
fn action_covers(action: &Action, pid: u32) -> bool {
    match action.sel {
        None => true,
        Some(sel) => sel.pid.is_none_or(|p| p == ALL_PROCESSES || p == pid),
    }
}

pub(super) struct Client {
    pub(super) framer: Framer,
    pub(super) no_ack: bool,
    pub(super) switch_to_no_ack: bool,
    pub(super) multiprocess: bool,
    pub(super) swbreak: bool,
    pub(super) hwbreak: bool,
    pub(super) fork_events: bool,
    pub(super) vfork_events: bool,
    pub(super) exec_events: bool,
    pub(super) nonstop: bool,
    /// Hg: the thread of g, m, Z and the other requests of the "general" thread.
    pub(super) general: Sel,
    pub(super) last_reply: Vec<u8>,
    /// All-stop: the target was resumed and a stop reply is owed.
    pub(super) waiting: bool,
    /// Non-stop notifications waiting for their turn, and the one sent.
    pub(super) queue: VecDeque<Vec<u8>>,
    pub(super) held: Option<Vec<u8>>,
    /// Initial stops beyond the first: gdb cannot take several while it is still
    /// starting up (its first wait asserts), so they follow as notifications once
    /// it has asked for symbols or resumed.
    pub(super) deferred: VecDeque<Vec<u8>>,
    /// More than one process has existed: exits name theirs.
    pub(super) multi_seen: bool,
}

impl Client {
    pub(super) fn new() -> Self {
        Self {
            framer: Framer::default(),
            no_ack: false,
            switch_to_no_ack: false,
            multiprocess: false,
            swbreak: false,
            hwbreak: false,
            fork_events: false,
            vfork_events: false,
            exec_events: false,
            nonstop: false,
            general: Sel::NONE,
            last_reply: Vec::new(),
            waiting: false,
            queue: VecDeque::new(),
            held: None,
            deferred: VecDeque::new(),
            multi_seen: false,
        }
    }
}

/// What the server hands a session besides the wire: a way to tell the app what
/// the target is doing, a look at the processes while the client is idle (the
/// panel's read-only view), and a reason to end the session from outside.
pub(super) struct Hooks<'a> {
    pub on_state: &'a mut dyn FnMut(&str),
    pub on_idle: &'a mut dyn FnMut(&mut Debugger),
    pub leave: &'a dyn Fn() -> Option<String>,
}

pub(super) struct Session<'a, W: Wire> {
    pub(super) wire: &'a mut W,
    pub(super) debugger: &'a mut Debugger,
    pub(super) stop: &'a AtomicBool,
    pub(super) client: Client,
    pub(super) on_state: &'a mut dyn FnMut(&str),
    on_idle: &'a mut dyn FnMut(&mut Debugger),
    leave: &'a dyn Fn() -> Option<String>,
}

/// Take a client from connect to its end.
pub(super) fn serve<W: Wire>(
    debugger: &mut Debugger,
    wire: &mut W,
    stop: &AtomicBool,
    hooks: Hooks<'_>,
) -> Outcome {
    let mut session = Session {
        wire,
        debugger,
        stop,
        client: Client::new(),
        on_state: hooks.on_state,
        on_idle: hooks.on_idle,
        leave: hooks.leave,
    };
    session.run()
}

fn describe(happening: &Happening) -> String {
    match happening {
        Happening::Exited { wait_status, .. } if wait_status & 0x7f == 0 => {
            format!("exited with status {}", (wait_status >> 8) & 0xff)
        }
        Happening::Exited { wait_status, .. } => format!("killed by signal {}", wait_status & 0x7f),
        Happening::Stopped { .. } => "stopped".into(),
    }
}

impl<W: Wire> Session<'_, W> {
    // ---- connect, loop, leave -----------------------------------------------------

    pub(super) fn run(&mut self) -> Outcome {
        match self.connect() {
            Ok(()) => {}
            Err(outcome) => return outcome,
        }
        (self.on_state)("stopped");
        loop {
            if self.stop.load(Ordering::Acquire) {
                return Outcome::Shutdown;
            }
            if let Some(why) = (self.leave)() {
                return Outcome::ClientGone(why);
            }
            (self.on_idle)(self.debugger);
            match self.step() {
                Ok(None) => {}
                Ok(Some(outcome)) => return outcome,
                Err(DebugError::Gone) => {
                    return Outcome::TargetGone("the guest ended the debug session".into());
                }
                Err(error) => return Outcome::ClientGone(error.to_string()),
            }
        }
    }

    /// A debugger expects a stopped target at connect.
    pub(super) fn connect(&mut self) -> Result<(), Outcome> {
        let mut pending_stops = Vec::new();
        for pid in self.debugger.pids() {
            let Some(inferior) = self.debugger.get(pid) else {
                continue;
            };
            if inferior.is_live() && !inferior.nonstop {
                match inferior.backend.state() {
                    Ok(super::target::TargetState::Stopped(event)) => {
                        // A fork or exec the panel left pending is the client's to
                        // see: the child becomes an inferior like any other.
                        pending_stops.push((pid, event));
                    }
                    Ok(
                        super::target::TargetState::Exited { .. }
                        | super::target::TargetState::Replaced,
                    ) => {
                        return Err(Outcome::TargetGone("the process has already ended".into()));
                    }
                    Ok(_) => inferior.run = RunState::Running,
                    Err(DebugError::Gone) => {
                        return Err(Outcome::TargetGone(
                            "the guest ended the debug session".into(),
                        ));
                    }
                    Err(error) => return Err(Outcome::ClientGone(error.to_string())),
                }
            }
        }
        for (pid, event) in pending_stops {
            self.debugger.take_stop(pid, event);
        }
        if self.debugger.any_running() {
            if let Err(error) = self.interrupt_all() {
                return Err(Outcome::ClientGone(format!(
                    "cannot stop the process: {error}"
                )));
            }
            if let Err(error) = self.wait_all_stopped() {
                return Err(Outcome::ClientGone(error.to_string()));
            }
        }
        Ok(())
    }

    pub(super) fn interrupt_all(&mut self) -> Result<(), DebugError> {
        for pid in self.debugger.pids() {
            if let Some(inferior) = self.debugger.get(pid)
                && inferior.is_running()
            {
                inferior.backend.interrupt()?;
            }
        }
        Ok(())
    }

    /// Wait for every running process to stop; their events are kept pending,
    /// not reported (the client asked for the stop or has just connected).
    pub(super) fn wait_all_stopped(&mut self) -> Result<(), DebugError> {
        let until = Instant::now() + INTERRUPT_DEADLINE;
        loop {
            let happenings = self.debugger.poll()?;
            for happening in &happenings {
                if let Happening::Exited { pid, .. } = happening {
                    let _ = pid;
                }
            }
            if !self.debugger.any_running() {
                return Ok(());
            }
            if self.stop.load(Ordering::Acquire) || Instant::now() >= until {
                let why = self
                    .debugger
                    .current_mut()
                    .and_then(|inferior| inferior.backend.take_failure())
                    .unwrap_or_else(|| "the process did not stop in time".into());
                return Err(DebugError::Transport(why));
            }
            thread::sleep(RUNNING_POLL);
        }
    }

    /// One turn of the loop: serve what the target did, then what the client sent.
    pub(super) fn step(&mut self) -> Result<Option<Outcome>, DebugError> {
        if self.client.nonstop {
            self.serve_nonstop()?;
        } else if self.client.waiting
            && let Some(outcome) = self.serve_all_stop()?
        {
            return Ok(Some(outcome));
        }
        let busy = self.client.waiting || self.client.nonstop;
        let timeout = if busy { RUNNING_POLL } else { IDLE_POLL };
        let byte = match self.wire.read_byte(timeout) {
            Ok(Some(byte)) => byte,
            Ok(None) => return Ok(None),
            Err(error) => return Ok(Some(Outcome::ClientGone(error.to_string()))),
        };
        match self.client.framer.feed(byte) {
            None | Some(Incoming::Ack) => Ok(None),
            Some(Incoming::Nack) => {
                let again = self.client.last_reply.clone();
                self.write(&again)?;
                Ok(None)
            }
            Some(Incoming::BadPacket) => Ok(Some(Outcome::ClientGone("bad packet".into()))),
            Some(Incoming::Interrupt) => self.interrupted(),
            Some(Incoming::Packet(payload)) => {
                if !self.client.no_ack {
                    self.write(b"+")?;
                }
                self.dispatch(&payload)
            }
        }
    }

    /// A non-stop client acknowledges its last notification with `vStopped` even
    /// as it detaches: answer it (and nothing else) so it is not told the
    /// connection died. Gives up after a moment.
    fn answer_last_acknowledgement(&mut self) {
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until {
            let Ok(Some(byte)) = self.wire.read_byte(RUNNING_POLL) else {
                continue;
            };
            match self.client.framer.feed(byte) {
                Some(Incoming::Packet(payload)) => {
                    if !self.client.no_ack {
                        let _ = self.write(b"+");
                    }
                    if payload == b"vStopped" {
                        let _ = self.reply(b"OK");
                    }
                    return;
                }
                Some(Incoming::BadPacket) => return,
                _ => {}
            }
        }
    }

    pub(super) fn write(&mut self, data: &[u8]) -> Result<(), DebugError> {
        self.wire
            .send(data)
            .map_err(|error| DebugError::Transport(error.to_string()))
    }
    pub(super) fn reply(&mut self, payload: &[u8]) -> Result<(), DebugError> {
        let framed = encode(payload);
        self.client.last_reply.clone_from(&framed);
        self.write(&framed)
    }

    /// All-stop: a stop reply is owed; send it when the target has stopped.
    pub(super) fn serve_all_stop(&mut self) -> Result<Option<Outcome>, DebugError> {
        let mut happenings = self.debugger.poll()?;
        if happenings.is_empty() {
            return Ok(None);
        }
        let happening = happenings.remove(0);
        // The rest, if any, stay pending on their processes.
        self.report(happening)
    }

    /// Send a stop reply for `happening`; an exit may end the session.
    pub(super) fn report(&mut self, happening: Happening) -> Result<Option<Outcome>, DebugError> {
        (self.on_state)(&describe(&happening));
        self.client.waiting = false;
        let payload = self.stop_reply(&happening);
        if self.debugger.inferiors.len() > 1 {
            self.client.multi_seen = true;
        }
        self.reply(&payload)?;
        if let Happening::Exited { pid, wait_status } = happening {
            self.debugger.reap(pid);
            if !self.debugger.any_live() {
                return Ok(Some(Outcome::TargetGone(describe(&Happening::Exited {
                    pid,
                    wait_status,
                }))));
            }
            if self.debugger.current == pid {
                self.debugger.current = self.debugger.pids().first().copied().unwrap_or(pid);
            }
        }
        if let Happening::Stopped { pid, .. } = happening {
            self.debugger.current = pid;
            // The client has been told: it is not news at the next resume.
            if let Some(inferior) = self.debugger.get(pid) {
                inferior.unreported = false;
            }
        }
        Ok(None)
    }

    /// The 0x03 byte: stop what runs and report it.
    pub(super) fn interrupted(&mut self) -> Result<Option<Outcome>, DebugError> {
        if self.client.nonstop {
            // The client uses vCont;t in non-stop; the byte stops every thread too.
            self.stop_all_threads()?;
            return Ok(None);
        }
        if !self.client.waiting {
            return Ok(None);
        }
        self.interrupt_all()?;
        let until = Instant::now() + INTERRUPT_DEADLINE;
        loop {
            if let Some(outcome) = self.serve_all_stop()? {
                return Ok(Some(outcome));
            }
            if !self.client.waiting {
                return Ok(None);
            }
            if self.stop.load(Ordering::Acquire) || Instant::now() >= until {
                let why = self
                    .debugger
                    .current_mut()
                    .and_then(|inferior| inferior.backend.take_failure())
                    .unwrap_or_else(|| "the process did not stop in time".into());
                return Ok(Some(Outcome::ClientGone(why)));
            }
            thread::sleep(RUNNING_POLL);
        }
    }

    // ---- stop replies ---------------------------------------------------------

    pub(super) fn thread_text(&self, pid: u32, tid: u32) -> String {
        if self.client.multiprocess {
            format!("p{}.{}", hex_id(pid), hex_id(tid))
        } else {
            hex_id(tid)
        }
    }

    pub(super) fn stop_reply(&mut self, happening: &Happening) -> Vec<u8> {
        match *happening {
            Happening::Exited { pid, wait_status } => {
                let mut reply = if wait_status & 0x7f == 0 {
                    format!("W{:02x}", (wait_status >> 8) & 0xff)
                } else {
                    let signal = wait_status & 0x7f;
                    format!(
                        "X{:02x}",
                        linux_to_gdb(signal).unwrap_or(GDB_SIGNAL_UNKNOWN)
                    )
                };
                if self.client.multiprocess
                    && (self.client.multi_seen || self.debugger.inferiors.len() > 1)
                {
                    reply.push_str(&format!(";process:{}", hex_id(pid).trim_start_matches('0')));
                }
                reply.into_bytes()
            }
            Happening::Stopped { pid, event } => {
                let thread = self.thread_text(pid, event.tid);
                let mut reply = String::new();
                match event.kind {
                    StopKind::Signal { signal } => {
                        reply.push_str(&format!(
                            "T{:02x}thread:{thread};",
                            linux_to_gdb(signal).unwrap_or(GDB_SIGNAL_UNKNOWN)
                        ));
                    }
                    // Stopped because it was asked to: gdb's own stop request in
                    // non-stop (signal 0), the user's Ctrl-C in all-stop (SIGINT).
                    StopKind::Interrupt if self.client.nonstop => {
                        reply.push_str(&format!("T00thread:{thread};"));
                    }
                    StopKind::Interrupt => reply.push_str(&format!("T02thread:{thread};")),
                    _ => {
                        reply.push_str(&format!("T05thread:{thread};"));
                        match event.kind {
                            StopKind::Breakpoint { .. } if self.client.swbreak => {
                                reply.push_str("swbreak:;");
                            }
                            StopKind::HardwareBreakpoint { .. } if self.client.hwbreak => {
                                reply.push_str("hwbreak:;");
                            }
                            StopKind::Watchpoint { addr, access } => reply.push_str(&format!(
                                "{}:{addr:x};",
                                if access == WatchAccess::Write {
                                    "watch"
                                } else {
                                    "awatch"
                                }
                            )),
                            StopKind::Fork { child } if self.client.fork_events => {
                                reply.push_str(&format!(
                                    "fork:p{}.{};",
                                    hex_id(child.tgid),
                                    hex_id(child.tgid)
                                ));
                            }
                            StopKind::Vfork { child } if self.client.vfork_events => {
                                reply.push_str(&format!(
                                    "vfork:p{}.{};",
                                    hex_id(child.tgid),
                                    hex_id(child.tgid)
                                ));
                            }
                            StopKind::VforkDone { .. } if self.client.vfork_events => {
                                reply.push_str("vforkdone:;");
                            }
                            StopKind::Exec if self.client.exec_events => {
                                let path = self
                                    .debugger
                                    .get(pid)
                                    .and_then(|inferior| inferior.exec_path.clone())
                                    .unwrap_or_default();
                                reply.push_str(&format!("exec:{};", to_hex(path.as_bytes())));
                            }
                            _ => {}
                        }
                    }
                }
                reply.into_bytes()
            }
        }
    }

    // ---- non-stop ---------------------------------------------------------------

    /// Collect what the threads did and tell the client, one notification at a
    /// time (the next waits for the client's `vStopped`).
    pub(super) fn serve_nonstop(&mut self) -> Result<(), DebugError> {
        let happenings = self.debugger.poll_nonstop()?;
        for happening in happenings {
            (self.on_state)(&describe(&happening));
            if self.debugger.inferiors.len() > 1 {
                self.client.multi_seen = true;
            }
            let payload = self.stop_reply(&happening);
            self.client.queue.push_back(payload);
            if let Happening::Exited { pid, .. } = happening {
                self.debugger.reap(pid);
            }
        }
        if self.client.held.is_none()
            && let Some(next) = self.client.queue.pop_front()
        {
            let framed = encode_notification("Stop", &next);
            self.client.held = Some(next);
            self.write(&framed)?;
        }
        Ok(())
    }

    /// Stop every thread of every process (non-stop `vCont;t` without threads).
    pub(super) fn stop_all_threads(&mut self) -> Result<(), DebugError> {
        for pid in self.debugger.pids() {
            if let Some(inferior) = self.debugger.get(pid)
                && inferior.is_live()
            {
                inferior.backend.thread_action(None, ThreadAction::Stop)?;
            }
        }
        Ok(())
    }

    // ---- dispatch ---------------------------------------------------------------

    pub(super) fn dispatch(&mut self, packet: &[u8]) -> Result<Option<Outcome>, DebugError> {
        let handled = self.handle(packet);
        let reply = handled?;
        match reply {
            Reply::Packet(payload) => self.reply(&payload)?,
            Reply::Later => {}
            Reply::Then(payload, outcome) => {
                self.reply(&payload)?;
                if self.client.nonstop && self.client.held.is_some() {
                    self.answer_last_acknowledgement();
                }
                return Ok(Some(outcome));
            }
        }
        if self.client.switch_to_no_ack {
            self.client.switch_to_no_ack = false;
            self.client.no_ack = true;
        }
        // A stop that was pending when the client resumed is reported at once.
        if self.client.waiting
            && !self.client.nonstop
            && let Some(happening) = self.debugger.take_unreported()
        {
            return self.report(happening);
        }
        Ok(None)
    }

    pub(super) fn handle(&mut self, packet: &[u8]) -> Result<Reply, DebugError> {
        let Some(&first) = packet.first() else {
            return Ok(unsupported());
        };
        let rest = &packet[1..];
        match first {
            b'?' => self.status(),
            b'!' => Ok(ok()),
            b'g' => self.read_registers(),
            b'G' => self.write_registers(rest),
            b'p' => self.read_register(rest),
            b'P' => self.write_register(rest),
            b'm' => self.read_memory(rest),
            b'M' => self.write_memory(rest, false),
            b'X' => self.write_memory(rest, true),
            b'Z' => self.breakpoint(rest, true),
            b'z' => self.breakpoint(rest, false),
            b'H' => self.select_thread(rest),
            b'T' => self.thread_alive(rest),
            b'D' => self.detach(rest),
            b'k' => self.kill_all(),
            b'c' | b's' => self.old_resume(first, rest),
            b'C' | b'S' => self.old_resume_signal(first, rest),
            b'v' => self.v_packet(packet),
            b'q' => self.query(packet),
            b'Q' => self.set(packet),
            _ => Ok(unsupported()),
        }
    }

    // ---- selecting the process and thread of a request ----------------------------

    /// The process a request is about.
    pub(super) fn target_pid(&mut self) -> Option<u32> {
        let sel = self.client.general;
        match sel.pid {
            Some(pid) if pid != ALL_PROCESSES => {
                self.debugger.inferiors.contains_key(&pid).then_some(pid)
            }
            _ => match sel.tid {
                TidSel::One(tid) => self.debugger.owner_of(tid).or(Some(self.debugger.current)),
                _ => Some(self.debugger.current),
            },
        }
    }
    /// The thread of g/G/p/P: the selected one, else the thread of the last stop.
    pub(super) fn target_tid(&mut self, pid: u32) -> Option<u32> {
        if let TidSel::One(tid) = self.client.general.tid {
            return Some(tid);
        }
        self.debugger.get(pid).map(|inferior| inferior.current_tid)
    }
    pub(super) fn with_inferior<T>(
        &mut self,
        f: impl FnOnce(&mut Inferior) -> Result<T, DebugError>,
    ) -> Result<Result<T, DebugError>, DebugError> {
        let Some(pid) = self.target_pid() else {
            return Ok(Err(DebugError::Gone));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(Err(DebugError::Gone));
        };
        Ok(f(inferior))
    }

    // ---- running ---------------------------------------------------------------------------

    pub(super) fn v_packet(&mut self, packet: &[u8]) -> Result<Reply, DebugError> {
        if let Some(list) = packet.strip_prefix(b"vCont") {
            self.release_deferred();
            return match list.first() {
                Some(b'?') => Ok(text("vCont;c;C;s;S;t")),
                Some(b';') => match parse_vcont(&list[1..]) {
                    Some(actions) => self.vcont(&actions),
                    None => Ok(errno(22)),
                },
                _ => Ok(unsupported()),
            };
        }
        if packet == b"vStopped" {
            return Ok(self.next_notification());
        }
        if packet == b"vCtrlC" {
            if self.client.nonstop {
                self.stop_all_threads()?;
            } else if let Some(outcome) = self.interrupted()? {
                let _ = outcome;
            }
            return Ok(ok());
        }
        if let Some(pid) = packet.strip_prefix(b"vKill;") {
            return match parse_hex(pid).and_then(|pid| u32::try_from(pid).ok()) {
                Some(pid) => self.kill_one(pid),
                None => Ok(errno(22)),
            };
        }
        Ok(unsupported())
    }

    fn vcont(&mut self, actions: &[Action]) -> Result<Reply, DebugError> {
        if self.client.nonstop {
            return self.vcont_nonstop(actions);
        }
        let mut resumed = false;
        for pid in self.debugger.pids() {
            let current = self.debugger.get(pid).map(|inferior| inferior.current_tid);
            let Some(current) = current else { continue };
            if !self
                .debugger
                .get(pid)
                .is_some_and(|inferior| inferior.is_stopped())
            {
                continue;
            }
            let mut step: Option<(u32, Option<u8>)> = None;
            let mut cont = false;
            let mut cont_signal: Option<(u32, u8)> = None;
            for action in actions.iter().filter(|action| action_covers(action, pid)) {
                let tid = match action.sel.map(|sel| sel.tid) {
                    Some(TidSel::One(tid)) => tid,
                    _ => current,
                };
                match action.kind {
                    ActionKind::Step(signal) if step.is_none() => step = Some((tid, signal)),
                    ActionKind::Continue(signal) => {
                        cont = true;
                        if let Some(signal) = signal
                            && cont_signal.is_none()
                        {
                            cont_signal = Some((tid, signal));
                        }
                    }
                    _ => {}
                }
            }
            let action = if let Some((tid, signal)) = step {
                match signal.and_then(gdb_to_linux) {
                    Some(signal) => ResumeAction::StepSignal { tid, signal },
                    None => ResumeAction::Step { tid },
                }
            } else if cont {
                match cont_signal.and_then(|(tid, signal)| Some((tid, gdb_to_linux(signal)?))) {
                    Some((tid, signal)) => ResumeAction::ContinueSignal { tid, signal },
                    None => ResumeAction::Continue,
                }
            } else {
                continue;
            };
            self.debugger.resume(pid, action)?;
            resumed = true;
        }
        if !resumed {
            // Nothing was asked to run: say where things stand.
            return self.status();
        }
        self.client.waiting = true;
        Ok(Reply::Later)
    }

    fn vcont_nonstop(&mut self, actions: &[Action]) -> Result<Reply, DebugError> {
        for action in actions {
            for pid in self.debugger.pids() {
                if !action_covers(action, pid) {
                    continue;
                }
                let (tid, all) = match action.sel.map(|sel| sel.tid) {
                    Some(TidSel::One(tid)) => (Some(tid), false),
                    _ => (None, true),
                };
                let Some(inferior) = self.debugger.get(pid) else {
                    continue;
                };
                if !inferior.is_live() {
                    continue;
                }
                // A bare thread id names a thread of one process only.
                if let (Some(tid), None) = (tid, action.sel.and_then(|sel| sel.pid))
                    && !inferior.threads()?.iter().any(|thread| thread.tid == tid)
                {
                    continue;
                }
                let what = match action.kind {
                    ActionKind::Stop => ThreadAction::Stop,
                    ActionKind::Continue(signal) => ThreadAction::Continue {
                        signal: signal.and_then(gdb_to_linux).unwrap_or(0),
                    },
                    ActionKind::Step(signal) => ThreadAction::Step {
                        signal: signal.and_then(gdb_to_linux).unwrap_or(0),
                    },
                };
                if all && matches!(what, ThreadAction::Step { .. }) {
                    continue;
                }
                inferior.invalidate();
                if let Err(error) = inferior.backend.thread_action(tid, what) {
                    return report(error);
                }
            }
        }
        Ok(ok())
    }

    /// `c` and `s` (with an optional address we do not support).
    pub(super) fn old_resume(&mut self, op: u8, rest: &[u8]) -> Result<Reply, DebugError> {
        if !rest.is_empty() {
            return Ok(errno(22));
        }
        let kind = if op == b'c' {
            ActionKind::Continue(None)
        } else {
            ActionKind::Step(None)
        };
        self.vcont(&[Action { kind, sel: None }])
    }
    pub(super) fn old_resume_signal(&mut self, op: u8, rest: &[u8]) -> Result<Reply, DebugError> {
        let digits = rest.split(|byte| *byte == b';').next().unwrap_or(rest);
        let Some(signal) = parse_hex(digits).and_then(|n| u8::try_from(n).ok()) else {
            return Ok(errno(22));
        };
        let kind = if op == b'C' {
            ActionKind::Continue(Some(signal))
        } else {
            ActionKind::Step(Some(signal))
        };
        self.vcont(&[Action { kind, sel: None }])
    }

    // ---- detach and kill -----------------------------------------------------------------

    /// `D` leaves the session (the processes run on, their sessions stay for the
    /// panel); `D;pid` releases one process for good when others remain.
    pub(super) fn detach(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let pid = rest
            .strip_prefix(b";")
            .and_then(parse_hex)
            .and_then(|pid| u32::try_from(pid).ok());
        if let Some(pid) = pid
            && self.debugger.inferiors.len() > 1
        {
            if !self.debugger.inferiors.contains_key(&pid) {
                return Ok(errno(1));
            }
            if self.debugger.nonstop {
                self.stop_one_for_detach(pid)?;
            }
            return match self.debugger.detach(pid, DetachMode::Resume, false) {
                Ok(()) => Ok(ok()),
                Err(error) => report(error),
            };
        }
        Ok(Reply::Then(
            b"OK".to_vec(),
            Outcome::ClientGone("detached".into()),
        ))
    }

    /// A non-stop process is stopped before it can be released (its breakpoints
    /// are in memory).
    pub(super) fn stop_one_for_detach(&mut self, pid: u32) -> Result<(), DebugError> {
        if let Some(inferior) = self.debugger.get(pid) {
            inferior.backend.thread_action(None, ThreadAction::Stop)?;
            let until = Instant::now() + INTERRUPT_DEADLINE;
            while inferior.threads()?.iter().any(|thread| !thread.stopped) {
                if Instant::now() >= until {
                    break;
                }
                thread::sleep(RUNNING_POLL);
            }
            inferior.with_registry(|registry, backend| registry.clear_client(backend));
        }
        Ok(())
    }

    pub(super) fn kill_one(&mut self, pid: u32) -> Result<Reply, DebugError> {
        if !self.debugger.inferiors.contains_key(&pid) {
            return Ok(errno(1));
        }
        if let Some(inferior) = self.debugger.get(pid) {
            inferior.with_registry(|registry, backend| registry.clear_client(backend));
        }
        match self.debugger.detach(pid, DetachMode::Kill, true) {
            Ok(()) => {}
            Err(error) => return report(error),
        }
        if self.debugger.any_live() {
            Ok(ok())
        } else {
            Ok(Reply::Then(
                b"OK".to_vec(),
                Outcome::TargetGone("killed by the debugger".into()),
            ))
        }
    }

    pub(super) fn kill_all(&mut self) -> Result<Reply, DebugError> {
        for pid in self.debugger.pids() {
            if let Some(inferior) = self.debugger.get(pid) {
                inferior.with_registry(|registry, backend| registry.clear_client(backend));
            }
            let _ = self.debugger.detach(pid, DetachMode::Kill, true);
        }
        // `k` has no reply.
        Ok(Reply::Then(
            Vec::new(),
            Outcome::TargetGone("killed by the debugger".into()),
        ))
    }
}
