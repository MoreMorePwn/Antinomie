// SPDX-License-Identifier: MIT
//! The processes of one debugger session. Following a fork turns a child the
//! guest holds parked into an inferior here; the controllers (an RSP client or the
//! in-app panel) decide which to run, follow or let go. All-stop and non-stop
//! polling live here so both controllers see the same events.
use super::{
    inferior::{Inferior, Registry, RunState},
    target::{
        ChildRef, DebugBackend, DebugError, DetachMode, ResumeAction, SessionOptions, StopEvent,
        StopKind, TargetState, ThreadAction,
    },
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

/// How long the other processes get to stop when one has stopped (all-stop).
const STOP_OTHERS_DEADLINE: Duration = Duration::from_secs(5);
const POLL_SLEEP: Duration = Duration::from_millis(1);

/// A process of a session the guest already had, with where it came from.
pub struct AdoptedChild {
    pub backend: Box<dyn DebugBackend>,
    /// The guest's id of the session of the process that forked it.
    pub parent_session: u64,
    pub shared_memory: bool,
    pub nonstop: bool,
}

/// Something a controller has to react to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Happening {
    /// A process (all-stop) or a thread of it (non-stop) stopped at an event.
    Stopped { pid: u32, event: StopEvent },
    /// The process ended; the value is its wait status.
    Exited { pid: u32, wait_status: u32 },
}

pub(super) struct Debugger {
    pub(super) inferiors: BTreeMap<u32, Inferior>,
    pub(super) root: u32,
    /// The process requests go to when they name none.
    pub(super) current: u32,
    pub(super) nonstop: bool,
    options: SessionOptions,
    /// What happened that a user may want to read (a child that could not be
    /// followed, a breakpoint that had to be set again).
    pub(super) log: Vec<String>,
}

impl Debugger {
    pub(super) fn new(root: Box<dyn DebugBackend>) -> Self {
        let pid = root.target_pid();
        let inferior = Inferior::new(
            pid,
            root,
            None,
            false,
            Rc::new(RefCell::new(Registry::default())),
        );
        let mut inferiors = BTreeMap::new();
        inferiors.insert(pid, inferior);
        Self {
            inferiors,
            root: pid,
            current: pid,
            nonstop: false,
            options: SessionOptions::default(),
            log: Vec::new(),
        }
    }

    pub(super) fn get(&mut self, pid: u32) -> Option<&mut Inferior> {
        self.inferiors.get_mut(&pid)
    }
    pub(super) fn current_mut(&mut self) -> Option<&mut Inferior> {
        self.inferiors.get_mut(&self.current)
    }
    pub(super) fn pids(&self) -> Vec<u32> {
        self.inferiors.keys().copied().collect()
    }
    pub(super) fn any_live(&self) -> bool {
        self.inferiors.values().any(Inferior::is_live)
    }
    pub(super) fn any_running(&self) -> bool {
        self.inferiors.values().any(Inferior::is_running)
    }
    /// The inferior whose thread `tid` is (thread ids are unique in the guest).
    pub(super) fn owner_of(&mut self, tid: u32) -> Option<u32> {
        if self.inferiors.contains_key(&tid) {
            return Some(tid);
        }
        let pids = self.pids();
        for pid in pids {
            let inferior = self.inferiors.get_mut(&pid)?;
            if !inferior.is_live() {
                continue;
            }
            if inferior
                .threads()
                .is_ok_and(|threads| threads.iter().any(|thread| thread.tid == tid))
            {
                return Some(pid);
            }
        }
        None
    }

    /// Ask the guest to follow forks and execs (when it can) for the root and
    /// every child to come. Not an error when it cannot: the session then behaves
    /// as in phase 2.
    pub(super) fn follow_forks(&mut self, on: bool) {
        let caps = self.inferiors[&self.root].backend.caps().clone();
        if !caps.follow {
            return;
        }
        self.options.fork = on;
        self.options.exec = on;
        let options = self.options;
        for inferior in self.inferiors.values_mut().filter(|i| i.is_live()) {
            if let Err(error) = inferior.backend.configure(options) {
                self.log
                    .push(format!("cannot follow forks in {}: {error}", inferior.pid));
            }
        }
    }

    /// A session the guest already had (found after a reconnect or a restored
    /// snapshot): the processes it held, with the breakpoints the guest knows as
    /// the panel's.
    pub(super) fn adopt_existing(&mut self, children: Vec<AdoptedChild>) {
        self.adopt_registry(self.root);
        for child in children {
            let parent = self
                .inferiors
                .values()
                .find(|inferior| inferior.backend.session_id() == child.parent_session)
                .map(|inferior| (inferior.pid, inferior.registry.clone()));
            let pid = child.backend.target_pid();
            let registry = match (&parent, child.shared_memory) {
                (Some((_, registry)), true) => registry.clone(),
                _ => Rc::new(RefCell::new(Registry::default())),
            };
            let mut inferior = Inferior::new(
                pid,
                child.backend,
                parent.as_ref().map(|(pid, _)| *pid),
                child.shared_memory,
                registry,
            );
            inferior.nonstop = child.nonstop;
            self.inferiors.insert(pid, inferior);
            if !child.shared_memory {
                self.adopt_registry(pid);
            }
        }
        self.nonstop = self.inferiors.values().any(|inferior| inferior.nonstop);
        self.options.nonstop = self.nonstop;
    }

    /// What the guest holds for a process becomes the panel's.
    fn adopt_registry(&mut self, pid: u32) {
        if let Some(inferior) = self.inferiors.get_mut(&pid)
            && let Ok(held) = inferior.backend.guest_breakpoints()
        {
            inferior.registry.borrow_mut().adopt_guest(&held);
        }
    }

    /// Non-stop to all-stop: every thread is stopped (they keep their stops).
    pub(super) fn leave_nonstop(&mut self) -> Result<(), DebugError> {
        if !self.nonstop {
            return Ok(());
        }
        for inferior in self.inferiors.values_mut().filter(|i| i.is_live()) {
            let _ = inferior.backend.thread_action(None, ThreadAction::Stop);
            let until = Instant::now() + STOP_OTHERS_DEADLINE;
            while inferior
                .threads()
                .is_ok_and(|threads| threads.iter().any(|thread| !thread.stopped))
                && Instant::now() < until
            {
                thread::sleep(POLL_SLEEP);
            }
            inferior.with_registry(|registry, backend| registry.clear_client(backend));
        }
        self.set_nonstop(false)
    }

    /// Switch every process between all-stop and non-stop. Needs them stopped.
    pub(super) fn set_nonstop(&mut self, on: bool) -> Result<(), DebugError> {
        if on == self.nonstop {
            return Ok(());
        }
        if on && !self.inferiors[&self.root].backend.caps().nonstop {
            return Err(DebugError::Unsupported("non-stop".into()));
        }
        self.options.nonstop = on;
        self.options.exec |= self.options.fork;
        let options = self.options;
        for inferior in self.inferiors.values_mut().filter(|i| i.is_live()) {
            inferior.backend.configure(options)?;
            inferior.nonstop = on;
            inferior.acknowledged = 0;
            inferior.reported_sequence = 0;
        }
        self.nonstop = on;
        Ok(())
    }

    // ---- polling -------------------------------------------------------------

    /// All-stop: look at every running process once. A stop of one stops the
    /// others (they are interrupted and waited for); their own events, if they
    /// had real ones, stay pending on them.
    pub(super) fn poll(&mut self) -> Result<Vec<Happening>, DebugError> {
        let mut out = Vec::new();
        for pid in self.pids() {
            if self.inferiors.get(&pid).is_some_and(Inferior::is_running) {
                self.poll_one(pid, &mut out)?;
            }
        }
        if out
            .iter()
            .any(|happening| matches!(happening, Happening::Stopped { .. }))
        {
            self.stop_others(&mut out)?;
        }
        Ok(out)
    }

    fn poll_one(&mut self, pid: u32, out: &mut Vec<Happening>) -> Result<(), DebugError> {
        let state = match self.inferiors.get_mut(&pid) {
            Some(inferior) => inferior.backend.state(),
            None => return Ok(()),
        };
        match state {
            Ok(TargetState::Running | TargetState::Transition) => {}
            Ok(TargetState::Stopped(event)) => self.stopped(pid, event, out),
            Ok(TargetState::Exited { wait_status }) => self.exited(pid, wait_status, out),
            Ok(TargetState::Replaced) => self.exited(pid, 0, out),
            Err(DebugError::Gone) => self.exited(pid, 0, out),
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn exited(&mut self, pid: u32, wait_status: u32, out: &mut Vec<Happening>) {
        if let Some(inferior) = self.inferiors.get_mut(&pid) {
            inferior.run = RunState::Exited(wait_status);
            inferior.unreported = true;
            out.push(Happening::Exited { pid, wait_status });
        }
    }

    /// Take in a stop found already standing (a connect): the same as one seen
    /// while polling, without telling anyone.
    pub(super) fn take_stop(&mut self, pid: u32, event: StopEvent) {
        self.stopped(pid, event, &mut Vec::new());
        // Only an event the client must hear of stays unreported.
        if !matches!(
            event.kind,
            StopKind::Fork { .. }
                | StopKind::Vfork { .. }
                | StopKind::VforkDone { .. }
                | StopKind::Exec
        ) && let Some(inferior) = self.inferiors.get_mut(&pid)
        {
            inferior.unreported = false;
        }
    }

    /// A process (or, in non-stop, one thread of it) stopped at `event`.
    fn stopped(&mut self, pid: u32, event: StopEvent, out: &mut Vec<Happening>) {
        let mut event = event;
        match event.kind {
            StopKind::Fork { child } | StopKind::Vfork { child } => {
                if let Err(error) = self.adopt_child(pid, &child) {
                    self.log.push(format!(
                        "could not follow the child {} of {pid}: {error}",
                        child.tgid
                    ));
                    event.kind = StopKind::Interrupt;
                }
            }
            StopKind::Exec => {
                if let Some(inferior) = self.inferiors.get_mut(&pid) {
                    inferior.image_replaced();
                }
            }
            _ => {}
        }
        if let Some(inferior) = self.inferiors.get_mut(&pid) {
            inferior.invalidate();
            inferior.current_tid = event.tid;
            inferior.last_sequence = Some(event.sequence);
            if !inferior.nonstop {
                inferior.run = RunState::Stopped(event);
                inferior.unreported = true;
                inferior.refresh_auxv();
            }
        }
        out.push(Happening::Stopped { pid, event });
    }

    /// The guest holds a child process; make it an inferior.
    fn adopt_child(&mut self, parent: u32, child: &ChildRef) -> Result<(), DebugError> {
        let registry = if child.shared_memory {
            self.inferiors[&parent].registry.clone()
        } else {
            Rc::new(RefCell::new(Registry::default()))
        };
        let backend = self
            .inferiors
            .get_mut(&parent)
            .ok_or(DebugError::Gone)?
            .backend
            .adopt_child(child)?;
        let mut inferior = Inferior::new(
            child.tgid,
            backend,
            Some(parent),
            child.shared_memory,
            registry,
        );
        inferior.nonstop = self.nonstop;
        // Held where the fork put it: stopped, not news.
        if !self.nonstop
            && let Ok(TargetState::Stopped(event)) = inferior.backend.state()
        {
            inferior.run = RunState::Stopped(event);
            inferior.last_sequence = Some(event.sequence);
        } else if self.nonstop {
            inferior.run = RunState::Running;
        }
        inferior.unreported = false;
        self.inferiors.insert(child.tgid, inferior);
        Ok(())
    }

    /// All-stop: every other process that runs is stopped. A real event one of
    /// them had meanwhile stays pending on it.
    fn stop_others(&mut self, out: &mut Vec<Happening>) -> Result<(), DebugError> {
        let running: Vec<u32> = self
            .inferiors
            .iter()
            .filter(|(_, inferior)| inferior.is_running())
            .map(|(pid, _)| *pid)
            .collect();
        for pid in &running {
            if let Some(inferior) = self.inferiors.get_mut(pid) {
                let _ = inferior.backend.interrupt();
            }
        }
        let deadline = Instant::now() + STOP_OTHERS_DEADLINE;
        let mut waiting = running;
        while !waiting.is_empty() {
            let mut still = Vec::new();
            for pid in waiting {
                let state = match self.inferiors.get_mut(&pid) {
                    Some(inferior) => inferior.backend.state(),
                    None => continue,
                };
                match state {
                    Ok(TargetState::Stopped(event)) => {
                        let mut quiet = Vec::new();
                        self.stopped(pid, event, &mut quiet);
                        // Our own interrupt is not news; anything else is kept.
                        if event.kind == StopKind::Interrupt
                            && let Some(inferior) = self.inferiors.get_mut(&pid)
                        {
                            inferior.unreported = false;
                        } else {
                            out.extend(quiet);
                        }
                    }
                    Ok(TargetState::Exited { wait_status }) => self.exited(pid, wait_status, out),
                    Ok(TargetState::Replaced) | Err(DebugError::Gone) => self.exited(pid, 0, out),
                    Ok(_) => still.push(pid),
                    Err(error) => return Err(error),
                }
            }
            if still.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                self.log
                    .push("a process did not stop in time; it keeps running".into());
                break;
            }
            waiting = still;
            thread::sleep(POLL_SLEEP);
        }
        Ok(())
    }

    /// Non-stop: the events every process has not yet had reported.
    pub(super) fn poll_nonstop(&mut self) -> Result<Vec<Happening>, DebugError> {
        let mut out = Vec::new();
        for pid in self.pids() {
            let Some(inferior) = self.inferiors.get_mut(&pid) else {
                continue;
            };
            if !inferior.is_live() {
                continue;
            }
            let batch = match inferior.backend.events(inferior.reported_sequence) {
                Ok(batch) => batch,
                Err(DebugError::Gone) => {
                    self.exited(pid, 0, &mut out);
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(wait_status) = batch.exited {
                self.exited(pid, wait_status, &mut out);
                continue;
            }
            if batch.dropped > 0 {
                self.log
                    .push(format!("{} events of {pid} were lost", batch.dropped));
            }
            for event in batch.events {
                let Some(inferior) = self.inferiors.get_mut(&pid) else {
                    break;
                };
                if event.sequence <= inferior.reported_sequence {
                    continue;
                }
                inferior.reported_sequence = event.sequence;
                self.stopped(pid, event, &mut out);
            }
        }
        Ok(out)
    }

    /// The first process with an event nobody has been told about.
    pub(super) fn take_unreported(&mut self) -> Option<Happening> {
        for (pid, inferior) in &mut self.inferiors {
            if !inferior.unreported {
                continue;
            }
            match inferior.run {
                RunState::Stopped(event) => {
                    inferior.unreported = false;
                    return Some(Happening::Stopped { pid: *pid, event });
                }
                RunState::Exited(wait_status) => {
                    inferior.unreported = false;
                    return Some(Happening::Exited {
                        pid: *pid,
                        wait_status,
                    });
                }
                _ => {}
            }
        }
        None
    }

    // ---- control -------------------------------------------------------------

    pub(super) fn resume(&mut self, pid: u32, action: ResumeAction) -> Result<(), DebugError> {
        let inferior = self.inferiors.get_mut(&pid).ok_or(DebugError::Gone)?;
        inferior.note_resumed();
        // On an error it is still where it was.
        inferior.backend.resume(action)
    }

    /// Release one process: its breakpoints go (the client's; the panel's with
    /// `all`), the guest lets it run (or kills it), and it is no longer ours.
    pub(super) fn detach(
        &mut self,
        pid: u32,
        mode: DetachMode,
        all_breakpoints: bool,
    ) -> Result<(), DebugError> {
        let Some(mut inferior) = self.inferiors.remove(&pid) else {
            return Ok(());
        };
        if inferior.is_stopped() && mode == DetachMode::Resume {
            if all_breakpoints {
                inferior.registry.borrow_mut().forget();
            } else {
                inferior.with_registry(|registry, backend| registry.clear_client(backend));
            }
        }
        let result = inferior.backend.detach(mode);
        if self.current == pid {
            self.current = *self.inferiors.keys().next().unwrap_or(&self.root);
        }
        result
    }

    /// Forget a process whose end was reported, and tell the guest it may drop
    /// the session.
    pub(super) fn reap(&mut self, pid: u32) {
        if let Some(mut inferior) = self.inferiors.remove(&pid) {
            let _ = inferior.backend.detach(DetachMode::Resume);
        }
        if self.current == pid {
            self.current = *self.inferiors.keys().next().unwrap_or(&self.root);
        }
    }
}
