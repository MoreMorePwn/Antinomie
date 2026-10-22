// SPDX-License-Identifier: GPL-3.0-only
//! The panel's handling of several processes and of what the program does to
//! them: forks (follow the parent, the child, or ask), vfork, exec, and the signal
//! table. A child the guest holds parked at its fork is an inferior of the
//! session; the panel's policy decides which process to run and which to let go.
use super::{
    debugger::Debugger,
    inferior::RunState as InferiorRun,
    signal_policy::SignalNote,
    target::{ChildRef, ResumeAction, StopEvent, StopKind},
    ui_control::{Flow, PanelControl, Phase},
    view::{
        FollowMode, ForkChoice, ForkPrompt, InferiorState, InferiorView, Pending, RunState,
        StopReason,
    },
};
use std::time::Instant;

/// Signals the log keeps.
const SIGNAL_LOG_LIMIT: usize = 64;

impl PanelControl {
    /// Tell the guest whether forks and execs are events (once per change).
    pub(super) fn apply_follow_option(&mut self, debugger: &mut Debugger) {
        if !self.caps.follow {
            return;
        }
        let on = self.policy.follow != FollowMode::Off;
        if self.following == Some(on) {
            return;
        }
        debugger.follow_forks(on);
        self.following = Some(on);
        if let Some(note) = debugger.log.pop() {
            self.view.notice = Some(note);
        }
    }

    /// The process list of the view, from the debugger.
    pub(super) fn sync_inferiors(&mut self, debugger: &mut Debugger) {
        self.view.inferiors = debugger
            .inferiors
            .values()
            .map(|inferior| InferiorView {
                pid: inferior.pid,
                parent: inferior.parent,
                selected: inferior.pid == self.selected,
                vfork: inferior.shared_memory,
                state: match inferior.run {
                    InferiorRun::Running => InferiorState::Running,
                    InferiorRun::Stopped(event) => {
                        if self.undecided.contains(&inferior.pid) {
                            InferiorState::Held
                        } else {
                            InferiorState::Stopped(StopReason::from_kind(event.kind))
                        }
                    }
                    InferiorRun::Exited(status) => InferiorState::Exited(status),
                },
            })
            .collect();
    }

    fn note_signal(&mut self, tid: u32, number: u8, passed: bool, stopped: bool) {
        self.view.signal_log.push(SignalNote {
            tid,
            number,
            passed,
            stopped,
        });
        let extra = self.view.signal_log.len().saturating_sub(SIGNAL_LOG_LIMIT);
        self.view.signal_log.drain(..extra);
    }

    /// An event of one process: act on it, or show it.
    pub(super) fn process_stopped(
        &mut self,
        debugger: &mut Debugger,
        pid: u32,
        event: StopEvent,
    ) -> Result<Flow, String> {
        match event.kind {
            StopKind::Signal { signal } => {
                let number = u8::try_from(signal).unwrap_or(0);
                let action = self.signals.action(number);
                if !action.stop {
                    if action.print {
                        self.note_signal(event.tid, number, action.pass, false);
                        self.publish();
                    }
                    let resume = if action.pass {
                        ResumeAction::ContinueSignal {
                            tid: event.tid,
                            signal,
                        }
                    } else {
                        ResumeAction::Continue
                    };
                    return match debugger.resume(pid, resume) {
                        Ok(()) => Ok(Flow::Handled),
                        Err(error) => self.fail(error).map(|()| Flow::Handled),
                    };
                }
                if action.print {
                    self.note_signal(event.tid, number, action.pass, true);
                }
            }
            StopKind::VforkDone { .. } => {
                // The child let go of the memory: not worth a stop.
                return match debugger.resume(pid, ResumeAction::Continue) {
                    Ok(()) => Ok(Flow::Handled),
                    Err(error) => self.fail(error).map(|()| Flow::Handled),
                };
            }
            StopKind::Fork { child } | StopKind::Vfork { child } => {
                return self.forked(debugger, pid, event, child);
            }
            StopKind::Exec => {
                for entry in self.list.entries().to_vec() {
                    self.list.set_enabled(entry.addr, false);
                }
                self.view.notice = Some(
                    "The program executed a new program; breakpoints of the old one were dropped."
                        .into(),
                );
            }
            _ => {}
        }
        if pid != self.selected {
            self.selected = pid;
        }
        self.stopped(debugger, event)?;
        Ok(Flow::Stay)
    }

    /// The program forked: the guest holds the child.
    fn forked(
        &mut self,
        debugger: &mut Debugger,
        parent: u32,
        event: StopEvent,
        child: ChildRef,
    ) -> Result<Flow, String> {
        let vfork = matches!(event.kind, StopKind::Vfork { .. });
        self.undecided.insert(child.tgid);
        let choice = match self.policy.follow {
            FollowMode::Child => ForkChoice::Child,
            FollowMode::Ask => {
                self.prompt = Some(ForkPrompt {
                    parent,
                    child: child.tgid,
                    vfork,
                });
                self.selected = parent;
                self.stopped(debugger, event)?;
                return Ok(Flow::Stay);
            }
            FollowMode::Parent | FollowMode::Off => ForkChoice::Parent,
        };
        self.follow_choice(
            debugger,
            parent,
            child.tgid,
            choice,
            self.policy.detach_other,
        )?;
        Ok(Flow::Handled)
    }

    /// The user's answer to a fork prompt.
    pub(super) fn decide_fork(
        &mut self,
        debugger: &mut Debugger,
        choice: ForkChoice,
        detach_other: bool,
    ) -> Result<(), String> {
        let Some(prompt) = self.prompt.take() else {
            self.view.notice = Some("There is no fork waiting for a decision.".into());
            return Ok(());
        };
        self.follow_choice(debugger, prompt.parent, prompt.child, choice, detach_other)
    }

    /// Carry on with one process of a fork; the other is let go or held.
    fn follow_choice(
        &mut self,
        debugger: &mut Debugger,
        parent: u32,
        child: u32,
        choice: ForkChoice,
        detach_other: bool,
    ) -> Result<(), String> {
        self.undecided.remove(&child);
        let (followed, other) = match choice {
            ForkChoice::Parent => (parent, child),
            ForkChoice::Child => (child, parent),
        };
        if choice == ForkChoice::Child {
            self.copy_panel_breakpoints(debugger, parent, child);
        }
        if detach_other
            && let Err(error) = debugger.detach(other, super::target::DetachMode::Resume, true)
        {
            self.view.notice = Some(format!("could not let process {other} go: {error}"));
        }
        self.show_and_run(debugger, followed)
    }

    /// The panel's breakpoints are about the program, not one process: the
    /// child of a fork gets them too (a vfork child shares its parent's table).
    fn copy_panel_breakpoints(&mut self, debugger: &mut Debugger, parent: u32, child: u32) {
        let Some(shared) = debugger.get(child).map(|inferior| inferior.shared_memory) else {
            return;
        };
        if shared {
            return;
        }
        let items = debugger
            .get(parent)
            .map(|inferior| inferior.registry.borrow().panel_items())
            .unwrap_or_default();
        let Some(inferior) = debugger.get(child) else {
            return;
        };
        for (kind, addr, len) in items {
            let result = inferior.with_registry(|registry, backend| match kind {
                super::view::BreakpointKind::Software => {
                    registry.panel_breakpoint(backend, addr, true)
                }
                kind => registry.panel_hardware(backend, kind, addr, u64::from(len), true),
            });
            if let Err(error) = result {
                self.view.notice = Some(format!(
                    "could not set the breakpoint at {addr:#x} in the child: {error}"
                ));
            }
        }
    }

    /// Show a process and let it run.
    fn show_and_run(&mut self, debugger: &mut Debugger, pid: u32) -> Result<(), String> {
        self.selected = pid;
        match debugger.resume(pid, ResumeAction::Continue) {
            Ok(()) => {}
            Err(error) => return self.fail(error),
        }
        self.view.run = RunState::Running {
            pending: Pending::Nothing,
        };
        self.view.loading = false;
        self.clear_stop_data();
        self.phase = Phase::Moving {
            pending: Pending::Nothing,
            deadline: None,
            next_poll: Instant::now() + self.running_poll,
            from: self.last_stop,
        };
        self.sync_inferiors(debugger);
        Ok(())
    }

    /// Show a process as it is: stopped (fetch it) or running.
    pub(super) fn show_inferior(
        &mut self,
        debugger: &mut Debugger,
        pid: u32,
    ) -> Result<(), String> {
        self.selected = pid;
        let run = debugger.get(pid).map(|inferior| inferior.run);
        match run {
            Some(InferiorRun::Stopped(event)) => self.stopped(debugger, event),
            Some(InferiorRun::Running) => {
                self.view.run = RunState::Running {
                    pending: Pending::Nothing,
                };
                self.clear_stop_data();
                self.phase = Phase::Moving {
                    pending: Pending::Nothing,
                    deadline: None,
                    next_poll: Instant::now() + self.running_poll,
                    from: self.last_stop,
                };
                self.sync_inferiors(debugger);
                Ok(())
            }
            Some(InferiorRun::Exited(status)) => Err(self.exited(status)),
            _ => Err("the guest ended the debug session".into()),
        }
    }

    pub(super) fn select_inferior(
        &mut self,
        debugger: &mut Debugger,
        pid: u32,
    ) -> Result<(), String> {
        if pid == self.selected {
            return Ok(());
        }
        if !debugger.get(pid).is_some_and(|inferior| inferior.is_live()) {
            self.view.notice = Some(format!("process {pid} is not part of the session any more"));
            return Ok(());
        }
        self.show_inferior(debugger, pid)
    }

    pub(super) fn detach_inferior(
        &mut self,
        debugger: &mut Debugger,
        pid: u32,
    ) -> Result<(), String> {
        if !debugger.inferiors.contains_key(&pid) {
            return Ok(());
        }
        self.undecided.remove(&pid);
        if self
            .prompt
            .is_some_and(|prompt| prompt.child == pid || prompt.parent == pid)
        {
            self.prompt = None;
        }
        if let Err(error) = debugger.detach(pid, super::target::DetachMode::Resume, true) {
            self.view.notice = Some(format!("could not let process {pid} go: {error}"));
        }
        if pid == self.selected {
            return self.after_selected_left(debugger, pid);
        }
        Ok(())
    }

    /// The process the panel showed is gone: show another, or end.
    fn after_selected_left(&mut self, debugger: &mut Debugger, gone: u32) -> Result<(), String> {
        let next = debugger
            .inferiors
            .values()
            .find(|inferior| inferior.is_live())
            .map(|inferior| inferior.pid);
        match next {
            Some(pid) => {
                self.view.notice = Some(format!("Process {gone} is gone; showing process {pid}."));
                self.show_inferior(debugger, pid)
            }
            None => Err("the guest ended the debug session".into()),
        }
    }

    /// A process of the session ended.
    pub(super) fn process_exited(
        &mut self,
        debugger: &mut Debugger,
        pid: u32,
        wait_status: u32,
    ) -> Result<Flow, String> {
        self.undecided.remove(&pid);
        let was_selected = pid == self.selected;
        debugger.reap(pid);
        if !debugger.any_live() {
            return Err(self.exited(wait_status));
        }
        if was_selected {
            self.after_selected_left(debugger, pid)?;
        } else {
            self.sync_inferiors(debugger);
            self.publish();
        }
        Ok(Flow::Handled)
    }
}
