// SPDX-License-Identifier: GPL-3.0-only
//! Start what a run persisted once its tree ended early
//! ([`crate::persist_start`]): choose the entries a little after the tree's
//! end, start each with the guest's EXEC as a boot or login would, fold the
//! starter's telemetry into the run, follow each starter's status, and hold
//! the run open until what was started has ended or the run is stopped.
use super::*;
use crate::persist_start::{
    self, DECIDE_AFTER, HOLD_MAX, POLL, PersistenceStart, StartedEntry, Starter,
};

/// The starter's EXEC reply: the session, the root task cookie, the pid.
const STARTER_REPLY: usize = 24;

impl ProgramRun {
    /// Entries Antinomie started still hold the run, or still write into its
    /// recording.
    pub(crate) fn persistence_busy(&self) -> bool {
        self.summary.persistence_holding() || self.starting.any_live()
    }

    /// The guest said the run's tree ended. With the option on, the run is
    /// held open at once (set with the status that ends the tree, so no
    /// snapshot shows the run ended before the entries are chosen).
    pub(super) fn persistence_tree_ended(&mut self) {
        if self.starting.tree_ended.is_some() {
            return;
        }
        self.starting.tree_ended = Some(Instant::now());
        let now = unix_ms();
        let elapsed = now.saturating_sub(self.summary.started_ms.unwrap_or(now));
        let hold = self.summary.request.start_persistence.is_some()
            && !self.summary.stop_requested()
            && self.watch.is_some();
        if hold {
            self.summary.persistence_start = Some(PersistenceStart {
                tree_ended_after_ms: elapsed,
                holding: true,
                hold_started_ms: Some(now),
                ..PersistenceStart::default()
            });
            self.starting.hold_since = Some(Instant::now());
        } else {
            // Kept only if the run turns out to have persisted something.
            self.summary.persistence_start = Some(PersistenceStart {
                tree_ended_after_ms: elapsed,
                ..PersistenceStart::default()
            });
        }
    }

    /// Choose the entries, or say why none is started; `can_start` is false
    /// when the recording is ending.
    fn persistence_decide(&mut self, can_start: bool) {
        self.starting.decided = true;
        let written = self
            .watch
            .as_mut()
            .map(|watch| std::mem::take(&mut watch.written))
            .unwrap_or_default();
        let Some(mut record) = self.summary.persistence_start.take() else {
            return;
        };
        let installed = written
            .iter()
            .any(|row| !row.failed && row.rule.starts_with("persistence."));
        if !installed {
            // Nothing persisted: the run ends as it would have.
            return;
        }
        let request = &self.summary.request;
        let home = persist_start::run_home(request.uid, &request.env);
        let (entries, more) = persist_start::select(&written, (request.uid, request.gid, &home));
        let elapsed = Duration::from_millis(record.tree_ended_after_ms);
        let refusal = persist_start::refusal(
            request.start_persistence.as_ref(),
            elapsed,
            self.summary.stop_requested(),
            true,
        )
        .or_else(|| {
            (!can_start).then(|| {
                format!(
                    "the tree ended after {}; the recording ended before the persistence it installed could be started",
                    persist_start::elapsed_words(elapsed)
                )
            })
        })
        .or_else(|| {
            entries.is_empty().then(|| {
                format!(
                    "the tree ended after {}; the persistence it installed is of no kind Antinomie starts (systemd services, init scripts, rc.local, cron, shell profiles, autostart entries)",
                    persist_start::elapsed_words(elapsed)
                )
            })
        });
        if let Some(reason) = refusal {
            record.holding = false;
            record.hold_started_ms = None;
            self.starting.hold_since = None;
            self.add_note(persist_start::not_started_note(&reason));
            record.not_started = Some(reason);
            self.summary.persistence_start = Some(record);
            return;
        }
        record.entries = entries.iter().map(StartedEntry::of).collect();
        record.more = more;
        record.holding = true;
        self.add_note(persist_start::started_note(&record));
        self.summary.persistence_start = Some(record);
        self.starting.plan = entries.into_iter().enumerate().collect();
        if let Some(log) = self.custody.as_mut() {
            log.action(
                crate::samples::ActionKind::PersistenceStart,
                "Start persistence: the entries the run installed were started by Antinomie",
            );
        }
    }

    /// End the hold for the started entries, saying why. Returns the root
    /// task cookies of the starters still running, to be stopped.
    pub(super) fn end_persistence_hold(&mut self, why: &str) -> Vec<u64> {
        self.starting.decided = true;
        self.starting.plan.clear();
        let mut stop = Vec::new();
        for starter in &mut self.starting.starters {
            if !starter.ended && !starter.stop_sent {
                starter.stop_sent = true;
                stop.push(starter.cookie);
            }
        }
        let Some(record) = self.summary.persistence_start.as_mut() else {
            return stop;
        };
        if !record.holding {
            return stop;
        }
        record.holding = false;
        record.hold_ended = Some(why.to_owned());
        let started = !record.entries.is_empty();
        if record.entries.is_empty() && record.not_started.is_none() {
            // Stopped before anything was chosen: nothing to keep.
            self.summary.persistence_start = None;
        }
        if started {
            self.add_note(format!(
                "The run is no longer held open for the persistence Antinomie started: {why}."
            ));
        }
        stop
    }

    /// The recording ends with the VM: nothing started goes on in it.
    pub(crate) fn persistence_finalize(&mut self) {
        // The VM stopped before the entries were chosen: the notes still say
        // what was installed and why nothing was started.
        if self.starting.tree_ended.is_some() && !self.starting.decided {
            if let Some(record) = self.summary.persistence_start.as_mut() {
                record.holding = false;
            }
            self.persistence_decide(false);
        }
        for starter in &mut self.starting.starters {
            starter.ended = true;
        }
        self.starting.plan.clear();
        if let Some(record) = self.summary.persistence_start.as_mut() {
            if record.holding {
                record.holding = false;
                record.hold_ended = Some("the recording ended (the VM stopped)".into());
            }
            if record.entries.is_empty() && record.not_started.is_none() {
                self.summary.persistence_start = None;
            }
        }
    }
}

impl Worker {
    /// One turn of the start of persisted entries for every run whose tree
    /// ended: choose, start the next entry, read the starters' status, end
    /// the hold.
    pub(super) fn start_persistence(&mut self) {
        if self.snapshot.state != VmState::Running {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let cookies: Vec<u64> = session
            .runs
            .iter()
            .filter(|(_, run)| run.starting.tree_ended.is_some())
            .filter(|(_, run)| !run.starting.decided || run.persistence_busy())
            .map(|(cookie, _)| *cookie)
            .collect();
        for cookie in cookies {
            self.persistence_turn(cookie);
        }
    }

    fn persistence_turn(&mut self, cookie: u64) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(run) = session.runs.get_mut(&cookie) else {
            return;
        };
        if !run.starting.decided {
            let due = run
                .starting
                .tree_ended
                .is_some_and(|at| at.elapsed() >= DECIDE_AFTER)
                && !matches!(
                    run.persisted.final_look,
                    crate::persisted_copy::FinalLook::Pending(_)
                );
            if !due {
                return;
            }
            run.persistence_decide(true);
            let _ = run.persist_summary();
        }
        // A run without a run time is held at most HOLD_MAX.
        let mut stop = Vec::new();
        if run.summary.persistence_holding()
            && run
                .summary
                .request
                .start_persistence
                .as_ref()
                .is_some_and(|option| option.run_limit_s.is_none())
            && run
                .starting
                .hold_since
                .is_some_and(|since| since.elapsed() >= HOLD_MAX)
        {
            stop = run.end_persistence_hold(&format!(
                "the hold limit ({} min) passed; what was started was stopped",
                HOLD_MAX.as_secs() / 60
            ));
            let _ = run.persist_summary();
        }
        if !stop.is_empty() {
            self.stop_starters(&stop);
        }
        self.poll_starters(cookie);
        let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        else {
            return;
        };
        if run.summary.persistence_holding() && run.starting.next_due() {
            self.launch_starter(cookie);
        }
        let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        else {
            return;
        };
        if run.summary.persistence_holding()
            && run.starting.decided
            && run.starting.plan.is_empty()
            && !run.starting.any_live()
        {
            let why = if run.starting.starters.is_empty() {
                "none of the entries could be started"
            } else {
                "every process the started entries ran has ended"
            };
            run.end_persistence_hold(why);
            let _ = run.persist_summary();
        }
    }

    /// Start the next entry of run `run_cookie`.
    fn launch_starter(&mut self, run_cookie: u64) {
        let offered = control::tracer_offer(self.snapshot.guest_tracer).unwrap_or(0);
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let timeout = session.reply_timeout();
        let Some(run) = session.runs.get_mut(&run_cookie) else {
            return;
        };
        let Some((index, entry)) = run.starting.plan.pop_front() else {
            return;
        };
        let request = ExecRequest {
            path: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                persist_start::script(&entry, &run.summary.request.path),
            ],
            cwd: "/".into(),
            env: persist_start::environment(&entry),
            uid: entry.uid,
            gid: entry.gid,
            ..ExecRequest::default()
        };
        // Started as a job of a closed shell (parent init), as a boot would,
        // with the written files hashed; never the root image's hash: the
        // starter's shell is not the run's program.
        let args = control::execute(&request).map(|encoded| {
            control::with_exec_flag(
                encoded,
                offered & (control::EXEC_HASH_WRITES | control::EXEC_SHELL_JOB),
            )
        });
        session.pre_ack.launch_sent(Instant::now());
        let reply = args.and_then(|args| {
            session.request(
                control::EXEC,
                &args,
                &mut self.snapshot,
                &self.sender,
                timeout,
            )
        });
        session.pre_ack.launch_answered();
        let acknowledged = reply.and_then(|reply| {
            if reply.len() != STARTER_REPLY || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0 {
                return Err("the guest's answer to the start was not understood".to_string());
            }
            let cookie = u64_at(&reply, 8).map_err(|e| e.to_string())?;
            let pid = u32_at(&reply, 16).map_err(|e| e.to_string())?;
            if cookie == 0
                || session.runs.contains_key(&cookie)
                || session.persist_alias.contains_key(&cookie)
            {
                return Err("the guest answered the start with a task it already uses".to_string());
            }
            Ok((cookie, pid))
        });
        let Some(mut run) = session.runs.remove(&run_cookie) else {
            return;
        };
        let started_ms = unix_ms();
        match acknowledged {
            Ok((cookie, pid)) => {
                session.persist_alias.insert(cookie, run_cookie);
                if let Some(record) = run
                    .summary
                    .persistence_start
                    .as_mut()
                    .and_then(|record| record.entries.get_mut(index))
                {
                    record.pid = Some(pid);
                    record.task_cookie = Some(cookie);
                    record.started_ms = Some(started_ms);
                }
                run.starting.starters.push(Starter {
                    cookie,
                    index,
                    launched: Instant::now(),
                    generation: 0,
                    last_poll: None,
                    returned: false,
                    ended: false,
                    stop_sent: false,
                });
                // What the starter sent before the answer belongs to the run.
                self.replay_pre_ack(&mut run, cookie);
            }
            Err(error) => {
                if let Some(record) = run
                    .summary
                    .persistence_start
                    .as_mut()
                    .and_then(|record| record.entries.get_mut(index))
                {
                    record.error = Some(format!("not started: {error}"));
                    record.ended = true;
                }
            }
        }
        let _ = run.persist_summary();
        if let Some(session) = self.session.as_mut() {
            session.runs.insert(run_cookie, run);
            session.update_runs(&mut self.snapshot);
        }
    }

    /// Read the status of each live starter of run `run_cookie` that is due.
    fn poll_starters(&mut self, run_cookie: u64) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let due: Vec<(u64, u64)> = session
            .runs
            .get(&run_cookie)
            .map(|run| {
                run.starting
                    .starters
                    .iter()
                    .filter(|starter| !starter.ended)
                    .filter(|starter| starter.last_poll.is_none_or(|at| at.elapsed() >= POLL))
                    .map(|starter| (starter.cookie, starter.generation))
                    .collect()
            })
            .unwrap_or_default();
        if due.is_empty() {
            return;
        }
        let timeout = session.reply_timeout().min(Duration::from_secs(2));
        let mut changed = false;
        for (cookie, generation) in due {
            let read = session
                .request(
                    control::RUN_STATUS,
                    &control::with_session(cookie),
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )
                .and_then(|reply| crate::execution::decode(&reply, cookie, generation));
            let Some(run) = session.runs.get_mut(&run_cookie) else {
                return;
            };
            let Some(starter) = run
                .starting
                .starters
                .iter_mut()
                .find(|starter| starter.cookie == cookie)
            else {
                continue;
            };
            starter.last_poll = Some(Instant::now());
            let Ok(execution) = read else {
                continue;
            };
            starter.generation = execution.generation;
            let returned = execution.root_exit.clone();
            let ended = matches!(
                crate::execution::state(&execution),
                RunState::Finished | RunState::Stopped
            );
            if returned.is_some() == starter.returned && ended == starter.ended {
                continue;
            }
            starter.returned |= returned.is_some();
            starter.ended |= ended;
            let index = starter.index;
            if let Some(record) = run
                .summary
                .persistence_start
                .as_mut()
                .and_then(|record| record.entries.get_mut(index))
            {
                if let Some(status) = returned {
                    record.returned = Some(persist_start::wait_words(status));
                }
                record.ended = ended;
            }
            changed = true;
        }
        if changed && let Some(run) = session.runs.get_mut(&run_cookie) {
            let _ = run.persist_summary();
        }
    }

    /// Stop the starters with these root task cookies (the guest's stop:
    /// SIGTERM, then SIGKILL on a guest that escalates).
    pub(super) fn stop_starters(&mut self, cookies: &[u64]) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let timeout = session.reply_timeout();
        for cookie in cookies {
            let mut args = control::header(0);
            args.extend(cookie.to_le_bytes());
            // A starter whose tree ended meanwhile is refused: nothing to do.
            let _ = session.request(0x1015, &args, &mut self.snapshot, &self.sender, timeout);
        }
    }
}

#[cfg(test)]
mod tests;
