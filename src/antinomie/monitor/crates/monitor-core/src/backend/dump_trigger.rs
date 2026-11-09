// SPDX-License-Identifier: GPL-3.0-only
//! Dump on suspicious activity, worker side: turns the findings the live judge
//! queued (see `crate::dump_trigger`) into a core, a memory dump or both,
//! within the run's budget, and keeps the record in `run.json`.
use super::*;
use crate::dump_trigger::{
    LiveFinding, RECORDS_MAX, TriggerDump, TriggerLog, TriggerMiss, TriggerRecord,
};
use crate::observation::GuestProcessIdentity;

/// Free disk space that must remain after a memory dump, bytes.
const DISK_RESERVE: u64 = 1 << 30;

/// A trigger core the guest refused because its process was not there.
struct GoneCore {
    cookie: u64,
    finding: LiveFinding,
    target: GuestProcessIdentity,
    run_id: String,
    root_pid: u32,
    limits: (Option<u32>, Option<u32>),
}

fn failed(error: impl Into<String>) -> TriggerDump {
    TriggerDump {
        state: RunArtifactState::Failed,
        error: Some(error.into()),
        ..TriggerDump::default()
    }
}

/// A core that cannot be taken because the process is gone is not an attempt:
/// its record goes, so the run's budget is kept, and the log keeps the match
/// with the reason it came too late.
fn drop_unattempted(
    log: &mut TriggerLog,
    index: Option<usize>,
    finding: &LiveFinding,
    reason: String,
) {
    if let Some(index) = index {
        log.records.remove(index);
    }
    if log.missed.len() < RECORDS_MAX {
        log.missed.push(TriggerMiss {
            at_ms: unix_ms(),
            finding: finding.clone(),
            reason,
        });
    }
}

impl Worker {
    /// Called every background turn: judge entries that waited for an exit,
    /// act on new findings and follow the dumps that are being written.
    pub(super) fn check_triggers(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let mut found = Vec::new();
        let mut over = Vec::new();
        for (cookie, run) in &mut session.runs {
            let ended = !run.summary.state.is_live() && run.recording_complete();
            let Some(watch) = run.watch.as_mut() else {
                continue;
            };
            watch.tick();
            if ended && !watch.settled {
                // The run is over: what still waits for an exit is judged now,
                // and its notes then say what the trigger did.
                watch.flush();
                over.push(*cookie);
            }
            while let Some(finding) = watch.queue.pop_front() {
                found.push((*cookie, finding));
            }
            if watch.lost > 0 {
                let lost = std::mem::take(&mut watch.lost);
                run.summary
                    .triggers
                    .get_or_insert_with(TriggerLog::default)
                    .lost += lost;
            }
        }
        for (cookie, finding) in found {
            self.take_trigger(cookie, finding);
        }
        for cookie in over {
            self.note_settled_trigger(cookie);
        }
        self.settle_triggers();
    }

    /// A run that is over says in its notes when its trigger took nothing.
    fn note_settled_trigger(&mut self, cookie: u64) {
        let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        else {
            return;
        };
        if run.settle_trigger()
            && let Err(error) = run.persist_summary()
        {
            self.snapshot.last_error = Some(error);
        }
    }

    fn take_trigger(&mut self, cookie: u64, finding: LiveFinding) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(run) = session.runs.get_mut(&cookie) else {
            return;
        };
        let Some(plan) = run.summary.request.dump_trigger.clone() else {
            return;
        };
        let now = unix_ms();
        let log = run.summary.triggers.get_or_insert_with(TriggerLog::default);
        let cooling = log.records.last().is_some_and(|last| {
            now < last
                .at_ms
                .saturating_add(u64::from(plan.cooldown_secs) * 1000)
        });
        if !run.summary.state.is_live() {
            // The run ended before the match was handled: the process is gone
            // too, and a note says by how much the dump was late.
            let reason = match run.watch.as_ref() {
                Some(watch) => format!("The run had already ended. {}", watch.too_late(&finding)),
                None => "The run had already ended before the core could be taken.".into(),
            };
            self.record_too_late(cookie, &finding, reason);
            return;
        }
        if log.records.len() >= plan.max_dumps.min(RECORDS_MAX as u32) as usize || cooling {
            log.skipped += 1;
            if log.skipped == 1
                && let Err(error) = run.persist_summary()
            {
                self.snapshot.last_error = Some(error);
            }
            return;
        }
        let mut record = TriggerRecord {
            at_ms: now,
            finding: finding.clone(),
            memory: None,
            core: None,
        };
        let (run_id, root_pid) = (run.summary.id.clone(), run.summary.pid);
        if plan.core {
            let request = (
                run.summary.request.core_max_size,
                run.summary.request.core_timeout_ms,
            );
            let (mut core, gone) =
                self.queue_trigger_core(&finding, &run_id, root_pid, request, None);
            if gone && core.error.as_deref() == Some("") {
                // The exit is seen while the guest answers the process list.
                core.error = Some(self.too_late_for(cookie, &finding));
            }
            if gone && !plan.memory {
                // Nothing can be taken from a process that is gone: not an
                // attempt, so the budget is kept for the next match.
                let error = core.error.unwrap_or_default();
                self.record_too_late(cookie, &finding, error);
                return;
            }
            record.core = Some(core);
        }
        if plan.memory {
            if record
                .core
                .as_ref()
                .is_some_and(|core| !core.state.is_terminal())
            {
                // Both: the core is taken first; the memory dump pauses the guest.
                record.memory = Some(TriggerDump {
                    state: RunArtifactState::Queued,
                    ..TriggerDump::default()
                });
            } else {
                record.memory =
                    Some(self.start_trigger_memory(plan.memory_max_mib, cookie, &finding));
            }
        }
        let note = format!(
            "Dump triggered by {} ({}) in process {}: {}.",
            finding.rule,
            finding.tier.label(),
            finding.pid,
            [("memory", &record.memory), ("core", &record.core)]
                .iter()
                .filter_map(|(name, dump)| dump.as_ref().map(|dump| match &dump.error {
                    Some(error) if dump.state == RunArtifactState::Failed => {
                        format!("{name} not taken ({error})")
                    }
                    _ => format!("{name} requested"),
                }))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        {
            run.add_note(note);
        }
        self.save_trigger(cookie, |log| log.records.push(record));
        // Start the core now: the first step asks the guest for it.
        self.check_manual_cores();
        let what = self
            .session
            .as_ref()
            .and_then(|session| session.runs.get(&cookie))
            .and_then(|run| run.summary.triggers.as_ref())
            .and_then(|log| log.records.last())
            .map(|record| {
                format!(
                    "dump triggered by {} ({}): {}",
                    finding.rule,
                    finding.tier.label(),
                    finding.summary
                ) + &[&record.core, &record.memory]
                    .iter()
                    .filter_map(|dump| dump.as_ref().and_then(|dump| dump.error.as_deref()))
                    .map(|error| format!("; {error}"))
                    .collect::<String>()
            })
            .unwrap_or_default();
        self.emit(Notification::CommandResult {
            id: 0,
            success: true,
            message: what,
        });
    }

    /// Why a dump of `finding`'s process came too late, from what the run saw.
    fn too_late_for(&self, cookie: u64, finding: &LiveFinding) -> String {
        self.session
            .as_ref()
            .and_then(|session| session.runs.get(&cookie))
            .and_then(|run| run.watch.as_ref())
            .map_or_else(
                || crate::dump_trigger::too_late_text(finding, None),
                |watch| watch.too_late(finding),
            )
    }

    /// A match whose process was gone before its core could be taken: the
    /// run's notes and its trigger log say so plainly, and the budget is kept.
    fn record_too_late(&mut self, cookie: u64, finding: &LiveFinding, reason: String) {
        if let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        {
            run.add_note(format!(
                "Dump skipped for {} ({}, process {}): {reason}",
                finding.rule,
                finding.tier.label(),
                finding.pid
            ));
        }
        self.save_trigger(cookie, |log| {
            drop_unattempted(log, None, finding, reason);
        });
    }

    fn queue_trigger_core(
        &mut self,
        finding: &LiveFinding,
        run_id: &str,
        root_pid: u32,
        (max_size, timeout_ms): (Option<u32>, Option<u32>),
        refused: Option<&GuestProcessIdentity>,
    ) -> (TriggerDump, bool) {
        let Some(session) = self.session.as_mut() else {
            return (failed("the VM is stopped"), false);
        };
        let pid = finding.pid;
        if pid == 0 {
            return (failed("the call names no process"), true);
        }
        let timeout = session.reply_timeout();
        let page = match session.list_processes(
            pid.saturating_sub(1),
            &mut self.snapshot,
            &self.sender,
            timeout,
        ) {
            Ok(page) => page,
            Err(error) => return (failed(format!("process list: {error}")), false),
        };
        let Some(process) = page.processes.iter().find(|p| p.identity.tgid == pid) else {
            // The caller words it once the exit has been seen.
            return (failed(""), true);
        };
        if refused == Some(&process.identity) {
            // The guest already said no to exactly this process.
            return (failed(crate::core_limits::no_core_reason(5, -3).text), true);
        }
        let request = ProcessCoreRequest {
            vm_id: session.vm.id.clone(),
            target: process.identity.clone(),
            source_run_id: (pid == root_pid).then(|| run_id.to_owned()),
            max_size: max_size.unwrap_or(64 << 20),
            timeout_ms: timeout_ms.unwrap_or(5000),
        };
        match session.queue_manual_core(request) {
            Ok(id) => {
                if let Some(owner) = session.manual_cores.get_mut(&id) {
                    owner.eager = true;
                    owner.summary.provenance = Some(crate::provenance::Provenance::trigger(
                        &session.vm.id,
                        &session.boot_id,
                        run_id,
                        finding,
                        unix_ms(),
                    ));
                }
                (
                    TriggerDump {
                        state: RunArtifactState::Queued,
                        capture_id: Some(id),
                        ..TriggerDump::default()
                    },
                    false,
                )
            }
            Err(error) => (failed(error), false),
        }
    }

    fn start_trigger_memory(
        &mut self,
        max_mib: u32,
        cookie: u64,
        finding: &LiveFinding,
    ) -> TriggerDump {
        let Some(session) = self.session.as_ref() else {
            return failed("the VM is stopped");
        };
        let ram = u64::from(session.vm.ram_mib);
        if ram > u64::from(max_mib) {
            return failed(format!(
                "the VM has {ram} MiB of RAM, more than the {max_mib} MiB this trigger may dump"
            ));
        }
        if let Ok(locations) = crate::locations::locations(&self.options, &session.vm.id)
            && let Ok(space) = rustix::fs::statvfs(&locations.recording_directory)
        {
            let free = space.f_bavail.saturating_mul(space.f_frsize);
            let need = (ram << 20).saturating_add(DISK_RESERVE);
            if free < need {
                return failed(format!(
                    "not enough free disk for a {ram} MiB memory dump ({} free)",
                    crate::byte_size::file_size(free)
                ));
            }
        }
        match self.start_memory_dump_for(None, Some((cookie, finding))) {
            Ok(_) => match self.snapshot.memory_dump.as_ref() {
                Some(progress) => TriggerDump {
                    state: RunArtifactState::InProgress,
                    path: Some(progress.dump.dir.clone()),
                    ..TriggerDump::default()
                },
                None => failed("the memory dump did not start"),
            },
            Err(error) => failed(error),
        }
    }

    /// Change one run's log and save `run.json`.
    fn save_trigger(&mut self, cookie: u64, change: impl FnOnce(&mut TriggerLog)) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(run) = session.runs.get_mut(&cookie) else {
            return;
        };
        change(run.summary.triggers.get_or_insert_with(TriggerLog::default));
        if let Err(error) = run.persist_summary() {
            self.snapshot.last_error = Some(error);
        }
        // The run's artifacts say the same: a trigger's cores are listed there,
        // beside the exit core, so the two files agree on what was taken.
        let taken = run
            .summary
            .triggers
            .as_ref()
            .map(|log| log.records.clone())
            .unwrap_or_default();
        if let Some(owner) = session.run_artifacts.get_mut(&cookie)
            && owner.summary.trigger_dumps != taken
        {
            owner.summary.trigger_dumps = taken;
            if let Err(error) = owner.save() {
                self.snapshot.last_error = Some(error);
            }
        }
    }

    /// Follow the cores, and start the memory dump of a trigger once its core
    /// is over.
    fn settle_triggers(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let mut start_memory = Vec::new();
        let mut changed = Vec::new();
        let mut gone = Vec::new();
        let self_dump = self
            .snapshot
            .memory_dump
            .as_ref()
            .map(|p| p.dump.dir.clone());
        for (cookie, run) in &mut session.runs {
            let Some(log) = run.summary.triggers.as_mut() else {
                continue;
            };
            let mut touched = false;
            for (index, record) in log.records.iter_mut().enumerate() {
                if let Some(core) = record.core.as_mut()
                    && core.state.in_progress()
                    && let Some(owner) = core
                        .capture_id
                        .as_ref()
                        .and_then(|id| session.manual_cores.get(id))
                {
                    let summary = &owner.summary;
                    let state = if owner.done {
                        summary.state
                    } else if summary.state.in_progress() {
                        RunArtifactState::InProgress
                    } else {
                        summary.state
                    };
                    let size = summary.stored_bytes.or(Some(summary.stored_size));
                    if core.state != state || core.size != size {
                        core.state = state;
                        core.size = size;
                        core.path = summary
                            .file
                            .clone()
                            .or_else(|| Some(summary.directory.clone()));
                        core.error = summary
                            .reason
                            .as_ref()
                            .map(|reason| reason.text.clone())
                            .or_else(|| summary.issue.clone());
                        touched = true;
                        if state == RunArtifactState::Failed
                            && record.memory.is_none()
                            && summary.reason.as_ref().is_some_and(|reason| {
                                reason.code == crate::core_limits::CoreReasonCode::ProcessGone
                            })
                        {
                            gone.push(GoneCore {
                                cookie: *cookie,
                                finding: record.finding.clone(),
                                target: summary.target.clone(),
                                run_id: run.summary.id.clone(),
                                root_pid: run.summary.pid,
                                limits: (
                                    run.summary.request.core_max_size,
                                    run.summary.request.core_timeout_ms,
                                ),
                            });
                        }
                    }
                }
                if let Some(memory) = record.memory.as_mut()
                    && memory.state.in_progress()
                    && memory.state != RunArtifactState::Queued
                    && let Some(path) = memory.path.clone()
                    && self_dump.as_ref().is_none_or(|dir| *dir != path)
                    && let Some(done) =
                        std::fs::read(path.join("dump.json"))
                            .ok()
                            .and_then(|bytes| {
                                serde_json::from_slice::<crate::memory::MemoryDump>(&bytes).ok()
                            })
                    && (done.finished_ms.is_some() || done.error.is_some())
                {
                    memory.state = if done.error.is_some() {
                        RunArtifactState::Failed
                    } else {
                        RunArtifactState::Complete
                    };
                    memory.size = done.bytes;
                    memory.error = done.error;
                    touched = true;
                }
                if let Some(memory) = &record.memory
                    && memory.state == RunArtifactState::Queued
                    && record
                        .core
                        .as_ref()
                        .is_none_or(|core| core.state.is_terminal())
                {
                    start_memory.push((*cookie, index));
                }
            }
            if touched {
                changed.push(*cookie);
            }
        }
        for cookie in changed {
            self.save_trigger(cookie, |_| {});
        }
        for (cookie, index) in start_memory {
            if self.snapshot.memory_dump.is_some() {
                continue;
            }
            let max = self
                .session
                .as_ref()
                .and_then(|session| session.runs.get(&cookie))
                .and_then(|run| run.summary.request.dump_trigger.as_ref())
                .map_or(0, |plan| plan.memory_max_mib);
            let Some(finding) = self
                .session
                .as_ref()
                .and_then(|session| session.runs.get(&cookie))
                .and_then(|run| run.summary.triggers.as_ref())
                .and_then(|log| log.records.get(index))
                .map(|record| record.finding.clone())
            else {
                continue;
            };
            let dump = self.start_trigger_memory(max, cookie, &finding);
            self.save_trigger(cookie, |log| {
                if let Some(record) = log.records.get_mut(index) {
                    record.memory = Some(dump);
                }
            });
        }
        for core in gone {
            self.retry_or_skip_core(core);
        }
    }

    /// The guest found no such process for a trigger's core. When the process
    /// is still there under a new identity (it started over), ask again for
    /// that one; otherwise the process is gone: the trigger is not an attempt,
    /// so its record is dropped, a note says why and the next match may dump.
    fn retry_or_skip_core(&mut self, gone: GoneCore) {
        let GoneCore {
            cookie,
            finding,
            target,
            run_id,
            root_pid,
            limits,
        } = gone;
        let (mut core, still_gone) =
            self.queue_trigger_core(&finding, &run_id, root_pid, limits, Some(&target));
        if still_gone && core.error.as_deref() == Some("") {
            core.error = Some(self.too_late_for(cookie, &finding));
        }
        let Some(run) = self
            .session
            .as_mut()
            .and_then(|session| session.runs.get_mut(&cookie))
        else {
            return;
        };
        let log = run.summary.triggers.get_or_insert_with(TriggerLog::default);
        let found = log
            .records
            .iter()
            .position(|record| record.finding == finding && record.memory.is_none());
        if !still_gone {
            if let Some(record) = found.and_then(|index| log.records.get_mut(index)) {
                record.core = Some(core);
            }
            self.save_trigger(cookie, |_| {});
            return;
        }
        let why = core.error.unwrap_or_default();
        drop_unattempted(log, found, &finding, why.clone());
        run.add_note(format!(
            "Dump skipped for {} ({}, process {}): {why}",
            finding.rule,
            finding.tier.label(),
            finding.pid
        ));
        self.save_trigger(cookie, |_| {});
    }

    /// A memory dump ended: record it where a trigger asked for it.
    pub(super) fn settle_memory_trigger(&mut self, dump: &crate::memory::MemoryDump) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let mut cookies = Vec::new();
        for (cookie, run) in &mut session.runs {
            let Some(log) = run.summary.triggers.as_mut() else {
                continue;
            };
            for record in &mut log.records {
                if let Some(memory) = record.memory.as_mut()
                    && memory.path.as_ref() == Some(&dump.dir)
                {
                    memory.state = if dump.error.is_some() {
                        RunArtifactState::Failed
                    } else {
                        RunArtifactState::Complete
                    };
                    memory.size = dump.bytes;
                    memory.error.clone_from(&dump.error);
                    cookies.push(*cookie);
                }
            }
        }
        for cookie in cookies {
            self.save_trigger(cookie, |_| {});
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32) -> TriggerRecord {
        TriggerRecord {
            at_ms: 1,
            finding: LiveFinding {
                rule: "persistence.binary_replace".into(),
                summary: String::new(),
                tier: crate::dump_trigger::TriggerTier::default(),
                pid,
                tid: pid,
                task_cookie: 0,
                stream_id: 0,
                call_id: 0,
                guest_ns: 0,
                syscall: String::new(),
            },
            memory: None,
            core: Some(failed("gone")),
        }
    }

    #[test]
    fn a_core_refused_for_a_missing_process_is_skipped_and_keeps_the_budget() {
        let mut log = TriggerLog::default();
        log.records.push(record(1160));
        let max_dumps = 1usize;
        assert!(log.records.len() >= max_dumps);
        let finding = log.records[0].finding.clone();
        drop_unattempted(&mut log, Some(0), &finding, "too late".into());
        assert!(log.records.is_empty());
        assert_eq!(log.missed.len(), 1);
        assert_eq!(log.missed[0].reason, "too late");
        assert_eq!(log.skipped, 0);
        // The next match finds room again.
        assert!(log.records.len() < max_dumps);
    }

    #[test]
    fn the_guest_refusal_of_a_missing_process_reads_as_gone() {
        let reason = crate::core_limits::no_core_reason(5, -3);
        assert_eq!(reason.code, crate::core_limits::CoreReasonCode::ProcessGone);
        assert!(crate::core_limits::process_gone(5, -3));
    }
}
