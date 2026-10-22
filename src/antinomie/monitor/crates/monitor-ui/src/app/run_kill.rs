// SPDX-License-Identifier: GPL-3.0-only
//! Stop one explicitly identified run tree without changing the VM lifecycle.
use super::*;

pub(super) struct Target {
    vm_id: String,
    boot_id: String,
    run_id: String,
}

impl Target {
    pub fn label(&self, snapshot: &Snapshot) -> String {
        let name = snapshot
            .runs
            .iter()
            .find(|run| run.id == self.run_id)
            .map_or("Program", |run| run.request.path.as_str());
        format!(
            "{} · {}",
            name,
            self.run_id.chars().take(12).collect::<String>()
        )
    }

    pub fn current(&self, snapshot: &Snapshot) -> bool {
        snapshot.state == VmState::Running
            && snapshot.active_vm.as_ref() == Some(&self.vm_id)
            && snapshot.boot_id.as_ref() == Some(&self.boot_id)
            && snapshot
                .runs
                .iter()
                .any(|run| run.id == self.run_id && actionable(run, snapshot))
    }
}

fn actionable(run: &RunSummary, snapshot: &Snapshot) -> bool {
    snapshot.active_vm.as_ref() == Some(&run.vm_id)
        && snapshot.boot_id.as_ref() == Some(&run.boot_id)
        && run.root_task_cookie != 0
        && matches!(run.state, RunState::Running | RunState::TerminalClosed)
}

impl MonitorApp {
    pub(super) fn kill_target(&self) -> Option<&RunSummary> {
        if !self.running()
            || self.closing
            || self.pending_kill.is_some()
            || self.snapshot.memory_dump.is_some()
            || self.vm_snapshots.pending.is_some()
        {
            return None;
        }
        let mut active = self
            .snapshot
            .runs
            .iter()
            .filter(|run| actionable(run, &self.snapshot));
        if let Some(selected) = &self.selected_run {
            return active.find(|run| &run.id == selected);
        }
        let first = active.next()?;
        active.next().is_none().then_some(first)
    }

    pub(super) fn request_kill(&mut self, run_id: Option<&str>) {
        if self.confirm.is_some() {
            return;
        }
        let run = match run_id {
            Some(id)
                if self.running()
                    && !self.closing
                    && self.pending_kill.is_none()
                    && self.snapshot.memory_dump.is_none()
                    && self.vm_snapshots.pending.is_none() =>
            {
                self.snapshot
                    .runs
                    .iter()
                    .find(|run| run.id == id && actionable(run, &self.snapshot))
            }
            Some(_) => None,
            None => self.kill_target(),
        };
        if let Some(run) = run {
            // An active run can still have bytes in flight even after a saving error.
            self.confirm = Some(Confirm::KillRun(run_kill::Target {
                vm_id: run.vm_id.clone(),
                boot_id: run.boot_id.clone(),
                run_id: run.id.clone(),
            }));
        }
    }

    pub(super) fn submit_kill(&mut self, target: Target) {
        if !target.current(&self.snapshot)
            || self.selected.as_ref() != Some(&target.vm_id)
            || self.closing
            || self.pending_kill.is_some()
            || self.snapshot.memory_dump.is_some()
            || self.vm_snapshots.pending.is_some()
        {
            self.report_warning("Run is no longer available to kill; select an active run".into());
            return;
        }
        self.pending_kill = self.send_request(Command::StopRun {
            run_id: target.run_id,
        });
    }
}
