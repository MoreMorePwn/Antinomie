// SPDX-License-Identifier: GPL-3.0-only
//! The sidebar's last run of a VM the window has not opened (ANT-T0441): a VM
//! that is not selected and has only command-line runs used to say "No recent
//! run". One background read of every VM's recordings finds the newest run of
//! each; it writes nothing and runs again when the set of VMs changes.
use super::*;
use std::sync::mpsc::{self, Receiver, TryRecvError};

#[derive(Default)]
pub(super) struct Scan {
    /// The VMs the last scan was started for.
    key: String,
    pending: Option<Receiver<Vec<(String, LastRun)>>>,
}

impl Scan {
    pub(super) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

/// The newest run of each VM as the sidebar remembers it.
fn newest(options: &BackendOptions) -> Vec<(String, LastRun)> {
    antinomie_monitor_core::samples::newest_run_per_vm(options)
        .into_iter()
        .filter_map(|(vm_id, run)| {
            Some((
                vm_id,
                LastRun {
                    run_id: run.id.clone(),
                    program: run.request.path.clone(),
                    started: run.started_ms? / 1000,
                },
            ))
        })
        .collect()
}

impl MonitorApp {
    /// Start the read when the VMs changed, and take its answer when ready.
    pub(super) fn scan_last_runs(&mut self) {
        let key = self
            .snapshot
            .vms
            .iter()
            .map(|vm| vm.id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        if !key.is_empty() && key != self.sidebar_scan.key && self.sidebar_scan.pending.is_none() {
            let (sender, receiver) = mpsc::channel();
            let options = self.options.clone();
            let spawned = std::thread::Builder::new()
                .name("antinomie-sidebar-runs".into())
                .spawn(move || {
                    let _ = sender.send(newest(&options));
                });
            self.sidebar_scan.key = key;
            if spawned.is_ok() {
                self.sidebar_scan.pending = Some(receiver);
            }
        }
        let Some(receiver) = &self.sidebar_scan.pending else {
            return;
        };
        let found = match receiver.try_recv() {
            Ok(found) => found,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Vec::new(),
        };
        self.sidebar_scan.pending = None;
        for (vm_id, last) in found {
            if !self.snapshot.vms.iter().any(|vm| vm.id == vm_id) {
                continue;
            }
            let newer =
                self.settings.last_runs.get(&vm_id).is_none_or(|known| {
                    known.run_id != last.run_id && known.started < last.started
                });
            if newer {
                self.settings.last_runs.insert(vm_id, last);
            }
        }
    }
}
