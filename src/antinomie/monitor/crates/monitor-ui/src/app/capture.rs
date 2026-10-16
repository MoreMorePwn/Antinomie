// SPDX-License-Identifier: MIT
//! Process observers, core captures and network capture state.
use super::*;

impl MonitorApp {
    pub(super) fn selected_capture_summary(&self) -> Option<&CaptureSummary> {
        self.selected_capture
            .as_deref()
            .and_then(|id| self.capture(id))
    }

    pub(super) fn trace_archive_directory(&self) -> Option<PathBuf> {
        if let Some(capture) = self.selected_capture_summary() {
            if self.archive_selected || !self.snapshot.capture_events.contains_key(&capture.id) {
                return Some(capture.directory.clone());
            }
            return None;
        }
        self.offline_run().map(|run| run.directory.clone())
    }

    pub(super) fn observer_supported(&self) -> bool {
        self.running()
            && !self.closing
            && self
                .snapshot
                .guest_kernel
                .as_ref()
                .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 11))
    }

    pub(super) fn active_observer(&self) -> Option<&CaptureSummary> {
        self.snapshot.captures.iter().find(|capture| {
            Some(&capture.vm_id) == self.snapshot.active_vm.as_ref()
                && matches!(capture.state, CaptureState::Active | CaptureState::Unknown)
        })
    }

    pub(super) fn observer_start_enabled(&self) -> bool {
        self.observer_supported()
            && self.pending_observer.is_none()
            && self.active_observer().is_none()
    }

    pub(super) fn open_process_picker(&mut self) {
        self.process_picker.purpose = captures::ProcessPurpose::Attach;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
    }

    pub(super) fn manual_core_unavailable(&self) -> Option<&'static str> {
        if !self.running()
            || self.closing
            || self.selected.is_none()
            || self.selected != self.snapshot.active_vm
        {
            Some("Start the selected VM to dump a process core.")
        } else if self.snapshot.memory_dump.is_some() {
            Some("Wait for the VM RAM dump to finish; the guest is paused.")
        } else if !self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 16))
        {
            Some("Live core capture needs a guest base with revision 16 or newer.")
        } else if self.pending_core.is_some()
            || self.snapshot.process_cores.iter().any(|capture| {
                Some(&capture.vm_id) == self.snapshot.active_vm.as_ref()
                    && matches!(
                        capture.phase,
                        ProcessCorePhase::Admission
                            | ProcessCorePhase::UnknownAdmission
                            | ProcessCorePhase::GuestCapture
                    )
            })
        {
            Some("Wait for the current process capture to release its pause.")
        } else {
            None
        }
    }

    pub(super) fn open_core_picker(&mut self) {
        if self.manual_core_unavailable().is_some() {
            return;
        }
        self.process_picker.purpose = captures::ProcessPurpose::Core;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
        self.focus_panel = Some(Panel::CoreDump);
    }

    pub(super) fn stop_observer(&mut self) {
        if self.observer_supported() && self.pending_observer.is_none() {
            if let Some(capture) = self.active_observer() {
                self.send(Command::StopCapture {
                    capture_id: capture.id.clone(),
                });
            }
        }
    }

    /// The running VM has NAT networking.
    fn running_nat(&self) -> bool {
        self.snapshot.vms.iter().any(|vm| {
            Some(&vm.id) == self.snapshot.active_vm.as_ref() && (vm.nat || vm.isolated_network)
        })
    }

    /// A network capture can be started or stopped now.
    pub(super) fn network_toggle_enabled(&self) -> bool {
        self.running()
            && !self.closing
            && self.pending_network.is_none()
            && (self.snapshot.network_capture.is_some() || self.running_nat())
    }

    pub(super) fn toggle_network_capture(&mut self) {
        if self.network_toggle_enabled() {
            self.send(if self.snapshot.network_capture.is_some() {
                Command::StopNetworkCapture
            } else {
                Command::StartNetworkCapture
            });
        }
    }

    pub(super) fn network_toggle_label(&self) -> &'static str {
        if self.snapshot.network_capture.is_some() {
            "Stop network capture"
        } else if self.running() && !self.running_nat() {
            "Capture network (choose Isolated or NAT network in VM settings)"
        } else {
            "Capture network"
        }
    }

    /// Loaded packets have no run id. Show them only when they belong to this
    /// selection; otherwise triage gets an empty slice.
    ///
    /// A selected observation capture contributes packets only when
    /// `loaded_path` equals that capture's pcap file. `CaptureSummary` stores
    /// an observation directory and has no pcap path, so the comparison fails
    /// and the slice is empty. An archived trace, or a selected run that is
    /// not the live running run, also has no proven pcap join. Anything else
    /// is the live VM and keeps the packets currently loaded.
    #[cfg(test)]
    pub(super) fn triage_hides_packets(&self) -> bool {
        if self.selected_capture.is_some() {
            return !self.selected_capture_owns_loaded_pcap();
        }
        if let Some(id) = self.selected_run.clone() {
            let owned = self
                .run(&id)
                .cloned()
                .is_some_and(|run| self.loaded_pcap_belongs_to_run(&run));
            if owned {
                return false;
            }
        }
        self.trace_archive_directory().is_some()
            || self
                .selected_run
                .as_ref()
                .is_some_and(|id| !self.run(id).is_some_and(|run| self.live_history_run(run)))
    }

    /// The loaded pcap is one this run recorded: the live boot capture, or a
    /// path listed in that run's artifacts. A path that is merely open is not
    /// treated as this run's capture.
    #[cfg(test)]
    fn loaded_pcap_belongs_to_run(&self, run: &RunSummary) -> bool {
        let Some(loaded) = self.network_view.loaded_path() else {
            return false;
        };
        if self
            .snapshot
            .network_capture
            .as_ref()
            .is_some_and(|capture| capture.file == loaded && capture.boot_id == run.boot_id)
        {
            return true;
        }
        antinomie_monitor_core::RunArtifacts::load(&run.directory)
            .ok()
            .flatten()
            .is_some_and(|artifacts| {
                artifacts.run_id == run.id
                    && artifacts
                        .network_captures
                        .iter()
                        .any(|file| file.as_path() == loaded)
            })
    }

    /// A pcap this selection recorded. An observation directory with no pcap
    /// file stays empty; the loaded preview is not substituted.
    pub(super) fn owned_triage_pcap(&self) -> Option<(std::path::PathBuf, bool)> {
        if let Some(capture) = self.selected_capture_summary() {
            return capture_pcap_file(capture).map(|file| (file, false));
        }
        let id = self.selected_run.clone()?;
        let run = self.run(&id)?.clone();
        if let Some(artifacts) = antinomie_monitor_core::RunArtifacts::load(&run.directory)
            .ok()
            .flatten()
        {
            if artifacts.run_id != run.id
                || artifacts.vm_id != run.vm_id
                || artifacts.boot_id != run.boot_id
            {
                return None;
            }
            if let Some(file) = artifacts
                .network_captures
                .into_iter()
                .find(|file| file.is_file() && pcap_magic(file))
            {
                return Some((
                    file,
                    self.live_history_run(&run)
                        || artifacts.network_state
                            != antinomie_monitor_core::RunArtifactState::Complete,
                ));
            }
        }
        self.snapshot
            .network_capture
            .as_ref()
            .filter(|capture| {
                capture.boot_id == run.boot_id
                    && capture.file.is_file()
                    && pcap_magic(&capture.file)
            })
            .map(|capture| (capture.file.clone(), capture.stopped_ms.is_none()))
    }

    #[cfg(test)]
    fn selected_capture_owns_loaded_pcap(&self) -> bool {
        let Some(loaded) = self
            .network_view
            .loaded_path()
            .map(std::path::Path::to_path_buf)
        else {
            return false;
        };
        self.selected_capture_summary()
            .and_then(capture_pcap_file)
            .is_some_and(|file| file == loaded)
    }
}

/// A file in the observation directory whose first four bytes are a classic
/// pcap magic. A directory with no such file is not a packet capture.
fn capture_pcap_file(capture: &CaptureSummary) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(&capture.directory).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && pcap_magic(&path) {
            return Some(path);
        }
    }
    None
}

fn pcap_magic(path: &std::path::Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut file, &mut magic).is_err() {
        return false;
    }
    matches!(magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4])
}

pub(crate) fn core_capture_status(state: antinomie_monitor_core::RunArtifactState) -> &'static str {
    use antinomie_monitor_core::RunArtifactState;
    match state {
        RunArtifactState::Disabled => "Disabled",
        RunArtifactState::WaitingForRootExit => "Waiting for root process exit",
        RunArtifactState::WaitingForTreeExit => "Waiting for process tree exit",
        RunArtifactState::Recording => "Recording",
        RunArtifactState::Queued => "Queued",
        RunArtifactState::InProgress => "Acquiring",
        RunArtifactState::Complete => "Complete",
        RunArtifactState::Partial => "Partial capture",
        RunArtifactState::Interrupted => "Interrupted",
        RunArtifactState::Failed => "Failed",
    }
}
