// SPDX-License-Identifier: GPL-3.0-only
//! The packet capture of the run or observation Triage shows.
//!
//! Finding it opens the run's artifact list and reads the first bytes of
//! each candidate file. Triage asks every frame, so the answer from disk is
//! kept for a few seconds and per selection; what only depends on memory
//! (whether the run is live, whether the capture stopped) is read fresh.
use super::capture::{capture_pcap_file, pcap_magic};
use super::*;
use std::time::Duration;

/// How long what the disk said is trusted for the same selection.
const KEEP: Duration = Duration::from_secs(5);

#[derive(Clone)]
enum Artifacts {
    /// No artifact list was written (yet).
    Absent,
    /// The list belongs to another run, boot or VM.
    Mismatch,
    /// The list names no readable capture.
    NoCapture,
    Found {
        file: PathBuf,
        complete: bool,
    },
}

#[derive(Clone)]
enum Disk {
    Capture(Option<PathBuf>),
    Run {
        artifacts: Artifacts,
        /// The boot's live capture file exists and is a capture.
        live_file: bool,
    },
}

/// What the disk said for one selection, and when.
#[derive(Default)]
pub(super) struct PcapLookup {
    entry: Option<(String, Instant, Disk)>,
}

impl MonitorApp {
    fn pcap_on_disk(&self, key: String, read: impl FnOnce() -> Disk) -> Disk {
        let mut lookup = self.triage_pcap.borrow_mut();
        if let Some((cached, at, disk)) = &lookup.entry {
            if *cached == key && at.elapsed() < KEEP {
                return disk.clone();
            }
        }
        let disk = read();
        lookup.entry = Some((key, Instant::now(), disk.clone()));
        disk
    }

    /// A pcap this selection recorded. An observation directory with no pcap
    /// file stays empty; the loaded preview is not substituted.
    pub(super) fn owned_triage_pcap(&self) -> Option<(PathBuf, bool)> {
        if let Some(capture) = self.selected_capture_summary() {
            let key = format!("capture\0{}\0{}", capture.id, capture.directory.display());
            let Disk::Capture(file) =
                self.pcap_on_disk(key, || Disk::Capture(capture_pcap_file(capture)))
            else {
                return None;
            };
            return file.map(|file| (file, false));
        }
        let run = self.run(self.selected_run.as_deref()?)?;
        let live = self.snapshot.network_capture.as_ref();
        let key = format!(
            "run\0{}\0{}\0{:?}\0{}",
            run.id,
            run.directory.display(),
            run.state,
            live.map(|capture| capture.file.display().to_string())
                .unwrap_or_default()
        );
        let Disk::Run {
            artifacts,
            live_file,
        } = self.pcap_on_disk(key, || Disk::Run {
            artifacts: match antinomie_monitor_core::RunArtifacts::load(&run.directory)
                .ok()
                .flatten()
            {
                None => Artifacts::Absent,
                Some(artifacts)
                    if artifacts.run_id != run.id
                        || artifacts.vm_id != run.vm_id
                        || artifacts.boot_id != run.boot_id =>
                {
                    Artifacts::Mismatch
                }
                Some(artifacts) => artifacts
                    .network_captures
                    .iter()
                    .find(|file| file.is_file() && pcap_magic(file))
                    .map_or(Artifacts::NoCapture, |file| Artifacts::Found {
                        file: file.clone(),
                        complete: artifacts.network_state
                            == antinomie_monitor_core::RunArtifactState::Complete,
                    }),
            },
            live_file: live
                .filter(|capture| capture.boot_id == run.boot_id)
                .is_some_and(|capture| capture.file.is_file() && pcap_magic(&capture.file)),
        })
        else {
            return None;
        };
        match artifacts {
            Artifacts::Mismatch => return None,
            Artifacts::Found { file, complete } => {
                return Some((file, self.live_history_run(run) || !complete));
            }
            Artifacts::Absent | Artifacts::NoCapture => {}
        }
        live.filter(|capture| capture.boot_id == run.boot_id && live_file)
            .map(|capture| (capture.file.clone(), capture.stopped_ms.is_none()))
    }
}
