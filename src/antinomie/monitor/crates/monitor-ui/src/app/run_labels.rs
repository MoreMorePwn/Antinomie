// SPDX-License-Identifier: GPL-3.0-only
//! What the selected run's saved captures and core read as: "Complete",
//! "Partial capture", "Deleted"... The run's artifact list is read on a
//! worker, when the selection changes, after a delete and on a slow timer,
//! never while a frame is drawn.
use super::*;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// How long an answer is kept before the artifact list is read again.
const KEEP: Duration = Duration::from_secs(30);

/// The state texts of one run's network capture and core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Labels {
    pub network: &'static str,
    pub core: &'static str,
}

type Answer = (String, Option<Labels>);

#[derive(Default)]
pub(super) struct RunLabels {
    /// The run the answer is for, and what it said.
    known: Option<Answer>,
    at: Option<Instant>,
    stale: bool,
    rx: Option<Receiver<Answer>>,
}

fn read(run: &RunSummary) -> Option<Labels> {
    let artifacts = antinomie_monitor_core::RunArtifacts::load(&run.directory)
        .ok()
        .flatten()
        .filter(|artifacts| {
            artifacts.run_id == run.id
                && artifacts.vm_id == run.vm_id
                && artifacts.boot_id == run.boot_id
        })?;
    Some(Labels {
        network: artifacts.network_label(),
        core: artifacts.core_label(),
    })
}

impl RunLabels {
    /// Saved evidence was deleted: read the list again.
    pub(super) fn invalidate(&mut self) {
        self.stale = true;
    }

    /// The labels last read for `run`; `None` until they arrive, for a run
    /// with no artifact list, and for a list that belongs to another run.
    pub(super) fn of(&mut self, ctx: &egui::Context, run: &RunSummary) -> Option<Labels> {
        let key = format!("{}\0{}", run.id, run.directory.display());
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(answer) => {
                    self.known = Some(answer);
                    self.at = Some(Instant::now());
                    self.rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.rx = None,
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
            }
        }
        let current = self.known.as_ref().filter(|(known, _)| *known == key);
        let due = self.stale || current.is_none() || self.at.is_none_or(|at| at.elapsed() >= KEEP);
        if due && self.rx.is_none() {
            let (tx, rx) = mpsc::sync_channel(1);
            let (run, repaint, asked) = (run.clone(), ctx.clone(), key.clone());
            if std::thread::Builder::new()
                .name("run-artifact-labels".into())
                .spawn(move || {
                    let _ = tx.send((asked, read(&run)));
                    repaint.request_repaint_of(egui::ViewportId::ROOT);
                })
                .is_ok()
            {
                self.rx = Some(rx);
                self.stale = false;
            }
        }
        // A run selected in the meantime does not show another run's answer.
        self.known
            .as_ref()
            .filter(|(known, _)| *known == key)
            .and_then(|(_, labels)| *labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(labels: &mut RunLabels, ctx: &egui::Context, run: &RunSummary) -> Option<Labels> {
        // The reader thread competes with whatever else runs: wait on the
        // clock, not on a count of polls.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while std::time::Instant::now() < deadline {
            if let Some(found) = labels.of(ctx, run) {
                return Some(found);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    #[test]
    fn deleted_captures_and_cores_read_as_deleted_and_frames_do_not_read_the_disk() {
        let dir = std::env::temp_dir().join(format!("ant-run-labels-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let artifacts = antinomie_monitor_core::RunArtifacts {
            run_id: "r1".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            network_state: antinomie_monitor_core::RunArtifactState::Complete,
            network_deleted: true,
            core_state: antinomie_monitor_core::RunArtifactState::Disabled,
            core_deleted: true,
            ..Default::default()
        };
        std::fs::write(
            dir.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
        let mut run = crate::app::tests::run("r1");
        run.boot_id = "boot".into();
        run.directory = dir.clone();
        let ctx = egui::Context::default();
        let mut labels = RunLabels::default();
        let found = wait(&mut labels, &ctx, &run).expect("the labels never arrived");
        assert_eq!((found.network, found.core), ("Deleted", "Deleted"));
        // The list goes: frames keep the answer and start no read.
        std::fs::remove_file(dir.join("artifacts.json")).unwrap();
        for _ in 0..50 {
            assert_eq!(labels.of(&ctx, &run), Some(found));
            assert!(labels.rx.is_none(), "a frame started a read");
        }
        // Another run does not show this run's labels.
        let other = RunSummary {
            id: "r2".into(),
            ..run.clone()
        };
        assert_eq!(labels.of(&ctx, &other), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
