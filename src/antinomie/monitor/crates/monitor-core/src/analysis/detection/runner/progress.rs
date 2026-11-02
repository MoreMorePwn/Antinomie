// SPDX-License-Identifier: GPL-3.0-only
//! Progress files written while a detection scan runs (moved out of `runner`).
use super::*;

pub(in crate::analysis::detection) struct ProgressWriter {
    path: PathBuf,
    rules_loaded: u64,
    coalescer: super::ProgressCoalescer,
}

impl ProgressWriter {
    pub(in crate::analysis::detection) fn new(work: &Path) -> Self {
        Self {
            path: work.join("progress.json"),
            rules_loaded: 0,
            coalescer: super::ProgressCoalescer::new(Duration::from_millis(250)),
        }
    }

    pub(in crate::analysis::detection) fn set_rules(&mut self, count: u64) {
        self.rules_loaded = count;
    }

    pub(in crate::analysis::detection) fn stage(&mut self, target: ScanTarget) {
        let progress = ScanProgress {
            target,
            rules_loaded: self.rules_loaded,
        };
        self.coalescer.force(Instant::now());
        write_progress(&self.path, &progress);
    }

    pub(in crate::analysis::detection) fn note(&mut self, target: ScanTarget) {
        let progress = ScanProgress {
            target,
            rules_loaded: self.rules_loaded,
        };
        if let Some(progress) = self.coalescer.push(progress, Instant::now()) {
            write_progress(&self.path, &progress);
        }
    }

    pub(in crate::analysis::detection) fn flush(&mut self) {
        if let Some(progress) = self.coalescer.poll(Instant::now() + Duration::from_secs(1)) {
            write_progress(&self.path, &progress);
        }
    }
}

pub(in crate::analysis::detection) fn write_progress(path: &Path, progress: &ScanProgress) {
    let _ = crate::storage::atomic_json(path, progress);
}

/// Reads `progress.json` until `cancel` or `stop`. Cancellation closes the
/// phase channel without another update.
pub(super) fn watch_progress(
    path: &Path,
    cancel: &AtomicBool,
    stop: &AtomicBool,
    tx: &std::sync::mpsc::Sender<ScanProgress>,
) {
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    let mut seen = Vec::<u8>::new();
    while !stop.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
        if let Ok(bytes) = fs::read(path)
            && bytes != seen
        {
            seen = bytes;
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(progress) = serde_json::from_slice::<ScanProgress>(&seen)
                && tx.send(progress).is_err()
            {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}
