// SPDX-License-Identifier: GPL-3.0-only
//! The earlier bytes of a boot whose VM was let go before they were copied
//! (ANT-T0612, `antinomie_monitor_core::earlier_kept`).
//!
//! `collect` lets the lane go once the VM is stopped, the recording saved
//! and the disk layer merged; the copy of the earlier bytes of the files the
//! run changed (a scan of the whole recording) goes on outside the lane.
//! Triage reads those bytes, so the `triage` item waits for the copy first.
//! A copy that no process is making (the daemon stopped while it ran) is
//! made here after [`ADOPT_AFTER`], on a thread of its own.
use antinomie_monitor_core::{disk_start::DiskStart, earlier_kept};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// How long a pending copy that no process works on is left to its owner.
pub(crate) const ADOPT_AFTER: Duration = Duration::from_secs(30);
/// How often the copy is looked at.
const LOOK: Duration = Duration::from_millis(250);

/// The boot folder of a job's recording.
pub(crate) fn boot_dir(job: &crate::api::run::Run) -> Option<PathBuf> {
    let recording = job.recording.as_ref()?;
    let directory = recording.directory.as_deref()?;
    DiskStart::boot_dir(Path::new(directory), &recording.boot_id)
}

/// Wait until the boot in `boot_dir` has no copy pending, making it here when
/// no process has been at it for `adopt_after`. `Some(waited)` when a copy
/// was pending; `None` when none was, or `cancel` was raised.
pub(crate) fn wait_for_copy(
    boot_dir: &Path,
    cancel: &AtomicBool,
    adopt_after: Duration,
) -> Option<Duration> {
    let began = Instant::now();
    let mut idle_since: Option<Instant> = None;
    let mut adopted = false;
    earlier_kept::pending(boot_dir)?;
    loop {
        if earlier_kept::pending(boot_dir).is_none() {
            return Some(began.elapsed());
        }
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        if earlier_kept::at_work(boot_dir) {
            idle_since = None;
        } else if !adopted {
            let since = *idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= adopt_after {
                adopted = true;
                let dir = boot_dir.to_path_buf();
                std::thread::spawn(move || earlier_kept::finish(&dir));
            }
        }
        std::thread::sleep(LOOK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::disk_start::{DiskStart, Start, Via};

    #[test]
    fn a_boot_with_no_pending_copy_does_not_wait() {
        let dir = std::env::temp_dir().join(format!("ant-earlier-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cancel = AtomicBool::new(false);
        assert_eq!(wait_for_copy(&dir, &cancel, Duration::ZERO), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_copy_nobody_makes_is_made_here_and_the_wait_ends() {
        let dir = std::env::temp_dir().join(format!("ant-earlier-adopt-{}", std::process::id()));
        let boot = dir.join("boots/b1");
        std::fs::create_dir_all(&boot).unwrap();
        // A start that was not frozen: nothing to keep, the copy is pending.
        DiskStart {
            format: 1,
            boot_id: "b1".into(),
            via: Via::Start,
            start: Start::Changed,
        }
        .save(&boot)
        .unwrap();
        let marker = boot.join(earlier_kept::DIR);
        std::fs::create_dir_all(&marker).unwrap();
        std::fs::write(
            marker.join("pending.json"),
            r#"{"format":1,"boot_id":"b1","original":null,"kept_ms":1}"#,
        )
        .unwrap();
        assert!(earlier_kept::pending(&boot).is_some());
        let cancel = AtomicBool::new(false);
        let waited = wait_for_copy(&boot, &cancel, Duration::ZERO).expect("a copy was pending");
        assert!(waited < Duration::from_secs(60));
        assert!(earlier_kept::pending(&boot).is_none());
        // No copy program in a unit test: the recording says why.
        let index = antinomie_monitor_core::file_before_store::Index::load(&boot).unwrap();
        assert!(!index.complete);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cancel_ends_the_wait() {
        let dir = std::env::temp_dir().join(format!("ant-earlier-cancel-{}", std::process::id()));
        let marker = dir.join(earlier_kept::DIR);
        std::fs::create_dir_all(&marker).unwrap();
        std::fs::write(
            marker.join("pending.json"),
            r#"{"format":1,"boot_id":"b1","original":null,"kept_ms":1}"#,
        )
        .unwrap();
        let cancel = AtomicBool::new(true);
        assert_eq!(
            wait_for_copy(&dir, &cancel, Duration::from_secs(3600)),
            None
        );
        assert!(earlier_kept::pending(&dir).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
