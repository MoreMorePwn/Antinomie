// SPDX-License-Identifier: GPL-3.0-only
//! The engine's host-side analyses, more than one at a time (ANT-T0618, audit
//! AN-01b).
//!
//! One [`Jobs`] queue runs one analysis worker at a time. The service's pool
//! runs up to `daemon.host_workers` static items at once, and each of them
//! used to sit in the engine's single queue holding its pool worker (13,000 of
//! 50,000 worker-seconds of the evaluation were spent that way). The engine
//! now keeps as many queues as the daemon has host workers
//! ([`set_host_analyses`]) and gives each new analysis to the least loaded
//! one, so a pool item meets a free worker. The desktop app sets nothing and
//! keeps one.
//!
//! Each queue is the one it always was: the same limits, deadline, stop and
//! disk accounting per analysis. The memory floor (2 GiB of `MemAvailable`
//! per item) is the pool's: it starts no item below it, and the pool is the
//! only caller that submits more than one analysis at a time. Capa, FLOSS and
//! Ghidra stay separate items.
use super::jobs::{Action, Jobs};
use super::{AnalysisKind, AnalysisLimits, AnalysisReport};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

/// The most queues the engine keeps (`daemon.host_workers`' own maximum).
pub const MAX_HOST_ANALYSES: usize = 8;

static HOST_ANALYSES: AtomicUsize = AtomicUsize::new(1);

/// How many analyses the engine runs at once on the host, for the engines
/// this process starts afterwards. The daemon sets it from
/// `daemon.host_workers`; 1 is the default and the app's.
pub fn set_host_analyses(count: usize) {
    HOST_ANALYSES.store(count.clamp(1, MAX_HOST_ANALYSES), Ordering::Relaxed);
}

/// The count of [`set_host_analyses`].
pub fn host_analyses() -> usize {
    HOST_ANALYSES
        .load(Ordering::Relaxed)
        .clamp(1, MAX_HOST_ANALYSES)
}

/// The queues of host analyses.
pub(crate) struct HostAnalysis {
    queues: Vec<Jobs>,
}

impl Default for HostAnalysis {
    fn default() -> Self {
        Self {
            queues: vec![Jobs::default()],
        }
    }
}

impl HostAnalysis {
    /// The queues the daemon asked for ([`set_host_analyses`]).
    pub(crate) fn configured(tools_dir: PathBuf) -> Self {
        Self::with_tools(tools_dir, host_analyses())
    }

    pub(crate) fn with_tools(tools_dir: PathBuf, count: usize) -> Self {
        Self {
            queues: (0..count.clamp(1, MAX_HOST_ANALYSES))
                .map(|_| Jobs::with_tools(tools_dir.clone()))
                .collect(),
        }
    }

    /// The queue with the fewest analyses unfinished; the first on a tie.
    fn least_loaded(&mut self) -> &mut Jobs {
        let index = self
            .queues
            .iter()
            .enumerate()
            .min_by_key(|(_, queue)| queue.load())
            .map_or(0, |(index, _)| index);
        &mut self.queues[index]
    }

    pub(crate) fn adopt(&mut self, carried: Jobs) {
        self.least_loaded().adopt(carried);
    }

    pub(crate) fn cancel(&mut self, id: &str) -> Result<(), String> {
        match self.queues.iter_mut().find(|queue| queue.tracks(id)) {
            Some(queue) => queue.cancel(id),
            None => Err("analysis job is unknown or already completed".into()),
        }
    }

    pub(crate) fn submit_host_file(
        &mut self,
        report: AnalysisReport,
        directory: PathBuf,
        source: &Path,
        available: u64,
    ) -> AnalysisReport {
        self.least_loaded()
            .submit_host_file(report, directory, source, available)
    }

    pub(crate) fn submit_host_opened(
        &mut self,
        report: AnalysisReport,
        directory: PathBuf,
        input: File,
        total_len: u64,
        available: u64,
    ) -> AnalysisReport {
        self.least_loaded()
            .submit_host_opened(report, directory, input, total_len, available)
    }

    pub(crate) fn analyze_more_with(
        &mut self,
        run_id: Option<String>,
        base: &Path,
        kinds: &[AnalysisKind],
        time_limit_seconds: Option<u64>,
        limits: Option<AnalysisLimits>,
        available: u64,
    ) -> Result<AnalysisReport, String> {
        // Checks added to an analysis that is still running in another queue
        // are refused, as they are in the one that holds it.
        if let Ok(saved) = super::jobs::open_report(base)
            && self.queues.iter().any(|queue| queue.tracks(&saved.id))
        {
            return Err("this analysis is already running".into());
        }
        self.least_loaded().analyze_more_with(
            run_id,
            base,
            kinds,
            time_limit_seconds,
            limits,
            available,
        )
    }

    /// Advance every queue; the first action one asks for (a handle to
    /// release) is returned.
    pub(crate) fn next(&mut self) -> Option<Action> {
        self.queues.iter_mut().find_map(Jobs::next)
    }

    pub(crate) fn updates(&mut self) -> Vec<(Option<String>, AnalysisReport)> {
        self.queues.iter_mut().flat_map(Jobs::updates).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_is_kept_between_one_and_eight_and_the_default_queue_is_single() {
        assert_eq!(HostAnalysis::default().queues.len(), 1);
        assert_eq!(
            HostAnalysis::with_tools(PathBuf::from("/t"), 0)
                .queues
                .len(),
            1
        );
        assert_eq!(
            HostAnalysis::with_tools(PathBuf::from("/t"), 3)
                .queues
                .len(),
            3
        );
        assert_eq!(
            HostAnalysis::with_tools(PathBuf::from("/t"), 99)
                .queues
                .len(),
            MAX_HOST_ANALYSES
        );
        set_host_analyses(5);
        assert_eq!(host_analyses(), 5);
        set_host_analyses(0);
        assert_eq!(host_analyses(), 1);
        set_host_analyses(1);
    }

    #[test]
    fn a_new_analysis_goes_to_a_queue_with_nothing_to_do() {
        let mut pool = HostAnalysis::with_tools(PathBuf::from("/nonexistent"), 3);
        let dir =
            std::env::temp_dir().join(format!("ant-host-pool-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("specimen");
        std::fs::write(&file, b"x").unwrap();
        let selection = super::super::AnalysisSelection::default();
        for _ in 0..3 {
            let report = super::super::jobs::new_report("sample:ab", &selection);
            let folder = dir.join(&report.id);
            pool.submit_host_file(report, folder, &file, u64::MAX);
        }
        // Three analyses, three queues, one each.
        let loads: Vec<usize> = pool.queues.iter().map(Jobs::load).collect();
        assert_eq!(loads, [1, 1, 1]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
