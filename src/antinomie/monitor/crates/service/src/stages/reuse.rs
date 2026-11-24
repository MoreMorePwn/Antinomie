// SPDX-License-Identifier: GPL-3.0-only
//! Static items that are not run: a result reused from an earlier analysis of
//! the same file (audit AN-09), and capa skipped because its history says it
//! will not finish (audit AN-02b). Both end in an analysis folder of the job's
//! own, so the report, the window and the CLI read them where a result would be.
use super::{
    LaneStages, StageStop,
    analyse::judge_report,
    items::{ItemEnd, JobWork, ended},
};
use crate::{
    api::run::{HostItemState, Run},
    engine::Engine,
    retention::analyses,
    store::lock,
};
use antinomie_monitor_core::analysis::{self, AnalysisKind};
use std::{path::PathBuf, sync::Mutex, time::Duration};

/// capa is skipped when its predicted time is over this many times its limit.
pub const SKIP_OVER: f64 = 1.5;

/// The sentence of a skipped capa, naming the prediction and how to run it.
pub fn skip_text(predicted_s: u64, limit_s: u64, runs: usize) -> String {
    format!(
        "skipped: predicted {predicted_s} s over the {limit_s} s limit (capa needed at least that on each of its last {runs} runs on files this size or bigger). To run it anyway, set static_analysis.force_capa = true in the preset (antinomie-cli auto submit --force-capa)"
    )
}

/// The prediction when it is over [`SKIP_OVER`] times `limit`.
pub fn over_limit(predicted: Option<(u64, usize)>, limit: Duration) -> Option<(u64, usize)> {
    predicted.filter(|(seconds, _)| *seconds as f64 > SKIP_OVER * limit.as_secs() as f64)
}

impl<E: Engine> LaneStages<'_, E> {
    fn analyses_root(&self) -> PathBuf {
        self.env.data_dir.join("analyses")
    }

    /// The key of `group` for the job's sample, when it has one.
    pub(super) fn reuse_key(
        &self,
        job: &Run,
        plan: &super::plan::HostPlan,
        group: &[AnalysisKind],
    ) -> Option<String> {
        let sample = job.sample.as_ref()?;
        Some(analysis::reuse_key(
            self.env.data_dir,
            sample.sha256.as_str(),
            group,
            plan.static_limits.for_report(),
        ))
    }

    /// Give the job the earlier whole result of `group`, when there is one.
    pub(super) fn reused_static(
        &mut self,
        job: &Run,
        work: &Mutex<JobWork>,
        plan: &super::plan::HostPlan,
        group: &[AnalysisKind],
    ) -> Option<ItemEnd> {
        if !plan.reuse_results {
            return None;
        }
        let key = self.reuse_key(job, plan, group)?;
        let roots = analyses::roots(self.env.data_dir);
        let found = analysis::find_reusable(&roots, &key, group, |folder| {
            std::fs::read_to_string(folder.join(analyses::MARKER))
                .ok()
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty())
        })?;
        let root = self.analyses_root();
        let report = analysis::adopt(&root, &key, &found).ok()?;
        let _ = analyses::mark(&root, &report.id, &job.id);
        let words = match &found.reused.run {
            Some(run) => format!("reused from run {run} (analysis {})", found.reused.report),
            None => format!("reused from analysis {}", found.reused.report),
        };
        self.progress(
            job,
            crate::api::run::Stage::Analyse,
            &format!("static analysis reused: {words}"),
        );
        let outcome = judge_report(plan, &report);
        let mut w = lock(work);
        w.static_reports.push(report.id);
        w.problems.extend(outcome.hard);
        w.incomplete.extend(outcome.soft);
        Some(ended(HostItemState::Done, Some(words)))
    }

    /// Remember the key of a finished analysis, so a later job can reuse it.
    pub(super) fn remember_static(
        &self,
        job: &Run,
        plan: &super::plan::HostPlan,
        group: &[AnalysisKind],
        id: &str,
    ) {
        if !plan.reuse_results {
            return;
        }
        let Some(key) = self.reuse_key(job, plan, group) else {
            return;
        };
        for root in analyses::roots(self.env.data_dir) {
            let folder = root.join(id);
            if folder.is_dir() {
                analysis::remember_reuse(&folder, &key);
                return;
            }
        }
    }

    /// End the capa item without running it: a reusable result when there is
    /// one, else a report of its own that says why it did not run.
    pub fn skip_static(
        &mut self,
        job: &Run,
        work: &Mutex<JobWork>,
        group: &[AnalysisKind],
        text: &str,
    ) -> Result<ItemEnd, StageStop> {
        let plan = lock(work).plan.clone();
        if let Some(end) = self.reused_static(job, work, &plan, group) {
            return Ok(end);
        }
        let Some(sample) = job.sample.as_ref() else {
            return Ok(ended(HostItemState::Skipped, Some(text.to_owned())));
        };
        let root = self.analyses_root();
        if let Some(Ok(report)) = group
            .first()
            .map(|kind| analysis::skipped_report(&root, sample.sha256.as_str(), *kind, text))
        {
            let _ = analyses::mark(&root, &report.id, &job.id);
            lock(work).static_reports.push(report.id);
        }
        Ok(ended(HostItemState::Skipped, Some(text.to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prediction_over_one_and_a_half_limits_skips_and_the_text_says_how_to_run_it() {
        let limit = Duration::from_secs(400);
        assert!(
            over_limit(Some((600, 3)), limit).is_none(),
            "exactly 1.5 is not over"
        );
        assert!(over_limit(None, limit).is_none(), "no history runs it");
        let over = over_limit(Some((601, 3)), limit).unwrap();
        let text = skip_text(over.0, 400, over.1);
        assert!(text.starts_with("skipped: predicted 601 s over the 400 s limit"));
        assert!(text.contains("static_analysis.force_capa = true"));
        assert!(text.contains("--force-capa"));
    }
}
