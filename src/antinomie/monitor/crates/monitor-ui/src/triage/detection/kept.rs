// SPDX-License-Identifier: GPL-3.0-only
//! The saved detection results of the last runs shown, kept in memory so a
//! run shown again has them at once instead of reading them back behind the
//! preparing bar (round 6 item 22).
use super::*;

/// Runs whose saved results are kept in memory.
pub(super) const KEPT_RUNS: usize = 6;

impl View {
    /// Show `identity`'s run. Its saved results come from memory when the
    /// run was shown a moment ago (true: nothing to read); otherwise they are
    /// to be read from disk (false). Nothing is re-scanned here: whether a
    /// scan is due is decided as before, from the selection digest and the
    /// evidence key the results carry.
    pub(super) fn switch_identity(&mut self, identity: Option<(PathBuf, Identity)>) -> bool {
        if let Some((_, old)) = self.identity.take() {
            let saved = self
                .results
                .clone()
                .map(|result| result.and_then(Result::ok));
            if saved.iter().any(Option::is_some) {
                self.kept.retain(|(kept, _)| *kept != old);
                self.kept.push((old, saved));
                if self.kept.len() > KEPT_RUNS {
                    self.kept.remove(0);
                }
            }
        }
        self.reset();
        self.identity = identity;
        let Some((_, new)) = self.identity.as_ref() else {
            return false;
        };
        let Some(at) = self.kept.iter().position(|(kept, _)| kept == new) else {
            return true;
        };
        let (_, saved) = self.kept.remove(at);
        self.results = saved.map(|report| report.map(Ok));
        for index in 0..3 {
            self.rows(index);
        }
        false
    }
}
