// SPDX-License-Identifier: GPL-3.0-only
//! A cancelled manual core whose guest refuses every status poll.
use super::*;

/// How long a cancelled capture keeps polling a status the guest refuses.
pub(super) const STATUS_GIVE_UP: Duration = Duration::from_secs(30);

impl Owner {
    /// A status poll failed. Once the capture is being cancelled and the guest
    /// has refused every poll for `STATUS_GIVE_UP`, the guest side is given up
    /// on: the owner no longer holds the guest or blocks snapshots. Returns
    /// whether it did.
    pub(super) fn status_unanswerable(&mut self, error: &str) -> bool {
        let since = *self.status_failing.get_or_insert_with(Instant::now);
        if !self.cancel_requested || since.elapsed() < STATUS_GIVE_UP {
            return false;
        }
        self.known_absent = true;
        let why = format!(
            "the guest kept refusing the core status ({error}); the capture is given up and its host prefix kept"
        );
        if self.desired.is_none() {
            let state = if self.summary.stored_size > 0 {
                RunArtifactState::Partial
            } else {
                RunArtifactState::Failed
            };
            self.finish(state, why);
        } else {
            self.issue(why);
        }
        self.done = true;
        self.summary.phase = ProcessCorePhase::Finished;
        true
    }
}
