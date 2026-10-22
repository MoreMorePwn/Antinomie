// SPDX-License-Identifier: GPL-3.0-only
//! A sample push from sending it to its result, or to giving up on it.
use super::SamplesView;
use antinomie_monitor_core::ExecRequest;

impl SamplesView {
    /// The app sent the upload as request `id`.
    pub(crate) fn sent(&mut self, id: u64) {
        if let Some(run) = self.awaiting.take() {
            self.pending = Some((id, run));
        }
    }

    /// A request finished; returns the run to start after a successful push.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        success: bool,
        message: &str,
    ) -> Option<ExecRequest> {
        let (pending, run) = self.pending.take_if(|(pending, _)| *pending == id)?;
        let _ = pending;
        self.stored = None;
        self.status = Some(if success {
            (format!("Sent into the VM: {message}"), false)
        } else {
            (format!("Could not send the sample: {message}"), true)
        });
        run.filter(|_| success)
    }

    /// Ends the push waiting on command `id` with `message`; a late result for
    /// it is then ignored. Returns whether that push was pending.
    pub(crate) fn cancel_pending(&mut self, id: u64, message: &str) -> bool {
        if self
            .pending
            .take_if(|(pending, _)| *pending == id)
            .is_none()
        {
            return false;
        }
        self.stored = None;
        self.status = Some((message.to_owned(), true));
        true
    }

    /// Ends any pending push with `message`.
    pub(crate) fn cancel_all_pending(&mut self, message: &str) {
        if self.pending.take().is_some() {
            self.stored = None;
            self.status = Some((message.to_owned(), true));
        }
    }
}
