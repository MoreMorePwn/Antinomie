// SPDX-License-Identifier: GPL-3.0-only
//! After Add file: the MalwareBazaar record of the new sample, looked up by
//! its hash when the user turned that on (Settings > Lookup) and set their
//! own abuse.ch key. Only the SHA-256 is sent; see
//! [`antinomie_monitor_core::samples::lookup_imported`].
use super::*;
use antinomie_monitor_core::api_keys::{self, ApiKey};
use antinomie_monitor_core::samples::{lookup_imported, Lookup};

/// A lookup running in the background.
pub(super) type Pending = Receiver<Result<Lookup, String>>;

impl SamplesPage {
    /// Start the lookup of `sha256` when `allowed` (the setting) and a key is
    /// set; otherwise nothing is started and nothing is sent.
    pub(super) fn start_lookup(
        &mut self,
        ctx: &egui::Context,
        data_dir: &std::path::Path,
        curl: &std::path::Path,
        allowed: bool,
        sha256: &str,
    ) {
        if !allowed || self.looking.is_some() {
            return;
        }
        let key = api_keys::get(data_dir, ApiKey::Abusech);
        if key.is_empty() {
            self.notice = Some((
                "MalwareBazaar lookup is on but no abuse.ch key is set (Tools > API keys)".into(),
                true,
            ));
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let (data_dir, curl, sha256) = (
            data_dir.to_path_buf(),
            curl.to_path_buf(),
            sha256.to_owned(),
        );
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("sample-lookup".into())
            .spawn(move || {
                let cancel = antinomie_monitor_core::cancel::flag();
                let result =
                    lookup_imported(&data_dir, &curl, key.expose(), true, &sha256, &cancel);
                if matches!(result, Ok(Lookup::Recorded { .. } | Lookup::NotListed)) {
                    api_keys::record_use(&data_dir, ApiKey::Abusech);
                }
                let _ = sender.send(result);
                wake.request_repaint();
            });
        match spawned {
            Ok(_) => self.looking = Some(receiver),
            Err(error) => self.notice = Some((error.to_string(), true)),
        }
    }

    /// Take a finished lookup: tell what it found and read the library again.
    pub(super) fn poll_lookup(&mut self) {
        let Some(receiver) = &self.looking else {
            return;
        };
        let Ok(result) = receiver.try_recv() else {
            return;
        };
        self.looking = None;
        match result {
            Ok(done) => {
                if let Some(text) = done.notice() {
                    self.notice = Some((text, false));
                }
                if matches!(done, Lookup::Recorded { .. }) {
                    self.refresh();
                }
            }
            Err(error) => self.notice = Some((format!("MalwareBazaar lookup: {error}"), true)),
        }
    }
}
