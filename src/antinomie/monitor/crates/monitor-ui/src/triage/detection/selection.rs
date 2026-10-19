// SPDX-License-Identifier: MIT
//! The digest of the rules each engine would use, computed off the UI thread.
use super::*;

/// The rule-selection digest of each engine, for one rule generation and set
/// of tool facts.
pub(super) struct SelectionDigests {
    pub epoch: u64,
    pub generation: u64,
    pub facts: antinomie_monitor_core::ruleset::ToolFacts,
    pub digests: [String; 3],
}

impl View {
    pub(super) fn current_digest(&mut self, ctx: &egui::Context, index: usize) -> String {
        if self.settings.rules_root.is_empty() {
            return String::new();
        }
        let Some(registry) = self.fresh_registry().cloned() else {
            self.request_registry(ctx);
            return "preparing".into();
        };
        let tools = antinomie_monitor_core::ruleset::ToolConfig::from_sigma_setting(
            &self.settings.effective_sigma_python(),
        );
        let repaint = ctx.clone();
        let Some(facts) = antinomie_monitor_core::ruleset::try_tool_facts(&tools, move || {
            repaint.request_repaint_of(egui::ViewportId::ROOT)
        }) else {
            return "preparing".into();
        };
        if let Some(rx) = &self.selection_rx {
            match rx.try_recv() {
                Ok(done) => {
                    self.selection_rx = None;
                    if done.epoch == self.epoch && done.generation == self.rules_generation {
                        let tools_changed = self
                            .digest_facts
                            .as_ref()
                            .is_some_and(|old| *old != done.facts);
                        self.digest_cache = done.digests;
                        self.digest_generation = done.generation;
                        self.digest_facts = Some(done.facts);
                        if tools_changed {
                            // A tool appeared, changed or went away: the selection is
                            // different even though no rule changed.
                            self.auto_key = Default::default();
                        }
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => self.selection_rx = None,
                Err(mpsc::TryRecvError::Empty) => return "preparing".into(),
            }
        }
        if self.digest_generation != self.rules_generation
            || self.digest_facts.as_ref() != Some(&facts)
        {
            // Reading the retained requirements touches the disk: not on the
            // UI thread.
            let (tx, rx) = mpsc::sync_channel(1);
            let (epoch, generation) = (self.epoch, self.rules_generation);
            let root = PathBuf::from(&self.settings.rules_root);
            let repaint = ctx.clone();
            let sent = facts.clone();
            let spawned = std::thread::Builder::new()
                .name("triage-selection-digest".into())
                .spawn(move || {
                    let digests = ENGINES.map(|engine| {
                        antinomie_monitor_core::ruleset::selection_digest_of(
                            &root,
                            &registry,
                            engine_key(engine),
                            &sent,
                        )
                    });
                    let _ = tx.send(SelectionDigests {
                        epoch,
                        generation,
                        facts: sent,
                        digests,
                    });
                    repaint.request_repaint_of(egui::ViewportId::ROOT);
                })
                .is_ok();
            if spawned {
                self.selection_rx = Some(rx);
            }
            return "preparing".into();
        }
        self.digest_cache[index].clone()
    }
}
