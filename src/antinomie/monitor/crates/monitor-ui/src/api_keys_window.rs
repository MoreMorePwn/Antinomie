// SPDX-License-Identifier: GPL-3.0-only
//! Tools > API keys: the one place a key is typed, replaced, tested or
//! removed. A saved key shows its last four characters only; the text field
//! holds what is being typed and is emptied as soon as it is saved. Nothing
//! here is written to a run, a report or a log.
use crate::theme;
use antinomie_monitor_core::api_keys::{self, ApiKey, Secret};
use eframe::egui::{self, RichText};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
};

/// The window's egui ID (Escape closes it).
pub(crate) const WINDOW_ID: &str = "api_keys";

/// What the window shows of a saved key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct KeyState {
    /// `…a91f`, or `None` when no key is saved.
    masked: Option<String>,
    last_used_ms: Option<u64>,
}

type TestResult = (ApiKey, Result<String, String>);

#[derive(Default)]
pub(crate) struct ApiKeysWindow {
    pub open: bool,
    states: BTreeMap<ApiKey, KeyState>,
    /// Keys being typed; cleared on save.
    drafts: BTreeMap<ApiKey, String>,
    /// The last message of each key and whether it is an error.
    messages: BTreeMap<ApiKey, (String, bool)>,
    testing: Option<(ApiKey, Receiver<TestResult>)>,
    loaded: bool,
    /// Keys changed since the app last asked.
    changed: bool,
}

impl ApiKeysWindow {
    fn reload(&mut self, data_dir: &Path) {
        for key in ApiKey::ALL {
            let secret = api_keys::get(data_dir, key);
            self.states.insert(
                key,
                KeyState {
                    masked: (!secret.is_empty()).then(|| api_keys::masked(&secret)),
                    last_used_ms: api_keys::last_used(data_dir, key),
                },
            );
        }
        self.loaded = true;
    }

    /// A key was saved or removed since the last call.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    fn save(&mut self, data_dir: &Path, key: ApiKey) {
        let draft = self.drafts.get(&key).cloned().unwrap_or_default();
        match api_keys::set(data_dir, key, &draft) {
            Ok(()) => {
                self.drafts.remove(&key);
                self.messages
                    .insert(key, ("Saved. Press Test to check it.".into(), false));
                self.changed = true;
            }
            Err(error) => {
                self.messages.insert(key, (error, true));
            }
        }
        self.reload(data_dir);
    }

    fn clear(&mut self, data_dir: &Path, key: ApiKey) {
        match api_keys::clear(data_dir, key) {
            Ok(()) => {
                self.messages.insert(key, ("Removed.".into(), false));
                self.changed = true;
            }
            Err(error) => {
                self.messages.insert(key, (error, true));
            }
        }
        self.drafts.remove(&key);
        self.reload(data_dir);
    }

    fn test(&mut self, ctx: &egui::Context, data_dir: &Path, curl: &Path, key: ApiKey) {
        if self.testing.is_some() {
            return;
        }
        let secret: Secret = api_keys::get(data_dir, key);
        let (sender, receiver) = mpsc::channel();
        let (curl, data_dir) = (curl.to_path_buf(), data_dir.to_path_buf());
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("api-key-test".into())
            .spawn(move || {
                let result = api_keys::test(&curl, key, &secret);
                if result.is_ok() {
                    api_keys::record_use(&data_dir, key);
                }
                let _ = sender.send((key, result));
                wake.request_repaint();
            });
        match spawned {
            Ok(_) => {
                self.messages
                    .insert(key, ("Asking the service…".into(), false));
                self.testing = Some((key, receiver));
            }
            Err(error) => {
                self.messages.insert(key, (error.to_string(), true));
            }
        }
    }

    fn poll(&mut self, data_dir: &Path) {
        let Some((_, receiver)) = &self.testing else {
            return;
        };
        match receiver.try_recv() {
            Ok((key, result)) => {
                self.testing = None;
                self.messages.insert(
                    key,
                    match result {
                        Ok(message) => (message, false),
                        Err(error) => (error, true),
                    },
                );
                self.reload(data_dir);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                if let Some((key, _)) = self.testing.take() {
                    self.messages
                        .insert(key, ("The test ended without an answer.".into(), true));
                }
            }
        }
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context, data_dir: &Path, curl: &Path) {
        if !self.open {
            self.loaded = false;
            return;
        }
        if !self.loaded {
            self.reload(data_dir);
        }
        self.poll(data_dir);
        if self.testing.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let mut open = true;
        crate::widgets::window("API keys")
            .id(egui::Id::new(WINDOW_ID))
            .collapsible(false)
            .resizable(true)
            .default_width(640.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(
                    "Keys are kept in the data folder, readable only by you. They are never \
                     written to run exports, reports, logs or screenshots, and only the last \
                     four characters are ever shown.",
                );
                for key in ApiKey::ALL {
                    ui.add_space(8.0);
                    ui.separator();
                    self.key_section(ui, ctx, data_dir, curl, key);
                }
            });
        if !open {
            self.open = false;
            // What was typed and not saved is dropped with the window.
            self.drafts.clear();
        }
    }

    fn key_section(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        data_dir: &Path,
        curl: &Path,
        key: ApiKey,
    ) {
        let state = self.states.get(&key).cloned().unwrap_or_default();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(key.label()).strong().color(theme::heading()));
            match &state.masked {
                Some(masked) => ui.colored_label(theme::good(), format!("set ({masked})")),
                None => ui.colored_label(theme::warn(), "not set"),
            };
            ui.hyperlink_to(
                format!("Get a key {}", egui_phosphor::regular::ARROW_SQUARE_OUT),
                key.keys_url(),
            );
        });
        // The key is the root; what uses it hangs below.
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let char_width = crate::tree_lines::char_width(ui, &mono);
        let depths = vec![1; key.features().len()];
        for (feature, prefix) in key
            .features()
            .iter()
            .zip(crate::tree_lines::prefixes(&depths))
        {
            crate::tree_lines::row(ui, &prefix, char_width, |ui| {
                ui.label(RichText::new(*feature).color(theme::text()));
            });
        }
        ui.label(
            RichText::new(match state.last_used_ms {
                Some(ms) => format!("Last used {}", when(ms)),
                None => "Not used yet".to_owned(),
            })
            .color(theme::muted()),
        );
        ui.horizontal_wrapped(|ui| {
            let draft = self.drafts.entry(key).or_default();
            ui.add(
                egui::TextEdit::singleline(draft)
                    .password(true)
                    .hint_text(theme::hint_text(if state.masked.is_some() {
                        "paste a new key to replace it"
                    } else {
                        "paste your key"
                    }))
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(340.0),
            );
            let has_draft = !draft.trim().is_empty();
            if ui
                .add_enabled(has_draft, egui::Button::new("Save"))
                .clicked()
            {
                self.save(data_dir, key);
            }
            if ui
                .add_enabled(
                    state.masked.is_some() && self.testing.is_none(),
                    egui::Button::new("Test"),
                )
                .on_hover_text("Asks the service whether it accepts the saved key")
                .clicked()
            {
                self.test(ctx, data_dir, curl, key);
            }
            if ui
                .add_enabled(state.masked.is_some(), egui::Button::new("Clear"))
                .on_hover_text("Forget the saved key")
                .clicked()
            {
                self.clear(data_dir, key);
            }
        });
        if let Some((message, error)) = self.messages.get(&key) {
            ui.colored_label(
                if *error {
                    theme::error()
                } else {
                    theme::muted()
                },
                message,
            );
        }
    }
}

fn when(ms: u64) -> String {
    i64::try_from(ms / 1000)
        .ok()
        .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0))
        .map(|time| time.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "at an unknown time".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ant-keys-window-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Two frames: a window lays itself out on its first and draws on its second.
    fn render(ctx: &egui::Context, window: &mut ApiKeysWindow, dir: &Path) -> String {
        frame(ctx, window, dir);
        frame(ctx, window, dir)
    }

    fn frame(ctx: &egui::Context, window: &mut ApiKeysWindow, dir: &Path) -> String {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 900.0),
                )),
                ..Default::default()
            },
            |ctx| window.show(ctx, dir, Path::new("curl")),
        );
        fn collect(shape: &egui::epaint::Shape, out: &mut Vec<String>) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let mut lines = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut lines);
        }
        lines.join("\n")
    }

    #[test]
    fn a_saved_key_is_shown_by_its_last_four_characters_only() {
        let dir = temp("show");
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut window = ApiKeysWindow {
            open: true,
            ..Default::default()
        };
        let text = render(&ctx, &mut window, &dir);
        assert!(
            text.contains("API keys") || text.contains("not set"),
            "{text}"
        );
        assert!(text.contains("not set"), "{text}");
        window
            .drafts
            .insert(ApiKey::Abusech, "super-secret-key-a91f".into());
        window.save(&dir, ApiKey::Abusech);
        assert!(window.take_changed());
        assert!(!window.take_changed());
        assert!(!window.drafts.contains_key(&ApiKey::Abusech));
        let text = render(&ctx, &mut window, &dir);
        assert!(text.contains("set (…a91f)"), "{text}");
        assert!(!text.contains("super-secret"), "{text}");
        assert!(text.contains("IOC datasets"), "{text}");
        assert!(text.contains("Not used yet"), "{text}");
        window.clear(&dir, ApiKey::Abusech);
        let text = render(&ctx, &mut window, &dir);
        assert!(text.contains("not set"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_key_is_refused_with_a_reason_and_nothing_is_saved() {
        let dir = temp("bad");
        let mut window = ApiKeysWindow::default();
        window.drafts.insert(ApiKey::MalShare, "not valid!".into());
        window.save(&dir, ApiKey::MalShare);
        assert!(!window.take_changed());
        let (message, error) = window.messages.get(&ApiKey::MalShare).unwrap();
        assert!(*error, "{message}");
        assert!(!api_keys::is_set(&dir, ApiKey::MalShare));
        let _ = std::fs::remove_dir_all(dir);
    }
}
