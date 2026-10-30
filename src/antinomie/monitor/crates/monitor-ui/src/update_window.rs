// SPDX-License-Identifier: GPL-3.0-only
//! Help > Check for updates: asks GitHub for the latest Antinomie release
//! when the person asks, and says whether it is newer than this one. Nothing
//! is downloaded or installed, and nothing is asked at startup. Like the rule
//! catalogue, it uses the network only when Tools > Settings > Detection >
//! "Allow outbound catalog and rule downloads" is on.
use crate::theme;
use antinomie_monitor_core::{
    update_check::{self, UpdateStatus},
    APP_VERSION,
};
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
        Arc,
    },
    thread::JoinHandle,
};

/// The window's egui ID.
pub(crate) const WINDOW_ID: &str = "update_check";

type Answer = Result<UpdateStatus, String>;

#[derive(Default)]
pub(crate) struct UpdateWindow {
    pub open: bool,
    /// The last answer: a status, or why there is none.
    answer: Option<Answer>,
    worker: Option<(Receiver<Answer>, JoinHandle<()>, Arc<AtomicBool>)>,
}

impl UpdateWindow {
    /// Help > Check for updates: show the window and, when downloads are
    /// allowed, ask now.
    pub(crate) fn request(&mut self, ctx: &egui::Context, curl: &Path, outbound: bool) {
        self.open = true;
        if outbound && self.worker.is_none() {
            self.start(ctx, curl);
        }
    }

    fn start(&mut self, ctx: &egui::Context, curl: &Path) {
        self.answer = None;
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let (curl, flag, wake): (PathBuf, _, _) = (curl.to_path_buf(), cancel.clone(), ctx.clone());
        match std::thread::Builder::new()
            .name("antinomie-update-check".into())
            .spawn(move || {
                let answer =
                    update_check::check(APP_VERSION, &update_check::CurlGet { curl: &curl }, &flag);
                // The window may have closed with the app.
                let _ = sender.send(answer);
                wake.request_repaint();
            }) {
            Ok(thread) => self.worker = Some((receiver, thread, cancel)),
            Err(error) => {
                self.answer = Some(Err(format!("Could not start the check: {error}")));
            }
        }
    }

    fn poll(&mut self) {
        let Some((receiver, _, _)) = &self.worker else {
            return;
        };
        self.answer = match receiver.try_recv() {
            Ok(answer) => Some(answer),
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Some(Err("The check stopped unexpectedly.".into())),
        };
        if let Some((_, thread, _)) = self.worker.take() {
            let _ = thread.join();
        }
    }

    #[cfg(test)]
    pub(crate) fn with_answer_for_test(answer: Answer) -> Self {
        Self {
            open: true,
            answer: Some(answer),
            worker: None,
        }
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context, curl: &Path, outbound: &mut bool) {
        if !self.open {
            return;
        }
        self.poll();
        if self.worker.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
        let mut open = true;
        let mut ask = false;
        crate::widgets::window("Check for updates")
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("This is Antinomie {APP_VERSION}."));
                ui.add_space(4.0);
                if self.worker.is_some() {
                    theme::loading(ui, "Asking GitHub for the latest release…");
                } else if !*outbound && self.answer.is_none() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new("Downloads are off.").color(theme::muted()));
                        if ui
                            .button("Allow downloads")
                            .on_hover_text(
                                "Antinomie contacts no server unless you allow it. This turns on \
                                 Tools > Settings > Detection > Allow outbound catalog and rule \
                                 downloads. The check sends one request to api.github.com, only \
                                 when you ask.",
                            )
                            .clicked()
                        {
                            *outbound = true;
                            ask = true;
                        }
                    });
                } else {
                    answer_text(ui, self.answer.as_ref());
                }
                ui.add_space(6.0);
                if ui
                    .add_enabled(
                        self.worker.is_none() && *outbound,
                        egui::Button::new(if self.answer.is_some() {
                            "Check again"
                        } else {
                            "Check now"
                        }),
                    )
                    .on_hover_text("Sends one request to api.github.com")
                    .clicked()
                {
                    ask = true;
                }
                ui.weak("Nothing is downloaded or installed.");
            });
        if ask && self.worker.is_none() {
            self.start(ctx, curl);
        }
        if !open || self.escape(ctx) {
            self.open = false;
        }
    }

    /// Escape closes the window when it is the topmost one.
    fn escape(&self, ctx: &egui::Context) -> bool {
        if !ctx.input(|input| input.key_pressed(egui::Key::Escape))
            || ctx.memory(|memory| memory.any_popup_open() || memory.focused().is_some())
        {
            return false;
        }
        let ours = egui::Id::new(WINDOW_ID);
        let top = ctx.memory(|memory| {
            memory
                .layer_ids()
                .filter(|layer| layer.order == egui::Order::Middle)
                .last()
                .map(|layer| layer.id)
        });
        let closes = top == Some(ours);
        if closes {
            ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
        }
        closes
    }
}

impl Drop for UpdateWindow {
    fn drop(&mut self) {
        if let Some((_, thread, cancel)) = self.worker.take() {
            cancel.store(true, Ordering::Relaxed);
            let _ = thread.join();
        }
    }
}

/// What the last check found, in words, with the release link.
fn answer_text(ui: &mut egui::Ui, answer: Option<&Answer>) {
    match answer {
        None => {}
        Some(Ok(UpdateStatus::Newer(release))) => {
            ui.colored_label(
                theme::good(),
                format!("A newer version is available: {}.", release.version),
            );
            ui.hyperlink_to(
                format!(
                    "Open the release page {}",
                    egui_phosphor::regular::ARROW_SQUARE_OUT
                ),
                &release.url,
            );
        }
        Some(Ok(UpdateStatus::Current(release))) => {
            ui.colored_label(
                theme::good(),
                format!("You have the latest version ({}).", release.version),
            );
        }
        Some(Ok(UpdateStatus::Ahead(release))) => {
            ui.label(format!(
                "This version is newer than the latest release ({}).",
                release.version
            ));
        }
        Some(Err(message)) => {
            crate::activity::error(ui, message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::update_check::Release;

    fn release(version: &str) -> Release {
        Release {
            tag: format!("v{version}"),
            version: version.into(),
            url: format!("{}/releases/tag/v{version}", update_check::REPOSITORY_URL),
        }
    }

    #[test]
    fn nothing_is_asked_while_downloads_are_off() {
        let ctx = egui::Context::default();
        let mut window = UpdateWindow::default();
        window.request(&ctx, Path::new("curl"), false);
        assert!(window.open);
        assert!(window.worker.is_none());
        assert!(window.answer.is_none());
    }

    /// The text a frame of the window draws.
    fn frame(ctx: &egui::Context, window: &mut UpdateWindow, outbound: &mut bool) -> String {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 600.0),
                )),
                ..Default::default()
            },
            |ctx| window.show(ctx, Path::new("curl"), outbound),
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

    fn text_of(window: &mut UpdateWindow, outbound: bool) -> String {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut outbound = outbound;
        frame(&ctx, window, &mut outbound);
        frame(&ctx, window, &mut outbound)
    }

    #[test]
    fn the_window_says_what_the_check_found() {
        for (answer, expected) in [
            (
                Ok(UpdateStatus::Newer(release("9.9.9"))),
                "A newer version is available: 9.9.9",
            ),
            (
                Ok(UpdateStatus::Current(release("0.8.0"))),
                "You have the latest version",
            ),
            (
                Ok(UpdateStatus::Ahead(release("0.1.0"))),
                "newer than the latest release",
            ),
            (
                Err("GitHub is limiting requests.".to_owned()),
                "GitHub is limiting requests.",
            ),
        ] {
            let mut window = UpdateWindow::with_answer_for_test(answer);
            let text = text_of(&mut window, true);
            assert!(text.contains(expected), "{expected}: {text}");
            assert!(
                text.contains("Nothing is downloaded or installed"),
                "{text}"
            );
        }
    }

    #[test]
    fn with_downloads_off_the_window_offers_to_allow_them_and_asks_nothing() {
        let mut window = UpdateWindow::default();
        window.open = true;
        let text = text_of(&mut window, false);
        assert!(text.contains("Downloads are off."), "{text}");
        assert!(text.contains("Allow downloads"), "{text}");
        assert!(window.worker.is_none());
    }
}
