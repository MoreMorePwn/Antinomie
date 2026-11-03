// SPDX-License-Identifier: GPL-3.0-only
//! The window's first-use dialog, warning, status line, source and search rows (moved out of `samples_view`).
use super::*;

impl SamplesView {
    /// Shown instead of the window until the user accepts it once.
    pub(super) fn first_use(&mut self, ctx: &egui::Context, cx: &SamplesContext<'_>) {
        let mut open = true;
        let mut cancel = false;
        crate::widgets::window("Malware samples")
            .id(egui::Id::new(WINDOW_ID).with("first_use"))
            .collapsible(false)
            .resizable(false)
            .default_width(620.0)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .open(&mut open)
            .show(ctx, |ui| {
                // The text scrolls on a short screen or at a large text size;
                // the checkbox and the buttons below it always stay in view.
                let reserved = cx.font_size * 7.0 + 110.0;
                let text_height =
                    (crate::title_bar::content_rect(ctx).height() - reserved).max(90.0);
                egui::ScrollArea::vertical()
                    .max_height(text_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(egui_phosphor::regular::BIOHAZARD)
                                    .size(cx.font_size * 2.0)
                                    .color(theme::warn()),
                            );
                            ui.label(
                                RichText::new("Before you use the malware catalog")
                                    .size(cx.font_size * 1.3)
                                    .strong()
                                    .color(theme::text()),
                            );
                        });
                        ui.add_space(8.0);
                        ui.label(
                            "This window downloads real, live malware from MalwareBazaar (abuse.ch) \
                             or MalShare so you can study it inside a VM.",
                        );
                        ui.add_space(6.0);
                        for point in FIRST_USE_POINTS {
                            // Wrapped lines hang under the text, not the bullet.
                            ui.horizontal_top(|ui| {
                                ui.label("•");
                                ui.add(egui::Label::new(*point).wrap());
                            });
                            ui.add_space(2.0);
                        }
                    });
                ui.add_space(8.0);
                ui.checkbox(
                    &mut self.understood,
                    "I understand these are live malware samples and I am responsible for \
                     handling them safely and lawfully.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.understood, egui::Button::new("Continue"))
                        .clicked()
                    {
                        match samples::acknowledge(cx.data_dir) {
                            Ok(()) => {
                                self.acknowledged = true;
                                self.status = None;
                            }
                            Err(error) => self.status = Some((error, true)),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if !open || cancel || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
            self.understood = false;
        }
    }

    pub(super) fn warning(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        egui::Frame::new()
            .fill(theme::panel())
            .stroke(egui::Stroke::new(1.0_f32, theme::line()))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.colored_label(theme::warn(), egui_phosphor::regular::BIOHAZARD);
                    crate::activity::inline_only(
                        ui,
                        crate::activity::Level::Warn,
                        LIVE_MALWARE_NOTICE,
                    );
                });
                if let Some(text) = &cx.network_warning {
                    ui.add_space(4.0);
                    crate::activity::warning(ui, text);
                }
            });
    }

    /// One line, always the same height, between the filters and the results:
    /// what is loading, the last outcome, or what the results are. The window
    /// does not change size when a search or a download starts or ends.
    pub(super) fn status_line(&mut self, ui: &mut egui::Ui) {
        let mut cleared = false;
        ui.horizontal(|ui| {
            ui.set_min_height(ui.spacing().interact_size.y);
            if self.searching.is_some() {
                crate::theme::spinner(ui);
                ui.colored_label(theme::muted(), format!("Asking {}…", self.source.label()));
            } else if let Some((message, _)) = &self.status {
                cleared = crate::activity::status(ui, crate::activity::Level::Info, message, None);
            } else if !self.results.is_empty() && !self.listing.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(&self.listing).color(theme::muted())).truncate(),
                )
                .on_hover_text(&self.listing);
            }
        });
        if cleared {
            self.status = None;
        }
    }

    /// The source to search: each has its own key and its own results.
    pub(super) fn source_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut switch = None;
        crate::widgets::tab_row(ui, |ui| {
            ui.label(RichText::new("Source").color(theme::muted()));
            for source in Source::ALL {
                if crate::widgets::tab(
                    ui,
                    self.source == source,
                    &crate::widgets::TabItem::new(source.label()),
                )
                .on_hover_text(match source {
                    Source::MalwareBazaar => {
                        "abuse.ch's MalwareBazaar: families, tags, architectures"
                    }
                    Source::MalShare => "MalShare: hashes, file types, file names and sources",
                })
                .clicked()
                    && self.source != source
                {
                    switch = Some(source);
                }
            }
        });
        if let Some(source) = switch {
            if let Some(cancel) = &self.search_cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            self.search_generation = self.search_generation.wrapping_add(1);
            self.source = source;
            if source == Source::MalShare && self.range_start.is_empty() {
                if let Ok((start, end)) = antinomie_monitor_core::malshare::recent_date_range(7) {
                    self.range_start = start;
                    self.range_end = end;
                }
            }
            self.key = samples::source_key(cx.data_dir, source);
            self.key_saved = !self.key.is_empty();
            self.results.clear();
            self.listing.clear();
            self.filters = Filters::default();
            self.sort = None;
            self.status = None;
            self.text.clear();
            self.catalog_errors.clear();
            self.catalog_progress = None;
            // The newest samples of the new source, once there is a key.
            self.listed = false;
        }
    }

    /// No key yet: it is set in Tools > API keys, not here.
    pub(super) fn key_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "{} needs a {}.",
                self.source.label(),
                samples::source_api_key(self.source).label()
            ));
            if ui.button("Open API keys…").clicked() {
                self.want_keys = true;
            }
            ui.hyperlink_to(
                format!("Get a key {}", egui_phosphor::regular::ARROW_SQUARE_OUT),
                self.source.keys_url(),
            );
        });
    }

    /// The key was changed in Tools > API keys: read it again.
    pub(crate) fn key_changed(&mut self) {
        self.key_loaded = false;
        self.listed = false;
    }

    pub(super) fn search_bar(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut search = None;
        let mut all = false;
        let ready = self.key_saved && self.searching.is_none();
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(format!("{} Key", egui_phosphor::regular::KEY))
                    .on_hover_text(format!(
                        "Change the {} in Tools > API keys",
                        samples::source_api_key(self.source).label()
                    ))
                    .clicked()
                {
                    self.want_keys = true;
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest (all)"))
                    .on_hover_text(match self.source {
                        Source::MalwareBazaar => {
                            "MalwareBazaar's latest 100 uploads of every type (it lists no \
                             architectures for these)"
                        }
                        Source::MalShare => {
                            "This list is the last 24 hours, not an archive (hashes only until \
                             searched or downloaded)"
                        }
                    })
                    .clicked()
                {
                    self.text.clear();
                    all = true;
                }
                if self.source == Source::MalShare
                    && ui
                        .add_enabled(
                            self.searching.is_none(),
                            egui::Button::new("Newest in range"),
                        )
                        .on_hover_text(
                            "Official dated SHA-256 lists. This is separate from the last-24-hours list. Cached-only mode covers local metadata. Archive dates are date-only observations, not first-seen timestamps. Type and architecture are unknown until a sample is downloaded.",
                        )
                        .clicked()
                {
                    self.search_dated(cx, false);
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest Linux"))
                    .on_hover_text(match self.source {
                        Source::MalwareBazaar => {
                            "The newest ELF programs and shell scripts: what the VMs run"
                        }
                        Source::MalShare => "This list is the last 24 hours, not an archive",
                    })
                    .clicked()
                {
                    self.text.clear();
                    search = Some(String::new());
                }
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(
                            RichText::new(format!(
                                "{} Search",
                                egui_phosphor::regular::MAGNIFYING_GLASS
                            ))
                            .color(theme::palette().primary_text),
                        )
                        .fill(theme::primary()),
                    )
                    .clicked()
                {
                    search = Some(self.text.clone());
                }
                if self.searching.is_some() {
                    crate::theme::spinner(ui);
                    if let Some(cancel) = &self.search_cancel
                        && ui.button("Cancel").clicked()
                    {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
                let edit = ui.add_sized(
                    egui::vec2(ui.available_width(), ui.spacing().interact_size.y),
                    egui::TextEdit::singleline(&mut self.text)
                        .hint_text(crate::theme::hint_text(format!(
                            "{}  {}",
                            egui_phosphor::regular::MAGNIFYING_GLASS,
                            match self.source {
                                Source::MalwareBazaar =>
                                    "Family, tag, file type or hash (Mirai, x86-64, elf, a SHA-256…)",
                                Source::MalShare =>
                                    "Hash, file type (elf, pe32) or a word in file names and sources",
                            }
                        )))
                        .margin(theme::TEXT_EDIT_MARGIN),
                );
                if ready
                    && edit.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter))
                {
                    search = Some(self.text.clone());
                }
            });
        });
        ui.add_space(6.0);
        if self.source == Source::MalShare {
            ui.horizontal_wrapped(|ui| {
                for (label, day_count) in [("7 days", 7), ("30 days", 30)] {
                    if ui.button(label).clicked() {
                        match antinomie_monitor_core::malshare::recent_date_range(day_count) {
                            Ok((start, end)) => {
                                self.range_start = start;
                                self.range_end = end;
                            }
                            Err(error) => self.status = Some((error, true)),
                        }
                    }
                }
                ui.label("From");
                ui.add(
                    egui::TextEdit::singleline(&mut self.range_start)
                        .desired_width(120.0)
                        .hint_text(crate::theme::hint_text("YYYY-MM-DD")),
                );
                ui.label("through");
                ui.add(
                    egui::TextEdit::singleline(&mut self.range_end)
                        .desired_width(120.0)
                        .hint_text(crate::theme::hint_text("YYYY-MM-DD")),
                );
                ui.checkbox(&mut self.offline, "Offline");
                if ui
                    .add_enabled(
                        self.searching.is_none(),
                        egui::Button::new("All cached metadata"),
                    )
                    .clicked()
                {
                    self.search_dated(cx, true);
                }
                if self.search_cancel.is_some() && ui.button("Cancel").clicked() {
                    if let Some(cancel) = &self.search_cancel {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
            });
            if let Some(progress) = &self.catalog_progress {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "{}: {}/{} days, {} cached, {} unavailable",
                        progress.day,
                        progress.done_days,
                        progress.total_days,
                        progress.cached_days,
                        progress.failed_days
                    ),
                );
            }
            if !self.catalog_errors.is_empty() {
                egui::CollapsingHeader::new("Unavailable days / retry details")
                    .show(ui, |ui| {
                        for error in &self.catalog_errors {
                            crate::activity::error(
                                ui,
                                format!(
                                    "MalShare lookup failed for {error}. Retry the range to resume."
                                ),
                            );
                        }
                    })
                    .header_response
                    .on_hover_text(
                        "Retry the range to resume. Successfully cached days are reused.",
                    );
            }
            ui.colored_label(theme::muted(), "Last 24 hours; ranges up to 366 UTC days.");
            if all {
                self.search_all(cx);
            } else if let Some(text) = search {
                self.search(cx, text);
            }
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Linux families:").color(theme::muted()));
            for (name, about) in samples::STARTERS {
                if ui
                    .add_enabled(ready, egui::Button::new(*name).small())
                    .on_hover_text(*about)
                    .clicked()
                {
                    self.text = (*name).into();
                    search = Some((*name).into());
                }
            }
        });
        if all {
            self.search_all(cx);
        } else if let Some(text) = search {
            self.search(cx, text);
        }
    }
}
