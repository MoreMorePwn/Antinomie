// SPDX-License-Identifier: GPL-3.0-only
//! Settings: a page list at the left, the chosen page at the right (the
//! mockup's layout). Appearance and the other pages apply at once; the
//! Recording page applies on Save.
use super::dialogs::{form_grid, text_size_control};
use super::*;
use crate::widgets::{self, chip, Tone};

/// The pages of the Settings window, in list order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SettingsPage {
    #[default]
    Appearance,
    Recording,
    Detection,
    Notifications,
    NetworkLookup,
    AnalysisTools,
    Disks,
    Advanced,
}

impl SettingsPage {
    pub(super) const ALL: [SettingsPage; 8] = [
        SettingsPage::Appearance,
        SettingsPage::Recording,
        SettingsPage::Detection,
        SettingsPage::Notifications,
        SettingsPage::NetworkLookup,
        SettingsPage::AnalysisTools,
        SettingsPage::Disks,
        SettingsPage::Advanced,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            SettingsPage::Appearance => "Appearance",
            SettingsPage::Recording => "Recording",
            SettingsPage::Detection => "Detection",
            SettingsPage::Notifications => "Notifications",
            SettingsPage::NetworkLookup => "Network lookup",
            SettingsPage::AnalysisTools => "Analysis tools",
            SettingsPage::Disks => "Disks",
            SettingsPage::Advanced => "Advanced",
        }
    }
}

const NAV_WIDTH: f32 = 150.0;

/// One entry of the page list.
fn nav_item(ui: &mut egui::Ui, label: &str, active: bool) -> egui::Response {
    let palette = theme::palette();
    let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y + 2.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, active, label)
    });
    if active {
        ui.painter().rect_filled(rect, 4.0, palette.selection_soft);
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 4.0, palette.hover);
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(10.0, 0.0),
        egui::Align2::LEFT_CENTER,
        label,
        egui::TextStyle::Body.resolve(ui.style()),
        if active || response.hovered() {
            palette.text
        } else {
            palette.muted
        },
    );
    response
}

/// A hint line under a control, in the muted color.
fn hint(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap());
}

impl MonitorApp {
    /// Settings: the page list, the page and a footer that stays in view.
    pub(super) fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut save = false;
        let mut close = false;
        let screen = ctx.screen_rect();
        let width = 820.0_f32.min((screen.width() - 50.0).max(320.0));
        // The page area scrolls; the title and the footer stay visible on a
        // short screen.
        let height = (screen.height() - 190.0).clamp(160.0, 440.0);
        widgets::window("Settings")
            .id(Dialog::Settings.window_id())
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(width)
            .default_height(0.0)
            .default_pos(egui::pos2(
                (screen.center().x - width * 0.5).max(0.0),
                screen.top() + 32.0,
            ))
            .max_height((screen.height() - 40.0).max(200.0))
            .show(ctx, |ui| {
                ui.set_width(width - 20.0);
                let gap = ui.spacing().item_spacing.x;
                let line = 1.0;
                let content = (ui.available_width() - NAV_WIDTH - line - 2.0 * gap).max(120.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(NAV_WIDTH, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(NAV_WIDTH);
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for page in SettingsPage::ALL {
                                if nav_item(ui, page.label(), self.settings_page == page).clicked()
                                {
                                    self.settings_page = page;
                                }
                            }
                        },
                    );
                    let (rule, _) =
                        ui.allocate_exact_size(egui::vec2(line, height), egui::Sense::hover());
                    ui.painter().vline(
                        rule.center().x,
                        rule.y_range(),
                        egui::Stroke::new(1.0_f32, theme::line_soft()),
                    );
                    ui.allocate_ui_with_layout(
                        egui::vec2(content, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(content);
                            egui::ScrollArea::vertical()
                                .id_salt("settings_page")
                                .max_height(height)
                                .auto_shrink([false, false])
                                .show(ui, |ui| self.settings_page(ui, ctx));
                        },
                    );
                });
                let stopped = self.snapshot.active_vm.is_none();
                widgets::footer_split(
                    ui,
                    |ui| {
                        let room = (ui.available_width() - 190.0).max(60.0);
                        ui.scope(|ui| {
                            ui.set_max_width(room);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(if stopped {
                                        "Appearance applies at once · Recording applies on Save"
                                    } else {
                                        "A VM is running: Recording applies after it stops"
                                    })
                                    .small()
                                    .color(theme::muted()),
                                )
                                .truncate(),
                            );
                        });
                    },
                    |ui| {
                        save = ui
                            .add_enabled(stopped, primary_button("Save settings"))
                            .clicked();
                        close = ui.button("Close").clicked();
                    },
                );
            });
        self.settings_open = open && !close;
        if save {
            self.update_options();
            self.settings_open = false;
        }
    }

    fn settings_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        match self.settings_page {
            SettingsPage::Appearance => self.appearance_page(ui, ctx),
            SettingsPage::Recording => self.recording_page(ui),
            SettingsPage::Detection => self.detection_page(ui),
            SettingsPage::Notifications => self.notifications_page(ui),
            SettingsPage::NetworkLookup => self.lookup_page(ui),
            SettingsPage::AnalysisTools => self.tools_page(ui),
            SettingsPage::Disks => self.disks_page(ui),
            SettingsPage::Advanced => self.advanced_page(ui),
        }
    }

    fn appearance_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        form_grid("settings_appearance", ui).show(ui, |ui| {
            ui.label("Theme");
            let mut chosen = self.settings.active_theme();
            if widgets::segmented(
                ui,
                theme::Theme::ALL
                    .into_iter()
                    .map(|theme| (theme, widgets::TabItem::new(theme.label()))),
                &mut chosen,
            ) {
                self.settings.set_theme(chosen);
                theme::apply_theme(ctx, chosen);
                theme::text_size(ctx, self.settings.font_size);
            }
            ui.end_row();
            ui.label("Text size");
            let before = self.settings.font_size;
            text_size_control(ui, &mut self.settings.font_size);
            if self.settings.font_size != before {
                theme::text_size(ctx, self.settings.font_size);
                for terminal in self.terminals.values_mut() {
                    terminal.terminal.invalidate_resize();
                }
            }
            ui.end_row();
            ui.label("Density");
            ui.vertical(|ui| {
                let before = self.settings.compact;
                widgets::segmented(
                    ui,
                    [
                        (true, widgets::TabItem::new("Compact")),
                        (false, widgets::TabItem::new("Comfortable")),
                    ],
                    &mut self.settings.compact,
                );
                if self.settings.compact != before {
                    theme::set_compact(ctx, self.settings.compact);
                }
                hint(
                    ui,
                    "Compact: tight rows and spacing. Comfortable: taller rows and roomier margins everywhere.",
                );
            });
            ui.end_row();
            ui.label("Trace colors");
            ui.checkbox(
                &mut self.settings.trace_colors,
                "Color syscall rows by category",
            )
            .on_hover_text("Tint each syscall by its category, like Wireshark's coloring rules");
            ui.end_row();
        });
        ui.add_space(10.0);
        hint(ui, "Appearance changes apply at once.");
    }

    fn recording_page(&mut self, ui: &mut egui::Ui) {
        if self.snapshot.active_vm.is_some() {
            crate::activity::warning(ui, "Stop the running VM to change these.");
        }
        ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
            form_grid("settings_recording", ui).show(ui, |ui| {
                ui.label("Installed base");
                let mut base = self
                    .snapshot
                    .bases
                    .iter()
                    .find(|base| base.directory == std::path::Path::new(&self.settings.bundle))
                    .or_else(|| preferred_new_base(&self.snapshot, &self.settings.bundle))
                    .map(|base| base.id.clone());
                base_selector(ui, &self.snapshot, &mut base, "settings_base");
                if let Some(base) = base
                    .and_then(|id| self.snapshot.bases.iter().find(|base| base.id == id))
                {
                    self.settings.bundle = base.directory.to_string_lossy().into_owned();
                }
                ui.end_row();
                ui.label("Recording quota");
                ui.add(
                    egui::DragValue::new(&mut self.settings.quota_gib)
                        .range(1..=4096)
                        .suffix(" GiB"),
                );
                ui.end_row();
                ui.label("Process cores: default budget");
                ui.add(
                    egui::DragValue::new(&mut self.settings.core_budget_mib)
                        .range(1..=1024)
                        .suffix(" MiB"),
                )
                .on_hover_text(
                    "Stored-byte budget a process core starts with. Each guest accepts up to a maximum of its own, so the budget in effect can be lower.",
                );
                ui.end_row();
                ui.label("Shutdown timeout");
                ui.add(
                    egui::DragValue::new(&mut self.settings.timeout)
                        .range(1..=120)
                        .suffix(" s"),
                );
                ui.end_row();
                if let Some(path) = &self.snapshot.capture_dir {
                    ui.label("Recording");
                    ui.add(
                        egui::Label::new(RichText::new(path.display().to_string()).monospace())
                            .truncate(),
                    )
                    .on_hover_text(path.display().to_string());
                    ui.end_row();
                }
            });
        });
    }

    fn detection_page(&mut self, ui: &mut egui::Ui) {
        form_grid("settings_detection", ui).show(ui, |ui| {
            ui.label("After a run");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.automatic_detection,
                    "Scan retained evidence when it is ready",
                );
                hint(
                    ui,
                    "Runs each engine once per ready input and rule selection. Scan still works when this is off.",
                );
            });
            ui.end_row();
            ui.label("Downloads");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.outbound_catalog,
                    "Allow outbound catalog and rule downloads",
                );
                hint(
                    ui,
                    "Only the Detection rules Check and Download buttons use the network. Scans stay offline.",
                );
            });
            ui.end_row();
            ui.label("Rule packs");
            if ui.button("Open Detection rules…").clicked() {
                self.open_library(crate::workspace::LibraryPage::Rules);
            }
            ui.end_row();
        });
    }

    fn notifications_page(&mut self, ui: &mut egui::Ui) {
        form_grid("settings_notifications", ui).show(ui, |ui| {
            ui.label("Live findings");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.toast_high_findings,
                    "Toast for live HIGH findings",
                );
                hint(
                    ui,
                    "The first HIGH finding of each rule in a run that is still going raises one toast; later matches of the same rule add ×N to it. Applies at once.",
                );
            });
            ui.end_row();
        });
    }

    fn lookup_page(&mut self, ui: &mut egui::Ui) {
        use crate::triage::AddressLookup;
        form_grid("settings_lookup", ui).show(ui, |ui| {
            ui.label("Address lookup");
            ui.vertical(|ui| {
                for (mode, label) in [
                    (AddressLookup::Tshark, "TShark GeoIP only"),
                    (AddressLookup::Whois, "dig and whois only"),
                    (
                        AddressLookup::TsharkThenWhois,
                        "TShark GeoIP, then dig and whois when unavailable",
                    ),
                ] {
                    ui.radio_value(&mut self.settings.address_lookup, mode, label);
                }
                hint(
                    ui,
                    "Public destination addresses get a country and organization. Local addresses stay “-” and “local network” and are never queried.",
                );
            });
            ui.end_row();
        });
    }

    fn tools_page(&mut self, ui: &mut egui::Ui) {
        ui.add(
            egui::Label::new(
                "Static analysis uses these tools when they are installed on this system. Downloads are checked by SHA-256 and used read-only by the analysis sandbox.",
            )
            .wrap(),
        );
        ui.add_space(6.0);
        if self.snapshot.analysis_tools.is_empty() {
            theme::loading_weak(ui, "Reading the tool list…");
        }
        for tool in &self.snapshot.analysis_tools {
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&tool.name).strong().color(theme::text()));
                ui.label(RichText::new(&tool.purpose).small().color(theme::muted()));
            });
            let (text, tone) = match (&tool.system, &tool.installed) {
                (Some(_), _) => ("On this system".to_owned(), Tone::Good),
                (None, Some(version)) => (format!("Installed {version}"), Tone::Good),
                (None, None) => ("Not installed".to_owned(), Tone::Warn),
            };
            chip(ui, text, tone);
        }
        ui.add_space(8.0);
        if ui.button("Manage tools…").clicked() {
            self.open_library(crate::workspace::LibraryPage::Tools);
        }
        ui.add_space(10.0);
        ui.separator();
        form_grid("settings_debugger_console", ui).show(ui, |ui| {
            ui.label("Debugger console");
            ui.vertical(|ui| {
                crate::widgets::segmented(
                    ui,
                    crate::app::debugger::GdbFlavour::ALL
                        .into_iter()
                        .map(|flavour| (flavour, crate::widgets::TabItem::new(flavour.label()))),
                    &mut self.settings.debugger.gdb_flavour,
                );
                hint(
                    ui,
                    "The gdb in the Debugger tab. GEF (bata24) runs on this system's gdb; pwndbg \
                     brings its own. Install either from Manage tools. Applies the next time the \
                     console starts.",
                );
            });
            ui.end_row();
        });
    }

    fn disks_page(&mut self, ui: &mut egui::Ui) {
        ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
            form_grid("settings_disks", ui).show(ui, |ui| {
                ui.label("Extraction limit");
                ui.add(
                    egui::DragValue::new(&mut self.settings.disks.extract_cap_mib)
                        .range(1..=4096)
                        .suffix(" MiB"),
                )
                .on_hover_text("Largest guest file the Disks tab extracts without asking");
                ui.end_row();
                ui.label("Hash limit");
                ui.add(
                    egui::DragValue::new(&mut self.settings.disks.hash_cap_mib)
                        .range(1..=1024)
                        .suffix(" MiB"),
                )
                .on_hover_text("Largest guest file the Disks tab hashes on request");
                ui.end_row();
                ui.label("Dump hashes");
                ui.vertical(|ui| {
                    ui.checkbox(
                        &mut self.settings.disks.dump_hash,
                        "SHA-256 of each disk dump",
                    )
                    .on_hover_text(
                        "Hash the whole image of a disk dump (what sha256sum prints). \
                         Views are never hashed.",
                    );
                    ui.checkbox(
                        &mut self.settings.disks.source_digests,
                        "SHA-256 of each source layer",
                    )
                    .on_hover_text(
                        "Also hash every layer of the disk chain a dump was read from. \
                         Doubles the time of a dump; for evidence-grade provenance.",
                    );
                });
                ui.end_row();
            });
        });
        if self.snapshot.active_vm.is_some() {
            crate::activity::warning(ui, "Stop the running VM to change these.");
        }
    }

    fn advanced_page(&mut self, ui: &mut egui::Ui) {
        form_grid("settings_advanced", ui).show(ui, |ui| {
            ui.label("FPS counter");
            ui.vertical(|ui| {
                ui.checkbox(&mut self.settings.show_fps, "Show FPS counter")
                    .on_hover_text(
                        "Shows frames per second, frame time and UI build time in the window corner.",
                    );
                hint(
                    ui,
                    "It reads only frames that are painted anyway, so an idle window shows idle.",
                );
            });
            ui.end_row();
        });
    }
}
