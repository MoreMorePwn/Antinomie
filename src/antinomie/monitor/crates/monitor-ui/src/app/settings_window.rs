// SPDX-License-Identifier: GPL-3.0-only
//! Settings: a page list at the left, the chosen page at the right (the
//! mockup's layout). Appearance and the other pages apply at once; the
//! Recording page applies on Save.
use super::dialogs::{form_grid, text_size_control};
use super::widgets::hint_tip;
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
    NetworkRoutes,
    AnalysisTools,
    Disks,
    Keyboard,
    Advanced,
}

impl SettingsPage {
    pub(super) const ALL: [SettingsPage; 10] = [
        SettingsPage::Appearance,
        SettingsPage::Recording,
        SettingsPage::Detection,
        SettingsPage::Notifications,
        SettingsPage::NetworkLookup,
        SettingsPage::NetworkRoutes,
        SettingsPage::AnalysisTools,
        SettingsPage::Disks,
        SettingsPage::Keyboard,
        SettingsPage::Advanced,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            SettingsPage::Appearance => "Appearance",
            SettingsPage::Recording => "Recording",
            SettingsPage::Detection => "Detection rules",
            SettingsPage::Notifications => "Notifications",
            SettingsPage::NetworkLookup => "Network lookup",
            SettingsPage::NetworkRoutes => "Network routes",
            SettingsPage::AnalysisTools => "Analysis tools",
            SettingsPage::Disks => "Disks",
            SettingsPage::Keyboard => "Keyboard",
            SettingsPage::Advanced => "Advanced",
        }
    }
}

/// The least the page list is wide; it grows with the text size so no page
/// name is cut.
const NAV_WIDTH: f32 = 150.0;

/// Width of the page list: the longest page name and the room round it.
fn nav_width(ui: &egui::Ui) -> f32 {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let widest = ui.fonts_mut(|fonts| {
        SettingsPage::ALL
            .iter()
            .map(|page| {
                fonts
                    .layout_no_wrap(
                        page.label().to_owned(),
                        font.clone(),
                        egui::Color32::PLACEHOLDER,
                    )
                    .size()
                    .x
            })
            .fold(0.0_f32, f32::max)
    });
    NAV_WIDTH.max(widest + 24.0)
}

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

/// The flag Settings sets while it draws a page: its form grids then leave
/// more room between rows (see `dialogs::form_grid`).
pub(super) fn roomy_forms() -> egui::Id {
    egui::Id::new("settings_roomy_forms")
}

/// A hint line under a control, in the muted color.
fn hint(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap())
}

impl MonitorApp {
    /// One field for each size and count a check may reach.
    pub(super) fn analysis_limit_fields(&mut self, ui: &mut egui::Ui) {
        let mut focus = self.settings_focus.take();
        form_grid("settings_analysis_size_limits", ui).show(ui, |ui| {
            for field in &antinomie_monitor_core::LIMIT_FIELDS {
                let label = ui.label(field.label);
                if focus == Some(field.setting) {
                    label.scroll_to_me(Some(egui::Align::Center));
                    focus = None;
                }
                ui.vertical(|ui| {
                    let mut value = self.settings.analysis_limits.get(field.setting);
                    let speed = f64::from((field.max - field.min) / 200).max(1.0);
                    let changed = ui
                        .add(
                            egui::DragValue::new(&mut value)
                                .range(field.min..=field.max)
                                .speed(speed)
                                .suffix(format!(" {}", field.unit)),
                        )
                        .on_hover_text(format!("{} to {} {}", field.min, field.max, field.unit))
                        .changed();
                    if changed {
                        self.settings.analysis_limits.set(field.setting, value);
                    }
                    hint_tip(
                        ui,
                        &format!("Default {} {}", field.default, field.unit),
                        &format!("{} Default {} {}.", field.help, field.default, field.unit),
                    );
                });
                ui.end_row();
            }
            ui.label("Ghidra for Disassembly");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.analysis_limits.ghidra_disassembly,
                    "List with Ghidra when Decompilation is not selected",
                )
                .on_hover_text(
                    "A run with Disassembly but without Decompilation also starts Ghidra, which lists \
                     every architecture with labels and cross references. The built-in rows show first. \
                     Needs Ghidra (Manage tools); the time limit and the listing size apply. \
                     With Decompilation selected there is only the one Ghidra run, whatever this says.",
                );
            });
            ui.end_row();
        });
        if ui
            .add_enabled(
                !self.settings.analysis_limits.is_default(),
                egui::Button::new("Reset size limits"),
            )
            .clicked()
        {
            self.settings.analysis_limits = antinomie_monitor_core::AnalysisLimits::default();
        }
    }

    /// Shows the settings page whose list label is `label`.
    pub(super) fn open_settings_page(&mut self, label: &str) {
        let Some(page) = SettingsPage::ALL
            .into_iter()
            .find(|page| page.label() == label)
        else {
            return;
        };
        self.settings_open = true;
        self.settings_page = page;
        if page == SettingsPage::NetworkRoutes {
            self.open_routes_page();
        }
    }

    /// Settings: the page list, the page and a footer that stays in view.
    pub(super) fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut save = false;
        let mut close = false;
        let screen = ctx.content_rect();
        let width = 900.0_f32.min((screen.width() - 50.0).max(320.0));
        // The page area scrolls; the title and the footer stay visible on a
        // short screen.
        let height = (screen.height() - 190.0).clamp(160.0, 440.0);
        widgets::window("Settings")
            .id(Dialog::Settings.window_id())
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            // One width for every page, so the window's edge stays put.
            .default_width(width)
            .min_width(width)
            .max_width(width)
            .default_height(0.0)
            // No default_pos: like every dialog, it opens centred in the window
            // (a position kept from a larger screen put it against the edge).
            .max_height((screen.height() - 40.0).max(200.0))
            .show(ctx, |ui| {
                ui.set_width(width - 20.0);
                let gap = ui.spacing().item_spacing.x;
                let line = 1.0;
                let nav = nav_width(ui);
                let content = (ui.available_width() - nav - line - 2.0 * gap).max(120.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(nav, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(nav);
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for page in SettingsPage::ALL {
                                if nav_item(ui, page.label(), self.settings_page == page).clicked()
                                {
                                    self.settings_page = page;
                                    if page == SettingsPage::NetworkRoutes {
                                        self.open_routes_page();
                                    }
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
                            // Bounded to the page area, so a page with a wide row
                            // cannot widen the window: its edge stays put between
                            // pages.
                            egui::ScrollArea::vertical()
                                .id_salt("settings_page")
                                .max_height(height)
                                .max_width(content)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    // Room at the right, so the scroll bar never lies on
                                    // a text; and roomier rows than in a dialog.
                                    ui.data_mut(|data| data.insert_temp(roomy_forms(), true));
                                    egui::Frame::NONE
                                        .inner_margin(egui::Margin {
                                            right: 18,
                                            ..Default::default()
                                        })
                                        .show(ui, |ui| self.settings_page(ui, ctx));
                                    ui.data_mut(|data| data.remove_temp::<bool>(roomy_forms()));
                                });
                        },
                    );
                });
                let stopped = self.snapshot.active_vm.is_none();
                widgets::footer_split(
                    ui,
                    |ui| {
                        // The buttons grow with the text size; leave their room.
                        let buttons =
                            egui::TextStyle::Button.resolve(ui.style()).size * 12.5 + 16.0;
                        let room = (ui.available_width() - buttons).max(60.0);
                        ui.scope(|ui| {
                            ui.set_max_width(room);
                            if !stopped {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new("Stop the VM to save changes")
                                            .small()
                                            .color(theme::muted()),
                                    )
                                    .truncate(),
                                );
                            }
                        });
                    },
                    |ui| {
                        save = ui
                            .add_enabled(stopped, primary_button("Save settings"))
                            .on_disabled_hover_text("Stop the running VM to save settings.")
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
            SettingsPage::NetworkRoutes => self.routes_page(ui),
            SettingsPage::AnalysisTools => self.tools_page(ui),
            SettingsPage::Disks => self.disks_page(ui),
            SettingsPage::Keyboard => self.keyboard_page(ui, ctx),
            SettingsPage::Advanced => self.advanced_page(ui),
        }
    }

    fn appearance_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        form_grid("settings_appearance", ui).show(ui, |ui| {
            self.appearance_rows(ui, ctx);
            self.time_zone_row(ui);
            ui.label("Trace colors");
            ui.checkbox(
                &mut self.settings.trace_colors,
                "Color syscall rows by category",
            )
            .on_hover_text("Tint each syscall by its category, like Wireshark's coloring rules");
            ui.end_row();
        });
    }

    /// The time zone the app shows times in: the host's, found by itself, or
    /// one chosen here. Stored data stays UTC.
    fn time_zone_row(&mut self, ui: &mut egui::Ui) {
        ui.label("Time zone").on_hover_text(
            "Every time shown in the app and written into a report follows this zone. Recordings keep UTC.",
        );
        let automatic = crate::tzone::Zone::detect();
        let label = |choice: &str| match choice {
            crate::tzone::AUTOMATIC => format!("Automatic ({})", automatic.name()),
            other => other.replace('_', " "),
        };
        let mut chosen = self.settings.time_zone.clone();
        let filter_id = ui.id().with("time-zone-filter");
        ui.vertical(|ui| {
            egui::ComboBox::from_id_salt("settings_time_zone")
                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                .selected_text(label(&chosen))
                .width(260.0)
                .show_ui(ui, |ui| {
                    let mut filter: String = ui.data(|d| d.get_temp(filter_id)).unwrap_or_default();
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut filter)
                            .margin(crate::widgets::clear_margin(egui::Margin::symmetric(4, 2)))
                            .hint_text(crate::theme::placeholder(ui, "Filter zones")),
                    );
                    crate::widgets::clear_button(ui, &edit, &mut filter);
                    if !edit.has_focus() && filter.is_empty() {
                        edit.request_focus();
                    }
                    ui.data_mut(|d| d.insert_temp(filter_id, filter.clone()));
                    let needle = filter.to_lowercase().replace(' ', "_");
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            let mut offer =
                                vec![crate::tzone::AUTOMATIC.to_owned(), "UTC".to_owned()];
                            offer.extend(crate::tzone::choices());
                            for name in offer {
                                if !needle.is_empty()
                                    && !name.to_lowercase().contains(&needle)
                                    && !label(&name).to_lowercase().contains(&needle)
                                {
                                    continue;
                                }
                                if ui
                                    .selectable_value(&mut chosen, name.clone(), label(&name))
                                    .clicked()
                                {
                                    ui.close();
                                }
                            }
                        });
                });
            ui.weak(crate::time_format::zone_note());
        });
        if chosen != self.settings.time_zone {
            self.settings.time_zone = chosen;
            crate::tzone::choose(&self.settings.time_zone);
        }
        ui.end_row();
    }

    /// The rows of Settings > Appearance that Getting started shows too:
    /// Theme, Text size and Density, each applied at once. The caller owns the
    /// two-column grid.
    pub(super) fn appearance_rows(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
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
        ui.label("Density").on_hover_text(
            "Compact: tight rows and spacing. Comfortable: taller rows and roomier margins everywhere.",
        );
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
        });
        ui.end_row();
        ui.label("Toolbar");
        ui.checkbox(
            &mut self.settings.minimal_toolbar,
            "Minimal toolbar (icons only)",
        )
        .on_hover_text("Show only icons on the toolbar buttons; the names are in the hover text.");
        ui.end_row();
    }

    fn recording_page(&mut self, ui: &mut egui::Ui) {
        if self.snapshot.active_vm.is_some() {
            crate::activity::info(ui, "Stop the VM to change these.");
        }
        ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
            theme::section(ui, "Base and storage");
            form_grid("settings_recording", ui).show(ui, |ui| {
                ui.label("Default base for new VMs").on_hover_text(
                    "The installed base a new VM starts with. Each VM keeps the base it was created with; this only sets the choice offered in New VM and Getting started.",
                );
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
                )
                .on_hover_text("The most disk space the recordings may use.");
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
            ui.add_space(12.0);
            theme::section(ui, "Limits and timing");
            form_grid("settings_recording_limits", ui).show(ui, |ui| {
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
                )
                .on_hover_text("How long a VM is given to shut down before it is stopped.");
                ui.end_row();
            });
        });
    }

    fn detection_page(&mut self, ui: &mut egui::Ui) {
        form_grid("settings_detection", ui).show(ui, |ui| {
            ui.label("After a run");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.automatic_detection,
                    "Scan runs with IDS and Sigma when they end",
                )
                .on_hover_text(
                    "Scans a run with YARA, IDS and Sigma once its evidence is ready, and again when the installed rule packs change. A run whose VM stopped is scanned with what it recorded, and the result says so. Scan still works when this is off.",
                );
            });
            ui.end_row();
            ui.label("Downloads");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.outbound_catalog,
                    "Allow outbound catalog and rule downloads",
                )
                .on_hover_text(
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
        ui.add_space(12.0);
        theme::section(ui, "Time limits");
        hint_tip(
            ui,
            "How long each engine may run.",
            "How long each engine may run before it is stopped; a scan that runs out of time says so.",
        );
        self.detection_timeouts(ui);
    }

    fn notifications_page(&mut self, ui: &mut egui::Ui) {
        form_grid("settings_notifications", ui).show(ui, |ui| {
            ui.label("Live findings");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.toast_high_findings,
                    "Toast for live HIGH findings",
                )
                .on_hover_text(
                    "The first HIGH finding of each rule in a run that is still going raises one toast; later matches of the same rule add ×N to it. Applies at once.",
                );
            });
            ui.end_row();
            ui.label("Runs");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.toast_run_finished,
                    "Toast when a run finishes",
                )
                .on_hover_text(
                    "One toast per run when its program tree really ends: green for exit 0, neutral for another exit code, a stop or a time limit, a warning for a crash or a kill. It has Open Triage, and Open sample for a library sample. Applies at once.",
                );
            });
            ui.end_row();
            ui.label("Start");
            ui.vertical(|ui| {
                ui.checkbox(
                    &mut self.settings.warn_no_snapshot,
                    "Warn before starting a VM with no snapshot",
                )
                .on_hover_text(
                    "Start asks first when the VM has no snapshot, because then nothing can restore the disk and what the program changes stays in it. Turned off by Don't ask me again in that question; turn it back on here. Applies at once.",
                );
                ui.checkbox(
                    &mut self.settings.warn_clear_activity,
                    "Ask before clearing Activity",
                )
                .on_hover_text(
                    "Clear in Activity asks first, because the saved log cannot be brought back. Turned off by Don't ask me again in that question; turn it back on here. Applies at once.",
                );
            });
            ui.end_row();
        });
    }

    fn lookup_page(&mut self, ui: &mut egui::Ui) {
        use crate::triage::AddressLookup;
        form_grid("settings_lookup", ui).show(ui, |ui| {
            ui.label("Address lookup").on_hover_text(
                "Public destination addresses get a country and organization. Local addresses stay “-” and “local network” and are never queried.",
            );
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
            });
            ui.end_row();
        });
        ui.add_space(10.0);
        ui.separator();
        self.geoip_section(ui);
    }

    fn tools_page(&mut self, ui: &mut egui::Ui) {
        ui.add(egui::Label::new("Tools used by static analysis.").wrap())
            .on_hover_text(
                "Static analysis uses these tools when they are installed on this system. Downloads are checked by SHA-256 and used read-only by the analysis sandbox.",
            );
        ui.add_space(6.0);
        theme::section(ui, "Tools and their time limits");
        if self.snapshot.analysis_tools.is_empty() {
            theme::loading_weak(ui, "Reading the tool list…");
        }
        let tools: Vec<_> = self
            .snapshot
            .analysis_tools
            .iter()
            .filter(|tool| !antinomie_monitor_core::analysis_tools::is_route_tool(&tool.id))
            .cloned()
            .collect();
        for tool in &tools {
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&tool.name).strong().color(theme::text()));
                ui.label(RichText::new(&tool.purpose).small().color(theme::muted()));
            });
            let (text, tone) = match (&tool.system, &tool.installed) {
                (Some(_), _) => ("On this system".to_owned(), Tone::Good),
                (None, Some(version)) => (format!("Installed {version}"), Tone::Good),
                (None, None) => ("Not installed".to_owned(), Tone::Accent),
            };
            chip(ui, text, tone);
            if let Some(timed) = antinomie_monitor_core::TimedTool::ALL
                .into_iter()
                .find(|timed| timed.package() == Some(tool.id.as_str()))
            {
                self.timeout_row(ui, timed);
            }
        }
        self.built_in_timeouts(ui);
        ui.add_space(8.0);
        if ui.button("Manage tools…").clicked() {
            self.open_library(crate::workspace::LibraryPage::Tools);
        }
        ui.add_space(12.0);
        theme::section(ui, "Time and size limits");
        form_grid("settings_analysis_limits", ui).show(ui, |ui| {
            ui.label("Time limit for every tool")
                .on_hover_text(crate::analysis::TIME_LIMIT_HELP);
            ui.add(crate::analysis::time_limit_drag(
                &mut self.settings.analysis_time_limit_minutes,
            ))
            .on_hover_text(crate::analysis::TIME_LIMIT_HELP);
            ui.end_row();
            let label = ui.label("Rebuilt file bytes (Triage)");
            if std::mem::take(&mut self.settings_focus_rebuild) {
                label.scroll_to_me(Some(egui::Align::Center));
            }
            ui.vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.settings.rebuild_file_mib)
                            .range(1..=4096)
                            .suffix(" MiB / file"),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.settings.rebuild_run_mib)
                            .range(1..=65_536)
                            .suffix(" MiB / run"),
                    );
                });
                hint_tip(
                    ui,
                    &format!(
                        "Defaults {} MiB per file, {} MiB per run.",
                        crate::triage::DEFAULT_REBUILD_FILE_MIB,
                        crate::triage::DEFAULT_REBUILD_RUN_MIB
                    ),
                    &format!(
                        "Most bytes Triage > Files rebuilds of one changed file, and of all files of a run together, \
                         from the writes the recording captured (memory while the run is open). Past a cap the rest \
                         stays in the syscall evidence and the file says which cap was met. Defaults {} MiB per file, {} MiB per run.",
                        crate::triage::DEFAULT_REBUILD_FILE_MIB,
                        crate::triage::DEFAULT_REBUILD_RUN_MIB
                    ),
                );
            });
            ui.end_row();
        });

        ui.add_space(12.0);
        theme::section(ui, "Debugger");
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
                hint(ui, "Applies on next console start.").on_hover_text(
                    "The gdb in the Debugger tab. GEF (bata24) runs on this system's gdb; pwndbg \
                     brings its own. Install either from Manage tools.",
                );
            });
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.label(theme::section_title(ui, "Size limits"));
        hint_tip(
            ui,
            "What a check keeps and reads before a bound cuts it short.",
            "What a check keeps and reads before it says a bound cut its result short. A warning's Analysis settings button leads here. A change applies to analyses started afterwards; a check can be run again from its tab.",
        );
        self.analysis_limit_fields(ui);
        ui.add_space(6.0);
        hint_tip(
            ui,
            "Some bounds are fixed.",
            &antinomie_monitor_core::fixed_limits_text(),
        );
    }

    fn disks_page(&mut self, ui: &mut egui::Ui) {
        if self.snapshot.active_vm.is_some() {
            crate::activity::info(ui, "Stop the VM to change these.");
        }
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
    }

    fn advanced_page(&mut self, ui: &mut egui::Ui) {
        theme::section(ui, "Display");
        form_grid("settings_advanced", ui).show(ui, |ui| {
            ui.label("FPS counter");
            ui.vertical(|ui| {
                ui.checkbox(&mut self.settings.show_fps, "Show FPS counter")
                    .on_hover_text(
                        "Shows frames per second, frame time and UI build time in the window corner. \
                         It reads only frames that are painted anyway, so an idle window shows idle.",
                    );
            });
            ui.end_row();
        });
        ui.add_space(12.0);
        theme::section(ui, "Starting a VM");
        form_grid("settings_advanced_start", ui).show(ui, |ui| {
            ui.label("VM start and guest connection timeouts");
            ui.vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.settings.start.guest_connect_secs)
                            .range(antinomie_monitor_core::StartSettings::GUEST_CONNECT_SECS)
                            .suffix(" s guest connection"),
                    )
                    .on_hover_text("How long a start waits for the guest to connect at KVM speed.");
                    ui.add(
                        egui::DragValue::new(&mut self.settings.start.tcg_multiplier)
                            .range(antinomie_monitor_core::StartSettings::TCG_MULTIPLIER)
                            .prefix("TCG multiplier x"),
                    )
                    .on_hover_text(
                        "TCG is software emulation, 10 to 50 times slower than KVM. Every start wait is this many times longer when a VM runs with TCG.",
                    );
                });
                ui.add(
                    egui::DragValue::new(&mut self.settings.start.boot_wait_secs)
                        .range(antinomie_monitor_core::StartSettings::BOOT_WAIT_SECS)
                        .suffix(" s boot wait before a run"),
                )
                .on_hover_text(
                    "How long the first run of a boot waits for a systemd guest to finish booting, at KVM speed (stretched by the TCG multiplier like the other waits). A guest still booting then gets the program anyway, with a warning on the run. Guests without systemd (BusyBox) never wait.",
                );
                ui.add(
                    egui::DragValue::new(&mut self.settings.start.network_wait_secs)
                        .range(antinomie_monitor_core::StartSettings::NETWORK_WAIT_SECS)
                        .suffix(" s network wait before a run"),
                )
                .on_hover_text(
                    "How long a run on a Routed VM waits, at KVM speed (stretched by the TCG multiplier), for the guest to have its network address from the gateway's DHCP. A guest without one then gets the program anyway, with a note on the run that its first connections may fail with \"network is unreachable\". 0 starts the program without waiting.",
                );
                ui.checkbox(
                    &mut self.settings.start.kvm_fallback,
                    "Use TCG when KVM is unavailable",
                )
                .on_hover_text(
                    "A VM set to KVM runs with TCG when /dev/kvm cannot be used, instead of refusing to start. A VM set to Default always does.",
                );
                let tcg = antinomie_monitor_core::accel::Choice {
                    accelerator: antinomie_monitor_core::accel::Accelerator::Tcg,
                    fallback: None,
                };
                let waits = antinomie_monitor_core::accel::Waits::new(&tcg, &self.settings.start);
                hint_tip(
                    ui,
                    &format!(
                        "With TCG a start waits up to {} s for the guest.",
                        waits.guest_connect().as_secs()
                    ),
                    &format!(
                        "A VM that runs with TCG waits up to {} s for its guest to connect now (the multiplier, and a host load above one per CPU, stretch every wait of a start; a QMP reply may take {} s). Raise the multiplier when a slow TCG boot is reported as not connecting. Applies to the next start.",
                        waits.guest_connect().as_secs(),
                        waits.qmp_reply().as_secs()
                    ),
                );
            });
            ui.end_row();
        });
        ui.add_space(12.0);
        theme::section(ui, "Triage");
        form_grid("settings_advanced_triage", ui).show(ui, |ui| {
            ui.label("Triage: rows per table");
            ui.vertical(|ui| {
                ui.add(
                    egui::DragValue::new(&mut self.settings.triage_page_rows)
                        .range(crate::triage::PAGE_ROWS_RANGE)
                        .suffix(" rows"),
                );
                hint_tip(
                    ui,
                    &format!(
                        "Default {}.",
                        crate::values::thousands(crate::triage::STORED_ROWS as u64)
                    ),
                    &format!(
                        "Most rows one Triage table (Opened, Read, Changed, Findings, Network) keeps per page and \
                         one report table keeps. A table with more says \"first N of M\"; Next shows the rest. \
                         Default {}; a higher value uses more memory.",
                        crate::values::thousands(crate::triage::STORED_ROWS as u64)
                    ),
                );
            });
            ui.end_row();
        });
        ui.add_space(12.0);
        theme::section(ui, "File activity");
        form_grid("settings_advanced_files", ui).show(ui, |ui| {
            ui.label("File activity: written content kept");
            ui.vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.settings.file_write_file_mib)
                            .range(1..=65_536)
                            .suffix(" MiB / file"),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.settings.file_write_run_mib)
                            .range(1..=1_048_576)
                            .suffix(" MiB / run"),
                    );
                });
                hint_tip(
                    ui,
                    "Bytes the run wrote that File activity can give back.",
                    "Bytes the run wrote that File activity can give back exactly. When a cap is \
                     reached the first writes are kept; later ranges are listed as not captured. \
                     The recording itself is limited by the Recording quota.",
                );
            });
            ui.end_row();
            ui.label("File activity: earlier bytes kept");
            ui.vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.settings.file_before_file_mib)
                            .range(1..=65_536)
                            .suffix(" MiB / file"),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.settings.file_before_run_mib)
                            .range(1..=1_048_576)
                            .suffix(" MiB / run"),
                    );
                });
                hint_tip(
                    ui,
                    "Bytes the files had before the run changed them.",
                    "When a run ends, the earlier bytes (before the run changed them) of the \
                     files it changed are copied into its recording, so they stay readable \
                     after the base is gone. A file over a cap keeps its size and SHA-256 and is \
                     listed as not captured. This copy is not counted in the Recording quota.",
                );
            });
            ui.end_row();
        });
    }
}
