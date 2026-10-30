// SPDX-License-Identifier: GPL-3.0-only
//! Modal dialogs and dialog layout helpers.
use super::*;

impl MonitorApp {
    pub(super) fn dialogs(&mut self, ctx: &egui::Context) {
        crate::evidence::dialogs(ctx);
        self.evidence_jobs.show(ctx);
        if self.vm_snapshots.open {
            let tree = self
                .vm_snapshots
                .vm_id
                .as_ref()
                .and_then(|id| self.snapshot.vm_snapshot_trees.get(id));
            let progress = self
                .snapshot
                .vm_snapshot_progress
                .as_ref()
                .filter(|progress| self.vm_snapshots.vm_id.as_deref() == Some(&progress.vm_id));
            if let Some(command) = self.vm_snapshots.show(ctx, tree, progress, !self.closing) {
                self.send(command);
            }
        }
        if self.import_open {
            let mut open = true;
            let mut import = false;
            let mut cancel = false;
            crate::widgets::window("Import base")
                .id(Dialog::Import.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(620.0)
                .max_width((ctx.screen_rect().width() - 50.0).max(300.0))
                .show(ctx, |ui| {
                    dialog_section(ui, "Base folder");
                    ui.label(
                        RichText::new(
                            "A built base: the folder holds bundle.json, the kernel and base.qcow2.",
                        )
                        .color(theme::muted()),
                    );
                    ui.horizontal(|ui| {
                        // A TextEdit clips its desired width to the space left
                        // in the row, so reserve the following button and its
                        // spacing before measuring the text itself.
                        let path_width = (ui.available_width()
                            - ui.spacing().interact_size.y
                            - ui.spacing().item_spacing.x
                            - theme::TEXT_EDIT_MARGIN.sum().x).clamp(24.0, 560.0);
                        ui.add(
                            text_field(&mut self.import_directory)
                                .desired_width(path_width)
                                .font(egui::TextStyle::Monospace)
                                .hint_text(theme::hint_text("Bundle directory")),
                        );
                        if icon(
                            ui,
                            egui_phosphor::regular::FOLDER_OPEN,
                            "Choose bundle directory",
                            self.folder_picker.available(),
                        ) {
                            if let Err(error) = self.folder_picker.choose(FolderTarget {
                                generation: 0,
                                kind: FolderKind::BaseImport,
                            }) {
                                self.report_error(error);
                            }
                        }
                    });
                    dialog_footer(ui, |ui| {
                        import = ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none()
                                    && !self.import_directory.trim().is_empty(),
                                primary_button("Import"),
                            )
                            .on_disabled_hover_text("Choose a folder; stop the running VM first")
                            .clicked();
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            self.import_open = open && !cancel;
            if import {
                self.send(Command::ImportBase {
                    directory: crate::folders::user_path(&self.import_directory),
                });
                self.import_open = false;
            }
        }
        if self.download_open {
            let mut open = true;
            if let Some(command) = self.download_window(ctx, &mut open) {
                self.send(command);
            }
            self.download_open = open;
        }
        if self.rules_summary.is_empty() {
            self.rules_summary = "Loading rules…".into();
        }
        if self.samples.open {
            let vm = self.selected_vm().cloned();
            let action = self.samples.show(
                ctx,
                &crate::samples_view::SamplesContext {
                    data_dir: &self.options.data_dir,
                    curl: &self.options.curl,
                    running: self.running(),
                    vm_name: vm.as_ref().map(|vm| vm.name.as_str()),
                    nat: vm.as_ref().is_some_and(|vm| vm.nat),
                    font_size: self.settings.font_size,
                },
            );
            if let Some(crate::samples_view::SamplesAction::Push {
                sha256,
                destination,
                ..
            }) = action
            {
                self.send(Command::UploadSample {
                    sha256,
                    destination,
                    executable: true,
                });
            }
            if self.samples.take_open_keys() {
                self.api_keys.open = true;
            }
        }
        self.api_keys
            .show(ctx, &self.options.data_dir, &self.options.curl);
        if self.api_keys.take_changed() {
            self.samples.key_changed();
        }
        self.getting_started_window(ctx);
        if self.about_open {
            let mut open = true;
            crate::widgets::window("About Antinomie")
                .id(Dialog::About.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    crate::branding::show_wordmark(ui, 300.0);
                    ui.label(
                        RichText::new(format!("Version {APP_VERSION}"))
                            .size(ui.text_style_height(&egui::TextStyle::Heading))
                            .color(theme::heading()),
                    );
                    ui.label("Run programs in a QEMU VM and record every system call they make.");
                    ui.label("Copyright (c) 2026 MikiMiku (MoreMorePwn)");
                    ui.label("Original application code: GPL-3.0-only. No warranty.");
                    ui.hyperlink_to(
                        "GNU GPL version 3",
                        "https://www.gnu.org/licenses/gpl-3.0.html",
                    );
                    dialog_section(ui, "Versions");
                    form_grid("about", ui).show(ui, |ui| {
                        ui.label(RichText::new("Guest kernel").color(theme::muted()));
                        ui.label("Linux 6.12.94 (Debian 6.12.94-1 source)");
                        ui.end_row();
                        ui.label(RichText::new("Bases").color(theme::muted()));
                        ui.label(format!(
                            "{} or newer",
                            RevisionStatus::describe(Some(APP_REVISION), None)
                        ));
                        ui.end_row();
                    });
                });
            self.about_open = open;
        }
        crate::query::guide(ctx);
        // A base's UEFI disk being laid out for its first UEFI VM (once).
        if let Some(progress) = self.snapshot.base_layout.clone() {
            crate::widgets::window("Preparing the UEFI disk")
                .id(egui::Id::new("base_uefi_layout"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!(
                            "Laying out the UEFI disk of base {}: {}",
                            progress.base, progress.stage
                        ));
                    });
                    ui.label(
                        RichText::new(
                            "Once per base: its UEFI VMs share this disk, laid out as the \
                             Debian installer lays out a UEFI PC. BIOS VMs keep the base's disk.",
                        )
                        .color(theme::muted()),
                    );
                });
        }
        if self.build_open {
            let mut open = true;
            let build = self.snapshot.build.clone();
            let mut action = None;
            crate::widgets::window("Build base")
                .id(Dialog::Build.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_size([900.0, 640.0])
                .min_size([720.0, 480.0])
                .show(ctx, |ui| {
                    action = self
                        .build_wizard
                        .show(ui, build.as_ref(), &self.options.data_dir);
                });
            self.build_open = open;
            match action {
                Some(build_wizard::Action::Build(request)) => {
                    self.send(Command::BuildBase { request: *request })
                }
                Some(build_wizard::Action::Cancel) => self.send(Command::CancelBuild),
                None => {}
            }
        }
        if let Some((vm_id, duplicate, name)) = &mut self.name_action {
            let mut open = true;
            let mut save = false;
            let mut cancel = false;
            crate::widgets::window(if *duplicate { "Duplicate VM" } else { "Rename VM" })
                .id(Dialog::Name.window_id())
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    form_grid("name_action_form", ui).show(ui, |ui| {
                        ui.label(if *duplicate { "New name" } else { "Name" });
                        let edit = ui.add(text_field(name).desired_width(300.0));
                        if edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                            save = true;
                        }
                        ui.end_row();
                    });
                    if *duplicate {
                        ui.label(
                            RichText::new(
                                "Copies the current disk with a new VM identity. Run history remains with the source VM.",
                            )
                            .color(theme::muted()),
                        );
                    }
                    let allowed = !name.trim().is_empty()
                        && (!*duplicate || self.snapshot.active_vm.as_ref() != Some(vm_id));
                    dialog_footer(ui, |ui| {
                        save = ui
                            .add_enabled(
                                allowed,
                                primary_button(if *duplicate { "Duplicate" } else { "Rename" }),
                            )
                            .clicked()
                            || (save && allowed);
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            if save {
                if let Some((vm_id, duplicate, name)) = self.name_action.take() {
                    self.send(if duplicate {
                        Command::Duplicate { vm_id, name }
                    } else {
                        Command::Rename { vm_id, name }
                    });
                }
            } else if !open || cancel {
                self.name_action = None;
            }
        }
        if self.create_open || self.config_open {
            self.vm_dialog(ctx);
        }
        if self.launch_open {
            let mut open = true;
            let viewport = crate::title_bar::content_rect(ctx);
            let width = 1000.0_f32.min((viewport.width() - 50.0).max(300.0));
            crate::widgets::window("Run program")
                .id(Dialog::Launch.window_id())
                .open(&mut open)
                .collapsible(false)
                .movable(true)
                .resizable(true)
                .default_width(width)
                .default_height((viewport.height() - 100.0).max(240.0))
                .default_pos(egui::pos2(
                    viewport.center().x - width * 0.5,
                    viewport.top() + 32.0,
                ))
                .max_width((viewport.width() - 50.0).max(300.0))
                .max_height((viewport.height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    self.launch_form(ui);
                });
            self.launch_open &= open;
            if !self.launch_open {
                self.cancel_upload_handoff();
            }
        }
        if self.upload_open {
            let mut open = true;
            crate::widgets::window("Upload file")
                .id(Dialog::Upload.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(660.0)
                .default_height(0.0)
                .max_width((ctx.screen_rect().width() - 50.0).max(300.0))
                .max_height((crate::title_bar::content_rect(ctx).height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    scroll_dialog(ui, ctx, |ui| {
                        self.upload_form(ui);
                    });
                });
            if !open {
                self.close_upload();
            }
        }
        if self.settings_open {
            self.settings_window(ctx);
        }
        if let Some(confirm) = &self.confirm {
            let evidence_text = match confirm {
                Confirm::DeleteEvidence(deletion) => deletion.text(),
                _ => String::new(),
            };
            let (title, text, button, destructive) = match confirm {
                Confirm::DeleteEvidence(deletion) => (
                    deletion.title(),
                    evidence_text.as_str(),
                    "Delete",
                    true,
                ),
                Confirm::KillRun(_) => (
                    "Kill program run",
                    "Terminate the selected run and its descendants? Recording remains active while termination is collected. The VM keeps running.",
                    "Kill run",
                    true,
                ),
                Confirm::Reset(_) => (
                    "Reset disk",
                    "Reset this VM's disk to the base image? All VM disk changes will be lost.",
                    "Reset disk",
                    true,
                ),
                Confirm::Delete(_) => (
                    "Delete VM",
                    "Delete this VM configuration, disk and all snapshots? All saved disk layers and memory states will be lost. Retained run recordings and terminal history are preserved.",
                    "Delete VM",
                    true,
                ),
                Confirm::DeleteBase(_) => (
                    "Delete base",
                    "Delete this base image? This cannot be undone. VMs that reference it must be deleted first.",
                    "Delete base",
                    true,
                ),
                Confirm::Upload(_) => (
                    "Overwrite file",
                    "Overwrite the chosen guest path with this host file?",
                    "Overwrite",
                    true,
                ),
                Confirm::Clipboard { .. } => (
                    "Type clipboard into VM",
                    "Type this long or multiline clipboard into the guest's focused input? US keyboard layout is required, with Caps Lock off. Newlines press Enter and may execute commands. Maximum 4 KiB; typing may take up to two minutes.",
                    "Type into VM",
                    false,
                ),
                Confirm::DebugKill => (
                    "Detach and kill",
                    "Detach the debugger and end the debugged process with SIGKILL? Its state is lost; the VM keeps running.",
                    "Detach and kill",
                    true,
                ),
            };
            let mut yes = false;
            let mut cancel = false;
            let mut open = true;
            // Like the other spawned windows: no dim behind it and free to move.
            crate::widgets::window(title)
                .id(Dialog::Confirm.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .pivot(egui::Align2::CENTER_CENTER)
                .default_pos(ctx.screen_rect().center())
                .show(ctx, |ui| {
                    ui.set_width(400.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(egui_phosphor::regular::WARNING)
                                .size(ui.text_style_height(&egui::TextStyle::Heading))
                                .color(if destructive {
                                    theme::error()
                                } else {
                                    theme::warn()
                                }),
                        );
                        ui.add(egui::Label::new(text).wrap());
                    });
                    if let Confirm::KillRun(target) = confirm {
                        ui.add(egui::Label::new(target.label(&self.snapshot)).wrap());
                    }
                    if let Confirm::Clipboard { text, .. } = confirm {
                        ui.label(format!("{} keys to type", text.key_count));
                    }
                    let enabled = !self.closing
                        && match confirm {
                            Confirm::KillRun(target) => {
                                target.current(&self.snapshot)
                                    && self.running()
                                    && self.pending_kill.is_none()
                                    && self.snapshot.memory_dump.is_none()
                                    && self.vm_snapshots.pending.is_none()
                            }
                            Confirm::Reset(_) | Confirm::Delete(_) | Confirm::DeleteBase(_) => {
                                self.snapshot.active_vm.is_none()
                            }
                            Confirm::DeleteEvidence(_) => self.selected.is_some(),
                            Confirm::Upload(intent) => {
                                intent.same_session(&self.snapshot)
                                    && self.snapshot.state == VmState::Running
                                    && self.pending_upload.is_none()
                            }
                            Confirm::Clipboard { intent, .. } => {
                                intent.current(&self.snapshot)
                                    && self.running()
                                    && self.snapshot.memory_dump.is_none()
                            }
                            Confirm::DebugKill => self
                                .snapshot
                                .debug
                                .as_ref()
                                .is_some_and(|session| session.ended.is_none()),
                        };
                    dialog_footer(ui, |ui| {
                        yes = ui
                            .add_enabled(
                                enabled,
                                if destructive {
                                    danger_button(button)
                                } else {
                                    primary_button(button)
                                },
                            )
                            .clicked();
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            // The close button cancels it; Escape is handled with the other
            // dialogs.
            cancel |= !open;
            if yes {
                if let Some(confirm) = self.confirm.take() {
                    match confirm {
                        Confirm::KillRun(target) => self.submit_kill(target),
                        Confirm::Reset(vm_id) => self.send(Command::Reset {
                            vm_id,
                            confirmed: true,
                        }),
                        Confirm::Delete(vm_id) => self.send(Command::Delete {
                            vm_id,
                            confirmed: true,
                        }),
                        Confirm::DeleteBase(identity) => self.send(Command::DeleteBase {
                            identity,
                            confirmed: true,
                        }),
                        Confirm::DeleteEvidence(deletion) => self.submit_delete_evidence(deletion),
                        Confirm::Upload(intent) => self.submit_upload(intent, true),
                        Confirm::Clipboard { intent, text } => self.submit_clipboard(intent, text),
                        Confirm::DebugKill => self.send(Command::DebugDetach { kill: true }),
                    }
                }
            }
            if cancel {
                self.confirm = None;
            }
        }
    }

    pub(super) fn dialog_open(&self, dialog: Dialog) -> bool {
        match dialog {
            Dialog::Confirm => self.confirm.is_some(),
            Dialog::Name => self.name_action.is_some(),
            Dialog::Transport => self.transport_open && (self.create_open || self.config_open),
            Dialog::Stealth => self.stealth_open && (self.create_open || self.config_open),
            Dialog::Vm => self.create_open || self.config_open,
            Dialog::Launch => self.launch_open,
            Dialog::Upload => self.upload_open,
            Dialog::Settings => self.settings_open,
            Dialog::Import => self.import_open,
            Dialog::Download => self.download_open,
            Dialog::Samples => self.samples.open,
            Dialog::ApiKeys => self.api_keys.open,
            Dialog::Snapshots => self.vm_snapshots.open,
            Dialog::SnapshotDecision => self.vm_snapshots.decision_open(),
            Dialog::Dependencies => self.dependencies.open,
            Dialog::GettingStarted => self.getting_started.open,
            Dialog::Performance => self.performance.open,
            Dialog::About => self.about_open,
            Dialog::Build => self.build_open,
            Dialog::Attach => self.process_picker.open,
        }
    }

    pub(super) fn close_dialog(&mut self, dialog: Dialog) {
        match dialog {
            Dialog::Confirm => self.confirm = None,
            Dialog::Name => self.name_action = None,
            Dialog::Transport => self.transport_open = false,
            Dialog::Stealth => self.stealth_open = false,
            Dialog::Vm => {
                self.create_open = false;
                self.config_open = false;
                self.transport_open = false;
                self.stealth_open = false;
                self.credentials.reset();
            }
            Dialog::Launch => {
                self.launch_open = false;
                self.cancel_upload_handoff();
            }
            Dialog::Upload => self.close_upload(),
            Dialog::Settings => self.settings_open = false,
            Dialog::Import => self.import_open = false,
            Dialog::Download => self.download_open = false,
            Dialog::Samples => self.samples.open = false,
            Dialog::ApiKeys => self.api_keys.open = false,
            Dialog::Snapshots | Dialog::SnapshotDecision => self.vm_snapshots.close(),
            Dialog::Dependencies => self.dependencies.open = false,
            Dialog::GettingStarted => self.getting_started.open = false,
            Dialog::Performance => self.performance.open = false,
            Dialog::About => self.about_open = false,
            Dialog::Build => self.build_open = false,
            Dialog::Attach => self.process_picker.open = false,
        }
    }

    /// The open dialog on top: the confirmation (modal), else the window
    /// raised last. A window not drawn yet was opened this frame, so it is
    /// on top.
    fn topmost_dialog(&self, ctx: &egui::Context) -> Option<Dialog> {
        if self.confirm.is_some() {
            return Some(Dialog::Confirm);
        }
        let order: Vec<egui::Id> =
            ctx.memory(|memory| memory.layer_ids().map(|layer| layer.id).collect());
        Dialog::ALL
            .into_iter()
            .filter(|dialog| self.dialog_open(*dialog))
            .max_by_key(|dialog| {
                order
                    .iter()
                    .position(|id| *id == dialog.window_id())
                    .unwrap_or(usize::MAX)
            })
    }

    /// Escape closes the topmost dialog. An open popup (a combo box list,
    /// a menu) takes the key first, and so does a widget that keeps the
    /// keyboard (a terminal).
    pub(super) fn escape(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.key_pressed(egui::Key::Escape))
            || ctx.memory(|memory| memory.any_popup_open() || memory.focused().is_some())
        {
            return;
        }
        if let Some(dialog) = self.topmost_dialog(ctx) {
            ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
            self.close_dialog(dialog);
        }
    }
}

pub(super) fn password_input(ui: &mut egui::Ui, text: &mut String, salt: &str) {
    let mut output = egui::TextEdit::singleline(text)
        .id(egui::Id::new(salt))
        .password(true)
        .margin(theme::TEXT_EDIT_MARGIN)
        .char_limit(128)
        .desired_width(280.0)
        .show(ui);
    // Do not let reopening the form restore a prior secret through undo.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
}

pub(super) fn directory_input(
    ui: &mut egui::Ui,
    path: &mut Option<PathBuf>,
    default_parent: &std::path::Path,
    picker: &mut FolderPicker,
    target: FolderTarget,
    status: &mut String,
) {
    let mut text = path
        .as_deref()
        .unwrap_or(default_parent)
        .to_string_lossy()
        .into_owned();
    ui.horizontal(|ui| {
        if ui
            .add(
                text_field(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(235.0),
            )
            .on_hover_text(text.clone())
            .changed()
        {
            *path = (!text.trim().is_empty()).then(|| crate::folders::user_path(&text));
        }
        if icon(
            ui,
            egui_phosphor::regular::FOLDER_OPEN,
            "Choose host folder",
            picker.available(),
        ) {
            if let Err(error) = picker.choose(target) {
                *status = format!("Host folder: {error}");
                crate::activity::error(ui, &*status);
            }
        }
    });
}

/// A titled group of fields in a dialog.
pub(super) fn dialog_section(ui: &mut egui::Ui, title: &str) {
    // theme::section leaves the room above a heading that follows something.
    theme::section(ui, title);
    ui.add_space(2.0);
}

/// Width of a dialog's label column: the longest label ("Recording
/// parent", "Confirm password") at the current text size.
pub(super) fn form_label_width(ctx: &egui::Context) -> f32 {
    ctx.style()
        .text_styles
        .get(&egui::TextStyle::Body)
        .map_or(16.0, |font| font.size)
        * 9.5
}

/// A label / field grid whose label column has the same width in every
/// section, so the fields line up.
pub(super) fn form_grid(id: &str, ui: &egui::Ui) -> egui::Grid {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([14.0, 8.0])
        .min_col_width(form_label_width(ui.ctx()))
}

/// A soft rule and the dialog's buttons, main action first.
pub(super) fn dialog_footer(ui: &mut egui::Ui, buttons: impl FnOnce(&mut egui::Ui)) {
    crate::widgets::footer(ui, buttons);
}

/// Settings > Text size: smaller and larger buttons around the size, and a
/// slider with a filled track.
pub(super) fn text_size_control(ui: &mut egui::Ui, size: &mut f32) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(*size > 12.0, egui::Button::new("A−"))
            .on_hover_text("Smaller text")
            .clicked()
        {
            *size = (*size - 1.0).max(12.0);
        }
        ui.scope(|ui| {
            let visuals = ui.visuals_mut();
            visuals.slider_trailing_fill = true;
            visuals.selection.bg_fill = theme::primary();
            visuals.widgets.inactive.bg_fill = theme::line();
            ui.spacing_mut().slider_width = 140.0;
            ui.add(
                egui::Slider::new(size, 12.0..=24.0)
                    .step_by(1.0)
                    .show_value(false),
            );
        });
        if ui
            .add_enabled(*size < 24.0, egui::Button::new("A+"))
            .on_hover_text("Larger text")
            .clicked()
        {
            *size = (*size + 1.0).min(24.0);
        }
        ui.label(RichText::new(format!("{size:.0} px")).monospace());
    });
}

fn scroll_dialog(ui: &mut egui::Ui, ctx: &egui::Context, content: impl FnOnce(&mut egui::Ui)) {
    let height = (crate::title_bar::content_rect(ctx).height() - 110.0).max(150.0);
    // Measure against the viewport even when restored window geometry is short.
    ui.set_max_height(height);
    egui::ScrollArea::vertical()
        .max_height(height)
        .auto_shrink([false, true])
        .show(ui, content);
}
