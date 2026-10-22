// SPDX-License-Identifier: GPL-3.0-only
//! Run program > Program > Source: a file already in the guest, or a host
//! file that is uploaded first.
use crate::theme;
use eframe::egui;

/// Where the Run program dialog gets the program from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum LaunchSource {
    /// A file already in the guest: its path is the executable.
    #[default]
    Guest,
    /// A host file: uploaded as executable to a guest path, then run.
    Upload,
}

/// What the Upload source edits, borrowed from the app.
pub(crate) struct UploadFields<'a> {
    pub host_file: &'a mut String,
    pub destination: &'a mut String,
    pub overwrite: &'a mut bool,
    /// The file chooser can be opened.
    pub can_choose: bool,
    /// Why it cannot (Zenity missing), or that it is being checked.
    pub chooser_note: Option<&'static str>,
    /// An upload is under way: the fields wait for it.
    pub busy: bool,
}

/// The Source choice and, for Upload, its fields.
pub(crate) struct ProgramSource<'a> {
    pub choice: &'a mut LaunchSource,
    pub upload: UploadFields<'a>,
}

/// What the user asked for in the source rows.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SourceOutcome {
    pub choose_file: bool,
    /// The host path was typed, so a remembered chosen file no longer applies.
    pub host_file_edited: bool,
}

/// The placeholder of the empty Arguments field: the rule, then an example
/// argument on each line below it.
pub(crate) const ARGUMENT_PLACEHOLDER: &str =
    "One argument per line\n--config\n/tmp/sample.conf\n-v";

fn text<'a>(value: &'a mut String, hint: &str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(value)
        .margin(theme::TEXT_EDIT_MARGIN)
        .font(egui::TextStyle::Monospace)
        .hint_text(theme::hint_text(hint))
}

/// A hint line in the field column, under the field it explains.
pub(crate) fn hint_row(ui: &mut egui::Ui, hint: &str) {
    ui.label("");
    // Wraps at a column's width, so a long line never widens the window.
    ui.scope(|ui| {
        ui.set_max_width(ui.available_width().min(360.0));
        ui.add(egui::Label::new(egui::RichText::new(hint).small().color(theme::muted())).wrap());
    });
    ui.end_row();
}

/// The Source row and the rows after it up to the executable: one grid row
/// each, in the Program grid.
pub(crate) fn rows(
    ui: &mut egui::Ui,
    executable: &mut String,
    source: ProgramSource<'_>,
) -> SourceOutcome {
    let mut outcome = SourceOutcome::default();
    let ProgramSource { choice, upload } = source;
    ui.label("Source");
    crate::widgets::segmented(
        ui,
        [
            (
                LaunchSource::Guest,
                crate::widgets::TabItem::new("Guest path"),
            ),
            (LaunchSource::Upload, crate::widgets::TabItem::new("Upload")),
        ],
        choice,
    );
    ui.end_row();
    match *choice {
        LaunchSource::Guest => {
            let label = ui.label("Executable");
            ui.add(text(executable, "/path/in/guest").desired_width(f32::INFINITY))
                .labelled_by(label.id);
            ui.end_row();
        }
        LaunchSource::Upload => {
            let label = ui.label("Host file");
            if ui
                .add_enabled(
                    !upload.busy,
                    text(upload.host_file, "Choose a file or enter its path")
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id)
                .changed()
            {
                outcome.host_file_edited = true;
            }
            ui.end_row();
            // Under the field, so the field keeps the whole column.
            ui.label("");
            if ui
                .add_enabled(
                    upload.can_choose && !upload.busy,
                    egui::Button::new("Choose…"),
                )
                .on_hover_text("Choose a file with the filesystem explorer")
                .clicked()
            {
                outcome.choose_file = true;
            }
            ui.end_row();
            if let Some(note) = upload.chooser_note {
                hint_row(ui, note);
            }
            let label = ui.label("Guest path");
            ui.add_enabled(
                !upload.busy,
                text(upload.destination, "/tmp/sample").desired_width(f32::INFINITY),
            )
            .labelled_by(label.id);
            ui.end_row();
            ui.label("");
            ui.add_enabled(
                !upload.busy,
                egui::Checkbox::new(upload.overwrite, "Overwrite an existing file"),
            );
            ui.end_row();
            hint_row(
                ui,
                "Uploaded as executable. The program is then set to this guest path, ready to Run.",
            );
        }
    }
    outcome
}
