// SPDX-License-Identifier: GPL-3.0-only
//! Captured-field presentation for the trace inspector: the field tree and
//! value lines. The model (capture sizes, flags, the trace line parts of a
//! call) is in `antinomie_triage::trace`.
use super::*;
use antinomie_monitor_core::typed_fields::{self, Call};

pub(crate) use antinomie_triage::trace::*;

/// The colour of a piece of a trace line in the active theme.
pub(crate) fn tone_color(tone: Tone) -> Color32 {
    match tone {
        Tone::Label => theme::muted(),
        Tone::Value(kind) => theme::value(kind),
        Tone::Note => theme::warn(),
    }
}

#[derive(Default)]
pub(super) struct FieldNode<'a> {
    pub(super) field: Option<&'a FieldSummary>,
    /// In capture order, so `[2]` comes before `[10]`.
    pub(super) children: Vec<(String, FieldNode<'a>)>,
}

impl<'a> FieldNode<'a> {
    pub(super) fn child(&mut self, label: String) -> &mut FieldNode<'a> {
        let index = match self.children.iter().position(|(name, _)| *name == label) {
            Some(index) => index,
            None => {
                self.children.push((label, FieldNode::default()));
                self.children.len() - 1
            }
        };
        &mut self.children[index].1
    }
}

impl FieldNode<'_> {
    /// Whether this field or one below it is a record array.
    fn holds_array(&self, call: Option<&Call<'_>>) -> bool {
        self.field
            .is_some_and(|field| typed_fields::brief(call, field).is_some())
            || self
                .children
                .iter()
                .any(|(_, child)| child.holds_array(call))
    }
}

/// The invocation, syscall number and phase that captured fields belong to.
pub(super) type FieldOwner<'a> = (&'a InvocationSummary, u64, u8);

/// Captured fields as a tree of their key components (`iov[0].data`).
pub(super) fn field_tree(
    ui: &mut egui::Ui,
    owner: FieldOwner<'_>,
    fields: &[&FieldSummary],
    strip_arg: bool,
    inspector: &mut Inspector,
    parent: &Prefix,
) {
    let mut root = FieldNode::default();
    for field in fields {
        let mut components = field.key.split('.');
        if strip_arg && field.key.starts_with("arg") {
            components.next();
        }
        // Outside the argument rows an argument's data goes by its name.
        let argument = (!strip_arg)
            .then(|| field_argument(owner.1, field))
            .flatten()
            .filter(|_| field.key.starts_with("arg"));
        let mut node = &mut root;
        for (position, component) in components.enumerate() {
            for (index, part) in component.split('[').enumerate() {
                if part.is_empty() {
                    continue;
                }
                let label = match argument {
                    Some(argument) if position == 0 && index == 0 => {
                        argument_name(owner.1, argument).to_owned()
                    }
                    _ if index == 0 => part.to_owned(),
                    _ => format!("[{part}"),
                };
                node = node.child(label);
            }
        }
        node.field = Some(field);
    }
    fn show(
        ui: &mut egui::Ui,
        owner: FieldOwner<'_>,
        node: &FieldNode<'_>,
        inspector: &mut Inspector,
        parent: &Prefix,
    ) {
        let (invocation, nr, phase) = owner;
        let call = field_call(nr, call_args(invocation));
        for (position, (label, child)) in node.children.iter().enumerate() {
            let branch = parent.child(position + 1 == node.children.len());
            let size = child.field.map(capture_size);
            let shown = child.field.map(|field| info_preview(call.as_ref(), field));
            // A record array opens on its records, a row each.
            let has_records = child
                .field
                .is_some_and(|field| typed_fields::brief(call.as_ref(), field).is_some());
            let (response, open) = tree_row(
                ui,
                Row {
                    id: ui
                        .id()
                        .with((key(invocation), phase, parent.levels(), label)),
                    branch: &branch,
                    expand: if has_records {
                        Some(true)
                    } else {
                        // Nested records are open to see; other nested fields stay closed.
                        (!child.children.is_empty()).then(|| child.holds_array(call.as_ref()))
                    },
                    name: label,
                    name_color: theme::text(),
                    value: child
                        .field
                        .zip(size.as_deref())
                        .map(|(field, size)| (size, capture_color(field))),
                    note: shown
                        .as_deref()
                        .map(|text| (text, theme::value(ValueKind::Text))),
                    tag: child
                        .field
                        .and_then(|field| field.recapture)
                        .map(Recapture::label),
                    selected: child.field.is_some_and(|field| {
                        inspector.selection
                            == Some(Selection::Captured {
                                phase,
                                object_id: field.object_id,
                            })
                    }),
                },
            );
            if let Some(field) = child.field {
                let mut hover = format!("{}\n{}", field.key, capture_summary(field));
                if let Some(mark) = field.recapture {
                    hover = format!("{hover}\n\n{}", recapture_explanation(mark));
                }
                let response = response.on_hover_text(hover);
                if field_menu(&response, field) {
                    inspector.request_data(invocation, nr, format!("p{phase}"), field);
                }
                if response.clicked() {
                    inspector.select_field(phase, field);
                }
            }
            if open {
                show(ui, owner, child, inspector, &branch);
                if has_records && let Some(field) = child.field {
                    let salt = (key(invocation), phase, parent.levels(), label);
                    record_tree::tree_rows(ui, salt, call.as_ref(), field, &branch);
                }
            }
        }
    }
    show(ui, owner, &root, inspector, parent);
}

pub(super) fn warning_line(ui: &mut egui::Ui, text: &str) {
    crate::activity::warning(ui, format!("{} {text}", egui_phosphor::regular::WARNING));
}

/// A value large, in its syntax color, with its number when it is a name.
pub(super) fn value_line(ui: &mut egui::Ui, shown: &values::Shown) {
    let size = egui::TextStyle::Body.resolve(ui.style()).size;
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(&shown.text)
                .font(theme::mono(size + 1.0))
                .color(theme::value(shown.kind)),
        );
        if let Some(raw) = &shown.raw {
            ui.label(
                RichText::new(format!("= {raw}"))
                    .font(theme::mono(size - 1.0))
                    .color(theme::muted()),
            );
        }
    });
}

pub(super) fn capture_color(field: &FieldSummary) -> Color32 {
    if field.complete {
        theme::value(ValueKind::Number)
    } else {
        theme::warn()
    }
}

/// The right-click menu of a captured field; true when the user asked to
/// open its data window.
pub(super) fn field_menu(response: &egui::Response, field: &FieldSummary) -> bool {
    let mut open = false;
    response.context_menu(|ui| {
        if ui
            .button(format!(
                "{} Open data…",
                egui_phosphor::regular::ARROW_SQUARE_OUT
            ))
            .clicked()
        {
            open = true;
            ui.close();
        }
        ui.separator();
        let mut items = vec![
            ("Key".to_owned(), field.key.clone()),
            ("Captured length".to_owned(), field.captured_len.to_string()),
        ];
        if let Some(logical) = field.logical_len {
            items.push(("Logical length".to_owned(), logical.to_string()));
        }
        let preview = covered_preview(field);
        if !preview.is_empty() {
            items.push((
                "Preview as hex".to_owned(),
                data_view::format_bytes(data_view::DataFormat::Hex, preview, 0),
            ));
        }
        data_view::copy_items(ui, &items);
    });
    open
}

/// `text` about `field`, in the warning color when its capture is incomplete.
pub(super) fn capture_text(field: &FieldSummary, text: String) -> RichText {
    if field.complete {
        RichText::new(text)
    } else {
        RichText::new(text).color(theme::warn())
    }
}

pub(super) fn show_flags(
    ui: &mut egui::Ui,
    number: u64,
    index: usize,
    value: u64,
    args: Option<[u64; 6]>,
) {
    if let Some(name) = args.and_then(|args| syscalls::selector_name(number, index, &args)) {
        let shown = format!("{name} (raw {value:#x})");
        let response = ui.add(egui::Label::new(&shown).sense(egui::Sense::click()));
        data_view::number_menu(&response, value, 8, &shown, &[("Name", &name)]);
    }
    if let Some(flags) = syscalls::argument_flags(number, index, value) {
        let names = flags.names.join(" | ");
        let shown = format!("{names} (raw {value:#x})");
        let response = ui.add(egui::Label::new(&shown).sense(egui::Sense::click()));
        data_view::number_menu(&response, value, 8, &shown, &[("Flag names", &names)]);
        if flags.unknown_bits != 0 {
            let response = ui.add(
                egui::Label::new(
                    RichText::new(format!("Unknown bits: {:#x}", flags.unknown_bits))
                        .color(theme::warn()),
                )
                .sense(egui::Sense::click()),
            );
            data_view::number_menu(
                &response,
                flags.unknown_bits,
                8,
                &format!("{:#x}", flags.unknown_bits),
                &[],
            );
        }
    }
}

pub(super) fn numeric(ui: &mut egui::Ui, value: u64, width: usize) {
    let size = egui::TextStyle::Body.resolve(ui.style()).size;
    ui.spacing_mut().interact_size.y = theme::row_height(size) - 4.0;
    egui::Grid::new("numeric_inspector")
        .num_columns(2)
        .spacing([16.0, 2.0])
        .show(ui, |ui| {
            let formats = numeric_formats(value, width);
            for (label, text) in &formats {
                ui.colored_label(theme::muted(), *label);
                let color = match *label {
                    "Char / ASCII" => theme::value(ValueKind::Text),
                    "Byte order" => theme::muted(),
                    _ if text.starts_with("needs") => theme::muted(),
                    _ => theme::value(ValueKind::Number),
                };
                let response = ui.add(
                    egui::Label::new(RichText::new(text).monospace().color(color))
                        .sense(egui::Sense::click()),
                );
                response.context_menu(|ui| {
                    let mut items = vec![((*label).to_owned(), text.clone())];
                    items.push((
                        "All forms".to_owned(),
                        formats
                            .iter()
                            .map(|(label, text)| format!("{label}: {text}"))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ));
                    items.extend(data_view::number_items(value, width, ""));
                    data_view::copy_items(ui, &items);
                });
                ui.end_row();
            }
        });
}
