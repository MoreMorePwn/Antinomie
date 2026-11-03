// SPDX-License-Identifier: GPL-3.0-only
//! The decoded call tree of the inspector: its heading, arguments, return value and phases.
use super::*;
use antinomie_monitor_core::EventSummary;

/// The call's name, its identity, and a line for every phase that was not captured whole.
pub(super) fn tree_header(
    ui: &mut egui::Ui,
    event: &EventSummary,
    nr: u64,
    invocation: &InvocationSummary,
) {
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.label(
            RichText::new(&event.syscall_name)
                .font(theme::mono(
                    ui.style().text_styles[&egui::TextStyle::Body].size,
                ))
                .color(theme::value(ValueKind::Name)),
        );
        ui.label(
            RichText::new(format!(
                "syscall {nr} · TID {} · call {}",
                event.tid, invocation.call_id
            ))
            .color(theme::muted()),
        );
    });
    for (label, event) in [("Entry", &invocation.entry), ("Exit", &invocation.exit)] {
        let Some(event) = event else {
            continue;
        };
        if !event.complete {
            warning_line(ui, &format!("{label}: incomplete capture"));
        }
        for issue in &event.issues {
            warning_line(ui, &format!("{label}: {issue}"));
        }
    }
    ui.add_space(4.0);
}

impl Inspector {
    /// The argument rows, each with the data captured behind it.
    pub(super) fn argument_rows(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        (args, arg_phase): (Option<[u64; 6]>, u8),
        fields: &[(u8, &FieldSummary)],
        (nr, salt): (u64, InvocationKey),
        root: &Prefix,
    ) {
        match args {
            Some(args) => {
                for index in 0..arg_count(nr) {
                    let branch = root.child(index + 1 == arg_count(nr));
                    let value = args[index];
                    let name = argument_name(nr, index);
                    let shown = values::argument(nr, index, &args);
                    let owned: Vec<_> = fields
                        .iter()
                        .copied()
                        .filter(|(_, field)| field_argument(nr, field) == Some(index))
                        .collect();
                    let note = info_argument(field_call(nr, Some(args)).as_ref(), &owned)
                        .map(|(_, text)| (text, theme::value(ValueKind::Text)))
                        .or_else(|| shown.raw.clone().map(|raw| (raw, theme::muted())))
                        .or_else(|| {
                            nothing_returned(invocation, nr, index).then(|| {
                                (
                                    "nothing to capture: the call returned 0 bytes".to_owned(),
                                    theme::muted(),
                                )
                            })
                        });
                    let selected = self.selection
                        == Some(Selection::Argument {
                            phase: arg_phase,
                            index,
                            value,
                        });
                    let mark = argument_recapture(&owned);
                    let (response, open) = tree_row(
                        ui,
                        Row {
                            id: ui.id().with((salt, "argument", index)),
                            branch: &branch,
                            expand: (!owned.is_empty()).then_some(true),
                            name,
                            name_color: theme::text(),
                            value: Some((&shown.text, theme::value(shown.kind))),
                            note: note.as_ref().map(|(text, color)| (text.as_str(), *color)),
                            tag: mark.map(Recapture::label),
                            selected,
                        },
                    );
                    let c_type = syscalls::syscall(nr)
                        .and_then(|info| info.arguments.get(index))
                        .map_or("", |argument| argument.c_type.as_str());
                    let mut hover = format!("{c_type} {name}\n{}\nraw {value:#x}", shown.hover());
                    if let Some(mark) = mark {
                        hover = format!("{hover}\n\n{}", recapture_explanation(mark));
                    }
                    let response = response.on_hover_text(hover);
                    data_view::number_menu(
                        &response,
                        value,
                        8,
                        &shown.text,
                        &[("Name and value", &format!("{name}={}", shown.text))],
                    );
                    if response.clicked() {
                        self.select_argument(arg_phase, index, value);
                    }
                    if open {
                        self.phase_fields(ui, invocation, nr, &owned, &branch, true);
                    }
                }
            }
            None => {
                note_row(
                    ui,
                    &root.child(true),
                    "Arguments unavailable",
                    theme::muted(),
                );
            }
        }
    }

    /// The return row: the value, the end of a task that never returned, or what is missing.
    pub(super) fn return_row(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        event: &EventSummary,
        (nr, salt): (u64, InvocationKey),
        root: &Prefix,
    ) {
        match invocation.exit.as_ref().and_then(|exit| exit.result) {
            Some(result) => {
                let shown = values::result(nr, result);
                let description = values::is_error(result)
                    .then(|| values::errno_description(result.unsigned_abs()))
                    .flatten()
                    .map(|text| format!("{result} · {text}"));
                let (response, _) = tree_row(
                    ui,
                    Row {
                        id: ui.id().with((salt, "return")),
                        branch: root,
                        expand: None,
                        name: "Return",
                        name_color: theme::heading(),
                        value: Some((&shown.text, theme::value(shown.kind))),
                        note: description.as_deref().map(|text| (text, theme::muted())),
                        tag: None,
                        selected: self.selection == Some(Selection::Return(result)),
                    },
                );
                let response = response.on_hover_text(values::result_hover(nr, result));
                let mut extra = Vec::new();
                if shown.raw.is_some() {
                    extra.push(("Name", shown.text.as_str()));
                }
                data_view::number_menu(&response, result as u64, 8, &result.to_string(), &extra);
                if response.clicked() {
                    self.clear();
                    self.selection = Some(Selection::Return(result));
                }
            }
            None if invocation.exit.is_none() && invocation.task_exit.is_some() => {
                let (ended, color) = match invocation.task_exit_status() {
                    Some(status @ WaitStatus::Exited { code: 0 }) => {
                        (values::task_end(&status), theme::good())
                    }
                    Some(status @ WaitStatus::Exited { .. }) => {
                        (values::task_end(&status), theme::value(ValueKind::Number))
                    }
                    Some(status) => (values::task_end(&status), theme::error()),
                    None => ("ended".to_owned(), theme::neutral_accent()),
                };
                let note = if matches!(event.syscall_name.as_str(), "exit" | "exit_group") {
                    "never returns: the task ended here"
                } else {
                    "never returned: the task ended while in this call"
                };
                tree_row(
                    ui,
                    Row {
                        id: ui.id().with((salt, "return")),
                        branch: root,
                        expand: None,
                        name: "Task ended",
                        name_color: theme::heading(),
                        value: Some((&ended, color)),
                        note: Some((note, theme::muted())),
                        tag: None,
                        selected: false,
                    },
                );
            }
            None => {
                let missing = if invocation.exit.is_some() {
                    "no value"
                } else {
                    "missing Exit"
                };
                tree_row(
                    ui,
                    Row {
                        id: ui.id().with((salt, "return")),
                        branch: root,
                        expand: None,
                        name: "Return",
                        name_color: theme::heading(),
                        value: Some((missing, theme::warn())),
                        note: None,
                        tag: None,
                        selected: false,
                    },
                );
            }
        }
    }

    /// The Entry and Exit rows with their records, and the task exit.
    pub(super) fn phase_rows(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        salt: InvocationKey,
        root: &Prefix,
    ) {
        let nr = representative(invocation).map_or(0, |event| event.syscall_nr);
        for (label, event) in [("Entry", &invocation.entry), ("Exit", &invocation.exit)] {
            // The task exit record, when there is one, comes last.
            let branch = root.child(label == "Exit" && invocation.task_exit.is_none());
            let Some(event) = event else {
                // A call the task ended in has no Exit to lose.
                let ended = label == "Exit" && invocation.task_exit.is_some();
                tree_row(
                    ui,
                    Row {
                        id: ui.id().with((salt, label)),
                        branch: &branch,
                        expand: None,
                        name: label,
                        name_color: theme::text(),
                        value: Some(if ended {
                            ("none", theme::muted())
                        } else {
                            ("missing", theme::warn())
                        }),
                        note: ended.then_some(("the call never returned", theme::muted())),
                        tag: None,
                        selected: false,
                    },
                );
                continue;
            };
            let record = format!("record {}", event.event_seq);
            let captured = match event.fields.len() {
                0 => String::new(),
                1 => " · 1 captured object".to_owned(),
                n => format!(" · {n} captured objects"),
            };
            let note = format!(
                "{} s · CPU {}{captured}{}",
                seconds(event.timestamp_ns),
                event.cpu,
                if event.complete { "" } else { " · incomplete" }
            );
            let (response, open) = tree_row(
                ui,
                Row {
                    id: ui.id().with((salt, label)),
                    branch: &branch,
                    // What the call read or wrote is listed under the
                    // phase that captured it, as well as by argument.
                    expand: (!event.fields.is_empty()).then_some(false),
                    name: label,
                    name_color: theme::text(),
                    value: Some((&record, theme::value(ValueKind::Number))),
                    note: Some((&note, theme::muted())),
                    tag: None,
                    selected: false,
                },
            );
            response.context_menu(|ui| {
                data_view::copy_items(
                    ui,
                    &[
                        ("Record".into(), event.event_seq.to_string()),
                        ("Time (ns)".into(), event.timestamp_ns.to_string()),
                        ("CPU".into(), event.cpu.to_string()),
                    ],
                );
            });
            if open {
                let phase = if label == "Entry" { 1 } else { 2 };
                let fields: Vec<_> = event.fields.iter().collect();
                field_tree(ui, (invocation, nr, phase), &fields, false, self, &branch);
            }
        }
        if let Some(event) = &invocation.task_exit {
            let record = format!("record {}", event.event_seq);
            let note = format!(
                "{} s · CPU {} · {}",
                seconds(event.timestamp_ns),
                event.cpu,
                invocation.task_exit_status().map_or_else(
                    || "status unreadable".to_owned(),
                    |status| { values::task_end(&status) }
                )
            );
            tree_row(
                ui,
                Row {
                    id: ui.id().with((salt, "task exit")),
                    branch: &root.child(true),
                    expand: None,
                    name: "Task exit",
                    name_color: theme::text(),
                    value: Some((&record, theme::value(ValueKind::Number))),
                    note: Some((&note, theme::muted())),
                    tag: None,
                    selected: false,
                },
            );
        }
    }
}
