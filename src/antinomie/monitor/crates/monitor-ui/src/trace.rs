//! Paired invocation presentation and inspectors for actually captured content.
use crate::tree_lines::Prefix;
use crate::{
    data_view::{self, OpenData},
    theme::{self, ValueKind},
    values,
};
use antinomie_monitor_core::{syscalls, FieldSummary, InvocationSummary, WaitStatus};
use eframe::egui::{self, Color32, RichText};

pub(crate) mod async_browse;
mod fields;
mod tree_row;
pub(crate) use fields::*;
use tree_row::{note_row, section_row, tree_row, Row};

pub(crate) type InvocationKey = (u64, u64, u64);

pub(crate) fn representative(
    invocation: &InvocationSummary,
) -> Option<&antinomie_monitor_core::EventSummary> {
    invocation
        .entry
        .as_ref()
        .or(invocation.exit.as_ref())
        .or(invocation.async_events.first())
}

pub(crate) fn key(invocation: &InvocationSummary) -> InvocationKey {
    (
        invocation.stream_id,
        invocation.task_cookie,
        invocation.call_id,
    )
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Selection {
    Argument { phase: u8, index: usize, value: u64 },
    Return(i64),
    Captured { phase: u8, object_id: u32 },
    AsyncCaptured { event_seq: u64, object_id: u32 },
}

#[derive(Default)]
pub(crate) struct Inspector {
    pub(crate) selection: Option<Selection>,
    pub(crate) data: Vec<u8>,
    pub(crate) data_offset: u64,
    pub(crate) generation: u64,
    pub(crate) pending: bool,
    pub(crate) error: Option<String>,
    byte_index: usize,
    numeric_width: usize,
    /// Fields the user asked to see in a data window; the app opens them.
    pub(crate) open_data: Vec<OpenData>,
    /// The saved async observations past a call's preview, a page at a time.
    pub(crate) observations: async_browse::State,
}

impl Inspector {
    pub(crate) fn clear(&mut self) {
        self.selection = None;
        self.data.clear();
        self.generation = self.generation.wrapping_add(1);
        self.pending = false;
        self.error = None;
    }

    fn select_argument(&mut self, phase: u8, index: usize, value: u64) {
        let selection = Selection::Argument {
            phase,
            index,
            value,
        };
        if self.selection.as_ref() != Some(&selection) {
            self.clear();
            self.selection = Some(selection);
        }
    }

    fn select_field(&mut self, phase: u8, field: &FieldSummary) {
        let selection = Selection::Captured {
            phase,
            object_id: field.object_id,
        };
        if self.selection.as_ref() != Some(&selection) {
            self.clear();
            self.selection = Some(selection);
            self.data = covered_preview(field).to_vec();
            self.data_offset = 0;
            self.byte_index = 0;
            self.numeric_width = 1;
        }
    }

    /// Ask for `field` of `invocation` to open in its own data window.
    fn request_data(
        &mut self,
        invocation: &InvocationSummary,
        nr: u64,
        scope: String,
        field: &FieldSummary,
    ) {
        self.open_data.push(OpenData {
            key: format!("{:?}/{scope}/{}", key(invocation), field.object_id),
            title: format!(
                "{} / {} call {}",
                field.key,
                syscall_name(nr),
                invocation.call_id
            ),
            field: field.clone(),
        });
    }

    /// Open the selected captured field in a data window.
    fn open_selected_data(&mut self, invocation: &InvocationSummary, field: &FieldSummary) {
        let (nr, scope) = match &self.selection {
            Some(Selection::Captured { phase, .. }) => (
                if *phase == 2 {
                    invocation.exit.as_ref()
                } else {
                    invocation.entry.as_ref()
                }
                .or(representative(invocation))
                .map_or(0, |event| event.syscall_nr),
                format!("p{phase}"),
            ),
            Some(Selection::AsyncCaptured { event_seq, .. }) => (
                self.find_async(invocation, *event_seq)
                    .map_or(0, |event| event.syscall_nr),
                format!("async{event_seq}"),
            ),
            _ => return,
        };
        self.request_data(invocation, nr, scope, field);
    }

    pub(crate) fn field<'a>(&self, invocation: &'a InvocationSummary) -> Option<&'a FieldSummary> {
        if let Some(Selection::AsyncCaptured {
            event_seq,
            object_id,
        }) = &self.selection
        {
            return invocation
                .async_events
                .iter()
                .find(|event| event.event_seq == *event_seq)?
                .fields
                .iter()
                .find(|field| field.object_id == *object_id);
        }
        let Selection::Captured { phase, object_id } = self.selection.as_ref()? else {
            return None;
        };
        let event = if *phase == 2 {
            invocation.exit.as_ref()?
        } else {
            invocation.entry.as_ref()?
        };
        event
            .fields
            .iter()
            .find(|field| field.object_id == *object_id)
    }

    /// The Details panel of a syscall: the decoded tree on the left, the
    /// selected value or captured bytes on the right (Wireshark-style).
    /// Returns a capture read the user asked for.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        invocation: Option<&InvocationSummary>,
        can_read: bool,
    ) -> Option<(FieldSummary, u64, usize)> {
        let Some(invocation) = invocation else {
            ui.add_space(6.0);
            ui.colored_label(
                theme::muted(),
                "Select a syscall in the trace to decode it here",
            );
            return None;
        };
        if self.selection.is_none() {
            self.select_first(invocation);
        }
        self.observations.allow_reads(can_read);
        let width = ui.available_width();
        egui::SidePanel::left("argument_tree")
            .default_width((width * 0.5).clamp(220.0, 640.0))
            .min_width(160.0)
            .max_width((width - 200.0).max(160.0))
            .resizable(true)
            .frame(egui::Frame::NONE.inner_margin(egui::Margin {
                left: 2,
                right: 6,
                top: 4,
                bottom: 4,
            }))
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("argument_tree_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.tree(ui, invocation));
            });
        let mut read = None;
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.inner_margin(egui::Margin {
                left: 10,
                right: 4,
                top: 4,
                bottom: 4,
            }))
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("value_inspector")
                    .auto_shrink([false, false])
                    .show(ui, |ui| read = self.value_pane(ui, invocation, can_read));
            });
        read
    }

    /// Select what the right side starts with: the first captured data in
    /// argument order (data an exit returned before data an entry passed),
    /// then other captured objects, else the return value.
    fn select_first(&mut self, invocation: &InvocationSummary) {
        let Some(event) = representative(invocation) else {
            return;
        };
        let nr = event.syscall_nr;
        let mut best: Option<(usize, u8, &FieldSummary)> = None;
        for (phase, event) in [
            (2, invocation.exit.as_ref()),
            (1, invocation.entry.as_ref()),
        ] {
            for field in event.into_iter().flat_map(|event| &event.fields) {
                if covered_preview(field).is_empty() {
                    continue;
                }
                let rank = field_argument(nr, field).unwrap_or(6);
                if best.is_none_or(|(best, ..)| rank < best) {
                    best = Some((rank, phase, field));
                }
            }
        }
        if let Some((_, phase, field)) = best {
            self.select_field(phase, field);
            return;
        }
        for event in &invocation.async_events {
            if let Some(field) = event.fields.iter().find(|field| {
                !field.key.starts_with("async.") && !covered_preview(field).is_empty()
            }) {
                self.select_async(event.event_seq, field);
                return;
            }
        }
        if let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) {
            self.selection = Some(Selection::Return(result));
        }
    }

    fn select_async(&mut self, event_seq: u64, field: &FieldSummary) {
        let selection = Selection::AsyncCaptured {
            event_seq,
            object_id: field.object_id,
        };
        if self.selection.as_ref() != Some(&selection) {
            self.clear();
            self.selection = Some(selection);
            self.data = covered_preview(field).to_vec();
            self.data_offset = 0;
            self.byte_index = 0;
            self.numeric_width = 1;
        }
    }

    /// The decoded call: arguments (with the data captured behind them),
    /// return value, other captured objects, phases and async observations.
    fn tree(&mut self, ui: &mut egui::Ui, invocation: &InvocationSummary) {
        let Some(event) = representative(invocation) else {
            ui.colored_label(theme::warn(), "Missing phases");
            return;
        };
        let nr = event.syscall_nr;
        let salt = key(invocation);
        let root = Prefix::default();
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

        let (args, arg_phase) = match (
            invocation.entry.as_ref().and_then(|entry| entry.args),
            invocation.exit.as_ref().and_then(|exit| exit.args),
        ) {
            (Some(args), _) => (Some(args), 1),
            (None, args) => (args, 2),
        };
        let fields: Vec<(u8, &FieldSummary)> = invocation
            .entry
            .iter()
            .flat_map(|event| event.fields.iter().map(|field| (1, field)))
            .chain(
                invocation
                    .exit
                    .iter()
                    .flat_map(|event| event.fields.iter().map(|field| (2, field))),
            )
            .collect();

        if section_row(ui, ui.id().with((salt, "arguments")), "Arguments", true) {
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
                        let note = argument_preview(&owned)
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
                                selected,
                            },
                        );
                        let c_type = syscalls::syscall(nr)
                            .and_then(|info| info.arguments.get(index))
                            .map_or("", |argument| argument.c_type.as_str());
                        let response = response.on_hover_text(format!(
                            "{c_type} {name}\n{}\nraw {value:#x}",
                            shown.hover()
                        ));
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
                        branch: &root,
                        expand: None,
                        name: "Return",
                        name_color: theme::heading(),
                        value: Some((&shown.text, theme::value(shown.kind))),
                        note: description.as_deref().map(|text| (text, theme::muted())),
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
                    None => ("ended".to_owned(), theme::warn()),
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
                        branch: &root,
                        expand: None,
                        name: "Task ended",
                        name_color: theme::heading(),
                        value: Some((&ended, color)),
                        note: Some((note, theme::muted())),
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
                        branch: &root,
                        expand: None,
                        name: "Return",
                        name_color: theme::heading(),
                        value: Some((missing, theme::warn())),
                        note: None,
                        selected: false,
                    },
                );
            }
        }

        let objects: Vec<_> = fields
            .iter()
            .copied()
            .filter(|(_, field)| args.is_none() || field_argument(nr, field).is_none())
            .collect();
        if !objects.is_empty()
            && section_row(
                ui,
                ui.id().with((salt, "objects")),
                &format!("Captured objects ({})", objects.len()),
                true,
            )
        {
            self.phase_fields(ui, invocation, nr, &objects, &root, false);
        }

        if section_row(ui, ui.id().with((salt, "phases")), "Phases", false) {
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
                        selected: false,
                    },
                );
            }
        }

        self.async_section(ui, invocation, &root);
    }

    /// Captured fields of one argument or of the call, under "At entry" and
    /// "At exit" rows when both phases captured some.
    fn phase_fields(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        nr: u64,
        fields: &[(u8, &FieldSummary)],
        parent: &Prefix,
        strip_arg: bool,
    ) {
        let both = fields.iter().any(|(phase, _)| *phase == 1)
            && fields.iter().any(|(phase, _)| *phase == 2);
        for (phase, label) in [(1, "At entry"), (2, "At exit")] {
            let phase_fields: Vec<_> = fields
                .iter()
                .filter(|(owner, _)| *owner == phase)
                .map(|(_, field)| *field)
                .collect();
            if phase_fields.is_empty() {
                continue;
            }
            if both {
                let branch = parent.child(phase == 2);
                let (_, open) = tree_row(
                    ui,
                    Row {
                        id: ui.id().with((
                            key(invocation),
                            parent.levels(),
                            label,
                            fields[0].1.object_id,
                        )),
                        branch: &branch,
                        expand: Some(true),
                        name: label,
                        name_color: theme::muted(),
                        value: None,
                        note: None,
                        selected: false,
                    },
                );
                if open {
                    field_tree(
                        ui,
                        (invocation, nr, phase),
                        &phase_fields,
                        strip_arg,
                        self,
                        &branch,
                    );
                }
            } else {
                field_tree(
                    ui,
                    (invocation, nr, phase),
                    &phase_fields,
                    strip_arg,
                    self,
                    parent,
                );
            }
        }
    }

    fn async_event(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        event: &antinomie_monitor_core::EventSummary,
        branch: Prefix,
    ) {
        let stage = async_stage(event);
        let record = format!("record {}", event.event_seq);
        let note = format!("TID {} · CPU {}", event.tid, event.cpu);
        let (response, open) = tree_row(
            ui,
            Row {
                id: ui.id().with(("async", event.event_seq)),
                branch: &branch,
                expand: Some(false),
                name: &stage,
                name_color: theme::text(),
                value: Some((&record, theme::value(ValueKind::Number))),
                note: Some((&note, theme::muted())),
                selected: false,
            },
        );
        response.context_menu(|ui| {
            data_view::copy_items(
                ui,
                &[
                    ("Stage".into(), stage.clone()),
                    ("Event sequence".into(), event.event_seq.to_string()),
                    ("TID".into(), event.tid.to_string()),
                    ("CPU".into(), event.cpu.to_string()),
                ],
            );
        });
        if !open {
            return;
        }
        let result = async_scalar(event, "async.result")
            .map(|value| value as i64)
            .or(event.result);
        // The rows below the event, to tell the last from the others.
        let count = event.issues.len() + usize::from(result.is_some()) + event.fields.len();
        let mut position = 0;
        let mut next = || {
            position += 1;
            branch.child(position == count)
        };
        for issue in &event.issues {
            note_row(ui, &next(), issue, theme::warn());
        }
        if let Some(result) = result {
            let label = match async_scalar(event, "async.stage") {
                Some(6) => "Observation error",
                Some(4 | 5) => "Operation result",
                Some(3) => "Submission rejection",
                _ => "Reported value",
            };
            let shown = values::result(event.syscall_nr, result);
            let (response, _) = tree_row(
                ui,
                Row {
                    id: ui.id().with(("async result", event.event_seq)),
                    branch: &next(),
                    expand: None,
                    name: label,
                    name_color: theme::text(),
                    value: Some((&shown.text, theme::value(shown.kind))),
                    note: None,
                    selected: false,
                },
            );
            let response = response.on_hover_text(values::result_hover(event.syscall_nr, result));
            data_view::number_menu(&response, result as u64, 8, &result.to_string(), &[]);
        }
        for field in &event.fields {
            let size = capture_size(field);
            let shown = preview(field);
            let (response, _) = tree_row(
                ui,
                Row {
                    id: ui
                        .id()
                        .with(("async field", event.event_seq, field.object_id)),
                    branch: &next(),
                    expand: None,
                    name: &field.key,
                    name_color: theme::text(),
                    value: Some((&size, capture_color(field))),
                    note: Some((&shown, theme::value(ValueKind::Text))),
                    selected: self.selection
                        == Some(Selection::AsyncCaptured {
                            event_seq: event.event_seq,
                            object_id: field.object_id,
                        }),
                },
            );
            let response = response.on_hover_text(capture_summary(field));
            if field_menu(&response, field) {
                self.request_data(
                    invocation,
                    event.syscall_nr,
                    format!("async{}", event.event_seq),
                    field,
                );
            }
            if response.clicked() {
                self.select_async(event.event_seq, field);
            }
        }
    }

    /// The right side: the selected number in every form, or the selected
    /// field's captured bytes as a hex dump.
    fn value_pane(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        can_read: bool,
    ) -> Option<(FieldSummary, u64, usize)> {
        let nr = representative(invocation).map_or(0, |event| event.syscall_nr);
        match self.selection.clone() {
            Some(Selection::Argument { index, value, .. }) => {
                let args = invocation
                    .entry
                    .as_ref()
                    .and_then(|entry| entry.args)
                    .or_else(|| invocation.exit.as_ref().and_then(|exit| exit.args));
                let name = argument_name(nr, index);
                ui.horizontal_wrapped(|ui| {
                    theme::section(ui, name);
                    if let Some(argument) =
                        syscalls::syscall(nr).and_then(|info| info.arguments.get(index))
                    {
                        ui.colored_label(theme::muted(), &argument.c_type);
                    }
                });
                if let Some(args) = args {
                    value_line(ui, &values::argument(nr, index, &args));
                }
                show_flags(ui, nr, index, value, args);
                ui.add_space(6.0);
                numeric(ui, value, 8);
                None
            }
            Some(Selection::Return(value)) => {
                theme::section(ui, "Return value");
                value_line(ui, &values::result(nr, value));
                if values::is_error(value) {
                    if let Some(description) = values::errno_description(value.unsigned_abs()) {
                        ui.colored_label(theme::muted(), description);
                    }
                }
                ui.add_space(6.0);
                numeric(ui, value as u64, 8);
                None
            }
            Some(Selection::Captured { .. } | Selection::AsyncCaptured { .. }) => {
                let browsed = self.browsed_field(invocation);
                let Some(field) = self.field(invocation).or(browsed.as_ref()) else {
                    ui.colored_label(theme::muted(), "Captured field unavailable");
                    return None;
                };
                self.bytes_pane(ui, invocation, field, can_read)
            }
            None => {
                ui.colored_label(
                    theme::muted(),
                    "Nothing captured for this call; select an argument or the return value",
                );
                None
            }
        }
    }

    fn bytes_pane(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        field: &FieldSummary,
        can_read: bool,
    ) -> Option<(FieldSummary, u64, usize)> {
        let mut read = None;
        let mut open_data = false;
        ui.horizontal_wrapped(|ui| {
            theme::section(ui, &field.key);
            let phase = match &self.selection {
                Some(Selection::Captured { phase: 1, .. }) => "at entry",
                Some(Selection::Captured { .. }) => "at exit",
                _ => "async",
            };
            ui.colored_label(theme::muted(), phase);
            open_data = ui
                .button(format!(
                    "{} Open data…",
                    egui_phosphor::regular::ARROW_SQUARE_OUT
                ))
                .on_hover_text("Show all captured bytes as text, hexdump, C array, Base64 and more")
                .clicked();
        });
        let length = ui.add(
            egui::Label::new(capture_text(field, capture_summary(field)))
                .sense(egui::Sense::click()),
        );
        data_view::number_menu(
            &length,
            field.captured_len,
            8,
            &field.captured_len.to_string(),
            &[],
        );
        let mut facts = vec![match field.logical_len {
            Some(logical) => format!("logical length {logical} bytes"),
            None => "logical length unknown".to_owned(),
        }];
        if !field.layout.is_empty() {
            facts.push(field.layout.clone());
        }
        if field.status.is_some_and(|status| status != 0) || field.capture_error != 0 {
            facts.push(format!(
                "status {}; error {}",
                field.status.map_or_else(|| "none".into(), status_name),
                if field.capture_error < 0 {
                    values::errno_name(u64::from(field.capture_error.unsigned_abs()))
                        .map_or_else(|| field.capture_error.to_string(), str::to_owned)
                } else {
                    field.capture_error.to_string()
                }
            ));
        }
        ui.add(egui::Label::new(RichText::new(facts.join(" · ")).color(theme::muted())).wrap());
        if open_data {
            self.open_selected_data(invocation, field);
        }
        if let Some(error) = &self.error {
            crate::activity::warning(ui, error);
        }
        if self.pending {
            theme::loading_colored(ui, theme::muted(), "Reading capture…");
        }
        ui.add_space(4.0);
        if self.data.is_empty() {
            ui.colored_label(theme::muted(), "No captured bytes in this view");
        } else {
            self.hex_dump(ui);
        }
        if let Some((offset, len)) = next_range(
            field,
            self.data_offset.saturating_add(self.data.len() as u64),
        ) {
            if ui
                .add_enabled(
                    can_read && !self.pending,
                    egui::Button::new(format!(
                        "{} Read capture at {offset:#x}",
                        egui_phosphor::regular::ARROW_RIGHT
                    )),
                )
                .clicked()
            {
                read = Some((field.clone(), offset, len.min(4096) as usize));
            }
        }
        if !self.data.is_empty() {
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "Value at {:#x} as",
                        self.data_offset + self.byte_index as u64
                    ),
                );
                for width in [1, 2, 4, 8] {
                    ui.selectable_value(&mut self.numeric_width, width, format!("{width} B"));
                }
            });
            let width = self.numeric_width.max(1);
            if let Some(slice) = self
                .data
                .get(self.byte_index..self.byte_index.saturating_add(width))
            {
                let mut data = [0; 8];
                data[..width].copy_from_slice(slice);
                numeric(ui, u64::from_le_bytes(data), width);
            } else {
                ui.colored_label(
                    theme::muted(),
                    "Selection needs more contiguous captured bytes",
                );
            }
        }
        egui::CollapsingHeader::new(format!("Captured ranges ({})", field.ranges.len()))
            .id_salt("captured_ranges")
            .show(ui, |ui| {
                for &(offset, len) in &field.ranges {
                    let end = offset.saturating_add(len);
                    let response = ui.add(
                        egui::Label::new(
                            RichText::new(format!("{offset:#x}..{end:#x}  ({len} bytes)"))
                                .monospace(),
                        )
                        .sense(egui::Sense::click()),
                    );
                    response.context_menu(|ui| {
                        data_view::copy_items(
                            ui,
                            &[
                                ("Range".into(), format!("{offset:#x}..{end:#x}")),
                                ("Start".into(), format!("{offset:#x}")),
                                ("End".into(), format!("{end:#x}")),
                                ("Length".into(), len.to_string()),
                            ],
                        );
                    });
                }
            });
        read
    }

    /// The loaded bytes: offset, hex (two groups of eight) and ASCII; a
    /// click picks the byte the numeric view starts at, and the bytes it
    /// covers are highlighted in both columns.
    fn hex_dump(&mut self, ui: &mut egui::Ui) {
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&font, '0'));
        let height = font.size + if theme::is_compact() { 5.0 } else { 9.0 };
        let per_line = if ui.available_width() >= char_width * 78.0 {
            16
        } else {
            8
        };
        let group = per_line / 2;
        let byte_x = |column: usize| {
            char_width * (10.0 + column as f32 * 3.0 + if column >= group { 1.0 } else { 0.0 })
        };
        let ascii_x = byte_x(per_line) + char_width;
        let width = ascii_x + per_line as f32 * char_width + 4.0;
        let selected_end = self.byte_index + self.numeric_width.max(1);
        let palette = theme::palette();
        ui.spacing_mut().item_spacing.y = 0.0;
        let mut clicked = None;
        for (line, chunk) in self.data.chunks(per_line).enumerate() {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
            if !ui.is_rect_visible(rect) {
                continue;
            }
            let painter = ui.painter();
            let y = rect.center().y;
            painter.text(
                egui::pos2(rect.left(), y),
                egui::Align2::LEFT_CENTER,
                format!("{:08x}", self.data_offset + (line * per_line) as u64),
                font.clone(),
                theme::muted(),
            );
            for (column, byte) in chunk.iter().enumerate() {
                let index = line * per_line + column;
                let hex = egui::Rect::from_min_size(
                    egui::pos2(rect.left() + byte_x(column) - char_width * 0.5, rect.top()),
                    egui::vec2(char_width * 3.0, height),
                );
                let ascii = egui::Rect::from_min_size(
                    egui::pos2(
                        rect.left() + ascii_x + column as f32 * char_width,
                        rect.top(),
                    ),
                    egui::vec2(char_width, height),
                );
                let response = ui
                    .interact(hex, ui.id().with(("hex", index)), egui::Sense::click())
                    .union(ui.interact(
                        ascii,
                        ui.id().with(("ascii", index)),
                        egui::Sense::click(),
                    ));
                let fill = if index == self.byte_index {
                    Some(palette.selection)
                } else if (self.byte_index..selected_end).contains(&index) {
                    Some(palette.selection.gamma_multiply(0.55))
                } else if response.hovered() {
                    Some(palette.hover)
                } else {
                    None
                };
                if let Some(fill) = fill {
                    painter.rect_filled(hex.shrink2(egui::vec2(1.0, 1.0)), 2.0, fill);
                    painter.rect_filled(ascii, 1.0, fill);
                }
                painter.text(
                    egui::pos2(hex.center().x, y),
                    egui::Align2::CENTER_CENTER,
                    format!("{byte:02x}"),
                    font.clone(),
                    if *byte == 0 {
                        theme::muted()
                    } else {
                        theme::text()
                    },
                );
                let printable = byte.is_ascii_graphic() || *byte == b' ';
                painter.text(
                    egui::pos2(ascii.center().x, y),
                    egui::Align2::CENTER_CENTER,
                    if printable { char::from(*byte) } else { '.' },
                    font.clone(),
                    if printable {
                        theme::value(ValueKind::Text)
                    } else {
                        theme::muted()
                    },
                );
                let offset = self.data_offset + index as u64;
                data_view::number_menu(
                    &response,
                    u64::from(*byte),
                    1,
                    &format!("{byte:02x}"),
                    &[("Offset", &format!("{offset:#x}"))],
                );
                if response.clicked() {
                    clicked = Some(index);
                }
            }
        }
        if let Some(index) = clicked {
            self.byte_index = index;
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn field() -> FieldSummary {
        FieldSummary {
            arg: None,
            object_id: 1,
            key: "buf".into(),
            layout: String::new(),
            logical_len: Some(10),
            captured_len: 3,
            status: None,
            capture_error: 0,
            complete: false,
            preview: b"abc".to_vec(),
            raw_path: None,
            ranges: vec![(0, 3), (8, 2)],
        }
    }

    #[test]
    fn captured_holes_never_become_preview_or_numeric_bytes() {
        let mut field = field();
        assert_eq!(covered_preview(&field), b"abc");
        assert_eq!(next_range(&field, 3), Some((8, 2)));
        field.ranges = vec![(8, 3)];
        assert!(covered_preview(&field).is_empty());
        assert_eq!(preview(&field), "uncaptured");
    }

    #[test]
    fn actual_capture_keys_associate_with_semantic_arguments() {
        assert_eq!(key_argument(0, "buf"), Some(1));
        assert_eq!(key_argument(257, "path"), Some(1));
        assert_eq!(key_argument(19, "arg1.iov[2].data"), Some(1));
        assert_eq!(key_argument(43, "address.length"), Some(2));
        assert_eq!(key_argument(45, "address.data"), Some(4));
        assert_eq!(key_argument(59, "context.exec.argv[0]"), None);
    }

    #[test]
    fn numeric_values_reinterpret_bits_without_numeric_conversion() {
        let formats = numeric_formats(u64::MAX, 8);
        assert_eq!(formats[1].1, "-1");
        assert_eq!(numeric_formats(0xff, 1)[1].1, "-1");
        assert_eq!(numeric_formats(u64::from(1f32.to_bits()), 4)[4].1, "1");
        assert_eq!(numeric_formats(1f64.to_bits(), 8)[5].1, "1");
        assert_eq!(numeric_formats(0x4241, 2)[6].1, "A B");
    }

    pub(super) fn openat(result: i64) -> InvocationSummary {
        let event = |phase: u8| antinomie_monitor_core::EventSummary {
            root_task_cookie: 7,
            stream_id: 1,
            task_cookie: 3,
            call_id: 9,
            event_seq: u64::from(phase) + 10,
            phase,
            syscall_nr: 257,
            syscall_name: "openat".into(),
            pid: 42,
            tid: 43,
            cpu: 0,
            timestamp_ns: 1_500_000_000,
            args: (phase == 1).then_some([(-100i64) as u64, 0x7ffe_0000, 0o2000000, 0, 0, 0]),
            result: (phase == 2).then_some(result),
            complete: true,
            issues: Vec::new(),
            fields: Vec::new(),
        };
        let mut entry = event(1);
        entry.fields.push(FieldSummary {
            arg: None,
            object_id: 4,
            key: "arg1.path".into(),
            layout: String::new(),
            logical_len: Some(12),
            captured_len: 12,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: b"/etc/passwd\0".to_vec(),
            raw_path: None,
            ranges: vec![(0, 12)],
        });
        InvocationSummary {
            stream_id: 1,
            task_cookie: 3,
            call_id: 9,
            entry: Some(entry),
            exit: Some(event(2)),
            async_events: Vec::new(),
            async_saved: 0,
            task_exit: None,
            kernel_notes: Vec::new(),
        }
    }

    #[test]
    fn info_reads_arguments_by_meaning_with_captured_strings() {
        let row = openat(-2);
        assert_eq!(
            info(&row),
            "dfd=AT_FDCWD filename=\"/etc/passwd\" flags=O_RDONLY|O_CLOEXEC mode=0"
        );
        let parts = info_parts(&row);
        assert!(parts.contains(&("AT_FDCWD".into(), Tone::Value(ValueKind::Name))));
        assert!(parts.contains(&("\"/etc/passwd\"".into(), Tone::Value(ValueKind::Text))));
        let cells = cells(&row);
        assert_eq!(cells[0].0[0].0, "1.500000");
        assert_eq!(cells[1].0[0].0, "11\u{2192}12");
        assert_eq!(cells[2].1, "TID 43, PID 42");
        assert_eq!(
            cells[5].0,
            vec![("ENOENT".to_owned(), Tone::Value(ValueKind::Error))]
        );
        assert!(cells[5].1.contains("ENOENT = -2"));
        let cells = super::cells(&openat(3));
        assert_eq!(cells[5].0[0].0, "3");
    }

    fn string_field(key: &str, object_id: u32, text: &[u8]) -> FieldSummary {
        FieldSummary {
            arg: Some(1),
            object_id,
            key: key.into(),
            layout: String::new(),
            logical_len: Some(text.len() as u64),
            captured_len: text.len() as u64,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: text.to_vec(),
            raw_path: None,
            ranges: vec![(0, text.len() as u64)],
        }
    }

    #[test]
    fn exec_vectors_and_nested_objects_read_as_data_not_addresses() {
        let fields = [
            string_field("arg1.ptr[0]", 1, &[0x10, 0, 0, 0, 0, 0, 0, 0]),
            string_field("arg1.string[0]", 2, b"sh\0"),
            string_field("arg1.ptr[1]", 3, &[0x20, 0, 0, 0, 0, 0, 0, 0]),
            string_field("arg1.string[1]", 4, b"-c\0"),
        ];
        let owned: Vec<_> = fields.iter().map(|field| (1, field)).collect();
        assert_eq!(
            argument_preview(&owned),
            Some((None, "[\"sh\", \"-c\"]".to_owned()))
        );
        let nested = [
            string_field("arg1.mmsg.0.header", 1, &[1; 8]),
            string_field("arg1.mmsg.1.header", 2, &[2; 8]),
        ];
        let owned: Vec<_> = nested.iter().map(|field| (1, field)).collect();
        assert_eq!(
            argument_preview(&owned),
            Some((None, "2 captured objects".to_owned()))
        );
        // A lone object of the argument is its data whatever its key.
        let lone = [string_field("arg2.socklen.capacity", 1, &[16, 0, 0, 0])];
        let owned: Vec<_> = lone.iter().map(|field| (1, field)).collect();
        assert_eq!(argument_preview(&owned).map(|(id, _)| id), Some(Some(1)));
    }

    #[test]
    fn selecting_a_call_starts_with_its_captured_data() {
        let row = openat(3);
        let mut inspector = Inspector::default();
        inspector.select_first(&row);
        assert_eq!(
            inspector.selection,
            Some(Selection::Captured {
                phase: 1,
                object_id: 4
            })
        );
        assert_eq!(inspector.data, b"/etc/passwd\0");
        // Nothing captured: the return value is what there is to inspect.
        let mut bare = openat(3);
        bare.entry.as_mut().unwrap().fields.clear();
        let mut inspector = Inspector::default();
        inspector.select_first(&bare);
        assert_eq!(inspector.selection, Some(Selection::Return(3)));
    }

    #[test]
    fn previews_show_text_without_terminators_and_zeros_as_bytes() {
        let mut field = field();
        field.preview = b"/etc\0".to_vec();
        field.ranges = vec![(0, 5)];
        field.captured_len = 5;
        field.logical_len = Some(5);
        assert_eq!(preview(&field), "\"/etc\"");
        field.preview = vec![0; 4];
        field.ranges = vec![(0, 4)];
        field.captured_len = 4;
        field.logical_len = Some(4);
        assert_eq!(preview(&field), "00 00 00 00");
        field.key = "address.data".into();
        field.preview = vec![2, 0, 0, 53, 10, 0, 2, 3];
        field.ranges = vec![(0, 8)];
        assert_eq!(preview(&field), "10.0.2.3:53");
    }

    #[test]
    fn preview_is_bounded_and_marks_truncation() {
        let mut field = field();
        field.preview = vec![b'A'; 256];
        field.ranges = vec![(0, 256)];
        field.captured_len = 256;
        assert!(preview(&field).ends_with("..."));
        assert!(preview(&field).len() <= 53);
    }
}
