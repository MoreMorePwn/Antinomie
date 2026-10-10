//! Paired invocation presentation and inspectors for actually captured content.
use crate::{
    data_view::{self, OpenData},
    theme::{self, ValueKind},
    values,
};
use antinomie_monitor_core::{syscalls, FieldSummary, InvocationSummary};
use eframe::egui::{self, Color32, RichText};

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
                invocation
                    .async_events
                    .iter()
                    .find(|event| event.event_seq == *event_seq)
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
                let rank = field_argument(nr, &field.key).unwrap_or(6);
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
                        let value = args[index];
                        let name = argument_name(nr, index);
                        let shown = values::argument(nr, index, &args);
                        let owned: Vec<_> = fields
                            .iter()
                            .copied()
                            .filter(|(_, field)| field_argument(nr, &field.key) == Some(index))
                            .collect();
                        let note = argument_data(&owned)
                            .map(|(_, field)| (preview(field), theme::value(ValueKind::Text)))
                            .or_else(|| shown.raw.clone().map(|raw| (raw, theme::muted())));
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
                                depth: 1,
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
                            self.phase_fields(ui, invocation, nr, &owned, 2, true);
                        }
                    }
                }
                None => {
                    note_row(ui, 1, "Arguments unavailable", theme::muted());
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
                        depth: 0,
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
                        depth: 0,
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
            .filter(|(_, field)| args.is_none() || field_argument(nr, &field.key).is_none())
            .collect();
        if !objects.is_empty()
            && section_row(
                ui,
                ui.id().with((salt, "objects")),
                &format!("Captured objects ({})", objects.len()),
                true,
            )
        {
            self.phase_fields(ui, invocation, nr, &objects, 1, false);
        }

        if section_row(ui, ui.id().with((salt, "phases")), "Phases", false) {
            for (label, event) in [("Entry", &invocation.entry), ("Exit", &invocation.exit)] {
                let Some(event) = event else {
                    tree_row(
                        ui,
                        Row {
                            id: ui.id().with((salt, label)),
                            depth: 1,
                            expand: None,
                            name: label,
                            name_color: theme::text(),
                            value: Some(("missing", theme::warn())),
                            note: None,
                            selected: false,
                        },
                    );
                    continue;
                };
                let record = format!("record {}", event.event_seq);
                let note = format!(
                    "{} s · CPU {}{}",
                    seconds(event.timestamp_ns),
                    event.cpu,
                    if event.complete { "" } else { " · incomplete" }
                );
                let (response, _) = tree_row(
                    ui,
                    Row {
                        id: ui.id().with((salt, label)),
                        depth: 1,
                        expand: None,
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
            }
        }

        if section_row(
            ui,
            ui.id().with((salt, "async")),
            &format!("Async ({})", invocation.async_events.len()),
            false,
        ) {
            if invocation.async_events.is_empty() {
                note_row(ui, 1, "No correlated async observations", theme::muted());
            }
            for event in &invocation.async_events {
                self.async_event(ui, invocation, event);
            }
        }
    }

    /// Captured fields of one argument or of the call, under "At entry" and
    /// "At exit" rows when both phases captured some.
    fn phase_fields(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        nr: u64,
        fields: &[(u8, &FieldSummary)],
        depth: usize,
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
                let (_, open) = tree_row(
                    ui,
                    Row {
                        id: ui
                            .id()
                            .with((key(invocation), depth, label, fields[0].1.object_id)),
                        depth,
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
                        depth + 1,
                    );
                }
            } else {
                field_tree(
                    ui,
                    (invocation, nr, phase),
                    &phase_fields,
                    strip_arg,
                    self,
                    depth,
                );
            }
        }
    }

    fn async_event(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        event: &antinomie_monitor_core::EventSummary,
    ) {
        let stage = async_stage(event);
        let record = format!("record {}", event.event_seq);
        let note = format!("TID {} · CPU {}", event.tid, event.cpu);
        let (response, open) = tree_row(
            ui,
            Row {
                id: ui.id().with(("async", event.event_seq)),
                depth: 1,
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
        for issue in &event.issues {
            note_row(ui, 2, issue, theme::warn());
        }
        if let Some(result) = async_scalar(event, "async.result")
            .map(|value| value as i64)
            .or(event.result)
        {
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
                    depth: 2,
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
                    depth: 2,
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
                let Some(field) = self.field(invocation) else {
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
            ui.colored_label(theme::warn(), error);
        }
        if self.pending {
            ui.colored_label(theme::muted(), "Reading capture...");
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

#[derive(Default)]
struct FieldNode<'a> {
    field: Option<&'a FieldSummary>,
    /// In capture order, so `[2]` comes before `[10]`.
    children: Vec<(String, FieldNode<'a>)>,
}

impl<'a> FieldNode<'a> {
    fn child(&mut self, label: String) -> &mut FieldNode<'a> {
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

/// The invocation, syscall number and phase that captured fields belong to.
type FieldOwner<'a> = (&'a InvocationSummary, u64, u8);

/// Captured fields as a tree of their key components (`iov[0].data`).
fn field_tree(
    ui: &mut egui::Ui,
    owner: FieldOwner<'_>,
    fields: &[&FieldSummary],
    strip_arg: bool,
    inspector: &mut Inspector,
    depth: usize,
) {
    let mut root = FieldNode::default();
    for field in fields {
        let mut components = field.key.split('.');
        if strip_arg && field.key.starts_with("arg") {
            components.next();
        }
        let mut node = &mut root;
        for component in components {
            for (index, part) in component.split('[').enumerate() {
                if part.is_empty() {
                    continue;
                }
                let label = if index == 0 {
                    part.to_owned()
                } else {
                    format!("[{part}")
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
        depth: usize,
    ) {
        let (invocation, nr, phase) = owner;
        for (label, child) in &node.children {
            let size = child.field.map(capture_size);
            let shown = child.field.map(preview);
            let (response, open) = tree_row(
                ui,
                Row {
                    id: ui.id().with((key(invocation), phase, depth, label)),
                    depth,
                    expand: (!child.children.is_empty()).then_some(false),
                    name: label,
                    name_color: theme::text(),
                    value: child
                        .field
                        .zip(size.as_deref())
                        .map(|(field, size)| (size, capture_color(field))),
                    note: shown
                        .as_deref()
                        .map(|text| (text, theme::value(ValueKind::Text))),
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
                let response =
                    response.on_hover_text(format!("{}\n{}", field.key, capture_summary(field)));
                if field_menu(&response, field) {
                    inspector.request_data(invocation, nr, format!("p{phase}"), field);
                }
                if response.clicked() {
                    inspector.select_field(phase, field);
                }
            }
            if open {
                show(ui, owner, child, inspector, depth + 1);
            }
        }
    }
    show(ui, owner, &root, inspector, depth);
}

/// One line of the decoded tree.
struct Row<'a> {
    id: egui::Id,
    depth: usize,
    /// Rows with children draw a caret: `Some(open by default)`.
    expand: Option<bool>,
    name: &'a str,
    name_color: Color32,
    /// Monospace, in its syntax color.
    value: Option<(&'a str, Color32)>,
    /// After the value: a decoded form, a preview or a remark.
    note: Option<(&'a str, Color32)>,
    selected: bool,
}

/// Draw a tree row: caret, name, then value and note aligned on a column
/// shared by the row's siblings. A click selects; the caret or a double
/// click opens and closes. Returns the response and whether the row is open.
fn tree_row(ui: &mut egui::Ui, row: Row<'_>) -> (egui::Response, bool) {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = theme::mono(body.size - 1.0);
    let height = theme::row_height(body.size);
    let step = body.size * 1.1;
    let caret = body.size;
    let name_x = 2.0 + row.depth as f32 * step + caret;
    let painter = ui.painter();
    let name = painter.layout_no_wrap(row.name.to_owned(), body.clone(), row.name_color);
    let value = row
        .value
        .map(|(text, color)| painter.layout_no_wrap(text.to_owned(), mono.clone(), color));
    let note = row
        .note
        .map(|(text, color)| painter.layout_no_wrap(text.to_owned(), body.clone(), color));
    let gap = body.size * 0.8;
    let value_x = (name_x + name.size().x + gap).max(name_x + body.size * 6.5);
    let note_x = value_x + value.as_ref().map_or(0.0, |value| value.size().x + gap);
    let end = note_x + note.as_ref().map_or(0.0, |note| note.size().x) + 4.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(end), height),
        egui::Sense::click(),
    );
    let mut open = false;
    if let Some(default) = row.expand {
        open = ui.data_mut(|data| *data.get_temp_mut_or(row.id, default));
        let caret_rect = egui::Rect::from_min_size(
            egui::pos2(rect.left() + name_x - caret, rect.top()),
            egui::vec2(caret, height),
        );
        let on_caret = response.clicked()
            && response
                .interact_pointer_pos()
                .is_some_and(|pos| caret_rect.contains(pos));
        if on_caret || response.double_clicked() {
            open = !open;
            ui.data_mut(|data| data.insert_temp(row.id, open));
        }
    }
    if ui.is_rect_visible(rect) {
        let palette = theme::palette();
        let painter = ui.painter();
        if row.selected {
            painter.rect_filled(rect, 2.0, palette.selection);
        } else if response.hovered() {
            painter.rect_filled(rect, 2.0, palette.hover);
        }
        let y = rect.center().y;
        if row.expand.is_some() {
            painter.text(
                egui::pos2(rect.left() + name_x - caret * 0.5, y),
                egui::Align2::CENTER_CENTER,
                if open {
                    egui_phosphor::regular::CARET_DOWN
                } else {
                    egui_phosphor::regular::CARET_RIGHT
                },
                body.clone(),
                theme::muted(),
            );
        }
        let place = |x: f32, galley: &std::sync::Arc<egui::Galley>| {
            egui::pos2(rect.left() + x, y - galley.size().y / 2.0)
        };
        painter.galley(place(name_x, &name), name.clone(), row.name_color);
        if let Some(value) = value {
            painter.galley(place(value_x, &value), value.clone(), theme::text());
        }
        if let Some(note) = note {
            painter.galley(place(note_x, &note), note.clone(), theme::muted());
        }
    }
    (response, open)
}

/// A top-level section of the tree (Arguments, Phases); true when open.
fn section_row(ui: &mut egui::Ui, id: egui::Id, title: &str, default_open: bool) -> bool {
    let (response, open) = tree_row(
        ui,
        Row {
            id,
            depth: 0,
            expand: Some(default_open),
            name: title,
            name_color: theme::heading(),
            value: None,
            note: None,
            selected: false,
        },
    );
    // A section has nothing to select: a click anywhere opens or closes it.
    if response.clicked() && !response.double_clicked() {
        let caret = egui::TextStyle::Body.resolve(ui.style()).size + 2.0;
        let on_caret = response
            .interact_pointer_pos()
            .is_some_and(|pos| pos.x < response.rect.left() + caret);
        if !on_caret {
            let open = !open;
            ui.data_mut(|data| data.insert_temp(id, open));
            return open;
        }
    }
    open
}

/// A remark in the tree, such as "Arguments unavailable".
fn note_row(ui: &mut egui::Ui, depth: usize, text: &str, color: Color32) {
    tree_row(
        ui,
        Row {
            id: ui.id().with(("note", depth, text)),
            depth,
            expand: None,
            name: text,
            name_color: color,
            value: None,
            note: None,
            selected: false,
        },
    );
}

fn warning_line(ui: &mut egui::Ui, text: &str) {
    ui.add(
        egui::Label::new(
            RichText::new(format!("{} {text}", egui_phosphor::regular::WARNING))
                .color(theme::warn()),
        )
        .wrap(),
    );
}

/// A value large, in its syntax color, with its number when it is a name.
fn value_line(ui: &mut egui::Ui, shown: &values::Shown) {
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

/// The number of arguments syscall `nr` takes (six when unknown).
pub(crate) fn arg_count(nr: u64) -> usize {
    syscalls::syscall(nr)
        .and_then(|info| info.arg_count)
        .map_or(6, usize::from)
        .min(6)
}

/// The captured data an argument points to, when one field holds it whole
/// (a path, a buffer): exit data first, as it is what the call returned.
fn argument_data<'a>(fields: &[(u8, &'a FieldSummary)]) -> Option<(u8, &'a FieldSummary)> {
    let top_level = |field: &FieldSummary| {
        let key = match field.key.strip_prefix("arg") {
            Some(rest) if rest.as_bytes().first().is_some_and(u8::is_ascii_digit) => {
                rest.get(2..).unwrap_or_default()
            }
            _ => field.key.as_str(),
        };
        !key.contains(['.', '['])
    };
    [2, 1].into_iter().find_map(|phase| {
        fields.iter().copied().find(|(owner, field)| {
            *owner == phase && top_level(field) && !covered_preview(field).is_empty()
        })
    })
}

/// "832 bytes", or "4 of 8 bytes" when only part was captured.
pub(crate) fn capture_size(field: &FieldSummary) -> String {
    match field.logical_len {
        Some(logical) if logical != field.captured_len => {
            format!("{} of {logical} bytes", field.captured_len)
        }
        _ => format!("{} bytes", field.captured_len),
    }
}

fn capture_color(field: &FieldSummary) -> Color32 {
    if field.complete {
        theme::value(ValueKind::Number)
    } else {
        theme::warn()
    }
}

/// Guest time in seconds, to the microsecond.
pub(crate) fn seconds(timestamp_ns: u64) -> String {
    format!(
        "{}.{:06}",
        timestamp_ns / 1_000_000_000,
        timestamp_ns % 1_000_000_000 / 1_000
    )
}

/// The right-click menu of a captured field; true when the user asked to
/// open its data window.
fn field_menu(response: &egui::Response, field: &FieldSummary) -> bool {
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
            ui.close_menu();
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

/// Status names of `enum ant_status` in the guest kernel's capture API.
pub(crate) fn status_name(status: u32) -> String {
    match status {
        0 => "complete",
        1 => "copy fault",
        2 => "invalid extent",
        3 => "unknown extent",
        4 => "no decoder",
        5 => "null pointer",
        6 => "address only",
        7 => "not observed asynchronously",
        8 => "resource exhausted",
        9 => "aborted on loss",
        10 => "context missing",
        11 => "not written",
        12 => "not resident",
        status => return format!("status {status}"),
    }
    .into()
}

/// Why a field's capture is not complete, in a few words.
pub(crate) fn incomplete_reason(field: &FieldSummary) -> String {
    match field.status {
        Some(0) | None => "incomplete".into(),
        Some(status) => status_name(status),
    }
}

/// "Captured bytes (N bytes)"; an incomplete capture also says how much of
/// the object it holds and why it stopped.
pub(crate) fn capture_summary(field: &FieldSummary) -> String {
    let count = capture_size(field);
    if field.complete {
        format!("Captured bytes ({count})")
    } else {
        format!("Captured bytes ({count}, {})", incomplete_reason(field))
    }
}

/// `text` about `field`, in the warning color when its capture is incomplete.
fn capture_text(field: &FieldSummary, text: String) -> RichText {
    if field.complete {
        RichText::new(text)
    } else {
        RichText::new(text).color(theme::warn())
    }
}

fn syscall_name(nr: u64) -> String {
    syscalls::syscall(nr).map_or_else(|| format!("syscall {nr}"), |info| info.name.clone())
}

pub(crate) fn argument_name(nr: u64, index: usize) -> &'static str {
    if let Some(argument) = syscalls::syscall(nr).and_then(|info| info.arguments.get(index)) {
        return &argument.name;
    }
    const GENERIC: [&str; 6] = ["first", "second", "third", "fourth", "fifth", "sixth"];
    let names: &[&str] = match nr {
        0 | 1 => &["fd", "buf", "count"],
        2 => &["path", "flags", "mode"],
        3 => &["fd"],
        4 => &["path", "stat"],
        5 => &["fd", "stat"],
        9 => &["address", "length", "protection", "flags", "fd", "offset"],
        10 => &["address", "length", "protection"],
        11 => &["address", "length"],
        16 => &["fd", "request", "argument"],
        19 | 20 => &["fd", "iov", "iov_count"],
        41 => &["domain", "type", "protocol"],
        42 | 49 => &["fd", "address", "address_len"],
        43 => &["fd", "address", "address_len"],
        44 | 45 => &["fd", "buf", "length", "flags", "address", "address_len"],
        50 => &["fd", "backlog"],
        56 => &["flags", "stack", "parent_tid", "child_tid", "tls"],
        59 => &["path", "argv", "envp"],
        60 | 231 => &["status"],
        62 => &["pid", "signal"],
        82 => &["old_path", "new_path"],
        87 => &["path"],
        257 => &["dirfd", "path", "flags", "mode"],
        322 => &["dirfd", "path", "argv", "envp", "flags"],
        _ => &[],
    };
    names.get(index).copied().unwrap_or(GENERIC[index.min(5)])
}

fn show_flags(ui: &mut egui::Ui, number: u64, index: usize, value: u64, args: Option<[u64; 6]>) {
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

fn async_scalar(event: &antinomie_monitor_core::EventSummary, key: &str) -> Option<u64> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    let data: [u8; 8] = covered_preview(field).get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(data))
}

fn async_stage(event: &antinomie_monitor_core::EventSummary) -> String {
    match async_scalar(event, "async.stage") {
        Some(1) => "Submission".into(),
        Some(2) => "Accepted".into(),
        Some(3) => "Rejected".into(),
        Some(4) => "Completion".into(),
        Some(5) => "Canceled".into(),
        Some(6) => "Observation unavailable".into(),
        Some(7) => "Reaped".into(),
        Some(stage) => format!("Unknown stage {stage}"),
        None => "Unknown stage".into(),
    }
}

pub(crate) fn field_argument(nr: u64, key: &str) -> Option<usize> {
    if let Some(rest) = key.strip_prefix("arg") {
        let index = rest.as_bytes().first().copied()?;
        if (b'0'..=b'5').contains(&index)
            && rest
                .as_bytes()
                .get(1)
                .is_none_or(|b| matches!(b, b'.' | b'['))
        {
            return Some(usize::from(index - b'0'));
        }
    }
    let head = key.split(['.', '[']).next()?;
    match head {
        "buf" | "data" if matches!(nr, 0 | 1 | 44 | 45) => Some(1),
        "iov" if matches!(nr, 19 | 20) => Some(1),
        "path" | "filename" => match nr {
            2 | 4 | 59 | 82 | 87 => Some(0),
            257 | 322 => Some(1),
            _ => None,
        },
        "argv" => match nr {
            59 => Some(1),
            322 => Some(2),
            _ => None,
        },
        "envp" => match nr {
            59 => Some(2),
            322 => Some(3),
            _ => None,
        },
        "address" | "sockaddr" => match nr {
            42 | 43 | 49 => Some(if key.ends_with("length") || key.ends_with("capacity") {
                2
            } else {
                1
            }),
            44 | 45 => Some(if key.ends_with("length") || key.ends_with("capacity") {
                5
            } else {
                4
            }),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn covered_preview(field: &FieldSummary) -> &[u8] {
    let covered = field
        .ranges
        .iter()
        .find(|(offset, _)| *offset == 0)
        .map_or(0, |(_, len)| *len);
    &field.preview[..field
        .preview
        .len()
        .min(usize::try_from(covered).unwrap_or(usize::MAX))]
}

pub(crate) fn next_range(field: &FieldSummary, offset: u64) -> Option<(u64, u64)> {
    field
        .ranges
        .iter()
        .filter_map(|&(start, len)| {
            let end = start.checked_add(len)?;
            let next = offset.max(start);
            (next < end).then_some((next, end - next))
        })
        .min_by_key(|(offset, _)| *offset)
}

/// A short form of a captured field: a socket address decoded, text quoted
/// (without its NUL terminator), other bytes in hex; "..." when the field
/// holds more than shown.
pub(crate) fn preview(field: &FieldSummary) -> String {
    let data = covered_preview(field);
    if data.is_empty() {
        return "uncaptured".into();
    }
    if field.key.contains("addr") {
        if let Some(address) = values::sockaddr(data) {
            return address;
        }
    }
    let shown = &data[..data.len().min(48)];
    // All zeros is a cleared structure, not an empty string.
    let printable = (shown.len() == 1 || shown.iter().any(|byte| *byte != 0))
        && shown.iter().all(|byte| {
            byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\n' | b'\r' | b'\t' | 0)
        });
    let text = if printable {
        values::quoted(shown)
    } else {
        shown
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let more = field
        .logical_len
        .is_some_and(|len| len > shown.len() as u64)
        || field.captured_len > shown.len() as u64;
    if more {
        format!("{text}...")
    } else {
        text
    }
}

/// How a piece of a trace line is colored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Argument names and separators.
    Label,
    Value(ValueKind),
    /// Missing phases, incomplete captures.
    Note,
}

impl Tone {
    pub(crate) fn color(self) -> Color32 {
        match self {
            Tone::Label => theme::muted(),
            Tone::Value(kind) => theme::value(kind),
            Tone::Note => theme::warn(),
        }
    }
}

/// The Info column of a call, strace-like: each argument by meaning
/// (`fd=3 buf="..." count=832`), the data captured behind a pointer in
/// place of its address, other captured objects, then remarks.
pub(crate) fn info_parts(invocation: &InvocationSummary) -> Vec<(String, Tone)> {
    let Some(event) = representative(invocation) else {
        return vec![("Missing phases".into(), Tone::Note)];
    };
    let nr = event.syscall_nr;
    let args = invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args));
    let fields: Vec<(u8, &FieldSummary)> = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| event.fields.iter().map(|field| (event.phase, field)))
        .collect();
    let mut parts = Vec::new();
    let mut shown_fields = Vec::new();
    let space = |parts: &mut Vec<(String, Tone)>| {
        if !parts.is_empty() {
            parts.push((" ".into(), Tone::Label));
        }
    };
    if let Some(args) = args {
        for index in 0..arg_count(nr) {
            space(&mut parts);
            parts.push((format!("{}=", argument_name(nr, index)), Tone::Label));
            let owned: Vec<_> = fields
                .iter()
                .copied()
                .filter(|(_, field)| field_argument(nr, &field.key) == Some(index))
                .collect();
            match argument_data(&owned) {
                Some((_, field)) => {
                    shown_fields.push(field.object_id);
                    parts.push((preview(field), Tone::Value(ValueKind::Text)));
                }
                None => {
                    let shown = values::argument(nr, index, &args);
                    parts.push((shown.text, Tone::Value(shown.kind)));
                }
            }
        }
    }
    for (_, field) in fields
        .iter()
        .filter(|(_, field)| {
            !shown_fields.contains(&field.object_id)
                && (field.key.contains("path")
                    || field.key.contains("data")
                    || field.key.contains("buf")
                    || field.key.contains("address")
                    || field.key.contains("argv"))
        })
        .take(3)
    {
        space(&mut parts);
        parts.push((format!("{}=", field.key), Tone::Label));
        parts.push((preview(field), Tone::Value(ValueKind::Text)));
    }
    let mut notes = Vec::new();
    if invocation.entry.is_none() {
        notes.push("missing Entry".to_owned());
    }
    if invocation.exit.is_none() {
        notes.push("missing Exit".to_owned());
    }
    if !invocation.async_events.is_empty() {
        notes.push(format!(
            "Async: {}",
            invocation
                .async_events
                .iter()
                .take(3)
                .map(async_stage)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for event in invocation.entry.iter().chain(invocation.exit.iter()) {
        if !event.complete || !event.issues.is_empty() {
            let mut note = format!(
                "incomplete {}",
                if event.phase == 2 { "Exit" } else { "Entry" }
            );
            for issue in event.issues.iter().take(2) {
                note.push_str(&format!(": {}", issue.chars().take(96).collect::<String>()));
            }
            notes.push(note);
        }
    }
    if !notes.is_empty() {
        if !parts.is_empty() {
            parts.push(("; ".into(), Tone::Label));
        }
        parts.push((notes.join("; "), Tone::Note));
    }
    parts
}

/// The trace table cells of a call, colored, each with its hover text:
/// time, records, TID, CPU, syscall, return and info.
pub(crate) fn cells(invocation: &InvocationSummary) -> Vec<(Vec<(String, Tone)>, String)> {
    let Some(event) = representative(invocation) else {
        return Vec::new();
    };
    let plain = |text: String| vec![(text, Tone::Value(ValueKind::Plain))];
    let label = |text: String| vec![(text, Tone::Label)];
    let (records, records_hover) = match (&invocation.entry, &invocation.exit) {
        (Some(entry), Some(exit)) => (
            format!("{}\u{2192}{}", entry.event_seq, exit.event_seq),
            format!(
                "Entry record {}, Exit record {}",
                entry.event_seq, exit.event_seq
            ),
        ),
        _ => (
            event.event_seq.to_string(),
            format!("Record {}", event.event_seq),
        ),
    };
    let (cpu, cpu_hover) = match (&invocation.entry, &invocation.exit) {
        (Some(entry), Some(exit)) if entry.cpu != exit.cpu => (
            format!("{}\u{2192}{}", entry.cpu, exit.cpu),
            format!("Entered on CPU {}, returned on CPU {}", entry.cpu, exit.cpu),
        ),
        _ => (event.cpu.to_string(), format!("CPU {}", event.cpu)),
    };
    let group = antinomie_monitor_core::syscall_groups::SyscallGroup::of(&event.syscall_name);
    let syscall = vec![
        (event.syscall_name.clone(), Tone::Value(ValueKind::Name)),
        (format!(" ({})", event.syscall_nr), Tone::Label),
    ];
    let syscall_hover = format!(
        "{} (syscall {}){}",
        event.syscall_name,
        event.syscall_nr,
        group.map_or_else(String::new, |group| format!("\n{}", group.label()))
    );
    let (result, result_hover) = match invocation.exit.as_ref().and_then(|exit| exit.result) {
        Some(result) => {
            let shown = values::result(event.syscall_nr, result);
            (
                vec![(shown.text, Tone::Value(shown.kind))],
                values::result_hover(event.syscall_nr, result),
            )
        }
        None => (
            vec![("missing Exit".to_owned(), Tone::Note)],
            "No Exit event: the call has not returned, or its Exit was lost".to_owned(),
        ),
    };
    let info = info_parts(invocation);
    let info_hover: String = info.iter().map(|(text, _)| text.as_str()).collect();
    vec![
        (
            plain(seconds(event.timestamp_ns)),
            format!("{} ns since the guest booted", event.timestamp_ns),
        ),
        (label(records), records_hover),
        (
            plain(event.tid.to_string()),
            if event.pid == 0 {
                format!("TID {}", event.tid)
            } else {
                format!("TID {}, PID {}", event.tid, event.pid)
            },
        ),
        (label(cpu), cpu_hover),
        (syscall, syscall_hover),
        (result, result_hover),
        (info, info_hover),
    ]
}

/// The Info column as plain text (filtering, sorting, copying).
pub(crate) fn info(invocation: &InvocationSummary) -> String {
    info_parts(invocation)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

pub(crate) fn numeric_formats(value: u64, width: usize) -> Vec<(&'static str, String)> {
    let bits = width.clamp(1, 8) * 8;
    let value = if bits == 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    let signed = ((value << (64 - bits)) as i64) >> (64 - bits);
    let data = value.to_le_bytes();
    vec![
        ("Unsigned", value.to_string()),
        ("Signed", signed.to_string()),
        ("Hex", format!("{value:#x}")),
        ("Octal", format!("{value:#o}")),
        (
            "Float32",
            if width >= 4 {
                f32::from_bits(value as u32).to_string()
            } else {
                "needs 4 bytes".into()
            },
        ),
        (
            "Float64",
            if width >= 8 {
                f64::from_bits(value).to_string()
            } else {
                "needs 8 bytes".into()
            },
        ),
        (
            "Char / ASCII",
            data[..width.clamp(1, 8)]
                .iter()
                .map(|byte| char::from(*byte).escape_default().to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        ("Byte order", "Little endian (x86-64)".into()),
    ]
}

fn numeric(ui: &mut egui::Ui, value: u64, width: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn field() -> FieldSummary {
        FieldSummary {
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
        assert_eq!(field_argument(0, "buf"), Some(1));
        assert_eq!(field_argument(257, "path"), Some(1));
        assert_eq!(field_argument(19, "arg1.iov[2].data"), Some(1));
        assert_eq!(field_argument(43, "address.length"), Some(2));
        assert_eq!(field_argument(45, "address.data"), Some(4));
        assert_eq!(field_argument(59, "context.exec.argv[0]"), None);
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
