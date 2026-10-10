//! Paired invocation presentation and inspectors for actually captured content.
use crate::{
    data_view::{self, OpenData},
    theme,
};
use antinomie_monitor_core::{syscalls, FieldSummary, InvocationSummary};
use eframe::egui::{self, RichText};
use std::collections::BTreeMap;

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

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        invocation: Option<&InvocationSummary>,
        can_read: bool,
    ) -> Option<(FieldSummary, u64, usize)> {
        let Some(invocation) = invocation else {
            ui.label("No invocation selected");
            return None;
        };
        let width = (ui.available_width() * 0.43).clamp(180.0, 460.0);
        egui::SidePanel::left("argument_tree")
            .default_width(width)
            .min_width(140.0)
            .max_width((ui.available_width() - 180.0).max(140.0))
            .resizable(true)
            .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 0)))
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("argument_tree_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (label, phase, event) in [
                            ("Entry", 1, invocation.entry.as_ref()),
                            ("Exit", 2, invocation.exit.as_ref()),
                        ] {
                            egui::CollapsingHeader::new(label)
                                .id_salt((key(invocation), phase))
                                .default_open(true)
                                .show(ui, |ui| {
                                    let Some(event) = event else {
                                        ui.colored_label(theme::WARN, "Missing phase");
                                        return;
                                    };
                                    if !event.complete {
                                        ui.colored_label(theme::WARN, "Incomplete capture");
                                    }
                                    for issue in &event.issues {
                                        ui.colored_label(theme::WARN, issue);
                                    }
                                    if let Some(result) = event.result {
                                        let response = ui.selectable_label(
                                            self.selection == Some(Selection::Return(result)),
                                            format!("Return: {result}"),
                                        );
                                        data_view::number_menu(
                                            &response,
                                            result as u64,
                                            8,
                                            &result.to_string(),
                                            &[],
                                        );
                                        if response.clicked() {
                                            self.clear();
                                            self.selection = Some(Selection::Return(result));
                                        }
                                    }
                                    let args = event.args.or_else(|| {
                                        invocation.entry.as_ref().and_then(|entry| entry.args)
                                    });
                                    if event.args.is_none() && args.is_some() {
                                        ui.colored_label(theme::MUTED, "Saved Entry arguments");
                                    }
                                    if let Some(args) = args {
                                        let arg_count = syscalls::syscall(event.syscall_nr)
                                            .and_then(|info| info.arg_count)
                                            .map_or(6, usize::from);
                                        for (index, value) in
                                            args.into_iter().enumerate().take(arg_count)
                                        {
                                            let selected = self.selection
                                                == Some(Selection::Argument {
                                                    phase,
                                                    index,
                                                    value,
                                                });
                                            let name = argument_name(event.syscall_nr, index);
                                            let response = egui::CollapsingHeader::new(format!(
                                                "{name}: {value:#x}"
                                            ))
                                            .id_salt((key(invocation), phase, index))
                                            .default_open(false)
                                            .show(ui, |ui| {
                                                show_flags(
                                                    ui,
                                                    event.syscall_nr,
                                                    index,
                                                    value,
                                                    Some(args),
                                                );
                                                let numeric =
                                                    ui.selectable_label(selected, "Numeric value");
                                                data_view::number_menu(
                                                    &numeric,
                                                    value,
                                                    8,
                                                    &format!("{value:#x}"),
                                                    &[],
                                                );
                                                if numeric.clicked() {
                                                    self.select_argument(phase, index, value);
                                                }
                                                let fields: Vec<_> = event
                                                    .fields
                                                    .iter()
                                                    .filter(|field| {
                                                        field_argument(event.syscall_nr, &field.key)
                                                            == Some(index)
                                                    })
                                                    .collect();
                                                field_tree(
                                                    ui,
                                                    (invocation, event.syscall_nr, phase),
                                                    &fields,
                                                    true,
                                                    self,
                                                );
                                            });
                                            data_view::number_menu(
                                                &response.header_response,
                                                value,
                                                8,
                                                &format!("{value:#x}"),
                                                &[(
                                                    "Name and value",
                                                    &format!("{name}: {value:#x}"),
                                                )],
                                            );
                                            if response.header_response.clicked() {
                                                self.select_argument(phase, index, value);
                                            }
                                        }
                                    } else {
                                        ui.colored_label(theme::MUTED, "Arguments unavailable");
                                    }
                                    let fields: Vec<_> = event
                                        .fields
                                        .iter()
                                        .filter(|field| {
                                            args.is_none()
                                                || field_argument(event.syscall_nr, &field.key)
                                                    .is_none()
                                        })
                                        .collect();
                                    if !fields.is_empty() {
                                        egui::CollapsingHeader::new("Captured objects")
                                            .id_salt((key(invocation), phase, "objects"))
                                            .default_open(true)
                                            .show(ui, |ui| {
                                                field_tree(
                                                    ui,
                                                    (invocation, event.syscall_nr, phase),
                                                    &fields,
                                                    false,
                                                    self,
                                                )
                                            });
                                    }
                                });
                        }
                        egui::CollapsingHeader::new(format!(
                            "Async ({})",
                            invocation.async_events.len()
                        ))
                        .id_salt((key(invocation), "async"))
                        .default_open(false)
                        .show(ui, |ui| {
                            if invocation.async_events.is_empty() {
                                ui.colored_label(theme::MUTED, "No correlated async observations");
                            }
                            for event in &invocation.async_events {
                                let header = egui::CollapsingHeader::new(format!(
                                    "{} / {} / TID {} / CPU {}",
                                    async_stage(event),
                                    event.event_seq,
                                    event.tid,
                                    event.cpu
                                ))
                                .id_salt(event.event_seq)
                                .show(ui, |ui| {
                                    for issue in &event.issues {
                                        ui.colored_label(theme::WARN, issue);
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
                                        let response = ui.add(
                                            egui::Label::new(format!("{label}: {result}"))
                                                .sense(egui::Sense::click()),
                                        );
                                        data_view::number_menu(
                                            &response,
                                            result as u64,
                                            8,
                                            &result.to_string(),
                                            &[],
                                        );
                                    }
                                    for field in &event.fields {
                                        let response = ui.selectable_label(
                                            self.selection
                                                == Some(Selection::AsyncCaptured {
                                                    event_seq: event.event_seq,
                                                    object_id: field.object_id,
                                                }),
                                            capture_text(
                                                field,
                                                format!(
                                                    "{} / {}",
                                                    field.key,
                                                    capture_summary(field)
                                                ),
                                            ),
                                        );
                                        if field_menu(&response, field) {
                                            self.request_data(
                                                invocation,
                                                event.syscall_nr,
                                                format!("async{}", event.event_seq),
                                                field,
                                            );
                                        }
                                        if response.clicked() {
                                            self.clear();
                                            self.selection = Some(Selection::AsyncCaptured {
                                                event_seq: event.event_seq,
                                                object_id: field.object_id,
                                            });
                                            self.data = covered_preview(field).to_vec();
                                            self.data_offset = 0;
                                            self.byte_index = 0;
                                            self.numeric_width = 1;
                                        }
                                    }
                                });
                                header.header_response.context_menu(|ui| {
                                    data_view::copy_items(
                                        ui,
                                        &[
                                            ("Stage".into(), async_stage(event)),
                                            ("Event sequence".into(), event.event_seq.to_string()),
                                            ("TID".into(), event.tid.to_string()),
                                            ("CPU".into(), event.cpu.to_string()),
                                        ],
                                    );
                                });
                            }
                        });
                    });
            });
        let mut read = None;
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(6, 0)))
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("value_inspector")
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.selection.as_ref() {
                        Some(Selection::Argument { value, index, .. }) => {
                            ui.strong("Numeric value");
                            if let Some(event) =
                                invocation.entry.as_ref().or(invocation.exit.as_ref())
                            {
                                show_flags(
                                    ui,
                                    event.syscall_nr,
                                    *index,
                                    *value,
                                    event.args.or_else(|| {
                                        invocation.entry.as_ref().and_then(|entry| entry.args)
                                    }),
                                );
                            }
                            numeric(ui, *value, 8);
                        }
                        Some(Selection::Return(value)) => {
                            ui.strong("Return value");
                            numeric(ui, *value as u64, 8);
                        }
                        Some(Selection::Captured { .. } | Selection::AsyncCaptured { .. }) => {
                            let Some(field) = self.field(invocation) else {
                                ui.label("Captured field unavailable");
                                return;
                            };
                            let mut open_data = false;
                            ui.horizontal_wrapped(|ui| {
                                ui.strong(&field.key);
                                open_data = ui
                                    .button(format!(
                                        "{} Open data…",
                                        egui_phosphor::regular::ARROW_SQUARE_OUT
                                    ))
                                    .on_hover_text(
                                        "Show all captured bytes as text, hexdump, C array, \
                                         Base64 and more",
                                    )
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
                            if let Some(logical) = field.logical_len {
                                let response = ui.add(
                                    egui::Label::new(format!("Logical length {logical} bytes"))
                                        .sense(egui::Sense::click()),
                                );
                                data_view::number_menu(
                                    &response,
                                    logical,
                                    8,
                                    &logical.to_string(),
                                    &[],
                                );
                            } else {
                                ui.label("Logical length unknown");
                            }
                            if field.status.is_some_and(|status| status != 0)
                                || field.capture_error != 0
                            {
                                ui.label(format!(
                                    "Status {}; error {}",
                                    field.status.map_or_else(|| "none".into(), status_name),
                                    field.capture_error
                                ));
                            }
                            if !field.layout.is_empty() {
                                ui.label(&field.layout);
                            }
                            egui::CollapsingHeader::new("Captured ranges").show(ui, |ui| {
                                for &(offset, len) in &field.ranges {
                                    let end = offset.saturating_add(len);
                                    let response = ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("{offset:#x}..{end:#x}"))
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
                            if open_data {
                                self.open_selected_data(invocation, field);
                            }
                            if let Some(error) = &self.error {
                                ui.colored_label(theme::WARN, error);
                            }
                            if self.pending {
                                ui.label("Reading capture...");
                            }
                            let offset = next_range(
                                field,
                                self.data_offset.saturating_add(self.data.len() as u64),
                            );
                            if let Some((offset, len)) = offset {
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
                            if self.data.is_empty() {
                                ui.colored_label(theme::MUTED, "No captured bytes in this view");
                            }
                            for (line, data) in self.data.chunks(16).enumerate() {
                                ui.horizontal(|ui| {
                                    ui.monospace(format!(
                                        "{:08x}",
                                        self.data_offset + (line * 16) as u64
                                    ));
                                    ui.spacing_mut().item_spacing.x = 3.0;
                                    for (column, byte) in data.iter().enumerate() {
                                        let index = line * 16 + column;
                                        let response = ui.selectable_label(
                                            self.byte_index == index,
                                            RichText::new(format!("{byte:02x}")).monospace(),
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
                                            self.byte_index = index;
                                        }
                                    }
                                    ui.monospace(ascii(data));
                                });
                            }
                            if !self.data.is_empty() {
                                ui.separator();
                                ui.horizontal(|ui| {
                                    for width in [1, 2, 4, 8] {
                                        ui.selectable_value(
                                            &mut self.numeric_width,
                                            width,
                                            format!("{width} B"),
                                        );
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
                                        theme::MUTED,
                                        "Selection needs more contiguous captured bytes",
                                    );
                                }
                            }
                        }
                        None => {
                            ui.label("No value selected");
                        }
                    });
            });
        read
    }
}

#[derive(Default)]
struct FieldNode<'a> {
    field: Option<&'a FieldSummary>,
    children: BTreeMap<String, FieldNode<'a>>,
}

/// The invocation, syscall number and phase that captured fields belong to.
type FieldOwner<'a> = (&'a InvocationSummary, u64, u8);

fn field_tree(
    ui: &mut egui::Ui,
    owner: FieldOwner<'_>,
    fields: &[&FieldSummary],
    strip_arg: bool,
    inspector: &mut Inspector,
) {
    let mut root = FieldNode::default();
    for field in fields {
        let mut components = field.key.split('.');
        if strip_arg && field.key.starts_with("arg") {
            components.next();
        }
        let mut node = &mut root;
        for component in components {
            let parts = component.split('[');
            for (index, part) in parts.enumerate() {
                if part.is_empty() {
                    continue;
                }
                let label = if index == 0 {
                    part.to_owned()
                } else {
                    format!("[{part}")
                };
                node = node.children.entry(label).or_default();
            }
        }
        node.field = Some(field);
    }
    fn show(
        ui: &mut egui::Ui,
        owner: FieldOwner<'_>,
        node: &FieldNode<'_>,
        inspector: &mut Inspector,
    ) {
        let (invocation, nr, phase) = owner;
        for (label, child) in &node.children {
            ui.push_id((phase, label), |ui| {
                let response =
                    egui::CollapsingHeader::new(label)
                        .default_open(false)
                        .show(ui, |ui| {
                            if let Some(field) = child.field {
                                let response = ui.selectable_label(
                                    inspector.selection
                                        == Some(Selection::Captured {
                                            phase,
                                            object_id: field.object_id,
                                        }),
                                    capture_text(field, capture_summary(field)),
                                );
                                if field_menu(&response, field) {
                                    inspector.request_data(
                                        invocation,
                                        nr,
                                        format!("p{phase}"),
                                        field,
                                    );
                                }
                                if response.clicked() {
                                    inspector.select_field(phase, field);
                                }
                            }
                            show(ui, owner, child, inspector);
                        });
                if let Some(field) = child.field {
                    if field_menu(&response.header_response, field) {
                        inspector.request_data(invocation, nr, format!("p{phase}"), field);
                    }
                    if response.header_response.clicked() {
                        inspector.select_field(phase, field);
                    }
                }
            });
        }
    }
    show(ui, owner, &root, inspector);
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
    let count = match field.logical_len {
        Some(logical) if logical != field.captured_len => {
            format!("{} of {logical} bytes", field.captured_len)
        }
        _ => format!("{} bytes", field.captured_len),
    };
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
        RichText::new(text).color(theme::WARN)
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
                        .color(theme::WARN),
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

fn ascii(data: &[u8]) -> String {
    data.iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

pub(crate) fn preview(field: &FieldSummary) -> String {
    let data = covered_preview(field);
    let data = &data[..data.len().min(48)];
    let printable = data
        .iter()
        .all(|byte| byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\n' | b'\r' | b'\t' | 0));
    let text = if printable {
        format!(
            "\"{}\"",
            data.iter()
                .flat_map(|byte| char::from(*byte).escape_default())
                .collect::<String>()
        )
    } else {
        data.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let suffix = if field.logical_len.is_some_and(|len| len > data.len() as u64)
        || field.captured_len > data.len() as u64
    {
        "..."
    } else {
        ""
    };
    if data.is_empty() {
        "uncaptured".into()
    } else {
        format!("{text}{suffix}")
    }
}

pub(crate) fn info(invocation: &InvocationSummary) -> String {
    let Some(event) = representative(invocation) else {
        return "Missing phases".into();
    };
    let args = invocation.entry.as_ref().and_then(|event| event.args);
    let result = invocation.exit.as_ref().and_then(|event| event.result);
    let fields = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| event.fields.iter());
    let mut content = match (event.syscall_nr, args) {
        (0 | 1 | 44 | 45, Some(args)) => format!(
            "fd={} requested={} returned={}",
            args[0],
            args[2],
            result
                .map(|n| n.to_string())
                .unwrap_or_else(|| "pending".into())
        ),
        (19 | 20, Some(args)) => format!(
            "fd={} iov_count={} returned={}",
            args[0],
            args[2],
            result
                .map(|n| n.to_string())
                .unwrap_or_else(|| "pending".into())
        ),
        (3 | 5 | 16 | 42 | 43 | 49 | 50, Some(args)) => format!("fd={}", args[0]),
        (41, Some(args)) => format!("domain={} type={} protocol={}", args[0], args[1], args[2]),
        (60 | 231, Some(args)) => format!("status={}", args[0]),
        (62, Some(args)) => format!("pid={} signal={}", args[0], args[1]),
        (9..=11, Some(args)) => format!("address={:#x} length={}", args[0], args[1]),
        _ => String::new(),
    };
    for field in fields
        .filter(|field| {
            field.key.contains("path")
                || field.key.contains("data")
                || field.key.contains("buf")
                || field.key.contains("address")
                || field.key.contains("argv")
        })
        .take(3)
    {
        if !content.is_empty() {
            content.push_str("; ");
        }
        content.push_str(&format!("{}={}", field.key, preview(field)));
    }
    if invocation.entry.is_none() {
        content.push_str("; missing Entry");
    }
    if invocation.exit.is_none() {
        content.push_str("; missing Exit");
    }
    if !invocation.async_events.is_empty() {
        content.push_str("; Async: ");
        content.push_str(
            &invocation
                .async_events
                .iter()
                .take(3)
                .map(async_stage)
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    for event in invocation.entry.iter().chain(invocation.exit.iter()) {
        if !event.complete || !event.issues.is_empty() {
            content.push_str(&format!(
                "; incomplete {}",
                if event.phase == 2 { "Exit" } else { "Entry" }
            ));
            for issue in event.issues.iter().take(2) {
                content.push_str(&format!(": {}", issue.chars().take(96).collect::<String>()));
            }
        }
    }
    content.trim_start_matches("; ").to_owned()
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
    egui::Grid::new("numeric_inspector")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            let formats = numeric_formats(value, width);
            for (label, text) in &formats {
                ui.label(*label);
                let response = ui.add(
                    egui::Label::new(RichText::new(text).monospace()).sense(egui::Sense::click()),
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
