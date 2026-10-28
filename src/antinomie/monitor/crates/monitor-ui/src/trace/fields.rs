// SPDX-License-Identifier: GPL-3.0-only
//! Captured-field presentation for the trace inspector: the field tree, value
//! lines, capture sizes and flags, and the trace line parts of a call.
use super::*;
use antinomie_monitor_core::typed_fields::{self, Call, Decoded};

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
            let shown = child.field.map(|field| preview_in(call.as_ref(), field));
            let (response, open) = tree_row(
                ui,
                Row {
                    id: ui
                        .id()
                        .with((key(invocation), phase, parent.levels(), label)),
                    branch: &branch,
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

/// The number of arguments syscall `nr` takes (six when unknown).
pub(crate) fn arg_count(nr: u64) -> usize {
    syscalls::syscall(nr)
        .and_then(|info| info.arg_count)
        .map_or(6, usize::from)
        .min(6)
}

/// The captured data an argument points to, when one field holds it whole
/// (a path, a buffer): exit data first, as it is what the call returned.
/// Whether argument `index` is a buffer the call fills and returns the
/// length of, and the call returned 0: a read at end of file, an empty
/// `/proc/<pid>/cmdline`, a closed socket. Nothing was written to capture.
pub(super) fn nothing_returned(invocation: &InvocationSummary, nr: u64, index: usize) -> bool {
    let Some(info) = syscalls::syscall(nr) else {
        return false;
    };
    let fills = match info.name.as_str() {
        "read" | "pread64" | "recvfrom" | "getrandom" | "readlink" => index == 1,
        "readlinkat" => index == 2,
        "getdents" | "getdents64" => index == 1,
        _ => false,
    };
    fills
        && invocation.exit.as_ref().and_then(|exit| exit.result) == Some(0)
        && info
            .arguments
            .get(index)
            .is_some_and(|argument| argument.pointer)
}

pub(super) fn argument_data<'a>(
    fields: &[(u8, &'a FieldSummary)],
) -> Option<(u8, &'a FieldSummary)> {
    // The argument's own object: its key past the first component ("arg1",
    // "address", "signal") is not nested ("arg1.iov[0].data", "msghdr.name").
    let top_level = |field: &FieldSummary| {
        let rest = field
            .key
            .split_once('.')
            .map_or(field.key.as_str(), |(_, rest)| rest);
        !rest.contains(['.', '['])
    };
    [2, 1].into_iter().find_map(|phase| {
        let captured: Vec<_> = fields
            .iter()
            .copied()
            .filter(|(owner, field)| *owner == phase && !covered_preview(field).is_empty())
            .collect();
        captured
            .iter()
            .copied()
            .find(|(_, field)| top_level(field))
            // A lone object of the argument is its data whatever its key
            // ("arg2.socklen.capacity").
            .or_else(|| (captured.len() == 1).then(|| captured[0]))
    })
}

/// What an argument row and the Info column show for the data captured
/// behind an argument: its own object's preview; for an exec vector the
/// strings as a list (`["sh", "-c", "id"]`); otherwise, when the argument has
/// several captured objects and none is its own, how many there are (they are
/// listed under the argument in the decoded tree). The object id is the one
/// shown, when a single object is.
pub(crate) fn argument_preview(
    call: Option<&Call<'_>>,
    fields: &[(u8, &FieldSummary)],
) -> Option<(Option<u32>, String)> {
    if let Some((_, field)) = argument_data(fields) {
        return Some((Some(field.object_id), preview_in(call, field)));
    }
    let mut strings: Vec<(usize, &FieldSummary)> = fields
        .iter()
        .filter_map(|(_, field)| {
            let rest = field.key.split_once(".string[")?.1;
            let index = rest.strip_suffix(']')?.parse().ok()?;
            Some((index, *field))
        })
        .collect();
    if !strings.is_empty() {
        strings.sort_by_key(|(index, _)| *index);
        const SHOWN: usize = 6;
        let mut items: Vec<String> = strings
            .iter()
            .take(SHOWN)
            .map(|(_, field)| {
                if field.complete {
                    values::quoted(covered_preview(field))
                } else {
                    "?".into()
                }
            })
            .collect();
        if strings.len() > SHOWN {
            items.push(format!("… {} more", strings.len() - SHOWN));
        }
        return Some((None, format!("[{}]", items.join(", "))));
    }
    let captured = fields
        .iter()
        .filter(|(_, field)| !covered_preview(field).is_empty())
        .count();
    (captured > 1).then(|| (None, format!("{captured} captured objects")))
}

/// The mark an argument row shows when data behind it was captured later:
/// "kernel copy" if any of its objects is one, else "at exit".
pub(crate) fn argument_recapture(fields: &[(u8, &FieldSummary)]) -> Option<Recapture> {
    let mut marks = fields.iter().filter_map(|(_, field)| field.recapture);
    let first = marks.next()?;
    Some(
        if first == Recapture::KernelCopy || marks.any(|mark| mark == Recapture::KernelCopy) {
            Recapture::KernelCopy
        } else {
            Recapture::AtExit
        },
    )
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

pub(super) fn capture_color(field: &FieldSummary) -> Color32 {
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
/// the object it holds and why it stopped, a later capture where it came from.
pub(crate) fn capture_summary(field: &FieldSummary) -> String {
    let count = capture_size(field);
    if !field.complete {
        format!("Captured bytes ({count}, {})", incomplete_reason(field))
    } else if let Some(mark) = field.recapture {
        format!("Captured bytes ({count}, {})", mark.label())
    } else {
        format!("Captured bytes ({count})")
    }
}

/// What a later capture's tag means, for its tooltip (contract section 22).
pub(crate) fn recapture_explanation(mark: Recapture) -> &'static str {
    match mark {
        Recapture::AtExit => {
            "Read when the call returned, not when it started: the memory was not loaded \
             yet when the call began, and the recorder never loads memory itself. The call \
             loaded it. Another thread of the program could have changed it while the call \
             ran, so the call may have been given something else."
        }
        Recapture::KernelCopy => {
            "The kernel's own copy: the program's memory was not loaded when the call \
             began, and the exec then replaced it. This is the path the exec opened, or an \
             argument or environment string as the kernel placed it on the new program's \
             stack, read when the call returned. Another thread could have changed the \
             original while the kernel copied it."
        }
    }
}

/// `text` about `field`, in the warning color when its capture is incomplete.
pub(super) fn capture_text(field: &FieldSummary, text: String) -> RichText {
    if field.complete {
        RichText::new(text)
    } else {
        RichText::new(text).color(theme::warn())
    }
}

pub(super) fn syscall_name(nr: u64) -> String {
    syscalls::syscall(nr).map_or_else(|| format!("syscall {nr}"), |info| info.name.clone())
}

pub(crate) fn argument_name(nr: u64, index: usize) -> &'static str {
    if let Some(argument) = syscalls::syscall(nr).and_then(|info| info.arguments.get(index)) {
        return &argument.name;
    }
    const GENERIC: [&str; 6] = ["first", "second", "third", "fourth", "fifth", "sixth"];
    GENERIC[index.min(5)]
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

pub(super) fn async_scalar(event: &antinomie_monitor_core::EventSummary, key: &str) -> Option<u64> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    let data: [u8; 8] = covered_preview(field).get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(data))
}

pub(super) fn async_stage(event: &antinomie_monitor_core::EventSummary) -> String {
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

/// The argument a captured field belongs to: the one its descriptor names,
/// else the one its key names (summaries saved before 0.7.0, fields the app
/// derives itself).
pub(crate) fn field_argument(nr: u64, field: &FieldSummary) -> Option<usize> {
    field_argument_of(syscalls::known_name(nr).unwrap_or(""), field)
}

/// `field_argument` for a call known by its name.
pub(crate) fn field_argument_of(name: &str, field: &FieldSummary) -> Option<usize> {
    match field.arg {
        Some(arg) => Some(usize::from(arg)),
        None => key_argument(name, &field.key),
    }
}

/// The argument a captured field's key names for the call `name`, where
/// the argument's role is read from the table by argument name.
pub(crate) fn key_argument(name: &str, key: &str) -> Option<usize> {
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
    let table = syscalls::native();
    let role = |argument: &str| table.argument(name, argument);
    let head = key.split(['.', '[']).next()?;
    let length = key.ends_with("length") || key.ends_with("capacity");
    match (head, name) {
        ("buf" | "data", "read" | "write" | "sendto" | "recvfrom") => role("buf")
            .or_else(|| role("buff"))
            .or_else(|| role("ubuf")),
        ("iov", "readv" | "writev") => role("vec"),
        ("path" | "filename", "open" | "stat" | "execve" | "rename" | "unlink") => role("filename")
            .or_else(|| role("oldname"))
            .or_else(|| role("pathname")),
        ("path" | "filename", "openat" | "execveat") => role("filename"),
        ("argv", "execve" | "execveat") => role("argv"),
        ("envp", "execve" | "execveat") => role("envp"),
        ("address" | "sockaddr", "connect" | "accept" | "bind") => {
            if length {
                role("addrlen").or_else(|| role("upeer_addrlen"))
            } else {
                role("uservaddr")
                    .or_else(|| role("upeer_sockaddr"))
                    .or_else(|| role("umyaddr"))
            }
        }
        ("address" | "sockaddr", "sendto" | "recvfrom") => {
            if length {
                role("addr_len")
            } else {
                role("addr")
            }
        }
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

/// How a captured field is shown. The field's type decides it (its
/// descriptor's encoding and layout), never whether its bytes look like text:
/// a time or a pointer whose bytes happen to be printable is still bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rendering {
    /// A C string or a character array: quoted, NUL terminators dropped.
    Text,
    /// A data buffer (what `write` sent, a key payload): quoted with every
    /// byte, zeros as `\0`.
    Buffer,
    /// A `struct sockaddr`: the address when its family is known, else hex.
    Address,
    /// A struct, scalar, pointer or array: hex bytes.
    Binary,
}

pub(crate) fn rendering(field: &FieldSummary) -> Rendering {
    let layout = typed_fields::layout_type(&field.layout);
    if layout == "sockaddr" {
        return Rendering::Address;
    }
    // Characters by type: `char[16]` (a task name), `char[]` (an interface
    // name), and mount's options (a filesystem's option string).
    if layout.starts_with("char[") || layout == "mount_options" {
        return Rendering::Text;
    }
    if !layout.is_empty() {
        return Rendering::Binary;
    }
    match field.encoding {
        Some(FieldEncoding::Bytes) => Rendering::Buffer,
        Some(FieldEncoding::Object | FieldEncoding::Scalar | FieldEncoding::Array) => {
            Rendering::Binary
        }
        // A field the host made itself (the async system's name) or saved
        // before 0.8.0 without its encoding: a layout-less field is a string.
        Some(FieldEncoding::String) | None => Rendering::Text,
    }
}

/// A short form of a captured field by its [`rendering`]: a socket address
/// decoded, text or a buffer quoted, other bytes in hex; "..." when the field
/// holds more than shown.
pub(crate) fn preview(field: &FieldSummary) -> String {
    let data = covered_preview(field);
    if data.is_empty() {
        return "uncaptured".into();
    }
    let rendering = rendering(field);
    if rendering == Rendering::Address
        && let Some(address) = values::sockaddr(data)
    {
        return address;
    }
    let shown = &data[..data.len().min(48)];
    let text = match rendering {
        Rendering::Text => values::quoted(shown),
        Rendering::Buffer => values::quoted_bytes(shown),
        Rendering::Address | Rendering::Binary => shown
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
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

/// The call a captured field belongs to, for the decoders that read another
/// of its arguments (bpf's command) or depend on the syscall (capget's header).
pub(crate) fn field_call(nr: u64, args: Option<[u64; 6]>) -> Option<Call<'static>> {
    syscalls::syscall(nr).map(|info| Call {
        name: info.name.as_str(),
        args,
    })
}

/// The register arguments of a call: the Entry's, else the Exit's.
pub(crate) fn call_args(invocation: &InvocationSummary) -> Option<[u64; 6]> {
    invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args))
}

/// A captured field decoded by its native layout (a signal set by name, a
/// siginfo by its branch, bpf's attr by its command), when it is one the
/// decoders know; see `typed_fields::decode`.
pub(crate) fn decoded(call: Option<&Call<'_>>, field: &FieldSummary) -> Option<Decoded> {
    typed_fields::decode(call, field)
}

/// A captured field's short form: decoded by its layout when it can be,
/// else by its [`rendering`] ([`preview`]).
pub(crate) fn preview_in(call: Option<&Call<'_>>, field: &FieldSummary) -> String {
    decoded(call, field).map_or_else(|| preview(field), |decoded| decoded.line())
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
    let call = field_call(nr, args);
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
                .filter(|(_, field)| field_argument(nr, field) == Some(index))
                .collect();
            match argument_preview(call.as_ref(), &owned) {
                Some((id, text)) => {
                    shown_fields.extend(id);
                    parts.push((text, Tone::Value(ValueKind::Text)));
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
        parts.push((
            preview_in(call.as_ref(), field),
            Tone::Value(ValueKind::Text),
        ));
    }
    let mut notes = Vec::new();
    if invocation.entry.is_none() {
        notes.push("missing Entry".to_owned());
    }
    if invocation.exit.is_none() && invocation.task_exit.is_none() {
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
    notes.extend(async_browse::partial_note(invocation));
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
        (Some(entry), None) if invocation.task_exit.is_some() => {
            let ended = invocation.task_exit.as_ref().map_or(0, |end| end.event_seq);
            (
                format!("{}\u{2192}{ended}", entry.event_seq),
                format!("Entry record {}, task exit record {ended}", entry.event_seq),
            )
        }
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
        None => match invocation.task_exit_status() {
            Some(status) => (
                vec![(values::task_end(&status), Tone::Value(ValueKind::Plain))],
                format!(
                    "The task ended in this call ({}), so it never returned",
                    values::task_end(&status)
                ),
            ),
            None => (
                vec![("missing Exit".to_owned(), Tone::Note)],
                "No Exit event: the call has not returned, or its Exit was lost".to_owned(),
            ),
        },
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
