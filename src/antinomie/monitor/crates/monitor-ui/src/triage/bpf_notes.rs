// SPDX-License-Identifier: GPL-3.0-only
//! BPF program loads and attachments seen in the trace.
use super::*;

pub(super) fn bpf_notes(input: &TriageInput<'_>) -> Vec<BpfNote> {
    let mut notes = Vec::new();
    // File descriptors returned by successful BPF_PROG_LOAD calls in this slice.
    let mut program_fds = Vec::<(u64, i64)>::new();
    for invocation in input.invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        if event.syscall_name == "close" && succeeded(invocation) {
            if let Some(fd) = call_args(invocation).and_then(|args| i64::try_from(args[0]).ok()) {
                program_fds.retain(|key| *key != (invocation.task_cookie, fd));
            }
        }
        let recorded_args = event.args.or_else(|| call_args(invocation));
        let args = recorded_args.unwrap_or([0; 6]);
        let Some(command) = bpf_command(event, args) else {
            continue;
        };
        let image = instruction_image(invocation, command);
        let (translation, dump, export, bytes, identity) = if let Some(bytes) = image.as_deref() {
            let action = if command == "BPF_PROG_LOAD" {
                "load"
            } else if command == "BPF_PROG_ATTACH" || command == "SO_ATTACH_FILTER" {
                "attach"
            } else {
                command
            };
            let identity = bpf::BpfIdentity {
                stream_id: invocation.stream_id,
                vm_id: input.vm_id.map(str::to_owned),
                boot_id: input.boot_id.map(str::to_owned),
                run_id: input.run_id.map(str::to_owned),
                cookie: Some(invocation.task_cookie),
                pid: Some(event.pid),
                tid: Some(event.tid),
                timestamp_ns: (event.timestamp_ns != 0).then_some(event.timestamp_ns),
                action: action.to_owned(),
                source_syscall: event.syscall_name.clone(),
                event_id: Some(invocation.call_id),
                result: invocation.exit.as_ref().and_then(|exit| exit.result),
                attachment_kind: if command == "SO_ATTACH_FILTER" {
                    "classic socket filter"
                } else if classic_image(command) {
                    "classic seccomp filter"
                } else {
                    "eBPF program"
                }
                .into(),
                declared_instruction_count: captured_integer(
                    invocation,
                    if classic_image(command) {
                        "len"
                    } else {
                        "insn_cnt"
                    },
                ),
                fd: if command == "BPF_PROG_LOAD" {
                    invocation
                        .exit
                        .as_ref()
                        .and_then(|exit| exit.result)
                        .filter(|ret| *ret >= 0)
                } else if command == "SO_ATTACH_FILTER" {
                    recorded_args.and_then(|args| i64::try_from(args[0]).ok())
                } else {
                    captured_integer(invocation, "attach_bpf_fd")
                        .and_then(|fd| i64::try_from(fd).ok())
                },
                capture_issues: invocation
                    .entry
                    .iter()
                    .chain(invocation.exit.iter())
                    .flat_map(|event| event.issues.iter().cloned())
                    .chain(
                        invocation
                            .entry
                            .iter()
                            .chain(invocation.exit.iter())
                            .flat_map(|event| &event.fields)
                            .filter(|field| !field.complete)
                            .map(|field| {
                                format!(
                                    "{} incomplete ({}/{:?} captured octets)",
                                    field.key, field.captured_len, field.logical_len
                                )
                            }),
                    )
                    .collect(),
                ..bpf::BpfIdentity::default()
            };
            let exported = bpf::export_capture(bytes, &identity);
            let translation = if classic_image(command) {
                bpf::translate_classic_explained(
                    bytes,
                    if command == "SO_ATTACH_FILTER" {
                        bpf::ClassicContext::Socket
                    } else if matches!(
                        command,
                        "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER" | "PR_SET_SECCOMP"
                    ) {
                        bpf::ClassicContext::Seccomp
                    } else {
                        bpf::ClassicContext::Unknown
                    },
                )
            } else {
                bpf::translate_explained(bytes)
            };
            let dump = classic_image(command).then(|| bpf::dump(bytes));
            (
                Some(translation),
                dump,
                Some(exported),
                Some(bytes.to_vec()),
                identity,
            )
        } else {
            (None, None, None, None, bpf::BpfIdentity::default())
        };
        let result = invocation.exit.as_ref().and_then(|exit| exit.result);
        notes.push(BpfNote {
            heading: format!("{}  tid {}  {command}", event.syscall_name, event.tid),
            outcome: outcome(invocation),
            lifecycle: attach_of_loaded(command, invocation, &program_fds)
                .or_else(|| bpf_lifecycle(command, result)),
            translation,
            dump,
            export,
            bytes,
            identity,
        });
        if command == "BPF_PROG_LOAD" {
            if let Some(fd) = result.filter(|result| *result >= 0) {
                program_fds.push((invocation.task_cookie, fd));
            }
        }
    }
    notes
}

fn captured_integer(invocation: &InvocationSummary, member: &str) -> Option<u64> {
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .filter(|field| field.key.rsplit('.').next() == Some(member))
        .find_map(|field| {
            let bytes = trace::covered_preview(field);
            match bytes.len() {
                2 => bytes.try_into().ok().map(u16::from_le_bytes).map(u64::from),
                4 => bytes.try_into().ok().map(u32::from_le_bytes).map(u64::from),
                8 => bytes.try_into().ok().map(u64::from_le_bytes),
                _ => None,
            }
        })
}

/// `attach requested of fd N` when a recorded argument is a program fd from
/// an earlier successful load in this slice. No fd is guessed from a pointer.
fn attach_of_loaded(
    command: &str,
    invocation: &InvocationSummary,
    program_fds: &[(u64, i64)],
) -> Option<String> {
    if command != "BPF_PROG_ATTACH" {
        return None;
    }
    let fd = i64::try_from(captured_integer(invocation, "attach_bpf_fd")?).ok()?;
    program_fds
        .contains(&(invocation.task_cookie, fd))
        .then(|| {
            format!(
                "{} of observed loaded fd {fd}",
                if succeeded(invocation) {
                    "attached"
                } else {
                    "attach attempted"
                }
            )
        })
}

fn bpf_lifecycle(command: &str, result: Option<i64>) -> Option<String> {
    let action = match command {
        "BPF_PROG_LOAD" => "load",
        "BPF_PROG_ATTACH" => "attach",
        "BPF_PROG_DETACH" => "detach",
        "SO_ATTACH_FILTER" => "socket attachment",
        "SECCOMP_SET_MODE_STRICT"
        | "SECCOMP_SET_MODE_FILTER"
        | "SECCOMP_MODE_STRICT"
        | "SECCOMP_MODE_FILTER"
        | "PR_SET_SECCOMP" => "seccomp installation",
        _ => return None,
    };
    Some(match result {
        Some(fd) if command == "BPF_PROG_LOAD" && fd >= 0 => format!("loaded program fd {fd}"),
        Some(0) => format!("{action} successful"),
        Some(ret) if ret < 0 => format!("{action} failed ({ret})"),
        Some(ret) => format!("{action} returned {ret}; interpretation depends on recorded flags"),
        None => format!("{action} attempted; exit not recorded"),
    })
}

fn classic_image(command: &str) -> bool {
    matches!(
        command,
        "SO_ATTACH_FILTER" | "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER"
    )
}

pub(super) fn bpf_command(event: &EventSummary, args: [u64; 6]) -> Option<&'static str> {
    if let Some(command) = bpf::command_name(event) {
        return Some(command);
    }
    if classic_socket_filter(event, args) {
        return Some("SO_ATTACH_FILTER");
    }
    if event.syscall_name == "seccomp" || event.syscall_nr == 317 {
        return match args[0] {
            0 => Some("SECCOMP_SET_MODE_STRICT"),
            1 => Some("SECCOMP_SET_MODE_FILTER"),
            _ => None,
        };
    }
    if (event.syscall_name == "prctl" || event.syscall_nr == 157) && args[0] == 22 {
        return Some(match args[1] {
            1 => "SECCOMP_MODE_STRICT",
            2 => "SECCOMP_MODE_FILTER",
            _ => "PR_SET_SECCOMP",
        });
    }
    None
}

/// Exact captured instruction arrays. A buffer whose name merely contains
/// `prog`, `buf` or `insns` is not a program image, and a short preview is
/// not padded out to the declared length.
fn instruction_image(invocation: &InvocationSummary, command: &str) -> Option<Vec<u8>> {
    let (key, layout) = match command {
        "BPF_PROG_LOAD" => ("arg1.attr.insns", "bpf_insn[]"),
        "SO_ATTACH_FILTER" => ("arg3.optval.filter", "sock_filter[]"),
        "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER" => {
            ("arg2.program.filter", "sock_filter[]")
        }
        _ => return None,
    };
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key == key && layout_is(&field.layout, layout))
        .and_then(isolated_instructions)
}

fn layout_is(layout: &str, name: &str) -> bool {
    layout == name || layout.ends_with(&format!("/{name}"))
}

fn isolated_instructions(field: &antinomie_monitor_core::FieldSummary) -> Option<Vec<u8>> {
    let logical = field.logical_len?;
    if !field.complete
        || logical == 0
        || !logical.is_multiple_of(8)
        || field.captured_len != logical
    {
        return None;
    }
    if field.ranges.as_slice() != [(0, logical)] {
        return None;
    }
    let bytes = trace::covered_preview(field);
    if bytes.len() as u64 != logical {
        return None;
    }
    Some(bytes.to_vec())
}

pub(super) fn bpf_view(ui: &mut egui::Ui, input: &TriageInput<'_>, indexed: Option<&[BpfNote]>) {
    let page_notes;
    let notes = if let Some(notes) = indexed {
        notes
    } else {
        page_notes = bpf_notes(input);
        page_notes.as_slice()
    };
    if notes.is_empty() {
        ui.colored_label(
            theme::muted(),
            "No bpf syscall, classic socket filter, or seccomp install was recorded.",
        );
        return;
    }
    let rows: Vec<_> = notes
        .iter()
        .map(|note| bpf_row(note, input.clock_anchor))
        .collect();
    table(
        ui,
        "triage-bpf",
        &["Time", "Observation", "Outcome", "Evidence"],
        &rows,
    );
}

pub(super) fn bpf_row(
    note: &BpfNote,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Vec<Cell> {
    let mut row = vec![
        cell(
            crate::time_format::guest_ns(clock, note.identity.timestamp_ns),
            theme::text(),
            true,
        ),
        cell(&note.heading, theme::text(), false),
        cell(&note.outcome, theme::text(), false),
        cell(
            note.identity
                .event_id
                .map_or("Unavailable".into(), |id| format!("call {id}")),
            theme::text(),
            true,
        ),
    ];
    row[0].values = vec![
        (
            "event.id",
            note.identity
                .event_id
                .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id))),
        ),
        (
            "process.cookie",
            note.identity
                .cookie
                .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id))),
        ),
        (
            "stream.id",
            RowValue::Number(i128::from(note.identity.stream_id)),
        ),
    ];
    row
}

pub(super) fn bpf_detail(
    ui: &mut egui::Ui,
    note: &BpfNote,
    directory: Option<&Path>,
    status: &mut String,
) {
    if !status.is_empty() {
        ui.label(status.as_str());
    }
    if let Some(line) = &note.lifecycle {
        ui.label(line);
    }
    if note.translation.is_none() && note.dump.is_none() {
        ui.weak("The instruction image was not isolated.");
    }
    for text in [&note.translation, &note.dump, &note.export]
        .into_iter()
        .flatten()
    {
        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
    }
    if let (Some(bytes), Some(directory)) = (&note.bytes, directory) {
        if ui.button("Export binary and JSON").clicked() {
            *status = match bpf::write_export(&directory.join("bpf"), bytes, &note.identity) {
                Ok((binary, metadata)) => {
                    format!("Wrote {} and {}", binary.display(), metadata.display())
                }
                Err(error) => error,
            };
        }
    }
}
