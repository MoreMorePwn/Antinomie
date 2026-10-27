// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in rendering check of recorded runs for the guest conformance suite
//! (`examples/conformance` in monitor-core, tests/monitor/conformance):
//!
//! ```text
//! ANTINOMIE_CONFORMANCE_RENDER_RUNS='user=DIR;root=DIR' \
//! ANTINOMIE_CONFORMANCE_RENDER_OUT=OUT_DIR \
//!     cargo test --release -p antinomie-monitor-ui --bin antinomie-monitor \
//!     conformance_trace_render -- --ignored --exact
//! ```
//!
//! Every call of each run goes through the Syscall Trace view's own code: the
//! table cells and Info column, the argument rows of the decoded tree and the
//! captured-field previews, and one frame of the inspector itself (so a panic
//! anywhere in it fails the test). `OUT_DIR/<label>.jsonl` gets one line per
//! call with what the view shows and every place it fell back to a raw value.
//! Labels listed in `ANTINOMIE_CONFORMANCE_RENDER_SUMMARY` (stress runs) keep
//! a sample of 200 calls with a warning or a fallback other than a raw pointer, draw
//! the inspector for those and every 64th call, stop after
//! `ANTINOMIE_CONFORMANCE_RENDER_LIMIT` calls (default 250000; the suite checks
//! every call's records itself) and end with a `{"summary": …}` line of totals.
use super::*;
use antinomie_monitor_core::recording;
use std::{io::Write, path::Path};

/// How one argument reads in the trace.
#[derive(serde::Serialize)]
pub(crate) struct ArgumentView {
    name: String,
    text: String,
    raw: Option<String>,
    /// The captured data shown for the argument instead of its address.
    data: Option<String>,
    kind: &'static str,
    value: String,
}

/// What the Syscall Trace view shows for one call.
#[derive(serde::Serialize)]
pub(crate) struct CallView {
    key: (u64, u64, u64),
    nr: u64,
    name: String,
    tid: u32,
    entry_ns: Option<u64>,
    cells: Vec<String>,
    info: String,
    arguments: Vec<ArgumentView>,
    result: Option<String>,
    fields: Vec<serde_json::Value>,
    /// Lines the decoded tree draws as warnings, and Info's remarks.
    warnings: Vec<String>,
    /// Places the view shows a raw number or a placeholder where it could
    /// say what the value means: `raw-pointer:argN`, `unknown-flags:argN`,
    /// `unknown-selector:argN`, `generic-name:argN`, `syscall-name`,
    /// `uncaptured:KEY`.
    fallbacks: Vec<String>,
}

fn kind(nr: u64, index: usize, args: &[u64; 6]) -> &'static str {
    let Some(argument) = syscalls::syscall(nr).and_then(|info| info.arguments.get(index)) else {
        return "unknown";
    };
    if syscalls::selector_name(nr, index, args).is_some() {
        "selector"
    } else if argument.pointer {
        "pointer"
    } else if argument.flags.is_some() {
        "flags"
    } else {
        "number"
    }
}

pub(crate) fn view(invocation: &InvocationSummary) -> CallView {
    let event = representative(invocation);
    let nr = event.map_or(0, |event| event.syscall_nr);
    let mut fallbacks = Vec::new();
    let mut warnings = Vec::new();
    let name = event.map_or_else(String::new, |event| event.syscall_name.clone());
    if syscalls::syscall(nr).is_none() || name.starts_with("syscall") {
        fallbacks.push("syscall-name".into());
    }
    for (label, event) in [("Entry", &invocation.entry), ("Exit", &invocation.exit)] {
        if let Some(event) = event {
            if !event.complete {
                warnings.push(format!("{label}: incomplete capture"));
            }
            for issue in &event.issues {
                warnings.push(format!("{label}: {issue}"));
            }
        }
    }
    let args = invocation
        .entry
        .as_ref()
        .and_then(|entry| entry.args)
        .or_else(|| invocation.exit.as_ref().and_then(|exit| exit.args));
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
    let mut arguments = Vec::new();
    if let Some(args) = args {
        for index in 0..arg_count(nr) {
            let shown = values::argument(nr, index, &args);
            let owned: Vec<_> = fields
                .iter()
                .copied()
                .filter(|(_, field)| field_argument(nr, field) == Some(index))
                .collect();
            let data = argument_preview(&owned).map(|(_, text)| text);
            let kind = kind(nr, index, &args);
            let name = argument_name(nr, index);
            if syscalls::syscall(nr)
                .and_then(|info| info.arguments.get(index))
                .is_none()
            {
                fallbacks.push(format!("generic-name:arg{index}"));
            }
            match kind {
                "pointer" if args[index] != 0 && data.is_none() => {
                    fallbacks.push(format!("raw-pointer:arg{index}"))
                }
                "flags"
                    if syscalls::argument_flags(nr, index, args[index])
                        .is_some_and(|flags| flags.unknown_bits != 0) =>
                {
                    fallbacks.push(format!("unknown-flags:arg{index}"))
                }
                "selector" if shown.text.starts_with("Unknown") => {
                    fallbacks.push(format!("unknown-selector:arg{index}"))
                }
                _ => {}
            }
            arguments.push(ArgumentView {
                name: name.to_owned(),
                text: shown.text,
                raw: shown.raw,
                data,
                kind,
                value: format!("{:#x}", args[index]),
            });
        }
    }
    let mut views = Vec::new();
    for (phase, field) in &fields {
        let shown = preview(field);
        if shown == "uncaptured" && field.status == Some(0) && field.captured_len > 0 {
            fallbacks.push(format!("uncaptured:{}", field.key));
        }
        views.push(serde_json::json!({
            "phase": phase,
            "key": field.key,
            "arg": field.arg,
            "size": capture_size(field),
            "preview": shown,
            "status": field.status.map(status_name),
            "complete": field.complete,
            "recapture": field.recapture.map(|mark| mark.label()),
        }));
    }
    let info_parts = info_parts(invocation);
    for (text, tone) in &info_parts {
        if *tone == Tone::Note {
            warnings.push(format!("Info: {text}"));
        }
    }
    let cells = cells(invocation)
        .into_iter()
        .map(|(parts, _)| parts.into_iter().map(|(text, _)| text).collect())
        .collect();
    CallView {
        key: key(invocation),
        nr,
        name,
        tid: event.map_or(0, |event| event.tid),
        entry_ns: invocation.entry.as_ref().map(|entry| entry.timestamp_ns),
        cells,
        info: info_parts.into_iter().map(|(text, _)| text).collect(),
        arguments,
        result: invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .map(|result| values::result(nr, result).text),
        fields: views,
        warnings,
        fallbacks,
    }
}

fn render_run(label: &str, directory: &Path, output: &Path, summary: bool) -> usize {
    let archive = recording::open_recording(directory).unwrap();
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(output.join(format!("{label}.jsonl"))).unwrap(),
    );
    let ctx = egui::Context::default();
    let mut inspector = Inspector::default();
    let mut cursor = Some(0);
    let mut count = 0;
    let mut totals = std::collections::BTreeMap::<String, u64>::new();
    let limit: u64 = std::env::var("ANTINOMIE_CONFORMANCE_RENDER_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(250_000);
    let mut limited = false;
    let mut written = 0;
    while let Some(offset) = cursor {
        if summary && count >= limit as usize {
            limited = true;
            break;
        }
        let page = archive.invocation_page(offset, 256).unwrap();
        for invocation in &page.invocations {
            let call = view(invocation);
            let notable = !call.warnings.is_empty()
                || call
                    .fallbacks
                    .iter()
                    .any(|fallback| !fallback.starts_with("raw-pointer"));
            for fallback in &call.fallbacks {
                let kind = fallback.split(':').next().unwrap_or(fallback);
                *totals.entry(kind.to_owned()).or_default() += 1;
            }
            *totals.entry("warnings".into()).or_default() += call.warnings.len() as u64;
            count += 1;
            if summary && !notable && count % 64 != 0 {
                continue;
            }
            // A stress run keeps a bounded sample of its notable calls.
            if !summary || (notable && written < 200) {
                written += 1;
                serde_json::to_writer(&mut file, &call).unwrap();
                file.write_all(b"\n").unwrap();
            }
            // The inspector itself, as the Details panel draws it.
            inspector.clear();
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1280.0, 820.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        inspector.show(ui, Some(invocation), false);
                    });
                },
            );
        }
        cursor = page.next_offset;
    }
    if summary {
        serde_json::to_writer(
            &mut file,
            &serde_json::json!({"summary": {"rendered": count, "limited": limited, "totals": totals}}),
        )
        .unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();
    count
}

#[test]
#[ignore = "requires ANTINOMIE_CONFORMANCE_RENDER_RUNS and ANTINOMIE_CONFORMANCE_RENDER_OUT"]
fn conformance_trace_render() {
    let runs = std::env::var("ANTINOMIE_CONFORMANCE_RENDER_RUNS")
        .expect("ANTINOMIE_CONFORMANCE_RENDER_RUNS");
    let output = std::path::PathBuf::from(
        std::env::var_os("ANTINOMIE_CONFORMANCE_RENDER_OUT")
            .expect("ANTINOMIE_CONFORMANCE_RENDER_OUT"),
    );
    let summarized = std::env::var("ANTINOMIE_CONFORMANCE_RENDER_SUMMARY").unwrap_or_default();
    let summarized: Vec<&str> = summarized.split(',').collect();
    std::fs::create_dir_all(&output).unwrap();
    for entry in runs.split(';').filter(|entry| !entry.is_empty()) {
        let (label, directory) = entry.split_once('=').expect("label=directory");
        let count = render_run(
            label,
            Path::new(directory),
            &output,
            summarized.contains(&label),
        );
        println!("RENDERED {label} {count}");
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;

    #[test]
    fn a_pointer_without_data_and_unknown_flag_bits_are_fallbacks() {
        let mut call = super::super::tests::openat(-2);
        let entry = call.entry.as_mut().unwrap();
        entry.fields.clear();
        entry.args = Some([(-100i64) as u64, 0x7ffe_0000, 1 << 40, 0, 0, 0]);
        let shown = view(&call);
        assert!(
            shown.fallbacks.contains(&"raw-pointer:arg1".to_owned()),
            "{:?}",
            shown.fallbacks
        );
        assert!(shown.fallbacks.contains(&"unknown-flags:arg2".to_owned()));
        assert_eq!(shown.arguments[0].text, "AT_FDCWD");
        assert_eq!(shown.result.as_deref(), Some("ENOENT"));
    }

    /// A call of `nr` with `args` and one captured entry field.
    fn call_with(nr: u64, name: &str, args: [u64; 6], field: FieldSummary) -> InvocationSummary {
        let mut call = super::super::tests::openat(-22);
        for event in call.entry.iter_mut().chain(call.exit.iter_mut()) {
            event.syscall_nr = nr;
            event.syscall_name = name.into();
        }
        let entry = call.entry.as_mut().unwrap();
        entry.args = Some(args);
        entry.fields = vec![field];
        call
    }

    /// The two golden failures: what the trace shows (and the golden file
    /// keeps) for a time or a pointer-holding struct whose bytes happen to be
    /// printable is their bytes.
    #[test]
    fn printable_looking_typed_data_renders_as_bytes() {
        use super::super::tests::typed;
        let object = Some(FieldEncoding::Object);
        let timeout = [10, 0, 0, 0, 0, 0, 0, 0, b'(', b'[', b'}', b'\r', 0, 0, 0, 0];
        let mut field = typed("arg3.timeout", "timespec", object, &timeout);
        field.arg = Some(3);
        let shown = view(&call_with(
            449,
            "futex_waitv",
            [0x4c_1000, 1, 0, 0x7ffe_0010, 1, 0],
            field,
        ));
        let expected = "0a 00 00 00 00 00 00 00 28 5b 7d 0d 00 00 00 00";
        assert_eq!(shown.arguments[3].data.as_deref(), Some(expected));
        assert_eq!(shown.fields[0]["preview"], expected);
        let program = [0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x2e, 0x4b, 0, 0, 0, 0, 0];
        let mut field = typed("arg2.program", "sock_fprog", object, &program);
        field.arg = Some(2);
        let shown = view(&call_with(
            317,
            "seccomp",
            [1, 0, 0x4c_2000, 0, 0, 0],
            field,
        ));
        let expected = "00 00 00 00 00 00 00 00 40 2e 4b 00 00 00 00 00";
        assert_eq!(shown.arguments[2].data.as_deref(), Some(expected));
        assert_eq!(shown.fields[0]["preview"], expected);
        assert!(!shown.info.contains('"'), "{}", shown.info);
    }

    #[test]
    fn captured_data_replaces_the_address() {
        let mut call = super::super::tests::openat(3);
        call.entry.as_mut().unwrap().fields = vec![FieldSummary {
            arg: Some(1),
            object_id: 9,
            key: "arg1.path".into(),
            layout: String::new(),
            logical_len: Some(5),
            captured_len: 5,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: b"/tmp\0".to_vec(),
            raw_path: None,
            ranges: vec![(0, 5)],
            recapture: None,
            encoding: None,
        }];
        let shown = view(&call);
        assert!(shown.fallbacks.is_empty(), "{:?}", shown.fallbacks);
        assert!(shown.warnings.is_empty());
    }
}
