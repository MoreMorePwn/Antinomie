// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::{EventSummary, FieldSummary, InvocationSummary};

const TABLE_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("name", "Displayed name"),
    FieldSpec::number("address", "Address"),
    FieldSpec::boolean("complete", "Completeness"),
    FieldSpec::tags("tag", "Annotation tags"),
];

#[test]
fn typed_tables_preserve_unsigned_addresses_missing_values_and_string_case() {
    let row = [
        ("name", RowValue::Text("Needs Review".into())),
        ("address", RowValue::Number(i128::from(u64::MAX))),
        ("complete", RowValue::Bool(false)),
        (
            "tag",
            RowValue::List(vec!["needs review".into(), "triaged".into()]),
        ),
    ];
    for filter in [
        "address == 0xffffffffffffffff",
        "address > 9223372036854775807",
        "complete == false",
        "!complete",
        "exists(complete)",
        "lower(name) == \"needs review\"",
        "tag == \"needs review\"",
        "tag != \"unknown\"",
        "tag in {\"unknown\", \"triaged\"}",
        "name contains \"Review\" and not missing(address)",
        "(address & 7) == 7",
        "address & 7 == 7",
    ] {
        let compiled = compile_table(filter, TABLE_FIELDS);
        assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
        assert!(compiled.keep_table(&row), "{filter}");
    }
    for filter in [
        "complete",
        "name == \"needs review\"",
        "tag != \"triaged\"",
        "name contains \"review\"",
    ] {
        assert!(
            !compile_table(filter, TABLE_FIELDS).keep_table(&row),
            "{filter}"
        );
    }
    let absent = [("name", RowValue::Missing), ("complete", RowValue::Missing)];
    for filter in ["name != \"unknown\"", "complete == false", "exists(name)"] {
        assert!(
            !compile_table(filter, TABLE_FIELDS).keep_table(&absent),
            "{filter}"
        );
    }
    assert!(compile_table("missing(name) && missing(complete)", TABLE_FIELDS).keep_table(&absent));
    for filter in [
        "typo == 2",
        "address contains 7",
        "name > 7",
        "complete == FALSE",
        "complete == 0",
        "lower(address) == 1",
        "name ==",
    ] {
        assert!(
            compile_table(filter, TABLE_FIELDS).error.is_some(),
            "{filter}"
        );
    }
}

#[test]
fn known_tag_completion_quotes_spaces_quotes_backslashes_and_unicode() {
    for tag in ["needs review", "a\"b", "a\\b", "révision", "and", "123"] {
        let source = "tag == ";
        let item = completions_with(source, source.len(), FilterScope::Record, &[tag.into()])
            .into_iter()
            .next()
            .expect("tag completion");
        let mut edited = source.to_owned();
        apply_completion(&mut edited, &item);
        let compiled = compile_record(&edited);
        assert!(compiled.error.is_none(), "{edited}: {:?}", compiled.error);
        assert!(
            compiled.keep_record(&RecordLabels {
                id: "record",
                name: "",
                path: "/tmp",
                tags: &[tag.into()]
            }),
            "{edited}"
        );
    }
    let text = "entry.id == \"é\" && tag == \"nee tail\" || entry.id == other";
    let caret = text.find("nee tail").unwrap() + 3;
    let item = completions_with(text, caret, FilterScope::Record, &["needs review".into()])
        .into_iter()
        .next()
        .expect("quoted completion");
    let mut edited = text.to_owned();
    apply_completion(&mut edited, &item);
    assert_eq!(
        edited,
        "entry.id == \"é\" && tag == \"needs review\" || entry.id == other"
    );
}

#[test]
fn completion_replaces_selection_and_does_not_offer_fields_as_values() {
    let text = "syscall.num == 9 && args.pr || tid == 2";
    let start = text.find("args.pr").unwrap();
    let end = start + 7;
    let item = completions_fields(
        text,
        end,
        &fields_for(FilterScope::Syscall),
        &[],
        Some((start, end)),
    )
    .into_iter()
    .find(|item| item.insert == "args.prot")
    .expect("selection completion");
    let mut edited = text.to_owned();
    apply_completion(&mut edited, &item);
    assert_eq!(edited, "syscall.num == 9 && args.prot || tid == 2");
    assert!(completions("syscall.num == ", 15, FilterScope::Syscall).is_empty());
    assert!(completions("syscall.num ex", 14, FilterScope::Syscall)
        .iter()
        .all(|item| !item.insert.starts_with("exists")));
}

#[test]
fn incomplete_table_drafts_keep_the_last_applied_filter() {
    let ctx = egui::Context::default();
    let row = [("address", RowValue::Number(9))];
    for (draft, expected) in [
        ("address == 9", true),
        ("address ==", true),
        ("address == 10", false),
        ("address == 10 &&", false),
        ("", true),
    ] {
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let compiled = applied_table(ui, draft, TABLE_FIELDS, "retention");
                assert!(compiled.keep_table(&row) == expected, "{draft}");
            });
        });
    }
}

#[test]
fn oversized_recursive_expressions_are_rejected_before_parser_recursion() {
    for source in [
        format!("{}name{}", "(".repeat(65), ")".repeat(65)),
        format!("{}name", "!".repeat(257)),
        (0..258)
            .map(|_| "name == \"x\"")
            .collect::<Vec<_>>()
            .join(" || "),
        format!("name == \"{}\"", "x".repeat(65 * 1024)),
    ] {
        let query = compile_table(&source, TABLE_FIELDS);
        assert!(query.error.is_some(), "large query was accepted");
    }
    let source = "name == \"x\"";
    assert!(compile_table(source, TABLE_FIELDS).error.is_none());
}

#[test]
fn help_lists_schema_argument_names() {
    assert!(guide_has("args.filename"));
    assert!(guide_has("execve"));
    assert!(guide_has("http.request.method"));
    assert!(guide_has("dns.qry.name"));
}

fn call(nr: u64, name: &str, args: [u64; 6]) -> InvocationSummary {
    InvocationSummary {
        stream_id: 1,
        task_cookie: 4,
        call_id: 1,
        entry: Some(EventSummary {
            root_task_cookie: 4,
            stream_id: 1,
            task_cookie: 4,
            call_id: 1,
            event_seq: 1,
            phase: 1,
            syscall_nr: nr,
            syscall_name: name.into(),
            pid: 9,
            tid: 9,
            cpu: 0,
            timestamp_ns: 0,
            args: Some(args),
            result: Some(3),
            complete: true,
            issues: Vec::new(),
            fields: Vec::new(),
        }),
        exit: None,
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: Vec::new(),
    }
}

#[test]
fn call_id_matches_only_that_invocation() {
    let one = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    assert_eq!(one.call_id, 1);
    assert!(compile_note("call.id == 5").error.is_none());
    assert!(matches("call.id == 1", &one).unwrap());
    assert!(matches("call_id == 1", &one).unwrap());
    let mut other = one.clone();
    other.call_id = 2;
    assert!(!matches("call.id == 1", &other).unwrap());
    assert!(!matches("call_id == 1", &other).unwrap());
}

#[test]
fn comparisons_combine_syscall_number_and_named_argument() {
    let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    assert!(matches("syscall.num == 9 && args.fd < 3", &mmap).unwrap());
    assert!(!matches("syscall.num == 9 && args.fd < 2", &mmap).unwrap());
    assert!(matches("syscall.name == mmap", &mmap).unwrap());
    assert!(matches("mmap", &mmap).unwrap());
    assert!(matches("args.prot == 7", &mmap).unwrap());
}

#[test]
fn syscall_aliases_are_registered_and_resolve_schema_argument_spellings() {
    let mmap = call(9, "mmap", [0x1234, 4096, 7, 0, 2, 0]);
    for filter in [
        "syscall.number == 9",
        "syscall == mmap",
        "task.cookie == 4",
        "call_id == 1",
        "args.addr == 4660",
        "args.address == 4660",
        "args.len == 4096",
        "args.length == 4096",
        "args.prot == 7",
        "args.protection == 7",
    ] {
        assert!(matches(filter, &mmap).unwrap(), "{filter}");
    }
    let read = call(0, "read", [0, 0x4321, 10, 0, 0, 0]);
    for filter in ["args.buf == 17185", "args.buffer == 17185"] {
        assert!(matches(filter, &read).unwrap(), "{filter}");
    }
}

#[test]
fn generated_captured_members_validate_complete_values_and_missing_ranges() {
    let mut invocation = call(437, "openat2", [u64::MAX - 99, 0x1000, 0x2000, 24, 0, 0]);
    let mut preview = Vec::new();
    for value in [7u64, 0o700, 0x1234] {
        preview.extend(value.to_le_bytes());
    }
    invocation
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(FieldSummary {
            arg: None,
            object_id: 1,
            key: "arg2.how".into(),
            layout: "linux-6.12.94/x86_64/open_how".into(),
            logical_len: Some(24),
            captured_len: 24,
            status: None,
            capture_error: 0,
            complete: true,
            preview,
            raw_path: None,
            ranges: vec![(0, 24)],
            recapture: None,
            encoding: None,
        });
    assert!(matches("args.how.flags == 7 && args.how.mode == 448 && args.how.resolve == 4660 && args.how.complete == true", &invocation).unwrap());
    invocation.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 8), (16, 8)];
    assert!(matches("missing(args.how.mode) && args.how.flags == 7", &invocation).unwrap());
    let fields = syscall_fields();
    let indexed = antinomie_monitor_core::filter_members::registry()
        .iter()
        .find(|member| {
            member.name.contains("[0].")
                && member.kind == antinomie_monitor_core::filter_members::MemberKind::Integer
        })
        .expect("generated array member");
    let expression = format!("missing({})", indexed.name);
    assert!(compile_note(&expression).error.is_none(), "{expression}");
    assert!(fields.iter().any(|field| field.name == indexed.name));
    assert!(compile_note("args.how.invented_member == 0")
        .error
        .is_some());
}

#[test]
fn process_provenance_requires_committed_exec_and_never_guesses_identity() {
    let mut invocation = call(59, "execve", [0x1000, 0x2000, 0, 0, 0, 0]);
    invocation.entry.as_mut().unwrap().result = None;
    for (key, value) in [
        ("arg0.path", b"/bin/example\0".as_slice()),
        ("arg1.argv[1]", b"second\0".as_slice()),
        ("arg1.argv[0]", b"first\0".as_slice()),
    ] {
        invocation
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(FieldSummary {
                arg: None,
                object_id: 1,
                key: key.into(),
                layout: String::new(),
                logical_len: Some(value.len() as u64),
                captured_len: value.len() as u64,
                status: None,
                capture_error: 0,
                complete: true,
                preview: value.to_vec(),
                raw_path: None,
                ranges: vec![(0, value.len() as u64)],
                recapture: None,
                encoding: None,
            });
    }
    assert!(matches("missing(process.exe) && missing(process.argv)", &invocation).unwrap());
    let mut exit = invocation.entry.clone().unwrap();
    exit.phase = 2;
    exit.result = Some(-2);
    invocation.exit = Some(exit);
    assert!(matches("missing(process.exe)", &invocation).unwrap());
    invocation.exit.as_mut().unwrap().result = Some(0);
    assert!(matches("process.exe == \"/bin/example\" && process.argv == \"first\" && process.argv == \"second\"", &invocation).unwrap());
    assert!(matches("missing(process.ppid) && missing(process.parent_cookie) && missing(process.uid) && missing(process.gid) && missing(process.comm) && missing(process.state)", &invocation).unwrap());
    invocation.task_exit = invocation.exit.clone();
    assert!(matches("process.state == exited", &invocation).unwrap());
}

#[test]
fn ret_uses_exit_outcome_when_entry_result_is_absent() {
    let mut paired = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    paired.entry.as_mut().unwrap().result = None;
    let mut exit = paired.entry.clone().unwrap();
    exit.phase = 2;
    exit.event_seq = 2;
    exit.result = Some(7);
    paired.exit = Some(exit);
    assert!(trace::representative(&paired).unwrap().result.is_none());
    for filter in ["ret == 7", "result == 7", "syscall.ret == 7"] {
        assert!(
            matches(filter, &paired).unwrap(),
            "{filter} should use the exit result"
        );
    }
    paired.entry.as_mut().unwrap().result = Some(3);
    paired.exit.as_mut().unwrap().result = None;
    assert!(matches(
        "missing(syscall.success) && missing(syscall.errno) && missing(ret)",
        &paired
    )
    .unwrap());
}

#[test]
fn tag_does_not_match_path_text_stored_only_in_info() {
    let mut row = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
    let path = b"/tmp/example\0";
    let captured = path.len() as u64;
    row.entry.as_mut().unwrap().fields.push(FieldSummary {
        arg: None,
        object_id: 1,
        key: "path".into(),
        layout: String::new(),
        logical_len: Some(captured),
        captured_len: captured,
        status: None,
        capture_error: 0,
        complete: true,
        preview: path.to_vec(),
        raw_path: None,
        ranges: vec![(0, captured)],
        recapture: None,
        encoding: None,
    });
    let info = trace::info(&row);
    assert!(info.contains("/tmp"), "{info}");
    assert!(!matches(r#"tag contains "tmp""#, &row).unwrap());
    assert!(!matches(r#"tags contains "tmp""#, &row).unwrap());
    assert!(matches(r#"info contains "tmp""#, &row).unwrap());
    assert!(matches(r#"args.path == "/tmp/example""#, &row).unwrap());
    assert!(matches("args.raw[0] == 4096", &row).unwrap());
    assert!(matches("args.0 == 4096", &row).unwrap());
    assert!(!matches(r#"args.path == "4096""#, &row).unwrap());
    row.entry.as_mut().unwrap().fields[0].preview = b" /tmp/spaces \0".to_vec();
    row.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 14)];
    row.entry.as_mut().unwrap().fields[0].captured_len = 14;
    row.entry.as_mut().unwrap().fields[0].logical_len = Some(14);
    assert!(matches(r#"args.path == " /tmp/spaces ""#, &row).unwrap());
    row.entry.as_mut().unwrap().fields[0].preview = vec![0];
    row.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 1)];
    row.entry.as_mut().unwrap().fields[0].captured_len = 1;
    row.entry.as_mut().unwrap().fields[0].logical_len = Some(1);
    assert!(matches(r#"exists(args.path) && args.path == """#, &row).unwrap());
}

#[test]
fn typo_in_dotted_field_is_a_compile_error() {
    let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    let compiled = compile_note("syscall.typo == 9");
    assert!(compiled.error.is_some());
    assert!(matches("syscall.typo == 9", &mmap).is_err());
}

#[test]
fn exists_set_mask_and_raw_slot() {
    let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    assert!(matches("exists ret", &mmap).unwrap());
    assert!(!matches("missing ret", &mmap).unwrap());
    assert!(matches("syscall.num in {9, 10}", &mmap).unwrap());
    assert!(!matches("syscall.num in {10, 11}", &mmap).unwrap());
    assert!(matches(r#"syscall.name in {"mmap", "open"}"#, &mmap).unwrap());
    assert!(matches("args.prot & 7 == 7", &mmap).unwrap());
    assert!(matches("args.prot & 7 != 1", &mmap).unwrap());
    assert!(!matches("args.prot & 7 == 1", &mmap).unwrap());
    assert!(matches("args.raw[4] == 2", &mmap).unwrap());
    assert!(matches("args.raw[0] == 0", &mmap).unwrap());
    assert!(matches("args.raw[5] == 0", &mmap).unwrap());
    assert!(matches("exists ret && syscall.num in {9, 10}", &mmap).unwrap());

    let mut zero = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    zero.entry.as_mut().unwrap().result = Some(0);
    assert!(matches("exists ret", &zero).unwrap());
    let mut absent = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
    absent.entry.as_mut().unwrap().result = None;
    assert!(!matches("exists ret", &absent).unwrap());
    assert!(matches("missing ret", &absent).unwrap());

    let mut tagged = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
    let path = b"/tmp/example\0";
    let captured = path.len() as u64;
    tagged.entry.as_mut().unwrap().fields.push(FieldSummary {
        arg: None,
        object_id: 1,
        key: "path".into(),
        layout: String::new(),
        logical_len: Some(captured),
        captured_len: captured,
        status: None,
        capture_error: 0,
        complete: true,
        preview: path.to_vec(),
        raw_path: None,
        ranges: vec![(0, captured)],
        recapture: None,
        encoding: None,
    });
    assert!(trace::info(&tagged).contains("/tmp"));
    assert!(!matches("exists tag", &tagged).unwrap());
    assert!(matches("missing tag", &tagged).unwrap());

    assert!(matches("syscall.num in {}", &mmap).is_err());
    assert!(matches("args.prot & -1 == 7", &mmap).is_err());
    assert!(matches("args.raw[6]", &mmap).is_err());
    assert!(matches("args.raw[6] == 0", &mmap).is_err());
    assert!(matches("args.raw[prot] == 7", &mmap).is_err());
}

#[test]
fn record_tags_come_from_annotations_not_from_the_path() {
    let labels = RecordLabels {
        id: "run-1",
        name: "sample",
        path: "/tmp/example",
        tags: &["review".into()],
    };
    let tagged = compile_record(r#"tag == "review""#);
    assert!(tagged.error.is_none());
    assert!(tagged.keep_record(&labels));
    assert!(!compile_record(r#"tag == "tmp""#).keep_record(&labels));
    assert!(!compile_record(r#"tag contains "tmp""#).keep_record(&labels));
    assert!(compile_record(r#"entry.path contains "tmp""#).keep_record(&labels));
    let untagged = RecordLabels {
        tags: &[],
        ..labels
    };
    assert!(!compile_record("exists tag").keep_record(&untagged));
    assert!(compile_record("missing tag").keep_record(&untagged));
    let invalid = compile_record("syscall.typo == 9");
    assert!(invalid.error.is_some());
    assert!(!invalid.keep_record(&labels));
}

#[test]
fn completions_keep_the_surrounding_clause_and_follow_the_registry() {
    let text = "syscall.num == 9 && args.pr";
    let items = completions(text, text.len(), FilterScope::Syscall);
    let prot = items
        .iter()
        .find(|item| item.insert == "args.prot")
        .expect("args.prot");
    let mut edited = text.to_owned();
    edited.replace_range(prot.start..prot.end, &prot.insert);
    assert_eq!(edited, "syscall.num == 9 && args.prot");
    let sysc = completions("sysc", 4, FilterScope::Syscall);
    let names: Vec<_> = sysc.iter().map(|item| item.insert.as_str()).collect();
    assert!(names.contains(&"syscall.name"), "{names:?}");
    assert!(names.contains(&"syscall.num"), "{names:?}");
    let method = completions("http.req", 8, FilterScope::Packet);
    assert!(method
        .iter()
        .any(|item| item.insert == "http.request.method"));
    assert!(method.iter().any(|item| item.insert == "http.request.uri"));
    let operators = completions("syscall.num ", 12, FilterScope::Syscall);
    assert!(operators.iter().any(|item| item.insert.contains("==")));
    assert!(operators.iter().any(|item| item.insert.contains("<=")));
    let inside = "info contains \"exa";
    assert!(completions(inside, inside.len(), FilterScope::Syscall).is_empty());
    let text = "syscall.num == 9 && args.prot";
    let caret = text.find("args.pr").unwrap() + "args.pr".len();
    let prot = completions(text, caret, FilterScope::Syscall)
        .into_iter()
        .find(|item| item.insert == "args.prot")
        .expect("whole token");
    let mut edited = text.to_owned();
    let next = apply_completion(&mut edited, &prot);
    assert_eq!(edited, "syscall.num == 9 && args.prot");
    assert_eq!(next, edited.len());
    let unicode = "info contains \"é\" && args.pr";
    let byte_caret = unicode.find("args.pr").unwrap() + "args.pr".len();
    let char_caret = char_index(unicode, byte_caret);
    assert_ne!(char_caret, byte_caret);
    assert_eq!(byte_index(unicode, char_caret), byte_caret);
    let prot = completions(
        unicode,
        byte_index(unicode, char_caret),
        FilterScope::Syscall,
    )
    .into_iter()
    .find(|item| item.insert == "args.prot")
    .expect("unicode caret");
    let mut edited = unicode.to_owned();
    apply_completion(&mut edited, &prot);
    assert_eq!(edited, "info contains \"é\" && args.prot");
    let presence = completions("ex", 2, FilterScope::Syscall);
    assert!(presence.iter().any(|item| item.insert == "exists "));
    assert!(completions("syscall.num ex", 14, FilterScope::Syscall)
        .iter()
        .all(|item| !item.insert.contains("exists")));
    let tags = completions_with("tag == mal", 10, FilterScope::Record, &["malware".into()]);
    assert!(tags.iter().any(|item| item.insert == "malware"));
}

#[test]
#[ignore = "native X11 filter popup; stays open long enough to cover a 30s refresh"]
fn native_filter_autocomplete() {
    use std::time::{Duration, Instant};
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct App {
        syscall: String,
        history: String,
        packet: String,
        frames: u64,
        started: Instant,
        deadline: Instant,
        focused: bool,
    }
    impl eframe::App for App {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            self.frames += 1;
            let elapsed = self.started.elapsed().as_secs();
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label(format!("refresh {elapsed}s · frame {}", self.frames));
                ui.label("Syscall filter");
                let syscall = crate::query::filter_edit(
                    ui,
                    &mut self.syscall,
                    "Filter syscalls",
                    ui.available_width(),
                    FilterScope::Syscall,
                );
                ui.label("Run history filter");
                let _ = crate::query::filter_edit(
                    ui,
                    &mut self.history,
                    "Filter runs",
                    ui.available_width(),
                    FilterScope::Record,
                );
                ui.label("Packet filter");
                let _ = crate::query::filter_edit(
                    ui,
                    &mut self.packet,
                    "Filter packets",
                    ui.available_width(),
                    FilterScope::Packet,
                );
                if !self.focused {
                    syscall.request_focus();
                    self.focused = true;
                }
            });
            let _ = std::fs::write(
                "/tmp/antinomie-filter-refresh",
                format!("{elapsed} {}\n", self.frames),
            );
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let wide = std::env::var_os("ANTINOMIE_FILTER_QA_WIDE").is_some();
    let font = std::env::var("ANTINOMIE_FILTER_QA_FONT")
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .unwrap_or(if wide { 16.0 } else { 24.0 });
    let seconds = std::env::var("ANTINOMIE_FILTER_QA_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(35)
        .clamp(1, 90);
    eframe::run_native(
        "Antinomie Filter QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size(if wide {
                    [1100.0, 720.0]
                } else {
                    [420.0, 760.0]
                })
                .with_position([80.0, 60.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::text_size(&cc.egui_ctx, font);
            Ok(Box::new(App {
                syscall: "syscall.num == 9 && args.pr".into(),
                history: "entry.na".into(),
                packet: "tcp.f".into(),
                frames: 0,
                started: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(seconds),
                focused: false,
            }))
        }),
    )
    .unwrap();
}

/// Runs one filter-editor frame at a fixed time and returns the completion
/// list's scroll offset (`None` while no popup is open).
fn filter_frame(ctx: &egui::Context, text: &mut String, events: Vec<egui::Event>) -> Option<f32> {
    let mut raw = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(600.0, 600.0),
        )),
        events,
        ..Default::default()
    };
    let frame = ctx.data_mut(|data| {
        let frame: &mut u32 = data.get_temp_mut_or_default(egui::Id::new("test-frame"));
        *frame += 1;
        *frame
    });
    raw.time = Some(f64::from(frame) * 0.05);
    let mut offset = None;
    let _ = ctx.run(raw, |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let response = filter_edit(ui, text, "Filter", 300.0, FilterScope::Syscall);
            if !response.has_focus() {
                response.request_focus();
            }
            let id = ui.id().with(("filter-edit", "Filter")).with("offset");
            offset = ui.data(|data| data.get_temp::<f32>(id));
        });
    });
    offset
}

#[test]
fn completion_list_keeps_the_scroll_position_the_user_chose() {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        filter_frame(&ctx, &mut text, Vec::new());
    }
    // Hover the popup (just below the editor) and wheel down.
    let wheel = vec![
        egui::Event::PointerMoved(egui::pos2(60.0, 80.0)),
        egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, -400.0),
            modifiers: egui::Modifiers::NONE,
        },
    ];
    filter_frame(&ctx, &mut text, wheel);
    let mut settled = 0.0;
    for _ in 0..20 {
        settled = filter_frame(&ctx, &mut text, Vec::new()).expect("popup is open");
    }
    assert!(settled > 5.0, "wheel scrolled the list down: {settled}");
    for _ in 0..10 {
        let offset = filter_frame(&ctx, &mut text, Vec::new()).expect("popup is open");
        assert_eq!(offset, settled, "list jumped back by itself");
    }
}

/// The texts and colors of one frame's text shapes.
fn shown_texts(output: &egui::FullOutput) -> Vec<(String, egui::Color32)> {
    fn collect(shape: &egui::Shape, texts: &mut Vec<(String, egui::Color32)>) {
        match shape {
            egui::Shape::Text(text) => {
                let color = text
                    .galley
                    .job
                    .sections
                    .first()
                    .map_or(egui::Color32::PLACEHOLDER, |section| section.format.color);
                texts.push((text.galley.text().to_owned(), color));
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, texts)),
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut texts);
    }
    texts
}

#[test]
fn empty_filter_boxes_show_a_muted_filter_e_g_placeholder() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut text = String::new();
    let mut table = String::new();
    let output = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            filter_edit(
                ui,
                &mut text,
                "syscall == openat",
                300.0,
                FilterScope::Syscall,
            );
            filter_edit_fields(ui, &mut table, "name == nginx", 300.0, TABLE_FIELDS, &[]);
        });
    });
    let shown = shown_texts(&output);
    for placeholder in ["filter e.g. syscall == openat", "filter e.g. name == nginx"] {
        let (_, color) = shown
            .iter()
            .find(|(text, _)| text == placeholder)
            .unwrap_or_else(|| panic!("{placeholder} missing from {shown:?}"));
        assert_eq!(*color, crate::theme::hint());
        assert_ne!(*color, crate::theme::muted());
    }
    assert!(compile_note("syscall == openat").error.is_none());
}
