// SPDX-License-Identifier: GPL-3.0-only
use super::super::tests::{call, captured, http_pcap, path_call, write_rwx_calls};
use super::*;
use antinomie_monitor_core::report::bundle::{self, BundleInput};

fn have_tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// A recording with RWX mapping calls (findings, processes) and an HTTP
/// capture (URL, endpoint, domain indicators).
fn fixture() -> (PacketSpool, PathBuf) {
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let pcap = temp.directory.join("fixture.pcap");
    std::fs::write(&pcap, http_pcap()).unwrap();
    // One rule that matched, with the credit its licence asks to keep.
    antinomie_monitor_core::run_digest::RunDigest::update(&temp.directory, |digest| {
        digest.detections = Some(vec![antinomie_monitor_core::run_digest::DetectionHit {
            engine: "YARA".into(),
            rule_id: "fixture_rule".into(),
            title: "fixture_rule".into(),
            severity: "high".into(),
            count: 2,
            author: "Jane Rule".into(),
            license: "DRL 1.1".into(),
            source: "Example Pack".into(),
            reference: "https://example.org/rule".into(),
            ..Default::default()
        }]);
    })
    .unwrap();
    (temp, pcap)
}

fn job(temp: &PacketSpool, pcap: &Path, choices: Choices) -> Job {
    Job {
        archive: temp.directory.clone(),
        pcap: Some(pcap.to_path_buf()),
        request: ScanRequest {
            root_cookie: 55,
            run_finished: true,
            ..ScanRequest::default()
        },
        choices,
        run: report::RunInfo {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run-fixture-1".into(),
            started_ms: Some(1_792_000_000_000),
            finished: true,
        },
        sample: Some(report::SampleInfo {
            name: "fixture.elf".into(),
            sha256: "ab".repeat(32),
            size: Some(100),
        }),
        clock: None,
        data_dir: None,
        now_ms: 1_792_000_100_000,
        folder: temp.directory.join("report"),
    }
}

fn all_formats() -> Choices {
    Choices {
        formats: Format::ALL.to_vec(),
        bundle: true,
        ..Choices::default()
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn a_whole_run_exports_every_format_whatever_the_screen_filters_say() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let mut job = job(&temp, &pcap, all_formats());
    // The screen's filters and page must not shape the report.
    let mut screen = job.request.clone();
    screen.filters[0] = "finding.rule == \"nothing-matches-this\"".into();
    screen.offsets[0] = 1000;
    screen.file_visibility.hide_libraries = false;
    job.request = whole_run_request(&screen);
    let written = run_job(&job, &Arc::new(AtomicBool::new(false)), &|_| {}).unwrap();
    let path = |label: &str| {
        written
            .files
            .iter()
            .find(|(l, _)| l == label)
            .unwrap_or_else(|| panic!("{label} written"))
            .1
            .clone()
    };
    let json: serde_json::Value = serde_json::from_str(&read(&path("JSON"))).unwrap();
    assert_eq!(json["schema"], report::SCHEMA);
    assert!(
        !json["findings"]["rows"].as_array().unwrap().is_empty(),
        "findings of the whole run"
    );
    assert!(!json["processes"]["rows"].as_array().unwrap().is_empty());
    let urls = json["network"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "URLs")
        .unwrap();
    assert_eq!(urls["table"]["rows"].as_array().unwrap().len(), 1);
    assert!(json["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["kind"] == "url"));
    assert!(json["summary"]["counts"]["findings"].as_u64().unwrap() >= 1);
    assert_eq!(json["sample"]["sha256"], "ab".repeat(32));
    assert_eq!(json["detections"][0]["author"], "Jane Rule");
    assert_eq!(json["detections"][0]["license"], "DRL 1.1");
    assert_eq!(
        json["detections"][0]["reference"],
        "https://example.org/rule"
    );
    let html = read(&path("HTML"));
    assert!(html.contains("Jane Rule") && html.contains("DRL 1.1"));
    assert!(html.contains("<h2>Processes</h2>") && html.contains("example.com"));
    let pdf = std::fs::read(path("PDF")).unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    let misp: serde_json::Value = serde_json::from_str(&read(&path("MISP"))).unwrap();
    assert!(misp["Event"]["Attribute"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["type"] == "url"));
    assert!(read(&path("MISP")).contains("Jane Rule"));
    assert!(read(&path("STIX 2.1")).contains("Jane Rule"));
    let stix: serde_json::Value = serde_json::from_str(&read(&path("STIX 2.1"))).unwrap();
    assert_eq!(stix["type"], "bundle");

    // The bundle holds the capture, and every hash in it checks.
    let bundle = written.bundle.as_ref().expect("bundle");
    let listed = bundle::verify(&path("Evidence bundle")).unwrap();
    let capture = listed
        .iter()
        .find(|f| f.path == "capture/fixture.pcap")
        .unwrap();
    assert_eq!(
        capture.sha256,
        antinomie_monitor_core::storage::sha256_hex(&http_pcap())
    );
    assert!(
        bundle
            .skipped
            .iter()
            .any(|(what, _)| what == "custody export"),
        "no library: said so"
    );

    if let Ok(out) = std::env::var("ANTINOMIE_REPORT_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        for (_, from) in &written.files {
            std::fs::copy(from, Path::new(&out).join(from.file_name().unwrap())).unwrap();
        }
    }
}

#[test]
fn unchecked_sections_and_formats_are_left_out_and_defanging_touches_only_html_and_pdf() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let mut choices = Choices {
        formats: vec![Format::Html, Format::Json],
        defang: true,
        ..Choices::default()
    };
    choices.set(Part::Network, false);
    choices.set(Part::Files, false);
    let written = run_job(
        &job(&temp, &pcap, choices),
        &Arc::new(AtomicBool::new(false)),
        &|_| {},
    )
    .unwrap();
    assert_eq!(written.files.len(), 2);
    assert!(written.bundle.is_none());
    let json = read(&written.files.iter().find(|(l, _)| l == "JSON").unwrap().1);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value["network"].is_null() && value["files"].is_null());
    assert!(value["processes"].is_object());
    let html = read(&written.files.iter().find(|(l, _)| l == "HTML").unwrap().1);
    assert!(!html.contains(">Network<") && !html.contains(">Files<"));
    // The fixture's indicators: raw in the JSON, defanged in the HTML.
    assert!(json.contains("example.com"));
    assert!(html.contains("example[.]com") && !html.contains("example.com"));
    if let Ok(keep) = std::env::var("ANTINOMIE_REPORT_OUT") {
        let keep = Path::new(&keep).join("limited-defanged");
        std::fs::create_dir_all(&keep).unwrap();
        for (_, from) in &written.files {
            std::fs::copy(from, keep.join(from.file_name().unwrap())).unwrap();
        }
    }
}

fn operation(id: u64, nr: u64, name: &str, ret: i64, args: [u64; 6]) -> InvocationSummary {
    let mut row = call(1, nr, name, ret);
    row.call_id = id;
    row.entry.as_mut().unwrap().call_id = id;
    row.entry.as_mut().unwrap().args = Some(args);
    row.exit.as_mut().unwrap().call_id = id;
    row
}

fn stored_write(
    id: u64,
    fd: u64,
    offset: u64,
    bytes: &[u8],
    dir: &Path,
    name: &str,
) -> InvocationSummary {
    std::fs::write(dir.join("objects").join(name), bytes).unwrap();
    let size = bytes.len() as u64;
    let mut row = operation(id, 18, "pwrite64", size as i64, [fd, 0, size, offset, 0, 0]);
    let mut field = captured("arg1.data", "", b"");
    field.raw_path = Some(PathBuf::from(format!("objects/{name}")));
    field.logical_len = Some(size);
    field.ranges = vec![(0, size)];
    row.entry.as_mut().unwrap().fields.push(field);
    row
}

#[test]
fn dropped_files_are_hashed_listed_and_written_into_the_password_zip() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let dir = temp.directory.clone();
    std::fs::create_dir_all(dir.join("objects")).unwrap();
    let open = |id: u64, path: &str, fd: i64| {
        let mut row = path_call(1, 2, "open", fd, path);
        row.call_id = id;
        row.entry.as_mut().unwrap().call_id = id;
        row.exit.as_mut().unwrap().call_id = id;
        row.entry.as_mut().unwrap().args = Some([0, 0x41, 0, 0, 0, 0]);
        row
    };
    let calls = [
        open(2, "/tmp/dropped.sh", 4),
        stored_write(3, 4, 0, b"#!/bin/sh\n", &dir, "a.raw"),
        stored_write(4, 4, 10, b"id\n", &dir, "b.raw"),
        // Over the per-file cap: only the first 8 bytes are kept.
        open(5, "/tmp/big.bin", 5),
        stored_write(6, 5, 0, b"12345678", &dir, "c.raw"),
        stored_write(7, 5, 8, b"abcdefgh", &dir, "d.raw"),
    ];
    let mut index = files::FileIndex::default();
    index.set_write_limits(antinomie_monitor_core::file_writes::Limits {
        per_file: 13,
        per_run: 1 << 20,
    });
    let mut state = FdState::default();
    let cookies = task_cookies(&calls);
    for row in &calls {
        let event = trace::representative(row).unwrap();
        remember_cwd(&mut state, row, event);
        remember_open(&mut state, row, event);
        apply_dup(&mut state, row, event);
        forget_closed(&mut state, row, event);
        inherit_open_fds(&mut state, row, event, &cookies);
        index.observe(&state, row, event, Some(&dir));
    }
    let activity = index.finish_all().1;
    let scan_job = job(&temp, &pcap, all_formats());
    let mut scan = scan_archive_query(
        &dir,
        Some(&pcap),
        false,
        &Arc::new(AtomicBool::new(false)),
        &scan_job.request,
    )
    .unwrap();
    scan.file_activity = Arc::new(activity);
    let built = build::build(&scan, &scan_job).unwrap();
    let records = built.report.file_activity.as_ref().unwrap();
    let dropped = records
        .iter()
        .find(|r| r.path == "/tmp/dropped.sh")
        .unwrap();
    let want = antinomie_monitor_core::storage::sha256_hex(b"#!/bin/sh\nid\n");
    assert_eq!(dropped.reconstruction, "complete");
    assert_eq!(dropped.final_size, Some(13));
    assert_eq!(
        dropped.bundle_entry,
        format!("dropped-files.zip/{want}.bin")
    );
    let big = records.iter().find(|r| r.path == "/tmp/big.bin").unwrap();
    assert_eq!(big.reconstruction, "incomplete");
    assert!(big.bytes_not_captured > 0 && big.bundle_entry.is_empty());
    let input: BundleInput = built.bundle.unwrap();
    assert_eq!(input.dropped.len(), 1);
    assert!(input
        .skipped
        .iter()
        .any(|(path, why)| path == "/tmp/big.bin" && why.contains("no recorded value")));

    let out = dir.join("b.zip");
    let bundled = bundle::write(&out, &dir.join("i.tmp"), input).unwrap();
    assert_eq!(bundled.dropped[0].0, "/tmp/dropped.sh");
    bundle::verify(&out).unwrap();
    let got = bundle::open_dropped(&out, &format!("dropped-files.zip/{want}.bin")).unwrap();
    if let Ok(keep) = std::env::var("ANTINOMIE_REPORT_OUT") {
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::copy(&out, Path::new(&keep).join("dropped-bundle.zip")).unwrap();
    }
    assert_eq!(got, b"#!/bin/sh\nid\n");
}

/// One frame of the dialog at `time`, with `events`.
fn frame(
    ctx: &egui::Context,
    view: &mut TriageView,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 1400.0),
            )),
            events,
            time: Some(time),
            ..Default::default()
        },
        |ctx| view.show_report_dialog(ctx),
    )
}

fn click(ctx: &egui::Context, view: &mut TriageView, at: egui::Pos2, time: &mut f64) {
    for pressed in [true, false] {
        *time += 0.05;
        frame(
            ctx,
            view,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            *time,
        );
    }
}

fn position(out: &egui::FullOutput, text: &str) -> egui::Pos2 {
    let drawn = crate::app::tests::texts(out);
    drawn
        .iter()
        .find(|(shown, _)| shown == text)
        .unwrap_or_else(|| {
            panic!(
                "{text:?} is drawn among {:?}",
                drawn
                    .iter()
                    .map(|(t, r)| format!("{t}@{:?}", r.min))
                    .collect::<Vec<_>>()
            )
        })
        .1
        .center()
}

#[test]
fn the_dialog_lists_every_section_and_format_remembers_changes_and_exports() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut view = TriageView::default();
    view.scan_request.root_cookie = 55;
    view.scan_request.run_finished = true;
    let input = TriageInput {
        archive: Some(&temp.directory),
        pcap: Some(&pcap),
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run-ui-1"),
        run_finished: true,
        ..TriageInput::empty()
    };
    let folder = temp.directory.join("out");
    let choices = Choices {
        folder: folder.display().to_string(),
        ..Choices::default()
    };
    view.set_report_choices(choices.clone());
    assert!(view.take_report_choices().is_none(), "nothing changed yet");
    view.open_report(&input);
    let mut time = 0.0;
    let mut out = frame(&ctx, &mut view, vec![], time);
    // A new window sizes itself over its first frames.
    for _ in 0..12 {
        time += 0.05;
        out = frame(&ctx, &mut view, vec![], time);
    }
    for part in Part::ALL {
        position(&out, part.label());
    }
    for format in Format::ALL {
        position(&out, format.label());
    }
    position(&out, "Evidence bundle (.zip next to the report)");
    position(&out, "Defang indicators in HTML and PDF");

    // Unchecking a section and choosing the JSON format is remembered.
    click(
        &ctx,
        &mut view,
        position(&out, Part::Processes.label()),
        &mut time,
    );
    out = frame(&ctx, &mut view, vec![], time + 0.01);
    click(&ctx, &mut view, position(&out, "JSON"), &mut time);
    let kept = view
        .take_report_choices()
        .expect("a change is reported once");
    assert!(!kept.has(Part::Processes) && kept.writes(Format::Json) && kept.has(Part::Summary));
    assert!(view.take_report_choices().is_none());
    // The app hands the stored choices back on the next frame.
    view.set_report_choices(kept.clone());
    assert_eq!(view.report.choices, kept);

    // Export runs the worker and lists what it wrote.
    out = frame(&ctx, &mut view, vec![], time + 0.01);
    click(&ctx, &mut view, position(&out, "Export"), &mut time);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !matches!(view.report.state, State::Done(_) | State::Failed(_)) {
        assert!(Instant::now() < deadline, "the export finished");
        std::thread::sleep(Duration::from_millis(100));
        time += 0.1;
        frame(&ctx, &mut view, vec![], time);
    }
    let State::Done(written) = &view.report.state else {
        let State::Failed(error) = &view.report.state else {
            unreachable!()
        };
        panic!("export failed: {error}");
    };
    let names: Vec<String> = written
        .files
        .iter()
        .map(|(_, p)| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with(".html")) && names.iter().any(|n| n.ends_with(".pdf"))
    );
    assert!(names
        .iter()
        .any(|n| n.ends_with(".json") && !n.contains("misp")));
    let json_path = &written.files.iter().find(|(l, _)| l == "JSON").unwrap().1;
    let value: serde_json::Value = serde_json::from_str(&read(json_path)).unwrap();
    assert!(
        value["processes"].is_null(),
        "the unchecked section is absent"
    );
    assert!(value["findings"].is_object());
    assert!(json_path.starts_with(&folder));
    out = frame(&ctx, &mut view, vec![], time + 0.1);
    assert!(
        crate::app::tests::texts(&out)
            .iter()
            .any(|(t, _)| t.contains(".html")),
        "paths are listed"
    );
}
