// SPDX-License-Identifier: GPL-3.0-only
//! The Export report dialog, and the Summary's ATT&CK list against the export.
//! The builder's own tests are `antinomie_triage::report_export`'s.
use super::*;
use antinomie_triage::report_export::fixtures::{fixture, have_tshark, job, read};

fn frame(
    ctx: &egui::Context,
    view: &mut TriageView,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 1400.0),
            )),
            events,
            time: Some(time),
            ..Default::default()
        },
        |root| {
            let ctx = &root.ctx().clone();
            view.show_report_dialog(ctx)
        },
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
    position(&out, "Defang indicators in HTML, PDF and Markdown");

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

/// The Summary on screen and the export list the same techniques: the ones the
/// behaviour rules cite (here the ransom note, T1486) and the ones a detection
/// engine cites (here a Sigma rule, T1036), each with its source.
#[test]
fn the_summary_and_the_export_agree_on_the_attack_techniques() {
    use antinomie_monitor_core::analysis::detection::{
        Engine, Finding as Match, Identity, Report as Detected, State,
    };
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let scan_job = job(&temp, &pcap, Choices::default());
    let mut scan = scan_archive_query(
        &temp.directory,
        Some(&pcap),
        false,
        &Arc::new(AtomicBool::new(false)),
        &scan_job.request,
    )
    .unwrap();
    let note = |dir: &str| {
        super::super::rules::tests::support::open_write(1, &format!("{dir}/README_DECRYPT.txt"), 3)
    };
    scan.findings = super::super::rules::tests::support::run(vec![
        note("/home/user/a"),
        note("/home/user/b"),
        note("/home/user/c"),
    ])
    .rows;
    let mut sigma = Detected::empty(
        Engine::Sigma,
        Identity {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run".into(),
            root_cookie: 55,
        },
    );
    sigma.state = State::Complete;
    sigma.findings = vec![Match {
        rule_id: "masq".into(),
        title: "Masquerading".into(),
        severity: "medium".into(),
        source: "s0".into(),
        license: "MIT".into(),
        author: "A".into(),
        mitre: vec!["T1036".into()],
        count: 2,
        evidence: vec![],
        events: vec![],
        details: String::new(),
        rule_text: String::new(),
    }];
    let mut view = TriageView::default();
    view.detection.results[2] = Some(Ok(sigma));
    // What the digest stores for the export to read back.
    let stored = super::super::digest::detections(&view.detection.results);
    antinomie_monitor_core::run_digest::RunDigest::update(&temp.directory, |digest| {
        digest.detections = stored;
    })
    .unwrap();
    let mut exported = build::build(&scan, &scan_job)
        .unwrap()
        .report
        .attack
        .unwrap();
    // The export adds its links; the techniques themselves are the same.
    for technique in &mut exported {
        technique.rule_refs.clear();
    }
    view.scan = Some(scan);
    let shown = view.attack_list().0.to_vec();
    assert_eq!(shown, exported);
    let ids: Vec<&str> = shown.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"T1486") && ids.contains(&"T1036"), "{ids:?}");
    let masq = shown.iter().find(|t| t.id == "T1036").unwrap();
    assert_eq!(masq.rules, ["Sigma: Masquerading"]);
}
