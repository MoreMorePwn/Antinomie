// SPDX-License-Identifier: GPL-3.0-only
//! The Suspicious activity table and the Details of a row: the default
//! columns, the tier chip and its meaning, the limited-confidence flag, the
//! sections in order and the links that leave the Details.
use super::layout::{
    click, context, details_output, draw, find, has, settle, tooltip_context, view,
};
use super::*;
use crate::app::tests::texts;
use crate::triage::rules::tests::support::{close, open_write, rows, run, write, Calls};

fn writes(path: &str) -> Calls {
    vec![open_write(1, path, 3), write(1, 3, b"x"), close(1, 3)]
}

/// The row of a rule from calls that write `path`.
fn row_for(path: &str, rule: &str) -> Finding {
    let out = run(vec![open_write(1, path, 3)]);
    rows(&out, rule)[0].clone()
}

/// The Suspicious activity tab of the fixture's run, with its own findings.
fn fixture_tab() -> (PacketSpool, TriageView) {
    let (temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Suspicious;
    (temp, view)
}

/// A Suspicious activity tab that shows `findings` and nothing else.
fn tab_with(findings: Vec<Finding>) -> (PacketSpool, TriageView) {
    let (temp, mut view) = fixture_tab();
    view.scan.as_mut().unwrap().findings = findings;
    (temp, view)
}

fn select(ctx: &egui::Context, row: &Finding) {
    let mut cells = row.cells.clone();
    cells[0].values.clone_from(&row.values);
    details::select(ctx, "triage-findings", rules::HEADERS, &cells);
}

#[test]
fn the_default_columns_are_the_eight_of_the_brief_in_order() {
    let ctx = context();
    let (_temp, mut view) = tab_with(vec![row_for("/etc/cron.d/job", "persistence.cron")]);
    let out = settle(&ctx, &mut view);
    let found: Vec<(f32, &str)> = [
        "Tier",
        "Behaviour",
        "Target",
        "Process",
        "ATT&CK",
        "Count",
        "Result",
        "When",
    ]
    .into_iter()
    .map(|title| (find(&out, title).min.x, title))
    .collect();
    let mut sorted = found.clone();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    assert_eq!(found, sorted, "left to right");
    for gone in ["Category", "Confidence", "Evidence", "Version", "Source"] {
        assert!(!has(&out, gone), "{gone} is not a default column");
    }
    for cell in [
        "Cron job installed",
        "/etc/cron.d/job",
        "T1053.003 Cron",
        "\u{d7}1",
        "succeeded",
        "H",
    ] {
        assert!(has(&out, cell), "{cell}: {:?}", texts(&out));
    }
}

#[test]
fn the_tier_chip_tooltip_gives_the_meaning_and_why() {
    let ctx = tooltip_context();
    let (_temp, mut view) = tab_with(vec![row_for("/etc/cron.d/job", "persistence.cron")]);
    let mut out = settle(&ctx, &mut view);
    let at = find(&out, "H").center();
    for step in 0..4 {
        out = draw(
            &ctx,
            &mut view,
            vec![egui::Event::PointerMoved(at)],
            1.0 + f64::from(step) * 0.1,
        );
    }
    let shown = texts(&out);
    let any = |needle: &str| shown.iter().any(|(text, _)| text.contains(needle));
    assert!(
        any("Something ordinary software essentially never does and that directly gives control, persistence or privilege. Look at these first."),
        "{shown:?}"
    );
    assert!(any("The rule's own tier (High)."));
}

#[test]
fn a_row_of_limited_confidence_wears_a_flag_with_the_reason() {
    let ctx = tooltip_context();
    let flag = egui_phosphor::regular::FLAG;
    let mut call = open_write(1, "/etc/cron.d/job", 3);
    call.exit.as_mut().unwrap().complete = false;
    let out = run(vec![call, write(1, 3, b"x"), close(1, 3)]);
    let limited = rows(&out, "persistence.cron")[0].clone();
    assert_eq!(
        limited.cells[rules::COL_TIER]
            .values
            .iter()
            .filter(|(key, _)| *key == rules::LIMITED)
            .count(),
        1
    );
    let (_temp, mut view) = tab_with(vec![limited]);
    let mut out = settle(&ctx, &mut view);
    assert!(has(&out, flag), "{:?}", texts(&out));
    let at = find(&out, flag).center();
    for step in 0..4 {
        out = draw(
            &ctx,
            &mut view,
            vec![egui::Event::PointerMoved(at)],
            1.0 + f64::from(step) * 0.1,
        );
    }
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text.contains("entry or exit record is incomplete")));
    // A full record has no flag.
    let (_temp, mut full) = tab_with(vec![row_for("/etc/cron.d/job", "persistence.cron")]);
    assert!(!has(&settle(&ctx, &mut full), flag));
}

#[test]
fn the_details_run_in_the_order_of_the_brief() {
    let ctx = context();
    let out = run(writes("/etc/profile"));
    let row = rows(&out, "persistence.shell_profile")[0].clone();
    let (_temp, mut view) = tab_with(vec![row.clone()]);
    select(&ctx, &row);
    details_output(&ctx, &mut view);
    let out = details_output(&ctx, &mut view);
    let order = [
        "What happened",
        "Why it matters",
        "Why this tier",
        "Evidence",
        "Related",
        "Rule facts",
    ];
    let heights: Vec<f32> = order.iter().map(|title| find(&out, title).min.y).collect();
    let mut sorted = heights.clone();
    sorted.sort_by(f32::total_cmp);
    assert_eq!(heights, sorted, "{order:?} top to bottom");
    // The header comes first: the tier, the title, the rule and its version.
    let header = find(&out, "Shell startup file changed").min.y;
    assert!(header < heights[0]);
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text.starts_with("persistence.shell_profile \u{b7} version ")));
    assert!(has(&out, "Medium") || has(&out, "High"));
    // The rule's description and the technique, by name.
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text.starts_with("A shell profile or rc file")));
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text.contains("T1546.004")));
    // The tier's meaning, and what lowers one.
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text.starts_with("Context lowers a tier by one")));
    // A sample call with its way to the Syscall Trace.
    assert!(has(&out, "Open in Syscall Trace"));
    // The folded fields come last.
    assert!(find(&out, "Observed fields").min.y > find(&out, "Rule facts").min.y);
}

#[test]
fn what_happened_is_one_sentence_with_process_target_count_time_and_result() {
    let row = row_for("/etc/cron.d/job", "persistence.cron");
    let sentence = finding_details::what_happened(
        "sshd (418 \u{b7} 418)",
        &row.values,
        "+1.2 s \u{2192} +9.8 s",
    );
    assert!(
        sentence.starts_with("sshd (418 \u{b7} 418): open"),
        "{sentence}"
    );
    assert!(sentence.contains("/etc/cron.d/job"));
    assert!(
        sentence.ends_with("Seen once, +1.2 s \u{2192} +9.8 s, succeeded."),
        "{sentence}"
    );
}

#[test]
fn the_samples_of_a_row_read_back_in_time_order() {
    let row = row_for("/etc/cron.d/job", "persistence.cron");
    let kept = finding_details::samples(&row.values);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].syscall, "open");
    assert!(kept[0].what.contains("/etc/cron.d/job"));
}

#[test]
fn a_target_that_is_an_address_is_recognised() {
    use std::net::IpAddr;
    let ip = |text: &str| text.parse::<IpAddr>().ok();
    assert_eq!(finding_details::endpoint("1.2.3.4:443"), ip("1.2.3.4"));
    assert_eq!(finding_details::endpoint("udp 0.0.0.0:53"), ip("0.0.0.0"));
    assert_eq!(finding_details::endpoint("[::1]:8080"), ip("::1"));
    assert_eq!(finding_details::endpoint("/etc/passwd"), None);
    assert_eq!(finding_details::endpoint("pid 418 attach"), None);
}

/// A finding of the fixture's scan, made to name `object` as its target.
fn finding_on(view: &TriageView, object: &str) -> Finding {
    let mut row = view.scan.as_ref().unwrap().findings[0].clone();
    for (key, value) in &mut row.values {
        if *key == "finding.object" {
            *value = RowValue::Text(object.into());
        }
    }
    row
}

fn click_text(ctx: &egui::Context, view: &mut TriageView, needle: &str) {
    let out = details_output(ctx, view);
    let at = texts(&out)
        .into_iter()
        .find(|(text, _)| text.contains(needle))
        .unwrap_or_else(|| panic!("{needle:?} not drawn in {:?}", texts(&out)))
        .1
        .center();
    for (n, pressed) in [true, false].into_iter().enumerate() {
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1500.0, 2600.0),
                )),
                events: vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                time: Some(10.0 + n as f64 * 0.05),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    view.details(ui);
                });
            },
        );
    }
}

#[test]
fn a_file_target_opens_its_history_in_files() {
    let ctx = context();
    let (_temp, mut view) = fixture_tab();
    let row = finding_on(&view, "/tmp/analysis-note.txt");
    select(&ctx, &row);
    click_text(&ctx, &mut view, ": open its history in Files");
    assert!(view.section == Section::Files);
    assert!(view.history_tab);
}

#[test]
fn an_address_target_opens_the_network_endpoints() {
    let ctx = context();
    let (_temp, mut view) = fixture_tab();
    let row = finding_on(&view, "203.0.113.9:443");
    select(&ctx, &row);
    click_text(&ctx, &mut view, ": open it in Network");
    assert!(view.section == Section::Network);
    assert!(view.new_tab == NewTab::Endpoints);
}

#[test]
fn the_process_link_opens_that_process_in_details() {
    let ctx = context();
    let (_temp, mut view) = fixture_tab();
    let row = view.scan.as_ref().unwrap().findings[0].clone();
    select(&ctx, &row);
    assert_eq!(
        details::selected_table(&ctx).as_deref(),
        Some("triage-findings")
    );
    click_text(&ctx, &mut view, ": open its details");
    assert_eq!(
        details::selected_table(&ctx).as_deref(),
        Some("triage-process")
    );
}

#[test]
fn a_click_on_the_process_cell_opens_that_process_in_details() {
    let ctx = context();
    let (_temp, mut view) = fixture_tab();
    let row = view.scan.as_ref().unwrap().findings[0].clone();
    let label = row.cells[rules::COL_PROCESS].text.clone();
    view.scan.as_mut().unwrap().findings = vec![row];
    let out = settle(&ctx, &mut view);
    click(&ctx, &mut view, find(&out, &label).center());
    settle(&ctx, &mut view);
    assert_eq!(
        details::selected_table(&ctx).as_deref(),
        Some("triage-process"),
        "{:?}",
        texts(&out)
    );
}

#[test]
fn other_findings_of_the_same_process_are_one_click_away() {
    let ctx = context();
    let (_temp, mut view) = fixture_tab();
    let first = view.scan.as_ref().unwrap().findings[0].clone();
    let mut second = first.clone();
    second.key.2 += 1000;
    for (key, value) in &mut second.values {
        if *key == "event.id" {
            *value = RowValue::Number(7777);
        }
    }
    view.scan.as_mut().unwrap().findings = vec![first.clone(), second];
    select(&ctx, &first);
    click_text(&ctx, &mut view, "other finding in this process");
    assert!(view.section == Section::Process);
    let pid = files::number(&first.values, "process.pid").unwrap();
    assert_eq!(view.filter_drafts[0], format!("process.pid == {pid}"));
}
