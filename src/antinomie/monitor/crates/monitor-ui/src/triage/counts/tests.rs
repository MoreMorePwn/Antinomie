// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn section_totals_ignore_preview_pages_and_filters_and_keep_missing_network_distinct() {
    let files = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
    super::super::tests::write_rwx_calls(&mut raw, 0..3);
    raw.sync_all().unwrap();
    let mut scan = scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
    scan.findings.clear();
    scan.counts.opened = 1234;
    scan.counts.reads = 5678;
    scan.counts.changed = 9012;
    scan.counts.http = 3456;
    scan.counts.dns = 7890;
    let mut view = TriageView::default();
    view.scan_request.filters[0] = "finding.kind == \"never\"".into();
    view.scan_request.offsets[0] = 2000;
    view.scan = Some(scan);
    for (metric, count) in [
        (Metric::Findings, 3),
        (Metric::Opened, 1234),
        (Metric::Reads, 5678),
        (Metric::Changed, 9012),
    ] {
        assert_eq!(view.section_count(metric), Count::Ready(count));
    }
    assert_eq!(view.section_count(Metric::Dns), Count::Unavailable);
    view.scan.as_mut().unwrap().network_counts = Some((50_000, 123, 456));
    for (metric, count) in [
        (Metric::Ips, 123),
        (Metric::Hosts, 456),
        (Metric::Http, 3456),
        (Metric::Dns, 7890),
    ] {
        assert_eq!(view.section_count(metric), Count::Ready(count));
    }
    let (_tx, rx) = mpsc::channel();
    view.scan_rx = Some(rx);
    assert_eq!(view.section_count(Metric::Opened), Count::Pending);
    view.scan_rx = None;
    view.scan = None;
    assert_eq!(view.section_count(Metric::Opened), Count::Unavailable);
}

#[test]
fn badge_states_are_grouped_muted_or_accented_and_wrap_in_both_themes() {
    for light in [false, true] {
        for (width, font) in [(320.0, 24.0), (800.0, 16.0)] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::apply(&ctx, light);
            theme::text_size(&ctx, font);
            assert_eq!(Count::Ready(1234).label(), "1,234");
            assert_eq!(Count::Ready(0).tone(true), Tone::Neutral);
            assert_eq!(Count::Ready(1).tone(true), Tone::Accent);
            assert_eq!(Count::Ready(1).tone(false), Tone::Plain);
            for _ in 0..3 {
                let mut bounds = egui::Rect::NOTHING;
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 600.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                for (title, count) in [
                                    ("Suspicious activity", Count::Ready(1234)),
                                    ("Opened files", Count::Ready(0)),
                                    ("HTTP", Count::Pending),
                                    ("DNS", Count::Unavailable),
                                ] {
                                    tab(ui, false, title, count, true);
                                }
                            });
                            bounds = ui.min_rect();
                        });
                    },
                );
                assert!(bounds.right() <= width + 1.0, "{width}/{font}: {bounds:?}");
                let texts = crate::app::tests::texts(&output);
                for label in ["1,234", "0", "…", "—"] {
                    let (_, rect) = texts.iter().find(|(text, _)| text == label).unwrap();
                    assert!(rect.right() <= width + 2.0, "{width}: {label} {rect:?}");
                }
            }
        }
    }
}

#[test]
fn tab_badges_read_the_whole_run_counts() {
    let temp = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
    super::super::tests::write_rwx_calls(&mut raw, 0..1);
    raw.sync_all().unwrap();
    let mut scan = scan_archive(&temp.directory, None, false, &AtomicBool::new(false)).unwrap();
    for (at, count) in scan.counts.tabs.iter_mut().enumerate() {
        *count = 100 + at as u64;
    }
    let mut view = TriageView::default();
    view.scan = Some(scan);
    for tab in FileTab::ALL {
        if matches!(tab, FileTab::Opened | FileTab::Read | FileTab::Changed) {
            continue;
        }
        assert_eq!(
            view.section_count(Metric::File(tab)),
            Count::Ready(100 + tab.slot() as u64 - 8),
            "{}",
            tab.title()
        );
    }
    view.scan = None;
    assert_eq!(
        view.section_count(Metric::File(FileTab::Created)),
        Count::Unavailable
    );
    // Every operation category has exactly one tab, and every tab its own slot.
    let mut slots: Vec<_> = FileTab::ALL.iter().map(|tab| tab.slot()).collect();
    slots.sort();
    slots.dedup();
    assert_eq!(slots.len(), FileTab::ALL.len());
    assert!(FileTab::ALL.iter().all(|tab| tab.slot() < SLOTS));
}
