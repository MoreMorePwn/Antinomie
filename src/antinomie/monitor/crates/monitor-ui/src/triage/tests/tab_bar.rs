// SPDX-License-Identifier: GPL-3.0-only
//! The sub-tab row: the Export report button never covers a tab or its
//! count, at the window widths the app is used at.
use super::layout::{context, view};
use super::*;
use crate::app::tests::texts;
use antinomie_triage::summary::indicators;

/// The texts on the tab row at `width` (left to right), then the Export
/// report button; `None` when the row has no room for the button.
fn row(width: f32, section: Section) -> Option<Vec<(String, egui::Rect)>> {
    let ctx = context();
    let (_temp, mut view) = view(section);
    view.last_refresh = Some(Instant::now());
    // The IOC tab carries its count and the matched one beside it.
    view.scan.as_mut().unwrap().ioc = Some(std::sync::Arc::new(
        crate::triage::ioc_scan::IocScan::for_tests(indicators::tests::sample()),
    ));
    let mut out = egui::FullOutput::default();
    for time in 0..4 {
        out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 900.0),
                )),
                time: Some(f64::from(time) * 0.02),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    view.show(
                        ui,
                        TriageInput {
                            vm_id: Some("vm"),
                            boot_id: Some("boot"),
                            run_id: Some("run"),
                            ..TriageInput::empty()
                        },
                    );
                });
            },
        );
    }
    let shown = texts(&out);
    let export = shown
        .iter()
        .find(|(text, _)| text.starts_with("Export report"))?
        .clone();
    let line = export.1.center().y;
    let mut row: Vec<_> = shown
        .into_iter()
        .filter(|(text, rect)| {
            !text.starts_with("Export report") && (rect.center().y - line).abs() < 8.0
        })
        .collect();
    row.sort_by(|a, b| a.1.min.x.total_cmp(&b.1.min.x));
    row.push(export);
    Some(row)
}

#[test]
fn export_report_does_not_overlap_the_tabs_or_their_counts() {
    for section in [Section::Ioc, Section::Process, Section::Bpf] {
        for width in (0..)
            .map(|n| 600.0 + 10.0 * n as f32)
            .take_while(|w| *w <= 1920.0)
        {
            let Some(row) = row(width, section) else {
                continue;
            };
            let (export, rest) = row.split_last().unwrap();
            assert!(
                rest.iter().any(|(text, _)| text.starts_with("IOC")),
                "the IOC tab is on the row at {width}: {row:?}"
            );
            for (text, rect) in rest {
                assert!(
                    rect.right() <= export.1.left() + 0.5,
                    "{width} wide: {text:?} reaches {} but Export report starts at {}: {row:?}",
                    rect.right(),
                    export.1.left()
                );
            }
        }
    }
}
