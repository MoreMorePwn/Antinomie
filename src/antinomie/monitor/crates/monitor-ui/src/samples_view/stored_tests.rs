// SPDX-License-Identifier: GPL-3.0-only
//! The Downloaded table of the Malware samples window.
use super::*;

fn stored(count: usize) -> Vec<StoredSample> {
    (0..count)
        .map(|at| StoredSample {
            info: SampleInfo {
                sha256_hash: format!("{at:0>64}"),
                file_name: format!("sample-{at:02}.bin"),
                ..SampleInfo::default()
            },
            source: "MalwareBazaar".into(),
            downloaded_ms: at as u64,
            pushes: Vec::new(),
        })
        .collect()
}

fn rows_shown(count: usize, largest_height: f32) -> usize {
    let data = std::env::temp_dir();
    let cx = SamplesContext {
        data_dir: &data,
        curl: Path::new("curl"),
        running: true,
        vm_name: None,
        vm_arch: None,
        network_warning: None,
        font_size: 14.0,
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let samples = stored(count);
    let mut view = SamplesView::default();
    let mut shown = 0;
    for _ in 0..3 {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1100.0, 1200.0),
                )),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let row =
                        theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
                    let list = tables::stored_list_height(
                        row,
                        ui.spacing().item_spacing.y,
                        largest_height,
                    );
                    view.stored_list(ui, &cx, &samples, list);
                });
            },
        );
        shown = crate::app::tests::texts(&output)
            .iter()
            .filter(|(text, _)| text.starts_with("sample-"))
            .count();
    }
    shown
}

#[test]
fn the_downloaded_table_shows_at_least_five_rows() {
    assert_eq!(rows_shown(12, 700.0), 5);
}

#[test]
fn the_downloaded_table_grows_with_a_taller_window() {
    assert!(rows_shown(30, 900.0) > 5);
    assert!(rows_shown(30, 1200.0) > rows_shown(30, 900.0));
}
