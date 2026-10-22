// SPDX-License-Identifier: GPL-3.0-only
//! A triage table keeps the colors of the theme it was built in only until
//! the next paint: switching theme restyles rows that are already indexed.
use super::*;
use crate::theme::{Theme, ValueKind};

const SIZE: egui::Vec2 = egui::vec2(900.0, 400.0);

fn rows() -> Vec<Vec<Cell>> {
    vec![
        vec![
            table::cell("rundll", theme::text(), false),
            table::cell("blocked", theme::error(), false),
            table::cell("slow", theme::warn(), true),
            table::cell("seen", theme::muted(), false),
            table::cell("done", theme::good(), false),
        ],
        vec![
            table::cell("hidden", theme::warn(), false),
            table::cell("0x7f", theme::value(ValueKind::Pointer), true),
            table::cell("12", theme::value(ValueKind::Number), true),
            table::cell("name", theme::value(ValueKind::Name), false),
            table::cell("tree", theme::tree_branch(2), false),
        ],
    ]
}

const HEADERS: [&str; 5] = ["A", "B", "C", "D", "E"];

fn text_color(output: &egui::FullOutput, label: &str) -> Option<egui::Color32> {
    fn find(shape: &egui::Shape, label: &str) -> Option<egui::Color32> {
        match shape {
            egui::Shape::Text(text) if text.galley.text() == label => Some(
                text.galley
                    .job
                    .sections
                    .first()
                    .map_or(text.fallback_color, |section| section.format.color),
            ),
            egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, label)),
            _ => None,
        }
    }
    output
        .shapes
        .iter()
        .find_map(|shape| find(&shape.shape, label))
}

fn colors(ctx: &egui::Context, rows: &[Vec<Cell>]) -> Vec<(String, egui::Color32)> {
    let mut output = egui::FullOutput::default();
    for frame in 0..3 {
        output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(f64::from(frame) * 0.1),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    table::table_rows(ui, "theme-switch", &HEADERS, rows)
                });
            },
        );
    }
    rows.iter()
        .flatten()
        .map(|cell| {
            let color = text_color(&output, &cell.text)
                .unwrap_or_else(|| panic!("{:?} was not painted", cell.text));
            (cell.text.clone(), color)
        })
        .collect()
}

#[test]
fn rows_built_in_one_theme_are_painted_in_the_palette_now_active() {
    for (from, to) in [
        (Theme::Dark, Theme::Light),
        (Theme::Light, Theme::Blue),
        (Theme::Blue, Theme::Dark),
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::apply_theme(&ctx, from);
        let rows = rows();
        let built = colors(&ctx, &rows);
        theme::apply_theme(&ctx, to);
        let switched = colors(&ctx, &rows);
        // The same rows built from scratch in the new theme.
        let fresh = colors(&ctx, &self::rows());
        assert_eq!(switched, fresh, "{from:?} -> {to:?}");
        assert_ne!(built, switched, "{from:?} and {to:?} differ");
    }
}

#[test]
fn a_color_outside_the_palette_is_left_as_it_is() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let odd = egui::Color32::from_rgb(1, 2, 3);
    let cell = table::cell("odd", odd, false);
    theme::apply_theme(&ctx, Theme::Light);
    assert_eq!(cell.color(), odd);
}

#[test]
fn every_slot_of_a_palette_translates_to_the_same_slot_of_another() {
    for (from, to) in [(Theme::Dark, Theme::Light), (Theme::Light, Theme::Blue)] {
        let (a, b) = (from.palette(), to.palette());
        for (old, new) in [
            (a.text, b.text),
            (a.muted, b.muted),
            (a.error, b.error),
            (a.warn, b.warn),
            (a.good, b.good),
            (a.number, b.number),
            (a.pointer, b.pointer),
        ] {
            assert_eq!(theme::translate(old, from, to), new, "{from:?} -> {to:?}");
        }
        assert_eq!(theme::translate(a.text, from, from), a.text);
    }
}

#[test]
fn packet_and_syscall_tints_are_read_from_the_active_palette_when_drawn() {
    // These tables hold a kind (PacketColor, SyscallGroup), not a color.
    let ctx = egui::Context::default();
    theme::install(&ctx);
    theme::apply_theme(&ctx, Theme::Dark);
    let dark = (
        theme::PacketColor::Tcp.tint(),
        theme::syscall_tint(antinomie_monitor_core::syscall_groups::SyscallGroup::File),
    );
    theme::apply_theme(&ctx, Theme::Light);
    let light = (
        theme::PacketColor::Tcp.tint(),
        theme::syscall_tint(antinomie_monitor_core::syscall_groups::SyscallGroup::File),
    );
    assert_ne!(dark.0, light.0);
    assert_ne!(dark.1, light.1);
    assert_eq!(light.0, Theme::Light.palette().packet[8]);
}
