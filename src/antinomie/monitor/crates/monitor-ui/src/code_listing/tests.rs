// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::table_sort::testing;

#[test]
fn lines_read_as_a_count_a_single_line_or_not_counted() {
    assert_eq!(lines_text(Some(7)), "7 lines");
    assert_eq!(lines_text(Some(1)), "1 line");
    assert_eq!(lines_text(Some(0)), "0 lines");
    assert_eq!(lines_text(None), "– lines");
    let function = Function {
        name: "_start",
        address: 0x401c20,
        lines: Some(12),
    };
    assert_eq!(detail_text(&function), "0x401c20 · 12 lines");
}

#[test]
fn the_sidebar_lists_each_function_with_its_lines_and_reports_a_click() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let functions = [
        Function {
            name: "_start",
            address: 0x1000,
            lines: Some(12),
        },
        Function {
            name: "main",
            address: 0x2000,
            lines: None,
        },
    ];
    let clicked = std::cell::Cell::new(None);
    let mut show = |ui: &mut egui::Ui| {
        if let Some(position) = function_list(
            ui,
            "test",
            functions.len(),
            |i| functions[i],
            Some(0),
            |_, _| {},
        ) {
            clicked.set(Some(position));
        }
    };
    let texts: Vec<_> = testing::frame(&ctx, vec![], &mut show)
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    for expected in ["_start", "0x1000 · 12 lines", "main", "0x2000 · – lines"] {
        assert!(
            texts.iter().any(|text| text == expected),
            "{expected}: {texts:?}"
        );
    }
    testing::click(&ctx, "main", &mut show);
    assert_eq!(clicked.get(), Some(1));
}

#[test]
fn the_heading_counts_all_functions_or_those_a_filter_keeps() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let heading_after = |shown, total| {
        testing::frame(&ctx, vec![], &mut |ui: &mut egui::Ui| {
            heading(ui, shown, total)
        })
        .into_iter()
        .map(|(text, _)| text)
        .collect::<Vec<_>>()
    };
    assert!(heading_after(12, 12).contains(&"Functions · 12".to_owned()));
    assert!(heading_after(3, 12).contains(&"Functions · 3 / 12".to_owned()));
}

#[test]
fn instructions_color_calls_jumps_and_bad_bytes_apart_from_plain_ones() {
    assert_eq!(mnemonic_color("call"), theme::blue());
    assert_eq!(mnemonic_color("jne"), theme::warn());
    assert_eq!(mnemonic_color("ret"), theme::warn());
    assert_eq!(mnemonic_color("(bad)"), theme::error());
    assert_eq!(mnemonic_color("mov"), theme::text());
    let job = instruction("mov", "rax, rbx", &FontId::monospace(14.0));
    assert_eq!(job.text, "mov      rax, rbx");
}

#[test]
fn decompiled_lines_keep_keyword_string_and_comment_colors() {
    let font = FontId::monospace(14.0);
    let color = |line: &str, token: &str| {
        let job = highlight(line, &font);
        job.sections.iter().find_map(|section| {
            let text = &job.text[section.byte_range.clone()];
            if text == token {
                Some(section.format.color)
            } else {
                None
            }
        })
    };
    assert_eq!(color("    return 1;", "return"), Some(theme::error()));
    assert_eq!(color("    return 1;", "1"), Some(theme::warn()));
    assert_eq!(color("    int value;", "int"), Some(theme::blue()));
    assert_eq!(color("    call(\"hi\");", "\"hi\""), Some(theme::good()));
    let comment = highlight("    // stay", &font);
    assert_eq!(comment.sections.len(), 1);
    assert_eq!(comment.sections[0].format.color, theme::muted());
}
