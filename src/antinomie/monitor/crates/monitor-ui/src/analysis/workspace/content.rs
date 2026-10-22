// SPDX-License-Identifier: GPL-3.0-only
//! The Content tab: the retained specimen read one page at a time and shown
//! as a hex dump, text or a byte literal. Reading is a report action; this
//! view only asks for the page it shows.
use super::*;
use crate::analysis::row_menu::preview_matches;
use antinomie_monitor_core::ANALYSIS_PREVIEW_MAX_SIZE;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Hex,
    Text,
    CArray,
    Python,
    Base64,
    HexString,
}

impl Format {
    const ALL: [Self; 6] = [
        Self::Hex,
        Self::Text,
        Self::CArray,
        Self::Python,
        Self::Base64,
        Self::HexString,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex dump",
            Self::Text => "Text",
            Self::CArray => "C array",
            Self::Python => "Python bytes",
            Self::Base64 => "Base64",
            Self::HexString => "Hex string",
        }
    }
}

/// Smallest and largest Content text size, in points.
const MIN_TEXT_PX: f32 = 8.0;
const MAX_TEXT_PX: f32 = 32.0;

#[derive(Default)]
pub(in crate::analysis) struct ContentState {
    offset: u64,
    format: Format,
    /// The page last asked for while this tab was shown.
    requested: Option<(u64, usize)>,
    go_to: String,
    /// Content text size in points. None follows the interface monospace size.
    text_px: Option<f32>,
}

impl ContentState {
    /// Show the page that starts at `offset` next time the tab opens.
    pub(super) fn go_to(&mut self, offset: u64) {
        self.offset = offset;
        self.requested = None;
    }

    /// Another tab shares the specimen preview; ask again on return.
    pub(super) fn leave(&mut self) {
        self.requested = None;
    }
}

pub(super) fn show(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut ContentState,
    preview: Option<&Result<AnalysisSpecimenPage, String>>,
) -> Option<ReportAction> {
    let Some(total) = report.specimen_len.filter(|len| *len > 0) else {
        ui.label("This report retained no specimen content.");
        return None;
    };
    let page = ANALYSIS_PREVIEW_MAX_SIZE as u64;
    state.offset = state.offset.min(total - 1);
    ui.horizontal_wrapped(|ui| {
        let last = (total - 1) / page * page;
        let mut target = None;
        for (icon, hover, enabled, offset) in [
            (
                egui_phosphor::regular::CARET_DOUBLE_LEFT,
                "First page",
                state.offset > 0,
                0,
            ),
            (
                egui_phosphor::regular::CARET_LEFT,
                "Previous page",
                state.offset > 0,
                state.offset.saturating_sub(page),
            ),
            (
                egui_phosphor::regular::CARET_RIGHT,
                "Next page",
                state.offset + page < total,
                state.offset + page,
            ),
            (
                egui_phosphor::regular::CARET_DOUBLE_RIGHT,
                "Last page",
                state.offset < last,
                last,
            ),
        ] {
            if ui
                .add_enabled(enabled, egui::Button::new(icon))
                .on_hover_text(hover)
                .clicked()
            {
                target = Some(offset);
            }
        }
        let field = ui.add(
            egui::TextEdit::singleline(&mut state.go_to)
                .hint_text(crate::theme::hint_text("Offset, e.g. 0x1f00"))
                .desired_width(190.0),
        );
        let entered = field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        if ui.button("Go").clicked() || entered {
            match parse_offset(&state.go_to) {
                Some(offset) if offset < total => target = Some(offset),
                _ => {
                    state.go_to = format!("beyond 0x{:x}", total - 1);
                }
            }
        }
        if let Some(offset) = target {
            state.go_to(offset);
        }
        egui::ComboBox::from_id_salt("analysis-content-format")
            .selected_text(state.format.label())
            .show_ui(ui, |ui| {
                for format in Format::ALL {
                    ui.selectable_value(&mut state.format, format, format.label());
                }
            });
        zoom_buttons(ui, state);
    });
    let data_len = usize::try_from((total - state.offset).min(page)).unwrap_or(0);
    let mut action = None;
    if state.requested != Some((state.offset, data_len)) {
        state.requested = Some((state.offset, data_len));
        action = Some(ReportAction::ReadSpecimen {
            report_id: report.id.clone(),
            offset: state.offset,
            data_len,
        });
    }
    ui.horizontal_wrapped(|ui| {
        ui.monospace(format!(
            "0x{:x}–0x{:x} of {}",
            state.offset,
            state.offset + data_len as u64 - 1,
            crate::values::file_size(total)
        ));
    });
    match preview {
        Some(Ok(page)) if preview_matches(page, report, state.offset, data_len) => {
            let text = render(state.format, page.offset, &page.data);
            if ui
                .button(format!("{} Copy page", egui_phosphor::regular::COPY))
                .on_hover_text(format!(
                    "Copy these {} as {}",
                    crate::values::file_size(page.data.len() as u64),
                    state.format.label()
                ))
                .clicked()
            {
                ui.ctx().copy_text(text.clone());
            }
            egui::ScrollArea::both()
                .id_salt("analysis-content")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let size = zoomed_text_px(ui, state);
                    let wrap = !matches!(state.format, Format::Hex);
                    ui.add(
                        egui::TextEdit::multiline(&mut text.as_str())
                            .code_editor()
                            .font(egui::FontId::monospace(size))
                            .desired_width(if wrap {
                                ui.available_width()
                            } else {
                                f32::INFINITY
                            })
                            .desired_rows(24),
                    );
                });
        }
        Some(Err(reason)) => {
            crate::activity::error(ui, reason);
        }
        _ => {
            crate::theme::loading(ui, "Reading specimen content…");
        }
    }
    action
}

fn resolved_text_px(ui: &egui::Ui, state: &ContentState) -> f32 {
    match state.text_px {
        Some(size) => size.clamp(MIN_TEXT_PX, MAX_TEXT_PX),
        None => egui::TextStyle::Monospace.resolve(ui.style()).size,
    }
}

fn zoom_buttons(ui: &mut egui::Ui, state: &mut ContentState) {
    let size = resolved_text_px(ui, state);
    if ui
        .add_enabled(
            size.round() > MIN_TEXT_PX,
            egui::Button::new(egui_phosphor::regular::MAGNIFYING_GLASS_MINUS),
        )
        .on_hover_text("Smaller content text")
        .clicked()
    {
        state.text_px = Some((size.round() - 1.0).max(MIN_TEXT_PX));
    }
    let size = resolved_text_px(ui, state);
    if ui
        .add_enabled(
            size.round() < MAX_TEXT_PX,
            egui::Button::new(egui_phosphor::regular::MAGNIFYING_GLASS_PLUS),
        )
        .on_hover_text("Larger content text")
        .clicked()
    {
        state.text_px = Some((size.round() + 1.0).min(MAX_TEXT_PX));
    }
    let shown = resolved_text_px(ui, state).round();
    ui.weak(format!("{shown:.0} px"))
        .on_hover_text("Content text size. Ctrl+wheel over the content zooms too.");
}

/// Ctrl+wheel (egui's zoom gesture) over the page changes its text size.
fn zoomed_text_px(ui: &mut egui::Ui, state: &mut ContentState) -> f32 {
    let size = resolved_text_px(ui, state);
    if !ui.rect_contains_pointer(ui.clip_rect()) {
        return size;
    }
    let zoom = ui.input(|input| input.zoom_delta());
    if (zoom - 1.0).abs() <= f32::EPSILON {
        return size;
    }
    let size = (size * zoom).clamp(MIN_TEXT_PX, MAX_TEXT_PX);
    state.text_px = Some(size);
    size
}

/// A hexadecimal (`0x…`) or decimal offset.
fn parse_offset(text: &str) -> Option<u64> {
    let text = text.trim().replace('_', "");
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn render(format: Format, offset: u64, data: &[u8]) -> String {
    let mut out = String::new();
    match format {
        Format::Hex => {
            for (index, chunk) in data.chunks(16).enumerate() {
                let hex: Vec<_> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
                let (left, right) = hex.split_at(hex.len().min(8));
                let text: String = chunk
                    .iter()
                    .map(|&byte| {
                        if byte.is_ascii_graphic() || byte == b' ' {
                            char::from(byte)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let _ = writeln!(
                    out,
                    "{:08x}  {:<23}  {:<23}  |{text}|",
                    offset + index as u64 * 16,
                    left.join(" "),
                    right.join(" ")
                );
            }
        }
        Format::Text => {
            for &byte in data {
                match byte {
                    b'\n' | b'\t' => out.push(char::from(byte)),
                    b'\r' => out.push_str("\\r"),
                    0x20..=0x7e => out.push(char::from(byte)),
                    _ => {
                        let _ = write!(out, "\\x{byte:02x}");
                    }
                }
            }
        }
        Format::CArray => {
            let _ = writeln!(
                out,
                "/* 0x{offset:x}, {} */",
                crate::values::file_size(data.len() as u64)
            );
            out.push_str("unsigned char data[] = {\n");
            for chunk in data.chunks(12) {
                let line: Vec<_> = chunk.iter().map(|byte| format!("0x{byte:02x}")).collect();
                let _ = writeln!(out, "    {},", line.join(", "));
            }
            out.push_str("};\n");
        }
        Format::Python => {
            let _ = writeln!(
                out,
                "# 0x{offset:x}, {}",
                crate::values::file_size(data.len() as u64)
            );
            out.push_str("data = (\n");
            for chunk in data.chunks(16) {
                let line: String = chunk.iter().map(|byte| format!("\\x{byte:02x}")).collect();
                let _ = writeln!(out, "    b\"{line}\"");
            }
            out.push_str(")\n");
        }
        Format::Base64 => {
            let encoded = base64(data);
            for line in encoded.as_bytes().chunks(76) {
                out.push_str(std::str::from_utf8(line).unwrap_or_default());
                out.push('\n');
            }
        }
        Format::HexString => {
            for byte in data {
                let _ = write!(out, "{byte:02x}");
            }
        }
    }
    out
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let value = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(
                    ALPHABET[(value >> (18 - 6 * index) & 63) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_renders_the_page_it_was_given() {
        let data = b"\x7fELF\x02\x01\x01\x00hello\nworld\r!";
        let hex = render(Format::Hex, 0x40, data);
        assert!(
            hex.starts_with(
                "00000040  7f 45 4c 46 02 01 01 00  68 65 6c 6c 6f 0a 77 6f  |.ELF....hello.wo|"
            ),
            "{hex}"
        );
        assert!(hex
            .lines()
            .nth(1)
            .unwrap()
            .starts_with("00000050  72 6c 64 0d 21"));
        assert_eq!(render(Format::Text, 0, b"a\tb\x00\r\n"), "a\tb\\x00\\r\n");
        assert!(render(Format::CArray, 0, data).contains("0x7f, 0x45, 0x4c, 0x46,"));
        assert!(render(Format::Python, 0, b"\x00A").contains("b\"\\x00\\x41\""));
        assert_eq!(render(Format::HexString, 0, b"\x00\xff"), "00ff");
        for (input, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), encoded);
        }
        assert_eq!(parse_offset(" 0x1F00 "), Some(0x1f00));
        assert_eq!(parse_offset("4096"), Some(4096));
        assert_eq!(parse_offset("zz"), None);
    }

    #[test]
    fn the_tab_asks_once_for_its_page_and_again_after_another_tab() {
        let report = AnalysisReport {
            id: "report".into(),
            state: AnalysisState::Complete,
            source_path: "/tmp/sample".into(),
            specimen_sha256: None,
            specimen_len: Some(10_000),
            reason: None,
            sections: Vec::new(),
        };
        let ctx = egui::Context::default();
        let mut state = ContentState::default();
        state.go_to(5000);
        let frame = |state: &mut ContentState| {
            let mut action = None;
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| action = show(ui, &report, state, None));
            });
            action
        };
        assert_eq!(
            frame(&mut state),
            Some(ReportAction::ReadSpecimen {
                report_id: "report".into(),
                offset: 5000,
                data_len: 4096
            })
        );
        assert_eq!(frame(&mut state), None);
        state.leave();
        assert!(frame(&mut state).is_some());
        state.go_to(9000);
        assert_eq!(
            frame(&mut state),
            Some(ReportAction::ReadSpecimen {
                report_id: "report".into(),
                offset: 9000,
                data_len: 1000
            })
        );
    }

    fn sample_page() -> (AnalysisReport, Result<AnalysisSpecimenPage, String>) {
        let data = b"Hello, content zoom!\n".to_vec();
        let report = AnalysisReport {
            id: "report".into(),
            state: AnalysisState::Complete,
            source_path: "/tmp/sample".into(),
            specimen_sha256: None,
            specimen_len: Some(data.len() as u64),
            reason: None,
            sections: Vec::new(),
        };
        let preview = Ok(AnalysisSpecimenPage {
            report_id: report.id.clone(),
            offset: 0,
            total_len: data.len() as u64,
            data,
        });
        (report, preview)
    }

    fn paint(
        ctx: &egui::Context,
        report: &AnalysisReport,
        state: &mut ContentState,
        preview: &Result<AnalysisSpecimenPage, String>,
        time: f64,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1100.0, 800.0),
                )),
                time: Some(time),
                predicted_dt: 1.0 / 60.0,
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let _ = show(ui, report, state, Some(preview));
                });
            },
        )
    }

    fn shapes(output: &egui::FullOutput) -> Vec<(String, egui::Rect, f32)> {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Rect, f32)>) {
            match shape {
                egui::epaint::Shape::Text(text) => {
                    let size = text
                        .galley
                        .job
                        .sections
                        .first()
                        .map(|section| section.format.font_id.size)
                        .unwrap_or(0.0);
                    out.push((
                        text.galley.text().to_owned(),
                        egui::Rect::from_min_size(text.pos, text.galley.size()),
                        size,
                    ));
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut found);
        }
        found
    }

    fn content_font(output: &egui::FullOutput) -> f32 {
        shapes(output)
            .into_iter()
            .find(|(text, _, _)| text.starts_with("00000000"))
            .map(|(_, _, size)| size)
            .expect("hex dump")
    }

    fn glyph(output: &egui::FullOutput, text: &str) -> egui::Pos2 {
        shapes(output)
            .into_iter()
            .find(|(found, _, _)| found == text)
            .map(|(_, rect, _)| rect.center())
            .unwrap_or_else(|| panic!("missing {text}"))
    }

    fn hex_point(output: &egui::FullOutput) -> egui::Pos2 {
        let (_, rect, _) = shapes(output)
            .into_iter()
            .find(|(text, _, _)| text.starts_with("00000000"))
            .expect("hex dump");
        egui::pos2(rect.left() + 8.0, rect.top() + 4.0)
    }

    fn click(
        ctx: &egui::Context,
        report: &AnalysisReport,
        state: &mut ContentState,
        preview: &Result<AnalysisSpecimenPage, String>,
        mut time: f64,
        pos: egui::Pos2,
    ) -> (f64, egui::FullOutput) {
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let mut output = egui::FullOutput::default();
        for events in [
            vec![egui::Event::PointerMoved(pos)],
            vec![button(true)],
            vec![button(false)],
            Vec::new(),
        ] {
            output = paint(ctx, report, state, preview, time, events);
            time += 1.0 / 60.0;
        }
        (time, output)
    }

    fn wheel(dy: f32, ctrl: bool) -> egui::Event {
        egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, dy),
            modifiers: egui::Modifiers {
                ctrl,
                ..Default::default()
            },
        }
    }

    fn settle(
        ctx: &egui::Context,
        report: &AnalysisReport,
        state: &mut ContentState,
        preview: &Result<AnalysisSpecimenPage, String>,
        mut time: f64,
        pos: egui::Pos2,
        first: Vec<egui::Event>,
    ) -> (f64, egui::FullOutput) {
        let mut output = egui::FullOutput::default();
        for frame in 0..45 {
            let mut events = vec![egui::Event::PointerMoved(pos)];
            if frame == 0 {
                events.extend(first.clone());
            }
            output = paint(ctx, report, state, preview, time, events);
            time += 1.0 / 60.0;
        }
        (time, output)
    }

    #[test]
    fn content_text_size_follows_buttons_and_ctrl_wheel() {
        let (report, preview) = sample_page();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut state = ContentState::default();
        let mut time = 0.0;
        let mut output = egui::FullOutput::default();
        for _ in 0..2 {
            output = paint(&ctx, &report, &mut state, &preview, time, Vec::new());
            time += 1.0 / 60.0;
        }
        let initial = content_font(&output);
        let plus = glyph(&output, egui_phosphor::regular::MAGNIFYING_GLASS_PLUS);
        let clicked = click(&ctx, &report, &mut state, &preview, time, plus);
        time = clicked.0;
        output = clicked.1;
        let larger = content_font(&output);
        assert!(
            (larger - (initial + 1.0)).abs() < 0.01,
            "plus button {initial} -> {larger}"
        );
        let minus = glyph(&output, egui_phosphor::regular::MAGNIFYING_GLASS_MINUS);
        let clicked = click(&ctx, &report, &mut state, &preview, time, minus);
        time = clicked.0;
        output = clicked.1;
        let restored = content_font(&output);
        assert!(
            (restored - initial).abs() < 0.01,
            "minus button {larger} -> {restored}, expected {initial}"
        );

        state.text_px = Some(MAX_TEXT_PX);
        output = paint(&ctx, &report, &mut state, &preview, time, Vec::new());
        time += 1.0 / 60.0;
        let plus = glyph(&output, egui_phosphor::regular::MAGNIFYING_GLASS_PLUS);
        let clicked = click(&ctx, &report, &mut state, &preview, time, plus);
        time = clicked.0;
        output = clicked.1;
        assert!((content_font(&output) - MAX_TEXT_PX).abs() < 0.01);
        state.text_px = Some(MIN_TEXT_PX);
        output = paint(&ctx, &report, &mut state, &preview, time, Vec::new());
        time += 1.0 / 60.0;
        let minus = glyph(&output, egui_phosphor::regular::MAGNIFYING_GLASS_MINUS);
        let clicked = click(&ctx, &report, &mut state, &preview, time, minus);
        time = clicked.0;
        output = clicked.1;
        assert!((content_font(&output) - MIN_TEXT_PX).abs() < 0.01);

        state.text_px = None;
        output = paint(&ctx, &report, &mut state, &preview, time, Vec::new());
        time += 1.0 / 60.0;
        let base = content_font(&output);
        let pos = hex_point(&output);
        let settled = settle(
            &ctx,
            &report,
            &mut state,
            &preview,
            time,
            pos,
            vec![wheel(80.0, true)],
        );
        time = settled.0;
        output = settled.1;
        let zoomed = content_font(&output);
        assert!(zoomed > base + 1.0, "ctrl+wheel in {base} -> {zoomed}");
        let pos = hex_point(&output);
        let settled = settle(
            &ctx,
            &report,
            &mut state,
            &preview,
            time,
            pos,
            vec![wheel(80.0, false)],
        );
        time = settled.0;
        output = settled.1;
        let scrolled = content_font(&output);
        assert!(
            (scrolled - zoomed).abs() < 0.05,
            "wheel without ctrl {zoomed} -> {scrolled}"
        );
        let pos = hex_point(&output);
        output = settle(
            &ctx,
            &report,
            &mut state,
            &preview,
            time,
            pos,
            vec![wheel(-80.0, true)],
        )
        .1;
        let smaller = content_font(&output);
        assert!(
            smaller < zoomed - 0.5,
            "ctrl+wheel out {zoomed} -> {smaller}"
        );
    }
}
