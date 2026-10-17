// SPDX-License-Identifier: MIT
//! The Content tab: the retained specimen read one page at a time and shown
//! as a hex dump, text or a byte literal. Reading is a report action; this
//! view only asks for the page it shows.
use super::*;
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

#[derive(Default)]
pub(in crate::analysis) struct ContentState {
    offset: u64,
    format: Format,
    /// The page last asked for while this tab was shown.
    requested: Option<(u64, usize)>,
    go_to: String,
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
                .hint_text("Offset, e.g. 0x1f00")
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
            "0x{:x}–0x{:x} of {total} octets",
            state.offset,
            state.offset + data_len as u64 - 1
        ));
    });
    match preview {
        Some(Ok(page)) if preview_matches(page, report, state.offset, data_len) => {
            let text = render(state.format, page.offset, &page.data);
            if ui
                .button(format!("{} Copy page", egui_phosphor::regular::COPY))
                .on_hover_text(format!(
                    "Copy these {} octets as {}",
                    page.data.len(),
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
                    let wrap = !matches!(state.format, Format::Hex);
                    ui.add(
                        egui::TextEdit::multiline(&mut text.as_str())
                            .code_editor()
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
            ui.colored_label(crate::theme::error(), reason);
        }
        _ => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading specimen content…");
            });
        }
    }
    action
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
            let _ = writeln!(out, "/* 0x{offset:x}, {} octets */", data.len());
            out.push_str("unsigned char data[] = {\n");
            for chunk in data.chunks(12) {
                let line: Vec<_> = chunk.iter().map(|byte| format!("0x{byte:02x}")).collect();
                let _ = writeln!(out, "    {},", line.join(", "));
            }
            out.push_str("};\n");
        }
        Format::Python => {
            let _ = writeln!(out, "# 0x{offset:x}, {} octets", data.len());
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
}
