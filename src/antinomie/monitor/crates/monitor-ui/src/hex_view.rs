// SPDX-License-Identifier: GPL-3.0-only
//! One row of a hex dump, shared by the process-core viewer and the debugger:
//! sixteen bytes as hex, then as printable characters. A byte the viewer has
//! not got is shown for what it is: `??` for one that cannot be read, `··` for
//! one still being fetched, blank past the end of the range.
use eframe::egui::{self, RichText};

/// Bytes per row.
pub(crate) const ROW_LEN: u64 = 16;

/// What is known about one byte of a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cell {
    Byte(u8),
    /// Cannot be read (unmapped, or not captured).
    Unavailable,
    /// Not fetched yet.
    Loading,
    /// Beyond the range being shown.
    Outside,
}

/// The text of the row starting at `address`: `cell` says what each byte is.
pub(crate) fn row_text(address: u64, mut cell: impl FnMut(u64) -> Cell) -> String {
    let mut line = format!("{address:016x}  ");
    let mut ascii = String::new();
    for column in 0..ROW_LEN {
        let Some(at) = address.checked_add(column) else {
            break;
        };
        match cell(at) {
            Cell::Outside => line.push_str("   "),
            Cell::Byte(byte) => {
                line.push_str(&format!("{byte:02x} "));
                ascii.push(if byte.is_ascii_graphic() || byte == b' ' {
                    char::from(byte)
                } else {
                    '.'
                });
            }
            Cell::Unavailable => {
                line.push_str("?? ");
                ascii.push('?');
            }
            Cell::Loading => {
                line.push_str("·· ");
                ascii.push(' ');
            }
        }
    }
    line.push_str(&format!(" {ascii}"));
    line
}

/// Paint one row as the viewers do.
pub(crate) fn paint_row(ui: &mut egui::Ui, text: String) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(text).monospace()).extend())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_show_bytes_gaps_and_the_end() {
        let row = row_text(0x1000, |at| match at - 0x1000 {
            0 => Cell::Byte(b'A'),
            1 => Cell::Byte(0),
            2 => Cell::Unavailable,
            3 => Cell::Loading,
            4..=5 => Cell::Byte(b' '),
            _ => Cell::Outside,
        });
        assert_eq!(
            row,
            format!(
                "{:016x}  41 00 ?? ·· 20 20 {} A.?   ",
                0x1000,
                " ".repeat(30)
            )
        );
    }

    #[test]
    fn a_row_at_the_top_of_the_address_space_stops_there() {
        let row = row_text(u64::MAX - 1, |_| Cell::Byte(0x41));
        assert!(row.ends_with(" AA"), "{row}");
    }
}
