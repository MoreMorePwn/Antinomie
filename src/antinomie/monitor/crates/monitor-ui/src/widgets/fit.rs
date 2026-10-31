// SPDX-License-Identifier: GPL-3.0-only
//! Text that must fit a width without losing its end: a path keeps its first
//! folder and its file name, and the middle becomes an ellipsis.
use eframe::egui::{self, FontId};

/// `text` as it is when it fits `width`, else its start and end around an
/// ellipsis, as long as `width` allows (`font` is the font it is drawn in).
pub fn fit_middle(ui: &egui::Ui, text: &str, font: &FontId, width: f32) -> String {
    let measure = |candidate: &str| {
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(candidate.to_owned(), font.clone(), egui::Color32::WHITE)
                .size()
                .x
        })
    };
    let chars: Vec<char> = text.chars().collect();
    if measure(text) <= width {
        return text.to_owned();
    }
    // Keep as many characters as fit, split 1:2 between the start and the
    // end, because the end of a path (the file name) says the most.
    let build = |kept: usize| {
        let head = kept / 3;
        let tail = kept - head;
        let start: String = chars[..head].iter().collect();
        let end: String = chars[chars.len() - tail..].iter().collect();
        format!("{start}...{end}")
    };
    let (mut low, mut high) = (0usize, chars.len());
    while low < high {
        let middle = (low + high).div_ceil(2);
        if measure(&build(middle)) <= width {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    build(low)
}
