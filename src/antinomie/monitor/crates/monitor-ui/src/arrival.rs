// SPDX-License-Identifier: GPL-3.0-only
//! Tells a list window that it was just opened or focused, so it can read its
//! list again without a click on Refresh (Network captures, Memory dumps,
//! Core dumps). A window arrives the first time it is drawn, when it is drawn
//! after frames in which it was not (another tab was showing), and when the
//! app's own window gets the keyboard focus back.
use eframe::egui;

#[derive(Default)]
pub(crate) struct Arrival {
    /// The frame this window was drawn in last.
    last_frame: Option<u64>,
    /// Whether the app window had the focus when it was drawn last.
    focused: Option<bool>,
}

impl Arrival {
    /// Call once per frame the window is drawn; true when it just arrived.
    pub(crate) fn arrived(&mut self, ctx: &egui::Context) -> bool {
        let frame = ctx.cumulative_frame_nr();
        let focused = ctx.input(|input| input.viewport().focused);
        let was_drawn = self.last_frame.is_some_and(|last| last + 1 >= frame);
        let regained = self.focused == Some(false) && focused == Some(true);
        self.last_frame = Some(frame);
        self.focused = focused.or(self.focused);
        !was_drawn || regained
    }

    /// A fixture's view that is already open: its first draw is no arrival,
    /// so a list the test filled by hand is not read again from the disk.
    #[cfg(test)]
    pub(crate) fn already_open(ctx: &egui::Context) -> Self {
        Self {
            last_frame: Some(ctx.cumulative_frame_nr()),
            focused: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ctx: &egui::Context, focused: Option<bool>, mut body: impl FnMut(&egui::Context)) {
        let mut input = egui::RawInput::default();
        input
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .focused = focused;
        let _ = ctx.run_ui(input, |ui| body(ui.ctx()));
    }

    #[test]
    fn a_window_arrives_once_then_again_after_a_gap_or_a_focus() {
        let ctx = egui::Context::default();
        let mut arrival = Arrival::default();
        let mut results = Vec::new();
        // Drawn in frames 1 and 2, hidden in 3 and 4, drawn in 5 and 6.
        for (drawn, focused) in [
            (true, Some(true)),
            (true, Some(true)),
            (false, Some(true)),
            (false, Some(true)),
            (true, Some(true)),
            (true, Some(true)),
            (true, Some(false)),
            (true, Some(true)),
            (true, Some(true)),
        ] {
            frame(&ctx, focused, |ctx| {
                if drawn {
                    results.push(arrival.arrived(ctx));
                }
            });
        }
        // First draw, no change, after the gap, no change, focus lost, focus back, no change.
        assert_eq!(
            results,
            [true, false, true, false, false, true, false],
            "{results:?}"
        );
    }
}
