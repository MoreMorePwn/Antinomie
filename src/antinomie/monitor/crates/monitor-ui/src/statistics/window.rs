// SPDX-License-Identifier: GPL-3.0-only
//! The window itself: floating over the main window, or popped out into its own
//! operating-system window (the Activity graph window's pattern,
//! `triage/graph/window.rs`), with the embedded fallback when the platform has
//! no separate windows. The state lives here; the parts are drawn by
//! `toolbar.rs`.
use super::worker::{Key, Worker};
use super::{hierarchy, latency, rate};
use super::{AppView, Navigate, Question, Tab, Target, TimeBase};
use crate::theme;
use eframe::egui;

/// The size a first window opens at, in points.
pub(crate) const DEFAULT_SIZE: [f32; 2] = [980.0, 640.0];
/// The smallest the window can be made.
const MIN_SIZE: [f32; 2] = [560.0, 420.0];

pub(crate) struct StatisticsWindow {
    pub(crate) open: bool,
    pub(super) tab: Tab,
    pub(super) popped: bool,
    pub(super) size: [f32; 2],
    /// The size a pop-out was built with: egui compares builders, so the
    /// measured size is kept apart and never fed back into it.
    opened_at: [f32; 2],
    /// Bring the window to the front on the next frame.
    pub(super) focus: bool,
    /// The saved size and pop-out state were read once.
    restored: bool,
    /// Size or pop-out state changed: hand them to the settings.
    saved: Option<([f32; 2], bool)>,
    /// The run or capture the results are for.
    pub(super) target_id: Option<String>,
    /// The filter box, and the filter in force (always one that compiles).
    pub(super) filter: String,
    pub(super) applied: String,
    pub(super) filter_error: Option<String>,
    pub(super) time_base: TimeBase,
    pub(super) worker: Worker,
    pub(super) hierarchy: hierarchy::State,
    pub(super) rate: rate::State,
    pub(super) latency: latency::State,
    /// The extra walk for custom Call rate lines.
    pub(super) rate_worker: Worker,
    /// Segments the run has, read once per run: the quality strip says when more than one.
    pub(super) segments: Option<(String, usize)>,
    /// The quality chips were clicked: show the Quality block.
    pub(super) scroll_quality: bool,
    /// The Stop button of a custom line was pressed.
    pub(super) rate_stop: bool,
    pub(super) question: Option<Question>,
    /// What the last Copy or Export did, in words.
    pub(super) note: Option<String>,
    /// Frames the window was drawn, for tests.
    #[cfg(test)]
    pub(crate) drawn: u64,
    /// Frames the pop-out's viewport closure ran, for tests.
    #[cfg(test)]
    pub(crate) drawn_popped: u64,
}

impl Default for StatisticsWindow {
    fn default() -> Self {
        Self {
            open: false,
            tab: Tab::default(),
            popped: false,
            size: DEFAULT_SIZE,
            opened_at: DEFAULT_SIZE,
            focus: false,
            restored: false,
            saved: None,
            target_id: None,
            filter: String::new(),
            applied: String::new(),
            filter_error: None,
            time_base: TimeBase::default(),
            worker: Worker::default(),
            hierarchy: hierarchy::State::default(),
            rate: rate::State::default(),
            latency: latency::State::default(),
            rate_worker: Worker::default(),
            segments: None,
            scroll_quality: false,
            rate_stop: false,
            question: None,
            note: None,
            #[cfg(test)]
            drawn: 0,
            #[cfg(test)]
            drawn_popped: 0,
        }
    }
}

fn floating_id() -> egui::Id {
    egui::Id::new("statistics-window")
}

pub(super) fn viewport_id() -> egui::ViewportId {
    egui::ViewportId::from_hash_of("statistics-window")
}

impl StatisticsWindow {
    /// Open the window, or bring it forward; `tab` chooses the tab (`None`
    /// keeps the last one).
    pub(crate) fn request_open(&mut self, tab: Option<Tab>) {
        if let Some(tab) = tab {
            self.tab = tab;
        }
        self.open = true;
        self.focus = true;
    }

    /// Open the window on `filter` (the Trace's "Statistics of these calls").
    pub(crate) fn open_with_filter(&mut self, filter: &str) {
        self.filter = filter.to_owned();
        self.apply();
        self.request_open(None);
    }

    #[cfg(test)]
    pub(crate) fn tab(&self) -> Tab {
        self.tab
    }

    #[cfg(test)]
    pub(crate) fn popped(&self) -> bool {
        self.popped
    }

    #[cfg(test)]
    pub(crate) fn applied_filter(&self) -> &str {
        &self.applied
    }

    /// Read the saved size and pop-out state, once.
    pub(crate) fn restore(&mut self, size: [f32; 2], popped: bool) {
        if self.restored {
            return;
        }
        self.restored = true;
        if size[0] >= MIN_SIZE[0] && size[1] >= MIN_SIZE[1] {
            self.size = size;
            self.opened_at = size;
        }
        self.popped = popped;
    }

    /// The size and pop-out state to save in the settings, when they changed.
    pub(crate) fn take_saved(&mut self) -> Option<([f32; 2], bool)> {
        self.saved.take()
    }

    #[cfg(test)]
    pub(crate) fn size(&self) -> [f32; 2] {
        self.size
    }

    pub(super) fn remember(&mut self, size: [f32; 2]) {
        let size = [size[0].round(), size[1].round()];
        if size[0] >= MIN_SIZE[0] && size[1] >= MIN_SIZE[1] && size != self.size {
            self.size = size;
            self.saved = Some((size, self.popped));
        }
    }

    pub(crate) fn set_popped(&mut self, popped: bool) {
        if self.popped != popped {
            self.popped = popped;
            self.opened_at = self.size;
            self.saved = Some((self.size, popped));
        }
    }

    /// A valid filter becomes the one in force and restarts the walk; an
    /// invalid one shows its message and keeps the last result, greyed.
    pub(super) fn apply(&mut self) {
        let compiled = crate::query::compile_note(&self.filter);
        match compiled.error {
            None => {
                self.applied.clone_from(&self.filter);
                self.filter_error = None;
            }
            Some(error) => self.filter_error = Some(error),
        }
    }

    pub(super) fn key_of(&self, target: &Target) -> Key {
        Key {
            directory: target.directory.clone(),
            capture: target.capture,
            root_cookie: target.root_cookie,
            filter: self.applied.clone(),
            lines: Vec::new(),
        }
    }

    /// Custom Call rate lines need one more walk, started once the main read is over
    /// (one walk at a time). A change of lines cancels the walk in progress.
    fn walk_custom_lines(&mut self, ctx: &egui::Context, target: &Target) {
        self.rate_worker.poll();
        let lines = self.rate.lines.customs();
        if lines.is_empty() {
            if self.rate_worker.running() || self.rate_worker.shown().is_some() {
                self.rate_worker.reset();
            }
            return;
        }
        if self.worker.running() && !self.rate_worker.running() {
            return;
        }
        let mut key = self.key_of(target);
        key.lines = lines;
        self.rate_worker.ensure(ctx, &key);
    }

    /// How many recording segments the run has, once per run.
    fn read_segments(&mut self, target: &Target) {
        if self
            .segments
            .as_ref()
            .is_some_and(|(id, _)| *id == target.id)
        {
            return;
        }
        let count = if target.capture {
            1
        } else {
            antinomie_monitor_core::recording::run_segments(
                &target.directory,
                &target.id,
                &target.vm,
            )
            .map_or(1, |segments| segments.len())
        };
        self.segments = Some((target.id.clone(), count));
    }

    pub(super) fn close(&mut self) {
        self.open = false;
        self.worker.cancel();
        self.rate_worker.cancel();
    }

    /// Draw the window if it is open and walk what it needs. Called every
    /// frame from the app; returns what the app should do with the Trace.
    pub(crate) fn show(&mut self, ctx: &egui::Context, view: &AppView<'_>) -> Vec<Navigate> {
        if !self.open {
            self.worker.cancel();
            self.rate_worker.cancel();
            return Vec::new();
        }
        // Follow the run chosen in the app: another run starts afresh.
        let id = view.target.as_ref().map(|target| target.id.clone());
        if id != self.target_id {
            self.worker.reset();
            self.rate_worker.reset();
            self.segments = None;
            self.question = None;
            self.note = None;
            self.target_id = id;
        }
        self.worker.poll();
        if let Some(target) = view.target.as_ref() {
            let key = self.key_of(target);
            self.worker.ensure(ctx, &key);
            self.walk_custom_lines(ctx, target);
            self.read_segments(target);
        }
        let mut navigate = Vec::new();
        if self.popped {
            self.show_popped(ctx, view, &mut navigate);
        } else {
            self.show_floating(ctx, view, &mut navigate);
        }
        navigate
    }

    fn title(view: &AppView<'_>) -> String {
        match view.target.as_ref() {
            Some(target) => format!("Statistics · {}", target.label),
            None => "Statistics".into(),
        }
    }

    fn show_floating(
        &mut self,
        ctx: &egui::Context,
        view: &AppView<'_>,
        navigate: &mut Vec<Navigate>,
    ) {
        #[cfg(test)]
        {
            self.drawn += 1;
        }
        let id = floating_id();
        if self.focus {
            self.focus = false;
            ctx.move_to_top(egui::LayerId::new(egui::Order::Middle, id));
        }
        let mut open = true;
        let shown = crate::widgets::window(Self::title(view))
            .id(id)
            .open(&mut open)
            .default_size(self.size)
            .min_size(MIN_SIZE)
            .show(ctx, |ui| self.body(ui, view, navigate));
        if let Some(inner) = shown {
            let rect = inner.response.rect;
            // The frame is part of the rect; the sizes asked for count it too.
            self.remember([rect.width(), rect.height()]);
        }
        if !open || crate::widgets::escape_closes(ctx, id) {
            self.close();
        }
    }

    fn show_popped(
        &mut self,
        ctx: &egui::Context,
        view: &AppView<'_>,
        navigate: &mut Vec<Navigate>,
    ) {
        let title = Self::title(view);
        let builder = crate::title_bar::builder(egui::ViewportBuilder::default())
            .with_title(title.clone())
            .with_inner_size(self.opened_at)
            .with_min_inner_size(MIN_SIZE);
        if std::mem::take(&mut self.focus) {
            ctx.send_viewport_cmd_to(viewport_id(), egui::ViewportCommand::Focus);
        }
        let mut closed = false;
        ctx.show_viewport_immediate(viewport_id(), builder, |viewport_ui, class| {
            let ctx = &viewport_ui.ctx().clone();
            #[cfg(test)]
            {
                self.drawn_popped += 1;
            }
            closed = ctx.input(|input| input.viewport().close_requested());
            if closed {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            if class == egui::ViewportClass::EmbeddedWindow {
                // Without separate windows the window floats inside the main one.
                let mut keep = true;
                crate::widgets::window(title.clone())
                    .id(floating_id())
                    .open(&mut keep)
                    .default_size(self.size)
                    .show(ctx, |ui| self.body(ui, view, navigate));
                closed = !keep;
                return;
            }
            if let Some(inner) = ctx.input(|input| input.viewport().inner_rect) {
                self.remember([inner.width(), inner.height()]);
            }
            crate::title_bar::show(viewport_ui, &title);
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(theme::bg()).inner_margin(8))
                .show(viewport_ui, |ui| self.body(ui, view, navigate));
            crate::title_bar::resize(ctx);
            let escape = ctx.input(|input| input.key_pressed(egui::Key::Escape))
                && ctx.memory(|memory| memory.focused().is_none())
                && !egui::Popup::is_any_open(ctx);
            if escape {
                closed = true;
            }
        });
        if closed {
            self.close();
        }
    }
}
