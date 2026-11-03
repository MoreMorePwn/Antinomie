// SPDX-License-Identifier: GPL-3.0-only
//! The Strings and Regex sub-windows of the Content window. Nothing runs
//! until the person presses Search; the search then walks the source on a
//! worker thread with progress and Cancel, and the hits are listed a page at
//! a time. A hit is a button that jumps the Content view to its offset.
use super::ContentSource;
use crate::widgets::fit_table::{Col, FitBuilder};
use antinomie_monitor_core::content_scan::{
    self, Scan, Stopped, StringsOptions, HITS_DEFAULT_COUNT, HITS_MAX_COUNT, MIN_LEN_RANGE,
};
use eframe::egui::{self, RichText};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{self, Receiver},
    Arc,
};
use std::time::Duration;

/// The scan a pane starts on a worker thread.
type ScanWork = Box<dyn FnOnce(&AtomicBool, &AtomicU64) -> Scan + Send>;

/// Hits listed per page.
pub(super) const HITS_PAGE_SIZE: usize = 200;
/// Characters of a hit shown in the list.
const HIT_SHOWN_LEN: usize = 120;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Strings,
    Regex,
}

struct Running {
    receiver: Receiver<Scan>,
    cancel: Arc<AtomicBool>,
    progress: Arc<AtomicU64>,
    total: u64,
}

pub(super) struct ScanPane {
    kind: Kind,
    open: bool,
    min_len: usize,
    ascii: bool,
    utf16: bool,
    pattern: String,
    case_insensitive: bool,
    max_hits: usize,
    running: Option<Running>,
    result: Option<Scan>,
    error: Option<String>,
    page: usize,
    /// The data the result belongs to.
    for_key: String,
}

impl ScanPane {
    pub(super) fn new(kind: Kind) -> Self {
        Self {
            kind,
            open: false,
            min_len: 4,
            ascii: true,
            utf16: true,
            pattern: String::new(),
            case_insensitive: false,
            max_hits: HITS_DEFAULT_COUNT,
            running: None,
            result: None,
            error: None,
            page: 0,
            for_key: String::new(),
        }
    }

    /// The search under way, for the Jobs window.
    pub(super) fn job(&self, key: &str, target: &str) -> Option<crate::jobs::Job> {
        let running = self.running.as_ref()?;
        let kind = match self.kind {
            Kind::Strings => "Content strings",
            Kind::Regex => "Content regex",
        };
        Some(
            crate::jobs::Job::new(format!("content-{}:{key}", self.title()), kind, target)
                .state("Searching")
                .progress(running.progress.load(Ordering::Relaxed), running.total)
                .flag(Some(Arc::clone(&running.cancel))),
        )
    }

    pub(super) fn open(&self) -> bool {
        self.open
    }

    pub(super) fn toggle(&mut self) {
        self.open = !self.open;
    }

    /// Stop a search under way.
    pub(super) fn cancel(&mut self) {
        if let Some(running) = &self.running {
            running.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn title(&self) -> &'static str {
        match self.kind {
            Kind::Strings => "Strings",
            Kind::Regex => "Regex",
        }
    }

    pub(super) fn start(&mut self, source: &ContentSource) {
        self.error = None;
        let reader = Arc::clone(&source.source);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let work: ScanWork = match self.kind {
            Kind::Strings => {
                if !self.ascii && !self.utf16 {
                    self.error = Some("Choose ASCII, UTF-16LE or both.".into());
                    return;
                }
                let options = StringsOptions {
                    min_len: self.min_len,
                    ascii: self.ascii,
                    utf16: self.utf16,
                    max_hits: self.max_hits,
                };
                Box::new(move |cancel, progress| {
                    content_scan::find_strings(&*reader, options, cancel, progress)
                })
            }
            Kind::Regex => {
                let regex = match content_scan::compile_regex(&self.pattern, self.case_insensitive)
                {
                    Ok(regex) => regex,
                    Err(error) => {
                        self.error = Some(error);
                        return;
                    }
                };
                let max_hits = self.max_hits;
                Box::new(move |cancel, progress| {
                    content_scan::find_matches(&*reader, &regex, max_hits, cancel, progress)
                })
            }
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let (worker_cancel, worker_progress) = (Arc::clone(&cancel), Arc::clone(&progress));
        let spawned = std::thread::Builder::new()
            .name("content-scan".into())
            .spawn(move || {
                // The window may be closed by now; a lost result is fine.
                let _ = sender.send(work(&worker_cancel, &worker_progress));
            });
        match spawned {
            Ok(_) => {
                self.result = None;
                self.page = 0;
                self.for_key = source.key.clone();
                self.running = Some(Running {
                    receiver,
                    cancel,
                    progress,
                    total: source.size(),
                });
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(running) = &self.running else {
            return;
        };
        match running.receiver.try_recv() {
            Ok(scan) => {
                self.result = Some(scan);
                self.running = None;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some("the search stopped unexpectedly".into());
                self.running = None;
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(75));
            }
        }
    }

    /// Draw the window if it is open. Returns the (offset, length) of a hit
    /// the person chose.
    pub(super) fn window(
        &mut self,
        ctx: &egui::Context,
        salt: &'static str,
        source: &ContentSource,
    ) -> Option<(u64, u64)> {
        self.poll(ctx);
        if self.for_key != source.key && self.running.is_none() {
            self.result = None;
        }
        if !self.open {
            return None;
        }
        let mut open = true;
        let mut chosen = None;
        egui::Window::new(self.title())
            .id(egui::Id::new((salt, "content-scan", self.title())))
            .open(&mut open)
            .default_size([560.0, 440.0])
            .resizable(true)
            .show(ctx, |ui| {
                chosen = self.body(ui, salt, source);
            });
        if !open {
            self.open = false;
        }
        chosen
    }

    fn body(
        &mut self,
        ui: &mut egui::Ui,
        salt: &'static str,
        source: &ContentSource,
    ) -> Option<(u64, u64)> {
        let idle = self.running.is_none();
        ui.add_enabled_ui(idle, |ui| {
            ui.horizontal_wrapped(|ui| match self.kind {
                Kind::Strings => {
                    ui.label("Minimum length");
                    ui.add(
                        egui::DragValue::new(&mut self.min_len)
                            .range(MIN_LEN_RANGE.0..=MIN_LEN_RANGE.1),
                    );
                    ui.checkbox(&mut self.ascii, "ASCII");
                    ui.checkbox(&mut self.utf16, "UTF-16LE");
                }
                Kind::Regex => {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pattern)
                            .hint_text("pattern, e.g. https?://[a-z0-9./-]+")
                            .desired_width(280.0)
                            .id(egui::Id::new((salt, "content-pattern"))),
                    );
                    ui.checkbox(&mut self.case_insensitive, "Ignore case")
                        .on_hover_text(
                            "Matches octets, not characters: \\xNN names one octet and . is any octet but a newline",
                        );
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Max hits");
                ui.add(egui::DragValue::new(&mut self.max_hits).range(1..=HITS_MAX_COUNT));
            });
        });
        ui.horizontal(|ui| {
            if let Some(running) = &self.running {
                if ui.button("Cancel").clicked() {
                    running.cancel.store(true, Ordering::Relaxed);
                }
                crate::theme::loading(
                    ui,
                    format!(
                        "Searching… {} of {}",
                        crate::values::file_size(running.progress.load(Ordering::Relaxed)),
                        crate::values::file_size(running.total)
                    ),
                );
            } else if ui.button("Search").clicked() {
                self.start(source);
            }
        });
        if let Some(error) = &self.error {
            crate::activity::inline_only(ui, crate::activity::Level::Warn, error);
        }
        ui.separator();
        self.hits(ui, source)
    }

    fn hits(&mut self, ui: &mut egui::Ui, source: &ContentSource) -> Option<(u64, u64)> {
        let scan = self.result.as_ref()?;
        let mut chosen = None;
        let found = scan.hits.len();
        match scan.stopped {
            Some(Stopped::Limit) => {
                crate::activity::info(
                    ui,
                    format!(
                        "Stopped at the limit of {found} hits; raise Max hits or search again for something narrower."
                    ),
                );
            }
            Some(Stopped::Cancelled) => {
                crate::activity::info(
                    ui,
                    format!(
                        "Cancelled after {}; the {found} hits found so far are listed.",
                        crate::values::file_size(scan.scanned)
                    ),
                );
            }
            Some(Stopped::Unreadable) => {
                crate::activity::info(
                    ui,
                    format!(
                        "The data ended early or could not be read after {}; the rest was not searched.",
                        crate::values::file_size(scan.scanned)
                    ),
                );
            }
            None => {}
        }
        let pages = found.div_ceil(HITS_PAGE_SIZE).max(1);
        self.page = self.page.min(pages - 1);
        ui.horizontal(|ui| {
            ui.label(format!("{found} hits"));
            if ui
                .add_enabled(self.page > 0, egui::Button::new("Previous"))
                .clicked()
            {
                self.page -= 1;
            }
            ui.label(format!("Page {} of {pages}", self.page + 1));
            if ui
                .add_enabled(self.page + 1 < pages, egui::Button::new("Next"))
                .clicked()
            {
                self.page += 1;
            }
        });
        let first = self.page * HITS_PAGE_SIZE;
        let shown: Vec<&content_scan::Hit> = scan.hits[first..(first + HITS_PAGE_SIZE).min(found)]
            .iter()
            .collect();
        let columns = [Col::fixed(150.0), Col::fixed(64.0), Col::rest(160.0)];
        FitBuilder::new(ui)
            .id_salt((self.title(), "content-hits", self.page))
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .min_scrolled_height(0.0)
            .auto_shrink([false, false])
            .column(columns[0])
            .column(columns[1])
            .column(columns[2])
            .header(24.0, |mut header| {
                for label in [source.address_name, "Kind", "Text"] {
                    header.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, shown.len(), |mut row| {
                    let hit = shown[row.index()];
                    row.col(|ui| {
                        let place = RichText::new(source.place(hit.offset)).monospace();
                        if ui
                            .add(egui::Button::new(place).frame(false).truncate())
                            .on_hover_text(format!(
                                "{} · {} octets · click to show it in Content",
                                source.hover(hit.offset),
                                hit.len
                            ))
                            .clicked()
                        {
                            chosen = Some((hit.offset, hit.len));
                        }
                    });
                    row.col(|ui| {
                        ui.colored_label(crate::theme::muted(), hit.kind);
                    });
                    row.col(|ui| {
                        let text: String = hit.text.chars().take(HIT_SHOWN_LEN).collect();
                        ui.add(egui::Label::new(RichText::new(text).monospace()).truncate());
                    });
                });
            });
        chosen
    }
}
