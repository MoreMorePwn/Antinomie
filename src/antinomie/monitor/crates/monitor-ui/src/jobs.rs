// SPDX-License-Identifier: GPL-3.0-only
//! The Jobs window: everything the app is doing right now in one list, and
//! the last few things it finished. Nothing runs for it. Every frame the app
//! asks the places that already own a job (the backend snapshot, the export
//! worker, the rules window, Triage, the Memory tab, the Samples page) what
//! they are doing; this module keeps when each job was first seen and which
//! ones have since gone, and draws the two lists.
use crate::{
    run_state_line::{clock, now_ms},
    theme,
    toasts::Action,
    widgets::fit_table::{Col, FitBuilder},
    workspace::Panel,
};
use antinomie_monitor_core::Command;
use eframe::egui::{self, RichText};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{atomic::AtomicBool, atomic::Ordering, Arc},
};

/// Finished jobs kept for the "Finished" list.
pub(crate) const FINISHED_LIMIT: usize = 20;

/// How a job is asked to stop.
#[derive(Clone)]
pub(crate) enum Stop {
    /// A cancel flag the worker watches.
    Flag(Arc<AtomicBool>),
    /// A command for the backend (cancel a download, a build, ...).
    Command(Command),
    /// Stop one run of the active VM (asks for the usual confirmation).
    Run(String),
    /// Stop the VM that is starting.
    Vm,
    /// Anything else that stops a worker (a plugin run's handle).
    Call(Arc<dyn Fn() + Send + Sync>),
}

/// One thing the app is doing.
#[derive(Clone)]
pub(crate) struct Job {
    /// Names the job across frames, so a job that goes away can be matched
    /// with what it was.
    pub key: String,
    /// What kind of work it is: "Run", "Download", "Detection scan", ...
    pub kind: &'static str,
    /// What it works on: a program and its VM, a file, a base, a dump.
    pub target: String,
    /// When it began (Unix ms), when its owner knows; otherwise the time the
    /// app first saw it.
    pub started_ms: Option<u64>,
    pub state: String,
    /// 0 to 1, when the owner knows how far it is.
    pub progress: Option<f32>,
    pub stop: Option<Stop>,
    /// Where the job's result or its panel is.
    pub open: Option<Action>,
}

impl Job {
    pub(crate) fn new(
        key: impl Into<String>,
        kind: &'static str,
        target: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            kind,
            target: target.into(),
            started_ms: None,
            state: "Running".into(),
            progress: None,
            stop: None,
            open: None,
        }
    }
    pub(crate) fn state(mut self, state: impl Into<String>) -> Self {
        self.state = state.into();
        self
    }
    pub(crate) fn started(mut self, started_ms: Option<u64>) -> Self {
        self.started_ms = started_ms.filter(|ms| *ms != 0);
        self
    }
    pub(crate) fn progress(mut self, done: u64, total: u64) -> Self {
        if total > 0 {
            self.progress = Some((done as f64 / total as f64).clamp(0.0, 1.0) as f32);
        }
        self
    }
    pub(crate) fn fraction(mut self, fraction: f32) -> Self {
        self.progress = Some(fraction.clamp(0.0, 1.0));
        self
    }
    pub(crate) fn stop(mut self, stop: Stop) -> Self {
        self.stop = Some(stop);
        self
    }
    pub(crate) fn flag(self, flag: Option<Arc<AtomicBool>>) -> Self {
        match flag {
            Some(flag) => self.stop(Stop::Flag(flag)),
            None => self,
        }
    }
    /// The panel the job is seen in.
    pub(crate) fn open(mut self, panel: Panel) -> Self {
        self.open = Some(Action {
            label: format!("Open {}", panel.title()),
            panel,
            then: None,
        });
        self
    }
    pub(crate) fn open_action(mut self, action: Action) -> Self {
        self.open = Some(action);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Finished,
    Failed,
    Cancelled,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Finished => "Finished",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }
    fn color(self) -> egui::Color32 {
        match self {
            Self::Finished => theme::good(),
            Self::Failed => theme::error(),
            Self::Cancelled => theme::muted(),
        }
    }
}

/// A job that is over.
#[derive(Clone)]
pub(crate) struct Done {
    job: Job,
    ended_ms: u64,
    took_ms: u64,
    outcome: Outcome,
    detail: String,
}

/// What the window asks the app to do.
pub(crate) enum Request {
    Open(Action),
    Stop(String),
}

#[derive(Default)]
pub(crate) struct Board {
    running: Vec<Job>,
    /// When each running job was first seen, Unix ms.
    first_seen: BTreeMap<String, u64>,
    /// Jobs the user asked to stop, until they are gone.
    stopping: BTreeSet<String>,
    finished: VecDeque<Done>,
    /// The window was drawn since the last frame: it ticks the clock.
    drawn: bool,
}

impl Board {
    /// Take this frame's jobs. A job that was there and is not any more is
    /// moved to Finished, with the outcome `outcome` finds for it (the second
    /// argument says whether the user stopped it).
    pub(crate) fn update(
        &mut self,
        now: u64,
        jobs: Vec<Job>,
        mut outcome: impl FnMut(&Job, bool) -> (Outcome, String),
    ) {
        let keys: BTreeSet<&str> = jobs.iter().map(|job| job.key.as_str()).collect();
        for job in std::mem::take(&mut self.running) {
            if keys.contains(job.key.as_str()) {
                continue;
            }
            let stopped = self.stopping.remove(&job.key);
            let began = self.first_seen.remove(&job.key).unwrap_or(now);
            let started = job.started_ms.unwrap_or(began);
            let (outcome, detail) = outcome(&job, stopped);
            self.finished.push_front(Done {
                took_ms: now.saturating_sub(started),
                ended_ms: now,
                job,
                outcome,
                detail,
            });
            self.finished.truncate(FINISHED_LIMIT);
        }
        for job in &jobs {
            self.first_seen.entry(job.key.clone()).or_insert(now);
        }
        self.first_seen.retain(|key, _| keys.contains(key.as_str()));
        self.stopping.retain(|key| keys.contains(key.as_str()));
        self.running = jobs;
    }

    pub(crate) fn count(&self) -> usize {
        self.running.len()
    }

    /// The running jobs, one line each, for the quit confirmation.
    pub(crate) fn lines(&self, now: u64) -> Vec<String> {
        self.running
            .iter()
            .map(|job| {
                format!(
                    "{}: {} ({}, {})",
                    job.kind,
                    job.target,
                    job.state,
                    clock(now.saturating_sub(self.started(job, now)))
                )
            })
            .collect()
    }

    fn started(&self, job: &Job, now: u64) -> u64 {
        job.started_ms
            .or_else(|| self.first_seen.get(&job.key).copied())
            .unwrap_or(now)
    }

    pub(crate) fn job(&self, key: &str) -> Option<&Job> {
        self.running.iter().find(|job| job.key == key)
    }

    pub(crate) fn mark_stopping(&mut self, key: &str) {
        self.stopping.insert(key.to_owned());
    }

    /// Whether the window was drawn since this was last asked.
    pub(crate) fn take_drawn(&mut self) -> bool {
        std::mem::take(&mut self.drawn)
    }

    /// The dock tab: "Jobs" and, while any run, a chip with the count.
    pub(crate) fn title(&self, font_size: f32) -> egui::WidgetText {
        let mut job = egui::text::LayoutJob::default();
        let format = |color, background, size| egui::TextFormat {
            font_id: egui::FontId::proportional(size),
            color,
            background,
            valign: egui::Align::Center,
            ..Default::default()
        };
        let none = egui::Color32::TRANSPARENT;
        job.append("Jobs", 0.0, format(theme::text(), none, font_size));
        if !self.running.is_empty() {
            let palette = theme::palette();
            job.append(" ", 0.0, format(theme::text(), none, font_size));
            let size = (font_size - 3.0).max(11.0);
            job.append(
                &format!(" {} ", self.running.len()),
                0.0,
                format(palette.warn, palette.warn_bg, size),
            );
        }
        job.into()
    }

    /// The status-bar chip: "3 jobs". True when it was clicked.
    pub(crate) fn chip(&self, ui: &mut egui::Ui) -> bool {
        let count = self.running.len();
        if count == 0 {
            return false;
        }
        let text = if count == 1 {
            "1 job".to_owned()
        } else {
            format!("{count} jobs")
        };
        ui.add(egui::Button::new(
            RichText::new(format!("{} {text}", egui_phosphor::regular::GEAR_FINE))
                .color(theme::warn()),
        ))
        .on_hover_text("Open Jobs: what is running now")
        .clicked()
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui) -> Option<Request> {
        self.drawn = true;
        let now = now_ms();
        let mut request = None;
        ui.horizontal(|ui| {
            let count = self.running.len();
            ui.label(RichText::new(match count {
                0 => "Nothing is running".to_owned(),
                1 => "1 job running".to_owned(),
                n => format!("{n} jobs running"),
            }))
            .on_hover_text(
                "Runs, VM starts, analyses, scans, downloads, exports and the other \
                 work the app is doing now",
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !self.finished.is_empty(),
                        egui::Button::new("Clear finished"),
                    )
                    .on_hover_text("Forget the finished jobs listed below")
                    .clicked()
                {
                    self.finished.clear();
                }
            });
        });
        ui.separator();
        let height = ui.available_height();
        let scale = ui.text_style_height(&egui::TextStyle::Body) / 16.0;
        if self.running.is_empty() {
            ui.label(RichText::new("No jobs running.").color(theme::muted()));
        } else {
            let running = self.running.clone();
            let columns = [
                Col::fixed(130.0 * scale),
                Col::flex(220.0 * scale),
                Col::fixed(72.0 * scale),
                Col::fixed(64.0 * scale),
                Col::fixed(110.0 * scale),
                Col::rest(120.0 * scale),
                Col::fixed(130.0 * scale),
            ];
            crate::widgets::table::begin(ui);
            FitBuilder::new(ui)
                .id_salt("jobs-running")
                .striped(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .max_scroll_height((height * 0.55).max(80.0))
                .min_scrolled_height(0.0)
                .auto_shrink([false, true])
                .column(columns[0])
                .column(columns[1])
                .column(columns[2])
                .column(columns[3])
                .column(columns[4])
                .column(columns[5])
                .column(columns[6])
                .header(26.0, |mut header| {
                    for label in [
                        "Kind", "Target", "Started", "Elapsed", "Progress", "State", "",
                    ] {
                        header.col(|ui| {
                            ui.strong(label);
                        });
                    }
                })
                .body(|body| {
                    body.rows(26.0, running.len(), |mut row| {
                        let job = &running[row.index()];
                        let started = self.started(job, now);
                        let stopping = self.stopping.contains(&job.key);
                        row.col(|ui| {
                            ui.add(egui::Label::new(job.kind).truncate());
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(&job.target).truncate())
                                .on_hover_text(&job.target);
                        });
                        row.col(|ui| {
                            ui.monospace(local_time(started));
                        });
                        row.col(|ui| {
                            ui.monospace(clock(now.saturating_sub(started)));
                        });
                        row.col(|ui| match job.progress {
                            Some(fraction) => {
                                ui.add(
                                    egui::ProgressBar::new(fraction)
                                        .desired_width(ui.available_width().min(100.0))
                                        .text(format!("{:.0}%", fraction * 100.0)),
                                );
                            }
                            None => {
                                ui.colored_label(theme::muted(), "—");
                            }
                        });
                        row.col(|ui| {
                            let state = if stopping {
                                format!("{} (stopping)", job.state)
                            } else {
                                job.state.clone()
                            };
                            ui.add(egui::Label::new(&state).truncate())
                                .on_hover_text(&state);
                        });
                        row.col(|ui| {
                            if let Some(open) = &job.open {
                                if ui.small_button("Open").on_hover_text(&open.label).clicked() {
                                    request = Some(Request::Open(open.clone()));
                                }
                            }
                            if job.stop.is_some()
                                && ui
                                    .add_enabled(!stopping, egui::Button::new("Stop").small())
                                    .on_hover_text("Stop this job")
                                    .clicked()
                            {
                                request = Some(Request::Stop(job.key.clone()));
                            }
                        });
                    });
                });
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong("Finished");
            ui.label(
                RichText::new(format!("last {FINISHED_LIMIT}, until cleared"))
                    .color(theme::muted()),
            );
        });
        if self.finished.is_empty() {
            ui.label(RichText::new("Nothing has finished yet.").color(theme::muted()));
            return request;
        }
        let finished: Vec<Done> = self.finished.iter().cloned().collect();
        let columns = [
            Col::fixed(130.0 * scale),
            Col::flex(220.0 * scale),
            Col::fixed(72.0 * scale),
            Col::fixed(64.0 * scale),
            Col::fixed(90.0 * scale),
            Col::rest(120.0 * scale),
            Col::fixed(60.0 * scale),
        ];
        crate::widgets::table::begin(ui);
        FitBuilder::new(ui)
            .id_salt("jobs-finished")
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .min_scrolled_height(0.0)
            .auto_shrink([false, false])
            .column(columns[0])
            .column(columns[1])
            .column(columns[2])
            .column(columns[3])
            .column(columns[4])
            .column(columns[5])
            .column(columns[6])
            .header(26.0, |mut header| {
                for label in ["Kind", "Target", "Ended", "Took", "Result", "Detail", ""] {
                    header.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(26.0, finished.len(), |mut row| {
                    let done = &finished[row.index()];
                    row.col(|ui| {
                        ui.add(egui::Label::new(done.job.kind).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&done.job.target).truncate())
                            .on_hover_text(&done.job.target);
                    });
                    row.col(|ui| {
                        ui.monospace(local_time(done.ended_ms));
                    });
                    row.col(|ui| {
                        ui.monospace(clock(done.took_ms));
                    });
                    row.col(|ui| {
                        ui.colored_label(done.outcome.color(), done.outcome.label());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&done.detail).truncate())
                            .on_hover_text(&done.detail);
                    });
                    row.col(|ui| {
                        if let Some(open) = &done.job.open {
                            if ui.small_button("Open").on_hover_text(&open.label).clicked() {
                                request = Some(Request::Open(open.clone()));
                            }
                        }
                    });
                });
            });
        request
    }
}

/// `HH:MM:SS` of a Unix-millisecond time, local.
fn local_time(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "—".into())
}

/// Stops a flag-stopped job.
pub(crate) fn raise(flag: &AtomicBool) {
    flag.store(true, Ordering::Relaxed);
}
