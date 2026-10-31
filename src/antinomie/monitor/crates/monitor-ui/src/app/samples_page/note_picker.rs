// SPDX-License-Identifier: GPL-3.0-only
//! The reference picker of the note editor: a search field and a cascade
//! (group, category, run) over what the open sample's notes can refer to,
//! with icons, hover and keyboard states. Entries of a run's recording (its
//! processes and the first calls of its Syscall Trace) are read on a thread.
use super::detail::Data;
use super::*;
use crate::widgets;
use antinomie_monitor_core::samples::{
    build_lineage, Known, LineageOptions, NoteRef, RefKind, RunLineage,
};
use std::{collections::HashMap, path::PathBuf};

/// The most rows the picker lists at once.
pub(super) const ROWS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Category {
    Runs,
    Processes,
    Trace,
    Ioc,
    Files,
    Custody,
    Lineage,
}

impl Category {
    pub(super) const ALL: [Category; 7] = [
        Self::Runs,
        Self::Processes,
        Self::Trace,
        Self::Ioc,
        Self::Files,
        Self::Custody,
        Self::Lineage,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Runs => "Runs",
            Self::Processes => "Processes",
            Self::Trace => "Trace entries",
            Self::Ioc => "IoC",
            Self::Files => "Files / artifacts",
            Self::Custody => "Custody entries",
            Self::Lineage => "Lineage nodes",
        }
    }

    /// What the category is, one line, for its hover.
    pub(super) fn about(self) -> &'static str {
        match self {
            Self::Runs => "A whole run of the sample",
            Self::Processes => "A process of one run, opened in its Syscall Trace",
            Self::Trace => "One entry of a run's Syscall Trace: the note jumps to that record",
            Self::Ioc => "An indicator the runs produced: address, domain, file hash",
            Self::Files => "A file or capture a run kept",
            Self::Custody => "An entry of this sample's custody log",
            Self::Lineage => "A file in the lineage graph",
        }
    }

    /// The group the picker lists the category under.
    pub(super) fn group(self) -> &'static str {
        match self {
            Self::Runs | Self::Processes | Self::Trace => "In a run",
            Self::Ioc | Self::Files => "What a run produced",
            Self::Custody | Self::Lineage => "In this sample's record",
        }
    }

    pub(super) fn icon(self) -> &'static str {
        use egui_phosphor::regular as icon;
        match self {
            Self::Runs => icon::PLAY_CIRCLE,
            Self::Processes => icon::TREE_STRUCTURE,
            Self::Trace => icon::LIST_BULLETS,
            Self::Ioc => icon::CROSSHAIR,
            Self::Files => icon::FILE,
            Self::Custody => icon::SCROLL,
            Self::Lineage => icon::GRAPH,
        }
    }

    /// Whether the category has a second level between it and its entries.
    pub(super) fn has_subtypes(self) -> bool {
        matches!(
            self,
            Self::Processes | Self::Trace | Self::Ioc | Self::Files
        )
    }

    /// Whether the entries are read from a run's recording, on a thread.
    pub(super) fn from_recording(self) -> bool {
        matches!(self, Self::Processes | Self::Trace)
    }
}

/// One thing a note can refer to.
pub(super) struct Candidate {
    pub(super) category: Category,
    /// The second level: a run, an indicator type or an artifact kind.
    pub(super) sub: String,
    pub(super) reference: NoteRef,
    /// What a typed search is matched against, lower case.
    pub(super) haystack: String,
}

/// A run whose processes the picker can read.
pub(super) struct RunInfo {
    pub(super) label: String,
    pub(super) key: String,
    pub(super) vm_id: String,
    pub(super) run_id: String,
    pub(super) directory: PathBuf,
    pub(super) pid: u32,
    pub(super) path: String,
    pub(super) folder: bool,
}

/// What the picker offers, read from the open sample's data.
pub(super) struct Candidates {
    pub(super) list: Vec<Candidate>,
    pub(super) runs: Vec<RunInfo>,
}

pub(super) fn candidate(category: Category, sub: &str, reference: NoteRef) -> Candidate {
    let haystack = format!("{} {}", reference.label, sub).to_lowercase();
    Candidate {
        category,
        sub: sub.to_owned(),
        reference,
        haystack,
    }
}

impl Candidates {
    pub(super) fn of(data: &Data) -> Self {
        let mut list = Vec::new();
        let mut runs = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &data.runs {
            let label = format!("Run {}", entry.number);
            let key = format!("{}/{}", entry.run.vm_id, entry.run.id);
            list.push(candidate(
                Category::Runs,
                "",
                NoteRef::new(RefKind::Run, key.clone(), label.clone()),
            ));
            runs.push(RunInfo {
                label,
                key,
                vm_id: entry.run.vm_id.clone(),
                run_id: entry.run.id.clone(),
                directory: entry.run.directory.clone(),
                pid: entry.run.pid,
                path: entry.run.request.path.clone(),
                folder: entry.folder,
            });
            for found in entry
                .digest
                .iter()
                .flat_map(|digest| digest.indicators.iter().flatten())
            {
                if seen.insert((found.ty.clone(), found.value.clone())) {
                    list.push(candidate(
                        Category::Ioc,
                        &found.ty,
                        NoteRef::new(
                            RefKind::Indicator,
                            format!("{}:{}", found.ty, found.value),
                            format!("{} ({})", found.value, found.ty),
                        ),
                    ));
                }
            }
        }
        for output in data.outputs() {
            let reference = output.reference();
            list.push(candidate(Category::Files, output.kind_label(), reference));
        }
        for event in &data.events {
            list.push(candidate(
                Category::Custody,
                "",
                NoteRef::new(
                    RefKind::Custody,
                    event.seq.to_string(),
                    format!("Custody entry {} · {}", event.seq, event.event.label()),
                ),
            ));
        }
        for node in lineage_nodes(data) {
            list.push(candidate(Category::Lineage, "", node));
        }
        Self { list, runs }
    }

    pub(super) fn count(&self, category: Category) -> usize {
        if category.from_recording() {
            return self.runs.iter().filter(|run| run.folder).count();
        }
        self.list
            .iter()
            .filter(|found| found.category == category)
            .count()
    }

    pub(super) fn subtypes(&self, category: Category) -> Vec<(String, usize)> {
        if category.from_recording() {
            return self
                .runs
                .iter()
                .filter(|run| run.folder)
                .map(|run| (run.label.clone(), 0))
                .collect();
        }
        let mut counts: Vec<(String, usize)> = Vec::new();
        for found in self.list.iter().filter(|found| found.category == category) {
            match counts.iter_mut().find(|(sub, _)| *sub == found.sub) {
                Some((_, count)) => *count += 1,
                None => counts.push((found.sub.clone(), 1)),
            }
        }
        counts
    }
}

/// The lineage graph's nodes as references (the graph at its default levels).
pub(super) fn lineage_nodes(data: &Data) -> Vec<NoteRef> {
    let runs: Vec<RunLineage<'_>> = data
        .runs
        .iter()
        .map(|entry| RunLineage {
            number: entry.number,
            sample: entry
                .run
                .request
                .sample
                .as_ref()
                .map_or("", |sample| sample.sha256.as_str()),
            sample_path: entry.run.request.path.as_str(),
            lineage: entry
                .digest
                .as_ref()
                .and_then(|digest| digest.lineage.as_ref()),
        })
        .collect();
    let known = |sha: &str| {
        data.known.get(sha).map(|(name, verdict)| Known {
            name: name.clone(),
            verdict: verdict.clone(),
        })
    };
    let options = LineageOptions {
        hide_system: false,
        ..LineageOptions::default()
    };
    build_lineage(&data.record.sha256, &runs, &data.links, &known, &options)
        .nodes
        .into_iter()
        .filter(|node| node.id != data.record.sha256)
        .map(|node| NoteRef::new(RefKind::Lineage, node.id, node.label))
        .collect()
}

/// What a thread read from a run's recording: the candidates it found.
pub(super) type Read = Result<Vec<(NoteRef, String)>, String>;

pub(super) enum Reading {
    Working(Receiver<Read>),
    Ready(Vec<Candidate>),
    Failed(String),
}

/// Calls of a run the picker lists: four pages of the Syscall Trace.
pub(super) const TRACE_PAGES: usize = 4;
/// Calls per page the recording gives.
pub(super) const TRACE_PAGE: usize = 256;

/// The first calls of a run's Syscall Trace, as `(event sequence, what the
/// call was)`; [`TRACE_PAGES`] pages at most.
pub(super) fn read_trace(
    recording: &antinomie_monitor_core::recording::Recording,
    cancel: &std::sync::atomic::AtomicBool,
) -> Read {
    let mut found = Vec::new();
    let mut offset = 0;
    for _ in 0..TRACE_PAGES {
        let page = recording
            .invocation_page_cancellable(offset, TRACE_PAGE, cancel)
            .map_err(|error| error.to_string())?;
        for invocation in &page.invocations {
            let Some(event) = crate::trace::representative(invocation) else {
                continue;
            };
            let info = crate::trace::info(invocation);
            let what = if info.is_empty() {
                event.syscall_name.clone()
            } else {
                format!(
                    "{} {}",
                    event.syscall_name,
                    info.chars().take(90).collect::<String>()
                )
            };
            found.push((
                NoteRef::new(RefKind::Trace, event.event_seq.to_string(), ""),
                what,
            ));
        }
        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    Ok(found)
}

/// The key a run's reading of `category` is kept under.
pub(super) fn reading_key(category: Category, run: &RunInfo) -> String {
    format!("{}|{}", category.label(), run.key)
}

/// How a row of the picker is drawn.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RowState {
    Normal,
    /// The row the arrow keys are on.
    Cursor,
    /// Already one of the note's references.
    Taken,
    /// Nothing to pick in it.
    Empty,
}

/// One row of the picker: an icon, the text cut to one line, a count or the
/// run it belongs to at the right and, for a group of entries, a chevron.
/// The row lights up under the pointer, and the row the keys are on has the
/// accent bar the tables use for a selected row.
pub(super) fn pick_row(
    ui: &mut egui::Ui,
    icon: &str,
    text: &str,
    right: &str,
    chevron: bool,
    state: RowState,
) -> egui::Response {
    let palette = theme::palette();
    let height = ui.spacing().interact_size.y + 6.0;
    let sense = if matches!(state, RowState::Taken | RowState::Empty) {
        egui::Sense::hover()
    } else {
        egui::Sense::click()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), sense);
    if ui.is_rect_visible(rect) {
        let lit = response.hovered() && sense != egui::Sense::hover();
        if lit || state == RowState::Cursor {
            ui.painter().rect_filled(rect, 4.0, palette.selection_soft);
        }
        if state == RowState::Cursor {
            let bar = egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height()));
            ui.painter().rect_filled(bar, 2.0, palette.accent);
        }
        if lit {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        let body = egui::TextStyle::Body.resolve(ui.style());
        let dim = matches!(state, RowState::Taken | RowState::Empty);
        let ink = if dim { palette.muted } else { palette.text };
        let centre = rect.left_center();
        ui.painter().text(
            centre + egui::vec2(12.0, 0.0),
            egui::Align2::LEFT_CENTER,
            icon,
            body.clone(),
            if dim { palette.muted } else { palette.accent },
        );
        let mut right_edge = rect.right() - 10.0;
        if chevron {
            ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                egui_phosphor::regular::CARET_RIGHT,
                body.clone(),
                palette.muted,
            );
            right_edge -= body.size + 6.0;
        }
        if state == RowState::Taken {
            let done = ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                format!("{} added", egui_phosphor::regular::CHECK),
                body.clone(),
                palette.good,
            );
            right_edge = done.left() - 8.0;
        } else if !right.is_empty() {
            let shown = ui.painter().text(
                egui::pos2(right_edge, centre.y),
                egui::Align2::RIGHT_CENTER,
                right,
                body.clone(),
                palette.muted,
            );
            right_edge = shown.left() - 8.0;
        }
        let left = rect.left() + 12.0 + body.size + 10.0;
        let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), body, ink);
        job.wrap = egui::text::TextWrapping {
            max_width: (right_edge - left).max(40.0),
            max_rows: 1,
            break_anywhere: true,
            overflow_character: Some('…'),
        };
        let galley = ui.fonts(|fonts| fonts.layout_job(job));
        ui.painter().galley(
            egui::pos2(left, centre.y - galley.size().y / 2.0),
            galley,
            ink,
        );
    }
    response
}

/// The small muted title of a group of rows.
pub(super) fn group_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .small()
            .strong()
            .color(theme::muted()),
    );
}

/// The picker inside the editor: a search field and a cascade.
pub(super) struct Picker {
    pub(super) search: String,
    pub(super) category: Option<Category>,
    pub(super) sub: Option<String>,
    pub(super) cursor: usize,
    pub(super) focus: bool,
    /// What the recording-backed categories read, by [`reading_key`].
    pub(super) processes: HashMap<String, Reading>,
}

impl Picker {
    pub(super) fn new() -> Self {
        Self {
            search: String::new(),
            category: None,
            sub: None,
            cursor: 0,
            focus: true,
            processes: HashMap::new(),
        }
    }

    /// Read the process tree, or the first calls of the Syscall Trace, of a
    /// run on a thread.
    pub(super) fn read_run(&mut self, ctx: &egui::Context, category: Category, run: &RunInfo) {
        let key = reading_key(category, run);
        if self.processes.contains_key(&key) {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let (directory, pid, path) = (run.directory.clone(), run.pid, run.path.clone());
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("note-run-read".into())
            .spawn(move || {
                let cancel = std::sync::atomic::AtomicBool::new(false);
                let recording = antinomie_monitor_core::recording::Recording {
                    directory,
                    manifest: serde_json::Value::Null,
                    events: Vec::new(),
                };
                let result = if category == Category::Trace {
                    read_trace(&recording, &cancel)
                } else {
                    recording
                        .process_tree_cancellable(pid, &path, &cancel)
                        .map(|(processes, _)| {
                            processes
                                .into_iter()
                                .map(|process| {
                                    let exe = process.exe.unwrap_or_default();
                                    let name = if exe.is_empty() { process.name } else { exe };
                                    (
                                        NoteRef::new(RefKind::Process, process.pid.to_string(), ""),
                                        name,
                                    )
                                })
                                .collect()
                        })
                        .map_err(|error| error.to_string())
                };
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.processes.insert(
            key,
            match spawned {
                Ok(_) => Reading::Working(receiver),
                Err(error) => Reading::Failed(error.to_string()),
            },
        );
    }

    pub(super) fn poll(&mut self, candidates: &Candidates) {
        for (key, reading) in &mut self.processes {
            let Reading::Working(receiver) = reading else {
                continue;
            };
            let Ok(result) = receiver.try_recv() else {
                continue;
            };
            let Some((tag, run_key)) = key.split_once('|') else {
                continue;
            };
            let Some(run) = candidates.runs.iter().find(|run| run.key == run_key) else {
                continue;
            };
            let trace = tag == Category::Trace.label();
            let category = if trace {
                Category::Trace
            } else {
                Category::Processes
            };
            let label = run.label.clone();
            *reading = match result {
                Ok(found) => Reading::Ready(
                    found
                        .into_iter()
                        .map(|(reference, name)| {
                            let number = reference.target.clone();
                            let reference = if trace {
                                // The recording named the call by its event sequence.
                                NoteRef::new(
                                    RefKind::Trace,
                                    antinomie_monitor_core::samples::trace_target(
                                        &run.vm_id,
                                        &run.run_id,
                                        number.parse().unwrap_or(0),
                                    ),
                                    format!("{label} · {name} · record {number}"),
                                )
                            } else {
                                NoteRef::new(
                                    RefKind::Process,
                                    format!("{run_key}/{number}"),
                                    format!(
                                        "{} {number} · {}",
                                        short_name(&name),
                                        label.to_lowercase()
                                    ),
                                )
                            };
                            candidate(category, &label, reference)
                        })
                        .collect(),
                ),
                Err(error) => Reading::Failed(error),
            };
        }
    }

    /// The entries to list now (at most [`ROWS`]) and how many there are.
    pub(super) fn entries(&self, candidates: &Candidates) -> (Vec<(Category, NoteRef)>, usize) {
        let needle = self.search.trim().to_lowercase();
        let loaded = || {
            self.processes.values().filter_map(|reading| match reading {
                Reading::Ready(list) => Some(list.iter()),
                _ => None,
            })
        };
        let wanted: Box<dyn Iterator<Item = &Candidate> + '_> = if !needle.is_empty() {
            Box::new(
                candidates
                    .list
                    .iter()
                    .chain(loaded().flatten())
                    .filter(|found| found.haystack.contains(&needle))
                    .filter(|found| {
                        self.category
                            .is_none_or(|category| found.category == category)
                            && self.sub.as_ref().is_none_or(|sub| found.sub == *sub)
                    }),
            )
        } else if let Some(category) = self.category {
            if category.from_recording() {
                let run = candidates
                    .runs
                    .iter()
                    .find(|run| Some(&run.label) == self.sub.as_ref());
                match run.and_then(|run| self.processes.get(&reading_key(category, run))) {
                    Some(Reading::Ready(list)) => Box::new(list.iter()),
                    _ => Box::new(std::iter::empty()),
                }
            } else {
                Box::new(
                    candidates
                        .list
                        .iter()
                        .filter(move |found| found.category == category)
                        .filter(|found| self.sub.as_ref().is_none_or(|sub| found.sub == *sub)),
                )
            }
        } else {
            Box::new(std::iter::empty())
        };
        let mut shown = Vec::new();
        let mut total = 0;
        for found in wanted {
            total += 1;
            if shown.len() < ROWS {
                shown.push((found.category, found.reference.clone()));
            }
        }
        (shown, total)
    }

    /// One frame of the picker; returns the reference picked, and whether it
    /// should close.
    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        candidates: &Candidates,
        taken: &[NoteRef],
    ) -> (Option<NoteRef>, bool) {
        self.poll(candidates);
        let mut picked = None;
        let mut close = false;
        let searching = !self.search.trim().is_empty();
        let hint = match self.category {
            Some(category) => format!("Search {}", category.label().to_lowercase()),
            None => "Search what this note refers to".into(),
        };
        let frame = egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .stroke(egui::Stroke::new(1.0_f32, theme::palette().line))
            .corner_radius(4)
            .inner_margin(egui::Margin::symmetric(6, 3));
        let search = frame
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(egui_phosphor::regular::MAGNIFYING_GLASS)
                            .color(theme::muted()),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text(theme::hint_text(hint))
                            .frame(false)
                            .desired_width(f32::INFINITY),
                    )
                })
                .inner
            })
            .inner;
        if self.focus {
            search.request_focus();
            self.focus = false;
        }
        let (entries, total) = self.entries(candidates);
        let shown = entries.len();
        let (down, up, enter, escape) = ui.input(|input| {
            (
                input.key_pressed(egui::Key::ArrowDown),
                input.key_pressed(egui::Key::ArrowUp),
                input.key_pressed(egui::Key::Enter),
                input.key_pressed(egui::Key::Escape),
            )
        });
        if search.has_focus() || search.lost_focus() {
            if down && shown > 0 {
                self.cursor = (self.cursor + 1).min(shown - 1);
            }
            if up {
                self.cursor = self.cursor.saturating_sub(1);
            }
        }
        if search.changed() {
            self.cursor = 0;
        }
        let mut back = escape && (search.has_focus() || search.lost_focus());
        let mut step = None;
        if back && searching {
            self.search.clear();
            self.cursor = 0;
            back = false;
        }
        if enter && search.lost_focus() && searching {
            picked = entries.get(self.cursor).map(|found| found.1.clone());
        }
        ui.add_space(4.0);
        if self.category.is_some() && !searching {
            // Where the list is: "‹ Back" and the path to the rows below.
            ui.horizontal(|ui| {
                if widgets::link(ui, "‹ Back").clicked() {
                    back = true;
                }
                if let Some(category) = self.category {
                    let mut place = category.label().to_owned();
                    if let Some(sub) = &self.sub {
                        place = format!("{place} › {sub}");
                    }
                    ui.label(RichText::new(place).color(theme::muted()))
                        .on_hover_text(category.about());
                }
            });
        }
        let height = 320.0_f32.min(ui.ctx().screen_rect().height() * 0.45);
        egui::ScrollArea::vertical()
            .id_salt("note_picker_rows")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if !searching && self.category.is_none() {
                    let mut group = "";
                    for category in Category::ALL {
                        if category.group() != group {
                            group = category.group();
                            group_title(ui, group);
                        }
                        let count = candidates.count(category);
                        let response = pick_row(
                            ui,
                            category.icon(),
                            category.label(),
                            &count.to_string(),
                            count > 0,
                            if count == 0 {
                                RowState::Empty
                            } else {
                                RowState::Normal
                            },
                        )
                        .on_hover_text(category.about());
                        if response.clicked() {
                            step = Some((Some(category), None));
                        }
                    }
                    return;
                }
                if !searching
                    && self.sub.is_none()
                    && self.category.is_some_and(Category::has_subtypes)
                {
                    let category = self.category.unwrap_or(Category::Runs);
                    for (sub, count) in candidates.subtypes(category) {
                        let right = if count > 0 {
                            count.to_string()
                        } else {
                            String::new()
                        };
                        if pick_row(ui, category.icon(), &sub, &right, true, RowState::Normal)
                            .clicked()
                        {
                            step = Some((Some(category), Some(sub)));
                        }
                    }
                    return;
                }
                if let (Some(sub), Some(category)) = (&self.sub, self.category) {
                    if category.from_recording() {
                        match candidates
                            .runs
                            .iter()
                            .find(|run| &run.label == sub)
                            .and_then(|run| self.processes.get(&reading_key(category, run)))
                        {
                            Some(Reading::Working(_)) => {
                                ui.horizontal(|ui| {
                                    theme::spinner(ui);
                                    ui.label(if category == Category::Trace {
                                        "Reading the Syscall Trace…"
                                    } else {
                                        "Reading the process tree…"
                                    });
                                });
                            }
                            Some(Reading::Failed(error)) => {
                                ui.colored_label(theme::error(), error);
                            }
                            _ => {}
                        }
                    }
                }
                if entries.is_empty() && !self.category.is_some_and(Category::from_recording) {
                    parts_line(ui, "Nothing matches.");
                }
                for (index, (category, reference)) in entries.iter().enumerate() {
                    let taken = taken.iter().any(|known| {
                        known.kind == reference.kind && known.target == reference.target
                    });
                    let text = if searching && self.category.is_none() {
                        format!("{}  ·  {}", category_word(*category), reference.label)
                    } else {
                        reference.label.clone()
                    };
                    let state = if taken {
                        RowState::Taken
                    } else if index == self.cursor {
                        RowState::Cursor
                    } else {
                        RowState::Normal
                    };
                    let response = pick_row(ui, category.icon(), &text, "", false, state)
                        .on_hover_text(&text);
                    if response.clicked() {
                        picked = Some(reference.clone());
                    }
                }
                if total > shown {
                    parts_line(ui, &format!("Showing {shown} of {total}"));
                }
                if self.category == Some(Category::Trace) && self.sub.is_some() {
                    parts_line(
                        ui,
                        &format!(
                            "The first {} calls of the run. Right-click any entry in the Syscall Trace to note one beyond them.",
                            TRACE_PAGES * TRACE_PAGE
                        ),
                    );
                }
            });
        if let Some((category, sub)) = step {
            self.category = category;
            self.sub = sub;
            self.cursor = 0;
            self.focus = true;
            if let (Some(category), Some(sub)) = (self.category, &self.sub) {
                if category.from_recording() {
                    if let Some(run) = candidates.runs.iter().find(|run| &run.label == sub) {
                        self.read_run(ui.ctx(), category, run);
                    }
                }
            }
        }
        if back {
            if self.sub.is_some() {
                self.sub = None;
            } else if self.category.is_some() {
                self.category = None;
            } else {
                close = true;
            }
            self.cursor = 0;
            self.focus = true;
        }
        (picked, close)
    }
}

pub(super) fn parts_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::muted()));
}

pub(super) fn category_word(category: Category) -> &'static str {
    match category {
        Category::Runs => "Run",
        Category::Processes => "Process",
        Category::Trace => "Trace entry",
        Category::Ioc => "IoC",
        Category::Files => "Artifact",
        Category::Custody => "Custody entry",
        Category::Lineage => "Lineage node",
    }
}

/// The last part of a path, for a process's label.
pub(super) fn short_name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}
