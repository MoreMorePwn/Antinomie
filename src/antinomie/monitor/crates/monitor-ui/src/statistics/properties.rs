// SPDX-License-Identifier: GPL-3.0-only
//! The Properties tab (design 2.2): what the run was, what the recording holds,
//! and how far it can be trusted. The rows are built by pure functions so the
//! tab, the clipboard and the export read the same text.
use super::TimeBase;
use antinomie_monitor_core::api::HostClockAnchor;
use antinomie_monitor_core::{CaptureSummary, RunSummary};
use antinomie_triage::statistics::export::{Cell, Table};
use antinomie_triage::statistics::quality::{Quality, QualitySource};
use antinomie_triage::statistics::RunStatistics;
use eframe::egui;

/// What the app knows about the run or capture that the recording does not say.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Facts {
    /// Rows of the Run (or Capture) block that need no recording.
    pub run: Vec<(String, String)>,
    /// Rows of the Guest block.
    pub guest: Vec<(String, String)>,
    pub started_ms: Option<u64>,
    pub anchor: Option<HostClockAnchor>,
    /// Tasks the guest counted (`total_task_count`).
    pub tasks_counted: Option<u64>,
    /// The run's notes, as Run History shows them.
    pub notes: Vec<String>,
    /// A capture, not a run: no run rows.
    pub capture: bool,
}

impl Facts {
    /// The facts of a run; `state` is the words Run History uses for its state.
    pub(crate) fn of_run(run: &RunSummary, state: &str) -> Self {
        let mut program = run.request.path.clone();
        for arg in &run.request.args {
            program.push(' ');
            program.push_str(arg);
        }
        let mut rows = vec![
            ("Program".to_owned(), program),
            ("Run id".to_owned(), run.id.clone()),
        ];
        let vm = run
            .environment
            .as_ref()
            .map(|e| e.vm_name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| run.vm_id.clone());
        rows.push(("VM".to_owned(), vm));
        rows.push(("State".to_owned(), state.to_owned()));
        rows.push((
            "Stopped by you".to_owned(),
            if run.stopped_by_user { "yes" } else { "no" }.to_owned(),
        ));
        let guest = run
            .environment
            .as_ref()
            .map(|env| {
                let accelerator = if env.accelerator.is_empty() {
                    "not recorded".to_owned()
                } else {
                    env.accelerator.clone()
                };
                let revision = |revision: Option<u32>| {
                    revision.map_or_else(String::new, |n| format!(" (revision {n})"))
                };
                vec![
                    (
                        "Base".to_owned(),
                        format!("{}{}", env.base_name, revision(env.base_revision)),
                    ),
                    (
                        "Kernel".to_owned(),
                        format!("{}{}", env.kernel_release, revision(env.kernel_revision)),
                    ),
                    ("Architecture".to_owned(), env.arch.label()),
                    ("Accelerator".to_owned(), accelerator),
                    ("vCPUs".to_owned(), env.cpus.to_string()),
                    ("RAM".to_owned(), format!("{} MiB", env.ram_mib)),
                    ("Stealth profile".to_owned(), env.stealth.clone()),
                    ("Network".to_owned(), env.network.clone()),
                ]
            })
            .unwrap_or_default();
        Self {
            run: rows,
            guest,
            started_ms: run.started_ms,
            anchor: run.clock_anchor,
            tasks_counted: run.execution.as_ref().map(|e| e.total_task_count),
            notes: run.notes.clone(),
            capture: false,
        }
    }

    pub(crate) fn of_capture(capture: &CaptureSummary, state: &str, scope: &str) -> Self {
        Self {
            run: vec![
                ("Capture id".to_owned(), capture.id.clone()),
                ("VM".to_owned(), capture.vm_id.clone()),
                ("State".to_owned(), state.to_owned()),
                ("Scope".to_owned(), scope.to_owned()),
            ],
            started_ms: capture.started_ms,
            capture: true,
            notes: capture.incomplete_reason.iter().cloned().collect(),
            ..Self::default()
        }
    }
}

/// How serious a row is, for its colour and its icon.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Tone {
    #[default]
    Plain,
    Warn,
    Bad,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Row {
    pub label: String,
    pub value: String,
    pub hint: String,
    pub tone: Tone,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Block {
    pub title: &'static str,
    pub rows: Vec<Row>,
}

impl Row {
    fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            hint: String::new(),
            tone: Tone::Plain,
        }
    }

    fn hint(mut self, hint: &str) -> Self {
        self.hint = hint.into();
        self
    }

    fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }
}

const BOOT: &str = "This VM boot's figure, not the run's alone.";

/// "not recorded" for a figure the manifest does not carry.
fn figure(value: Option<u64>) -> String {
    value.map_or_else(|| "not recorded".into(), super::int)
}

fn tone_of(value: Option<u64>) -> Tone {
    if value.is_some_and(|n| n > 0) {
        Tone::Warn
    } else {
        Tone::Plain
    }
}

/// All the blocks of the tab. `host_now_ms` is not needed: every figure is the recording's.
pub(crate) fn blocks(facts: &Facts, stats: &RunStatistics, base: TimeBase) -> Vec<Block> {
    vec![
        run_block(facts, &stats.quality),
        guest_block(facts, &stats.quality),
        recording_block(facts, stats, base),
        transport_block(&stats.quality),
        quality_block(facts, stats),
    ]
    .into_iter()
    .filter(|block| !block.rows.is_empty())
    .collect()
}

fn run_block(facts: &Facts, quality: &Quality) -> Block {
    let mut rows: Vec<Row> = facts
        .run
        .iter()
        .map(|(label, value)| Row::new(label, value))
        .collect();
    let started = facts.started_ms.or(quality.started_ms);
    let host = |ms: u64| crate::time_format::local_seconds(ms / 1000);
    rows.push(Row::new(
        "Started",
        started.map_or_else(|| "not recorded".into(), host),
    ));
    rows.push(Row::new(
        "Ended",
        quality.ended_ms.map_or_else(|| "not recorded".into(), host),
    ));
    if let (Some(start), Some(end)) = (started, quality.ended_ms) {
        rows.push(
            Row::new(
                "Duration",
                super::duration_ns(end.saturating_sub(start) * 1_000_000),
            )
            .hint("Host clock, from the launch to the end of the recording."),
        );
    }
    Block {
        title: if facts.capture { "Capture" } else { "Run" },
        rows,
    }
}

fn guest_block(facts: &Facts, quality: &Quality) -> Block {
    let mut rows: Vec<Row> = facts
        .guest
        .iter()
        .map(|(label, value)| {
            let mut row = Row::new(label, value);
            if label == "Accelerator" && quality.accelerator.is_none() {
                row.tone = Tone::Warn;
            }
            row
        })
        .collect();
    if rows.is_empty() && !facts.capture {
        rows.push(Row::new("Environment", "not recorded"));
    }
    Block {
        title: "Guest",
        rows,
    }
}

fn recording_block(facts: &Facts, stats: &RunStatistics, base: TimeBase) -> Block {
    let anchor = facts.anchor;
    let at = |ns: Option<u64>| {
        ns.map_or_else(
            || "none".into(),
            |ns| super::time_text(base, ns, stats.first_ns, anchor),
        )
    };
    let mut rows = vec![Row::new("Calls in the view", super::int(stats.calls)).hint(
        "Calls of this run's program that pass the filter. Click a count in Hierarchy to see them in the Syscall Trace.",
    )];
    rows.push(Row::new("First call", at(stats.first_ns)));
    rows.push(Row::new("Last call", at(stats.last_ns)));
    if let (Some(first), Some(last)) = (stats.first_ns, stats.last_ns) {
        let span = last.saturating_sub(first);
        rows.push(Row::new("Span", super::duration_ns(span)));
        if span > 0 {
            let rate = stats.calls as f64 * 1e9 / span as f64;
            rows.push(Row::new("Average calls/s", format!("{rate:.1}")));
        }
    }
    if let Some(peak) = stats.peak_per_s {
        let rate = peak.calls as f64 * 1e9 / peak.span_ns.max(1) as f64;
        let over = if peak.span_ns > 1_500_000_000 {
            format!(" (busiest {})", super::duration_ns(peak.span_ns))
        } else {
            String::new()
        };
        rows.push(Row::new("Peak calls/s", format!("{rate:.0}{over}")).hint(
            "The busiest second, from the Call rate bins; wider bins make it the busiest bin.",
        ));
    }
    let ids = |capped: antinomie_triage::statistics::aggregate::Capped| {
        if stats.pid_not_recorded {
            "not recorded".to_owned()
        } else if capped.at_least {
            format!("at least {}", super::int(capped.count))
        } else {
            super::int(capped.count)
        }
    };
    rows.push(Row::new("Processes seen", ids(stats.processes)));
    rows.push(Row::new("Threads seen", ids(stats.threads)));
    if let Some(tasks) = facts.tasks_counted {
        rows.push(Row::new("Tasks the guest counted", super::int(tasks)));
    }
    if let Some(packets) = stats.quality.packets {
        let bytes = stats.quality.bytes.map_or_else(String::new, |bytes| {
            format!(
                " · {}",
                antinomie_monitor_core::byte_size::short_size(bytes)
            )
        });
        rows.push(Row::new(
            "Packets saved",
            format!("{}{bytes}", super::int(packets)),
        ));
    }
    rows.push(
        Row::new("Calls with no result recorded", super::int(stats.no_result)).hint(&format!(
            "{} of them ended their task (exit, exit_group, a fatal signal); the others never returned or their exit was lost.",
            super::int(stats.ended_task)
        )),
    );
    if stats.out_of_scope > 0 {
        rows.push(
            Row::new("Calls of other programs", super::int(stats.out_of_scope))
                .hint("Calls in this recording that belong to another launched program; they are not counted here, the Syscall Trace lists them.")
                .tone(Tone::Warn),
        );
    }
    Block {
        title: "Recording",
        rows,
    }
}

fn transport_block(quality: &Quality) -> Block {
    let mut rows = Vec::new();
    if let Some(wait) = quality.send_wait_us {
        rows.push(
            Row::new(
                "Transport policy",
                if wait == 0 {
                    "drop mode: a full ring drops the packet".to_owned()
                } else {
                    format!("never-drop: the guest waits up to {wait} µs for room")
                },
            )
            .hint(BOOT),
        );
    }
    if let Some(size) = quality.ring_size {
        rows.push(
            Row::new(
                "Ring size per vCPU",
                antinomie_monitor_core::byte_size::short_size(u64::from(size)),
            )
            .hint(BOOT),
        );
    }
    Block {
        title: "Transport policy",
        rows,
    }
}

fn quality_block(facts: &Facts, stats: &RunStatistics) -> Block {
    let q = &stats.quality;
    let mut rows = Vec::new();
    match q.source {
        QualitySource::Missing => rows.push(
            Row::new("Recording quality", "not recorded")
                .hint("The run has no manifest figures; nothing is known about loss.")
                .tone(Tone::Warn),
        ),
        QualitySource::SealedEarly => rows.push(
            Row::new(
                "Recording quality",
                "sealed early: only the telemetry loss is known",
            )
            .tone(Tone::Warn),
        ),
        QualitySource::Finalized => {}
    }
    if let Some(loss) = q.telemetry_lost {
        let value = if loss.lost_packets == 0 {
            "none seen missing".to_owned()
        } else {
            format!(
                "at least {} of {} packets ({:.2} %)",
                super::int(loss.lost_packets),
                super::int(loss.received_packets.saturating_add(loss.lost_packets)),
                loss.percent()
            )
        };
        rows.push(
            Row::new("Telemetry lost", value)
                .hint("A lower bound. Calls that lost every packet are missing from the trace, the findings and the counts.")
                .tone(if loss.lost_packets > 0 { Tone::Bad } else { Tone::Plain }),
        );
    }
    rows.push(
        Row::new("Dropped by the transport", figure(q.transport_dropped))
            .hint("Guest sends given up after the whole wait. This VM boot's figure.")
            .tone(match q.transport_dropped {
                Some(n) if n > 0 => Tone::Bad,
                _ => Tone::Plain,
            }),
    );
    rows.push(
        Row::new("Not saved by the recorder", figure(q.storage_dropped))
            .hint("Packets the host received but could not write.")
            .tone(match q.storage_dropped {
                Some(n) if n > 0 => Tone::Bad,
                _ => Tone::Plain,
            }),
    );
    rows.push(
        Row::new("Screen previews dropped", figure(q.ui_dropped)).hint(
            "Live preview rows the window skipped. Not a recording loss. This VM boot's figure.",
        ),
    );
    rows.push(
        Row::new("Async observations lost", figure(q.async_lost))
            .hint("io_uring and similar completions the guest could not report.")
            .tone(tone_of(q.async_lost)),
    );
    rows.push(
        Row::new("Credential and hash notes lost", figure(q.guest_note_lost))
            .tone(tone_of(q.guest_note_lost)),
    );
    rows.push(match &q.reduced {
        None => Row::new("Reduced recording", "no"),
        Some(reduced) => Row::new(
            "Reduced recording",
            format!(
                "from the switch on, only calls the Triage rules read were kept; {} calls not saved",
                super::int(reduced.dropped_total())
            ),
        )
        .tone(Tone::Warn),
    });
    match &q.read_gaps {
        Some(gaps) => {
            rows.push(
                Row::new(
                    "Host read gaps",
                    format!(
                        "{} · {} in all · longest {}",
                        super::int(gaps.count),
                        super::duration_ns(gaps.total_ns),
                        super::duration_ns(gaps.longest_ns)
                    ),
                )
                .hint(BOOT)
                .tone(tone_of(Some(gaps.count))),
            );
            rows.push(
                Row::new(
                    "Full-ring spells",
                    format!(
                        "{} · {} in all · longest {}",
                        super::int(gaps.full_spell_count),
                        super::duration_ns(gaps.full_spell_total_ns),
                        super::duration_ns(gaps.full_spell_longest_ns)
                    ),
                )
                .hint(BOOT)
                .tone(tone_of(Some(gaps.full_spell_count))),
            );
        }
        None => rows.push(Row::new("Host read gaps", "not recorded")),
    }
    rows.push(match q.guest_send_waits {
        Some(waits) => Row::new(
            "Guest send waits",
            format!(
                "{} times · {} in all",
                super::int(waits.count),
                super::duration_ns(waits.total_ns)
            ),
        )
        .hint("Guest sends that found the ring full and waited. This VM boot's figure.")
        .tone(tone_of(Some(waits.count))),
        None => Row::new("Guest send waits", "not recorded"),
    });
    rows.push(match q.writer_held_ns {
        Some(held) => Row::new("Writer held", super::duration_ns(held))
            .hint("The host stopped taking telemetry because the disk writer was behind. This VM boot's figure.")
            .tone(tone_of(Some(held))),
        None => Row::new("Writer held", "not recorded"),
    });
    rows.push(match q.shedding {
        Some(shedding) => Row::new(
            "Shedding",
            if shedding.shed_count == 0 && !shedding.active {
                "none".to_owned()
            } else {
                format!(
                    "{} dropped over {}",
                    super::int(shedding.shed_count),
                    super::duration_ns(shedding.shed_ns)
                )
            },
        )
        .hint("Capture All dropped telemetry to keep the guest responsive. This VM boot's figure.")
        .tone(tone_of(Some(shedding.shed_count))),
        None => Row::new("Shedding", "not recorded"),
    });
    if !facts.notes.is_empty() {
        rows.push(Row::new("Run notes", facts.notes.join(" · ")));
    }
    Block {
        title: "Quality",
        rows,
    }
}

/// The blocks as one table (block, field, value) for Copy and Export.
pub(crate) fn table(blocks: &[Block]) -> Table {
    Table {
        name: "properties",
        columns: vec!["block".into(), "field".into(), "value".into()],
        rows: blocks
            .iter()
            .flat_map(|block| {
                block.rows.iter().map(|row| {
                    vec![
                        Cell::Text(block.title.into()),
                        Cell::Text(row.label.clone()),
                        Cell::Text(row.value.clone()),
                    ]
                })
            })
            .collect(),
    }
}

/// Draw the blocks, each a two-column table that copies as a whole.
/// `scroll_to_quality`: bring the Quality block into view (a quality chip was clicked).
pub(super) fn show(ui: &mut egui::Ui, blocks: &[Block], scroll_to_quality: bool) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for block in blocks {
                ui.add_space(6.0);
                let heading = crate::theme::section(ui, block.title);
                if scroll_to_quality && block.title == "Quality" {
                    heading.scroll_to_me(Some(egui::Align::TOP));
                }
                egui::Grid::new(("statistics-properties", block.title))
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for row in &block.rows {
                            let label = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&row.label).color(crate::theme::muted()),
                                )
                                .selectable(true),
                            );
                            if !row.hint.is_empty() {
                                label.on_hover_text(&row.hint);
                            }
                            let color = match row.tone {
                                Tone::Plain => crate::theme::text(),
                                Tone::Warn => crate::theme::warn(),
                                Tone::Bad => crate::theme::error(),
                            };
                            let text = match row.tone {
                                Tone::Plain => row.value.clone(),
                                Tone::Warn => {
                                    format!("{}  {}", egui_phosphor::regular::WARNING, row.value)
                                }
                                Tone::Bad => format!(
                                    "{}  {}",
                                    egui_phosphor::regular::WARNING_OCTAGON,
                                    row.value
                                ),
                            };
                            let value = ui.add(
                                egui::Label::new(egui::RichText::new(text).color(color)).wrap(),
                            );
                            if !row.hint.is_empty() {
                                value.on_hover_text(&row.hint);
                            }
                            ui.end_row();
                        }
                    });
            }
        });
}
