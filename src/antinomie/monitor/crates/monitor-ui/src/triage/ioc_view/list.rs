// SPDX-License-Identifier: GPL-3.0-only
//! One IOC tab: the filter, the verdict chips, the rows and the details of
//! the selected one.
use super::*;
use crate::{
    query::{self, FieldSpec, RowValue},
    widgets::table,
};
use antinomie_monitor_core::ioc::indicator::Jump as Evidence;
use egui_extras::{Column, TableBuilder};

/// Where a jump to evidence goes.
pub(in crate::triage) enum Jump {
    Packet { capture: String, frame: u64 },
    Call { stream: u64, cookie: u64, call: u64 },
    Properties,
}

pub(in crate::triage) const FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("ioc.type", "endpoint, domain, url, tls or file"),
    FieldSpec::text("ioc.value", "The indicator as the row shows it"),
    FieldSpec::text("ioc.match", "matched, known_fp, no_match or not_checked"),
    FieldSpec::tags("ioc.source", "pcap, syscall, disk or static"),
    FieldSpec::text("ioc.process", "The one process that made a matching call"),
    FieldSpec::text("ioc.dataset", "The dataset that lists it"),
    FieldSpec::text("ioc.family", "The family the record names"),
    FieldSpec::number("ioc.confidence", "The record's confidence, when it has one"),
    FieldSpec::number("ioc.first_us", "First seen in the run, Unix microseconds"),
    FieldSpec::number("ioc.last_us", "Last seen in the run, Unix microseconds"),
    FieldSpec::text("tls.sni", "TLS server name"),
    FieldSpec::text("tls.ja3", "JA3 client fingerprint"),
    FieldSpec::text("tls.ja4", "JA4 client fingerprint"),
    FieldSpec::text("tls.ja3s", "JA3S server fingerprint"),
    FieldSpec::text("tls.cert", "Certificate SHA-1"),
    FieldSpec::tags(
        "file.role",
        "sample, created, executed, deleted, written at close, changed",
    ),
    FieldSpec::text("file.path", "Path in the guest"),
    FieldSpec::text("file.sha256", "SHA-256 of the content"),
];

fn example(ty: Type) -> &'static str {
    match ty {
        Type::Endpoint => "ioc.match == matched",
        Type::Domain => "ioc.value contains example",
        Type::Url => "ioc.value contains .kd",
        Type::Tls => "tls.ja3 == \"f6d64cbcb6dead5e8e864400f056fa32\"",
        Type::File => "file.role contains executed",
    }
}

/// The rows a filter keeps.
pub(super) struct Listing {
    key: String,
    rows: Vec<usize>,
}

fn text(value: &str) -> RowValue {
    if value.is_empty() {
        RowValue::Missing
    } else {
        RowValue::Text(value.to_owned())
    }
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Matched => "matched",
        Outcome::KnownFp => "known_fp",
        Outcome::NoMatch => "no_match",
        Outcome::NotChecked => "not_checked",
    }
}

/// The values a filter can read from one row.
pub(super) fn values(indicator: &Indicator, verdict: &Verdict) -> Vec<(&'static str, RowValue)> {
    let tls = indicator.tls.clone().unwrap_or_default();
    let primary = verdict
        .primary()
        .or_else(|| verdict.excused.as_ref().map(|(found, _)| found));
    let hash = indicator
        .hashes
        .as_ref()
        .map(|hashes| hashes.sha256.as_str())
        .unwrap_or("");
    vec![
        ("ioc.type", RowValue::Text(indicator.ty.id().into())),
        ("ioc.value", RowValue::Text(indicator.value.clone())),
        (
            "ioc.match",
            RowValue::Text(outcome_name(verdict.outcome).into()),
        ),
        (
            "ioc.source",
            RowValue::List(
                indicator
                    .sources
                    .iter()
                    .map(|s| s.label().to_owned())
                    .collect(),
            ),
        ),
        (
            "ioc.process",
            indicator
                .process
                .as_ref()
                .map_or(RowValue::Missing, |process| RowValue::Text(process.label())),
        ),
        (
            "ioc.dataset",
            primary.map_or(RowValue::Missing, |found| text(&found.record.feed)),
        ),
        (
            "ioc.family",
            primary.map_or(RowValue::Missing, |found| text(&found.record.family)),
        ),
        (
            "ioc.confidence",
            primary
                .and_then(|found| found.record.confidence)
                .map_or(RowValue::Missing, |c| RowValue::Number(i128::from(c))),
        ),
        (
            "ioc.first_us",
            indicator
                .first_us
                .map_or(RowValue::Missing, |us| RowValue::Number(i128::from(us))),
        ),
        (
            "ioc.last_us",
            indicator
                .last_us
                .map_or(RowValue::Missing, |us| RowValue::Number(i128::from(us))),
        ),
        ("tls.sni", text(&tls.sni)),
        ("tls.ja3", text(&tls.ja3)),
        ("tls.ja4", text(&tls.ja4)),
        ("tls.ja3s", text(&tls.ja3s)),
        ("tls.cert", text(&tls.cert_sha1)),
        (
            "file.role",
            RowValue::List(indicator.roles.iter().map(|r| (*r).to_owned()).collect()),
        ),
        ("file.path", text(&indicator.path)),
        ("file.sha256", text(hash)),
    ]
}

fn time_text(us: Option<u64>) -> String {
    us.map_or("—".into(), crate::time_format::short_time_us)
}

impl View {
    pub(super) fn list_tab(&mut self, ui: &mut egui::Ui, ioc: &IocScan, ty: Type) -> Option<Jump> {
        let all = self.count_of(Some(ty));
        // The filter bar.
        let draft = self.drafts.entry(ty).or_default();
        ui.horizontal_wrapped(|ui| {
            query::filter_edit_fields(
                ui,
                draft,
                example(ty),
                (ui.available_width() * 0.45).clamp(220.0, 520.0),
                FIELDS,
                &[],
            );
            let outcome = &mut self.outcome;
            widgets::segmented(
                ui,
                [
                    (None, TabItem::new(format!("All {}", all.all()))),
                    (
                        Some(Outcome::Matched),
                        TabItem::new(format!("Matched {}", all.matched)),
                    ),
                    (
                        Some(Outcome::KnownFp),
                        TabItem::new(format!("Known FP {}", all.known_fp)),
                    ),
                    (
                        Some(Outcome::NoMatch),
                        TabItem::new(format!("No match {}", all.no_match)),
                    ),
                    (
                        Some(Outcome::NotChecked),
                        TabItem::new(format!("Not checked {}", all.not_checked)),
                    ),
                ],
                outcome,
            );
        });
        let filter = self.drafts.get(&ty).cloned().unwrap_or_default();
        let compiled = query::compile_table(&filter, FIELDS);
        if let Some(error) = &compiled.error {
            crate::activity::warning(ui, format!("{error}; showing every row"));
        }
        let key = format!("{:?}|{:?}|{filter}", self.made_from, self.outcome);
        let stale = self
            .listings
            .get(&ty)
            .is_none_or(|listing| listing.key != key);
        if stale {
            let rows = (0..ioc.indicators.len())
                .filter(|&at| {
                    let (indicator, verdict) = (&ioc.indicators[at], &self.verdicts[at]);
                    indicator.ty == ty
                        && self.outcome.is_none_or(|wanted| verdict.outcome == wanted)
                        && (compiled.error.is_some()
                            || compiled.keep_table(&values(indicator, verdict)))
                })
                .collect();
            self.listings.insert(ty, Listing { key, rows });
        }
        let rows: Vec<usize> = self.listings[&ty].rows.clone();
        let mut export = None;
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(theme::muted(), format!("{} of {}", rows.len(), all.all()));
            ui.menu_button("Export…", |ui| {
                ui.label("The rows listed, with dataset dates and verdicts");
                if ui.button("CSV").clicked() {
                    export = Some(false);
                    ui.close_menu();
                }
                if ui.button("JSON").clicked() {
                    export = Some(true);
                    ui.close_menu();
                }
            });
        });
        if let Some(json) = export {
            self.export(ioc, ty, &rows, json);
        }
        if ty == Type::Url {
            ui.colored_label(
                theme::muted(),
                "Encrypted request contents are unavailable. HTTP/2 is listed only when it is cleartext (h2c).",
            );
        }
        if ty == Type::Tls {
            ui.colored_label(
                theme::muted(),
                "JA4 and JA3S have no abuse.ch feed: they are shown, not matched.",
            );
        }
        let selected = self
            .selected
            .get(&ty)
            .and_then(|id| {
                rows.iter()
                    .copied()
                    .find(|&at| ioc.indicators[at].id() == *id)
            })
            .or_else(|| rows.first().copied());
        let mut jump = None;
        let mut picked = None;
        let width = ui.available_width();
        let height = ui.available_height().max(260.0);
        if width >= 980.0 {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(width - 392.0, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        picked = self.table(ui, ioc, ty, &rows, selected, &mut jump);
                    },
                );
                ui.add_space(8.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(380.0, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt(("ioc-detail", ty.id()))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if let Some(next) = self.detail(ui, ioc, selected) {
                                    jump = Some(next);
                                }
                            });
                    },
                );
            });
        } else {
            picked = self.table(ui, ioc, ty, &rows, selected, &mut jump);
            if let Some(next) = self.detail(ui, ioc, selected) {
                jump = Some(next);
            }
        }
        if let Some(at) = picked {
            self.selected.insert(ty, ioc.indicators[at].id());
        }
        jump
    }

    fn table(
        &mut self,
        ui: &mut egui::Ui,
        ioc: &IocScan,
        ty: Type,
        rows: &[usize],
        selected: Option<usize>,
        jump: &mut Option<Jump>,
    ) -> Option<usize> {
        if rows.is_empty() {
            ui.add_space(8.0);
            ui.colored_label(
                theme::muted(),
                if ty == Type::Tls && ioc.capture == Capture::Off {
                    "Nothing was collected."
                } else if ioc.indicators.iter().any(|i| i.ty == ty) {
                    "Nothing matches this filter."
                } else {
                    "No indicators of this type in this run."
                },
            );
            return None;
        }
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = table::row_height(font) + 6.0;
        let mut picked = None;
        let height = ui.available_height().max(180.0);
        egui::ScrollArea::horizontal()
            .id_salt(("ioc-table", ty.id()))
            .show(ui, |ui| {
                ui.set_min_width(760.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt(("ioc-rows", ty.id()))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::initial(280.0).at_least(160.0).clip(true))
                    .column(Column::exact(120.0))
                    .column(Column::exact(130.0))
                    .column(Column::exact(96.0))
                    .column(Column::exact(96.0))
                    .column(Column::remainder().at_least(140.0).clip(true))
                    .column(Column::exact(70.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        let first = match ty {
                            Type::Endpoint => "Endpoint",
                            Type::Domain => "Domain",
                            Type::Url => "URL",
                            Type::Tls => "Server name",
                            Type::File => "SHA-256",
                        };
                        for title in [
                            first, "Sources", "Process", "First", "Last", "Match", "Evidence",
                        ] {
                            header.col(|ui| table::head(ui, title));
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, rows.len(), |mut row| {
                            let at = rows[row.index()];
                            let (indicator, verdict) = (&ioc.indicators[at], &self.verdicts[at]);
                            row.set_selected(selected == Some(at));
                            row.col(|ui| {
                                let value = if ty == Type::File && indicator.hashes.is_some() {
                                    let hash = &indicator.value;
                                    format!(
                                        "{}…{}",
                                        &hash[..16.min(hash.len())],
                                        &hash[hash.len().saturating_sub(8)..]
                                    )
                                } else {
                                    indicator.value.clone()
                                };
                                let sub = if ty == Type::File {
                                    format!("{} · {}", indicator.path, indicator.roles.join(", "))
                                } else {
                                    indicator.sub.clone()
                                };
                                let mut job = egui::text::LayoutJob::default();
                                job.append(
                                    &value,
                                    0.0,
                                    egui::TextFormat::simple(
                                        egui::TextStyle::Monospace.resolve(ui.style()),
                                        theme::text(),
                                    ),
                                );
                                job.append(
                                    &format!("   {sub}"),
                                    0.0,
                                    egui::TextFormat::simple(
                                        egui::TextStyle::Small.resolve(ui.style()),
                                        theme::muted(),
                                    ),
                                );
                                ui.add(egui::Label::new(job).selectable(false).truncate());
                            });
                            row.col(|ui| {
                                ui.horizontal_wrapped(|ui| {
                                    for source in &indicator.sources {
                                        widgets::chip(ui, source.label(), source_tone(*source));
                                    }
                                });
                            });
                            row.col(|ui| {
                                let (text, muted) =
                                    match (&indicator.process, indicator.candidates.len()) {
                                        (Some(process), _) => (process.label(), false),
                                        (None, n) if n > 0 => (format!("{n} candidates"), true),
                                        _ if indicator.sources.contains(&Source::Pcap)
                                            && !indicator.sources.contains(&Source::Syscall) =>
                                        {
                                            ("unattributed".to_owned(), true)
                                        }
                                        _ => ("—".to_owned(), true),
                                    };
                                table::cell_rich(
                                    ui,
                                    table::Cell::Text,
                                    RichText::new(text).color(if muted {
                                        theme::muted()
                                    } else {
                                        theme::text()
                                    }),
                                );
                            });
                            row.col(|ui| {
                                table::cell_click(
                                    ui,
                                    table::Cell::Mono,
                                    &time_text(indicator.first_us),
                                );
                            });
                            row.col(|ui| {
                                table::cell_click(
                                    ui,
                                    table::Cell::Mono,
                                    &time_text(indicator.last_us),
                                );
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    verdict_chip(ui, verdict);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(verdict_line(verdict))
                                                .small()
                                                .color(theme::muted()),
                                        )
                                        .selectable(false)
                                        .truncate(),
                                    );
                                });
                            });
                            row.col(|ui| {
                                if let Some(evidence) = indicator.evidence.first() {
                                    if ui
                                        .small_button("Jump ▸")
                                        .on_hover_text(&evidence.label)
                                        .clicked()
                                    {
                                        *jump = jump_of(&evidence.jump);
                                    }
                                }
                            });
                            if row.response().clicked() {
                                picked = Some(at);
                            }
                        });
                    });
            });
        picked
    }

    /// Write the rows listed as CSV or JSON beside the run's other files.
    pub(super) fn export(&mut self, ioc: &IocScan, ty: Type, rows: &[usize], json: bool) {
        let Some(dir) = self.run_dir.clone() else {
            self.message("This run has no folder to write to.", true);
            return;
        };
        let pairs: Vec<(&Indicator, &Verdict)> = rows
            .iter()
            .map(|&at| (&ioc.indicators[at], &self.verdicts[at]))
            .collect();
        let text = if json {
            export::json(&pairs)
        } else {
            export::csv(&pairs)
        };
        let name = format!(
            "ioc-{}-{}.{}",
            ty.id(),
            feeds::now_unix(),
            if json { "json" } else { "csv" }
        );
        match write_new(&dir.join("ioc"), &name, text.as_bytes()) {
            Ok(path) => self.message(
                format!("Exported {} rows to {}", pairs.len(), path.display()),
                false,
            ),
            Err(error) => self.message(error, true),
        }
    }
}

/// Create `dir/name` (private, never replacing a file) and write `bytes`.
fn write_new(
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, String> {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

pub(super) fn source_tone(source: Source) -> Tone {
    match source {
        Source::Pcap => Tone::Info,
        Source::Syscall => Tone::Accent,
        Source::Disk => Tone::Good,
        Source::Static => Tone::Neutral,
    }
}

pub(super) fn jump_of(jump: &Evidence) -> Option<Jump> {
    match jump {
        Evidence::Packet { capture, frame } => Some(Jump::Packet {
            capture: capture.clone(),
            frame: *frame,
        }),
        Evidence::Call {
            stream,
            cookie,
            call,
        } => Some(Jump::Call {
            stream: *stream,
            cookie: *cookie,
            call: *call,
        }),
        Evidence::Text => Some(Jump::Properties),
    }
}
