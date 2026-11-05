// SPDX-License-Identifier: GPL-3.0-only
//! Selection information rendered exclusively in the shared Details panel.
use super::*;

#[derive(Clone)]
struct Selection {
    table: String,
    key: String,
    headers: Vec<String>,
    cells: Vec<Cell>,
}

fn selection_id() -> egui::Id {
    egui::Id::new("triage-details-selection")
}

const TABLES: &[&str] = &[
    "triage-findings",
    "triage-process",
    "triage-opened",
    "triage-read",
    "triage-changed",
    "triage-created",
    "triage-written",
    "triage-deleted",
    "triage-renamed",
    "triage-executed",
    "triage-attributes",
    "triage-probed",
    "triage-other",
    "triage-ips",
    "triage-hosts",
    "triage-http",
    "triage-dns",
    "triage-sessions",
    "triage-endpoints",
    "triage-domains",
    "triage-tls",
    "triage-bpf",
    "triage-yara",
    "triage-ids",
    "triage-sigma",
    "file-operation-timeline",
    super::file_activity::CALLS_TABLE,
    super::file_activity::FILE_TABLE,
];

pub(super) fn clear(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.remove::<Selection>(selection_id());
        for table in TABLES {
            data.remove::<String>(egui::Id::new(("triage-selected-row", *table)));
        }
        data.remove::<trace::InvocationKey>(egui::Id::new("triage-call-jump"));
        data.remove::<u64>(egui::Id::new("triage-packet-jump"));
        data.remove::<std::path::PathBuf>(egui::Id::new("triage-packet-capture"));
        data.remove::<antinomie_monitor_core::analysis::detection::Evidence>(egui::Id::new(
            "triage-byte-jump",
        ));
        data.remove::<bool>(egui::Id::new("triage-details-focus"));
    });
}

pub(super) fn clicked(ctx: &egui::Context, table: &str) {
    if table != "file-operation-timeline" {
        ctx.data_mut(|data| data.insert_temp(egui::Id::new("triage-details-focus"), true));
    }
}

/// The table of the row Details shows now.
#[cfg(test)]
pub(super) fn selected_table(ctx: &egui::Context) -> Option<String> {
    ctx.data(|data| data.get_temp::<Selection>(selection_id()))
        .map(|selection| selection.table)
}

pub(super) fn select(ctx: &egui::Context, table: &str, headers: &[&str], cells: &[Cell]) {
    // Timeline rows are already inside the selected changed file's Details.
    if table == "file-operation-timeline" {
        return;
    }
    ctx.data_mut(|data| {
        data.insert_temp(
            selection_id(),
            Selection {
                table: table.into(),
                key: evidence_key(cells),
                headers: headers.iter().map(|header| (*header).into()).collect(),
                cells: cells.to_vec(),
            },
        )
    });
}

pub(super) fn refresh(ctx: &egui::Context, table: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    let selected_id = egui::Id::new(("triage-selected-row", table));
    let selected = ctx.data(|data| data.get_temp::<String>(selected_id));
    if let Some(cells) = rows.iter().find(|row| Some(evidence_key(row)) == selected) {
        // Do not replace another table's most recently clicked selection.
        let owns = ctx
            .data(|data| data.get_temp::<Selection>(selection_id()))
            .is_some_and(|selection| selection.table == table);
        if owns {
            select(ctx, table, headers, cells);
        }
    } else {
        ctx.data_mut(|data| {
            data.remove::<String>(selected_id);
            if data
                .get_temp::<Selection>(selection_id())
                .is_some_and(|selection| selection.table == table)
            {
                data.remove::<Selection>(selection_id());
            }
        });
    }
}

fn title(table: &str) -> &str {
    match table {
        "triage-findings" => "Suspicious activity",
        "triage-process" => "Process",
        "triage-opened" => "Opened file",
        "triage-read" => "Read file",
        "triage-changed" => "Changed file",
        "triage-created" => "Created file",
        "triage-written" => "Written file",
        "triage-deleted" => "Deleted file",
        "triage-renamed" => "Renamed file",
        "triage-executed" => "Executed file",
        "triage-attributes" => "File attribute change",
        "triage-probed" => "Probed file",
        "triage-other" => "File operation",
        "triage-ips" => "Destination IP",
        "triage-hosts" => "Host",
        "triage-http" => "HTTP request",
        "triage-dns" => "DNS request",
        "triage-sessions" => "Network session",
        "triage-bpf" => "BPF observation",
        "triage-file-calls" => "File call",
        "triage-file-history" => "File history",
        _ => "Selected evidence",
    }
}

pub(super) fn refresh_findings(
    ctx: &egui::Context,
    table: &str,
    headers: &[&str],
    rows: &[Finding],
) {
    let Some(selected) = ctx
        .data(|data| data.get_temp::<Selection>(selection_id()))
        .filter(|selection| selection.table == table)
    else {
        return;
    };
    if let Some(finding) = rows
        .iter()
        .find(|finding| evidence_values_key(&finding.values) == selected.key)
    {
        let mut cells = finding.cells.clone();
        if let Some(first) = cells.first_mut() {
            first.values.clone_from(&finding.values);
        }
        select(ctx, table, headers, &cells);
    } else {
        ctx.data_mut(|data| data.remove::<Selection>(selection_id()));
    }
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui) {
    let Some(selected) = ui
        .ctx()
        .data(|data| data.get_temp::<Selection>(selection_id()))
    else {
        ui.weak("Select a row to see its details.");
        return;
    };
    if selected.table == ioc_view::DETAILS_TABLE {
        let id = selected.cells.get(2).map_or("", |cell| cell.text.as_str());
        egui::ScrollArea::vertical()
            .id_salt("triage-shared-details")
            .auto_shrink([false, false])
            .show(ui, |ui| view.ioc_details(ui, id));
        return;
    }
    egui::ScrollArea::vertical().id_salt("triage-shared-details")
        .auto_shrink([false, false]).show(ui, |ui| {
        presentation::heading(ui, title(&selected.table), "");
        if selected.table == "triage-findings" {
            let values = selected.cells.first().map(|cell| cell.values.clone()).unwrap_or_default();
            let process = selected.cells.get(rules::COL_PROCESS).map_or("", |cell| cell.text.as_str());
            view.finding_details(ui, &values, process);
            observed_fields(ui, &values);
            return;
        }
        presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::Grid::new("triage-detail-values").num_columns(2).spacing(egui::vec2(14.0, 9.0))
            .max_col_width((ui.available_width() * 0.7).max(80.0)).show(ui, |ui| {
        for (header, cell) in selected.headers.iter().zip(&selected.cells) {
            ui.label(RichText::new(header).small().color(theme::muted()));
            let text = RichText::new(&cell.text).color(cell.color());
            ui.add(egui::Label::new(if cell.mono { text.monospace() } else { text }).wrap());
            ui.end_row();
        }
        });
        });
        ui.add_space(10.0);
        let values = selected.cells.first().map(|cell| cell.values.as_slice()).unwrap_or_default();
        if matches!(selected.table.as_str(), "triage-yara" | "triage-ids" | "triage-sigma") { view.detection.details(ui, values); }
        if selected.table == "triage-changed" {
            disk_diff_link(ui, &selected);
            if let Some(change) = view.scan.as_ref().and_then(|scan| scan.file_changes.iter().find(|change| change.evidence_key() == selected.key)) {
                if ui.button("Per-file history").on_hover_text("Open this file in the Per-file history tab").clicked() {
                    view.file_history.open_on(&change.path);
                    view.history_tab = true;
                }
                change.show(ui, view.scan.as_ref().and_then(|scan| scan.clock_anchor));
            } else {
                crate::activity::error(ui, "This file's retained differences are no longer available in the current index; refresh the Triage index.");
            }
        } else if selected.table == "triage-process" {
            process_details::show(view, ui, values);
        } else if selected.table == "triage-bpf" {
            if let Some(note) = view.scan.as_ref().and_then(|scan| scan.bpf.iter().find(|note| evidence_key(&bpf_row(note, scan_clock(view))) == selected.key)) {
                bpf_detail(ui, note, view.details_directory.as_deref(), &mut view.bpf_export_status);
            } else {
                ui.weak("This BPF observation is not available in the retained index yet.");
            }
        }
        observed_fields(ui, values);
        if files::number(values, "event.id").is_some()
            && files::number(values, "stream.id").is_some()
            && files::number(values, "process.cookie").is_some()
            && files::number(values, "frame.number").is_none()
            && ui.button("Open original syscall").clicked()
        { request_evidence_jump(ui.ctx(), values); }
        if files::number(values, "frame.number").is_some()
            && ui.button("Open original packet").clicked() {
                request_evidence_jump(ui.ctx(), values);
        }
        for frame in selected.headers.iter().zip(&selected.cells)
            .filter(|(header, _)| header.as_str() == "Response frame")
            .flat_map(|(_, cell)| cell.text.split(','))
            .filter_map(|frame| frame.trim().parse::<u64>().ok()).filter(|frame| *frame > 0).take(32) {
            if ui.button(format!("Open response packet #{frame}")).clicked() {
                let mut response_values = values.to_vec(); response_values.retain(|(name, _)| *name != "frame.number"); response_values.push(("frame.number", RowValue::Number(i128::from(frame))));
                request_evidence_jump(ui.ctx(), &response_values);
            }
        }
    });
}

/// Every value the row carries, folded: for a check against the other sections.
fn observed_fields(ui: &mut egui::Ui, values: &[(&'static str, RowValue)]) {
    if values.is_empty() {
        return;
    }
    egui::CollapsingHeader::new("Observed fields").show(ui, |ui| {
        for (name, value) in values {
            ui.colored_label(theme::muted(), *name);
            let text = match value {
                RowValue::Text(value) => value.clone(),
                RowValue::Number(value) => u64::try_from(*value)
                    .ok()
                    .filter(|_| *name == "file.fd")
                    .and_then(crate::values::standard_fd_name)
                    .map_or_else(|| value.to_string(), |role| format!("{value} ({role})")),
                RowValue::Bool(value) => value.to_string(),
                RowValue::List(values) => values.join(", "),
                RowValue::Missing => "Unavailable".into(),
            };
            ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
        }
    });
}

/// "Dump taken" under a finding that triggered one, with a link to the tab.
pub(super) fn dump_taken(ui: &mut egui::Ui, values: &[(&'static str, RowValue)]) {
    use antinomie_monitor_core::dump_trigger::TriggerLog;
    let Some(log) = ui.ctx().data(|data| {
        data.get_temp::<std::sync::Arc<TriggerLog>>(egui::Id::new(super::TRIGGER_LOG))
    }) else {
        return;
    };
    let key = (
        files::number(values, "stream.id"),
        files::number(values, "process.cookie"),
        files::number(values, "event.id"),
    );
    let Some(record) = log.records.iter().find(|record| {
        let f = &record.finding;
        key == (Some(f.stream_id), Some(f.task_cookie), Some(f.call_id))
    }) else {
        return;
    };
    ui.label(RichText::new("Dumps taken").strong().color(theme::text()));
    for (name, dump, tab) in [
        ("Memory dump", &record.memory, "memory"),
        ("Core", &record.core, "core"),
    ] {
        let Some(dump) = dump else { continue };
        ui.horizontal_wrapped(|ui| {
            let size = dump
                .size
                .map(|size| format!(" ({})", antinomie_monitor_core::byte_size::short_size(size)))
                .unwrap_or_default();
            ui.label(format!("{name}{size}: {:?}", dump.state));
            if ui
                .link(if tab == "memory" {
                    "Open Memory dumps"
                } else {
                    "Open Core dumps"
                })
                .clicked()
            {
                ui.ctx().data_mut(|data| {
                    data.insert_temp(egui::Id::new(super::OPEN_DUMP_TAB), tab);
                });
            }
        });
        if let Some(error) = &dump.error {
            ui.colored_label(theme::warn(), error);
        }
    }
    ui.add_space(8.0);
}

/// The Trace filter that shows the calls a finding cites, in its process when
/// the task cookie is known.
fn evidence_filter(cookie: Option<u64>, calls: &[u64]) -> String {
    let set = calls
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    match cookie.filter(|cookie| *cookie != 0) {
        Some(cookie) => format!("process.cookie == {cookie} && call.id in {{{set}}}"),
        None => format!("call.id in {{{set}}}"),
    }
}

/// "Show the N calls in Syscall Trace" for a finding whose detail lines cite
/// more calls than its own (an anti-analysis row lists each check's call):
/// Open original syscall below goes to the first one only.
pub(super) fn evidence_link(ui: &mut egui::Ui, values: &[(&'static str, RowValue)]) {
    let calls = super::digest::evidence_calls(values);
    if calls.len() < 2 {
        return;
    }
    let label = format!("Show the {} calls in Syscall Trace", calls.len());
    if ui
        .button(label)
        .on_hover_text("Open Syscall Trace filtered to the calls these lines cite")
        .clicked()
    {
        let filter = evidence_filter(files::number(values, "process.cookie"), &calls);
        ui.ctx().data_mut(|data| {
            data.insert_temp(egui::Id::new(process_details::TRACE_SCOPE), filter);
        });
    }
    ui.add_space(8.0);
}

fn scan_clock(view: &TriageView) -> Option<antinomie_monitor_core::HostClockAnchor> {
    view.scan
        .as_ref()
        .and_then(|scan| scan.clock_anchor)
        .or(view.scan_request.clock_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finding_citing_several_calls_offers_them_all_in_trace() {
        let values = vec![
            ("event.id", RowValue::Number(12)),
            ("process.cookie", RowValue::Number(7)),
            (
                "finding.detail",
                RowValue::List(vec![
                    "DMI: product_name [read] → \"Q35\"  (call 12)".into(),
                    "MAC: address [read] → \"52:54\"  (call 40)".into(),
                ]),
            ),
        ];
        let calls = super::super::digest::evidence_calls(&values);
        assert_eq!(calls, vec![12, 40]);
        assert_eq!(
            evidence_filter(files::number(&values, "process.cookie"), &calls),
            "process.cookie == 7 && call.id in {12, 40}"
        );
        assert_eq!(evidence_filter(Some(0), &[5]), "call.id in {5}");
    }

    #[test]
    fn row_clicks_show_information_only_in_the_shared_details_area() {
        for table_id in TABLES.iter().filter(|id| **id != "file-operation-timeline") {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut row = vec![cell("select this observation", theme::text(), false)];
            row[0].values = vec![("frame.number", RowValue::Number(520))];
            let rows = vec![row];
            let mut view = TriageView::default();
            let mut draw = |events, time| {
                ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1400.0, 800.0),
                        )),
                        events,
                        time: Some(time),
                        ..Default::default()
                    },
                    |root| {
                        egui::Panel::right("shared-details")
                            .exact_size(400.0)
                            .show(root, |ui| {
                                view.details(ui);
                            });
                        egui::CentralPanel::default()
                            .show(root, |ui| table(ui, table_id, &["Observation"], &rows));
                    },
                )
            };
            for n in 0..3 {
                draw(vec![], n as f64 * 0.01);
            }
            let output = draw(vec![], 0.04);
            let pos = crate::app::tests::texts(&output)
                .into_iter()
                .find(|(text, rect)| text == "select this observation" && rect.center().x < 900.0)
                .unwrap()
                .1
                .center();
            for (n, pressed) in [true, false].into_iter().enumerate() {
                draw(
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    0.1 + n as f64 * 0.05,
                );
            }
            let output = draw(vec![], 0.3);
            let labels = crate::app::tests::texts(&output);
            let evidence = labels
                .iter()
                .find(|(text, _)| text == "Open original packet")
                .expect(table_id);
            assert!(
                evidence.1.left() >= 990.0,
                "{table_id}: detail action escaped the shared panel"
            );
            assert!(!labels
                .iter()
                .any(|(text, rect)| text == "Selected evidence" && rect.left() < 990.0));
            assert!(
                ctx.data(|data| data.get_temp::<u64>(egui::Id::new("triage-packet-jump")))
                    .is_none(),
                "single click must not navigate"
            );
        }
    }

    #[test]
    fn suspicious_activity_click_selects_shared_details_without_inline_fields() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut call = super::super::tests::call(1, 9, "mmap", 4096);
        call.entry.as_mut().unwrap().args = Some([0, 4096, 7, 0, 0, 0]);
        let findings = suspicious_rows(&[call]);
        assert!(!findings.is_empty());
        let label = findings[0].cells[rules::COL_BEHAVIOUR].text.clone();
        let mut view = TriageView::default();
        let mut draw = |events, time| {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400.0, 900.0),
                    )),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |root| {
                    egui::Panel::right("shared-details")
                        .exact_size(400.0)
                        .show(root, |ui| {
                            view.details(ui);
                        });
                    egui::CentralPanel::default().show(root, |ui| {
                        view.suspicious_findings(ui, findings.clone(), 0);
                    });
                },
            )
        };
        for n in 0..3 {
            draw(vec![], n as f64 * 0.01);
        }
        let output = draw(vec![], 0.04);
        let pos = crate::app::tests::texts(&output)
            .into_iter()
            .find(|(text, _)| text == &label)
            .unwrap()
            .1
            .center();
        for (n, pressed) in [true, false].into_iter().enumerate() {
            draw(
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                0.1 + n as f64 * 0.05,
            );
        }
        let output = draw(vec![], 0.3);
        let labels = crate::app::tests::texts(&output);
        assert!(labels
            .iter()
            .any(|(text, rect)| text == "Open in Syscall Trace" && rect.left() >= 990.0));
        assert!(!labels.iter().any(|(text, _)| text.contains(": Text(")));
        assert!(view.take_details_focus(&ctx));
    }

    #[test]
    fn refreshed_findings_update_selected_time_and_clear_filtered_out_details() {
        let ctx = egui::Context::default();
        let mut call = super::super::tests::call(1, 9, "mmap", 4096);
        call.entry.as_mut().unwrap().args = Some([0, 4096, 7, 0, 0, 0]);
        let mut rows = suspicious_rows(&[call]);
        let mut cells = rows[0].cells.clone();
        cells[0].values.clone_from(&rows[0].values);
        select(&ctx, "triage-findings", &["Rule"], &cells);
        rows[0].cells[5].text = "~16:00:00 (UTC+7)".into();
        refresh_findings(&ctx, "triage-findings", &["Rule"], &rows);
        assert_eq!(
            ctx.data(|data| data.get_temp::<Selection>(selection_id()))
                .unwrap()
                .cells[5]
                .text,
            "~16:00:00 (UTC+7)"
        );
        refresh_findings(&ctx, "triage-findings", &["Rule"], &[]);
        assert!(ctx
            .data(|data| data.get_temp::<Selection>(selection_id()))
            .is_none());
    }

    #[test]
    fn changing_run_clears_shared_information_and_old_row_highlights() {
        let ctx = egui::Context::default();
        let mut row = vec![cell("old run evidence", theme::text(), false)];
        row[0].values = vec![("event.id", RowValue::Number(1))];
        select(&ctx, "triage-read", &["Path"], &row);
        ctx.data_mut(|data| {
            data.insert_temp(
                egui::Id::new(("triage-selected-row", "triage-read")),
                evidence_key(&row),
            )
        });
        let mut view = TriageView::default();
        view.context_key = Some("vm\nboot\nold\n".into());
        view.tick(
            &ctx,
            TriageInput {
                vm_id: Some("vm"),
                boot_id: Some("boot"),
                run_id: Some("new"),
                ..TriageInput::empty()
            },
        );
        assert!(ctx
            .data(|data| data.get_temp::<Selection>(selection_id()))
            .is_none());
        assert!(ctx
            .data(|data| data
                .get_temp::<String>(egui::Id::new(("triage-selected-row", "triage-read"))))
            .is_none());
    }

    #[test]
    fn findings_on_the_same_call_keep_distinct_selected_information() {
        let ctx = egui::Context::default();
        let mut row = vec![cell("first rule", theme::text(), false)];
        row[0].values = vec![
            ("stream.id", RowValue::Number(1)),
            ("process.cookie", RowValue::Number(2)),
            ("event.id", RowValue::Number(3)),
            ("finding.rule", RowValue::Text("first".into())),
        ];
        select(&ctx, "triage-findings", &["Rule"], &row);
        let first = ctx
            .data(|data| data.get_temp::<Selection>(selection_id()))
            .unwrap();
        row[0].values.last_mut().unwrap().1 = RowValue::Text("second".into());
        select(&ctx, "triage-findings", &["Rule"], &row);
        let second = ctx
            .data(|data| data.get_temp::<Selection>(selection_id()))
            .unwrap();
        assert_ne!(first.key, second.key);
    }
}

/// Block evidence meets syscall evidence: when the Disks tab is showing a
/// diff that lists this path, say so and offer the jump. The diff is
/// between two disk images; this row is what the kernel was observed doing
/// in one run. Neither proves the other.
fn disk_diff_link(ui: &mut egui::Ui, selected: &Selection) {
    let Some(path) = selected
        .headers
        .iter()
        .position(|header| header == "Path")
        .and_then(|index| selected.cells.get(index))
        .and_then(|cell| crate::disk_view::normalize_guest_path(&cell.text))
    else {
        return;
    };
    let listed = ui
        .ctx()
        .data(|data| {
            data.get_temp::<std::sync::Arc<std::collections::BTreeSet<String>>>(egui::Id::new(
                crate::disk_view::DIFF_PATHS_KEY,
            ))
        })
        .is_some_and(|paths| paths.contains(&path));
    if !listed {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.colored_label(
            theme::muted(),
            "Syscall evidence: this row is what was observed in the run. The Disks tab diff lists \
             the same path as block evidence: it differs between two disk images.",
        );
        if ui.button("Show in the Disks diff").clicked() {
            ui.ctx().data_mut(|data| {
                data.insert_temp(egui::Id::new(crate::disk_view::DIFF_JUMP_KEY), path.clone());
            });
        }
    });
    ui.add_space(6.0);
}

#[cfg(test)]
mod disk_link_tests {
    use super::*;
    use crate::{
        app::tests::texts,
        disk_view::{DIFF_JUMP_KEY, DIFF_PATHS_KEY},
        triage::table::cell,
    };
    use std::{collections::BTreeSet, sync::Arc};

    fn changed(path: &str) -> Selection {
        Selection {
            table: "triage-changed".into(),
            key: "key".into(),
            headers: vec!["Time".into(), "Path".into()],
            cells: vec![
                cell("12:00:00", theme::text(), true),
                cell(path, theme::text(), true),
            ],
        }
    }

    fn frame(
        ctx: &egui::Context,
        selection: &Selection,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 400.0),
                )),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| disk_diff_link(ui, selection));
            },
        )
    }

    fn publish(ctx: &egui::Context, paths: &[&str]) {
        let set: BTreeSet<String> = paths.iter().map(|path| path.to_string()).collect();
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(DIFF_PATHS_KEY), Arc::new(set)));
    }

    const LABEL: &str = "Show in the Disks diff";

    fn shown(output: &egui::FullOutput) -> Vec<String> {
        texts(output).into_iter().map(|(text, _)| text).collect()
    }

    #[test]
    fn a_changed_file_in_the_disk_diff_links_there_and_says_what_kind_of_evidence_each_is() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let selection = changed("/etc/passwd");
        // No diff open: nothing is offered.
        for _ in 0..2 {
            assert!(!shown(&frame(&ctx, &selection, Vec::new())).contains(&LABEL.to_string()));
        }
        publish(&ctx, &["/etc/passwd", "/etc/other"]);
        let mut output = frame(&ctx, &selection, Vec::new());
        for _ in 0..2 {
            output = frame(&ctx, &selection, Vec::new());
        }
        let seen = shown(&output);
        assert!(seen.contains(&LABEL.to_string()), "{seen:?}");
        assert!(
            seen.iter().any(|text| text
                .starts_with("Syscall evidence: this row is what was observed")
                && text.contains("block evidence")),
            "{seen:?}"
        );
        let position = texts(&output)
            .into_iter()
            .find(|(text, _)| text == LABEL)
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            frame(
                &ctx,
                &selection,
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        let jump = ctx.data(|data| data.get_temp::<String>(egui::Id::new(DIFF_JUMP_KEY)));
        assert_eq!(jump.as_deref(), Some("/etc/passwd"));
        // The path is spelled the way the diff spells it.
        let selection = changed("/etc//passwd/");
        assert!(shown(&frame(&ctx, &selection, Vec::new())).contains(&LABEL.to_string()));
        // A path that is not in the diff, and a relative one, get no link.
        for path in ["/var/log/other", "etc/passwd", ""] {
            let selection = changed(path);
            assert!(!shown(&frame(&ctx, &selection, Vec::new())).contains(&LABEL.to_string()));
        }
    }

    #[test]
    fn show_changed_path_opens_changed_files_filtered_to_one_path() {
        let ctx = egui::Context::default();
        let mut view = TriageView::default();
        view.show_changed_path(&ctx, "/etc/passwd");
        assert!(matches!(view.section, Section::Files));
        assert!(view.files == FileTab::Changed);
        let draft = |ctx: &egui::Context| {
            ctx.data_mut(|data| {
                data.remove_temp::<String>(egui::Id::new((
                    "triage-filter-draft",
                    FileTab::Changed.slot(),
                )))
            })
        };
        assert_eq!(draft(&ctx).as_deref(), Some("file.path == \"/etc/passwd\""));
        // A name the filter cannot quote shows the tab unfiltered.
        view.show_changed_path(&ctx, "/tmp/we\"ird");
        assert_eq!(draft(&ctx), None);
        // The Disks tab's request is taken once.
        assert_eq!(view.take_disk_jump(&ctx), None);
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(DIFF_JUMP_KEY), "/x".to_string()));
        assert_eq!(view.take_disk_jump(&ctx).as_deref(), Some("/x"));
        assert_eq!(view.take_disk_jump(&ctx), None);
        assert!(view.changed_paths().is_empty());
    }
}
