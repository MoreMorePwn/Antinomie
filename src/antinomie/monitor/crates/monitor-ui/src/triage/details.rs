// SPDX-License-Identifier: MIT
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
    "triage-ips",
    "triage-hosts",
    "triage-http",
    "triage-dns",
    "triage-bpf",
    "triage-yara",
    "triage-ids",
    "triage-sigma",
    "file-operation-timeline",
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
        "triage-ips" => "Destination IP",
        "triage-hosts" => "Host",
        "triage-http" => "HTTP request",
        "triage-dns" => "DNS request",
        "triage-bpf" => "BPF observation",
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
        ui.weak("Select an entry in Triage to inspect it here.");
        return;
    };
    egui::ScrollArea::vertical().id_salt("triage-shared-details")
        .auto_shrink([false, false]).show(ui, |ui| {
        presentation::heading(ui, title(&selected.table), "Selected evidence");
        presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::Grid::new("triage-detail-values").num_columns(2).spacing(egui::vec2(14.0, 9.0))
            .max_col_width((ui.available_width() * 0.7).max(80.0)).show(ui, |ui| {
        for (header, cell) in selected.headers.iter().zip(&selected.cells) {
            ui.label(RichText::new(header).small().color(theme::muted()));
            let text = RichText::new(&cell.text).color(cell.color);
            ui.add(egui::Label::new(if cell.mono { text.monospace() } else { text }).wrap());
            ui.end_row();
        }
        });
        });
        ui.add_space(10.0);
        let values = selected.cells.first().map(|cell| cell.values.as_slice()).unwrap_or_default();
        if matches!(selected.table.as_str(), "triage-yara" | "triage-ids" | "triage-sigma") { view.detection.details(ui, values); }
        if selected.table == "triage-changed" {
            if let Some(change) = view.scan.as_ref().and_then(|scan| scan.file_changes.iter().find(|change| change.evidence_key() == selected.key)) {
                change.show(ui, view.scan.as_ref().and_then(|scan| scan.clock_anchor));
            } else {
                ui.colored_label(theme::warn(), "This file's retained differences are no longer available in the current index.");
            }
        } else if selected.table == "triage-bpf" {
            if let Some(note) = view.scan.as_ref().and_then(|scan| scan.bpf.iter().find(|note| evidence_key(&bpf_row(note, scan_clock(view))) == selected.key)) {
                bpf_detail(ui, note, view.details_directory.as_deref(), &mut view.bpf_export_status);
            } else {
                ui.weak("This BPF observation is not available in the retained index yet.");
            }
        }
        if !values.is_empty() {
            egui::CollapsingHeader::new("Observed fields").show(ui, |ui| {
                for (name, value) in values {
                    ui.colored_label(theme::muted(), *name);
                    let text = match value {
                        RowValue::Text(value) => value.clone(),
                        RowValue::Number(value) => u64::try_from(*value).ok()
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
        if files::number(values, "event.id").is_some()
            && files::number(values, "stream.id").is_some()
            && files::number(values, "process.cookie").is_some()
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
    fn row_clicks_show_information_only_in_the_shared_details_area() {
        for table_id in TABLES.iter().filter(|id| **id != "file-operation-timeline") {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut row = vec![cell("select this observation", theme::text(), false)];
            row[0].values = vec![("frame.number", RowValue::Number(520))];
            let rows = vec![row];
            let mut view = TriageView::default();
            let mut draw = |events, time| {
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1400.0, 800.0),
                        )),
                        events,
                        time: Some(time),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::SidePanel::right("shared-details")
                            .exact_width(400.0)
                            .show(ctx, |ui| {
                                view.details(ui);
                            });
                        egui::CentralPanel::default()
                            .show(ctx, |ui| table(ui, table_id, &["Observation"], &rows));
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
        let label = findings[0].cells[0].text.clone();
        let mut view = TriageView::default();
        let mut draw = |events, time| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400.0, 900.0),
                    )),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |ctx| {
                    egui::SidePanel::right("shared-details")
                        .exact_width(400.0)
                        .show(ctx, |ui| {
                            view.details(ui);
                        });
                    egui::CentralPanel::default().show(ctx, |ui| {
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
            .any(|(text, rect)| text == "Open original syscall" && rect.left() >= 990.0));
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
        rows[0].cells[5].text = "~16:00:00 (UTC+07:00)".into();
        refresh_findings(&ctx, "triage-findings", &["Rule"], &rows);
        assert_eq!(
            ctx.data(|data| data.get_temp::<Selection>(selection_id()))
                .unwrap()
                .cells[5]
                .text,
            "~16:00:00 (UTC+07:00)"
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
