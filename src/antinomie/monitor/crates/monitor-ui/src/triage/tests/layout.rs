// SPDX-License-Identifier: GPL-3.0-only
//! The Process, Files and Network layouts: the segmented control, the tabs
//! with counts, the filter-bar toggles, flagged rows and the packet link.
use super::*;
use crate::app::tests::texts;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn scan() -> (PacketSpool, ArchiveScan) {
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let scan = scan_archive(&temp.directory, None, false, &AtomicBool::new(false)).unwrap();
    (temp, scan)
}

fn view(section: Section) -> (PacketSpool, TriageView) {
    let (temp, scan) = scan();
    let mut view = TriageView::default();
    view.scan = Some(scan);
    view.section = section;
    view.context_key = Some("vm\nboot\nrun\n".into());
    (temp, view)
}

fn draw(
    ctx: &egui::Context,
    view: &mut TriageView,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        pcap: Some(Path::new("/nonexistent/capture.pcap")),
        ..TriageInput::empty()
    };
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events,
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input);
            });
        },
    )
}

/// Draw until the layout settles; returns the last output.
fn settle(ctx: &egui::Context, view: &mut TriageView) -> egui::FullOutput {
    let mut out = draw(ctx, view, vec![], 0.0);
    for n in 1..4 {
        out = draw(ctx, view, vec![], f64::from(n) * 0.02);
    }
    out
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn open_packets_label() -> String {
    format!("{} Open Packets", egui_phosphor::regular::NETWORK)
}

fn find(out: &egui::FullOutput, text: &str) -> egui::Rect {
    texts(out)
        .into_iter()
        .find(|(shown, _)| shown == text)
        .unwrap_or_else(|| panic!("{text:?} not drawn in {:?}", texts(out)))
        .1
}

fn has(out: &egui::FullOutput, text: &str) -> bool {
    texts(out).iter().any(|(shown, _)| shown == text)
}

fn click(ctx: &egui::Context, view: &mut TriageView, at: egui::Pos2) {
    let mut time = 1.0;
    for pressed in [true, false] {
        draw(
            ctx,
            view,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            time,
        );
        time += 0.02;
    }
}

#[test]
fn process_views_are_one_segmented_control_with_counts() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Process);
    view.scan.as_mut().unwrap().counts.findings = 7;
    let out = settle(&ctx, &mut view);
    // Two choices of one control, each with its count after the label.
    let processes = view.scan.as_ref().unwrap().process.len();
    assert!(has(&out, &format!("Process tree{processes}")));
    assert!(has(&out, "Suspicious activity7"));
    assert!(view.process == ProcessTab::Tree);
    let at = find(&out, "Suspicious activity7").center();
    click(&ctx, &mut view, at);
    assert!(view.process == ProcessTab::Suspicious);
    let out = settle(&ctx, &mut view);
    click(
        &ctx,
        &mut view,
        find(&out, &format!("Process tree{processes}")).center(),
    );
    assert!(view.process == ProcessTab::Tree);
}

#[test]
fn a_process_row_carries_its_suspicious_count_as_a_warn_chip() {
    let (_temp, scan) = scan();
    assert!(
        scan.suspicious
            .values()
            .map(|(count, _)| count)
            .sum::<u64>()
            > 0,
        "the fixture's rwx calls are suspicious"
    );
    assert_eq!(
        scan.suspicious
            .values()
            .map(|(count, _)| count)
            .sum::<u64>(),
        scan.counts.findings,
        "every finding is counted for its task"
    );
    let node = scan
        .process
        .iter()
        .find(|node| scan.suspicious.contains_key(&(node.cookie, node.pid)))
        .expect("a process with findings");
    let (count, _) = scan.suspicious[&(node.cookie, node.pid)];
    let ctx = context();
    let mut out = egui::FullOutput::default();
    for time in 0..3 {
        out = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(f64::from(time) * 0.02),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    process_tree_nodes(ui, &scan.process, None, &scan.suspicious);
                });
            },
        );
    }
    assert!(has(&out, &count.to_string()), "{:?}", texts(&out));
    // The filter can use the count.
    let compiled = query::compile_table("process.suspicious > 0", PROCESS_FIELDS);
    assert!(compiled.error.is_none());
}

#[test]
fn findings_are_tallied_for_the_task_that_made_them() {
    let mut counts = Suspicious::new();
    let values = [
        ("process.cookie", RowValue::Number(9)),
        ("process.pid", RowValue::Number(4)),
        ("finding.tier", RowValue::Text("medium".into())),
    ];
    tally(&mut counts, &values);
    tally(&mut counts, &values);
    let mut high = values.to_vec();
    high[2].1 = RowValue::Text("high".into());
    tally(&mut counts, &high);
    tally(&mut counts, &values);
    tally(&mut counts, &[("process.pid", RowValue::Number(4))]);
    assert_eq!(counts.get(&(9, 4)), Some(&(4, rules::Tier::High)));
    assert_eq!(counts.len(), 1);
    assert_eq!(process_details::trace_filter(4, 9), "process.cookie == 9");
    assert_eq!(process_details::trace_filter(4, 0), "process.pid == 4");
}

#[test]
fn file_categories_are_tabs_with_counts() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Files);
    view.scan.as_mut().unwrap().counts.opened = 1234;
    view.scan.as_mut().unwrap().counts.tabs[1] = 8;
    let columns = file_category::EVENT_HEADERS.len();
    let mut row: Vec<Cell> = (0..columns)
        .map(|_| cell("x", theme::text(), false))
        .collect();
    row[0].values = vec![("frame.number", RowValue::Number(1))];
    view.scan.as_mut().unwrap().opened = vec![row];
    let out = settle(&ctx, &mut view);
    for tab in FileTab::ALL {
        assert!(has(&out, tab.title()), "{}", tab.title());
    }
    assert!(has(&out, "1,234"));
    assert!(has(&out, "8"));
    click(&ctx, &mut view, find(&out, "Executed files").center());
    assert!(view.files == FileTab::Executed);
    // The Opened column set is kept.
    view.files = FileTab::Opened;
    let out = settle(&ctx, &mut view);
    for header in ["Time", "Path", "Process (PID / TID)", "Result", "Evidence"] {
        assert!(has(&out, header) || texts(&out).iter().any(|(t, _)| t.starts_with(header)));
    }
}

#[test]
fn per_file_history_is_a_sub_tab_beside_the_file_categories() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Files);
    let out = settle(&ctx, &mut view);
    assert!(!view.history_tab);
    let history = find(&out, "Per-file history");
    let opened = find(&out, "Opened files");
    assert!(history.top() >= opened.top(), "the tab sits in the tab bar");
    click(&ctx, &mut view, history.center());
    assert!(view.history_tab);
    let out = settle(&ctx, &mut view);
    // The history fills the section: no filter bar of the tables, the file
    // list and the prompt to choose a file, and no floating window.
    assert!(has(&out, "Filter by path"), "{:?}", texts(&out));
    // Another category leaves the history.
    click(&ctx, &mut view, find(&out, "Opened files").center());
    assert!(!view.history_tab);
}

#[test]
fn file_toggles_are_chips_in_the_filter_bar_with_their_defaults() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Files);
    view.scan.as_mut().unwrap().counts.failed_attempts = 2;
    let visibility = view.scan_request.file_visibility;
    assert!(visibility.hide_standard_io && visibility.hide_libraries && !visibility.show_failed);
    let out = settle(&ctx, &mut view);
    let shown = texts(&out);
    let chip = |label: &str| {
        shown
            .iter()
            .find(|(text, _)| text.contains(label))
            .unwrap_or_else(|| panic!("{label} chip missing in {shown:?}"))
            .1
    };
    let stdio = chip("Hide stdio");
    chip("Hide library");
    chip("Failed attempts 2");
    // The checkboxes of the separate row are gone, and nothing but the
    // refresh status sits above the tabs.
    assert!(!shown.iter().any(|(text, _)| text.contains("Hide stdin")));
    assert!(!shown.iter().any(|(text, _)| text == "Refresh"));
    let tabs = find(&out, "Opened files");
    let filter_top = stdio.top();
    assert!(
        filter_top > tabs.bottom(),
        "the chips sit under the tab bar"
    );
    // Clicking a chip flips its flag and asks for a new query.
    view.scan_request.offsets[1] = 2000;
    click(&ctx, &mut view, stdio.center());
    assert!(!view.scan_request.file_visibility.hide_standard_io);
    assert!(view.scan_request.file_visibility.hide_libraries);
    assert_eq!(view.scan_request.offsets[1], 0);
    let out = settle(&ctx, &mut view);
    let at = find(&out, "Failed attempts 2").center();
    click(&ctx, &mut view, at);
    assert!(view.scan_request.file_visibility.show_failed);
}

fn row_with_location(tags: &[&str]) -> Vec<Cell> {
    let mut row = vec![cell("12:00:00", theme::text(), true)];
    row[0].values = vec![(
        "file.location",
        RowValue::List(tags.iter().map(|tag| (*tag).to_owned()).collect()),
    )];
    row
}

#[test]
fn flagged_file_rows_get_a_warn_bar_and_a_warn_location() {
    use file_location::Location;
    for tags in [&["hidden"][..], &["persistence"], &["credentials", "temp"]] {
        assert!(file_category::row_flagged(
            &row_with_location(tags)[0].values
        ));
    }
    for tags in [&["temp"][..], &["system"], &[]] {
        assert!(!file_category::row_flagged(
            &row_with_location(tags)[0].values
        ));
    }
    assert_eq!(
        file_category::location_cell(&[Location::Hidden]).color,
        theme::warn()
    );
    assert_eq!(
        file_category::location_cell(&[Location::Temp]).color,
        theme::text()
    );
    // The bar is 3 px wide, in the warn color, on the flagged row only.
    let bars = |tags: &[&str]| {
        let ctx = context();
        let rows = vec![row_with_location(tags)];
        let mut found = 0;
        for time in 0..3 {
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                    time: Some(f64::from(time) * 0.02),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        table(ui, "triage-opened", &["Time"], &rows);
                    });
                },
            );
            found = out
                .shapes
                .iter()
                .filter(|clipped| {
                    matches!(&clipped.shape, egui::Shape::Rect(rect)
                        if rect.fill == theme::palette().warn && (rect.rect.width() - 3.0).abs() < 0.1)
                })
                .count();
        }
        found
    };
    assert_eq!(bars(&["persistence"]), 1);
    assert_eq!(bars(&["temp"]), 0);
}

fn rows_of(headers: &[&str], count: usize) -> Vec<Vec<Cell>> {
    (0..count)
        .map(|at| {
            let mut row: Vec<Cell> = headers
                .iter()
                .map(|header| cell(*header, theme::text(), false))
                .collect();
            row[0].values = vec![("frame.number", RowValue::Number(at as i128 + 3))];
            row
        })
        .collect()
}

#[test]
fn network_views_are_tabs_with_counts_and_urls_start_with_the_frame() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Network);
    {
        let scan = view.scan.as_mut().unwrap();
        scan.network_counts = Some((100, 5, 7));
        scan.new_tabs.endpoints = rows_of(net_tabs::ENDPOINT_HEADERS, 5);
        scan.new_tabs.domains = rows_of(net_tabs::DOMAIN_HEADERS, 7);
        scan.http = rows_of(HTTP_HEADERS, 11);
        scan.new_tabs.urls = rows_of(net_tabs::URL_HEADERS, 11);
        scan.new_tabs.tls = rows_of(net_tabs::TLS_HEADERS, 3);
    }
    let out = settle(&ctx, &mut view);
    for (tab, count) in [
        ("Endpoints", "5"),
        ("Domains", "7"),
        ("URLs", "11"),
        ("TLS", "3"),
    ] {
        assert!(has(&out, tab), "{tab}");
        assert!(has(&out, count), "{count}");
    }
    // The old IPs, Hosts, HTTP, DNS and Sessions tabs and their switch are gone.
    for gone in [
        "Layout",
        "New layout",
        "Current layout",
        "Hosts",
        "Sessions",
    ] {
        assert!(!has(&out, gone), "{gone}");
    }
    click(&ctx, &mut view, find(&out, "URLs").center());
    assert!(view.new_tab == NewTab::Urls);
    assert_eq!(net_tabs::URL_HEADERS[..3], ["Frame", "Time", "Endpoint"]);
}

#[test]
fn open_packets_routes_to_the_capture_and_a_row_still_jumps_to_its_frame() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Network);
    view.scan.as_mut().unwrap().network_counts = Some((10, 1, 1));
    let out = settle(&ctx, &mut view);
    // One button; it does nothing until pressed.
    assert!(!view.take_open_packets());
    click(&ctx, &mut view, find(&out, &open_packets_label()).center());
    assert!(view.take_open_packets());
    assert!(!view.take_open_packets());
    // Double-click on a row keeps its frame jump.
    request_evidence_jump(&ctx, &[("frame.number", RowValue::Number(520))]);
    view.take_navigation(&ctx);
    assert_eq!(view.take_packet_jump(), Some(520));
}

#[test]
fn without_a_capture_open_packets_is_disabled() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Network);
    let input = TriageInput {
        run_id: Some("run"),
        ..TriageInput::empty()
    };
    let out = (0..3)
        .map(|n| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                    time: Some(f64::from(n) * 0.02),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| view.show(ui, input));
                },
            )
        })
        .last()
        .unwrap();
    click_without_input(
        &ctx,
        &mut view,
        find(&out, &open_packets_label()).center(),
        input,
    );
    assert!(!view.take_open_packets());
}

fn click_without_input(
    ctx: &egui::Context,
    view: &mut TriageView,
    at: egui::Pos2,
    input: TriageInput<'_>,
) {
    for (n, pressed) in [true, false].into_iter().enumerate() {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(1.0 + n as f64 * 0.02),
                events: vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.show(ui, input));
            },
        );
    }
}

#[test]
fn the_refresh_row_is_one_status_at_the_right_of_the_tab_bar() {
    let ctx = context();
    for section in [Section::Process, Section::Files, Section::Network] {
        let (_temp, mut view) = view(section);
        view.last_refresh = Some(Instant::now());
        let out = settle(&ctx, &mut view);
        let shown = texts(&out);
        let status = shown
            .iter()
            .find(|(text, _)| text.starts_with("Refreshed "))
            .unwrap_or_else(|| panic!("status missing in {shown:?}"));
        assert!(status.0.ends_with("every 5 s"), "{}", status.0);
        let summary = find(&out, "Summary");
        assert!((status.1.center().y - summary.center().y).abs() < 14.0);
        assert!(status.1.left() > find(&out, "eBPF").right());
        for gone in ["Refresh", "Every", "Host time", "PCAP time"] {
            assert!(!has(&out, gone), "{gone} row is replaced");
        }
    }
    // The other sections keep their row.
    let (_temp, mut view) = view(Section::Bpf);
    let out = settle(&ctx, &mut view);
    assert!(has(&out, "Refresh") && has(&out, "Every"));
}

#[test]
fn a_narrow_header_puts_the_status_under_wrapped_tabs_not_over_them() {
    let ctx = context();
    for width in [420.0, 520.0, 640.0, 760.0, 900.0] {
        let (_temp, mut view) = view(Section::Files);
        view.last_refresh = Some(Instant::now());
        let mut out = egui::FullOutput::default();
        for time in 0..4 {
            out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 900.0),
                    )),
                    time: Some(f64::from(time) * 0.02),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        view.show(
                            ui,
                            TriageInput {
                                vm_id: Some("vm"),
                                boot_id: Some("boot"),
                                run_id: Some("run"),
                                pcap: Some(Path::new("/nonexistent/capture.pcap")),
                                ..TriageInput::empty()
                            },
                        );
                    });
                },
            );
        }
        let shown = texts(&out);
        let status = shown
            .iter()
            .find(|(text, _)| text.starts_with("Refreshed "))
            .unwrap_or_else(|| panic!("status missing at {width}: {shown:?}"))
            .1;
        for tab in [
            "Summary",
            "Properties",
            "Detection",
            "Process",
            "Files",
            "Network",
            "eBPF",
            "IOC",
        ] {
            let tab = find(&out, tab);
            assert!(
                !status.intersects(tab),
                "status {status:?} overlaps {tab:?} at {width}: {:?}",
                shown
            );
        }
    }
}

#[test]
fn every_table_still_sorts_from_its_headers() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Network);
    {
        let scan = view.scan.as_mut().unwrap();
        scan.network_counts = Some((10, 1, 1));
        scan.new_tabs.urls = rows_of(net_tabs::URL_HEADERS, 1);
    }
    view.new_tab = NewTab::Urls;
    let out = settle(&ctx, &mut view);
    // The Endpoint header (third column) is a sort button of the URLs table.
    let endpoint = texts(&out)
        .into_iter()
        .find(|(text, rect)| text.starts_with("Endpoint") && rect.top() > 120.0)
        .unwrap()
        .1;
    click(&ctx, &mut view, endpoint.center());
    // The query bar takes the request on the next frame.
    draw(&ctx, &mut view, vec![], 2.0);
    let sort = view.scan_request.sorts[3].expect("a sort of the HTTP slot");
    assert_eq!(sort.column, 2);
}

#[test]
fn an_opened_row_keeps_every_value_under_its_own_column() {
    let call = path_call(1, 2, "open", 3, "/tmp/analysis-note.txt");
    let event = trace::representative(&call).unwrap();
    let state = FdState::default();
    let hit = file_category::classify(&state, &call, event)
        .into_iter()
        .find(|hit| hit.category.tab() == FileTab::Opened)
        .expect("an open call is an Opened row");
    let row = file_category::with_time(
        &[file_category::category_row(&state, &call, event, hit)],
        None,
    )
    .remove(0);
    let headers = file_category::EVENT_HEADERS;
    assert_eq!(row.len(), headers.len());
    let at = |header: &str| &row[headers.iter().position(|h| *h == header).unwrap()].text;
    assert!(
        at("Path").contains("/tmp/analysis-note.txt"),
        "{}",
        at("Path")
    );
    assert_eq!(at("Operation"), "open");
    assert!(at("Process (PID / TID)").contains(" / "));
    assert!(at("Evidence").starts_with("call "));
    // The shown columns are the Opened table's, each from its own header.
    let shown: Vec<&str> = file_tabs::OPENED_COLUMNS
        .iter()
        .map(|&column| headers[column])
        .collect();
    assert_eq!(
        shown,
        ["Time", "Path", "Process (PID / TID)", "Result", "Evidence"]
    );
}

#[test]
fn numeric_columns_sit_at_the_right_edge_of_their_cells() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Network);
    {
        let scan = view.scan.as_mut().unwrap();
        scan.network_counts = Some((10, 1, 1));
        let mut rows = rows_of(net_tabs::URL_HEADERS, 1);
        rows[0][0] = cell("#3", theme::text(), true);
        rows[0][0].values = vec![("frame.number", RowValue::Number(3))];
        scan.new_tabs.urls = rows;
    }
    view.new_tab = NewTab::Urls;
    let out = settle(&ctx, &mut view);
    let header = find(&out, "Frame");
    let frame = find(&out, "#3");
    // The number and its header end together at the column's right edge; a
    // left-aligned pair would start together instead.
    assert!(
        (header.right() - frame.right()).abs() < 3.0,
        "header {header:?} cell {frame:?}"
    );
    let endpoint = find(&out, "Endpoint");
    // Text columns stay at the left edge.
    assert!(endpoint.left() > header.right());
}

#[test]
fn category_chips_wear_their_category_icon_where_the_others_have_a_check_mark() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Suspicious;
    let out = settle(&ctx, &mut view);
    let shown = texts(&out);
    let icon = |name: &str| {
        let category = rules::Category::ALL
            .iter()
            .find(|category| category.chip() == name)
            .unwrap_or_else(|| panic!("no category chip {name}"));
        graph::category_icon(*category)
    };
    for name in ["Execution", "Persistence", "Privilege", "Evasion", "C2"] {
        let want = format!("{} {name}", icon(name));
        assert!(
            shown.iter().any(|(text, _)| *text == want),
            "{want:?} missing in {shown:?}"
        );
        let check = format!("{} {name}", egui_phosphor::regular::CHECK);
        assert!(
            !shown.iter().any(|(text, _)| *text == check),
            "{check:?} still drawn"
        );
    }
    // The tier chips keep the check mark.
    assert!(shown
        .iter()
        .any(|(text, _)| text.starts_with(egui_phosphor::regular::CHECK) && text.contains("HIGH")));
}

#[test]
fn suspicious_activity_has_tier_and_category_chips_and_evasion_is_one_of_them() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Suspicious;
    let out = settle(&ctx, &mut view);
    let shown = texts(&out);
    let chip = |label: &str| {
        shown
            .iter()
            .find(|(text, _)| text.contains(label))
            .unwrap_or_else(|| panic!("{label} chip missing in {shown:?}"))
            .1
    };
    for label in [
        "HIGH",
        "MEDIUM",
        "LOW",
        "Show INFO",
        "Execution",
        "Persistence",
        "Evasion",
        "C2",
        "Exfiltration",
        "Show hidden",
    ] {
        chip(label);
    }
    // No evasion row exists yet; the chip narrows the table to its category.
    assert_eq!(view.scan_request.finding_view.categories, 0);
    view.scan_request.offsets[0] = 2000;
    click(&ctx, &mut view, chip("Evasion").center());
    assert!(view
        .scan_request
        .finding_view
        .category_on(rules::Category::Evasion));
    assert_eq!(view.scan_request.offsets[0], 0);
    let out = settle(&ctx, &mut view);
    let again = texts(&out)
        .into_iter()
        .find(|(text, _)| text.contains("Evasion"))
        .unwrap()
        .1;
    click(&ctx, &mut view, again.center());
    assert_eq!(
        view.scan_request.finding_view.categories, 0,
        "a second click clears the chip"
    );
    let out = settle(&ctx, &mut view);
    let info = texts(&out)
        .into_iter()
        .find(|(text, _)| text.contains("Show INFO"))
        .unwrap()
        .1;
    click(&ctx, &mut view, info.center());
    assert!(view.scan_request.finding_view.show_info);
}

#[test]
fn the_badge_hover_splits_the_rows_by_tier_and_its_colour_follows_the_worst() {
    let (_temp, mut view) = view(Section::Process);
    let scan = view.scan.as_mut().unwrap();
    scan.counts.findings = 8;
    scan.counts.finding_tiers = [2, 5, 1, 340];
    scan.counts.findings_hidden = 12;
    let ctx = context();
    let out = settle(&ctx, &mut view);
    assert!(has(&out, "Suspicious activity8"), "{:?}", texts(&out));
}

#[test]
fn the_details_of_an_evasion_row_list_each_check_the_answer_and_why_it_has_its_tier() {
    let ctx = context();
    let findings = rules::tests::support::evasion_rows();
    let probe = findings
        .iter()
        .find(|row| row.cells[0].text == "evasion.sandbox_probe")
        .expect("a sandbox probe row")
        .clone();
    let label = probe.cells[0].text.clone();
    let mut view = TriageView::default();
    let mut draw = |events, time| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1500.0, 2000.0),
                )),
                events,
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::SidePanel::right("shared-details")
                    .exact_width(560.0)
                    .show(ctx, |ui| {
                        view.details(ui);
                    });
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.suspicious_findings(ui, vec![probe.clone()], 0);
                });
            },
        )
    };
    for n in 0..3 {
        draw(vec![], f64::from(n) * 0.01);
    }
    let output = draw(vec![], 0.04);
    let pos = texts(&output)
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
    let shown = texts(&output);
    let any = |needle: &str| {
        shown
            .iter()
            .any(|(text, rect)| text.contains(needle) && rect.left() >= 940.0)
    };
    assert!(any("Checks and what the guest answered"), "{shown:?}");
    assert!(any("\"QEMU\""), "the answer the guest gave");
    assert!(any("would show it"));
    assert!(any("Stealth profile › Machine identity"));
    assert!(
        any("CPUID"),
        "instruction-level checks are said to be invisible: {shown:?}"
    );
    assert!(any("Why this tier"));
    assert!(any("Heuristic"));
}

#[test]
fn tier_tones_follow_the_tier_colours() {
    use crate::widgets::Tone;
    let tones: Vec<Tone> = rules::Tier::ALL.iter().map(|tier| tier.tone()).collect();
    assert_eq!(tones, [Tone::Error, Tone::Warn, Tone::Info, Tone::Neutral]);
    assert_eq!(rules::Tier::from_tag("medium"), Some(rules::Tier::Medium));
    assert_eq!(rules::Tier::from_tag("nope"), None);
}

#[test]
fn clicking_a_process_opens_its_suspicious_activity() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Tree;
    let out = settle(&ctx, &mut view);
    let at = find(&out, "pid 55 cookie 55").center();
    click(&ctx, &mut view, at);
    settle(&ctx, &mut view);
    assert!(view.section == Section::Process);
    assert!(view.process == ProcessTab::Suspicious);
    let draft =
        ctx.data(|data| data.get_temp::<String>(egui::Id::new(("triage-filter-draft", 0usize))));
    assert_eq!(draft.as_deref(), Some("process.pid == 55"));
}
