// SPDX-License-Identifier: MIT
use super::*;

mod async_files;
mod async_previews;
mod layout;
mod theme_switch;

#[test]
#[ignore = "requires X11 native rendering; synthetic triage evidence fixture"]
fn native_triage_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        deadline: Instant,
        details_width: f32,
    }
    impl eframe::App for Fixture {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::SidePanel::right("shared-details-fixture")
                .exact_width(self.details_width)
                .show(ctx, |ui| {
                    ui.heading("Details");
                    self.view.details(ui);
                });
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Run triage — synthetic fixture");
                let _ = self.view.show(
                    ui,
                    TriageInput {
                        vm_id: Some("vm"),
                        boot_id: Some("boot"),
                        run_id: Some("run"),
                        ..TriageInput::empty()
                    },
                );
            });
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    // Cells keep the colours they are made with, so the theme comes first.
    if let Ok(name) = std::env::var("ANTINOMIE_QA_THEME") {
        let chosen = match name.as_str() {
            "light" => theme::Theme::Light,
            "blue" => theme::Theme::Blue,
            _ => theme::Theme::Dark,
        };
        theme::apply_theme(&egui::Context::default(), chosen);
    }
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let scene = std::env::var("ANTINOMIE_TRIAGE_QA_SCENE").unwrap_or_else(|_| "changed".into());
    let pcap = temp.directory.join("fixture.pcap");
    std::fs::write(
        &pcap,
        if scene == "http" {
            http_pcap()
        } else {
            dns_pcap()
        },
    )
    .unwrap();
    let mut scan =
        scan_archive(&temp.directory, Some(&pcap), false, &AtomicBool::new(false)).unwrap();
    let clock = Some(antinomie_monitor_core::HostClockAnchor {
        guest_ns: 0,
        host_us: 1_700_000_000_000_000,
    });
    scan.clock_anchor = clock;
    let mut calls = [
        path_call(1, 2, "open", 3, "/tmp/analysis-note.txt"),
        call(1, 0, "read", 5),
        call(1, 0, "read", 0),
        call(1, 18, "pwrite64", 2),
    ];
    calls[0].entry.as_mut().unwrap().args = Some([0, 2, 0, 0, 0, 0]);
    calls[1].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
    calls[1]
        .exit
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.data", "", b"hello"));
    calls[2].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
    calls[3].entry.as_mut().unwrap().args = Some([3, 0, 2, 1, 0, 0]);
    calls[3]
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.data", "", b"XY"));
    let mut state = FdState::default();
    let mut index = files::FileIndex::default();
    for (at, call) in calls.iter_mut().enumerate() {
        call.call_id = at as u64 + 1;
        for event in call.entry.iter_mut().chain(call.exit.iter_mut()) {
            event.call_id = call.call_id;
            event.timestamp_ns = at as u64 * 1_000_000_000;
        }
        let event = trace::representative(call).unwrap();
        remember_open(&mut state, call, event);
        // Opened rows are the index's own, in the Opened table's column order.
        for hit in file_category::classify(&state, call, event) {
            if hit.category.tab() == FileTab::Opened {
                scan.opened
                    .push(file_category::category_row(&state, call, event, hit));
                scan.counts.opened += 1;
            }
        }
        if let Some(row) = index.observe(&state, call, event, None) {
            scan.read.push(row);
        }
    }
    scan.file_changes = index.finish();
    scan.changed = scan
        .file_changes
        .iter()
        .map(|change| change.row(clock))
        .collect();
    let mut view = TriageView::default();
    view.scan = Some(scan);
    view.last_refresh = Some(Instant::now());
    view.context_key = Some("vm\nboot\nrun\n".into());
    match scene.as_str() {
        "findings" => {
            view.section = Section::Process;
            view.process = ProcessTab::Suspicious;
        }
        "opened" => {
            view.section = Section::Files;
            view.files = FileTab::Opened;
        }
        "read" => {
            view.section = Section::Files;
            view.files = FileTab::Read;
        }
        "changed" => {
            view.section = Section::Files;
            view.files = FileTab::Changed;
        }
        "http" => {
            view.section = Section::Network;
            view.network = NetTab::Http;
        }
        "dns" => {
            view.section = Section::Network;
            view.network = NetTab::Dns;
        }
        "hosts" => {
            view.section = Section::Network;
            view.network = NetTab::Hosts;
        }
        _ => {
            view.section = Section::Process;
        }
    }
    // ANTINOMIE_QA_SIZE = 1280x820 and ANTINOMIE_QA_THEME = dark | light | blue
    // are the screenshot controls; the width variable stays for the narrow QA.
    let size = std::env::var("ANTINOMIE_QA_SIZE").ok().and_then(|value| {
        let (w, h) = value.split_once('x')?;
        Some((w.parse::<u32>().ok()?, h.parse::<f32>().ok()?))
    });
    let width = size
        .map(|size| size.0)
        .or_else(|| {
            std::env::var("ANTINOMIE_TRIAGE_QA_WIDTH")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
        })
        .unwrap_or(1280)
        .clamp(420, 1920);
    let height = size.map_or(880.0, |size| size.1);
    let palette = match std::env::var("ANTINOMIE_QA_THEME").as_deref() {
        Ok("light") => theme::Theme::Light,
        Ok("blue") => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let font = if width < 700 { 24.0 } else { 16.0 };
    eframe::run_native(
        "Antinomie Triage QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([width as f32, height])
                .with_position([16.0, 16.0]),
            persist_window: false,
            persistence_path: Some(temp.directory.join("native-ui.ron")),
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, palette);
            theme::text_size(&cc.egui_ctx, font);
            let initial = view.scan.as_ref().and_then(|scan| match scene.as_str() {
                "changed" => scan.changed.first().cloned().map(|row| {
                    (
                        "triage-changed",
                        vec!["Time", "Path", "PID / TID", "Diff count", "Evidence"],
                        row,
                    )
                }),
                "read" => scan.read.first().cloned().map(|row| {
                    (
                        "triage-read",
                        vec![
                            "Time",
                            "Path",
                            "PID / TID",
                            "Transferred / content",
                            "Result",
                            "Evidence",
                        ],
                        row,
                    )
                }),
                "http" => scan
                    .http
                    .first()
                    .cloned()
                    .map(|row| ("triage-http", HTTP_HEADERS.to_vec(), row)),
                "dns" => scan
                    .dns
                    .first()
                    .cloned()
                    .map(|row| ("triage-dns", DNS_HEADERS.to_vec(), row)),
                "hosts" => scan.hosts.first().cloned().map(|row| {
                    (
                        "triage-hosts",
                        vec![
                            "Hostname",
                            "Resolved / connected IPs",
                            "First seen",
                            "Last seen",
                            "Requests",
                            "Source",
                        ],
                        row,
                    )
                }),
                "findings" => scan.findings.first().map(|finding| {
                    let mut row = finding.cells.clone();
                    row[0].values.clone_from(&finding.values);
                    (
                        "triage-findings",
                        vec![
                            "Rule",
                            "Severity",
                            "Process",
                            "Summary",
                            "Source",
                            "Time",
                            "Confidence",
                            "Evidence",
                            "Version",
                            "Outcome",
                        ],
                        row,
                    )
                }),
                _ => None,
            });
            if let Some((table_id, headers, row)) = initial {
                details::select(&cc.egui_ctx, table_id, &headers, &row);
                let selected = evidence_key(&row);
                cc.egui_ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new(("triage-selected-row", table_id)), selected)
                });
            }
            Ok(Box::new(Fixture {
                view,
                deadline: Instant::now() + Duration::from_secs(10),
                details_width: (width as f32 * 0.38).min(420.0),
            }))
        }),
    )
    .unwrap();
}

#[test]
fn evidence_navigation_uses_stream_task_and_call_identity() {
    let context = egui::Context::default();
    let values = [
        ("stream.id", RowValue::Number(7)),
        ("process.cookie", RowValue::Number(9)),
        ("event.id", RowValue::Number(1)),
    ];
    request_evidence_jump(&context, &values);
    assert_eq!(
        context.data_mut(
            |data| data.remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
        ),
        Some((7, 9, 1))
    );
    let first = call(9, 0, "read", 1);
    let other = call(10, 0, "read", 1);
    let query = query::compile_note("stream.id == 1 && process.cookie == 9 && call.id == 1");
    assert!(query.error.is_none());
    assert!(query.keep(&first));
    assert!(!query.keep(&other));
    request_evidence_jump(&context, &[("frame.number", RowValue::Number(520))]);
    assert_eq!(
        context.data_mut(|data| data.remove_temp::<u64>(egui::Id::new("triage-packet-jump"))),
        Some(520)
    );
}

#[test]
fn double_click_table_text_requests_its_exact_evidence() {
    for packet in [false, true] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut c = cell("click this evidence", theme::text(), false);
        c.values = if packet {
            vec![("frame.number", RowValue::Number(520))]
        } else {
            vec![
                ("stream.id", RowValue::Number(7)),
                ("process.cookie", RowValue::Number(9)),
                ("event.id", RowValue::Number(1)),
            ]
        };
        let rows = vec![vec![c]];
        let draw = |events, time| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 600.0),
                    )),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        table(ui, "pointer-evidence", &["Evidence"], &rows)
                    });
                },
            )
        };
        for n in 0..3 {
            draw(vec![], f64::from(n) * 0.01);
        }
        let out = draw(vec![], 0.04);
        let pos = crate::app::tests::texts(&out)
            .into_iter()
            .find(|(text, _)| text == "click this evidence")
            .unwrap()
            .1
            .center();
        for (index, pressed) in [true, false, true, false].into_iter().enumerate() {
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
                0.1 + index as f64 * 0.05,
            );
        }
        if packet {
            assert_eq!(
                ctx.data(|data| data.get_temp::<u64>(egui::Id::new("triage-packet-jump"))),
                Some(520)
            );
        } else {
            assert_eq!(
                ctx.data(
                    |data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
                ),
                Some((7, 9, 1))
            );
        }
    }
}

#[test]
fn saved_run_scope_excludes_another_root_in_the_same_raw_archive() {
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..2);
    // Rewrite only the second invocation's inherited root cookie.
    let mut at = 0;
    while at < raw.len() {
        let size = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        if u64::from_le_bytes(raw[at + 4 + 40..at + 4 + 48].try_into().unwrap()) == 1 {
            raw[at + 4 + 128..at + 4 + 136].copy_from_slice(&99u64.to_le_bytes());
        }
        at += 4 + size;
    }
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let request = ScanRequest {
        root_cookie: 55,
        ..Default::default()
    };
    let scan = scan_archive_query(
        &temp.directory,
        None,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap();
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].key, (1, 55, 0));
    assert_eq!(scan.process.len(), 1);
}

#[test]
fn network_rows_are_bounded_to_the_run_host_time_window() {
    let temp = PacketSpool::new().unwrap();
    let path = temp.directory.join("dns.pcap");
    std::fs::write(&path, dns_pcap()).unwrap();
    let request = ScanRequest {
        started_ms: Some(u64::MAX / 1000),
        ..Default::default()
    };
    let scan = scan_pcap_query(&path, false, &Arc::new(AtomicBool::new(false)), &request).unwrap();
    assert!(
        scan.http.is_empty() && scan.dns.is_empty() && scan.ips.is_empty() && scan.hosts.is_empty()
    );
}

#[test]
fn network_field_stream_without_geoip_preserves_dns_and_original_frames() {
    use std::io::{BufRead, BufReader};
    let temp = PacketSpool::new().unwrap();
    let path = temp.directory.join("dns.pcap");
    std::fs::write(&path, dns_pcap()).unwrap();
    let identity = antinomie_monitor_core::packet_filter::CaptureIdentity::read(&path).unwrap();
    let (spool, _) =
        spool_packet_fields(&identity, false, &Arc::new(AtomicBool::new(false)), false).unwrap();
    let state = spool.lock().unwrap();
    let file = std::fs::File::open(state.directory.join("rows.tsv")).unwrap();
    let rows: Vec<_> = BufReader::new(file)
        .lines()
        .map(|line| tsv_fields(&line.unwrap()).unwrap())
        .collect();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row.len() == TSHARK_FIELDS.len()));
    assert_eq!(rows[0][0], "1");
    assert_eq!(rows[0][19], "example.com");
    assert!(rows[0][31..35].iter().all(String::is_empty));
}

#[test]
fn tshark_boolean_formats_preserve_missing_and_reject_malformed_or_mixed_values() {
    for text in ["False", "false", "FALSE", "0", "False\u{1f}0"] {
        assert_eq!(tshark_boolean(text), Some(false));
    }
    for text in ["True", "true", "TRUE", "1", "True\u{1f}1"] {
        assert_eq!(tshark_boolean(text), Some(true));
    }
    for text in ["", "2", "Falsehood", " True ", "False\u{1f}True", "0\u{1f}"] {
        assert_eq!(tshark_boolean(text), None, "{text:?}");
    }
}

#[test]
fn real_tshark_dns_ipv4_ipv6_and_retry_rows_preserve_original_frames_and_responses() {
    if !std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return;
    }
    let temp = PacketSpool::new().unwrap();
    let path = temp.directory.join("dns.pcap");
    std::fs::write(&path, dns_pcap()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    for live in [false, true] {
        let index = scan_pcap_query(&path, live, &cancel, &ScanRequest::default()).unwrap();
        assert_eq!(index.dns.len(), 3, "{}", index.coverage);
        assert_eq!(
            index
                .dns
                .iter()
                .map(|row| row[0].text.as_str())
                .collect::<Vec<_>>(),
            ["#1", "#2", "#4"]
        );
        // The Time column sits after Frame, as in the HTTP table.
        assert_eq!(DNS_HEADERS[..2], ["Frame", "Time"]);
        assert!(index.dns.iter().all(|row| row.len() == DNS_HEADERS.len()));
        assert!(index.dns.iter().all(|row| !row[1].text.is_empty()));
        assert!(index.dns.iter().all(|row| row[3].text == "example.com"));
        assert_eq!(index.dns[0][7].text, "3");
        assert_eq!(index.dns[2][7].text, "5");
        assert!(index.dns[0][6].text.contains("93.184.216.34"));
        assert!(index.dns[2][2].text.contains("::1"));
        assert_eq!(index.dns[0][4].text, "A");
        assert!(!index.ips.is_empty());
        assert_eq!(index.hosts.len(), 1);
        assert!(index.dns[1][0]
            .values
            .iter()
            .any(|(name, value)| *name == "dns.retry" && matches!(value, RowValue::Bool(true))));
    }
    let mut request = ScanRequest::default();
    request.filters[4] = "dns.retry == true".into();
    let index = scan_pcap_query(&path, false, &cancel, &request).unwrap();
    assert_eq!(index.dns.len(), 1);
    assert_eq!(index.dns[0][0].text, "#2");
}

fn dns_pcap() -> Vec<u8> {
    fn message(response: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [
            0x1234u16,
            if response { 0x8180 } else { 0x0100 },
            1,
            u16::from(response),
            0,
            0,
        ] {
            bytes.extend(word.to_be_bytes());
        }
        bytes.extend(b"\x07example\x03com\0");
        bytes.extend(1u16.to_be_bytes());
        bytes.extend(1u16.to_be_bytes());
        if response {
            bytes.extend([0xc0, 0x0c]);
            bytes.extend(1u16.to_be_bytes());
            bytes.extend(1u16.to_be_bytes());
            bytes.extend(60u32.to_be_bytes());
            bytes.extend(4u16.to_be_bytes());
            bytes.extend([93, 184, 216, 34]);
        }
        bytes
    }
    fn frame(response: bool, ipv6: bool) -> Vec<u8> {
        let payload = message(response);
        let mut udp = Vec::new();
        udp.extend(if response { 53u16 } else { 5353u16 }.to_be_bytes());
        udp.extend(if response { 5353u16 } else { 53u16 }.to_be_bytes());
        udp.extend(((payload.len() + 8) as u16).to_be_bytes());
        udp.extend([0; 2]);
        udp.extend(payload);
        let mut bytes = vec![0; 12];
        if ipv6 {
            bytes.extend(0x86ddu16.to_be_bytes());
            let local = "::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
            let remote = "2001:db8::53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets();
            bytes.extend(0x60000000u32.to_be_bytes());
            bytes.extend((udp.len() as u16).to_be_bytes());
            bytes.extend([17, 64]);
            bytes.extend(if response { remote } else { local });
            bytes.extend(if response { local } else { remote });
        } else {
            bytes.extend(0x0800u16.to_be_bytes());
            bytes.extend([0x45, 0]);
            bytes.extend(((udp.len() + 20) as u16).to_be_bytes());
            bytes.extend([0; 4]);
            bytes.extend([64, 17]);
            bytes.extend([0; 2]);
            bytes.extend(if response {
                [8, 8, 8, 8]
            } else {
                [10, 0, 2, 15]
            });
            bytes.extend(if response {
                [10, 0, 2, 15]
            } else {
                [8, 8, 8, 8]
            });
        }
        bytes.extend(udp);
        bytes
    }
    let frames = [
        frame(false, false),
        frame(false, false),
        frame(true, false),
        frame(false, true),
        frame(true, true),
    ];
    let mut bytes = http_pcap()[..24].to_vec();
    for (index, frame) in frames.iter().enumerate() {
        bytes.extend((1_700_000_000u32 + index as u32).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    bytes
}

#[test]
fn quoted_packet_fields_and_epoch_times_preserve_exact_values() {
    assert_eq!(
        tsv_fields("\"GET\"\t\"/a\tb\"\"c\"\t\"\"").unwrap(),
        ["GET", "/a\tb\"c", ""]
    );
    assert!(tsv_fields("\"truncated").is_err());
    assert_eq!(epoch_us("123.123456789"), Some(123_123456));
    assert_eq!(epoch_us("0.000001"), Some(1));
    assert_eq!(epoch_us("18446744073709551615.999999"), None);
    assert_eq!(epoch_us("1.bad"), None);
}

pub(super) fn write_rwx_calls(raw: &mut dyn std::io::Write, calls: std::ops::Range<u64>) {
    for call in calls {
        for phase in [1u8, 2] {
            for fragment in [1u8, 5] {
                let mut body = vec![0u8; if fragment == 1 { 120 } else { 32 }];
                if fragment == 1 {
                    body[16..24].copy_from_slice(&7u64.to_le_bytes());
                    body[24..32].copy_from_slice(&(MAP_PRIVATE | MAP_ANONYMOUS).to_le_bytes());
                    if phase == 2 {
                        body[49] = 1;
                        body[56..64].copy_from_slice(&4096u64.to_le_bytes());
                    }
                }
                let mut packet = vec![0u8; 136];
                packet[..4].copy_from_slice(b"ANTT");
                packet[4..6].copy_from_slice(&1u16.to_le_bytes());
                packet[6..8].copy_from_slice(&1u16.to_le_bytes());
                packet[8..10].copy_from_slice(&136u16.to_le_bytes());
                packet[10..12].copy_from_slice(&1u16.to_le_bytes());
                packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
                packet[20..24].copy_from_slice(&1u32.to_le_bytes());
                packet[24..32].copy_from_slice(&1u64.to_le_bytes());
                packet[32..40].copy_from_slice(&55u64.to_le_bytes());
                packet[40..48].copy_from_slice(&call.to_le_bytes());
                packet[48..56].copy_from_slice(&(call * 2 + u64::from(phase)).to_le_bytes());
                packet[56..64].copy_from_slice(
                    &(call * 4 + u64::from(phase) + u64::from(fragment)).to_le_bytes(),
                );
                packet[64..72].copy_from_slice(&(call * 10 + u64::from(phase)).to_le_bytes());
                packet[72..76].copy_from_slice(&55u32.to_le_bytes());
                packet[76..80].copy_from_slice(&55u32.to_le_bytes());
                packet[88..96].copy_from_slice(&9u64.to_le_bytes());
                packet[96..98].copy_from_slice(&1u16.to_le_bytes());
                packet[98] = phase;
                packet[99] = fragment;
                packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
                packet[128..136].copy_from_slice(&55u64.to_le_bytes());
                packet.extend(body);
                raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
                raw.write_all(&packet).unwrap();
            }
        }
    }
}

#[test]
fn hidden_tick_indexes_once_a_shown_pane_refreshes_growth_preserves_selection_and_rejects_prior_run(
) {
    fn input<'a>(archive: &'a Path, run: &'a str) -> TriageInput<'a> {
        TriageInput {
            analysis: None,
            invocations: &[],
            vm_id: Some("vm"),
            boot_id: Some("boot"),
            run_id: Some(run),
            archive: Some(archive),
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 0,
            run_finished: false,
            current_boot: false,
        }
    }
    fn wait(view: &mut TriageView, ctx: &egui::Context, archive: &Path, run: &str, count: usize) {
        // Only a bound on a hang; the refresh timer runs on the view's clock.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            // Intentionally never call show: another panel owns the workspace.
            view.clock.advance(Duration::from_secs(1));
            view.tick(ctx, input(archive, run));
            if view
                .scan
                .as_ref()
                .is_some_and(|scan| scan.findings.len() == count)
                && view.scan_rx.is_none()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "hidden index stalled: expected {count}; error {:?}; findings {:?}; calls {:?}; pending {}; generation {}",
                view.scan_error,
                view.scan.as_ref().map(|scan| scan.findings.len()),
                view.scan.as_ref().map(|scan| scan.counts.calls),
                view.scan_rx.is_some(),
                view.scan_generation
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let first = PacketSpool::new().unwrap();
    let second = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(first.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut raw, 0..1);
    raw.sync_all().unwrap();
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 1;
    view.scan_request.filters[0] = "finding.rule == \"memory.rwx\"".into();
    wait(&mut view, &ctx, &first.directory, "first", 1);
    view.selected_call_id = Some((1, 55, 0));
    let first_refresh = view.last_refresh.unwrap();
    write_rwx_calls(&mut raw, 1..2);
    raw.sync_all().unwrap();
    // Hidden, a live run keeps the index it has: the pane refreshes it when shown.
    let generation = view.scan_generation;
    for _ in 0..3 {
        view.clock.advance(Duration::from_secs(1));
        view.tick(&ctx, input(&first.directory, "first"));
    }
    assert_eq!(view.scan_generation, generation, "re-indexed while hidden");
    view.mark_shown(&ctx);
    wait(&mut view, &ctx, &first.directory, "first", 2);
    assert!(view.last_refresh.unwrap() > first_refresh);
    assert_eq!(view.selected_call_id, Some((1, 55, 0)));
    assert_eq!(
        view.scan_request.filters[0],
        "finding.rule == \"memory.rwx\""
    );
    // Hold a completed worker reply to exercise refresh pressure deterministically.
    view.refresh_requested = true;
    view.ensure_scan(
        Some(&first.directory),
        None,
        false,
        Some("vm"),
        Some("boot"),
        Some("first"),
    );
    let actual = view.scan_rx.take().unwrap();
    let (held_tx, held_rx) = mpsc::channel();
    view.scan_rx = Some(held_rx);
    let generation = view.scan_generation;
    for _ in 0..100 {
        view.refresh_requested = true;
        view.tick(&ctx, input(&first.directory, "first"));
        assert_eq!(view.scan_generation, generation);
    }
    assert!(view.refresh_queued);
    held_tx
        .send(actual.recv_timeout(Duration::from_secs(60)).unwrap())
        .unwrap();
    view.tick(&ctx, input(&first.directory, "first"));
    assert_eq!(view.scan_generation, generation + 1);
    let stale_cancel = Arc::clone(view.scan_cancel.as_ref().unwrap());
    let mut other = std::fs::File::create(second.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut other, 7..8);
    other.sync_all().unwrap();
    view.tick(&ctx, input(&second.directory, "second"));
    assert!(stale_cancel.load(Ordering::Relaxed));
    assert!(view.scan.is_none());
    assert!(view.selected_call_id.is_none());
    wait(&mut view, &ctx, &second.directory, "second", 1);
    assert_eq!(view.scan.as_ref().unwrap().findings[0].call_id, 7);
}

#[test]
fn complete_retained_archive_query_pages_every_rwx_finding_and_persists_facts() {
    let temp = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
    write_rwx_calls(&mut raw, 0..2051);
    raw.sync_all().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let first = scan_archive_query(
        &temp.directory,
        None,
        false,
        &cancel,
        &ScanRequest::default(),
    )
    .unwrap();
    assert_eq!(first.findings.len(), STORED_ROWS);
    assert_eq!(first.findings_omitted, 51);
    let mut request = ScanRequest::default();
    request.offsets[0] = STORED_ROWS;
    request.filters[0] = "finding.rule == \"memory.rwx\" && finding.success == true".into();
    let second = scan_archive_query(&temp.directory, None, false, &cancel, &request).unwrap();
    assert_eq!(second.findings.len(), 51);
    assert_eq!(second.findings_omitted, STORED_ROWS as u64);
    assert!(second
        .findings
        .iter()
        .all(|finding| finding.call_id >= STORED_ROWS as u64));
    let journal = std::fs::read_to_string(temp.directory.join("triage-findings-v1.jsonl")).unwrap();
    assert_eq!(journal.lines().count(), 2051);
    let fact: serde_json::Value = serde_json::from_str(journal.lines().next().unwrap()).unwrap();
    assert_eq!(fact["facts"]["finding.rule"], "memory.rwx");
    assert_eq!(fact["facts"]["finding.version"], 1);
    assert_eq!(fact["facts"]["finding.success"], true);
}

#[test]
fn relative_chdir_retains_symlink_components_and_unknown_fchdir_invalidates_cwd() {
    let start = path_call(1, 80, "chdir", 0, "/tmp/link");
    let relative = path_call(1, 80, "chdir", 0, "../child");
    let mut opened = path_call(1, 257, "openat", 4, "note");
    opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
    let rows = file_rows(&[start.clone(), relative, opened.clone()], OPEN_NAMES);
    assert_eq!(
        rows.rows[0][0].text,
        "/tmp/link/../child/note (lexical cwd path; symlinks unknown)"
    );
    let mut moved = call(1, 81, "fchdir", 0);
    moved.entry.as_mut().unwrap().args = Some([99, 0, 0, 0, 0, 0]);
    let rows = file_rows(&[start, moved, opened], OPEN_NAMES);
    assert_eq!(rows.rows[0][0].text, "note (relative, cwd not recorded)");
}

#[test]
fn exec_cloexec_and_shared_tables_keep_parent_descriptor_provenance_separate() {
    let mut opened = path_call(1, 257, "openat", 7, "/etc/test");
    opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0x80000, 0, 0, 0]);
    let mut clone = call(1, CLONE, "clone", 42);
    clone.entry.as_mut().unwrap().args = Some([CLONE_FILES, 0, 0, 0, 0, 0]);
    let exec = path_call(42, 59, "execve", 0, "/bin/true");
    let mut child = call(42, 1, "write", 3);
    child.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let mut parent = call(1, 1, "write", 3);
    parent.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let rows = file_rows(&[opened, clone, exec, child, parent], &["write"]);
    assert_eq!(rows.rows[0][0].text, "—");
    assert_eq!(rows.rows[1][0].text, "/etc/test");
    assert_eq!(rows.rows[1][8].text, "3");
}

#[test]
fn encrypted_and_binary_sessions_h2c_requests_and_quic_hosts_come_from_tshark() {
    if std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return;
    }
    let temp = PacketSpool::new().unwrap();
    let path = temp.directory.join("protocols.pcap");
    std::fs::write(
        &path,
        include_bytes!("../../../monitor-core/src/packet_filter/testdata/protocols.pcap"),
    )
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut inventory = network::Inventory::default();
    let mut kinds = Vec::new();
    let index = scan_pcap_query_observed(
        &path,
        false,
        &cancel,
        &ScanRequest::default(),
        &mut inventory,
        &mut |kind, _, _, _| {
            kinds.push(kind);
            Ok(())
        },
    )
    .unwrap();
    let rows: Vec<Vec<String>> = index
        .sessions
        .iter()
        .map(|row| row.iter().map(|cell| cell.text.clone()).collect())
        .collect();
    let find = |protocol: &str, kind: &str| {
        rows.iter()
            .find(|row| row[3] == format!("{protocol} {kind}"))
            .unwrap_or_else(|| panic!("{protocol} {kind} in {rows:?}"))
    };
    let tls = find("TLSv1.2", "client hello");
    assert_eq!(tls[4], "secure.example.test");
    assert_eq!(tls[5], "h2, http/1.1");
    assert!(tls[6].contains("3 cipher suites"), "{tls:?}");
    let quic = find("QUIC", "client hello");
    assert_eq!(
        (quic[4].as_str(), quic[5].as_str()),
        ("quic.example.test", "h3")
    );
    assert!(find("TLSv1.3", "server hello")[6].contains("0x1301"));
    assert!(
        rows.iter()
            .any(|row| row[3] == "SSHv2 banner" && row[6].starts_with("SSH-2.0-")),
        "{rows:?}"
    );
    // Cleartext HTTP/2 is listed with the HTTP requests, by authority.
    assert!(index
        .http
        .iter()
        .any(|row| row[3].text == "GET" && row[4].text == "www.example.com" && row[5].text == "/"));
    let (_, hosts) = inventory.rows();
    let sources: Vec<String> = hosts
        .iter()
        .map(|row| format!("{} {}", row[0].text, row[5].text))
        .collect();
    assert!(
        sources.iter().any(|h| h == "quic.example.test QUIC SNI"),
        "{sources:?}"
    );
    assert!(
        sources.iter().any(|h| h == "secure.example.test TLS SNI"),
        "{sources:?}"
    );
    assert!(
        sources.iter().any(|h| h == "www.example.com HTTP/2"),
        "{sources:?}"
    );
    assert!(kinds.contains(&RowKind::Session));
}

#[test]
fn tshark_saved_and_live_prefix_index_use_all_capture_frames() {
    if std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return;
    }
    let temp = PacketSpool::new().unwrap();
    let path = temp.directory.join("capture.pcap");
    std::fs::write(&path, http_pcap()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    for live in [false, true] {
        let index = scan_pcap_query(&path, live, &cancel, &ScanRequest::default()).unwrap();
        assert_eq!(index.http.len(), 1);
        assert_eq!(index.http[0][3].text, "GET");
        assert_eq!(index.http[0][4].text, "example.com");
        assert_eq!(index.http[0][5].text, "/");
        // TShark parses everything it knows; the coverage says what stays
        // encrypted, and HTTP/2 and session fields are requested from it.
        assert!(index.coverage.contains(
            "the content of HTTPS, HTTP/3 and encrypted DNS stays encrypted, and cleartext HTTP/2 requests are listed without their responses"
        ));
        assert!(TSHARK_FIELDS.contains(&"tls.handshake.extensions_server_name"));
        assert!(TSHARK_FIELDS.contains(&"http2.headers.method"));
        assert!(TSHARK_FIELDS.contains(&"ssh.protocol"));
    }
}
use antinomie_monitor_core::{EventSummary, FieldSummary, InvocationSummary};

fn page_notes(invocations: &[InvocationSummary]) -> Vec<BpfNote> {
    bpf_notes(&TriageInput::page(invocations))
}

#[test]
#[ignore = "requires an actual recorded sample run in ANTINOMIE_TRIAGE_SAMPLE"]
fn recorded_triage_sample_populates_every_evidence_table() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("ANTINOMIE_TRIAGE_SAMPLE").expect("set recorded sample run directory"),
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap();
    let identity = (
        run["vm_id"].as_str().unwrap().to_owned(),
        run["boot_id"].as_str().unwrap().to_owned(),
        run["id"].as_str().unwrap().to_owned(),
    );
    let request = ScanRequest {
        root_cookie: run["root_task_cookie"].as_u64().unwrap(),
        identity: Some(identity),
        run_finished: true,
        ..Default::default()
    };
    let artifacts = antinomie_monitor_core::RunArtifacts::load(&directory)
        .unwrap()
        .expect("sample artifacts");
    let scan = scan_archive_query(
        &directory,
        artifacts
            .network_captures
            .first()
            .map(|path| path.as_path()),
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap();
    assert!(scan.event_error.is_none(), "{:?}", scan.event_error);
    assert!(scan.event_journal.is_some());
    let rows = |table: &[Vec<Cell>]| {
        table
            .iter()
            .map(|row| row.iter().map(|cell| cell.text.clone()).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    };
    let value = serde_json::json!({
        "coverage": scan.coverage, "partial": scan.partial,
        "calls": scan.counts.calls, "tasks": scan.process.len(),
        "findings": scan.findings.iter().map(|finding| finding.cells.iter()
            .map(|cell| cell.text.clone()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "opened": rows(&scan.opened), "read": rows(&scan.read), "changed": rows(&scan.changed),
        "http": rows(&scan.http), "dns": rows(&scan.dns),
        "ips": rows(&scan.ips), "hosts": rows(&scan.hosts),
        "bpf_observations": scan.bpf.len(), "network_warning": scan.network_warning,
        "journal": scan.event_journal,
    });
    std::fs::write(
        directory.join("sample-triage.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    assert!(scan.process.len() >= 4, "{value}");
    for key in [
        "findings", "opened", "read", "changed", "http", "dns", "ips", "hosts",
    ] {
        assert!(
            !value[key].as_array().unwrap().is_empty(),
            "empty {key}: {value}"
        );
    }
    assert!(!scan.bpf.is_empty(), "{value}");
}

#[test]
fn saved_recording_from_env_is_indexed_when_present() {
    let Ok(dir) = std::env::var("ANTINOMIE_RECORDING") else {
        return;
    };
    let scan = scan_archive(Path::new(&dir), None, false, &AtomicBool::new(false))
        .unwrap_or_else(|error| panic!("index failed: {error}"));
    assert!(scan.coverage.contains("indexed "), "{}", scan.coverage);
    assert!(
        scan.coverage.contains(" of ") || scan.coverage.contains("saved total unavailable"),
        "{}",
        scan.coverage
    );
    let _ = std::fs::write("/tmp/antinomie-index-coverage.txt", &scan.coverage);
    let files = scan
        .opened
        .iter()
        .chain(scan.changed.iter())
        .map(|row| {
            row.iter()
                .map(|cell| cell.text.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write("/tmp/antinomie-fd-rows.txt", files);
    let findings = scan
        .findings
        .iter()
        .map(|finding| {
            finding
                .cells
                .iter()
                .map(|cell| cell.text.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write("/tmp/antinomie-findings.txt", findings);
    let recording = antinomie_monitor_core::recording::Recording {
        directory: std::fs::canonicalize(&dir).unwrap(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let mut offset = 0u64;
    let mut bpf = String::new();
    loop {
        let page = recording.invocation_page(offset, 256).unwrap();
        for invocation in &page.invocations {
            let Some(event) = invocation.entry.as_ref().or(invocation.exit.as_ref()) else {
                continue;
            };
            if event.syscall_name.contains("bpf")
                || event.syscall_name.contains("seccomp")
                || event.syscall_name == "setsockopt"
            {
                bpf.push_str(&format!(
                    "{} result {:?} args {:?}\n",
                    event.syscall_name,
                    invocation.exit.as_ref().and_then(|exit| exit.result),
                    event.args
                ));
            }
        }
        match page.next_offset {
            Some(next) if next > offset => offset = next,
            _ => break,
        }
    }
    if bpf.is_empty() {
        bpf.push_str("no bpf, seccomp, or setsockopt call in this recording\n");
    }
    let _ = std::fs::write("/tmp/antinomie-bpf-scan.txt", bpf);
}

pub(super) fn http_pcap() -> Vec<u8> {
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut tcp = Vec::new();
    tcp.extend(40000u16.to_be_bytes());
    tcp.extend(80u16.to_be_bytes());
    tcp.extend(1u32.to_be_bytes());
    tcp.extend(0u32.to_be_bytes());
    tcp.push(0x50);
    tcp.push(0x18);
    tcp.extend(0u16.to_be_bytes());
    tcp.extend(0u16.to_be_bytes());
    tcp.extend(0u16.to_be_bytes());
    tcp.extend(payload);
    let total = (20 + tcp.len()) as u16;
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 2, 15, 93, 184, 216, 34,
    ];
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend(tcp);
    let mut frame = vec![0; 12];
    frame.extend(0x0800u16.to_be_bytes());
    frame.extend(ip);
    let mut pcap = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    let len = frame.len() as u32;
    pcap.extend(0u32.to_le_bytes());
    pcap.extend(0u32.to_le_bytes());
    pcap.extend(len.to_le_bytes());
    pcap.extend(len.to_le_bytes());
    pcap.extend(frame);
    pcap
}

#[test]
fn missing_raw_archive_is_not_treated_as_a_whole_run() {
    let dir = std::env::temp_dir().join(format!("antinomie-triage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Err(error) = scan_archive(&dir, None, false, &AtomicBool::new(false)) else {
        panic!("a directory without telemetry.raw must not count as a whole-run index");
    };
    assert!(error.contains("telemetry.raw"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

pub(super) fn call(pid: u32, nr: u64, name: &str, result: i64) -> InvocationSummary {
    InvocationSummary {
        stream_id: 1,
        task_cookie: u64::from(pid),
        call_id: 1,
        entry: Some(EventSummary {
            root_task_cookie: 1,
            stream_id: 1,
            task_cookie: u64::from(pid),
            call_id: 1,
            event_seq: 1,
            phase: 1,
            syscall_nr: nr,
            syscall_name: name.into(),
            pid,
            tid: pid,
            cpu: 0,
            timestamp_ns: 0,
            args: Some([0; 6]),
            result: None,
            complete: true,
            issues: Vec::new(),
            fields: Vec::new(),
        }),
        exit: Some(EventSummary {
            root_task_cookie: 1,
            stream_id: 1,
            task_cookie: u64::from(pid),
            call_id: 1,
            event_seq: 2,
            phase: 2,
            syscall_nr: nr,
            syscall_name: name.into(),
            pid,
            tid: pid,
            cpu: 0,
            timestamp_ns: 1,
            args: None,
            result: Some(result),
            complete: true,
            issues: Vec::new(),
            fields: Vec::new(),
        }),
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: Vec::new(),
    }
}

pub(super) fn captured(key: &str, layout: &str, data: &[u8]) -> FieldSummary {
    let len = data.len() as u64;
    FieldSummary {
        object_id: 1,
        key: key.into(),
        layout: layout.into(),
        logical_len: Some(len),
        captured_len: len,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: data.to_vec(),
        raw_path: None,
        ranges: vec![(0, len)],
    }
}

#[test]
fn fork_indents_the_child_under_its_parent() {
    let lines = process_tree_lines(&[call(1, FORK, "fork", 42), call(42, 59, "execve", 0)]);
    assert_eq!(
        lines,
        vec![
            "pid 1 cookie 1  ?".to_string(),
            "  pid 42 cookie 42  ?".to_string()
        ]
    );
}

fn with_cookie(pid: u32, cookie: u64) -> InvocationSummary {
    let mut row = call(pid, 1, "write", 0);
    row.task_cookie = cookie;
    for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
        event.task_cookie = cookie;
    }
    row
}

#[test]
fn same_pid_two_cookies_are_two_process_nodes() {
    let lines = process_tree_lines(&[with_cookie(7, 100), with_cookie(7, 200)]);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines.iter().any(|line| line.contains("pid 7 cookie 100")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("pid 7 cookie 200")),
        "{lines:?}"
    );
}

#[test]
fn triage_keeps_cookie_scoped_terminal_facts_after_a_late_parent_fork_and_pid_reuse() {
    let mut ended = with_cookie(42, 200);
    let mut terminal = ended.entry.as_ref().unwrap().clone();
    terminal.phase = 3;
    terminal.timestamp_ns = 120;
    terminal.fields = vec![captured("lifecycle.task_exit", "u64", &0_u64.to_le_bytes())];
    ended.task_exit = Some(terminal);
    let mut nodes = std::collections::BTreeMap::new();
    observe_processes(&mut nodes, &[ended]);
    let mut fork = call(1, FORK, "fork", 42);
    for event in fork.entry.iter_mut().chain(fork.exit.iter_mut()) {
        event.timestamp_ns = 100;
    }
    observe_processes(&mut nodes, &[fork, with_cookie(42, 201)]);
    let result = finish_processes(nodes);
    let old = result.iter().find(|node| node.cookie == 200).unwrap();
    assert!(old.state.contains("task exit"));
    assert_eq!(old.parent.unwrap().pid, 1);
    let current = result.iter().find(|node| node.cookie == 201).unwrap();
    assert_eq!(current.state, "exit not recorded");
}

#[test]
fn failed_exec_does_not_replace_the_program() {
    let mut started = call(3, 59, "execve", 0);
    started
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/old\0"));
    let mut failed = call(3, 59, "execve", -2);
    failed
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/new\0"));
    let lines = process_tree_lines(&[started, failed]);
    assert!(
        lines.iter().any(|line| line.contains("/bin/old")),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("/bin/new")),
        "{lines:?}"
    );

    let mut again = call(3, 59, "execve", 0);
    again
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/old\0"));
    let mut pending = call(3, 322, "execveat", 0);
    pending.exit = None;
    pending
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.pathname", "", b"/bin/pending\0"));
    let lines = process_tree_lines(&[again, pending]);
    assert!(
        lines.iter().any(|line| line.contains("/bin/old")),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("/bin/pending")),
        "{lines:?}"
    );

    let mut rejected = call(4, 59, "execve", -13);
    rejected
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/rejected\0"));
    let lines = process_tree_lines(&[rejected]);
    assert!(
        lines.iter().all(|line| !line.contains("/bin/rejected")),
        "{lines:?}"
    );
}

#[test]
fn exec_commit_without_syscall_exit_names_image_and_fork_inherits_it() {
    let mut exec = call(3, 59, "execve", 0);
    exec.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/old\0"));
    let mut commit = exec.exit.take().unwrap();
    commit.phase = 3;
    commit
        .fields
        .push(captured("lifecycle.exec_commit", "", &[0; 8]));
    exec.async_events.push(commit);
    let fork = call(3, FORK, "fork", 42);
    let child = call(42, 0, "read", 0);
    let nodes = process_nodes(&[exec.clone(), fork, child]);
    assert_eq!(
        nodes.iter().find(|node| node.pid == 3).unwrap().comm,
        "/bin/old"
    );
    assert_eq!(
        nodes.iter().find(|node| node.pid == 42).unwrap().comm,
        "/bin/old"
    );
    exec.async_events[0].fields[0].complete = false;
    assert_eq!(process_nodes(&[exec])[0].comm, "?");
}

#[test]
fn file_process_labels_follow_exec_time_without_guessing_unknown_or_reused_pid() {
    let mut files = FdState::default();
    let mut first = call(3, 59, "execve", 0);
    first
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/old\0"));
    observe_processes(&mut files.process_images, &[first]);
    let read = call(3, 0, "read", 0);
    let event = trace::representative(&read).unwrap();
    assert_eq!(
        process_identity(event.pid, event.tid, process_image(&files, event)),
        "old (3 / 3)"
    );
    let mut next = call(3, 59, "execve", 0);
    next.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", b"/bin/new\0"));
    observe_processes(&mut files.process_images, &[next]);
    assert_eq!(
        process_identity(event.pid, event.tid, process_image(&files, event)),
        "new (3 / 3)"
    );
    let mut reused = event.clone();
    reused.task_cookie += 100;
    assert!(process_image(&files, &reused).is_none());
}

#[test]
fn clone3_thread_flags_create_no_child() {
    let mut threaded = call(1, CLONE3, "clone3", 99);
    threaded.entry.as_mut().unwrap().args = Some([0x1000, 88, 0, 0, 0, 0]);
    threaded.entry.as_mut().unwrap().fields.push(captured(
        "arg0.clone_args.flags",
        "u64",
        &CLONE_THREAD.to_le_bytes(),
    ));
    let lines = process_tree_lines(&[threaded]);
    assert!(
        lines.iter().all(|line| !line.contains("pid 99")),
        "{lines:?}"
    );

    let mut spawned = call(1, CLONE3, "clone3", 77);
    spawned.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 88, 0, 0, 0, 0]);
    spawned.entry.as_mut().unwrap().fields.push(captured(
        "arg0.clone_args.flags",
        "u64",
        &0u64.to_le_bytes(),
    ));
    let lines = process_tree_lines(&[spawned]);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("pid 77") && line.starts_with("  ")),
        "{lines:?}"
    );

    let mut missing = call(1, CLONE3, "clone3", 66);
    missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
    let lines = process_tree_lines(&[missing]);
    assert!(
        lines.iter().all(|line| !line.contains("pid 66")),
        "{lines:?}"
    );
}

#[test]
fn child_whose_parent_pid_is_absent_contains_parent_not_in_this_trace() {
    let lines = process_tree_lines(&[call(42, 1, "write", 0)]);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("parent not in this trace"),
        "{}",
        lines[0]
    );
    assert!(lines[0].starts_with("pid 42"), "{}", lines[0]);
}

#[test]
fn write_fd_argument_is_shown_not_the_return() {
    let mut write = call(9, 1, "write", 100);
    write.entry.as_mut().unwrap().args = Some([5, 0x1000, 100, 0, 0, 0]);
    let rows = file_rows(&[write], &["write"]);
    assert_eq!(rows.rows.len(), 1);
    assert!(!rows.stopped_early);
    assert_eq!(rows.rows[0][2].text, "5");
    assert_eq!(rows.rows[0][4].text, "100");
    assert_ne!(rows.rows[0][0].text, "100");

    let mut opened = call(9, 257, "openat", 7);
    opened
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.path", "", b"/etc/passwd\0"));
    let rows = file_rows(&[opened], &["openat"]);
    assert_eq!(rows.rows[0][0].text, "/etc/passwd");
    assert_eq!(rows.rows[0][2].text, "7");

    let failed = call(9, 2, "open", -2);
    assert_eq!(file_rows(&[failed], &["open"]).rows[0][2].text, "—");

    let unlinked = call(9, 87, "unlink", 0);
    assert_eq!(file_rows(&[unlinked], &["unlink"]).rows[0][2].text, "—");
}

#[test]
fn bpf_program_finding_skips_maps_and_requires_socket_level() {
    let mut load = call(1, 321, "bpf", 3);
    load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    let mut create = call(1, 321, "bpf", -1);
    create.entry.as_mut().unwrap().args = Some([0, 0, 0, 0, 0, 0]);
    let mut attached = call(1, 54, "setsockopt", 0);
    attached.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
    let mut other = call(1, 54, "setsockopt", 0);
    other.entry.as_mut().unwrap().args = Some([4, 6, 26, 0, 0, 0]);
    let rules: Vec<_> = suspicious_rows(&[load, create, attached, other])
        .into_iter()
        .map(|row| row.cells[0].text.clone())
        .collect();
    assert_eq!(rules, ["bpf.program", "bpf.socket_filter"]);

    let mut bytes = call(1, 321, "bpf", 0);
    bytes.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    bytes.entry.as_mut().unwrap().fields.push(captured(
        "buf",
        "linux-6.12.94/x86_64/bpf_insn[]",
        &[0xb7, 0, 0, 0, 0, 0, 0, 0],
    ));
    let notes = page_notes(&[bytes]);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].heading.contains("BPF_PROG_LOAD"));
    assert!(notes[0].translation.is_none());
    assert_eq!(notes[0].outcome, "returned 0");
    assert_eq!(notes[0].lifecycle.as_deref(), Some("loaded program fd 0"));

    let mut image = call(1, 321, "bpf", 0);
    image.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    image.entry.as_mut().unwrap().fields.push(captured(
        "arg1.attr.insns",
        "linux-6.12.94/x86_64/bpf_insn[]",
        &[0xb7, 0, 0, 0, 0, 0, 0, 0],
    ));
    let notes = page_notes(&[image]);
    let text = notes[0].translation.as_deref().unwrap_or("");
    assert!(text.contains("mov64 r0, 0"), "{text}");

    let mut filter = call(1, 317, "seccomp", 0);
    filter.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
    let notes = page_notes(&[filter]);
    assert!(notes[0].heading.contains("SECCOMP_SET_MODE_FILTER"));
    assert!(notes[0].translation.is_none());
    assert_eq!(
        notes[0].lifecycle.as_deref(),
        Some("seccomp installation successful")
    );

    let mut prctl = call(1, 157, "prctl", 0);
    prctl.entry.as_mut().unwrap().args = Some([22, 2, 0, 0, 0, 0]);
    assert!(page_notes(&[prctl])[0]
        .heading
        .contains("SECCOMP_MODE_FILTER"));

    let mut lookup = call(1, 321, "bpf", 0);
    lookup.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
    assert!(page_notes(&[lookup.clone()])[0]
        .heading
        .contains("BPF_MAP_LOOKUP_ELEM"));
    assert!(page_notes(&[lookup.clone()])[0].lifecycle.is_none());
    assert!(suspicious_rows(&[lookup]).is_empty());

    let mut denied = call(1, 321, "bpf", -13);
    denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[denied])[0].lifecycle.as_deref(),
        Some("load failed (-13)")
    );
    let mut pending = call(1, 321, "bpf", 4);
    pending.exit = None;
    pending.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[pending])[0].lifecycle.as_deref(),
        Some("attach attempted; exit not recorded")
    );
    let mut attached_prog = call(1, 321, "bpf", 7);
    attached_prog.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[attached_prog])[0].lifecycle.as_deref(),
        Some("attach returned 7; interpretation depends on recorded flags")
    );
    let mut detach = call(1, 321, "bpf", 0);
    detach.entry.as_mut().unwrap().args = Some([9, 0, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[detach])[0].lifecycle.as_deref(),
        Some("detach successful")
    );
    let mut socket = call(1, 54, "setsockopt", 0);
    socket.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
    assert_eq!(
        page_notes(&[socket])[0].lifecycle.as_deref(),
        Some("socket attachment successful")
    );
}

#[test]
fn write_fd_copied_at_fork_is_not_shared_with_parent() {
    let mut opened = call(1, 257, "openat", 7);
    opened
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.path", "", b"/etc/passwd\0"));
    let forked = call(1, FORK, "fork", 42);
    let mut child_write = call(42, 1, "write", 3);
    child_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let rows = file_rows(
        &[opened.clone(), forked.clone(), child_write.clone()],
        &["write"],
    );
    assert_eq!(rows.rows[0][0].text, "/etc/passwd");
    assert_eq!(rows.rows[0][2].text, "7");

    let mut child_close = call(42, 3, "close", 0);
    child_close.entry.as_mut().unwrap().args = Some([7, 0, 0, 0, 0, 0]);
    let mut parent_write = call(1, 1, "write", 3);
    parent_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let rows = file_rows(
        &[
            opened.clone(),
            forked,
            child_close,
            child_write,
            parent_write,
        ],
        &["write"],
    );
    assert_eq!(rows.rows.len(), 2);
    assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
    assert_eq!(rows.rows[1][0].text, "/etc/passwd");

    let mut thread = call(1, CLONE, "clone", 99);
    thread.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 0, 0, 0, 0, 0]);
    let mut thread_write = call(99, 1, "write", 3);
    thread_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let rows = file_rows(&[opened.clone(), thread, thread_write], &["write"]);
    assert_eq!(rows.rows[0][0].text, "/etc/passwd");

    let mut missing = call(1, CLONE3, "clone3", 77);
    missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
    let mut missing_write = call(77, 1, "write", 3);
    missing_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
    let rows = file_rows(&[opened, missing, missing_write], &["write"]);
    assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
}

pub(super) fn path_call(
    pid: u32,
    nr: u64,
    name: &str,
    result: i64,
    path: &str,
) -> InvocationSummary {
    let mut row = call(pid, nr, name, result);
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg0.pathname", "", &bytes));
    row
}

#[test]
fn ordinary_exec_is_not_a_unix_shell_and_sigsuspend_is_not_privilege() {
    let rows = suspicious_rows(&[
        path_call(1, 59, "execve", 0, "/bin/ls"),
        path_call(1, 59, "execve", 0, "/bin/sh"),
        call(1, 130, "rt_sigsuspend", 0),
        call(1, 105, "setuid", 0),
    ]);
    let text = |row: &Finding, key: &str| -> String {
        row.values
            .iter()
            .find_map(|(name, value)| match (*name, value) {
                (name, RowValue::Text(text)) if name == key => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_default()
    };
    let exec = |needle: &str| {
        rows.iter()
            .find(|row| {
                text(row, "finding.rule") == "process.exec"
                    && text(row, "finding.summary").contains(needle)
            })
            .unwrap()
    };
    assert_eq!(
        text(exec("/bin/ls"), "finding.source"),
        "Observed process execution"
    );
    assert_eq!(
        text(exec("/bin/sh"), "finding.source"),
        "MITRE ATT&CK T1059.004"
    );
    assert!(rows.iter().all(|row| {
        text(row, "finding.rule") != "privilege.change"
            || !text(row, "finding.summary").contains("rt_sigsuspend")
    }));
    assert!(rows.iter().any(|row| {
        text(row, "finding.rule") == "privilege.change"
            && text(row, "finding.summary").contains("setuid")
    }));
}

#[test]
fn clone_files_does_not_share_cwd_and_relative_chdir_is_applied() {
    let start = path_call(1, 80, "chdir", 0, "/tmp");
    let mut files_only = call(1, CLONE, "clone", 42);
    files_only.entry.as_mut().unwrap().args = Some([CLONE_FILES, 0, 0, 0, 0, 0]);
    let parent_move = path_call(1, 80, "chdir", 0, "later");
    let mut child_open = call(42, 257, "openat", 3);
    child_open.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
    child_open
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.path", "", b"note\0"));
    let rows = file_rows(&[start, files_only, parent_move, child_open], &["openat"]);
    assert_eq!(rows.rows.len(), 1, "{}", rows.rows.len());
    assert_eq!(
        rows.rows[0][0].text,
        "/tmp/note (lexical cwd path; symlinks unknown)"
    );

    let start = path_call(1, 80, "chdir", 0, "/tmp");
    let relative = path_call(1, 80, "chdir", 0, "sub");
    let mut opened = call(1, 257, "openat", 4);
    opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
    opened
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.path", "", b"note\0"));
    let rows = file_rows(&[start, relative, opened], &["openat"]);
    assert_eq!(
        rows.rows[0][0].text,
        "/tmp/sub/note (lexical cwd path; symlinks unknown)"
    );

    let start = path_call(1, 80, "chdir", 0, "/tmp");
    let mut shared = call(1, CLONE, "clone", 42);
    shared.entry.as_mut().unwrap().args = Some([CLONE_FILES | CLONE_FS, 0, 0, 0, 0, 0]);
    let parent_move = path_call(1, 80, "chdir", 0, "/var");
    let mut child_open = call(42, 257, "openat", 3);
    child_open.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
    child_open
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.path", "", b"note\0"));
    let rows = file_rows(&[start, shared, parent_move, child_open], &["openat"]);
    assert_eq!(
        rows.rows[0][0].text,
        "/var/note (lexical cwd path; symlinks unknown)"
    );
}

#[test]
fn private_writable_mmap_is_not_a_changed_file() {
    let mut private = call(1, 9, "mmap", 0x1000);
    private.entry.as_mut().unwrap().args = Some([0, 4096, 2, MAP_PRIVATE, 3, 0]);
    let mut shared = call(1, 9, "mmap", 0x2000);
    shared.entry.as_mut().unwrap().args = Some([0, 4096, 2, 1, 3, 0]);
    let rows = file_rows(&[private, shared], &["mmap"]);
    assert_eq!(rows.rows.len(), 1, "{}", rows.rows.len());
    assert_eq!(rows.rows[0][3].text, "mmap");
}

#[test]
fn bpf_program_attach_uses_the_loaded_fd() {
    let mut load = call(1, 321, "bpf", 6);
    load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    let mut attach = call(1, 321, "bpf", 0);
    attach.entry.as_mut().unwrap().args = Some([8, 6, 0, 0, 0, 0]);
    let notes = page_notes(&[load.clone(), attach]);
    assert_eq!(notes[0].lifecycle.as_deref(), Some("loaded program fd 6"));
    assert_eq!(notes[1].lifecycle.as_deref(), Some("attach successful"));
    assert_eq!(suspicious_rows(&[load])[0].cells[8].text, "1");

    let mut other = call(1, 321, "bpf", 7);
    other.entry.as_mut().unwrap().args = Some([8, 4, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[other])[0].lifecycle.as_deref(),
        Some("attach returned 7; interpretation depends on recorded flags")
    );

    let mut denied = call(1, 321, "bpf", -13);
    denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
    let mut attach_exit = call(1, 321, "bpf", 3);
    attach_exit.entry.as_mut().unwrap().args = Some([8, 3, 0, 0, 0, 0]);
    assert_eq!(
        page_notes(&[denied, attach_exit])[1].lifecycle.as_deref(),
        Some("attach returned 3; interpretation depends on recorded flags")
    );
}

#[test]
fn a_long_content_cell_shows_a_bounded_hover_and_keeps_the_full_value() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 22.0);
    let long = format!("4096 B: {}", "ELF\\x02\\x01".repeat(200));
    let rows = vec![vec![
        cell("12:00:00", theme::text(), true),
        cell("/tmp/sample", theme::text(), true),
        cell(long.clone(), theme::text(), true),
    ]];
    let headers = ["Time", "Path", "Transferred / content"];
    let draw = |events, time| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 600.0),
                )),
                events,
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| table(ui, "triage-read", &headers, &rows));
            },
        )
    };
    fn shown(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
        fn all(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(t) => {
                    out.push((t.galley.text().to_owned(), t.visual_bounding_rect()))
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| all(s, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        output.shapes.iter().for_each(|s| all(&s.shape, &mut out));
        out
    }
    let first = draw(vec![], 0.0);
    let cell_rect = shown(&first)
        .into_iter()
        .find(|(text, _)| text.starts_with("4096 B:"))
        .unwrap()
        .1;
    let mut output = first;
    for frame in 0..40 {
        output = draw(
            vec![egui::Event::PointerMoved(
                cell_rect.left_center() + egui::vec2(30.0, 0.0),
            )],
            0.1 + f64::from(frame) * 0.05,
        );
    }
    let texts: Vec<_> = shown(&output)
        .into_iter()
        .filter(|(text, _)| text.starts_with("4096 B:"))
        .collect();
    assert!(texts.len() >= 2, "the cell and its hover text are drawn");
    for (text, rect) in &texts {
        assert!(
            text.chars().count() <= 240 + 30,
            "{} characters",
            text.chars().count()
        );
        assert!(rect.height() < 600.0, "hover box fits the window: {rect:?}");
    }
    assert_eq!(rows[0][2].text, long, "Details keeps the full value");
}
