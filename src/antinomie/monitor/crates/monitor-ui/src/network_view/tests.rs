// SPDX-License-Identifier: MIT
#[test]
fn explicit_evidence_jump_reveals_a_frame_hidden_by_prior_filters() {
    let mut view = super::NetworkView::default();
    view.open(Some(std::path::PathBuf::from("/fixture/run.pcap")));
    view.filter = "old quick search".into();
    view.applied_filter = "old quick search".into();
    view.display_filter = "dns".into();
    view.jump_to_evidence(520).unwrap();
    assert!(
        view.filter.is_empty() && view.applied_filter.is_empty() && view.display_filter.is_empty()
    );
    assert_eq!(view.display_jump, Some(520));
}

use super::*;

#[test]
fn disconnected_capture_warning_is_visible_while_inspecting_saved_packets() {
    for enabled in [false, true] {
        let mut view = NetworkView {
            captures_for: Some((None, vec![])),
            list: PacketList::new(Some(PathBuf::from("/tmp/missing-saved-network.pcap"))),
            ..Default::default()
        };
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        view.show(
                            ui,
                            NetworkContext {
                                active: None,
                                recordings: None,
                                recording_roots: &[],
                                nat: enabled,
                                running: true,
                                pending: false,
                                boot_id: None,
                                font_size: 16.0,
                            },
                        );
                    });
                },
            );
        }
        let text: String = crate::app::tests::texts(&output)
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert_eq!(
            text.contains("Disconnected: network capture is unavailable"),
            !enabled
        );
        assert!(
            view.list.path.is_some(),
            "saved capture selection is retained"
        );
    }
}

fn ok_filter(text: &str) -> Filter {
    Filter::parse(text)
}

fn packet(protocol: &str, source: &str, destination: &str) -> NetworkPacket {
    let parse = |text: &str| -> (Option<IpAddr>, Option<u16>) {
        match text.parse::<SocketAddr>() {
            Ok(endpoint) => (Some(endpoint.ip()), Some(endpoint.port())),
            Err(_) => (text.parse().ok(), None),
        }
    };
    let ((src_ip, src_port), (dst_ip, dst_port)) = (parse(source), parse(destination));
    NetworkPacket {
        source: source.into(),
        destination: destination.into(),
        protocol: protocol.into(),
        info: format!("{protocol} info"),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags: (protocol == "TCP").then_some(0x10),
        ..NetworkPacket::default()
    }
}

#[test]
fn display_filter_preserves_page_selection_and_prior_result_on_error_if_tshark_installed() {
    use std::io::Write;
    if !std::process::Command::new("tshark")
        .arg("-v")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "antinomie-packet-view-{}-{stamp}.pcap",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
    file.write_all(&2u16.to_le_bytes()).unwrap();
    file.write_all(&4u16.to_le_bytes()).unwrap();
    file.write_all(&[0; 8]).unwrap();
    file.write_all(&65535u32.to_le_bytes()).unwrap();
    file.write_all(&1u32.to_le_bytes()).unwrap();
    for number in 0..520u32 {
        file.write_all(&(1_700_000_000 + number).to_le_bytes())
            .unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&14u32.to_le_bytes()).unwrap();
        file.write_all(&14u32.to_le_bytes()).unwrap();
        file.write_all(&[0; 14]).unwrap();
    }
    drop(file);
    let original = std::fs::read(&path).unwrap();
    let ctx = egui::Context::default();
    let mut view = NetworkView::default();
    view.open(Some(path.clone()));
    view.display_filter = "frame.number > 10".into();
    let wait = |view: &mut NetworkView, error: bool| {
        let started = Instant::now();
        loop {
            view.refresh_display(false, &ctx);
            if !view.display_pending
                && if error {
                    view.display_error.is_some()
                } else {
                    // The index, TShark's parse finished and the page filled.
                    view.display_index.as_ref().is_some_and(|index| {
                        index.rows().status() != ParseStatus::Parsing
                            && view.display_page.len() as u64
                                >= index
                                    .matching_count
                                    .saturating_sub(view.display_page_start)
                                    .min(PAGE_SIZE as u64)
                    })
                }
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "display worker timeout: {:?}",
                view.display_error
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    wait(&mut view, false);
    assert_eq!(view.display_index.as_ref().unwrap().matching_count, 510);
    assert_eq!(view.display_page.first().unwrap().number, 11);
    assert_eq!(view.display_page.last().unwrap().number, 510);
    view.list.selected = Some(view.display_page[20].clone());
    let selected = view.list.selected.clone().unwrap();
    view.list.frame = Some((selected.offset, Ok(vec![0; 14])));
    let index = Arc::clone(view.display_index.as_ref().unwrap());
    view.display_generation = view
        .display_worker
        .as_ref()
        .unwrap()
        .request_page(index, 500);
    view.display_pending = true;
    wait(&mut view, false);
    assert_eq!(view.display_page_start, 500);
    assert_eq!(view.display_page.first().unwrap().number, 511);
    assert_eq!(view.display_page.len(), 10);
    assert_eq!(view.list.selected, Some(selected.clone()));
    assert_eq!(view.list.frame, Some((selected.offset, Ok(vec![0; 14]))));
    view.display_filter = "tcp.port in {".into();
    view.display_requested = None;
    wait(&mut view, true);
    assert_eq!(
        view.display_index.as_ref().unwrap().expression,
        "frame.number > 10"
    );
    assert_eq!(view.display_page_start, 500);
    assert_eq!(view.list.selected, Some(selected));
    view.apply_filter();
    assert_eq!(view.list.rows.len(), 10);
    view.jump_to_frame(20).unwrap();
    wait(&mut view, false);
    assert_eq!(view.list.selected.as_ref().unwrap().number, 20);
    assert_eq!(view.display_page_start, 0);
    view.jump_to_frame(520).unwrap();
    wait(&mut view, false);
    assert_eq!(view.list.selected.as_ref().unwrap().number, 520);
    assert_eq!(view.display_page_start, 500);
    view.jump_to_frame(5).unwrap();
    wait(&mut view, false);
    assert_eq!(view.list.selected.as_ref().unwrap().number, 5);
    assert!(view
        .display_jump_note
        .as_ref()
        .unwrap()
        .contains("hidden by the current display filter"));
    assert_eq!(
        view.display_index.as_ref().unwrap().expression,
        "frame.number > 10"
    );
    assert_eq!(view.display_filter, "tcp.port in {");
    assert_eq!(view.display_page_start, 500);
    view.filter = "missing-packet-text".into();
    view.apply_filter();
    assert!(view.list.selected.is_none());
    view.jump_to_frame(510).unwrap();
    view.jump_to_frame(515).unwrap();
    wait(&mut view, false);
    assert_eq!(view.list.selected.as_ref().unwrap().number, 515);
    assert!(view
        .display_jump_note
        .as_ref()
        .unwrap()
        .contains("hidden by the current quick search"));
    assert!(view.jump_to_frame(0).is_err());
    view.filter.clear();
    view.apply_filter();
    view.display_filter = "frame.number > 515".into();
    view.display_requested = None;
    view.display_rejected = None;
    wait(&mut view, false);
    assert!(view.list.selected.is_none());
    assert!(view
        .display_jump_note
        .as_ref()
        .unwrap()
        .contains("hides frame 515"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    drop(view);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn capture_record_filters_cover_annotations_partial_state_and_missing_counts() {
    use antinomie_monitor_core::annotations::Annotation;
    let capture = NetworkCapture {
        id: "capture-a".into(),
        boot_id: "boot-a".into(),
        file: PathBuf::from("/recordings/network/a.pcap"),
        started_ms: 12,
        stopped_ms: None,
        packets: None,
        bytes: None,
        whole_boot: true,
    };
    let annotation = Annotation {
        name: "First DNS query".into(),
        tags: vec!["needs review".into()],
    };
    let row = capture_row_values(&capture, Some(&annotation), false);
    let query = crate::query::compile_table("tag == \"needs review\" && name contains \"DNS\" && state == \"unfinished\" && missing(packets) && whole_boot == true", &capture_fields());
    assert!(query.error.is_none(), "{:?}", query.error);
    assert!(query.keep_table(&row));
    let zero = crate::query::compile_table("packets == 0", &capture_fields());
    assert!(!zero.keep_table(&row));
    let mut completed = capture;
    completed.stopped_ms = Some(24);
    completed.packets = Some(0);
    completed.bytes = Some(24);
    assert!(zero.keep_table(&capture_row_values(&completed, Some(&annotation), false)));
    let identity = crate::query::compile_table("entry.kind == \"network\" && boot.id == \"boot-a\" && entry.complete == true && entry.size == 24", &capture_fields());
    assert!(identity.keep_table(&capture_row_values(&completed, Some(&annotation), false)));
}

#[test]
fn hex_dump_pads_short_rows_and_marks_the_chosen_bytes() {
    let bytes = b"GET / HTTP/1.1\r\nHost";
    let job = hex_job(bytes, &theme::mono(14.0), Some(4..6), None);
    let lines: Vec<_> = job.text.lines().collect();
    assert_eq!(
        lines[0],
        "0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1.."
    );
    assert!(lines[1].starts_with("0010  48 6f 73 74"));
    assert!(lines[1].ends_with("  Host"));
    // Bytes 4 and 5 ("2f", "20", the space between, "/", " ") are marked.
    let marked: String = job
        .sections
        .iter()
        .filter(|section| section.format.background == theme::palette().selection)
        .map(|section| &job.text[section.byte_range.clone()])
        .collect();
    assert_eq!(marked, "2f 20/ ");
    assert_eq!(format_date(1_791_554_943), "2026-10-09 14:09:03 UTC");
    assert_eq!(format_date(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(format_duration(6_404), "6 s");
    assert_eq!(format_duration(125_000), "2 min 5 s");
    assert_eq!(format_bytes(3_620), "3620 bytes (3.5 KB)");
}

#[test]
fn filters_match_ports_addresses_endpoints_protocols_and_text() {
    let dns = packet("DNS", "10.0.2.15:5353", "10.0.2.3:53");
    let http = packet("HTTP", "10.0.2.15:40000", "93.184.216.34:80");
    let ping = packet("ICMPv6", "fe80::1", "ff02::1");
    let v6 = packet("UDP", "[fe80::1]:546", "[ff02::1:2]:547");
    let all = [&dns, &http, &ping, &v6];
    let matching = |filter: &str| -> Vec<&str> {
        let filter = ok_filter(filter);
        all.iter()
            .filter(|packet| filter.matches(packet))
            .map(|packet| packet.protocol.as_str())
            .collect()
    };
    assert_eq!(matching(""), ["DNS", "HTTP", "ICMPv6", "UDP"]);
    assert_eq!(matching("port 53"), ["DNS"]);
    assert_eq!(matching("Port 80"), ["HTTP"]);
    assert_eq!(matching("ip 10.0.2.15"), ["DNS", "HTTP"]);
    assert_eq!(matching("10.0.2.3"), ["DNS"]);
    assert_eq!(matching("fe80::1"), ["ICMPv6", "UDP"]);
    assert_eq!(matching("10.0.2.15:5353"), ["DNS"]);
    assert_eq!(matching("[ff02::1:2]:547"), ["UDP"]);
    assert_eq!(matching("proto http"), ["HTTP"]);
    assert_eq!(matching("icmp"), ["ICMPv6"]);
    assert_eq!(matching("info"), ["DNS", "HTTP", "ICMPv6", "UDP"]);
    // "port 5" is port 5, not every port starting with 5.
    assert!(matching("port 5").is_empty());
    assert_eq!(ok_filter("port x"), Filter::Text("port x".into()));
}

#[test]
fn quick_filter_counts_are_sorted_by_use() {
    let packets = vec![
        packet("HTTP", "10.0.2.15:40000", "1.2.3.4:80"),
        packet("TCP", "1.2.3.4:80", "10.0.2.15:40000"),
        packet("TCP", "10.0.2.15:40001", "1.2.3.4:443"),
        packet("DNS", "10.0.2.15:53", "10.0.2.3:53"),
    ];
    let counts = counts(&packets);
    assert_eq!(
        counts.ports,
        [(80, 2), (40000, 2), (53, 1), (443, 1), (40001, 1)]
    );
    assert_eq!(counts.addresses[0], ("10.0.2.15".parse().unwrap(), 4));
    assert_eq!(counts.addresses[1], ("1.2.3.4".parse().unwrap(), 3));
    assert_eq!(
        counts.protocols,
        [("TCP".to_owned(), 2), ("DNS".into(), 1), ("HTTP".into(), 1)]
    );
}

#[test]
fn quick_filter_counts_keep_only_the_entries_the_lists_show() {
    // A busy capture has a distinct port and address per packet; only the
    // most used QUICK_ENTRIES of each are listed, so only those are kept.
    let packets: Vec<_> = (0..QUICK_ENTRIES as u32 * 5)
        .map(|n| {
            let mut packet = packet("TCP", "10.0.2.15:1", "1.2.3.4:80");
            packet.src_ip = Some(IpAddr::from([10, 0, (n >> 8) as u8, n as u8]));
            packet.src_port = Some(1000 + n as u16);
            packet
        })
        .collect();
    let counts = counts(&packets);
    assert_eq!(counts.ports.len(), QUICK_ENTRIES);
    assert_eq!(counts.addresses.len(), QUICK_ENTRIES);
    // The busiest entries survive: every packet shares 1.2.3.4 and port 80.
    assert_eq!(counts.ports[0], (80, packets.len()));
    assert_eq!(
        counts.addresses[0],
        ("1.2.3.4".parse().unwrap(), packets.len())
    );
}

#[test]
fn packets_are_colored_like_wireshark() {
    let mut syn = packet("TCP", "10.0.2.15:40000", "1.2.3.4:80");
    syn.tcp_flags = Some(network::TCP_SYN);
    let mut reset = syn.clone();
    reset.tcp_flags = Some(network::TCP_RST | 0x10);
    assert_eq!(packet_color(&syn), Some(PacketColor::TcpSynFin));
    assert_eq!(packet_color(&reset), Some(PacketColor::TcpReset));
    let plain = packet("TCP", "10.0.2.15:40000", "1.2.3.4:80");
    assert_eq!(packet_color(&plain), Some(PacketColor::Tcp));
    for (protocol, color) in [
        ("HTTP", PacketColor::Http),
        ("TLS", PacketColor::Tls),
        ("DNS", PacketColor::Dns),
        ("DHCP", PacketColor::Dhcp),
        ("ARP", PacketColor::Arp),
        ("ICMP", PacketColor::Icmp),
        ("ICMPv6", PacketColor::Icmp),
        ("UDP", PacketColor::Udp),
    ] {
        assert_eq!(packet_color(&packet(protocol, "", "")), Some(color));
    }
    assert_eq!(packet_color(&packet("0x88cc", "", "")), None);
}

#[test]
fn filtered_rows_follow_new_packets_and_filter_changes() {
    let mut list = PacketList::default();
    list.packets
        .push(packet("DNS", "10.0.2.15:5353", "10.0.2.3:53"));
    list.filter_rows("port 53");
    assert_eq!(list.rows, [0]);
    list.packets
        .push(packet("HTTP", "10.0.2.15:4000", "1.2.3.4:80"));
    list.packets
        .push(packet("DNS", "10.0.2.3:53", "10.0.2.15:5353"));
    list.filter_rows("port 53");
    assert_eq!(list.rows, [0, 2]);
    list.filter_rows("proto HTTP");
    assert_eq!(list.rows, [1]);
    list.filter_rows("");
    assert_eq!(list.rows, [0, 1, 2]);
}

#[test]
fn capture_history_merges_retained_roots_and_deduplicates_moved_captures() {
    let fixture = std::env::temp_dir().join(format!(
        "ant-network-roots-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let current = fixture.join("current");
    let prior = fixture.join("prior");
    let write_capture = |root: &Path, boot: &str, id: &str, started_ms: u64| {
        let mut capture = NetworkCapture::new(&root.join("boots").join(boot), boot, id, started_ms);
        capture.stopped_ms = Some(started_ms + 1_000);
        std::fs::create_dir_all(capture.file.parent().unwrap()).unwrap();
        std::fs::write(&capture.file, []).unwrap();
        let mut saved = capture.clone();
        saved.file = capture.file.file_name().unwrap().into();
        std::fs::write(capture.summary_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
        capture
    };
    let newest = write_capture(&current, "b-current", "moved", 4_000_000_000_000);
    // A retained root may contain the same capture after a location move.
    write_capture(&prior, "b-current", "moved", newest.started_ms);
    let older = write_capture(&prior, "b-prior", "older", 3_000_000_000_000);
    let legacy = prior.join("boots/b-legacy").join(network::PCAP_FILE);
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    let mut header = Vec::new();
    header.extend(0xa1b2c3d4u32.to_le_bytes());
    header.extend(2u16.to_le_bytes());
    header.extend(4u16.to_le_bytes());
    header.extend([0u8; 8]);
    header.extend(65_535u32.to_le_bytes());
    header.extend(1u32.to_le_bytes());
    // A fixed first-packet timestamp makes ordering independent of the
    // host clock and the file's modification time.
    header.extend(1_000_000_000u32.to_le_bytes());
    header.extend(0u32.to_le_bytes());
    header.extend(14u32.to_le_bytes());
    header.extend(14u32.to_le_bytes());
    header.extend([0u8; 14]);
    std::fs::write(&legacy, header).unwrap();
    let retained = [
        prior.clone(),
        current.clone(),
        prior.join("."),
        prior.clone(),
    ];
    let captures = capture_history(Some(&current), &retained);
    assert_eq!(captures.len(), 3);
    assert_eq!(captures[0], newest);
    assert_eq!(captures[1], older);
    assert_eq!(captures[2].file, legacy);
    assert!(captures[2].whole_boot);
    std::fs::remove_dir_all(fixture).unwrap();
}

/// A pcap of `count` distinct TCP and UDP frames, like a busy capture.
fn busy_pcap(count: u32) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend(0xa1b2c3d4u32.to_le_bytes());
    file.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    file.extend(65535u32.to_le_bytes());
    file.extend(1u32.to_le_bytes());
    for n in 0..count {
        let tcp = n % 2 == 0;
        let mut transport = if tcp {
            let mut header = Vec::new();
            header.extend(((40_000 + n % 20_000) as u16).to_be_bytes());
            header.extend(([443u16, 80, 8080][(n % 3) as usize]).to_be_bytes());
            header.extend(n.to_be_bytes());
            header.extend(0u32.to_be_bytes());
            header.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
            header
        } else {
            let mut header = vec![0x14, 0xe9, 0, 53, 0, 8, 0, 0];
            header.extend(b"");
            header
        };
        transport.extend(std::iter::repeat_n(b'a', (n % 40) as usize));
        let mut frame = vec![
            0x52, 0x55, 10, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 8, 0,
        ];
        let total = (20 + transport.len()) as u16;
        frame.extend([0x45, 0]);
        frame.extend(total.to_be_bytes());
        frame.extend([0, 0, 0x40, 0, 64, if tcp { 6 } else { 17 }, 0, 0]);
        frame.extend([10, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
        frame.extend([93, 184, (n >> 8) as u8, n as u8]);
        frame.extend(&transport);
        file.extend((1_800_000_000 + n / 1000).to_le_bytes());
        file.extend((n % 1000 * 1000).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend(frame);
    }
    file
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn memory_probe_packet_list_at_its_cap() {
    use crate::memory_probe::{anon_kib, report};
    let path = std::env::temp_dir().join(format!("ant-mem-probe-{}.pcap", std::process::id()));
    std::fs::write(&path, busy_pcap(220_000)).unwrap();
    let before = anon_kib();
    let mut list = PacketList::new(Some(path.clone()));
    while !list.truncated {
        list.last_read = None;
        list.refresh(false);
    }
    let loaded = anon_kib();
    report("network", "packets", list.packets.len());
    report("network", "packet_list_kib", loaded as i64 - before as i64);
    list.filter_rows("");
    let rows = anon_kib();
    report("network", "rows_kib", rows as i64 - loaded as i64);
    let _ = list.counts();
    report(
        "network",
        "quick_counts_kib",
        anon_kib() as i64 - rows as i64,
    );
    report(
        "network",
        "quick_count_entries",
        list.counts
            .as_ref()
            .map_or(0, |(_, c)| c.ports.len() + c.addresses.len()),
    );
    drop(list);
    std::fs::remove_file(path).unwrap();
}

fn fixture_capture() -> NetworkCapture {
    NetworkCapture {
        id: "cap-1".into(),
        boot_id: "boot-9".into(),
        file: PathBuf::from("/fixture/net/cap-1.pcap"),
        started_ms: 1_700_000_000_000,
        stopped_ms: Some(1_700_000_061_000),
        packets: Some(1234),
        bytes: Some(16_080),
        whole_boot: false,
    }
}

/// Runs one frame of the panel at `time`, feeding `events`.
fn network_frame(
    ctx: &egui::Context,
    view: &mut NetworkView,
    time: f64,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(
                    ui,
                    NetworkContext {
                        active: None,
                        recordings: None,
                        recording_roots: &[],
                        nat: true,
                        running: true,
                        pending: false,
                        boot_id: None,
                        font_size: 16.0,
                    },
                );
            });
        },
    )
}

fn view_with_capture() -> (egui::Context, NetworkView) {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let view = NetworkView {
        captures_for: Some((None, vec![])),
        captures: vec![fixture_capture()],
        ..Default::default()
    };
    (ctx, view)
}

fn text_rect(output: &egui::FullOutput, needle: &str) -> Option<egui::Rect> {
    crate::app::tests::texts(output)
        .into_iter()
        .find(|(text, _)| text.contains(needle))
        .map(|(_, rect)| rect)
}

#[test]
fn filters_share_one_section_in_order_with_gray_example_placeholders() {
    let (ctx, mut view) = view_with_capture();
    let mut output = egui::FullOutput::default();
    for frame in 0..3 {
        output = network_frame(&ctx, &mut view, f64::from(frame) * 0.1, vec![]);
    }
    let section = text_rect(&output, "Filters").expect("Filters section");
    let quick = text_rect(&output, "Quick Search").expect("quick label");
    let display = text_rect(&output, "Display Filter").expect("display label");
    let record = text_rect(&output, "Record Filter").expect("record label");
    assert!(section.top() < quick.top() && quick.top() < display.top());
    assert!(display.top() < record.top());
    assert!((quick.left() - display.left()).abs() < 2.0);
    assert!((display.left() - record.left()).abs() < 2.0);
    let (first, last) = (
        text_rect(&output, "filter e.g. port 443").unwrap(),
        text_rect(&output, "filter e.g. packets > 100").unwrap(),
    );
    assert!(
        (first.left() - last.left()).abs() < 0.5,
        "boxes start together"
    );
    for (needle, row) in [
        ("filter e.g. port 443", &quick),
        ("filter e.g. packets > 100", &record),
    ] {
        let hint = text_rect(&output, needle).expect(needle);
        assert!(
            hint.left() > row.right(),
            "{needle} sits right of its label"
        );
    }
    // Without TShark the display box is disabled and says why.
    assert!(
        text_rect(&output, "filter e.g. tcp.port == 443").is_some()
            || text_rect(&output, "filter e.g. tcp.port == 443 (needs tshark)").is_some()
    );
    // The hint color is the grayish theme token, not the typed-text color.
    let mut hint_colors = Vec::new();
    for clipped in &output.shapes {
        collect_text_colors(&clipped.shape, "filter e.g. port 443", &mut hint_colors);
    }
    assert!(!hint_colors.is_empty());
    assert!(hint_colors.iter().all(|color| *color == theme::hint()));
    assert_ne!(theme::hint(), theme::text());
    assert_ne!(theme::hint(), theme::muted());
}

fn collect_text_colors(shape: &egui::Shape, needle: &str, out: &mut Vec<egui::Color32>) {
    match shape {
        egui::Shape::Text(text) if text.galley.text().contains(needle) => {
            if let Some(section) = text.galley.job.sections.first() {
                out.push(section.format.color);
            }
        }
        egui::Shape::Vec(shapes) => shapes
            .iter()
            .for_each(|shape| collect_text_colors(shape, needle, out)),
        _ => {}
    }
}

#[test]
fn clicking_a_capture_shows_its_record_in_details_and_hover_shows_no_tooltip() {
    let (ctx, mut view) = view_with_capture();
    let mut output = egui::FullOutput::default();
    for frame in 0..3 {
        output = network_frame(&ctx, &mut view, f64::from(frame) * 0.1, vec![]);
    }
    assert!(
        text_rect(&output, &crate::time_format::local_seconds(1_700_000_000)).is_some(),
        "entry title is local time with its offset"
    );
    let row = text_rect(&output, "1234 packets").expect("capture row detail");
    let point = row.center();
    // Hover for a while: no tooltip with the path or boot appears.
    for frame in 0..8 {
        output = network_frame(
            &ctx,
            &mut view,
            1.0 + f64::from(frame) * 0.3,
            vec![egui::Event::PointerMoved(point)],
        );
    }
    assert!(text_rect(&output, "/fixture/net/cap-1.pcap").is_none());
    assert!(text_rect(&output, "boot-9").is_none());
    let click = |pressed| egui::Event::PointerButton {
        pos: point,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    };
    network_frame(&ctx, &mut view, 4.0, vec![click(true)]);
    network_frame(&ctx, &mut view, 4.1, vec![click(false)]);
    assert!(view.capture_details.is_some());
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.details(ui, 16.0));
        },
    );
    for needle in [
        "cap-1",
        "boot-9",
        "1234",
        "/fixture/net/cap-1.pcap",
        "16080 bytes (15.7 KB)",
        "Completed",
    ] {
        assert!(
            text_rect(&output, needle).is_some(),
            "Details shows {needle}"
        );
    }
}

#[test]
fn network_toolbar_has_no_colors_button() {
    let (ctx, mut view) = view_with_capture();
    let output = network_frame(&ctx, &mut view, 0.0, vec![]);
    assert!(text_rect(&output, "Colors").is_none());
}

/// One frame of the panel with its controls; the action it asks for.
fn delete_frame(
    ctx: &egui::Context,
    view: &mut NetworkView,
    time: f64,
    events: Vec<egui::Event>,
    boot_id: Option<&str>,
) -> (egui::FullOutput, Option<NetworkAction>) {
    let mut action = None;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                action = view.show(
                    ui,
                    NetworkContext {
                        active: None,
                        recordings: None,
                        recording_roots: &[],
                        nat: true,
                        running: true,
                        pending: false,
                        boot_id,
                        font_size: 16.0,
                    },
                );
            });
        },
    );
    (output, action)
}

/// Right-click the row showing `detail`, then click Delete…. Returns whether
/// the menu had a Delete… item, and the action the click asked for.
fn right_click_delete(
    view: &mut NetworkView,
    detail: &str,
    boot_id: Option<&str>,
) -> (bool, Option<NetworkAction>) {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut time = 0.0;
    let mut frame = |view: &mut NetworkView, events: Vec<egui::Event>| {
        time += 0.1;
        delete_frame(&ctx, view, time, events, boot_id)
    };
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = frame(view, vec![]).0;
    }
    let point = text_rect(&output, detail).expect("capture row").center();
    let button = |pressed, button| egui::Event::PointerButton {
        pos: point,
        button,
        pressed,
        modifiers: Default::default(),
    };
    frame(view, vec![egui::Event::PointerMoved(point)]);
    frame(view, vec![button(true, egui::PointerButton::Secondary)]);
    frame(view, vec![button(false, egui::PointerButton::Secondary)]);
    for _ in 0..2 {
        output = frame(view, vec![]).0;
    }
    let Some(item) = text_rect(&output, "Delete…") else {
        return (false, None);
    };
    let point = item.center();
    let click = |pressed| egui::Event::PointerButton {
        pos: point,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    };
    let mut asked = None;
    for events in [
        vec![egui::Event::PointerMoved(point)],
        vec![click(true)],
        vec![click(false)],
        vec![],
    ] {
        asked = frame(view, events).1.or(asked);
    }
    (true, asked)
}

#[test]
fn a_saved_capture_has_a_delete_item_that_asks_to_delete_it() {
    let dir = std::env::temp_dir().join(format!("ant-net-delete-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("cap-1.pcap");
    std::fs::write(&file, vec![0u8; 4096]).unwrap();
    let (_, mut view) = view_with_capture();
    view.captures[0].file = file.clone();
    view.record_shown.insert(file.clone());
    let (present, asked) = right_click_delete(&mut view, "1234 packets", Some("other-boot"));
    assert!(present, "the menu has Delete…");
    let Some(NetworkAction::Delete(deletion)) = asked else {
        panic!("Delete… asks the app to delete, got {asked:?}");
    };
    assert_eq!(
        deletion.item,
        antinomie_monitor_core::EvidenceItem::NetworkCapture { file: file.clone() }
    );
    assert_eq!(deletion.size, "4096 bytes (4.0 KB)");
    // Asking does not delete: the app confirms first.
    assert!(file.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_capture_still_being_written_cannot_be_deleted() {
    let (_, mut view) = view_with_capture();
    view.captures[0].stopped_ms = None;
    view.record_shown.insert(view.captures[0].file.clone());
    let (present, asked) = right_click_delete(&mut view, "not stopped", Some("boot-9"));
    assert!(present, "the item is shown, disabled");
    assert_eq!(asked, None, "a disabled item asks for nothing");
    // The same capture from an earlier boot (the app ended first) can go.
    let (present, asked) = right_click_delete(&mut view, "not stopped", Some("newer-boot"));
    assert!(present);
    assert!(matches!(asked, Some(NetworkAction::Delete(_))));
}

#[test]
fn a_deleted_capture_leaves_the_list_and_clears_its_selection() {
    let (ctx, mut view) = view_with_capture();
    let file = view.captures[0].file.clone();
    view.record_shown.insert(file.clone());
    view.open(Some(file.clone()));
    view.capture_details = Some((view.captures[0].clone(), false));
    view.forget_capture(&file);
    assert!(view.captures.is_empty());
    assert!(view.list.path.is_none() && view.capture_details.is_none());
    let (output, _) = delete_frame(&ctx, &mut view, 0.0, vec![], None);
    assert!(text_rect(&output, "1234 packets").is_none());
}

#[test]
fn the_capture_size_is_not_looked_up_on_every_frame() {
    let dir = std::env::temp_dir().join(format!("ant-size-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("c.pcap");
    std::fs::write(&file, b"").unwrap();
    let mut list = PacketList::new(Some(file.clone()));
    assert!(!list.more_on_disk(&file));
    // The file grows, but the answer within the same quarter second is the
    // remembered one: no second `stat` on the render thread.
    std::fs::write(&file, b"more").unwrap();
    assert!(!list.more_on_disk(&file));
    list.size_checked = Some((Instant::now() - Duration::from_millis(300), false));
    assert!(list.more_on_disk(&file));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_launched_wireshark_does_not_stay_a_zombie() {
    let child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    toolbar::reap(child).join().unwrap();
    // Waited for: the process table has no entry left for it.
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn without_tshark_the_list_is_raw_frames_with_a_clear_notice() {
    let root = std::env::temp_dir().join(format!("ant-raw-frames-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("raw.pcap");
    std::fs::write(&path, crate::app::tests::test_pcap()).unwrap();
    let mut view = NetworkView {
        captures_for: Some((None, vec![])),
        list: PacketList::new(Some(path)),
        display_worker_error: Some("TShark unavailable: tshark is missing".into()),
        ..Default::default()
    };
    assert!(view.raw_frames());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut shown = Vec::new();
    for _ in 0..3 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 800.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(
                        ui,
                        NetworkContext {
                            active: None,
                            recordings: None,
                            recording_roots: &[],
                            nat: true,
                            running: false,
                            pending: false,
                            boot_id: None,
                            font_size: 16.0,
                        },
                    );
                });
            },
        );
        shown = crate::app::tests::texts(&output)
            .into_iter()
            .map(|(text, _)| text)
            .collect();
    }
    // The frames are listed by number, time and length only: nothing is decoded.
    assert_eq!(view.list.packets.len(), 2);
    assert!(view.list.packets.iter().all(|p| p.protocol.is_empty()));
    assert!(
        shown.iter().any(|text| text.starts_with("Raw frame, ")),
        "{shown:?}"
    );
    assert!(
        shown
            .iter()
            .any(|text| text.starts_with("TShark could not run")
                || text.starts_with("TShark not installed")),
        "{shown:?}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_tshark_notice_names_the_fix_when_it_is_not_installed() {
    assert_eq!(
        tshark_notice(false, "boom", "Frames only."),
        "TShark not installed — install it from Tools. Frames only."
    );
    assert!(tshark_notice(true, "boom", "x").starts_with("TShark could not run: boom"));
}

/// `ANTINOMIE_BIG_PCAP=<file> cargo test --release -p antinomie-monitor --
/// --ignored --nocapture big_capture_frame_times`: how long the slowest frame
/// of the Network tab takes while TShark parses a large capture.
#[test]
#[ignore = "probe; needs ANTINOMIE_BIG_PCAP"]
fn big_capture_frame_times() {
    let Ok(path) = std::env::var("ANTINOMIE_BIG_PCAP") else {
        return;
    };
    let mut view = NetworkView {
        captures_for: Some((None, vec![])),
        list: PacketList::new(Some(PathBuf::from(path))),
        ..Default::default()
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let started = Instant::now();
    let (mut worst, mut frames) = (Duration::ZERO, 0u32);
    let mut done = None;
    while started.elapsed() < Duration::from_secs(120) {
        let frame = Instant::now();
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1600.0, 900.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(
                        ui,
                        NetworkContext {
                            active: None,
                            recordings: None,
                            recording_roots: &[],
                            nat: true,
                            running: false,
                            pending: false,
                            boot_id: None,
                            font_size: 16.0,
                        },
                    );
                });
            },
        );
        worst = worst.max(frame.elapsed());
        frames += 1;
        if view
            .display_index
            .as_ref()
            .is_some_and(|index| index.rows().status() == ParseStatus::Complete)
        {
            done = Some(started.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(16));
    }
    println!(
        "{frames} frames; parse complete after {done:?}; slowest frame {worst:?}; page rows {}",
        view.display_page.len()
    );
}

fn details_frame(
    view: &mut NetworkView,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> Vec<(String, egui::Rect)> {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 900.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.details(ui, 16.0));
        },
    );
    crate::app::tests::texts(&output)
}

#[test]
fn the_details_pane_draws_tshark_lines_and_marks_the_bytes_of_the_clicked_one() {
    use antinomie_monitor_core::packet_filter::{DetailNode, PacketTree};
    let node = |depth, label: &str, name: &str, start, len, end| DetailNode {
        depth,
        label: label.into(),
        name: name.into(),
        start,
        len,
        end,
    };
    let tree = PacketTree {
        nodes: vec![
            node(0, "Frame 1: 40 bytes", "frame", 0, 40, 2),
            node(1, "Frame Length: 40", "frame.len", 0, 0, 2),
            node(0, "Internet Protocol Version 4", "ip", 14, 20, 5),
            node(1, "Source Address: 10.0.2.15", "ip.src", 26, 4, 4),
            node(1, "Beyond the frame: 1", "ip.bad", 900, 4, 5),
        ],
        cut: false,
    };
    let mut view = NetworkView::default();
    view.list.selected = Some(NetworkPacket {
        number: 1,
        offset: 24,
        length: 40,
        captured: 40,
        protocol: "UDP".into(),
        info: "info".into(),
        ..NetworkPacket::default()
    });
    view.list.frame = Some((24, Ok((0..40).collect())));
    view.detail = Some(DetailView {
        number: 1,
        generation: 1,
        state: DetailState::Ready(Box::new(PacketDetail {
            number: 1,
            frame_len: 40,
            tree,
        })),
    });
    let ctx = egui::Context::default();
    theme::install(&ctx);
    for _ in 0..3 {
        details_frame(&mut view, &ctx, Vec::new());
    }
    let shown = details_frame(&mut view, &ctx, Vec::new());
    let find = |shown: &[(String, egui::Rect)], text: &str| {
        shown
            .iter()
            .find(|(shown, _)| shown == text)
            .map(|(_, rect)| *rect)
    };
    // The last protocol is open, the first closed; the lines are TShark's.
    assert!(find(&shown, "Frame 1: 40 bytes").is_some());
    assert!(find(&shown, "Frame Length: 40").is_none());
    let line = find(&shown, "Source Address: 10.0.2.15").expect("open protocol shows its fields");
    for pressed in [true, false] {
        details_frame(
            &mut view,
            &ctx,
            vec![
                egui::Event::PointerMoved(line.center()),
                egui::Event::PointerButton {
                    pos: line.center(),
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    let shown = details_frame(&mut view, &ctx, Vec::new());
    assert!(
        find(&shown, "Source Address: 10.0.2.15: 4 bytes at 0x001a").is_some(),
        "{shown:?}"
    );
    // A range that does not fit the frame marks nothing.
    view.detail_node = Some(4);
    let shown = details_frame(&mut view, &ctx, Vec::new());
    assert!(find(&shown, "40 bytes").is_some(), "{shown:?}");
}

#[test]
fn packet_rows_sort_by_every_header_column_and_keep_ties_in_order() {
    use super::packets::ordered_rows;
    use crate::triage::SortSpec;
    let mut packets = vec![
        packet("TCP", "10.0.2.15:40000", "1.2.3.4:80"),
        packet("DNS", "10.0.2.3:53", "10.0.2.15:5353"),
        packet("ARP", "", ""),
    ];
    for (index, (number, time, length)) in [(1, 30, 60), (2, 10, 120), (3, 20, 60)]
        .into_iter()
        .enumerate()
    {
        packets[index].number = number;
        packets[index].time_us = time;
        packets[index].length = length;
    }
    let rows = [0, 1, 2];
    let by =
        |column, descending| ordered_rows(&rows, &packets, Some(SortSpec { column, descending }));
    assert_eq!(ordered_rows(&rows, &packets, None), [0, 1, 2]);
    assert_eq!(by(0, true), [2, 1, 0]);
    assert_eq!(by(1, false), [1, 2, 0]);
    // Addresses by IP; a packet without one is last when ascending.
    assert_eq!(by(2, false), [1, 0, 2]);
    assert_eq!(by(3, false), [0, 1, 2]);
    assert_eq!(by(4, false), [2, 1, 0]);
    // Equal lengths keep the capture order.
    assert_eq!(by(5, false), [0, 2, 1]);
    assert_eq!(by(6, false), [2, 1, 0]);
    // A filtered subset sorts as itself.
    assert_eq!(
        ordered_rows(
            &[2, 0],
            &packets,
            Some(SortSpec {
                column: 1,
                descending: false
            })
        ),
        [2, 0]
    );
}
