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
                    view.display_index.is_some()
                }
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
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
    assert_eq!(format_bytes(3_620), "3.5 KiB");
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
