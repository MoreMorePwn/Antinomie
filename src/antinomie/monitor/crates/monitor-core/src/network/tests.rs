// SPDX-License-Identifier: MIT
use super::*;

fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x52, 0x55, 0x0a, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
    frame.extend(ethertype.to_be_bytes());
    frame.extend(payload);
    frame
}

fn ipv4_packet(protocol: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![
        0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0, 10, 0, 2, 15, 10, 0, 2, 3,
    ];
    let total = (20 + body.len()) as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet.extend(body);
    packet
}

fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend(sport.to_be_bytes());
    udp.extend(dport.to_be_bytes());
    udp.extend(((8 + data.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(data);
    udp
}

fn dns_query() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        dns.push(label.len() as u8);
        dns.extend(label.as_bytes());
    }
    dns.extend([0, 0, 1, 0, 1]);
    dns
}

fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend(0xa1b2c3d4u32.to_le_bytes());
    file.extend(2u16.to_le_bytes());
    file.extend(4u16.to_le_bytes());
    file.extend([0; 8]);
    file.extend(65535u32.to_le_bytes());
    file.extend(1u32.to_le_bytes());
    for (i, frame) in frames.iter().enumerate() {
        file.extend((1_700_000_000u32 + i as u32).to_le_bytes());
        file.extend(250u32.to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend(frame);
    }
    file
}

/// A TLS record with a ClientHello naming `name` (SNI).
fn client_hello(name: &[u8]) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend(0u16.to_be_bytes());
    sni.extend(((name.len() + 5) as u16).to_be_bytes());
    sni.extend(((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend((name.len() as u16).to_be_bytes());
    sni.extend(name);
    let mut body = vec![3, 3];
    body.extend([0; 32]);
    body.push(0);
    body.extend(2u16.to_be_bytes());
    body.extend([0x13, 0x01]);
    body.extend([1, 0]);
    body.extend((sni.len() as u16).to_be_bytes());
    body.extend(&sni);
    let mut handshake = vec![1];
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(&body);
    let mut record = vec![22, 3, 1];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(&handshake);
    record
}

fn arp_request() -> Vec<u8> {
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend([0x52, 0x54, 0, 0x12, 0x34, 0x56, 10, 0, 2, 15]);
    arp.extend([0, 0, 0, 0, 0, 0, 10, 0, 2, 2]);
    arp
}

/// A TCP header from 40000 to `dport` with `flags` and no options.
fn tcp(dport: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[..2].copy_from_slice(&40000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp.extend(data);
    tcp
}

fn field<'a>(layer: &'a PacketLayer, name: &str) -> &'a PacketField {
    layer
        .fields
        .iter()
        .find(|field| field.name == name)
        .unwrap_or_else(|| panic!("no {name} in {layer:?}"))
}

fn bytes<'a>(frame: &'a [u8], field: &PacketField) -> &'a [u8] {
    &frame[field.start..field.start + field.len]
}

#[test]
fn dissects_layers_with_the_byte_range_of_each_field() {
    // DNS query: Ethernet, IPv4, UDP, DNS.
    let query = ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query())));
    let layers = dissect(&query);
    let names: Vec<_> = layers.iter().map(|layer| layer.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Ethernet II",
            "Internet Protocol Version 4",
            "User Datagram Protocol",
            "Domain Name System"
        ]
    );
    assert_eq!(field(&layers[0], "Source").value, "52:54:00:12:34:56");
    assert_eq!(field(&layers[0], "Type").value, "IPv4 (0x0800)");
    assert_eq!(layers[1].summary, "Src 10.0.2.15, Dst 10.0.2.3");
    let source = field(&layers[1], "Source address");
    assert_eq!((source.start, source.len), (26, 4));
    assert_eq!(bytes(&query, source), [10, 0, 2, 15]);
    assert_eq!(field(&layers[1], "Protocol").value, "UDP (17)");
    assert_eq!(field(&layers[2], "Destination port").value, "53");
    assert_eq!(
        bytes(&query, field(&layers[2], "Destination port")),
        [0, 53]
    );
    assert_eq!(layers[3].summary, "query A example.com");
    let question = field(&layers[3], "Query");
    assert_eq!(question.value, "example.com: type A, class IN");
    assert_eq!(question.start, 14 + 20 + 8 + 12);
    assert_eq!(question.start + question.len, query.len());
    // A response whose answer names the question by a compression pointer.
    let mut answer = dns_query();
    answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    answer[7] = 1;
    answer.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    let response = ethernet(0x0800, &ipv4_packet(17, &udp(53, 5353, &answer)));
    let dns_layer = &dissect(&response)[3];
    assert_eq!(
        field(dns_layer, "Answer").value,
        "example.com: type A, class IN, addr 93.184.216.34"
    );
    assert_eq!(field(dns_layer, "Time to live").value, "60");
    assert_eq!(
        bytes(&response, field(dns_layer, "Data")),
        [93, 184, 216, 34]
    );
    assert_eq!(
        describe(&response).info,
        "response A example.com → 93.184.216.34"
    );
    // TCP flags, then TLS with the server name's bytes.
    let hello = ethernet(
        0x0800,
        &ipv4_packet(6, &tcp(443, 0x18, &client_hello(b"evil.example"))),
    );
    let layers = dissect(&hello);
    assert_eq!(field(&layers[2], "Flags").value, "0x018 [ACK, PSH]");
    assert_eq!(field(&layers[2], "Sequence number").value, "1000");
    assert_eq!(layers[3].name, "Transport Layer Security");
    assert_eq!(layers[3].summary, "Client Hello, SNI evil.example");
    assert_eq!(
        bytes(&hello, field(&layers[3], "Server name")),
        b"evil.example"
    );
    // HTTP request lines and headers.
    let get = ethernet(
        0x0800,
        &ipv4_packet(
            6,
            &tcp(80, 0x18, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ),
    );
    let http = &dissect(&get)[3];
    assert_eq!(http.name, "Hypertext Transfer Protocol");
    assert_eq!(field(http, "Request line").value, "GET / HTTP/1.1");
    assert_eq!(field(http, "Host").value, "example.com");
    assert_eq!(bytes(&get, field(http, "Host")), b"Host: example.com\r\n");
    // ARP and ICMP echo.
    let arp = dissect(&ethernet(0x0806, &arp_request()));
    assert_eq!(arp[1].summary, "Who has 10.0.2.2? Tell 10.0.2.15");
    assert_eq!(field(&arp[1], "Opcode").value, "request (1)");
    let ping = dissect(&ethernet(
        0x0800,
        &ipv4_packet(1, &[8, 0, 0, 0, 0, 7, 0, 1, 0xaa, 0xbb]),
    ));
    assert_eq!(field(&ping[2], "Type").value, "8 (Echo request)");
    assert_eq!(field(&ping[2], "Sequence number").value, "1");
    assert_eq!(ping[3].name, "Data");
    assert_eq!(ping[3].len, 2);
}

#[test]
fn dissecting_truncated_frames_keeps_every_range_inside_the_frame() {
    let mut v6 = vec![0x60, 0, 0, 0, 0, 16, 0, 64];
    v6.extend([0u8; 32]);
    v6.extend([17, 0, 1, 4, 0, 0, 0, 0]);
    v6.extend(udp(1234, 53, &[]));
    let frames = [
        ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
        ethernet(
            0x0800,
            &ipv4_packet(6, &tcp(443, 0x18, &client_hello(b"evil.example"))),
        ),
        ethernet(0x0806, &arp_request()),
        ethernet(0x86dd, &v6),
    ];
    for frame in &frames {
        for end in 0..=frame.len() {
            let part = &frame[..end];
            for layer in dissect(part) {
                assert!(layer.start + layer.len <= end, "{layer:?}");
                for field in &layer.fields {
                    assert!(field.start + field.len <= end, "{field:?}");
                }
            }
        }
    }
    // IPv6 hop-by-hop options are listed, then the UDP header.
    let layers = dissect(&frames[3]);
    assert_eq!(
        field(&layers[1], "Extension header").value,
        "Hop-by-hop options (0), 8 bytes"
    );
    assert_eq!(layers[2].name, "User Datagram Protocol");
}

#[test]
fn reads_pages_and_describes_dns_tcp_arp_and_tls() {
    let mut syn = vec![0u8; 20];
    syn[..2].copy_from_slice(&40000u16.to_be_bytes());
    syn[2..4].copy_from_slice(&443u16.to_be_bytes());
    syn[12] = 5 << 4;
    syn[13] = 0x02;
    let mut hello = syn.clone();
    hello[13] = 0x18;
    hello.extend(client_hello(b"evil.example"));
    let frames = vec![
        ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
        ethernet(0x0800, &ipv4_packet(6, &syn)),
        ethernet(0x0800, &ipv4_packet(6, &hello)),
        ethernet(0x0806, &arp_request()),
    ];
    let path = std::env::temp_dir().join(format!("ant-pcap-{}", crate::storage::unique_id()));
    std::fs::write(&path, pcap(&frames)).unwrap();
    let first = read_page(&path, 0, 0, 2).unwrap();
    assert_eq!(first.packets.len(), 2);
    assert_eq!(first.packets[0].protocol, "DNS");
    assert_eq!(first.packets[0].info, "query A example.com");
    assert_eq!(first.packets[0].source, "10.0.2.15:5353");
    assert_eq!(first.packets[0].time_us, 1_700_000_000_000_250);
    assert_eq!(first.packets[1].info, "40000 → 443 [SYN] len 0");
    // Addresses and ports are structured, not only text.
    let dns = &first.packets[0];
    assert_eq!(dns.src_ip, Some("10.0.2.15".parse().unwrap()));
    assert_eq!(dns.dst_ip, Some("10.0.2.3".parse().unwrap()));
    assert_eq!((dns.src_port, dns.dst_port), (Some(5353), Some(53)));
    assert_eq!(dns.tcp_flags, None);
    let syn = &first.packets[1];
    assert_eq!((syn.src_port, syn.dst_port), (Some(40000), Some(443)));
    assert_eq!(syn.tcp_flags, Some(TCP_SYN));
    let rest = read_page(&path, first.next_offset, first.next_number, 10).unwrap();
    assert_eq!(rest.packets.len(), 2);
    assert_eq!(rest.packets[0].number, 3);
    assert_eq!(rest.packets[0].protocol, "TLS");
    assert_eq!(rest.packets[0].info, "Client Hello, SNI evil.example");
    assert_eq!(rest.packets[1].info, "Who has 10.0.2.2? Tell 10.0.2.15");
    assert_eq!(rest.packets[1].src_ip, None);
    assert_eq!(rest.packets[1].src_port, None);
    assert_eq!(frame(&path, rest.packets[1].offset).unwrap(), frames[3]);
    // A partly written record ends the page without an error.
    let mut partial = pcap(&frames);
    partial.truncate(partial.len() - 3);
    std::fs::write(&path, partial).unwrap();
    assert_eq!(read_page(&path, 0, 0, 10).unwrap().packets.len(), 3);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn ipv6_and_icmp_carry_addresses_without_ports() {
    let mut ip = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
    ip.extend(
        [0xfe, 0x80]
            .iter()
            .chain([0u8; 13].iter())
            .chain([1u8].iter()),
    );
    ip.extend(
        [0xff, 0x02]
            .iter()
            .chain([0u8; 13].iter())
            .chain([1u8].iter()),
    );
    ip.extend([128, 0, 0, 0, 0, 0, 0, 0]);
    let packet = describe(&ethernet(0x86dd, &ip));
    assert_eq!(packet.protocol, "ICMPv6");
    assert_eq!(packet.info, "Echo request");
    assert_eq!(packet.src_ip, Some("fe80::1".parse().unwrap()));
    assert_eq!(packet.dst_ip, Some("ff02::1".parse().unwrap()));
    assert_eq!((packet.src_port, packet.dst_port), (None, None));
    // A UDP endpoint over IPv6 brackets the address.
    let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
    ip.extend(
        [0xfe, 0x80]
            .iter()
            .chain([0u8; 13].iter())
            .chain([1u8].iter()),
    );
    ip.extend(
        [0xfe, 0x80]
            .iter()
            .chain([0u8; 13].iter())
            .chain([2u8].iter()),
    );
    ip.extend(udp(546, 547, &[]));
    let packet = describe(&ethernet(0x86dd, &ip));
    assert_eq!(packet.source, "[fe80::1]:546");
    assert_eq!(packet.dst_port, Some(547));
}

#[test]
fn captures_are_listed_newest_first_with_older_whole_boot_files() {
    let _disk = crate::storage::slow_disk::SlowDisk::install();
    let root = std::env::temp_dir().join(format!("ant-netcap-{}", crate::storage::unique_id()));
    let frames = vec![ethernet(
        0x0800,
        &ipv4_packet(17, &udp(5353, 53, &dns_query())),
    )];
    // An older boot with one whole-boot capture.
    let old_boot = root.join("boots").join("oldboot");
    std::fs::create_dir_all(&old_boot).unwrap();
    std::fs::write(old_boot.join(PCAP_FILE), pcap(&frames)).unwrap();
    // A newer boot with a finished capture and a running one.
    let boot = root.join("boots").join("newboot");
    let first = NetworkCapture::new(&boot, "newboot", "aaaa", 1_800_000_000_000);
    let second = NetworkCapture::new(&boot, "newboot", "bbbb", 1_800_000_060_000);
    std::fs::create_dir_all(first.file.parent().unwrap()).unwrap();
    std::fs::write(&first.file, pcap(&[frames[0].clone(), frames[0].clone()])).unwrap();
    std::fs::write(&second.file, pcap(&[])).unwrap();
    let (packets, bytes) = count_packets(&first.file).unwrap();
    assert_eq!(packets, 2);
    assert_eq!(bytes, std::fs::metadata(&first.file).unwrap().len());
    let finished = NetworkCapture {
        stopped_ms: Some(1_800_000_030_000),
        packets: Some(packets),
        bytes: Some(bytes),
        ..first.clone()
    };
    save_summary(&finished).unwrap();
    save_summary(&second).unwrap();
    crate::storage::flush_json().unwrap();
    // The summary names the pcap relative to its folder.
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(first.summary_path()).unwrap()).unwrap();
    assert_eq!(saved["file"], "aaaa.pcap");
    let listed = list_captures(&root);
    let ids: Vec<_> = listed.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["bbbb", "aaaa", "oldboot"]);
    assert_eq!(listed[0].stopped_ms, None);
    assert_eq!(listed[1], finished);
    assert!(listed[2].whole_boot);
    assert_eq!(listed[2].file, old_boot.join(PCAP_FILE));
    assert_eq!(listed[2].started_ms, 1_700_000_000_000);
    // A partly written last record is not counted.
    let mut partial = pcap(&[frames[0].clone(), frames[0].clone()]);
    partial.truncate(partial.len() - 1);
    std::fs::write(&first.file, partial).unwrap();
    assert_eq!(count_packets(&first.file).unwrap().0, 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn qmp_commands_add_and_remove_a_filter_dump_on_net0() {
    let capture = NetworkCapture::new(Path::new("/rec/boots/b1"), "b1", "c0ffee", 1);
    assert_eq!(
        filter_dump_add(&capture).unwrap(),
        serde_json::json!({"execute": "object-add", "arguments": {
            "qom-type": "filter-dump", "id": "netdump-c0ffee", "netdev": "net0",
            "file": "/rec/boots/b1/network/c0ffee.pcap", "maxlen": 65535}})
    );
    assert_eq!(
        filter_dump_del(&capture),
        serde_json::json!({"execute": "object-del", "arguments": {"id": "netdump-c0ffee"}})
    );
    assert_eq!(
        capture.summary_path(),
        Path::new("/rec/boots/b1/network/c0ffee.json")
    );
}

#[test]
fn malformed_ipv4_and_ipv6_fragments_do_not_invent_ports() {
    let mut ip = ipv4_packet(17, &udp(1234, 53, &dns_query()));
    ip[0] = 0x40;
    let packet = describe(&ethernet(0x0800, &ip));
    assert_eq!(packet.protocol, "IPv4");
    assert_eq!(packet.dst_port, None);
    let mut ip = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
    ip.extend([0u8; 32]);
    ip.extend([17, 0, 0, 8, 0, 0, 0, 1]);
    ip.extend(udp(1234, 53, &[]));
    let packet = describe(&ethernet(0x86dd, &ip));
    assert_eq!(packet.protocol, "IPv6");
    assert_eq!(packet.info, "fragment");
    assert_eq!((packet.src_port, packet.dst_port), (None, None));
}

#[test]
fn history_rejects_escaped_paths_and_fifo_members_without_blocking() {
    let root = std::env::temp_dir().join(format!("ant-net-reject-{}", crate::storage::unique_id()));
    let dir = root.join("boots/b1/network");
    std::fs::create_dir_all(&dir).unwrap();
    let external = root.join("outside.pcap");
    std::fs::write(&external, pcap(&[])).unwrap();
    let summary = |name: &str, file: PathBuf| {
        let capture = NetworkCapture {
            file,
            id: name.into(),
            ..NetworkCapture::default()
        };
        std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_vec(&capture).unwrap(),
        )
        .unwrap();
    };
    summary("absolute", external.clone());
    summary("traversal", PathBuf::from("../../../outside.pcap"));
    std::os::unix::fs::symlink(&external, dir.join("linked.pcap")).unwrap();
    summary("linked", PathBuf::from("linked.pcap"));
    let fifo = dir.join("fifo.pcap");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    summary("fifo", PathBuf::from("fifo.pcap"));
    assert!(list_captures(&root).is_empty());
    assert!(read_page(&fifo, 0, 0, 1).is_err());
    assert!(frame(&fifo, 24).is_err());
    assert!(count_packets(&fifo).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

fn tcp_seq(seq: u32, dport: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut tcp = tcp(dport, flags, data);
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp
}

fn reversed(mut ip: Vec<u8>) -> Vec<u8> {
    ip[12..16].copy_from_slice(&[10, 0, 2, 3]);
    ip[16..20].copy_from_slice(&[10, 0, 2, 15]);
    ip
}

#[test]
fn reconstructs_http1_and_dns_and_drops_a_retransmission() {
    let request = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let get = ethernet(0x0800, &ipv4_packet(6, &tcp_seq(1000, 80, 0x18, request)));
    let again = ethernet(0x0800, &ipv4_packet(6, &tcp_seq(1000, 80, 0x18, request)));
    let mut reply_tcp = tcp_seq(50, 40000, 0x18, response);
    reply_tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
    let reply = ethernet(0x0800, &reversed(ipv4_packet(6, &reply_tcp)));
    let query = ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query())));
    let mut answer = dns_query();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[6] = 0;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 2, 9]);
    let response_dns = ethernet(0x0800, &reversed(ipv4_packet(17, &udp(53, 5353, &answer))));
    let hello = ethernet(
        0x0800,
        &ipv4_packet(6, &tcp_seq(1, 443, 0x18, &client_hello(b"secret.example"))),
    );
    let frames = [
        CapturedFrame {
            number: 1,
            time_us: 1,
            bytes: &get,
        },
        CapturedFrame {
            number: 2,
            time_us: 2,
            bytes: &again,
        },
        CapturedFrame {
            number: 3,
            time_us: 3,
            bytes: &reply,
        },
        CapturedFrame {
            number: 4,
            time_us: 4,
            bytes: &query,
        },
        CapturedFrame {
            number: 5,
            time_us: 5,
            bytes: &response_dns,
        },
        CapturedFrame {
            number: 6,
            time_us: 6,
            bytes: &hello,
        },
    ];
    let built = reconstruct(&frames);
    assert_eq!(built.retransmissions_dropped, 1);
    assert_eq!(built.http.len(), 1, "{:?}", built.http);
    assert_eq!(built.http[0].method, "GET");
    assert_eq!(built.http[0].uri, "/api");
    assert_eq!(built.http[0].host, "example.com");
    assert_eq!(built.http[0].version, "HTTP/1.1");
    assert_eq!(built.http[0].status, Some(200));
    assert!(built.http[0].complete);
    assert_eq!(built.dns.len(), 1, "{:?}", built.dns);
    assert_eq!(built.dns[0].name, "example.com");
    assert_eq!(built.dns[0].id, 0x1234);
    assert_eq!(built.dns[0].protocol, "UDP");
    assert_eq!(built.dns[0].answers, vec!["10.0.2.9".to_string()]);
    assert_eq!(built.https_segments, 1);
    assert!(built.notes.iter().any(|note| note.contains("HTTPS")));
}

/// Hand-made well-formed frames of every dissected kind.
fn corpus() -> Vec<Vec<u8>> {
    vec![
        ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
        ethernet(
            0x0800,
            &ipv4_packet(6, &tcp(443, 0x18, &client_hello(b"evil.example"))),
        ),
        ethernet(
            0x0800,
            &ipv4_packet(
                6,
                &tcp(80, 0x18, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ),
        ),
        ethernet(
            0x0800,
            &ipv4_packet(17, &udp(68, 67, &[1, 1, 6, 0, 0, 0, 0, 1, 0, 0, 0, 0])),
        ),
        ethernet(0x0806, &arp_request()),
    ]
}

#[test]
fn malformed_frames_never_panic_the_dissectors_or_the_reconstruction() {
    for frame in corpus() {
        // Every truncation, and the frame with each byte forced to the
        // values that break lengths, counts and offsets.
        for len in 0..=frame.len() {
            let _ = dissect(&frame[..len]);
            let _ = describe(&frame[..len]);
        }
        for at in 0..frame.len() {
            for value in [0x00, 0x7f, 0xff] {
                let mut mutated = frame.clone();
                mutated[at] = value;
                let layers = dissect(&mutated);
                // Field ranges stay inside the frame whatever the content.
                for field in layers.iter().flat_map(|layer| &layer.fields) {
                    assert!(field.start + field.len <= mutated.len(), "{field:?}");
                }
                let _ = describe(&mutated);
            }
        }
    }
    let frames = corpus();
    let mut damaged: Vec<Vec<u8>> = frames
        .iter()
        .map(|frame| frame[..frame.len() * 2 / 3].to_vec())
        .collect();
    damaged.extend(frames);
    let captured: Vec<_> = damaged
        .iter()
        .enumerate()
        .map(|(i, bytes)| CapturedFrame {
            number: i as u64 + 1,
            time_us: i as u64,
            bytes,
        })
        .collect();
    let _ = reconstruct(&captured);
}

mod app_layers;
mod packet_summaries;
mod reassembly;
