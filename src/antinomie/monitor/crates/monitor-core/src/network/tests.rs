// SPDX-License-Identifier: GPL-3.0-only
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

#[test]
fn raw_pages_carry_only_what_the_record_header_says() {
    let frames = vec![
        ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
        ethernet(0x0806, &[0; 28]),
        ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
    ];
    let path = std::env::temp_dir().join(format!("ant-pcap-{}", crate::storage::unique_id()));
    std::fs::write(&path, pcap(&frames)).unwrap();
    let first = read_page(&path, 0, 0, 2).unwrap();
    assert_eq!(first.packets.len(), 2);
    let packet = &first.packets[0];
    assert_eq!((packet.number, packet.offset), (1, 24));
    assert_eq!(packet.time_us, 1_700_000_000_000_250);
    assert_eq!(packet.length as usize, frames[0].len());
    // The list decodes nothing: protocol, endpoints and ports are TShark's.
    assert_eq!(packet.protocol, "");
    assert_eq!((packet.src_ip, packet.src_port), (None, None));
    assert_eq!(packet.info, format!("Raw frame, {} bytes", frames[0].len()));
    let rest = read_page(&path, first.next_offset, first.next_number, 10).unwrap();
    assert_eq!(rest.packets.len(), 1);
    assert_eq!(rest.packets[0].number, 3);
    assert_eq!(frame(&path, rest.packets[0].offset).unwrap(), frames[2]);
    // A partly written record ends the page without an error.
    let mut partial = pcap(&frames);
    partial.truncate(partial.len() - 3);
    std::fs::write(&path, partial).unwrap();
    assert_eq!(read_page(&path, 0, 0, 10).unwrap().packets.len(), 2);
    std::fs::remove_file(path).unwrap();
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
