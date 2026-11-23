// SPDX-License-Identifier: GPL-3.0-only
//! The Source column over a small capture: a TCP connect, a UDP DNS lookup, an
//! accepted connection, background NTP and a flow no call names, read by
//! TShark from a pcap the test writes; and a scan storm's frames counted on
//! one Endpoints row (ANT-T0612).
use super::net_attr::*;
use super::*;
use std::net::IpAddr;

const BASE_S: u32 = 1_700_000_000;

/// One Ethernet/IPv4 frame with a TCP SYN (`tcp`) or a UDP datagram.
fn frame(tcp: bool, from: ([u8; 4], u16), to: ([u8; 4], u16)) -> Vec<u8> {
    let mut transport = Vec::new();
    transport.extend(from.1.to_be_bytes());
    transport.extend(to.1.to_be_bytes());
    if tcp {
        transport.extend(1u32.to_be_bytes());
        transport.extend(0u32.to_be_bytes());
        transport.extend([0x50, 0x02]);
        transport.extend(0xffffu16.to_be_bytes());
        transport.extend(0u32.to_be_bytes());
    } else {
        transport.extend(12u16.to_be_bytes());
        transport.extend(0u16.to_be_bytes());
        transport.extend(b"abcd");
    }
    let total = (20 + transport.len()) as u16;
    let mut ip = vec![
        0x45,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        64,
        if tcp { 6 } else { 17 },
        0,
        0,
    ];
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend(from.0);
    ip.extend(to.0);
    ip.extend(transport);
    let mut frame = vec![0; 12];
    frame.extend(0x0800u16.to_be_bytes());
    frame.extend(ip);
    frame
}

fn pcap(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    for (offset, bytes) in frames {
        let len = bytes.len() as u32;
        out.extend((BASE_S + offset).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(len.to_le_bytes());
        out.extend(len.to_le_bytes());
        out.extend(bytes);
    }
    out
}

fn call(
    pid: u32,
    name: &str,
    call: &'static str,
    role: Role,
    peer: (&str, u16),
    udp: bool,
    second: u32,
) -> FlowCall {
    let us = (u64::from(BASE_S) + u64::from(second)) * 1_000_000;
    FlowCall {
        ip: peer.0.parse::<IpAddr>().unwrap(),
        port: peer.1,
        udp,
        role,
        call,
        caller: Caller {
            pid,
            tid: pid + 1,
            cookie: u64::from(pid) * 10,
            name: name.into(),
        },
        first_us: Some(us),
        last_us: Some(us),
        stream: 1,
        call_id: u64::from(second),
    }
}

#[test]
fn endpoints_name_the_process_the_base_image_or_nothing() {
    if !Path::new("/usr/bin/tshark").is_file() {
        return;
    }
    let files = PacketSpool::new().unwrap();
    let capture = files.directory.join("flows.pcap");
    let guest = [10, 0, 2, 15];
    std::fs::write(
        &capture,
        pcap(&[
            // curl connects to a documentation address.
            (0, frame(true, (guest, 40001), ([192, 0, 2, 9], 80))),
            // nslookup asks the gateway's resolver; it answers.
            (1, frame(false, (guest, 41000), ([10, 0, 2, 3], 53))),
            (1, frame(false, ([10, 0, 2, 3], 53), (guest, 41000))),
            // nc accepts a client of the host on its port.
            (2, frame(true, ([10, 0, 2, 2], 51000), (guest, 8080))),
            // Clock sync nobody in the run asked for.
            (3, frame(false, (guest, 123), ([203, 0, 113, 5], 123))),
            // A SYN a raw socket sent: no call names it.
            (4, frame(true, (guest, 40009), ([203, 0, 113, 77], 22))),
        ]),
    )
    .unwrap();
    let artifacts = serde_json::json!({"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[capture],"network_state":"complete","memory_dump":null,"memory_state":"disabled","core_dump":null,"core_state":"disabled","issues":[]});
    std::fs::write(
        files.directory.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let attribution = NetAttribution::new(vec![
        call(
            40,
            "curl",
            "connect",
            Role::Remote,
            ("192.0.2.9", 80),
            false,
            0,
        ),
        call(
            52,
            "nslookup",
            "sendto",
            Role::Remote,
            ("10.0.2.3", 53),
            true,
            1,
        ),
        call(70, "nc", "bind", Role::Bound, ("0.0.0.0", 8080), false, 0),
        call(
            70,
            "nc",
            "accept",
            Role::Accepted,
            ("10.0.2.2", 51000),
            false,
            2,
        ),
    ]);
    let request = ScanRequest {
        owned_pcap: true,
        identity: Some(("v".into(), "b".into(), "r".into())),
        attribution: Some(Arc::new(attribution)),
        ..Default::default()
    };
    let index = network_index::collect(
        &files.directory,
        &capture,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
        &mut |_, _, _, _, _| Ok(()),
    )
    .unwrap();
    let source_of = |endpoint: &str| -> (String, String) {
        let row = index
            .new_tabs
            .endpoints
            .iter()
            .find(|row| row[0].text == endpoint)
            .unwrap_or_else(|| panic!("no row for {endpoint}"));
        (
            row[1].text.clone(),
            ioc_scan::text_of(&row[0].values, "network.source_kind").to_owned(),
        )
    };
    assert_eq!(source_of("192.0.2.9:80").0, "curl (40 \u{b7} 41)");
    assert_eq!(source_of("10.0.2.3:53").0, "nslookup (52 \u{b7} 53)");
    // The capture counts the guest's own side for a client's connection.
    assert_eq!(source_of("10.0.2.15:8080").0, "nc (70 \u{b7} 71)");
    assert_eq!(
        source_of("203.0.113.5:123"),
        ("Base image background: NTP".into(), "background".into())
    );
    assert_eq!(
        source_of("203.0.113.77:22"),
        ("Unattributed".into(), "unattributed".into())
    );
    // The packet list reads the same attribution.
    let attribution = index.attribution.expect("kept for the Packets list");
    let reply = attribution.source_of_packet(
        true,
        [
            (IpAddr::from([10, 0, 2, 3]), 53),
            (IpAddr::from(guest), 41000),
        ],
        (u64::from(BASE_S) + 1) * 1_000_000 + 20_000,
    );
    assert_eq!(reply.label(), "nslookup (52 \u{b7} 53)");
    // The row carries the values the filter keys read.
    let row = index
        .new_tabs
        .endpoints
        .iter()
        .find(|row| row[0].text == "192.0.2.9:80")
        .unwrap();
    assert_eq!(
        files::number(&row[0].values, "network.source_pid"),
        Some(40)
    );
    assert_eq!(
        ioc_scan::text_of(&row[0].values, "network.source_process"),
        "curl"
    );
}

/// A scanner's SYNs to 300 addresses (and the refusals of a few) are one
/// Endpoints row with all their frames; the capture's IOC list holds none of
/// the scanned addresses, and the other process's endpoint keeps its row.
#[test]
fn a_scan_storm_in_the_capture_is_one_endpoints_row() {
    if !Path::new("/usr/bin/tshark").is_file() {
        return;
    }
    let files = PacketSpool::new().unwrap();
    let capture = files.directory.join("scan.pcap");
    let guest = [10, 0, 2, 15];
    let target = |at: u32| -> ([u8; 4], u16) {
        let ip = std::net::Ipv4Addr::from(0x0b00_0000 + at).octets();
        (ip, if at.is_multiple_of(4) { 2323 } else { 23 })
    };
    let mut log = rules::ioc::Log::default();
    let mut frames = vec![(0, frame(true, (guest, 40001), ([192, 0, 2, 9], 80)))];
    for at in 0..300u32 {
        let (ip, port) = target(at);
        let who = rules::ioc::Who {
            cookie: 70,
            pid: 7,
            tid: 8,
            time_ns: 1_000 + u64::from(at),
            stream: 1,
            call_id: u64::from(at),
            ..Default::default()
        };
        rules::ioc::push(
            &mut log,
            rules::ioc::Connection {
                ip: IpAddr::from(ip),
                port,
                udp: false,
                ok: false,
                who,
                name: "connect",
            },
        );
        frames.push((1, frame(true, (guest, 50000 + at as u16), (ip, port))));
        if at.is_multiple_of(50) {
            // A refusal from the scanned host.
            frames.push((2, frame(true, (ip, port), (guest, 50000 + at as u16))));
        }
    }
    std::fs::write(&capture, pcap(&frames)).unwrap();
    let artifacts = serde_json::json!({"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[capture],"network_state":"complete","memory_dump":null,"memory_state":"disabled","core_dump":null,"core_state":"disabled","issues":[]});
    std::fs::write(
        files.directory.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let sweeps = crate::sweeps::Sweeps::of(&log);
    assert_eq!(sweeps.scans.len(), 1);
    // The scan's row is attributed by its lowest endpoint's call.
    let (low_ip, low_port, _) = *sweeps.scans[0].endpoints.iter().min().unwrap();
    let mut scanner = call(
        7,
        "scanner",
        "connect",
        Role::Remote,
        ("0.0.0.0", 0),
        false,
        1,
    );
    scanner.ip = low_ip;
    scanner.port = low_port;
    scanner.caller.cookie = 70;
    let attribution = NetAttribution::new(vec![
        call(
            40,
            "curl",
            "connect",
            Role::Remote,
            ("192.0.2.9", 80),
            false,
            0,
        ),
        scanner,
    ]);
    let request = ScanRequest {
        owned_pcap: true,
        identity: Some(("v".into(), "b".into(), "r".into())),
        attribution: Some(Arc::new(attribution)),
        sweeps: Some(Arc::new(sweeps)),
        ..Default::default()
    };
    let index = network_index::collect(
        &files.directory,
        &capture,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
        &mut |_, _, _, _, _| Ok(()),
    )
    .unwrap();
    let rows = &index.new_tabs.endpoints;
    let texts: Vec<&str> = rows.iter().map(|row| row[0].text.as_str()).collect();
    assert_eq!(rows.len(), 2, "{texts:?}");
    let scan = rows
        .iter()
        .find(|row| row[0].text == "scanned 300 addresses on ports 23, 2323")
        .unwrap_or_else(|| panic!("no scan row in {texts:?}"));
    // 300 SYNs and 6 refusals, every frame of the scan on its row.
    assert_eq!(scan[3].text, "306");
    assert_eq!(scan[1].text, "scanner (7 \u{b7} 8)");
    assert_eq!(files::number(&scan[0].values, "network.port"), Some(23));
    assert_eq!(files::number(&scan[0].values, "network.frames"), Some(306));
    let curl = rows
        .iter()
        .find(|row| row[0].text == "192.0.2.9:80")
        .expect("curl keeps its row");
    assert_eq!(curl[3].text, "1");
    // The capture lists none of the scanned addresses as indicators.
    let indicators = index.ioc.finish();
    let keys: Vec<&str> = indicators
        .iter()
        .map(|indicator| indicator.key.as_str())
        .collect();
    assert!(keys.contains(&"192.0.2.9:80"), "{keys:?}");
    assert!(!keys.iter().any(|key| key.starts_with("11.0.")), "{keys:?}");
}
