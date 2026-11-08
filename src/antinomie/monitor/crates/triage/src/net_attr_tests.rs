// SPDX-License-Identifier: GPL-3.0-only
//! The Source column over a small capture: a TCP connect, a UDP DNS lookup, an
//! accepted connection, background NTP and a flow no call names, read by
//! TShark from a pcap the test writes.
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
