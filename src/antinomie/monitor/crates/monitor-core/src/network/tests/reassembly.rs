// SPDX-License-Identifier: MIT
//! Direct tests of the HTTP and DNS reassembly, on hand-made frames.
use super::*;

const CLIENT: [u8; 4] = [10, 0, 2, 15];
const SERVER: [u8; 4] = [93, 184, 216, 34];

/// An Ethernet/IPv4/TCP frame with the given endpoints, sequence number and payload.
fn tcp_frame(from: ([u8; 4], u16), to: ([u8; 4], u16), seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[..2].copy_from_slice(&from.1.to_be_bytes());
    segment[2..4].copy_from_slice(&to.1.to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = 0x18;
    segment.extend(payload);
    ip_frame(6, from.0, to.0, &segment)
}

fn udp_frame(from: ([u8; 4], u16), to: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    ip_frame(17, from.0, to.0, &udp(from.1, to.1, payload))
}

fn ip_frame(protocol: u8, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut packet = ipv4_packet(protocol, body);
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    ethernet(0x0800, &packet)
}

fn run(frames: &[Vec<u8>]) -> Reconstruction {
    let captured: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(index, bytes)| CapturedFrame {
            number: index as u64 + 1,
            time_us: 1_000 * index as u64,
            bytes,
        })
        .collect();
    reconstruct(&captured)
}

const REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

#[test]
fn a_request_and_its_response_are_paired_with_their_frames() {
    let out = run(&[
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1000, REQUEST),
        tcp_frame((SERVER, 80), (CLIENT, 40000), 5000, RESPONSE),
    ]);
    assert_eq!(out.http.len(), 1);
    let http = &out.http[0];
    assert_eq!(
        (http.method.as_str(), http.uri.as_str(), http.host.as_str()),
        ("GET", "/index.html", "example.test")
    );
    assert_eq!(http.version, "HTTP/1.1");
    assert_eq!(http.status, Some(404));
    assert_eq!(
        (&http.request_frames[..], &http.response_frames[..]),
        (&[1][..], &[2][..])
    );
    assert!(http.complete);
}

#[test]
fn segments_out_of_order_are_put_back_and_a_retransmission_is_counted_once() {
    let (first, second) = REQUEST.split_at(20);
    let out = run(&[
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1000 + 20, second),
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1000, first),
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1000, first),
    ]);
    assert_eq!(out.retransmissions_dropped, 1);
    assert_eq!(out.http.len(), 1);
    assert_eq!(out.http[0].host, "example.test");
    assert!(out.http[0].complete);
    assert_eq!(out.http[0].status, None, "no response was captured");
}

#[test]
fn a_missing_segment_leaves_the_request_incomplete_instead_of_inventing_data() {
    let (first, rest) = REQUEST.split_at(28);
    let out = run(&[
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1000, first),
        // Ten bytes after the first segment never arrived.
        tcp_frame((CLIENT, 40000), (SERVER, 80), 1038, &rest[10..]),
    ]);
    assert_eq!(out.http.len(), 1);
    assert!(!out.http[0].complete);
    assert_eq!(out.http[0].host, "", "the Host header was not captured");
}

#[test]
fn a_request_cut_inside_its_headers_is_incomplete() {
    let out = run(&[tcp_frame(
        (CLIENT, 40000),
        (SERVER, 80),
        1000,
        b"POST /up HTTP/1.1\r\nHost: a.test\r\nContent-",
    )]);
    assert_eq!(out.http.len(), 1);
    assert_eq!(out.http[0].host, "a.test");
    assert!(!out.http[0].complete);
}

#[test]
fn tls_records_and_an_http2_preface_are_counted_not_decoded() {
    let out = run(&[
        tcp_frame(
            (CLIENT, 40000),
            (SERVER, 443),
            1000,
            &client_hello(b"example.test"),
        ),
        tcp_frame(
            (CLIENT, 40001),
            (SERVER, 8080),
            7,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        ),
    ]);
    assert_eq!((out.https_segments, out.http2_prefaces), (1, 1));
    assert!(out.http.is_empty());
}

#[test]
fn text_that_is_not_http_gives_no_exchange() {
    let out = run(&[
        tcp_frame(
            (CLIENT, 40000),
            (SERVER, 80),
            1000,
            b"FOO / HTTP/1.1\r\nHost: x\r\n\r\n",
        ),
        tcp_frame((CLIENT, 40001), (SERVER, 80), 1000, b"GET / SPDY/3\r\n\r\n"),
        tcp_frame((CLIENT, 40002), (SERVER, 80), 1000, &[0xff, 0xfe, 0x00]),
    ]);
    assert!(out.http.is_empty());
}

/// A DNS message for `example.com` type A, as query or as response with `answers`.
fn dns_message(id: u16, response: bool, rcode: u16, answers: &[[u8; 4]]) -> Vec<u8> {
    let flags: u16 = if response { 0x8180 | rcode } else { 0x0100 };
    let mut message = id.to_be_bytes().to_vec();
    message.extend(flags.to_be_bytes());
    message.extend([0, 1]);
    message.extend((answers.len() as u16).to_be_bytes());
    message.extend([0; 4]);
    for label in ["example", "com"] {
        message.push(label.len() as u8);
        message.extend(label.as_bytes());
    }
    message.extend([0, 0, 1, 0, 1]);
    for answer in answers {
        message.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        message.extend(answer);
    }
    message
}

#[test]
fn a_dns_response_is_paired_with_its_query_and_carries_the_answers() {
    let out = run(&[
        udp_frame(
            (CLIENT, 5353),
            ([10, 0, 2, 3], 53),
            &dns_message(7, false, 0, &[]),
        ),
        udp_frame(
            ([10, 0, 2, 3], 53),
            (CLIENT, 5353),
            &dns_message(7, true, 0, &[[93, 184, 216, 34]]),
        ),
    ]);
    assert_eq!(out.dns.len(), 1);
    let dns = &out.dns[0];
    assert_eq!(
        (dns.name.as_str(), dns.qtype.as_str(), dns.protocol),
        ("example.com", "A", "UDP")
    );
    assert_eq!(dns.answers, ["93.184.216.34"]);
    assert_eq!(dns.rcode, Some(0));
    assert_eq!(
        (&dns.query_frames[..], &dns.response_frames[..]),
        (&[1][..], &[2][..])
    );
    assert!(!dns.retry);
}

#[test]
fn a_repeated_query_is_a_retry_and_a_response_with_another_id_is_not_paired() {
    let out = run(&[
        udp_frame(
            (CLIENT, 5353),
            ([10, 0, 2, 3], 53),
            &dns_message(7, false, 0, &[]),
        ),
        udp_frame(
            (CLIENT, 5353),
            ([10, 0, 2, 3], 53),
            &dns_message(7, false, 0, &[]),
        ),
        udp_frame(
            ([10, 0, 2, 3], 53),
            (CLIENT, 5353),
            &dns_message(8, true, 3, &[]),
        ),
    ]);
    assert_eq!(out.dns.len(), 2);
    assert!(!out.dns[0].retry && out.dns[1].retry);
    assert!(out.dns.iter().all(|dns| dns.response_frames.is_empty()));
}

#[test]
fn dns_over_tcp_reads_each_length_prefixed_message_and_stops_at_a_cut_one() {
    let query = dns_message(9, false, 0, &[]);
    let mut stream = (query.len() as u16).to_be_bytes().to_vec();
    stream.extend(&query);
    // A second message announced longer than the segment carries.
    stream.extend(200u16.to_be_bytes());
    stream.extend(&query[..5]);
    let out = run(&[tcp_frame((CLIENT, 40000), ([10, 0, 2, 3], 53), 1, &stream)]);
    assert_eq!(out.dns.len(), 1);
    assert_eq!(out.dns[0].protocol, "TCP");
}

#[test]
fn damaged_dns_is_skipped_without_a_panic() {
    let good = dns_message(1, true, 0, &[[1, 2, 3, 4]]);
    let mut pointer_loop = dns_message(2, false, 0, &[]);
    pointer_loop[12] = 0xc0;
    pointer_loop[13] = 12;
    let frames: Vec<_> = [
        good[..11].to_vec(),
        good[..good.len() - 2].to_vec(),
        pointer_loop,
        vec![0; 12],
    ]
    .iter()
    .map(|message| udp_frame((CLIENT, 5353), ([10, 0, 2, 3], 53), message))
    .collect();
    let out = run(&frames);
    assert!(out.dns.is_empty());
}

#[test]
fn frames_that_are_not_ip_tcp_or_udp_are_ignored() {
    let fragment = {
        let mut packet = ipv4_packet(6, &[0; 30]);
        packet[6] = 0;
        packet[7] = 8; // a later fragment
        ethernet(0x0800, &packet)
    };
    let out = run(&[
        arp_request_frame(),
        fragment,
        ethernet(0x0800, &[0x45]),
        vec![0; 5],
    ]);
    assert!(out.http.is_empty() && out.dns.is_empty());
    assert_eq!(
        out.notes.len(),
        2,
        "the capability notes are always present"
    );
}

fn arp_request_frame() -> Vec<u8> {
    ethernet(0x0806, &arp_request())
}
