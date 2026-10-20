// SPDX-License-Identifier: MIT
//! Direct tests of the one-line summaries the packet list shows.
use super::*;

#[test]
fn addresses_are_formatted_and_unequal_frames_are_described_in_words() {
    assert_eq!(
        summary::mac(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]),
        "52:54:00:12:34:56"
    );
    assert_eq!(summary::ipv4(&[10, 0, 2, 15]), "10.0.2.15");
    let mut v6 = [0u8; 16];
    v6[15] = 1;
    assert_eq!(summary::ipv6(&v6), "::1");
    assert_eq!(summary::describe(&[1, 2, 3]).info, "truncated frame");
    assert_eq!(
        summary::endpoint("10.0.2.15".parse().unwrap(), 80),
        "10.0.2.15:80"
    );
}

/// A DNS query for `a.example` of type `kind`.
fn query(kind: u16) -> Vec<u8> {
    let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["a", "example"] {
        message.push(label.len() as u8);
        message.extend(label.as_bytes());
    }
    message.push(0);
    message.extend(kind.to_be_bytes());
    message.extend([0, 1]);
    message
}

#[test]
fn dns_summaries_name_the_type_and_the_first_addresses() {
    assert_eq!(summary::dns(&query(1)), "query A a.example");
    assert_eq!(summary::dns(&query(28)), "query AAAA a.example");
    assert_eq!(summary::dns(&query(99)), "query type 99 a.example");
    let mut response = query(1);
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 2;
    for address in [[1, 2, 3, 4], [5, 6, 7, 8]] {
        response.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        response.extend(address);
    }
    assert_eq!(
        summary::dns(&response),
        "response A a.example → 1.2.3.4, 5.6.7.8"
    );
    // An error code replaces the answers.
    response[3] = 0x83;
    assert_eq!(summary::dns(&response), "response A a.example: error 3");
}

#[test]
fn dns_summaries_survive_truncation_and_hostile_lengths() {
    assert_eq!(summary::dns(&[1, 2]), "DNS");
    let mut message = query(1);
    for cut in 0..message.len() {
        let _ = summary::dns(&message[..cut]);
    }
    message[12] = 63; // a label longer than the message
    let _ = summary::dns(&message);
    let mut response = query(1);
    response[2] = 0x81;
    response[7] = 8;
    response.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0xff, 0xff, 1]);
    assert!(summary::dns(&response).starts_with("response A a.example"));
    assert_eq!(summary::dns(&[0, 0, 0x01, 0, 0, 0]), "query");
}

#[test]
fn http_lines_need_a_method_or_a_status_and_are_cut_to_160_characters() {
    assert_eq!(
        summary::http_line(b"GET /a HTTP/1.1\r\nHost: x\r\n").as_deref(),
        Some("GET /a HTTP/1.1")
    );
    assert_eq!(
        summary::http_line(b"HTTP/1.1 200 OK\r\n").as_deref(),
        Some("HTTP/1.1 200 OK")
    );
    assert_eq!(summary::http_line(b"SSH-2.0-OpenSSH\r\n"), None);
    assert_eq!(summary::http_line(&[0xff, 0xfe]), None);
    let long = format!("GET /{} HTTP/1.1\r\n", "a".repeat(400));
    assert_eq!(
        summary::http_line(long.as_bytes()).unwrap().chars().count(),
        160
    );
}

#[test]
fn the_server_name_is_read_only_from_a_whole_client_hello() {
    let hello = client_hello(b"example.test");
    let (at, len) = summary::tls_sni(&hello).unwrap();
    assert_eq!(&hello[at..at + len], b"example.test");
    // Every prefix is either rejected or points inside the data.
    for cut in 0..hello.len() {
        if let Some((at, len)) = summary::tls_sni(&hello[..cut]) {
            assert!(at + len <= cut);
        }
    }
    let mut other = hello.clone();
    other[5] = 2; // ServerHello
    assert_eq!(summary::tls_sni(&other), None);
    assert_eq!(summary::tls_sni(&[]), None);
}
