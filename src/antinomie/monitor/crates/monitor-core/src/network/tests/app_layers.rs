// SPDX-License-Identifier: MIT
//! Direct tests of the DNS, DHCP, HTTP and TLS layers.
use super::*;

fn layer<'a>(layers: &'a [PacketLayer], name: &str) -> Option<&'a PacketLayer> {
    layers.iter().find(|layer| layer.name == name)
}

#[test]
fn a_dns_name_follows_compression_and_reports_where_it_was_written() {
    let mut data = vec![0u8; 12];
    data.extend([3, b'w', b'w', b'w', 7]);
    data.extend(b"example");
    data.extend([3, b'c', b'o', b'm', 0]);
    let pointer_at = data.len();
    data.extend([4, b'm', b'a', b'i', b'l', 0xc0, 16]);
    assert_eq!(
        dns_name(&data, 12),
        Some(("www.example.com".into(), data.len() - 7))
    );
    // "mail" then the tail of the name at offset 16 ("example.com").
    assert_eq!(
        dns_name(&data, pointer_at),
        Some(("mail.example.com".into(), data.len()))
    );
    assert_eq!(dns_name(&[0], 0), Some(("<Root>".into(), 1)));
}

#[test]
fn a_dns_name_that_loops_is_too_long_or_runs_off_the_data_is_refused() {
    assert_eq!(dns_name(&[0xc0, 0], 0), None, "a pointer to itself");
    assert_eq!(
        dns_name(&[0xc0, 2, 0xc0, 0], 0),
        None,
        "two pointers to each other"
    );
    assert_eq!(dns_name(&[5, b'a', b'b'], 0), None, "a label past the end");
    assert_eq!(dns_name(&[0x80, 0], 0), None, "a reserved label type");
    assert_eq!(dns_name(&[], 0), None);
    assert_eq!(dns_name(&[3, b'a', b'b', b'c'], 0), None, "no terminator");
    let long: Vec<u8> = (0..130).flat_map(|_| [1, b'a']).collect();
    assert_eq!(dns_name(&long, 0), None, "more than 127 labels");
}

#[test]
fn dns_classes_are_named_and_the_cache_flush_bit_is_ignored() {
    assert_eq!(dns_class(1), "IN");
    assert_eq!(dns_class(0x8001), "IN");
    assert_eq!(dns_class(3), "CH");
    assert_eq!(dns_class(255), "ANY");
    assert_eq!(dns_class(42), "class 42");
}

fn udp_over_ip(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    ethernet(0x0800, &ipv4_packet(17, &udp(sport, dport, data)))
}

fn tcp_over_ip(dport: u16, data: &[u8]) -> Vec<u8> {
    ethernet(0x0800, &ipv4_packet(6, &tcp(dport, 0x18, data)))
}

#[test]
fn a_dhcp_message_gives_its_type_and_a_cut_option_list_gives_no_panic() {
    let mut message = vec![0u8; 236];
    message[0] = 1;
    message.extend([0x63, 0x82, 0x53, 0x63]);
    message.extend([53, 1, 1]); // Discover
    message.extend([12, 4, b'h', b'o', b's', b't']);
    message.push(255);
    let layers = dissect(&udp_over_ip(68, 67, &message));
    let dhcp = layers
        .iter()
        .find(|layer| layer.name.contains("Dynamic Host"))
        .expect("a DHCP layer");
    assert!(
        dhcp.fields
            .iter()
            .any(|f| f.name == "Message type" && f.value == "Discover")
    );
    assert!(dhcp.fields.iter().any(|f| f.value == "host"));
    // An option whose length runs past the datagram, and one shorter than the header.
    let mut cut = message[..236 + 4].to_vec();
    cut.extend([53, 200, 1]);
    let _ = dissect(&udp_over_ip(68, 67, &cut));
    let _ = dissect(&udp_over_ip(68, 67, &message[..100]));
}

#[test]
fn an_http_request_is_split_into_its_line_headers_and_body() {
    let payload = b"POST /up HTTP/1.1\r\nHost: a.test\r\nX-Odd\r\n\r\nbody!";
    let frame = tcp_over_ip(80, payload);
    let layers = dissect(&frame);
    let http = layer(&layers, "Hypertext Transfer Protocol").expect("an HTTP layer");
    assert_eq!(http.summary, "POST /up HTTP/1.1");
    let value = |name: &str| {
        http.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    };
    assert_eq!(value("Request line"), Some("POST /up HTTP/1.1"));
    assert_eq!(value("Host"), Some("a.test"));
    assert_eq!(value("Header"), Some("X-Odd"));
    assert_eq!(value("Body"), Some("5 bytes"));
    for field in &http.fields {
        assert!(field.start + field.len <= frame.len(), "{field:?}");
    }
}

#[test]
fn an_http_response_cut_before_the_blank_line_reports_the_remainder_as_data() {
    let frame = tcp_over_ip(80, b"HTTP/1.1 200 OK\r\nServer: x\r\nPartial");
    let layers = dissect(&frame);
    let http = layer(&layers, "Hypertext Transfer Protocol").expect("an HTTP layer");
    assert!(http.fields.iter().any(|f| f.name == "Status line"));
    assert!(
        http.fields
            .iter()
            .any(|f| f.name == "Data" && f.value == "7 bytes")
    );
}

#[test]
fn tls_records_are_read_by_type_and_a_lying_length_stays_inside_the_frame() {
    let frame = tcp_over_ip(443, &client_hello(b"example.test"));
    let layers = dissect(&frame);
    let tls = layer(&layers, "Transport Layer Security").expect("a TLS layer");
    assert!(tls.start + tls.len <= frame.len());
    assert!(
        tls.fields.iter().any(|f| f.value.contains("example.test")),
        "{tls:?}"
    );
    let mut lying = client_hello(b"example.test");
    lying[3] = 0xff;
    lying[4] = 0xff;
    let frame = tcp_over_ip(443, &lying);
    for layer in dissect(&frame) {
        assert!(layer.start + layer.len <= frame.len());
        for field in layer.fields {
            assert!(field.start + field.len <= frame.len());
        }
    }
    let _ = dissect(&tcp_over_ip(443, &[22, 3, 1]));
}
