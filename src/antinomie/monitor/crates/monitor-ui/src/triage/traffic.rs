// SPDX-License-Identifier: MIT
//! HTTP and DNS rows and their link to the process that sent them. These
//! earlier row builders are kept for the tests that compare against them.
use super::*;

pub(super) fn flow(
    frame: impl Into<String>,
    ends: impl Into<String>,
    detail: impl Into<String>,
) -> Vec<Cell> {
    vec![
        cell(frame, theme::value(theme::ValueKind::Number), true),
        cell(ends, theme::text(), true),
        cell(detail, theme::text(), false),
    ]
}

pub(super) fn http_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for request in built.http {
        let packet = request
            .request_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let mut row = flow(
            request
                .request_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            format!("{} {} {}", request.method, request.uri, request.version),
        );
        row.push(cell(
            request
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            false,
        ));
        row.push(cell(
            packet
                .map(|packet| http_process(packet, input.invocations))
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            true,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
}

fn reconstruct_input(
    input: &TriageInput<'_>,
) -> Option<antinomie_monitor_core::network::Reconstruction> {
    let frames = input.frames?;
    if frames.is_empty() || frames.len() > input.packets.len() {
        return None;
    }
    let captured: Vec<_> = input
        .packets
        .iter()
        .zip(frames.iter())
        .map(
            |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                number: packet.number,
                time_us: packet.time_us,
                bytes,
            },
        )
        .collect();
    Some(antinomie_monitor_core::network::reconstruct(&captured))
}

/// Process of a connect or sendto whose path or info text contains this
/// packet's destination address and destination port. Port text alone is
/// not enough. Anything else is an em dash.
pub(super) fn http_process(packet: &NetworkPacket, invocations: &[InvocationSummary]) -> String {
    let Some(port) = packet.dst_port else {
        return "—".into();
    };
    let address = packet_address(packet);
    if address.is_empty() {
        return "—".into();
    }
    let port_text = port.to_string();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        if !connects_or_sends(event) {
            continue;
        }
        if mentions_endpoint(invocation, &address, &port_text) {
            return format!(
                "ambiguous: endpoint candidate pid {} tid {}",
                event.pid, event.tid
            );
        }
    }
    "—".into()
}

fn packet_address(packet: &NetworkPacket) -> String {
    if let Some(ip) = packet.dst_ip {
        return ip.to_string();
    }
    let destination = packet.destination.trim();
    if let Some(port) = packet.dst_port {
        let suffix = format!(":{port}");
        if let Some(host) = destination.strip_suffix(&suffix) {
            let host = host
                .strip_prefix('[')
                .and_then(|text| text.strip_suffix(']'))
                .unwrap_or(host)
                .trim();
            if !host.is_empty() {
                return host.to_string();
            }
        }
    }
    destination.to_string()
}

fn connects_or_sends(event: &EventSummary) -> bool {
    matches!(event.syscall_name.as_str(), "connect" | "sendto")
        || matches!(event.syscall_nr, 42 | 44)
}

fn mentions_endpoint(invocation: &InvocationSummary, address: &str, port: &str) -> bool {
    let info = trace::info(invocation);
    path_list(invocation)
        .iter()
        .any(|path| contains_address_and_port(path, address, port))
        || contains_address_and_port(&info, address, port)
}

fn contains_address_and_port(text: &str, address: &str, port: &str) -> bool {
    text.contains(address) && text.contains(port)
}

pub(super) fn dns_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for query in built.dns {
        let packet = query
            .query_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let detail = if query.answers.is_empty() {
            format!("{} {} {}", query.name, query.qtype, query.class_name)
        } else {
            format!(
                "{} {} {} → {}",
                query.name,
                query.qtype,
                query.class_name,
                query.answers.join(", ")
            )
        };
        let mut row = flow(
            query
                .query_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            detail,
        );
        let kind = if query.retry {
            "retry"
        } else if query.rcode.is_some() {
            "response"
        } else {
            "query"
        };
        row.push(cell(
            format!("{kind} {}", query.protocol),
            theme::text(),
            false,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
}
