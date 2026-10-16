// SPDX-License-Identifier: MIT
//! HTTP and DNS exchanges reassembled from TCP and UDP payloads.
use super::*;

pub(super) struct Segment {
    number: u64,
    #[allow(dead_code)]
    time_us: u64,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seq: Option<u32>,
    payload: Vec<u8>,
}

/// Rebuild cleartext HTTP/1 and DNS from frame bytes.
/// HTTPS, HTTP/2, HTTP/3 and encrypted DNS are counted as unavailable.
pub fn reconstruct(frames: &[CapturedFrame<'_>]) -> Reconstruction {
    let mut out = Reconstruction {
        notes: vec![
            "Supported: HTTP/1.0 and HTTP/1.1 over TCP, DNS over UDP, DNS over TCP.".into(),
            "Unavailable: HTTPS, HTTP/2, HTTP/3, and encrypted DNS.".into(),
        ],
        ..Reconstruction::default()
    };
    let mut segments = Vec::new();
    for frame in frames {
        if let Some(segment) = segment_from_frame(frame) {
            segments.push(segment);
        }
    }
    let mut seen: HashSet<(IpAddr, IpAddr, u16, u16, u32, u64)> = HashSet::new();
    let mut unique = Vec::new();
    for segment in segments {
        if let Some(seq) = segment.seq
            && !segment.payload.is_empty()
        {
            let key = (
                segment.src,
                segment.dst,
                segment.sport,
                segment.dport,
                seq,
                segment.payload.len() as u64,
            );
            if !seen.insert(key) {
                out.retransmissions_dropped += 1;
                continue;
            }
        }
        unique.push(segment);
    }
    reconstruct_dns(&unique, &mut out);
    reconstruct_http(&unique, &mut out);
    out
}

fn segment_from_frame(frame: &CapturedFrame<'_>) -> Option<Segment> {
    let bytes = frame.bytes;
    let mut ethertype = u16_be(bytes, 12)?;
    let mut at = 14;
    if ethertype == 0x8100 {
        ethertype = u16_be(bytes, 16)?;
        at = 18;
    }
    let packet = bytes.get(at..)?;
    let (next, body, src, dst) = match ethertype {
        0x0800 if packet.len() >= 20 && packet[0] >> 4 == 4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16_be(packet, 2).unwrap_or(0)).min(packet.len());
            if header_len < 20 || header_len > total {
                return None;
            }
            if u16_be(packet, 6).unwrap_or(0) & 0x1fff != 0 {
                return None;
            }
            (
                packet[9],
                packet.get(header_len..total)?.to_vec(),
                ipv4_addr(&packet[12..16]),
                ipv4_addr(&packet[16..20]),
            )
        }
        0x86dd if packet.len() >= 40 => {
            let src = ipv6_addr(&packet[8..24]);
            let dst = ipv6_addr(&packet[24..40]);
            let length = usize::from(u16_be(packet, 4).unwrap_or(0));
            let mut body = packet.get(40..(40 + length).min(packet.len()))?.to_vec();
            let mut next = packet[6];
            for _ in 0..8 {
                let skip = match next {
                    0 | 43 | 60 => body.get(1).map(|len| (usize::from(*len) + 1) * 8),
                    44 => Some(8),
                    51 => body.get(1).map(|len| (usize::from(*len) + 2) * 4),
                    _ => break,
                }?;
                next = *body.first()?;
                body = body.get(skip..)?.to_vec();
            }
            (next, body, src, dst)
        }
        _ => return None,
    };
    match next {
        6 if body.len() >= 20 => {
            let sport = u16_be(&body, 0)?;
            let dport = u16_be(&body, 2)?;
            let seq = u32_be(&body, 4)?;
            let offset = usize::from(body[12] >> 4) * 4;
            let payload = body.get(offset..).unwrap_or(&[]).to_vec();
            Some(Segment {
                number: frame.number,
                time_us: frame.time_us,
                src,
                dst,
                sport,
                dport,
                seq: Some(seq),
                payload,
            })
        }
        17 if body.len() >= 8 => {
            let sport = u16_be(&body, 0)?;
            let dport = u16_be(&body, 2)?;
            Some(Segment {
                number: frame.number,
                time_us: frame.time_us,
                src,
                dst,
                sport,
                dport,
                seq: None,
                payload: body[8..].to_vec(),
            })
        }
        _ => None,
    }
}

struct HttpDirection {
    src: String,
    dst: String,
    data: Vec<u8>,
    frames: Vec<u64>,
    gap: bool,
}

fn reconstruct_http(segments: &[Segment], out: &mut Reconstruction) {
    use std::collections::BTreeMap;
    let mut directions: BTreeMap<(String, String), Vec<&Segment>> = BTreeMap::new();
    for segment in segments.iter().filter(|segment| segment.seq.is_some()) {
        if segment.payload.is_empty() {
            continue;
        }
        if segment.payload.first() == Some(&22) {
            out.https_segments += 1;
            continue;
        }
        let key = (
            format!("{}:{}", segment.src, segment.sport),
            format!("{}:{}", segment.dst, segment.dport),
        );
        directions.entry(key).or_default().push(segment);
    }
    let mut streams: Vec<HttpDirection> = Vec::new();
    for ((src, dst), mut parts) in directions {
        parts.sort_by_key(|segment| segment.seq.unwrap_or(0));
        let mut data = Vec::new();
        let mut frames = Vec::new();
        let mut expected: Option<u32> = None;
        let mut gap = false;
        for segment in parts {
            let seq = segment.seq.unwrap_or(0);
            if let Some(next) = expected {
                if seq < next {
                    continue;
                }
                if seq > next {
                    gap = true;
                    break;
                }
            }
            if data.is_empty() && segment.payload.starts_with(b"PRI * HTTP/2.0") {
                out.http2_prefaces += 1;
                data.clear();
                break;
            }
            data.extend_from_slice(&segment.payload);
            frames.push(segment.number);
            expected = Some(seq.wrapping_add(segment.payload.len() as u32));
        }
        if !data.is_empty() {
            streams.push(HttpDirection {
                src,
                dst,
                data,
                frames,
                gap,
            });
        }
    }
    for direction in &streams {
        if direction.data.starts_with(b"HTTP/") {
            continue;
        }
        let text = String::from_utf8_lossy(&direction.data);
        let mut rest = text.as_ref();
        while let Some(request) = take_http_request(&mut rest) {
            let response = streams.iter().find(|other| {
                other.src == direction.dst
                    && other.dst == direction.src
                    && other.data.starts_with(b"HTTP/")
            });
            let (status, response_frames) = response
                .map(|other| (http_status(&other.data), other.frames.clone()))
                .unwrap_or((None, Vec::new()));
            out.http.push(ReconstructedHttp {
                method: request.0,
                host: request.3,
                uri: request.1,
                version: request.2,
                status,
                request_frames: direction.frames.clone(),
                response_frames,
                complete: !direction.gap && request.4,
            });
        }
    }
}

fn take_http_request(rest: &mut &str) -> Option<(String, String, String, String, bool)> {
    let line_end = rest.find("\r\n").or_else(|| rest.find('\n'))?;
    let line = &rest[..line_end];
    let mut words = line.split_whitespace();
    let method = words.next()?.to_string();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "HEAD" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return None;
    }
    let uri = words.next().unwrap_or("").to_string();
    let version = words.next().unwrap_or("").to_string();
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let header_at = line_end
        + if rest[line_end..].starts_with("\r\n") {
            2
        } else {
            1
        };
    let headers = &rest[header_at..];
    let (header_block, complete) = if let Some(end) = headers.find("\r\n\r\n") {
        *rest = &headers[end + 4..];
        (&headers[..end], true)
    } else if let Some(end) = headers.find("\n\n") {
        *rest = &headers[end + 2..];
        (&headers[..end], true)
    } else {
        *rest = "";
        (headers, false)
    };
    let host = header_block
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    Some((method, uri, version, host, complete))
}

fn http_status(body: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(body).ok()?.lines().next()?;
    let mut words = line.split_whitespace();
    let version = words.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    words.next()?.parse().ok()
}

fn reconstruct_dns(segments: &[Segment], out: &mut Reconstruction) {
    let mut pending: Vec<ReconstructedDns> = Vec::new();
    for segment in segments {
        let on_dns = segment.sport == 53 || segment.dport == 53;
        if !on_dns || segment.payload.is_empty() {
            continue;
        }
        let messages: Vec<Vec<u8>> = if segment.seq.is_some() {
            tcp_dns_messages(&segment.payload)
        } else {
            vec![segment.payload.clone()]
        };
        let protocol = if segment.seq.is_some() { "TCP" } else { "UDP" };
        for message in messages {
            let Some(parsed) = parse_dns(&message) else {
                continue;
            };
            if parsed.response {
                if let Some(query) = pending.iter_mut().rev().find(|query| {
                    query.id == parsed.id
                        && query.name == parsed.name
                        && query.response_frames.is_empty()
                }) {
                    query.rcode = Some(parsed.rcode);
                    query.answers = parsed.answers;
                    query.response_frames.push(segment.number);
                }
            } else {
                let retry = pending.iter().any(|query| {
                    query.id == parsed.id && query.name == parsed.name && query.protocol == protocol
                });
                pending.push(ReconstructedDns {
                    id: parsed.id,
                    name: parsed.name,
                    qtype: parsed.qtype,
                    class_name: parsed.class_name,
                    protocol,
                    rcode: None,
                    answers: Vec::new(),
                    query_frames: vec![segment.number],
                    response_frames: Vec::new(),
                    retry,
                });
            }
        }
    }
    out.dns = pending;
}

fn tcp_dns_messages(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    let mut at = 0;
    while at + 2 <= payload.len() {
        let len = usize::from(u16_be(payload, at).unwrap_or(0));
        at += 2;
        if len == 0 || at + len > payload.len() {
            break;
        }
        messages.push(payload[at..at + len].to_vec());
        at += len;
    }
    messages
}

struct ParsedDns {
    id: u16,
    response: bool,
    rcode: u16,
    name: String,
    qtype: String,
    class_name: String,
    answers: Vec<String>,
}

fn parse_dns(data: &[u8]) -> Option<ParsedDns> {
    if data.len() < 12 {
        return None;
    }
    let id = u16_be(data, 0)?;
    let flags = u16_be(data, 2)?;
    let questions = u16_be(data, 4)?;
    let answers = u16_be(data, 6)?;
    if questions == 0 {
        return None;
    }
    let (name, mut at) = dns_name(data, 12)?;
    let qtype = dns_type(u16_be(data, at)?);
    let class_name = dns_class(u16_be(data, at + 2)?);
    at += 4;
    let mut decoded = Vec::new();
    if flags & 0x8000 != 0 {
        for _ in 0..answers {
            let (_, next) = dns_name(data, at)?;
            at = next;
            let kind = u16_be(data, at)?;
            at += 8;
            let len = usize::from(u16_be(data, at)?);
            at += 2;
            let rdata = data.get(at..at + len)?;
            if kind == 1 && rdata.len() == 4 {
                decoded.push(ipv4(rdata));
            } else if kind == 28 && rdata.len() == 16 {
                decoded.push(ipv6(rdata));
            }
            at += len;
        }
    }
    Some(ParsedDns {
        id,
        response: flags & 0x8000 != 0,
        rcode: flags & 0x000f,
        name,
        qtype,
        class_name,
        answers: decoded,
    })
}
