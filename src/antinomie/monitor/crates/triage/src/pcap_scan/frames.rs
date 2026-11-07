// SPDX-License-Identifier: GPL-3.0-only
//! What one TShark frame holds, read as HTTP/1 requests, DNS queries and HTTP/2 requests.
use super::*;

/// The frame being read.
#[derive(Clone, Copy)]
pub struct Frame<'a> {
    pub path: &'a Path,
    pub fields: &'a [String],
    pub frame: u64,
    pub time: Option<u64>,
    pub endpoints: &'a str,
    pub destination: &'a str,
    pub destination_port: &'a str,
}

/// The spooled responses a request looks up, and the page the HTTP rows go to.
pub struct Spool<'a> {
    pub offsets: &'a mut std::fs::File,
    pub responses: &'a mut std::io::BufReader<std::fs::File>,
    pub http_query: &'a crate::query::Compiled,
    pub http_page: &'a mut sorting::Page<Vec<Cell>>,
}

/// The HTTP/1 requests of a frame, each with the response its link names.
pub fn http_requests(
    frame_context: &Frame<'_>,
    inventory: &mut network::Inventory,
    spool: &mut Spool<'_>,
    observe: &mut impl FnMut(RowKind, &[Cell], &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let Frame {
        path,
        fields,
        frame,
        time,
        endpoints,
        destination,
        destination_port,
    } = *frame_context;
    let field = |at: usize| fields[at].as_str();
    let Spool {
        offsets,
        responses,
        http_query,
        http_page,
    } = spool;
    if !field(11).is_empty() {
        let methods = field(11).split('\u{1f}').collect::<Vec<_>>();
        let response_frames = field(16)
            .split('\u{1f}')
            .filter_map(|id| id.parse::<u64>().ok())
            .collect::<Vec<_>>();
        for (at, method) in methods.iter().enumerate() {
            let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
            let response = match response_frames.get(at).copied() {
                Some(frame) => spool_response(frame, offsets, responses)?,
                None => Vec::new(),
            };
            let status = response
                .get(15)
                .and_then(|value| value.split('\u{1f}').next())
                .and_then(|value| value.parse::<u16>().ok());
            let row = http_row(
                path,
                &HttpRequest {
                    frame,
                    time,
                    endpoints,
                    method,
                    host: item(12),
                    uri: item(13),
                    version: item(14),
                    status,
                    response_frames: field(16),
                },
            );
            inventory.host(item(12), frame, time, &[destination.into()], "HTTP");
            inventory.url(&network::UrlFacts {
                frame,
                time,
                method,
                host: item(12),
                uri: item(13),
                version: item(14),
                status,
                destination,
                port: destination_port,
            });
            observe(
                RowKind::Http,
                &row,
                destination,
                if field(7).is_empty() {
                    field(9)
                } else {
                    field(7)
                },
            )?;
            if http_query.keep_table(&row[0].values) {
                http_page.push(row)?;
            }
        }
    }
    Ok(())
}

/// The DNS queries of a frame, with the answers of the response it links.
pub fn dns_queries(
    frame_context: &Frame<'_>,
    inventory: &mut network::Inventory,
    spool: &mut Spool<'_>,
    observe: &mut impl FnMut(RowKind, &[Cell], &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let Frame {
        path,
        fields,
        frame,
        time,
        endpoints,
        destination,
        ..
    } = *frame_context;
    let field = |at: usize| fields[at].as_str();
    let Spool {
        offsets, responses, ..
    } = spool;
    if !field(19).is_empty() && tshark_boolean(field(22)) == Some(false) {
        let response_frame = field(28)
            .split('\u{1f}')
            .next()
            .and_then(|id| id.parse::<u64>().ok());
        let response = match response_frame {
            Some(frame) => spool_response(frame, offsets, responses)?,
            None => Vec::new(),
        };
        let rcode = response.get(23).and_then(|value| value.parse::<u16>().ok());
        let answers = [24, 25, 26, 27]
            .iter()
            .filter_map(|at| response.get(*at))
            .filter(|text| !text.is_empty())
            .flat_map(|text| text.split('\u{1f}').map(str::to_owned))
            .collect::<Vec<_>>();
        for (at, name) in field(19).split('\u{1f}').enumerate() {
            let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
            let id = field(18).split('\u{1f}').next().and_then(parse_integer);
            let protocol = if field(6).is_empty() { "UDP" } else { "TCP" };
            let retry = tshark_boolean(field(30));
            let mut row = vec![
                cell(format!("#{frame}"), tone::text(), true),
                cell(endpoints, tone::text(), true),
                cell(field(18), tone::text(), true),
                cell(name, tone::text(), false),
                cell(network::qtype(item(20)), tone::text(), false),
                cell(item(21), tone::text(), false),
                cell(protocol, tone::text(), false),
                cell(
                    rcode.map_or("—".into(), |code| code.to_string()),
                    tone::text(),
                    true,
                ),
                cell(answers.join(", "), tone::text(), false),
                cell(field(28), tone::text(), true),
                cell(
                    match retry {
                        Some(true) => "retry",
                        Some(false) => "query",
                        None => "—",
                    },
                    tone::text(),
                    false,
                ),
            ];
            row[0].values = vec![
                ("capture.path", RowValue::Text(path.display().to_string())),
                ("frame.number", RowValue::Number(i128::from(frame))),
                (
                    "frame.time_us",
                    time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                ("network.endpoints", RowValue::Text(endpoints.to_owned())),
                ("dns.id", id.map_or(RowValue::Missing, RowValue::Number)),
                ("dns.name", RowValue::Text(name.into())),
                ("dns.type", text_value(&network::qtype(item(20)))),
                ("dns.class", text_value(item(21))),
                ("dns.protocol", RowValue::Text(protocol.into())),
                (
                    "dns.rcode",
                    rcode.map_or(RowValue::Missing, |code| RowValue::Number(i128::from(code))),
                ),
                ("dns.answers", RowValue::List(answers.clone())),
                ("dns.retry", retry.map_or(RowValue::Missing, RowValue::Bool)),
            ];
            let addresses: Vec<_> = answers
                .iter()
                .filter(|answer| answer.parse::<std::net::IpAddr>().is_ok())
                .cloned()
                .collect();
            inventory.host(name, frame, time, &addresses, "DNS lookup");
            if let Some(code) = rcode {
                inventory.host_rcode(
                    name,
                    &network::rcode_name(i128::from(code), !answers.is_empty()),
                );
            }
            for at in [10, 6, 5, 2] {
                row.remove(at);
            }
            observe(
                RowKind::Dns,
                &row,
                destination,
                if field(7).is_empty() {
                    field(9)
                } else {
                    field(7)
                },
            )?;
        }
    }
    Ok(())
}

/// The cleartext HTTP/2 requests of a frame.
pub fn h2_requests(
    frame_context: &Frame<'_>,
    inventory: &mut network::Inventory,
    spool: &mut Spool<'_>,
    observe: &mut impl FnMut(RowKind, &[Cell], &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let Frame {
        path,
        fields,
        frame,
        time,
        endpoints,
        destination,
        destination_port,
    } = *frame_context;
    let field = |at: usize| fields[at].as_str();
    let Spool {
        http_query,
        http_page,
        ..
    } = spool;
    // Cleartext HTTP/2: TShark decodes the request headers; the response
    // is in another frame (a stream) and is not matched here.
    for (at, method) in field(F_H2_METHOD)
        .split('\u{1f}')
        .filter(|method| !method.is_empty())
        .enumerate()
    {
        let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
        let row = http_row(
            path,
            &HttpRequest {
                frame,
                time,
                endpoints,
                method,
                host: item(F_H2_AUTHORITY),
                uri: item(F_H2_PATH),
                version: "HTTP/2",
                status: None,
                response_frames: "",
            },
        );
        inventory.host(
            item(F_H2_AUTHORITY),
            frame,
            time,
            &[destination.into()],
            "HTTP/2",
        );
        inventory.url(&network::UrlFacts {
            frame,
            time,
            method,
            host: item(F_H2_AUTHORITY),
            uri: item(F_H2_PATH),
            version: "HTTP/2",
            status: None,
            destination,
            port: destination_port,
        });
        observe(RowKind::Http, &row, destination, destination_port)?;
        if http_query.keep_table(&row[0].values) {
            http_page.push(row)?;
        }
    }
    Ok(())
}
