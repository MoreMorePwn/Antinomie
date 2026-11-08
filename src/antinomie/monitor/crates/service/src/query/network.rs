// SPDX-License-Identifier: GPL-3.0-only
//! `recording.network.summary` and `recording.network.list` (design 5.12.3
//! class T, card Q-4): the Network tabs of the Triage scan. The field lists are
//! the Triage crate's own; the rows keep the capture as a `capture_id` of
//! `recording.network.captures`, never a host path.

use super::{
    page::{Page, PageRequest, Single},
    request::{NetworkListParams, RunParams},
    service::{Opened, QueryService},
    tables::{self, Cut, V, Values},
    types::*,
};
use crate::api::error::ApiError;
use antinomie_triage::{
    Cell, HTTP_FIELDS, ScanData,
    network::{DOMAIN_FIELDS, ENDPOINT_FIELDS, TLS_FIELDS},
    query::{FieldSpec, RowValue},
};
use std::collections::BTreeMap;

/// Rows of the summary's `top_*` lists.
const TOP: usize = 10;

/// The Triage field list a tab filters and sorts by.
pub fn fields_of(tab: NetworkTab) -> &'static [FieldSpec<'static>] {
    match tab {
        NetworkTab::Endpoints => ENDPOINT_FIELDS,
        NetworkTab::Domains | NetworkTab::Dns => DOMAIN_FIELDS,
        NetworkTab::Tls => TLS_FIELDS,
        NetworkTab::Urls | NetworkTab::Http => HTTP_FIELDS,
    }
}

type Owned = Vec<(&'static str, RowValue)>;

fn cells(rows: &[Vec<Cell>]) -> Vec<Owned> {
    rows.iter()
        .map(|row| tables::values_of(row).to_vec())
        .collect()
}

/// The rows of a tab as owned values, and what the scan left out of the page.
fn tab_rows(scan: &ScanData, tab: NetworkTab) -> (Vec<Owned>, u64) {
    let tabs = &scan.new_tabs;
    match tab {
        NetworkTab::Endpoints => (cells(&tabs.endpoints), tabs.endpoints_omitted),
        NetworkTab::Domains => (cells(&tabs.domains), tabs.domains_omitted),
        NetworkTab::Dns => (
            cells(&tabs.domains)
                .into_iter()
                .filter(|values| V(values).list("network.sources").iter().any(|s| s == "DNS"))
                .collect(),
            tabs.domains_omitted,
        ),
        NetworkTab::Tls => (cells(&tabs.tls), tabs.tls_omitted),
        NetworkTab::Http => (cells(&scan.http), scan.http_omitted),
        NetworkTab::Urls => (urls(&tabs.urls), 0),
    }
}

/// One row per distinct request URL: the first HTTP row of it, with the
/// number of requests, the first non-empty response status and the earliest
/// time.
fn urls(rows: &[Vec<Cell>]) -> Vec<Owned> {
    let mut order: Vec<(String, String, String)> = Vec::new();
    let mut groups: BTreeMap<(String, String, String), (Owned, u64)> = BTreeMap::new();
    for row in rows {
        let values = tables::values_of(row).to_vec();
        let v = V(&values);
        let key = (
            v.text("http.method"),
            v.text("http.host"),
            v.text("http.uri"),
        );
        match groups.get_mut(&key) {
            Some((first, count)) => {
                *count += 1;
                let known = |values: &Owned, name: &str| V(values).number(name);
                if known(first, "http.status").is_none()
                    && let Some(status) = v.number("http.status")
                {
                    set(first, "http.status", RowValue::Number(status));
                }
                if let (Some(old), Some(new)) =
                    (known(first, "frame.time_us"), v.number("frame.time_us"))
                    && new < old
                {
                    set(first, "frame.time_us", RowValue::Number(new));
                    if let Some(frame) = v.number("frame.number") {
                        set(first, "frame.number", RowValue::Number(frame));
                    }
                }
            }
            None => {
                order.push(key.clone());
                groups.insert(key, (values, 1));
            }
        }
    }
    order
        .into_iter()
        .filter_map(|key| groups.remove(&key))
        .map(|(mut values, count)| {
            values.push(("network.count", RowValue::Number(i128::from(count))));
            values
        })
        .collect()
}

fn set(values: &mut Owned, name: &str, value: RowValue) {
    if let Some(slot) = values.iter_mut().find(|(field, _)| *field == name) {
        slot.1 = value;
    }
}

fn status(v: &V<'_>) -> Option<u16> {
    v.number("http.status").and_then(|n| u16::try_from(n).ok())
}

fn name_source(text: &str) -> Option<NameSource> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

/// The `capture_id` the capture path of a row stands for.
struct Captures(Vec<(String, String)>);

impl Captures {
    fn id(&self, path: &str) -> String {
        self.0
            .iter()
            .find(|(known, _)| known == path || (!path.is_empty() && known.ends_with(path)))
            .map(|(_, id)| id.clone())
            .unwrap_or_else(|| {
                // Not a listed capture: the file name, never the host path.
                std::path::Path::new(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
    }
}

fn row_of(tab: NetworkTab, values: &Values, captures: &Captures) -> NetworkRow {
    let v = V(values);
    let capture = captures.id(&v.text("capture.path"));
    let frame = v.u64("frame.number");
    match tab {
        NetworkTab::Endpoints => NetworkRow::Endpoint(EndpointRow {
            capture,
            endpoint: v.text("network.endpoint"),
            ip: v.text("network.ip"),
            port: v
                .opt_u64("network.port")
                .and_then(|p| u16::try_from(p).ok()),
            protocol: if v.text("network.protocol") == "udp" {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            },
            frames: v.u64("network.frames"),
            bytes: v.u64("network.bytes"),
            country: v.opt_text("network.country"),
            organization: v.opt_text("network.organization"),
            first_us: v.u64("network.first_us"),
            last_us: v.u64("network.last_us"),
            frame,
        }),
        NetworkTab::Domains => NetworkRow::Domain(DomainRow {
            capture,
            hostname: v.text("network.hostname"),
            addresses: v.list("network.addresses"),
            count: v.u64("network.count"),
            sources: v
                .list("network.sources")
                .iter()
                .filter_map(|s| name_source(s))
                .collect(),
            rcodes: v.list("dns.rcode"),
            first_us: v.u64("network.first_us"),
            last_us: v.u64("network.last_us"),
            frame,
        }),
        NetworkTab::Dns => NetworkRow::Dns(DnsRow {
            hostname: v.text("network.hostname"),
            rcodes: v.list("dns.rcode"),
            addresses: v.list("network.addresses"),
            count: v.u64("network.count"),
            first_us: v.u64("network.first_us"),
            frame,
        }),
        NetworkTab::Urls => NetworkRow::Url(url_row(&v, frame)),
        NetworkTab::Tls => NetworkRow::Tls(TlsRow {
            capture,
            frame,
            time_us: v.u64("frame.time_us"),
            endpoint: v.text("tls.endpoint"),
            sni: v.text("tls.sni"),
            alpn: v.list("session.alpn"),
            version: v.text("tls.version"),
            ja3: v.text("tls.ja3"),
            ja4: v.text("tls.ja4"),
            ja3s: v.text("tls.ja3s"),
            cert_sha1: v.opt_text("tls.cert"),
            sessions: v.u64("tls.sessions"),
        }),
        NetworkTab::Http => NetworkRow::Http(HttpRow {
            capture,
            frame,
            time_us: v.u64("frame.time_us"),
            endpoints: v.text("network.endpoints"),
            method: v.text("http.method"),
            host: v.text("http.host"),
            uri: v.text("http.uri"),
            version: v.text("http.version"),
            status: status(&v),
            complete: v
                .flag("entry.complete")
                .unwrap_or_else(|| status(&v).is_some()),
            attribution: v.text("network.attribution"),
        }),
    }
}

fn url_row(v: &V<'_>, frame: u64) -> UrlRow {
    let host = v.text("http.host");
    let uri = v.text("http.uri");
    UrlRow {
        url: if uri.starts_with("http://") || uri.starts_with("https://") {
            uri.clone()
        } else {
            format!("http://{host}{uri}")
        },
        method: v.text("http.method"),
        host,
        uri,
        status: status(v),
        count: v.u64("network.count").max(1),
        first_us: v.u64("frame.time_us"),
        frame,
    }
}

impl QueryService {
    fn capture_ids(&self, opened: &Opened) -> Captures {
        Captures(self.capture_paths(opened))
    }

    /// `recording.network.list`.
    pub(super) fn network_list(
        &self,
        params: &NetworkListParams,
    ) -> Result<Page<NetworkRow>, ApiError> {
        let fields = fields_of(params.tab);
        tables::check_sort(params.sort.as_ref(), fields)?;
        let compiled = tables::compile_q(params.q.as_deref(), fields)?;
        let opened = self.open_run(&params.run_key)?;
        let binding = opened.binding(&(params.tab, &params.q), &params.sort);
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Page::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let (rows, omitted) = tab_rows(&scanned.scan, params.tab);
        // Default order: first seen; the endpoints by bytes, largest first.
        let mut base: Vec<usize> = (0..rows.len()).collect();
        let key = |at: usize, name: &str| V(&rows[at]).u64(name);
        match params.tab {
            NetworkTab::Endpoints => {
                base.sort_by_key(|at| std::cmp::Reverse(key(*at, "network.bytes")))
            }
            NetworkTab::Tls | NetworkTab::Http | NetworkTab::Urls => {
                base.sort_by_key(|at| key(*at, "frame.time_us"));
            }
            _ => base.sort_by_key(|at| key(*at, "network.first_us")),
        }
        let values: Vec<&Values> = base.iter().map(|at| rows[*at].as_slice()).collect();
        let order: Vec<usize> = tables::select(
            values.iter().copied(),
            &compiled,
            |_| true,
            params.sort.as_ref(),
        )
        .into_iter()
        .map(|at| base[at])
        .collect();
        let captures = self.capture_ids(&opened);
        let cut = Cut {
            request: &PageRequest {
                limit: params.limit,
                cursor: params.cursor.clone(),
            },
            max: self.settings.rows().1,
            binding,
            omitted,
            untrusted: true,
        };
        tables::page_of(&opened, &order, &cut, |at| {
            row_of(params.tab, &rows[at], &captures)
        })
    }

    /// `recording.network.summary`.
    pub(super) fn network_summary(
        &self,
        params: &RunParams,
    ) -> Result<Single<NetworkSummary>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Single::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let scan = &scanned.scan;
        let captures = self.capture_ids(&opened);
        let top = |tab: NetworkTab, key: &str| -> Vec<NetworkRow> {
            let (rows, _) = tab_rows(scan, tab);
            let mut order: Vec<usize> = (0..rows.len()).collect();
            order.sort_by_key(|at| std::cmp::Reverse(V(&rows[*at]).u64(key)));
            order
                .into_iter()
                .take(TOP)
                .map(|at| row_of(tab, &rows[at], &captures))
                .collect()
        };
        let count = |tab: NetworkTab| {
            let (rows, omitted) = tab_rows(scan, tab);
            rows.len() as u64 + omitted
        };
        let (endpoint_rows, _) = tab_rows(scan, NetworkTab::Endpoints);
        let bytes = endpoint_rows
            .iter()
            .map(|values| V(values).u64("network.bytes"))
            .sum();
        let summary = NetworkSummary {
            captures: captures.0.len() as u64,
            frames: scan.network_counts.map_or(0, |(frames, _, _)| frames),
            bytes,
            endpoints: count(NetworkTab::Endpoints),
            domains: count(NetworkTab::Domains),
            urls: count(NetworkTab::Urls),
            tls_sessions: count(NetworkTab::Tls),
            dns_names: count(NetworkTab::Dns),
            http_requests: count(NetworkTab::Http),
            top_endpoints: top(NetworkTab::Endpoints, "network.bytes")
                .into_iter()
                .filter_map(|row| match row {
                    NetworkRow::Endpoint(row) => Some(row),
                    _ => None,
                })
                .collect(),
            top_domains: top(NetworkTab::Domains, "network.count")
                .into_iter()
                .filter_map(|row| match row {
                    NetworkRow::Domain(row) => Some(row),
                    _ => None,
                })
                .collect(),
            top_urls: top(NetworkTab::Urls, "network.count")
                .into_iter()
                .filter_map(|row| match row {
                    NetworkRow::Url(row) => Some(row),
                    _ => None,
                })
                .collect(),
            top_tls: top(NetworkTab::Tls, "tls.sessions")
                .into_iter()
                .filter_map(|row| match row {
                    NetworkRow::Tls(row) => Some(row),
                    _ => None,
                })
                .collect(),
        };
        Ok(opened.single(summary, true))
    }
}
