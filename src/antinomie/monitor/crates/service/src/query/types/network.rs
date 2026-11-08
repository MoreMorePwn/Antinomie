// SPDX-License-Identifier: GPL-3.0-only
//! The network result objects of the `recording.network.*` operations
//! (design 5.12.3): summary, rows of each tab, captures and packets.

use super::*;

/// One row of a `top_*` list: the tab's [`NetworkRow`] shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NetworkSummary {
    /// Capture segments.
    pub captures: u64,
    pub frames: u64,
    pub bytes: u64,
    pub endpoints: u64,
    pub domains: u64,
    pub urls: u64,
    pub tls_sessions: u64,
    pub dns_names: u64,
    pub http_requests: u64,
    /// Ten rows each, by bytes (endpoints) or count. U
    pub top_endpoints: Vec<EndpointRow>,
    pub top_domains: Vec<DomainRow>,
    pub top_urls: Vec<UrlRow>,
    pub top_tls: Vec<TlsRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTab {
    Endpoints,
    Domains,
    Urls,
    Tls,
    Dns,
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// `endpoints` tab. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointRow {
    /// A `capture_id` from `recording.network.captures`.
    pub capture: String,
    pub endpoint: String,
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: TransportProtocol,
    pub frames: u64,
    pub bytes: u64,
    pub country: Option<String>,
    pub organization: Option<String>,
    pub first_us: u64,
    pub last_us: u64,
    /// The first frame number.
    pub frame: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum NameSource {
    #[serde(rename = "DNS")]
    Dns,
    #[serde(rename = "HTTP")]
    Http,
    #[serde(rename = "TLS")]
    Tls,
}

/// `domains` tab. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DomainRow {
    pub capture: String,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub count: u64,
    pub sources: Vec<NameSource>,
    pub rcodes: Vec<String>,
    pub first_us: u64,
    pub last_us: u64,
    pub frame: u64,
}

/// `dns` tab: the `domains` rows whose `sources` contain `DNS`. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DnsRow {
    pub hostname: String,
    pub rcodes: Vec<String>,
    pub addresses: Vec<String>,
    pub count: u64,
    pub first_us: u64,
    pub frame: u64,
}

/// `urls` tab: one row per distinct cleartext request URL. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UrlRow {
    pub url: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub status: Option<u16>,
    pub count: u64,
    pub first_us: u64,
    pub frame: u64,
}

/// `tls` tab. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TlsRow {
    pub capture: String,
    pub frame: u64,
    pub time_us: u64,
    pub endpoint: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub version: String,
    pub ja3: String,
    pub ja4: String,
    pub ja3s: String,
    pub cert_sha1: Option<String>,
    pub sessions: u64,
}

/// `http` tab. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpRow {
    pub capture: String,
    pub frame: u64,
    pub time_us: u64,
    pub endpoints: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub version: String,
    pub status: Option<u16>,
    pub complete: bool,
    /// `unknown` unless the socket identity proves it.
    pub attribution: String,
}

/// `recording.network.list` row: the shape depends on `tab`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum NetworkRow {
    Endpoint(EndpointRow),
    Domain(DomainRow),
    Dns(DnsRow),
    Url(UrlRow),
    Tls(TlsRow),
    Http(HttpRow),
}

/// `recording.network.captures` item. The host path is L and never sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Capture {
    pub capture_id: String,
    /// The order; a snapshot boundary starts a new segment.
    pub segment: u32,
    pub size: u64,
    pub packets: Option<u64>,
    pub first_ms: Option<u64>,
    pub last_ms: Option<u64>,
    pub state: ArtifactState,
    /// L
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Which run the segment belongs to, from the runs' own records; none
    /// when no run record could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<CaptureLink>,
}

/// How sure a link to a run is (the provenance of cores and memory dumps
/// uses the same four).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkCertainty {
    /// The run started the segment and lists it in its artifacts.
    Exact,
    /// The segment was written while the runs in `live_runs` were live: the
    /// time is the only link.
    ByTime,
    /// The segment holds the whole VM's traffic and no run was live.
    VmWide,
    Unknown,
}

/// The run behind a capture segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureLink {
    pub certainty: LinkCertainty,
    /// The run that started the segment (`exact` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Other runs that were live while the segment was written, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_runs: Vec<String>,
}

/// What made a packet's flow, matched on the host from the run's recorded
/// network calls (address, protocol and time).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MadeByKind {
    /// A process of the run.
    Process,
    /// The base image's own traffic (NTP, DHCP, apt).
    Background,
    /// No recorded call matches.
    Unattributed,
}

/// The `made_by` of a packet row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MadeBy {
    pub kind: MadeByKind,
    /// `curl (412 \u{b7} 413)`, `Base image background: NTP` or `Unattributed`.
    pub label: String,
    /// The first process and its thread, for `process`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    /// Further processes that made a matching call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PacketTransport {
    Tcp,
    Udp,
}

/// `recording.network.packets` row (no payload bytes). The columns are
/// TShark's defaults, each cut to 256 characters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PacketRow {
    /// Frame number from 1.
    pub n: u64,
    /// Capture time, Unix microseconds on the host clock.
    pub time_us: u64,
    /// Octets on the wire.
    pub length: u32,
    pub captured: u32,
    /// U
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u16>,
    pub transport: Option<PacketTransport>,
    /// What made the packet's flow; absent when the run's calls could not be
    /// read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub made_by: Option<MadeBy>,
}

/// A node of a decoded packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetailNode {
    pub depth: u32,
    /// Carries decoded payload text. S
    pub label: String,
    pub name: String,
    pub start: u32,
    pub len: u32,
    pub end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetailTree {
    pub nodes: Vec<DetailNode>,
    /// The tree was cut.
    pub cut: bool,
}

/// `recording.network.packet`. The whole object is S.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PacketDetail {
    pub n: u64,
    pub frame_len: u32,
    pub tree: DetailTree,
    /// The whole frame, base64.
    pub bytes: String,
}
