//! Network panel: the network captures of the selected VM and the packet list
//! of one of them. While a capture runs, QEMU writes every frame of the VM's
//! network interface to its pcap file, outside the guest; the list follows
//! that file live.
use crate::theme::{self, PacketColor, ValueKind};
use antinomie_monitor_core::network::{
    self, FieldKind, NetworkCapture, NetworkPacket, PacketLayer,
};
use antinomie_monitor_core::packet_filter::{
    CaptureIdentity, FieldRegistry, PacketFilterEvent, PacketFilterIndex, PacketFilterWorker,
    PAGE_SIZE,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

/// Packets kept in the list; older ones stay in the file (open it in Wireshark).
const MAX_PACKETS: usize = 200_000;
/// Packets read per refresh, so a large file loads over a few frames.
const READ_BATCH: usize = 5_000;
/// Entries of each quick-filter list.
const QUICK_ENTRIES: usize = 100;

/// What the panel asks the app to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkAction {
    Start,
    Stop,
}

/// The selected VM, as the panel needs it.
pub(crate) struct NetworkContext<'a> {
    /// The VM's running network capture.
    pub active: Option<&'a NetworkCapture>,
    /// The VM's recording folder.
    pub recordings: Option<&'a Path>,
    /// Recording folders retained after the VM's recording location changed.
    pub recording_roots: &'a [PathBuf],
    pub nat: bool,
    /// The VM is the one running.
    pub running: bool,
    /// A start or stop request is still being answered.
    pub pending: bool,
    pub font_size: f32,
}

/// The packets read from the open capture.
#[derive(Default)]
struct PacketList {
    path: Option<PathBuf>,
    packets: Vec<NetworkPacket>,
    next_offset: u64,
    next_number: u64,
    truncated: bool,
    error: Option<String>,
    last_read: Option<Instant>,
    selected: Option<NetworkPacket>,
    frame: Option<(u64, Result<Vec<u8>, String>)>,
    /// The selected frame's decoded layers, and the chosen layer (and field)
    /// whose bytes are marked.
    layers: Vec<PacketLayer>,
    field: Option<(usize, Option<usize>)>,
    /// Packets matching the filter, and the filter and packet count they were
    /// computed for (new packets are filtered as they arrive).
    rows: Vec<usize>,
    rows_for: Option<(String, usize)>,
    /// Quick-filter counts and the packet count they were computed for.
    counts: Option<(usize, Counts)>,
}

#[derive(Default)]
pub(crate) struct NetworkView {
    list: PacketList,
    filter: String,
    /// Last filter that parsed. Packet rows are built from this, not from an
    /// invalid expression still sitting in the box.
    applied_filter: String,
    filter_error: Option<String>,
    display_filter: String,
    display_index: Option<Arc<PacketFilterIndex>>,
    display_next_index: Option<Arc<PacketFilterIndex>>,
    display_page: Vec<NetworkPacket>,
    display_page_start: u64,
    display_error: Option<String>,
    display_rejected: Option<String>,
    display_worker: Option<PacketFilterWorker>,
    display_worker_error: Option<String>,
    display_generation: u64,
    display_pending: bool,
    display_requested: Option<(CaptureIdentity, String, bool)>,
    display_edited: Option<Instant>,
    display_identity_checked: Option<Instant>,
    display_identity: Option<CaptureIdentity>,
    display_follow_live: bool,
    display_jump: Option<u64>,
    display_validate_selection: bool,
    display_jump_note: Option<String>,
    record_filter: String,
    record_shown: HashSet<PathBuf>,
    record_history: Vec<String>,
    display_history: Vec<String>,
    /// Captures of the selected VM, newest first, and the current and retained
    /// recording folders they were listed from.
    captures: Vec<NetworkCapture>,
    captures_for: Option<(Option<PathBuf>, Vec<PathBuf>)>,
    /// The running capture (id, file) last seen, to notice a start or stop.
    seen_active: Option<(String, PathBuf)>,
    hide_list: bool,
    /// Payload bytes for the packets currently loaded. `None` when a record
    /// could not be read; an empty capture is not treated as reconstructed HTTP.
    payloads: Option<PayloadCache>,
}

struct PayloadCache {
    path: PathBuf,
    offsets: Vec<u64>,
    frames: Vec<Vec<u8>>,
    note: Option<String>,
}

fn capture_fields() -> Vec<crate::query::FieldSpec<'static>> {
    use crate::query::FieldSpec;
    let mut fields = crate::query::LABEL_FIELDS.to_vec();
    fields.extend([
        FieldSpec::text("name", "Displayed capture name"),
        FieldSpec::text("state", "Live, completed or unfinished capture"),
        FieldSpec::text("boot", "Recorded guest boot identity"),
        FieldSpec::number("start", "Unix start time in milliseconds"),
        FieldSpec::number("stop", "Unix stop time in milliseconds"),
        FieldSpec::number("packets", "Packet count recorded on finalization"),
        FieldSpec::number("size", "PCAP extent recorded on finalization, in octets"),
        FieldSpec::boolean("whole_boot", "Whole-boot recording"),
    ]);
    fields
}

fn remember_filter(history: &mut Vec<String>, expression: &str) {
    if !expression.trim().is_empty() && history.first().is_none_or(|prior| prior != expression) {
        history.retain(|prior| prior != expression);
        history.insert(0, expression.into());
        history.truncate(24);
    }
}

fn packet_display_clauses(packet: &NetworkPacket) -> Vec<(String, String)> {
    let mut clauses = vec![
        (
            "Frame number".into(),
            format!("frame.number == {}", packet.number),
        ),
        (
            "Frame length".into(),
            format!("frame.len == {}", packet.length),
        ),
    ];
    for (label, side, address) in [
        ("Source address", "src", packet.src_ip),
        ("Destination address", "dst", packet.dst_ip),
    ] {
        if let Some(address) = address {
            let prefix = if address.is_ipv4() { "ip" } else { "ipv6" };
            clauses.push((label.into(), format!("{prefix}.{side} == {address}")));
        }
    }
    let transport = if packet.tcp_flags.is_some() {
        Some("tcp")
    } else if matches!(packet.protocol.as_str(), "UDP" | "DNS" | "DHCP") {
        Some("udp")
    } else {
        None
    };
    if let Some(transport) = transport {
        clauses.push(("Transport protocol".into(), transport.into()));
        for (label, side, port) in [
            ("Source port", "srcport", packet.src_port),
            ("Destination port", "dstport", packet.dst_port),
        ] {
            if let Some(port) = port {
                clauses.push((label.into(), format!("{transport}.{side} == {port}")));
            }
        }
    }
    clauses
}

fn display_clause_menu(ui: &mut egui::Ui, clause: &str, filter: &mut String) {
    for (label, join, exclude) in [
        ("Apply as filter", None, false),
        ("Add AND", Some("&&"), false),
        ("Add OR", Some("||"), false),
        ("Exclude", Some("&&"), true),
    ] {
        if ui.button(label).clicked() {
            let clause = if exclude {
                format!("!({clause})")
            } else {
                clause.to_owned()
            };
            *filter = join.filter(|_| !filter.trim().is_empty()).map_or_else(
                || clause.clone(),
                |join| format!("({filter}) {join} ({clause})"),
            );
            ui.close_menu();
        }
    }
}

fn capture_row_values(
    capture: &NetworkCapture,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
    live: bool,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let state = if live {
        "live"
    } else if capture.stopped_ms.is_some() {
        "completed"
    } else {
        "unfinished"
    };
    let number = |value: Option<u64>| {
        value.map_or(RowValue::Missing, |value| {
            RowValue::Number(i128::from(value))
        })
    };
    let name = annotation
        .filter(|value| !value.name.is_empty())
        .map_or_else(
            || {
                if live {
                    "Live capture".into()
                } else {
                    format_date(capture.started_ms / 1000)
                }
            },
            |value| value.name.clone(),
        );
    let mut row = crate::query::label_row(
        &capture.id,
        annotation.map_or("", |value| &value.name),
        &capture.file.display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("entry.kind", RowValue::Text("network".into())),
        ("entry.state", RowValue::Text(state.into())),
        (
            "entry.complete",
            RowValue::Bool(capture.stopped_ms.is_some()),
        ),
        ("entry.time_ms", number(Some(capture.started_ms))),
        ("entry.size", number(capture.bytes)),
        ("boot.id", RowValue::Text(capture.boot_id.clone())),
        ("name", RowValue::Text(name)),
        ("state", RowValue::Text(state.into())),
        ("boot", RowValue::Text(capture.boot_id.clone())),
        ("start", number(Some(capture.started_ms))),
        ("stop", number(capture.stopped_ms)),
        ("packets", number(capture.packets)),
        ("size", number(capture.bytes)),
        ("whole_boot", RowValue::Bool(capture.whole_boot)),
    ]);
    row
}

/// Capture identity is stable when a recording folder is copied or moved.
/// Prefer the current folder, then merge retained folders without duplicate
/// roots or captures. Whole-boot pcaps remain part of the same history.
fn capture_history(current: Option<&Path>, retained: &[PathBuf]) -> Vec<NetworkCapture> {
    let mut roots = HashSet::new();
    let mut identities = HashSet::new();
    let mut captures = Vec::new();
    for root in current
        .into_iter()
        .chain(retained.iter().map(PathBuf::as_path))
    {
        let identity = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if !roots.insert(identity) {
            continue;
        }
        captures.extend(network::list_captures(root).into_iter().filter(|capture| {
            identities.insert((
                capture.boot_id.clone(),
                capture.id.clone(),
                capture.whole_boot,
            ))
        }));
    }
    captures.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
            .then_with(|| b.boot_id.cmp(&a.boot_id))
    });
    captures
}

/// Native quick search, separate from the external display-filter grammar.
#[derive(Clone, Debug, PartialEq)]
enum Filter {
    All,
    Port(u16),
    Address(IpAddr),
    Endpoint(IpAddr, u16),
    Protocol(String),
    Text(String),
}

impl Filter {
    fn parse(text: &str) -> Filter {
        let text = text.trim();
        if text.is_empty() {
            return Filter::All;
        }
        let lower = text.to_lowercase();
        if let Some(port) = lower
            .strip_prefix("port ")
            .and_then(|p| p.trim().parse().ok())
        {
            return Filter::Port(port);
        }
        if let Some(address) = lower
            .strip_prefix("ip ")
            .or_else(|| lower.strip_prefix("host "))
            .and_then(|a| a.trim().parse().ok())
        {
            return Filter::Address(address);
        }
        if let Some(protocol) = lower.strip_prefix("proto ") {
            return Filter::Protocol(protocol.trim().into());
        }
        if let Ok(endpoint) = text.parse::<SocketAddr>() {
            return Filter::Endpoint(endpoint.ip(), endpoint.port());
        }
        if let Ok(address) = text.parse() {
            return Filter::Address(address);
        }
        Filter::Text(lower)
    }

    fn matches(&self, packet: &NetworkPacket) -> bool {
        match self {
            Filter::All => true,
            Filter::Port(port) => packet.src_port == Some(*port) || packet.dst_port == Some(*port),
            Filter::Address(address) => {
                packet.src_ip == Some(*address) || packet.dst_ip == Some(*address)
            }
            Filter::Endpoint(address, port) => {
                (packet.src_ip == Some(*address) && packet.src_port == Some(*port))
                    || (packet.dst_ip == Some(*address) && packet.dst_port == Some(*port))
            }
            Filter::Protocol(protocol) => packet.protocol.to_lowercase().contains(protocol),
            Filter::Text(needle) => [
                &packet.source,
                &packet.destination,
                &packet.protocol,
                &packet.info,
            ]
            .iter()
            .any(|text| text.to_lowercase().contains(needle)),
        }
    }
}

/// Packets per port, address and protocol, most used first.
#[derive(Default)]
struct Counts {
    ports: Vec<(u16, usize)>,
    addresses: Vec<(IpAddr, usize)>,
    protocols: Vec<(String, usize)>,
}

fn counts(packets: &[NetworkPacket]) -> Counts {
    fn sorted<K: Ord>(map: HashMap<K, usize>) -> Vec<(K, usize)> {
        let mut entries: Vec<_> = map.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }
    let (mut ports, mut addresses, mut protocols) = (
        HashMap::new(),
        HashMap::new(),
        HashMap::<&str, usize>::new(),
    );
    for packet in packets {
        // A packet counts once for a value it carries on both sides.
        for port in [
            packet.src_port,
            packet.dst_port.filter(|p| Some(*p) != packet.src_port),
        ]
        .into_iter()
        .flatten()
        {
            *ports.entry(port).or_default() += 1;
        }
        for address in [
            packet.src_ip,
            packet.dst_ip.filter(|a| Some(*a) != packet.src_ip),
        ]
        .into_iter()
        .flatten()
        {
            *addresses.entry(address).or_default() += 1;
        }
        *protocols.entry(packet.protocol.as_str()).or_default() += 1;
    }
    Counts {
        ports: sorted(ports),
        addresses: sorted(addresses),
        protocols: sorted(protocols)
            .into_iter()
            .map(|(protocol, count)| (protocol.to_owned(), count))
            .collect(),
    }
}

/// The row color of a packet, by the first matching rule.
fn packet_color(packet: &NetworkPacket) -> Option<PacketColor> {
    if let Some(flags) = packet.tcp_flags {
        if flags & network::TCP_RST != 0 {
            return Some(PacketColor::TcpReset);
        }
        if flags & (network::TCP_SYN | network::TCP_FIN) != 0 {
            return Some(PacketColor::TcpSynFin);
        }
    }
    Some(match packet.protocol.as_str() {
        "HTTP" => PacketColor::Http,
        "TLS" => PacketColor::Tls,
        "DNS" => PacketColor::Dns,
        "DHCP" => PacketColor::Dhcp,
        "ARP" => PacketColor::Arp,
        "ICMP" | "ICMPv6" => PacketColor::Icmp,
        "TCP" => PacketColor::Tcp,
        "UDP" => PacketColor::Udp,
        _ => return None,
    })
}

impl PacketList {
    fn new(path: Option<PathBuf>) -> Self {
        PacketList {
            path,
            ..PacketList::default()
        }
    }

    /// Read new packets: always for a file that is complete, about once a
    /// second while `live`.
    fn refresh(&mut self, live: bool) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let due = self.last_read.is_none_or(|last| {
            last.elapsed() >= Duration::from_secs(1) || (!live && self.more_on_disk(&path))
        });
        if !due || self.truncated {
            return;
        }
        self.last_read = Some(Instant::now());
        match network::read_page(&path, self.next_offset, self.next_number, READ_BATCH) {
            Ok(page) => {
                let more = page.packets.len() == READ_BATCH;
                self.next_offset = page.next_offset.max(self.next_offset);
                self.next_number = page.next_number.max(self.next_number);
                self.packets.extend(page.packets);
                if self.packets.len() >= MAX_PACKETS {
                    self.packets.truncate(MAX_PACKETS);
                    self.truncated = true;
                }
                self.error = None;
                if more {
                    // Keep loading on the next frame.
                    self.last_read = None;
                }
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn more_on_disk(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.len() > self.next_offset)
    }

    /// Bring the filtered rows up to date with `filter` and the packets read.
    fn filter_rows(&mut self, filter: &str) {
        let filter = filter.trim();
        let done = match &self.rows_for {
            Some((current, done)) if current == filter && *done <= self.packets.len() => *done,
            _ => {
                self.rows.clear();
                0
            }
        };
        let parsed = Filter::parse(filter);
        let packets = &self.packets;
        self.rows
            .extend((done..packets.len()).filter(|&i| parsed.matches(&packets[i])));
        self.rows_for = Some((filter.to_owned(), packets.len()));
    }

    fn counts(&mut self) -> &Counts {
        let len = self.packets.len();
        if self.counts.as_ref().is_none_or(|(done, _)| *done != len) {
            self.counts = Some((len, counts(&self.packets)));
        }
        &self.counts.as_ref().expect("counted").1
    }
}

impl NetworkView {
    pub(crate) fn open(&mut self, path: Option<PathBuf>) {
        if self.list.path != path {
            self.list = PacketList::new(path);
            self.reset_display_capture();
        }
    }

    fn reset_display_capture(&mut self) {
        if let Some(worker) = &self.display_worker {
            worker.cancel();
        }
        self.display_index = None;
        self.display_next_index = None;
        self.display_page.clear();
        self.display_page_start = 0;
        self.display_pending = false;
        self.display_requested = None;
        self.display_identity = None;
        self.display_identity_checked = None;
        self.display_error = None;
        self.display_rejected = None;
        self.display_jump = None;
        self.display_validate_selection = false;
        self.display_jump_note = None;
        self.payloads = None;
    }

    /// Select an original PCAP frame, including a frame outside the current
    /// display page. Its display filter and quick search remain applied.
    pub(crate) fn jump_to_frame(&mut self, frame_number: u64) -> Result<(), String> {
        if self.list.path.is_none() {
            return Err("open the request's PCAP capture before selecting its frame".into());
        }
        if frame_number == 0 {
            return Err("PCAP frame numbers start at 1".into());
        }
        if let Some(worker) = &self.display_worker {
            if let FieldRegistry::Unavailable(error) = worker.fields() {
                return Err(error);
            }
        }
        if self.display_index.is_none() {
            if let Some(error) = self
                .display_worker_error
                .as_ref()
                .or(self.display_error.as_ref())
            {
                return Err(format!("frame navigation is unavailable: {error}"));
            }
        }
        self.display_jump = Some(frame_number);
        self.display_validate_selection = false;
        self.display_jump_note = Some(format!("Locating frame {frame_number}…"));
        self.display_follow_live = false;
        self.list.selected = None;
        self.list.frame = None;
        self.list.layers.clear();
        self.list.field = None;
        Ok(())
    }

    pub(crate) fn loaded_packets(&self) -> &[antinomie_monitor_core::network::NetworkPacket] {
        &self.list.packets
    }

    pub(crate) fn loaded_path(&self) -> Option<&Path> {
        self.list.path.as_deref()
    }

    /// Frames aligned with the loaded packet list, up to 128 records.
    /// `None` when there is no capture or a record could not be read.
    pub(crate) fn captured_payloads(&mut self) -> (Option<Vec<Vec<u8>>>, Option<String>) {
        self.refresh_payloads();
        match &self.payloads {
            Some(cache) if !cache.frames.is_empty() => {
                (Some(cache.frames.clone()), cache.note.clone())
            }
            Some(cache) => (None, cache.note.clone()),
            None => (None, None),
        }
    }

    fn reconstruction(&self) -> Option<antinomie_monitor_core::network::Reconstruction> {
        let frames = self
            .payloads
            .as_ref()
            .filter(|cache| !cache.frames.is_empty())
            .map(|cache| cache.frames.clone())?;
        let captured: Vec<_> = self
            .list
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

    fn refresh_payloads(&mut self) {
        const LIMIT: usize = 128;
        let Some(path) = self.list.path.clone() else {
            self.payloads = None;
            return;
        };
        let offsets: Vec<u64> = self
            .list
            .packets
            .iter()
            .take(LIMIT)
            .map(|packet| packet.offset)
            .collect();
        if self
            .payloads
            .as_ref()
            .is_some_and(|cache| cache.path == path && cache.offsets == offsets)
        {
            return;
        }
        let mut frames = Vec::with_capacity(offsets.len());
        for offset in &offsets {
            match antinomie_monitor_core::network::frame(&path, *offset) {
                Ok(bytes) => frames.push(bytes),
                Err(error) => {
                    self.payloads = Some(PayloadCache {
                        path,
                        offsets,
                        frames: Vec::new(),
                        note: Some(format!("Request reconstruction is unavailable: {error}")),
                    });
                    return;
                }
            }
        }
        let note = if self.list.packets.len() > LIMIT {
            Some(format!(
                "Reconstruction uses the first {LIMIT} loaded packets, not the whole capture."
            ))
        } else if frames.is_empty() {
            Some(
                "Request reconstruction is unavailable for this view: the loaded packet list has no payload."
                    .into(),
            )
        } else {
            None
        };
        self.payloads = Some(PayloadCache {
            path,
            offsets,
            frames,
            note,
        });
    }

    /// Keep the last valid filter. A display expression that does not parse,
    /// including an unknown dotted field, does not become a text search.
    fn apply_filter(&mut self) {
        let text = self.filter.trim();
        if self.applied_filter != text
            && self
                .list
                .selected
                .as_ref()
                .is_some_and(|packet| !Filter::parse(text).matches(packet))
        {
            self.list.selected = None;
            self.list.frame = None;
            self.list.layers.clear();
            self.list.field = None;
            self.display_jump_note = Some(
                "The quick search hides the previously selected frame. Select a visible packet."
                    .into(),
            );
        }
        self.applied_filter = text.to_owned();
        self.filter_error = None;
        if self.display_index.is_some() {
            let parsed = Filter::parse(text);
            self.list.rows = self
                .display_page
                .iter()
                .enumerate()
                .filter_map(|(i, packet)| parsed.matches(packet).then_some(i))
                .collect();
            self.list.rows_for = None;
        } else {
            self.list.filter_rows(&self.applied_filter);
        }
    }

    fn refresh_display(&mut self, live: bool, ctx: &egui::Context) {
        if self.display_worker.is_none() && self.display_worker_error.is_none() {
            match PacketFilterWorker::new() {
                Ok(worker) => self.display_worker = Some(worker),
                Err(error) => self.display_worker_error = Some(error),
            }
        }
        let Some(worker) = &self.display_worker else {
            return;
        };
        if let Some(event) = worker.poll() {
            match event {
                PacketFilterEvent::Evaluated {
                    generation,
                    identity,
                    expression,
                    result,
                } if generation == self.display_generation
                    && self
                        .display_requested
                        .as_ref()
                        .is_some_and(|(requested, query, _)| {
                            requested == &identity && query == &expression
                        }) =>
                {
                    self.display_pending = false;
                    match result {
                        Ok(index) => {
                            remember_filter(&mut self.display_history, &expression);
                            if self
                                .display_identity
                                .as_ref()
                                .is_some_and(|current| identity.permits_append(current))
                            {
                                let changed = self
                                    .display_index
                                    .as_ref()
                                    .is_none_or(|prior| prior.expression != expression);
                                let page_start = if live
                                    && self.display_follow_live
                                    && self.list.selected.is_none()
                                {
                                    index.matching_count.saturating_sub(1) / PAGE_SIZE as u64
                                        * PAGE_SIZE as u64
                                } else if changed {
                                    0
                                } else {
                                    self.display_page_start.min(
                                        index.matching_count.saturating_sub(1) / PAGE_SIZE as u64
                                            * PAGE_SIZE as u64,
                                    )
                                };
                                self.display_generation =
                                    worker.request_page(Arc::clone(&index), page_start);
                                self.display_pending = true;
                                self.display_next_index = Some(index);
                                if expression == self.display_filter.trim() {
                                    self.display_error = None;
                                    self.display_rejected = None;
                                }
                            }
                        }
                        Err(error) => {
                            self.display_error = Some(error);
                            self.display_rejected = Some(expression);
                        }
                    }
                }
                PacketFilterEvent::Page {
                    generation,
                    start,
                    result,
                } if generation == self.display_generation => {
                    self.display_pending = false;
                    match result {
                        Ok(packets) => {
                            self.display_page = packets;
                            self.display_page_start = start;
                            if let Some(index) = self.display_next_index.take() {
                                if self
                                    .display_index
                                    .as_ref()
                                    .is_some_and(|prior| prior.expression != index.expression)
                                {
                                    self.display_jump =
                                        self.list.selected.as_ref().map(|packet| packet.number);
                                    self.display_validate_selection = self.display_jump.is_some();
                                }
                                self.display_index = Some(index);
                            }
                            self.list.rows_for = None;
                        }
                        Err(error) => self.display_error = Some(error),
                    }
                }
                PacketFilterEvent::Frame {
                    generation,
                    number,
                    result,
                } if generation == self.display_generation => {
                    self.display_pending = false;
                    match result {
                        Ok((packet, position)) => {
                            if self.display_validate_selection && position.is_none() {
                                self.list.selected = None;
                                self.list.frame = None;
                                self.list.layers.clear();
                                self.list.field = None;
                                self.display_validate_selection = false;
                                self.display_jump_note = Some(format!("The display filter hides frame {number}. Select a visible packet."));
                            } else {
                                self.display_validate_selection = false;
                                self.list.selected = Some(packet.clone());
                                self.list.frame = None;
                                self.list.field = None;
                                self.display_jump_note = if position.is_none() {
                                    Some(format!("Frame {number} is selected in Details and hidden by the current display filter."))
                                } else if !Filter::parse(&self.filter).matches(&packet) {
                                    Some(format!("Frame {number} is selected in Details and hidden by the current quick search."))
                                } else {
                                    Some(format!("Selected frame {number}"))
                                };
                                if let (Some(position), Some(index)) =
                                    (position, &self.display_index)
                                {
                                    let start = position / PAGE_SIZE as u64 * PAGE_SIZE as u64;
                                    if start != self.display_page_start {
                                        self.display_generation =
                                            worker.request_page(Arc::clone(index), start);
                                        self.display_pending = true;
                                    }
                                }
                            }
                        }
                        Err(error) => self.display_jump_note = Some(error),
                    }
                }
                _ => {}
            }
        }
        if !self.display_pending {
            if let (Some(number), Some(index)) = (self.display_jump, &self.display_index) {
                self.display_jump = None;
                self.display_generation = worker.request_frame(Arc::clone(index), number);
                self.display_pending = true;
            }
        }
        if self
            .display_identity_checked
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.display_identity_checked = Some(Instant::now());
            if let Some(path) = &self.list.path {
                match CaptureIdentity::read(path) {
                    Ok(identity) => {
                        if self
                            .display_identity
                            .as_ref()
                            .is_some_and(|previous| !previous.permits_append(&identity))
                        {
                            worker.cancel();
                            self.display_pending = false;
                            self.display_index = None;
                            self.display_next_index = None;
                            self.display_page.clear();
                            self.display_requested = None;
                            self.list.selected = None;
                            self.list.frame = None;
                            self.list.packets.clear();
                            self.list.next_offset = 0;
                            self.list.next_number = 0;
                            self.list.truncated = false;
                            self.list.rows_for = None;
                            self.list.counts = None;
                            self.list.last_read = None;
                            self.payloads = None;
                        }
                        self.display_identity = Some(identity);
                    }
                    Err(error) => {
                        self.display_error = Some(error);
                        worker.cancel();
                        self.display_pending = false;
                    }
                }
            }
        }
        if matches!(worker.fields(), FieldRegistry::Ready(_))
            && !self.display_pending
            && self
                .display_edited
                .is_none_or(|at| at.elapsed() >= Duration::from_millis(350))
        {
            if let Some(identity) = self
                .display_identity
                .as_ref()
                .filter(|identity| identity.file_size >= 24)
            {
                let expression = self.display_filter.trim().to_owned();
                // Invalid edited expressions are only retried on a new edit. Live
                // updates continue evaluating the prior valid expression instead.
                if self.display_rejected.as_deref() == Some(expression.as_str())
                    && self.display_index.is_none()
                {
                    return;
                }
                let expression = if self.display_rejected.as_deref() == Some(expression.as_str()) {
                    self.display_index
                        .as_ref()
                        .map_or(expression.clone(), |index| index.expression.clone())
                } else {
                    expression
                };
                let request = (identity.clone(), expression.clone(), live);
                if self.display_requested.as_ref() != Some(&request) {
                    self.display_generation = worker.request(identity.clone(), expression, live);
                    self.display_requested = Some(request);
                    self.display_pending = true;
                }
            }
        }
        if self.display_pending || matches!(worker.fields(), FieldRegistry::Loading) {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if self.display_jump.is_some() && self.display_index.is_none() && !self.display_pending {
            let error = match worker.fields() {
                FieldRegistry::Unavailable(error) => Some(error),
                _ => self.display_error.clone(),
            };
            if let Some(error) = error {
                self.display_jump = None;
                self.display_jump_note = Some(format!("frame navigation is unavailable: {error}"));
            }
        }
        if let Some(at) = self
            .display_edited
            .filter(|at| at.elapsed() < Duration::from_millis(350))
        {
            ctx.request_repaint_after(Duration::from_millis(350).saturating_sub(at.elapsed()));
        }
    }

    fn scan(&mut self, recordings: Option<&Path>, recording_roots: &[PathBuf]) {
        self.captures = capture_history(recordings, recording_roots);
        self.captures_for = Some((recordings.map(Path::to_path_buf), recording_roots.to_vec()));
    }

    /// Draw the panel.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        cx: NetworkContext<'_>,
    ) -> Option<NetworkAction> {
        let active = cx
            .active
            .map(|capture| (capture.id.clone(), capture.file.clone()));
        if self
            .captures_for
            .as_ref()
            .is_none_or(|(current, retained)| {
                current.as_deref() != cx.recordings || retained != cx.recording_roots
            })
        {
            // Another VM: show its running capture, else its newest one.
            self.scan(cx.recordings, cx.recording_roots);
            let first = active
                .as_ref()
                .map(|(_, file)| file.clone())
                .or_else(|| self.captures.first().map(|capture| capture.file.clone()));
            self.list = PacketList::new(first);
            self.reset_display_capture();
            self.seen_active = active.clone();
        } else if self.seen_active != active {
            // A capture started or stopped: list it, and show a new one live.
            self.scan(cx.recordings, cx.recording_roots);
            if let Some((_, file)) = &active {
                self.open(Some(file.clone()));
            }
            self.seen_active = active.clone();
        }
        let is_live =
            active.is_some() && self.list.path.as_ref() == active.as_ref().map(|(_, file)| file);
        self.refresh_display(is_live, ui.ctx());
        if self.display_index.is_none() {
            self.list.refresh(is_live);
        }
        if active.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
        self.apply_filter();

        let mut action = None;
        self.toolbar(ui, is_live, &cx);
        if !cx.nat
            && cx.active.is_none()
            && (cx.running || cx.recordings.is_some() || self.list.path.is_some())
        {
            ui.add(egui::Label::new(RichText::new(
                "Disconnected: network capture is unavailable. Choose Isolated or NAT in VM settings. Saved captures can still be inspected.",
            ).color(theme::warn())).wrap());
        }
        if !self.hide_list {
            egui::SidePanel::left("network_captures")
                .resizable(true)
                .default_width(230.0)
                .width_range(170.0..=480.0)
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    right: 8,
                    ..Default::default()
                }))
                .show_inside(ui, |ui| {
                    action = self.capture_list(ui, &cx);
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 10,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.packets(ui, is_live, &cx));
        action
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(egui_phosphor::regular::SIDEBAR_SIMPLE)
                        .frame(false)
                        .selected(!self.hide_list),
                )
                .on_hover_text(if self.hide_list {
                    "Show the capture list"
                } else {
                    "Hide the capture list"
                })
                .clicked()
            {
                self.hide_list = !self.hide_list;
            }
            let open = self.list.path.as_ref().map(|path| {
                self.captures
                    .iter()
                    .find(|capture| &capture.file == path)
                    .map_or_else(
                        || path.display().to_string(),
                        |capture| capture_title(capture, is_live),
                    )
            });
            match open {
                Some(open) => {
                    if is_live {
                        ui.colored_label(theme::error(), egui_phosphor::regular::RECORD);
                    }
                    ui.label(RichText::new(open).strong().color(theme::heading()));
                }
                None => {
                    ui.colored_label(theme::muted(), "No capture open");
                }
            }
            ui.separator();
            ui.menu_button(
                format!("{} Colors", egui_phosphor::regular::PALETTE),
                |ui| {
                    for color in PacketColor::ALL {
                        ui.horizontal(|ui| {
                            let (rect, _) = ui
                                .allocate_exact_size(egui::vec2(28.0, 14.0), egui::Sense::hover());
                            ui.painter().rect_filled(rect, 2.0, color.tint());
                            ui.label(color.label());
                        });
                    }
                },
            )
            .response
            .on_hover_text("Row colors by protocol, as in Wireshark");
            if let Some(path) = self.list.path.clone() {
                self.wireshark_button(ui, &path, is_live);
            }
            if let Some(filter) = self.quick_filters(ui) {
                self.filter = filter;
            }
            ui.separator();
            ui.label(RichText::new(egui_phosphor::regular::FUNNEL).color(theme::muted()));
            let width = ui.available_width().max(180.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text(if self.display_index.is_some() { "Quick search on this page" } else { "Quick search loaded packets" })
                    .desired_width(width),
            ).on_hover_text("Native quick search: port N, ip ADDRESS, ADDRESS:PORT, proto NAME, or column text. Quick search affects only the loaded page; use the display filter below for the whole capture.");
        });
        let registry = self.display_worker.as_ref().map(PacketFilterWorker::fields);
        let mut edited = false;
        ui.horizontal(|ui| {
            ui.label("Display filter");
            let width = ui.available_width().max(100.0);
            match &registry {
                Some(FieldRegistry::Ready(fields)) => {
                    ui.data_mut(|data| data.insert_temp(ui.id().with(("filter-edit", "Wireshark expression for the whole capture")).with("history"), self.display_history.clone()));
                    let schema = fields.iter().map(|field| crate::query::FieldSpec {
                        name: &field.name,
                        kind: &field.kind,
                        detail: &field.description,
                    });
                    edited = crate::query::filter_edit_packet_field_iter(
                        ui, &mut self.display_filter, "Wireshark expression for the whole capture", width, schema, &[],
                    ).on_hover_text("Evaluated by installed TShark with two-pass Wireshark display-filter semantics. Field suggestions come from that installation. Example: tcp.port in {80, 443} && ip.addr == 10.0.2.15").changed();
                }
                _ => {
                    ui.add_enabled(false, egui::TextEdit::singleline(&mut self.display_filter)
                        .hint_text("Install tshark to enable display filters").desired_width(width));
                }
            }
        });
        if edited {
            if let Some(worker) = &self.display_worker {
                worker.cancel();
            }
            self.display_pending = false;
            self.display_next_index = None;
            self.display_edited = Some(Instant::now());
            self.display_requested = None;
            self.display_rejected = None;
            self.display_error = None;
            ui.ctx().request_repaint_after(Duration::from_millis(350));
        }
        let fields = capture_fields();
        let captures: Vec<_> = cx
            .active
            .into_iter()
            .chain(
                self.captures
                    .iter()
                    .filter(|capture| cx.active.is_none_or(|active| active.file != capture.file)),
            )
            .cloned()
            .collect();
        let annotations: Vec<_> = captures
            .iter()
            .map(|capture| {
                crate::evidence::annotation(ui, &capture.file.with_extension("metadata"))
            })
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|annotation| annotation.tags.iter().cloned())
            .collect();
        egui::CollapsingHeader::new("Record filter")
            .id_salt("network_record_filter")
            .show(ui, |ui| {
                ui.data_mut(|data| {
                    data.insert_temp(
                        ui.id()
                            .with(("filter-edit", "Filter capture name, tags and metadata"))
                            .with("history"),
                        self.record_history.clone(),
                    )
                });
                crate::query::filter_edit_fields(
                    ui,
                    &mut self.record_filter,
                    "Filter capture name, tags and metadata",
                    ui.available_width(),
                    &fields,
                    &tags,
                );
                ui.weak("Record metadata AND packet display filter. Tags belong to the capture.");
            });
        let record_filter =
            crate::query::applied_table(ui, &self.record_filter, &fields, "network-records");
        if crate::query::compile_table(&self.record_filter, &fields)
            .error
            .is_none()
        {
            remember_filter(&mut self.record_history, &self.record_filter);
        }
        self.record_shown = captures
            .iter()
            .zip(annotations.iter())
            .filter_map(|(capture, annotation)| {
                let live = cx.active.is_some_and(|active| active.file == capture.file);
                record_filter
                    .keep_table(&capture_row_values(capture, annotation.as_ref(), live))
                    .then(|| capture.file.clone())
            })
            .collect();
        if self.list.path.as_ref().is_some_and(|path| {
            captures.iter().any(|capture| &capture.file == path)
                && !self.record_shown.contains(path)
        }) {
            self.open(None);
            self.display_jump_note = Some("The record filter hides the selected capture. Select another capture or clear the record filter.".into());
        }
        if !self.record_filter.trim().is_empty() {
            ui.weak(format!(
                "{} of {} captures match the record filter",
                self.record_shown.len(),
                captures.len()
            ));
        }
        match registry {
            Some(FieldRegistry::Loading) => {
                ui.colored_label(theme::muted(), "Loading installed TShark fields…");
            }
            Some(FieldRegistry::Unavailable(error)) => {
                ui.colored_label(theme::warn(), error);
            }
            _ => {}
        }
        if let Some(error) = &self.display_worker_error {
            ui.colored_label(theme::warn(), error);
        }
        if let Some(error) = &self.display_error {
            ui.colored_label(theme::warn(), error);
        }
        if let Some(note) = &self.display_jump_note {
            ui.colored_label(theme::muted(), note);
        }
        if self.display_pending {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.colored_label(
                    theme::muted(),
                    "Applying display filter… Previous result stays visible.",
                );
            });
        }
        if let Some(index) = &self.display_index {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    theme::blue(),
                    format!(
                        "{} of {} packets · Display filter: {}",
                        index.matching_count,
                        index.packet_count(),
                        if index.expression.is_empty() {
                            "(all)"
                        } else {
                            &index.expression
                        }
                    ),
                );
                if !self.display_filter.is_empty()
                    && ui.small_button("Clear display filter").clicked()
                {
                    self.display_filter.clear();
                    if let Some(worker) = &self.display_worker {
                        worker.cancel();
                    }
                    self.display_pending = false;
                    self.display_next_index = None;
                    self.display_edited = None;
                    self.display_requested = None;
                    self.display_rejected = None;
                    self.display_error = None;
                    ui.ctx().request_repaint();
                }
            });
            if index.complete_extent() < index.identity().file_size {
                ui.colored_label(theme::muted(), "The current display result includes complete records; an unfinished live record is waiting for more data.");
            }
        }
        if let Some(error) = &self.filter_error {
            ui.colored_label(theme::warn(), error);
        }
        let shown_filter = if self.filter_error.is_some() {
            self.applied_filter.trim().to_owned()
        } else {
            self.filter.trim().to_owned()
        };
        let total = if self.display_index.is_some() {
            self.display_page.len()
        } else {
            self.list.packets.len()
        };
        if !shown_filter.is_empty() || cx.pending {
            ui.horizontal_wrapped(|ui| {
                if cx.pending {
                    ui.add(egui::Spinner::new());
                    ui.colored_label(theme::muted(), "Waiting for the VM...");
                }
                if !shown_filter.is_empty() {
                    ui.colored_label(
                        theme::blue(),
                        format!(
                            "Quick search {shown_filter}: {} of {total} loaded packets",
                            self.list.rows.len()
                        ),
                    );
                    if ui.small_button("Clear filter").clicked() {
                        self.filter.clear();
                    }
                }
            });
        }
    }

    /// Port, address and protocol lists with their packet counts; choosing
    /// one returns its filter.
    fn quick_filters(&mut self, ui: &mut egui::Ui) -> Option<String> {
        let mut chosen = None;
        let page_counts = self
            .display_index
            .as_ref()
            .map(|_| counts(&self.display_page));
        let counts = page_counts.as_ref().unwrap_or_else(|| self.list.counts());
        let empty = counts.protocols.is_empty();
        let mono = theme::mono(ui.style().text_styles[&egui::TextStyle::Body].size - 1.0);
        // A value and its packet count, as one menu entry.
        let entry = |ui: &mut egui::Ui, value: String, color: egui::Color32, count: usize| {
            let mut job = egui::text::LayoutJob::default();
            job.append(&value, 0.0, text_format(mono.clone(), color));
            job.append(
                &format!(" ({count})"),
                0.0,
                text_format(mono.clone(), theme::muted()),
            );
            ui.selectable_label(false, job).clicked()
        };
        ui.add_enabled_ui(!empty, |ui| {
            egui::ComboBox::from_id_salt("network_ports")
                .selected_text("Ports")
                .width(90.0)
                .height(420.0)
                .show_ui(ui, |ui| {
                    for (port, count) in counts.ports.iter().take(QUICK_ENTRIES) {
                        if entry(
                            ui,
                            format!("Port {port}"),
                            theme::value(ValueKind::Number),
                            *count,
                        ) {
                            chosen = Some(format!("port {port}"));
                        }
                    }
                });
            egui::ComboBox::from_id_salt("network_addresses")
                .selected_text("Addresses")
                .width(110.0)
                .height(420.0)
                .show_ui(ui, |ui| {
                    for (address, count) in counts.addresses.iter().take(QUICK_ENTRIES) {
                        if entry(ui, address.to_string(), theme::text(), *count) {
                            chosen = Some(format!("ip {address}"));
                        }
                    }
                });
            egui::ComboBox::from_id_salt("network_protocols")
                .selected_text("Protocols")
                .width(100.0)
                .height(420.0)
                .show_ui(ui, |ui| {
                    for (protocol, count) in counts.protocols.iter().take(QUICK_ENTRIES) {
                        if entry(ui, protocol.clone(), protocol_color(protocol), *count) {
                            chosen = Some(format!("proto {protocol}"));
                        }
                    }
                });
        });
        chosen
    }

    fn wireshark_button(&mut self, ui: &mut egui::Ui, path: &Path, is_live: bool) {
        let wireshark = which("wireshark");
        let clicked = ui
            .add_enabled(
                wireshark.is_some(),
                egui::Button::new(format!(
                    "{} Open in Wireshark",
                    egui_phosphor::regular::ARROW_SQUARE_OUT
                )),
            )
            .on_disabled_hover_text("Wireshark is not installed")
            .on_hover_text(path.display().to_string())
            .clicked();
        if let (true, Some(wireshark)) = (clicked, wireshark) {
            // A live capture streams into Wireshark as it grows; a finished
            // one opens as it is.
            let spawned = if is_live {
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg("tail -c +1 -f \"$1\" | \"$2\" -k -i -")
                    .arg("antinomie-wireshark")
                    .arg(path)
                    .arg(&wireshark)
                    .spawn()
            } else {
                std::process::Command::new(wireshark)
                    .arg("-r")
                    .arg(path)
                    .spawn()
            };
            if let Err(error) = spawned {
                self.list.error = Some(format!("Wireshark: {error}"));
            }
        }
    }

    /// The running capture first, then earlier ones; a click opens one.
    fn capture_list(
        &mut self,
        ui: &mut egui::Ui,
        cx: &NetworkContext<'_>,
    ) -> Option<NetworkAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            theme::section(ui, "Captures");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false))
                    .on_hover_text("Refresh the list")
                    .clicked()
                {
                    self.scan(cx.recordings, cx.recording_roots);
                }
            });
        });
        if let Some(active) = cx.active {
            let button = ui
                .add_enabled(
                    !cx.pending,
                    egui::Button::new(format!("{} Stop capture", egui_phosphor::regular::STOP))
                        .min_size(egui::vec2(ui.available_width(), 0.0)),
                )
                .on_hover_text(format!("Stop writing {}", active.file.display()));
            if button.clicked() {
                action = Some(NetworkAction::Stop);
            }
        } else {
            let why = if !cx.running {
                Some("Start the VM to capture its network traffic")
            } else if !cx.nat {
                Some("Choose Isolated or NAT network in the VM settings and restart it")
            } else {
                None
            };
            let button = ui
                .add_enabled(
                    why.is_none() && !cx.pending,
                    egui::Button::new(format!("{} Start capture", egui_phosphor::regular::RECORD))
                        .min_size(egui::vec2(ui.available_width(), 0.0)),
                )
                .on_hover_text(
                    "Record every packet of the VM's network interface, outside the guest",
                )
                .on_disabled_hover_text(why.unwrap_or("Waiting for the VM"));
            if button.clicked() {
                action = Some(NetworkAction::Start);
            }
        }
        ui.add_space(2.0);
        let mut open = None;
        let font_size = cx.font_size;
        egui::ScrollArea::vertical()
            .id_salt("network_capture_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(active) = cx
                    .active
                    .filter(|capture| self.record_shown.contains(&capture.file))
                {
                    let selected = self.list.path.as_ref() == Some(&active.file);
                    let loaded = selected.then_some(self.list.packets.len());
                    let title = crate::evidence::title(
                        ui,
                        &active.file.with_extension("metadata"),
                        &format!("{} Live capture", egui_phosphor::regular::RECORD),
                    );
                    let response = capture_row(
                        ui,
                        selected,
                        (&title, theme::error()),
                        &capture_detail(active, true, loaded),
                        font_size,
                    )
                    .on_hover_text(active.file.display().to_string());
                    response.context_menu(|ui| {
                        self.capture_menu(ui, active, true);
                    });
                    if response.clicked() {
                        open = Some(active.file.clone());
                    }
                }
                let earlier: Vec<_> = self
                    .captures
                    .iter()
                    .filter(|capture| {
                        Some(capture.id.as_str()) != cx.active.map(|a| a.id.as_str())
                            && self.record_shown.contains(&capture.file)
                    })
                    .cloned()
                    .collect();
                for capture in &earlier {
                    let selected = self.list.path.as_ref() == Some(&capture.file);
                    // The date in UTC; the zone is in the hover text.
                    let started = format_date(capture.started_ms / 1000);
                    let title = crate::evidence::title(
                        ui,
                        &capture.file.with_extension("metadata"),
                        started.trim_end_matches(" UTC"),
                    );
                    let response = capture_row(
                        ui,
                        selected,
                        (&title, theme::text()),
                        &capture_detail(capture, false, None),
                        font_size,
                    )
                    .on_hover_text(format!(
                        "Started {started}\nBoot {}\n{}",
                        capture.boot_id,
                        capture.file.display()
                    ));
                    response.context_menu(|ui| {
                        self.capture_menu(ui, capture, false);
                    });
                    if response.clicked() {
                        open = Some(capture.file.clone());
                    }
                }
                if cx.active.is_none() && earlier.is_empty() {
                    ui.colored_label(theme::muted(), "No network captures for this VM");
                }
            });
        if let Some(path) = open {
            self.open(Some(path));
        }
        action
    }

    fn capture_menu(&mut self, ui: &mut egui::Ui, capture: &NetworkCapture, live: bool) {
        let directory = capture.file.with_extension("metadata");
        crate::evidence::menu(ui, &directory);
        if ui.button("Open PCAP directory").clicked() {
            if let Some(parent) = capture.file.parent() {
                crate::evidence::reveal(ui.ctx(), parent);
            }
            ui.close_menu();
        }
        let annotation = crate::evidence::annotation(ui, &directory);
        for (field, value) in capture_row_values(capture, annotation.as_ref(), live) {
            ui.menu_button(field, |ui| {
                crate::query::value_menu(ui, field, &value, &mut self.record_filter);
            });
        }
    }

    fn packets(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
        if let Some(path) = self.list.path.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.label(crate::evidence::title(
                    ui,
                    &path.with_extension("metadata"),
                    &path.file_name().unwrap_or_default().to_string_lossy(),
                ));
                if ui.button("Open PCAP directory").clicked() {
                    if let Some(parent) = path.parent() {
                        crate::evidence::reveal(ui.ctx(), parent);
                    }
                }
            });
        }
        self.refresh_payloads();
        if let Some(rebuilt) = self.reconstruction() {
            for note in &rebuilt.notes {
                ui.colored_label(theme::muted(), note);
            }
            ui.colored_label(
                theme::muted(),
                format!(
                    "{} HTTP/1 requests, {} DNS queries, {} retransmissions dropped. HTTPS segments seen: {}. HTTP/2 prefaces seen: {}.",
                    rebuilt.http.len(),
                    rebuilt.dns.len(),
                    rebuilt.retransmissions_dropped,
                    rebuilt.https_segments,
                    rebuilt.http2_prefaces,
                ),
            );
        } else if let Some(note) = self.payloads.as_ref().and_then(|cache| cache.note.clone()) {
            ui.colored_label(theme::muted(), note);
        }
        if self.list.path.is_none() {
            empty_state(
                ui,
                if !cx.nat {
                    "The VM is disconnected. With Isolated or NAT network, a capture \
                     records every packet of its network interface, outside the guest."
                } else if self.captures.is_empty() && cx.active.is_none() {
                    "No network captures yet. Start a capture to record every packet of \
                     the VM's network interface, outside the guest."
                } else {
                    "Select a capture"
                },
            );
            return;
        }
        if let Some(error) = &self.list.error {
            ui.colored_label(theme::warn(), error);
        }
        if self.list.truncated && self.display_index.is_none() {
            ui.colored_label(
                theme::warn(),
                format!(
                    "Showing the first {MAX_PACKETS} packets; open the capture in Wireshark for all."
                ),
            );
        }
        if let Some(index) = self.display_index.clone() {
            let mut requested_page = None;
            let page_count = index.matching_count.div_ceil(PAGE_SIZE as u64).max(1);
            let current_page = self.display_page_start / PAGE_SIZE as u64 + 1;
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled_ui(!self.display_pending, |ui| {
                    if ui
                        .add_enabled(current_page > 1, egui::Button::new("Previous page"))
                        .clicked()
                    {
                        requested_page = Some(current_page - 1);
                    }
                    let mut page = current_page;
                    ui.label("Page");
                    if ui
                        .add(egui::DragValue::new(&mut page).range(1..=page_count))
                        .changed()
                    {
                        requested_page = Some(page);
                    }
                    ui.label(format!("of {page_count}"));
                    if ui
                        .add_enabled(current_page < page_count, egui::Button::new("Next page"))
                        .clicked()
                    {
                        requested_page = Some(current_page + 1);
                    }
                    ui.label(format!(
                        "{}–{} of {} matching packets",
                        if index.matching_count == 0 {
                            0
                        } else {
                            self.display_page_start + 1
                        },
                        (self.display_page_start + self.display_page.len() as u64)
                            .min(index.matching_count),
                        index.matching_count
                    ));
                });
                if is_live {
                    ui.checkbox(&mut self.display_follow_live, "Follow live");
                }
            });
            if let (Some(page), Some(worker)) = (requested_page, &self.display_worker) {
                self.display_generation = worker.request_page(index, (page - 1) * PAGE_SIZE as u64);
                self.display_pending = true;
                ui.ctx().request_repaint_after(Duration::from_millis(50));
            }
        }
        let font_size = cx.font_size;
        let mono = theme::mono(font_size - 1.0);
        // Data columns fit their monospace contents; Info gets the rest.
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let chars = |count: f32| count * char_width + 8.0;
        let start = self.display_index.as_ref().map_or_else(
            || self.list.packets.first().map_or(0, |p| p.time_us),
            |index| index.first_time_us(),
        );
        let mut clicked = None;
        let mut filter = None;
        let mut display_filter = self.display_filter.clone();
        let list = &self.list;
        let packets = if self.display_index.is_some() {
            &self.display_page
        } else {
            &list.packets
        };
        let filtering = !self.filter.trim().is_empty();
        egui::ScrollArea::horizontal()
            .id_salt("network_columns")
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt(("network_packets", self.display_page_start))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .stick_to_bottom(is_live && list.selected.is_none())
                    .max_scroll_height(f32::INFINITY)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false])
                    .column(Column::exact(chars(6.0)))
                    .column(Column::exact(chars(10.0)))
                    .column(
                        Column::initial(chars(16.0))
                            .at_least(chars(6.0))
                            .resizable(true)
                            .clip(true),
                    )
                    .column(
                        Column::initial(chars(16.0))
                            .at_least(chars(6.0))
                            .resizable(true)
                            .clip(true),
                    )
                    .column(Column::exact(chars(7.0)).clip(true))
                    .column(Column::exact(chars(6.0)))
                    .column(Column::remainder().at_least(chars(12.0)).clip(true))
                    .header(theme::row_height(font_size) + 4.0, |mut header| {
                        for label in [
                            "No.",
                            "Time",
                            "Source",
                            "Destination",
                            "Protocol",
                            "Length",
                            "Info",
                        ] {
                            header.col(|ui| {
                                ui.label(RichText::new(label).strong().color(theme::heading()));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(theme::row_height(font_size), list.rows.len(), |mut row| {
                            let index = list.rows[row.index()];
                            let packet = &packets[index];
                            let selected = list
                                .selected
                                .as_ref()
                                .is_some_and(|selected| selected.number == packet.number);
                            row.set_selected(selected);
                            let tint = packet_color(packet)
                                .filter(|_| !selected)
                                .map(PacketColor::tint);
                            let elapsed = packet.time_us.saturating_sub(start) as f64 / 1e6;
                            for column in 0..7 {
                                row.col(|ui| {
                                    // Paint the cell and half of each gap so a
                                    // tinted row reads as one band.
                                    if let Some(tint) = tint {
                                        let cell = ui.max_rect().expand2(egui::vec2(
                                            ui.spacing().item_spacing.x / 2.0,
                                            0.0,
                                        ));
                                        ui.painter().rect_filled(cell, 0.0, tint);
                                    }
                                    let set = match column {
                                        2 => address_cell(
                                            ui,
                                            &mono,
                                            &packet.source,
                                            packet.src_ip,
                                            packet.src_port,
                                        ),
                                        3 => address_cell(
                                            ui,
                                            &mono,
                                            &packet.destination,
                                            packet.dst_ip,
                                            packet.dst_port,
                                        ),
                                        4 => link(
                                            ui,
                                            RichText::new(&packet.protocol)
                                                .font(mono.clone())
                                                .color(protocol_color(&packet.protocol)),
                                            &format!("Filter by protocol {}", packet.protocol),
                                        )
                                        .then(|| format!("proto {}", packet.protocol)),
                                        6 => {
                                            ui.add(
                                                egui::Label::new(info_text(packet, font_size))
                                                    .selectable(false)
                                                    .truncate(),
                                            );
                                            None
                                        }
                                        _ => {
                                            let (text, color) = match column {
                                                0 => (packet.number.to_string(), theme::muted()),
                                                1 => (
                                                    format!("{elapsed:.6}"),
                                                    theme::value(ValueKind::Number),
                                                ),
                                                _ => (packet.length.to_string(), theme::text()),
                                            };
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(text)
                                                        .font(mono.clone())
                                                        .color(color),
                                                )
                                                .selectable(false)
                                                .truncate(),
                                            );
                                            None
                                        }
                                    };
                                    if set.is_some() {
                                        filter = set;
                                    }
                                });
                            }
                            let response = row.response();
                            if response.clicked() {
                                clicked = Some(packet.clone());
                            }
                            response.context_menu(|ui| {
                                ui.menu_button("Display filter", |ui| {
                                    for (field, clause) in packet_display_clauses(packet) {
                                        ui.menu_button(field, |ui| {
                                            display_clause_menu(ui, &clause, &mut display_filter);
                                        });
                                    }
                                });
                                if let Some(set) = filter_menu(ui, packet, filtering) {
                                    filter = Some(set);
                                    ui.close_menu();
                                }
                            });
                        });
                    });
            });
        if list.rows.is_empty() {
            ui.colored_label(
                theme::muted(),
                if packets.is_empty()
                    && self
                        .display_index
                        .as_ref()
                        .is_none_or(|index| index.packet_count() == 0)
                {
                    "No packets yet"
                } else {
                    "No packets match the filter"
                },
            );
        }
        if let Some(packet) = clicked {
            self.list.selected = Some(packet);
        }
        if let Some(set) = filter {
            self.filter = set;
        }
        if display_filter != self.display_filter {
            self.display_filter = display_filter;
            if let Some(worker) = &self.display_worker {
                worker.cancel();
            }
            self.display_pending = false;
            self.display_next_index = None;
            self.display_edited = None;
            self.display_requested = None;
            self.display_rejected = None;
            self.display_error = None;
            ui.ctx().request_repaint();
        }
    }

    /// The selected packet for the Details panel: its decoded layers on the
    /// left, its bytes on the right with the chosen field's bytes marked.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let Some(packet) = self.list.selected.clone() else {
            if let Some(note) = &self.display_jump_note {
                ui.colored_label(theme::muted(), note);
            }
            empty_state(
                ui,
                if self.list.packets.is_empty() {
                    "No packet selected. Open a capture in the Network tab, then select a \
                     packet to see its layers and bytes here."
                } else {
                    "No packet selected. Select a packet in the Network tab to see its \
                     layers and bytes here."
                },
            );
            return;
        };
        if self
            .list
            .frame
            .as_ref()
            .is_none_or(|(offset, _)| *offset != packet.offset)
        {
            if let Some(path) = &self.list.path {
                let frame = if let Some(index) = &self.display_index {
                    index.frame(packet.offset)
                } else {
                    network::frame(path, packet.offset)
                };
                self.list.layers = frame
                    .as_ref()
                    .map(|bytes| network::dissect(bytes))
                    .unwrap_or_default();
                self.list.frame = Some((packet.offset, frame));
                self.list.field = None;
            }
        }
        let start = self.display_index.as_ref().map_or_else(
            || self.list.packets.first().map_or(0, |p| p.time_us),
            |index| index.first_time_us(),
        );
        let mono = theme::mono(font_size - 1.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("Frame {}", packet.number))
                    .strong()
                    .color(theme::heading()),
            );
            ui.label(
                RichText::new(&packet.protocol)
                    .font(mono.clone())
                    .color(protocol_color(&packet.protocol)),
            );
            ui.label(info_text(&packet, font_size));
            ui.label(
                RichText::new(format!(
                    "{} bytes on the wire, {} captured · {:.6} s",
                    packet.length,
                    packet.captured,
                    packet.time_us.saturating_sub(start) as f64 / 1e6
                ))
                .color(theme::muted()),
            );
        });
        let bytes = match self.list.frame.as_ref().map(|(_, frame)| frame) {
            Some(Ok(bytes)) => bytes.clone(),
            Some(Err(error)) => {
                ui.colored_label(theme::warn(), error);
                return;
            }
            None => return,
        };
        let mut hovered = None;
        // The bytes get the width of a full hex row; the tree the rest.
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let hex_width = char_width * 74.0 + 28.0;
        let available = ui.available_width();
        egui::SidePanel::left("packet_tree")
            .resizable(true)
            .default_width((available - hex_width).max(available * 0.45))
            .width_range(160.0..=(ui.available_width() - 160.0).max(161.0))
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 6,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("packet_tree_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        hovered = layer_tree(ui, &self.list.layers, &mut self.list.field, &mono);
                    });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 6,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                let chosen = self.list.field.and_then(|(layer, field)| {
                    let layer = self.list.layers.get(layer)?;
                    Some(match field.and_then(|field| layer.fields.get(field)) {
                        Some(field) => (field.name.clone(), field.start, field.len),
                        None => (layer.name.clone(), layer.start, layer.len),
                    })
                });
                ui.horizontal(|ui| {
                    theme::section(ui, "Bytes");
                    match &chosen {
                        Some((name, start, len)) if *len > 0 => {
                            ui.label(
                                RichText::new(format!("{name}: {len} bytes at 0x{start:04x}"))
                                    .color(theme::muted()),
                            );
                        }
                        _ => {
                            ui.colored_label(theme::muted(), format!("{} bytes", bytes.len()));
                        }
                    }
                });
                let marked = chosen.map(|(_, start, len)| start..start + len);
                egui::ScrollArea::both()
                    .id_salt("packet_bytes")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(hex_job(&bytes, &mono, marked, hovered))
                                .selectable(true)
                                .extend(),
                        );
                    });
            });
    }
}

/// A two-line entry of the capture list: its title, then muted details.
pub(crate) fn capture_row(
    ui: &mut egui::Ui,
    selected: bool,
    (title, color): (&str, egui::Color32),
    detail: &str,
    font_size: f32,
) -> egui::Response {
    let small = (font_size - 2.0).max(11.0);
    let padding = egui::vec2(8.0, 5.0);
    let height = font_size + small + padding.y * 2.0 + 6.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    let fill = if selected {
        Some(ui.visuals().selection.bg_fill)
    } else if response.hovered() {
        Some(ui.visuals().widgets.hovered.weak_bg_fill)
    } else {
        None
    };
    if let Some(fill) = fill {
        ui.painter().rect_filled(rect, 4.0, fill);
    }
    let width = rect.width() - padding.x * 2.0;
    let line = |text: &str, font: egui::FontId, color: egui::Color32| {
        let mut job =
            egui::text::LayoutJob::single_section(text.to_owned(), text_format(font, color));
        job.wrap = egui::text::TextWrapping::truncate_at_width(width);
        ui.fonts(|fonts| fonts.layout_job(job))
    };
    let title = line(title, theme::mono(font_size - 1.0), color);
    let detail = line(detail, egui::FontId::proportional(small), theme::muted());
    let top = rect.min + padding;
    let title_height = title.size().y;
    ui.painter().galley(top, title, color);
    ui.painter().galley(
        top + egui::vec2(0.0, title_height + 3.0),
        detail,
        theme::muted(),
    );
    response
}

/// A muted hint centered near the top of an empty area.
fn empty_state(ui: &mut egui::Ui, text: &str) {
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(520.0);
        ui.label(
            RichText::new(egui_phosphor::regular::NETWORK)
                .size(28.0)
                .color(theme::muted()),
        );
        ui.add(egui::Label::new(RichText::new(text).color(theme::muted())).wrap());
    });
}

fn text_format(font: egui::FontId, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat::simple(font, color)
}

/// The color of a protocol name.
fn protocol_color(protocol: &str) -> egui::Color32 {
    match protocol {
        "DNS" | "DHCP" => theme::info(),
        "HTTP" => theme::good(),
        "TLS" => theme::value(ValueKind::Pointer),
        "TCP" => theme::value(ValueKind::Flags),
        "UDP" => theme::value(ValueKind::Number),
        "ARP" => theme::warn(),
        "ICMP" | "ICMPv6" => theme::value(ValueKind::Name),
        _ => theme::muted(),
    }
}

/// The Info column: TCP flags in brackets get the flag color (a reset the
/// error color).
fn info_text(packet: &NetworkPacket, font_size: f32) -> egui::text::LayoutJob {
    let font = egui::FontId::proportional(font_size);
    let mut job = egui::text::LayoutJob::default();
    let info = packet.info.as_str();
    match (info.find('['), info.find(']')) {
        (Some(open), Some(close)) if open < close => {
            let flags = &info[open..=close];
            let color = if flags.contains("RST") {
                theme::error()
            } else {
                theme::value(ValueKind::Flags)
            };
            job.append(&info[..open], 0.0, text_format(font.clone(), theme::text()));
            job.append(flags, 0.0, text_format(font.clone(), color));
            job.append(&info[close + 1..], 0.0, text_format(font, theme::text()));
        }
        _ => job.append(info, 0.0, text_format(font, theme::text())),
    }
    job
}

/// The color of a decoded field's value.
fn field_color(kind: FieldKind) -> egui::Color32 {
    theme::value(match kind {
        FieldKind::Number => ValueKind::Number,
        FieldKind::Address => ValueKind::Pointer,
        FieldKind::Flags => ValueKind::Flags,
        FieldKind::Name => ValueKind::Name,
        FieldKind::Text => ValueKind::Text,
        FieldKind::Bytes => ValueKind::Plain,
    })
}

/// The packet's layers as a collapsible tree; a click chooses a layer or a
/// field (`chosen`). Returns the byte range under the pointer.
fn layer_tree(
    ui: &mut egui::Ui,
    layers: &[PacketLayer],
    chosen: &mut Option<(usize, Option<usize>)>,
    mono: &egui::FontId,
) -> Option<std::ops::Range<usize>> {
    let mut hovered = None;
    let font_size = mono.size + 1.0;
    // Dense rows, as in Wireshark's details tree.
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.spacing_mut().button_padding.y = 1.0;
    ui.spacing_mut().interact_size.y = theme::row_height(font_size) - 2.0;
    for (index, layer) in layers.iter().enumerate() {
        let id = ui.make_persistent_id(("packet_layer", &layer.name));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                let mut job = egui::text::LayoutJob::default();
                job.append(
                    &layer.name,
                    0.0,
                    text_format(egui::FontId::proportional(font_size), theme::heading()),
                );
                if !layer.summary.is_empty() {
                    job.append(
                        &format!("  {}", layer.summary),
                        0.0,
                        text_format(egui::FontId::proportional(font_size), theme::text()),
                    );
                }
                let response = ui.selectable_label(*chosen == Some((index, None)), job);
                if response.clicked() {
                    *chosen = Some((index, None));
                }
                if response.hovered() {
                    hovered = Some(layer.start..layer.start + layer.len);
                }
            })
            .body(|ui| {
                for (field_index, field) in layer.fields.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if field.depth > 0 {
                            ui.add_space(f32::from(field.depth) * 16.0);
                        }
                        let mut job = egui::text::LayoutJob::default();
                        job.append(
                            &format!("{}: ", field.name),
                            0.0,
                            text_format(egui::FontId::proportional(font_size), theme::muted()),
                        );
                        let font = match field.kind {
                            FieldKind::Number | FieldKind::Address | FieldKind::Bytes => {
                                mono.clone()
                            }
                            _ => egui::FontId::proportional(font_size),
                        };
                        job.append(
                            &field.value,
                            0.0,
                            text_format(font, field_color(field.kind)),
                        );
                        let selected = *chosen == Some((index, Some(field_index)));
                        let response = ui.selectable_label(selected, job);
                        if response.clicked() {
                            *chosen = Some((index, Some(field_index)));
                        }
                        if response.hovered() {
                            hovered = Some(field.start..field.start + field.len);
                        }
                    });
                }
            });
    }
    hovered
}

/// A hex dump (offset, 16 bytes, text) with `marked` bytes on the selection
/// color and `hovered` ones on a fainter band.
fn hex_job(
    bytes: &[u8],
    mono: &egui::FontId,
    marked: Option<std::ops::Range<usize>>,
    hovered: Option<std::ops::Range<usize>>,
) -> egui::text::LayoutJob {
    let selection = theme::palette().selection;
    let hover = theme::line();
    let mut job = egui::text::LayoutJob::default();
    let background = |at: usize| {
        if marked.as_ref().is_some_and(|range| range.contains(&at)) {
            Some(selection)
        } else if hovered.as_ref().is_some_and(|range| range.contains(&at)) {
            Some(hover)
        } else {
            None
        }
    };
    let mut push = |text: &str, color: egui::Color32, fill: Option<egui::Color32>| {
        let mut format = text_format(mono.clone(), color);
        if let Some(fill) = fill {
            format.background = fill;
        }
        job.append(text, 0.0, format);
    };
    for (row, chunk) in bytes.chunks(16).enumerate() {
        if row > 0 {
            push("\n", theme::text(), None);
        }
        push(&format!("{:04x}  ", row * 16), theme::muted(), None);
        for column in 0..16 {
            let at = row * 16 + column;
            match chunk.get(column) {
                Some(byte) => {
                    let fill = background(at);
                    push(&format!("{byte:02x}"), theme::text(), fill);
                    // The gap is marked too when both neighbors are.
                    let gap = if column == 7 { "  " } else { " " };
                    let joined = fill.filter(|_| column < 15 && background(at + 1) == fill);
                    push(gap, theme::text(), joined);
                }
                None => push(
                    if column == 7 { "    " } else { "   " },
                    theme::text(),
                    None,
                ),
            }
        }
        push(" ", theme::text(), None);
        for (column, &byte) in chunk.iter().enumerate() {
            let printable = (0x20..0x7f).contains(&byte);
            let text = if printable { byte as char } else { '.' };
            let color = if printable {
                theme::value(ValueKind::Text)
            } else {
                theme::muted()
            };
            push(&text.to_string(), color, background(row * 16 + column));
        }
    }
    job
}

/// Text that sets a filter when clicked.
fn link(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>, hover: &str) -> bool {
    let response = ui
        .add(
            egui::Label::new(text)
                .selectable(false)
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hover);
    if response.hovered() {
        let rect = response.rect;
        ui.painter().hline(
            rect.x_range(),
            rect.bottom(),
            egui::Stroke::new(1.0_f32, theme::text()),
        );
    }
    response.clicked()
}

/// A Source or Destination cell: its address and port filter separately.
fn address_cell(
    ui: &mut egui::Ui,
    mono: &egui::FontId,
    text: &str,
    address: Option<IpAddr>,
    port: Option<u16>,
) -> Option<String> {
    ui.spacing_mut().item_spacing.x = 0.0;
    let address_text = |text: String| RichText::new(text).font(mono.clone()).color(theme::text());
    match (address, port) {
        (Some(address), Some(port)) => {
            let shown = match address {
                IpAddr::V4(_) => address.to_string(),
                IpAddr::V6(_) => format!("[{address}]"),
            };
            let by_address = link(
                ui,
                address_text(shown),
                &format!("Filter by address {address}"),
            );
            let by_port = link(
                ui,
                RichText::new(format!(":{port}"))
                    .font(mono.clone())
                    .color(theme::value(ValueKind::Number)),
                &format!("Filter by port {port}"),
            );
            if by_address {
                Some(format!("ip {address}"))
            } else {
                by_port.then(|| format!("port {port}"))
            }
        }
        (Some(address), None) => link(
            ui,
            address_text(text.to_owned()),
            &format!("Filter by address {address}"),
        )
        .then(|| format!("ip {address}")),
        _ if !text.is_empty() => link(
            ui,
            address_text(text.to_owned()),
            &format!("Filter by {text}"),
        )
        .then(|| text.into()),
        _ => None,
    }
}

/// The row's right-click menu: filters by its endpoints, ports and protocol.
fn filter_menu(ui: &mut egui::Ui, packet: &NetworkPacket, filtering: bool) -> Option<String> {
    let mut choices = Vec::new();
    for (side, text, port) in [
        ("source", &packet.source, packet.src_port),
        ("destination", &packet.destination, packet.dst_port),
    ] {
        if !text.is_empty() {
            choices.push((format!("Filter by {side} {text}"), text.clone()));
        }
        if let Some(port) = port {
            if !choices
                .iter()
                .any(|(_, filter)| *filter == format!("port {port}"))
            {
                choices.push((format!("Filter by port {port}"), format!("port {port}")));
            }
        }
    }
    choices.push((
        format!("Filter by protocol {}", packet.protocol),
        format!("proto {}", packet.protocol),
    ));
    if filtering {
        choices.push(("Clear filter".into(), String::new()));
    }
    choices
        .into_iter()
        .find_map(|(label, filter)| ui.button(label).clicked().then_some(filter))
}

/// The list's name for a capture.
fn capture_title(capture: &NetworkCapture, live: bool) -> String {
    let started = format_date(capture.started_ms / 1000);
    if live {
        format!("Live capture of {started}")
    } else if capture.whole_boot {
        format!("Whole boot of {started}")
    } else {
        started
    }
}

/// Packets, length and size of a capture; `loaded` packets of a live one.
fn capture_detail(capture: &NetworkCapture, live: bool, loaded: Option<usize>) -> String {
    let mut parts = Vec::new();
    if live {
        parts.push(format!(
            "started {}",
            format_date(capture.started_ms / 1000)
        ));
        if let Some(loaded) = loaded {
            parts.push(format!("{loaded} packets"));
        }
        return parts.join(" · ");
    }
    if capture.whole_boot {
        parts.push("Whole boot".into());
    }
    if let Some(packets) = capture.packets {
        parts.push(format!("{packets} packets"));
    }
    match capture.stopped_ms {
        Some(stopped) if !capture.whole_boot => {
            parts.push(format_duration(stopped.saturating_sub(capture.started_ms)))
        }
        Some(_) => {}
        None => parts.push("not stopped (the app ended first)".into()),
    }
    if let Some(bytes) = capture.bytes {
        parts.push(format_bytes(bytes));
    }
    parts.join(" · ")
}

fn format_duration(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0 => format!("{ms} ms"),
        1..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, seconds / 60 % 60),
    }
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|path| path.is_file())
    })
}

/// UTC date and time of Unix `seconds`.
pub(crate) fn format_date(seconds: u64) -> String {
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let days = (seconds / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_capture_warning_is_visible_while_inspecting_saved_packets() {
        for enabled in [false, true] {
            let mut view = NetworkView {
                captures_for: Some((None, vec![])),
                list: PacketList::new(Some(PathBuf::from("/tmp/missing-saved-network.pcap"))),
                ..Default::default()
            };
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut output = egui::FullOutput::default();
            for _ in 0..3 {
                output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1000.0, 700.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            view.show(
                                ui,
                                NetworkContext {
                                    active: None,
                                    recordings: None,
                                    recording_roots: &[],
                                    nat: enabled,
                                    running: true,
                                    pending: false,
                                    font_size: 16.0,
                                },
                            );
                        });
                    },
                );
            }
            let text: String = crate::app::tests::texts(&output)
                .into_iter()
                .map(|(text, _)| text)
                .collect();
            assert_eq!(
                text.contains("Disconnected: network capture is unavailable"),
                !enabled
            );
            assert!(
                view.list.path.is_some(),
                "saved capture selection is retained"
            );
        }
    }

    fn ok_filter(text: &str) -> Filter {
        Filter::parse(text)
    }

    fn packet(protocol: &str, source: &str, destination: &str) -> NetworkPacket {
        let parse = |text: &str| -> (Option<IpAddr>, Option<u16>) {
            match text.parse::<SocketAddr>() {
                Ok(endpoint) => (Some(endpoint.ip()), Some(endpoint.port())),
                Err(_) => (text.parse().ok(), None),
            }
        };
        let ((src_ip, src_port), (dst_ip, dst_port)) = (parse(source), parse(destination));
        NetworkPacket {
            source: source.into(),
            destination: destination.into(),
            protocol: protocol.into(),
            info: format!("{protocol} info"),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags: (protocol == "TCP").then_some(0x10),
            ..NetworkPacket::default()
        }
    }

    #[test]
    fn display_filter_preserves_page_selection_and_prior_result_on_error_if_tshark_installed() {
        use std::io::Write;
        if !std::process::Command::new("tshark")
            .arg("-v")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "antinomie-packet-view-{}-{stamp}.pcap",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap();
        file.write_all(&4u16.to_le_bytes()).unwrap();
        file.write_all(&[0; 8]).unwrap();
        file.write_all(&65535u32.to_le_bytes()).unwrap();
        file.write_all(&1u32.to_le_bytes()).unwrap();
        for number in 0..520u32 {
            file.write_all(&(1_700_000_000 + number).to_le_bytes())
                .unwrap();
            file.write_all(&0u32.to_le_bytes()).unwrap();
            file.write_all(&14u32.to_le_bytes()).unwrap();
            file.write_all(&14u32.to_le_bytes()).unwrap();
            file.write_all(&[0; 14]).unwrap();
        }
        drop(file);
        let original = std::fs::read(&path).unwrap();
        let ctx = egui::Context::default();
        let mut view = NetworkView::default();
        view.open(Some(path.clone()));
        view.display_filter = "frame.number > 10".into();
        let wait = |view: &mut NetworkView, error: bool| {
            let started = Instant::now();
            loop {
                view.refresh_display(false, &ctx);
                if !view.display_pending
                    && if error {
                        view.display_error.is_some()
                    } else {
                        view.display_index.is_some()
                    }
                {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "display worker timeout: {:?}",
                    view.display_error
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        wait(&mut view, false);
        assert_eq!(view.display_index.as_ref().unwrap().matching_count, 510);
        assert_eq!(view.display_page.first().unwrap().number, 11);
        assert_eq!(view.display_page.last().unwrap().number, 510);
        view.list.selected = Some(view.display_page[20].clone());
        let selected = view.list.selected.clone().unwrap();
        view.list.frame = Some((selected.offset, Ok(vec![0; 14])));
        let index = Arc::clone(view.display_index.as_ref().unwrap());
        view.display_generation = view
            .display_worker
            .as_ref()
            .unwrap()
            .request_page(index, 500);
        view.display_pending = true;
        wait(&mut view, false);
        assert_eq!(view.display_page_start, 500);
        assert_eq!(view.display_page.first().unwrap().number, 511);
        assert_eq!(view.display_page.len(), 10);
        assert_eq!(view.list.selected, Some(selected.clone()));
        assert_eq!(view.list.frame, Some((selected.offset, Ok(vec![0; 14]))));
        view.display_filter = "tcp.port in {".into();
        view.display_requested = None;
        wait(&mut view, true);
        assert_eq!(
            view.display_index.as_ref().unwrap().expression,
            "frame.number > 10"
        );
        assert_eq!(view.display_page_start, 500);
        assert_eq!(view.list.selected, Some(selected));
        view.apply_filter();
        assert_eq!(view.list.rows.len(), 10);
        view.jump_to_frame(20).unwrap();
        wait(&mut view, false);
        assert_eq!(view.list.selected.as_ref().unwrap().number, 20);
        assert_eq!(view.display_page_start, 0);
        view.jump_to_frame(520).unwrap();
        wait(&mut view, false);
        assert_eq!(view.list.selected.as_ref().unwrap().number, 520);
        assert_eq!(view.display_page_start, 500);
        view.jump_to_frame(5).unwrap();
        wait(&mut view, false);
        assert_eq!(view.list.selected.as_ref().unwrap().number, 5);
        assert!(view
            .display_jump_note
            .as_ref()
            .unwrap()
            .contains("hidden by the current display filter"));
        assert_eq!(
            view.display_index.as_ref().unwrap().expression,
            "frame.number > 10"
        );
        assert_eq!(view.display_filter, "tcp.port in {");
        assert_eq!(view.display_page_start, 500);
        view.filter = "missing-packet-text".into();
        view.apply_filter();
        assert!(view.list.selected.is_none());
        view.jump_to_frame(510).unwrap();
        view.jump_to_frame(515).unwrap();
        wait(&mut view, false);
        assert_eq!(view.list.selected.as_ref().unwrap().number, 515);
        assert!(view
            .display_jump_note
            .as_ref()
            .unwrap()
            .contains("hidden by the current quick search"));
        assert!(view.jump_to_frame(0).is_err());
        view.filter.clear();
        view.apply_filter();
        view.display_filter = "frame.number > 515".into();
        view.display_requested = None;
        view.display_rejected = None;
        wait(&mut view, false);
        assert!(view.list.selected.is_none());
        assert!(view
            .display_jump_note
            .as_ref()
            .unwrap()
            .contains("hides frame 515"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        drop(view);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn capture_record_filters_cover_annotations_partial_state_and_missing_counts() {
        use antinomie_monitor_core::annotations::Annotation;
        let capture = NetworkCapture {
            id: "capture-a".into(),
            boot_id: "boot-a".into(),
            file: PathBuf::from("/recordings/network/a.pcap"),
            started_ms: 12,
            stopped_ms: None,
            packets: None,
            bytes: None,
            whole_boot: true,
        };
        let annotation = Annotation {
            name: "First DNS query".into(),
            tags: vec!["needs review".into()],
        };
        let row = capture_row_values(&capture, Some(&annotation), false);
        let query = crate::query::compile_table("tag == \"needs review\" && name contains \"DNS\" && state == \"unfinished\" && missing(packets) && whole_boot == true", &capture_fields());
        assert!(query.error.is_none(), "{:?}", query.error);
        assert!(query.keep_table(&row));
        let zero = crate::query::compile_table("packets == 0", &capture_fields());
        assert!(!zero.keep_table(&row));
        let mut completed = capture;
        completed.stopped_ms = Some(24);
        completed.packets = Some(0);
        completed.bytes = Some(24);
        assert!(zero.keep_table(&capture_row_values(&completed, Some(&annotation), false)));
        let identity = crate::query::compile_table("entry.kind == \"network\" && boot.id == \"boot-a\" && entry.complete == true && entry.size == 24", &capture_fields());
        assert!(identity.keep_table(&capture_row_values(&completed, Some(&annotation), false)));
    }

    #[test]
    fn hex_dump_pads_short_rows_and_marks_the_chosen_bytes() {
        let bytes = b"GET / HTTP/1.1\r\nHost";
        let job = hex_job(bytes, &theme::mono(14.0), Some(4..6), None);
        let lines: Vec<_> = job.text.lines().collect();
        assert_eq!(
            lines[0],
            "0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1.."
        );
        assert!(lines[1].starts_with("0010  48 6f 73 74"));
        assert!(lines[1].ends_with("  Host"));
        // Bytes 4 and 5 ("2f", "20", the space between, "/", " ") are marked.
        let marked: String = job
            .sections
            .iter()
            .filter(|section| section.format.background == theme::palette().selection)
            .map(|section| &job.text[section.byte_range.clone()])
            .collect();
        assert_eq!(marked, "2f 20/ ");
        assert_eq!(format_date(1_791_554_943), "2026-10-09 14:09:03 UTC");
        assert_eq!(format_date(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_duration(6_404), "6 s");
        assert_eq!(format_duration(125_000), "2 min 5 s");
        assert_eq!(format_bytes(3_620), "3.5 KiB");
    }

    #[test]
    fn filters_match_ports_addresses_endpoints_protocols_and_text() {
        let dns = packet("DNS", "10.0.2.15:5353", "10.0.2.3:53");
        let http = packet("HTTP", "10.0.2.15:40000", "93.184.216.34:80");
        let ping = packet("ICMPv6", "fe80::1", "ff02::1");
        let v6 = packet("UDP", "[fe80::1]:546", "[ff02::1:2]:547");
        let all = [&dns, &http, &ping, &v6];
        let matching = |filter: &str| -> Vec<&str> {
            let filter = ok_filter(filter);
            all.iter()
                .filter(|packet| filter.matches(packet))
                .map(|packet| packet.protocol.as_str())
                .collect()
        };
        assert_eq!(matching(""), ["DNS", "HTTP", "ICMPv6", "UDP"]);
        assert_eq!(matching("port 53"), ["DNS"]);
        assert_eq!(matching("Port 80"), ["HTTP"]);
        assert_eq!(matching("ip 10.0.2.15"), ["DNS", "HTTP"]);
        assert_eq!(matching("10.0.2.3"), ["DNS"]);
        assert_eq!(matching("fe80::1"), ["ICMPv6", "UDP"]);
        assert_eq!(matching("10.0.2.15:5353"), ["DNS"]);
        assert_eq!(matching("[ff02::1:2]:547"), ["UDP"]);
        assert_eq!(matching("proto http"), ["HTTP"]);
        assert_eq!(matching("icmp"), ["ICMPv6"]);
        assert_eq!(matching("info"), ["DNS", "HTTP", "ICMPv6", "UDP"]);
        // "port 5" is port 5, not every port starting with 5.
        assert!(matching("port 5").is_empty());
        assert_eq!(ok_filter("port x"), Filter::Text("port x".into()));
    }

    #[test]
    fn quick_filter_counts_are_sorted_by_use() {
        let packets = vec![
            packet("HTTP", "10.0.2.15:40000", "1.2.3.4:80"),
            packet("TCP", "1.2.3.4:80", "10.0.2.15:40000"),
            packet("TCP", "10.0.2.15:40001", "1.2.3.4:443"),
            packet("DNS", "10.0.2.15:53", "10.0.2.3:53"),
        ];
        let counts = counts(&packets);
        assert_eq!(
            counts.ports,
            [(80, 2), (40000, 2), (53, 1), (443, 1), (40001, 1)]
        );
        assert_eq!(counts.addresses[0], ("10.0.2.15".parse().unwrap(), 4));
        assert_eq!(counts.addresses[1], ("1.2.3.4".parse().unwrap(), 3));
        assert_eq!(
            counts.protocols,
            [("TCP".to_owned(), 2), ("DNS".into(), 1), ("HTTP".into(), 1)]
        );
    }

    #[test]
    fn packets_are_colored_like_wireshark() {
        let mut syn = packet("TCP", "10.0.2.15:40000", "1.2.3.4:80");
        syn.tcp_flags = Some(network::TCP_SYN);
        let mut reset = syn.clone();
        reset.tcp_flags = Some(network::TCP_RST | 0x10);
        assert_eq!(packet_color(&syn), Some(PacketColor::TcpSynFin));
        assert_eq!(packet_color(&reset), Some(PacketColor::TcpReset));
        let plain = packet("TCP", "10.0.2.15:40000", "1.2.3.4:80");
        assert_eq!(packet_color(&plain), Some(PacketColor::Tcp));
        for (protocol, color) in [
            ("HTTP", PacketColor::Http),
            ("TLS", PacketColor::Tls),
            ("DNS", PacketColor::Dns),
            ("DHCP", PacketColor::Dhcp),
            ("ARP", PacketColor::Arp),
            ("ICMP", PacketColor::Icmp),
            ("ICMPv6", PacketColor::Icmp),
            ("UDP", PacketColor::Udp),
        ] {
            assert_eq!(packet_color(&packet(protocol, "", "")), Some(color));
        }
        assert_eq!(packet_color(&packet("0x88cc", "", "")), None);
    }

    #[test]
    fn filtered_rows_follow_new_packets_and_filter_changes() {
        let mut list = PacketList::default();
        list.packets
            .push(packet("DNS", "10.0.2.15:5353", "10.0.2.3:53"));
        list.filter_rows("port 53");
        assert_eq!(list.rows, [0]);
        list.packets
            .push(packet("HTTP", "10.0.2.15:4000", "1.2.3.4:80"));
        list.packets
            .push(packet("DNS", "10.0.2.3:53", "10.0.2.15:5353"));
        list.filter_rows("port 53");
        assert_eq!(list.rows, [0, 2]);
        list.filter_rows("proto HTTP");
        assert_eq!(list.rows, [1]);
        list.filter_rows("");
        assert_eq!(list.rows, [0, 1, 2]);
    }

    #[test]
    fn capture_history_merges_retained_roots_and_deduplicates_moved_captures() {
        let fixture = std::env::temp_dir().join(format!(
            "ant-network-roots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let current = fixture.join("current");
        let prior = fixture.join("prior");
        let write_capture = |root: &Path, boot: &str, id: &str, started_ms: u64| {
            let mut capture =
                NetworkCapture::new(&root.join("boots").join(boot), boot, id, started_ms);
            capture.stopped_ms = Some(started_ms + 1_000);
            std::fs::create_dir_all(capture.file.parent().unwrap()).unwrap();
            std::fs::write(&capture.file, []).unwrap();
            let mut saved = capture.clone();
            saved.file = capture.file.file_name().unwrap().into();
            std::fs::write(capture.summary_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
            capture
        };
        let newest = write_capture(&current, "b-current", "moved", 4_000_000_000_000);
        // A retained root may contain the same capture after a location move.
        write_capture(&prior, "b-current", "moved", newest.started_ms);
        let older = write_capture(&prior, "b-prior", "older", 3_000_000_000_000);
        let legacy = prior.join("boots/b-legacy").join(network::PCAP_FILE);
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        let mut header = Vec::new();
        header.extend(0xa1b2c3d4u32.to_le_bytes());
        header.extend(2u16.to_le_bytes());
        header.extend(4u16.to_le_bytes());
        header.extend([0u8; 8]);
        header.extend(65_535u32.to_le_bytes());
        header.extend(1u32.to_le_bytes());
        // A fixed first-packet timestamp makes ordering independent of the
        // host clock and the file's modification time.
        header.extend(1_000_000_000u32.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(14u32.to_le_bytes());
        header.extend(14u32.to_le_bytes());
        header.extend([0u8; 14]);
        std::fs::write(&legacy, header).unwrap();
        let retained = [
            prior.clone(),
            current.clone(),
            prior.join("."),
            prior.clone(),
        ];
        let captures = capture_history(Some(&current), &retained);
        assert_eq!(captures.len(), 3);
        assert_eq!(captures[0], newest);
        assert_eq!(captures[1], older);
        assert_eq!(captures[2].file, legacy);
        assert!(captures[2].whole_boot);
        std::fs::remove_dir_all(fixture).unwrap();
    }
}
