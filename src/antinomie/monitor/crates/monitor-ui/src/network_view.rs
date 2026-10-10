//! Network panel: the network captures of the selected VM and the packet list
//! of one of them. While a capture runs, QEMU writes every frame of the VM's
//! network interface to its pcap file, outside the guest; the list follows
//! that file live.
use crate::theme::{self, PacketColor, ValueKind};
use antinomie_monitor_core::network::{
    self, FieldKind, NetworkCapture, NetworkPacket, PacketLayer,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
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
    selected: Option<usize>,
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
    /// Captures of the selected VM, newest first, and the current and retained
    /// recording folders they were listed from.
    captures: Vec<NetworkCapture>,
    captures_for: Option<(Option<PathBuf>, Vec<PathBuf>)>,
    /// The running capture (id, file) last seen, to notice a start or stop.
    seen_active: Option<(String, PathBuf)>,
    hide_list: bool,
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

/// A packet filter, typed or set by clicking a value.
#[derive(Clone, Debug, PartialEq)]
enum Filter {
    All,
    /// `port 80`: either TCP/UDP port.
    Port(u16),
    /// `ip 10.0.2.15` (or a bare address): either address.
    Address(IpAddr),
    /// `10.0.2.15:5353`: that address and port, either direction.
    Endpoint(IpAddr, u16),
    /// `proto DNS`: the Protocol column.
    Protocol(String),
    /// Any other text: found in Source, Destination, Protocol or Info.
    Text(String),
}

impl Filter {
    fn parse(text: &str) -> Filter {
        let text = text.trim();
        if text.is_empty() {
            return Filter::All;
        }
        let lower = text.to_lowercase();
        let argument = |prefix: &str| lower.strip_prefix(prefix).map(str::trim);
        if let Some(port) = argument("port ").and_then(|port| port.parse().ok()) {
            return Filter::Port(port);
        }
        if let Some(address) = argument("ip ")
            .or_else(|| argument("host "))
            .and_then(|address| address.parse().ok())
        {
            return Filter::Address(address);
        }
        if let Some(protocol) = argument("proto ") {
            return Filter::Protocol(protocol.to_owned());
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
            Filter::Protocol(protocol) => packet.protocol.eq_ignore_ascii_case(protocol),
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
    fn open(&mut self, path: Option<PathBuf>) {
        if self.list.path != path {
            self.list = PacketList::new(path);
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
        self.list.refresh(is_live);
        if active.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
        self.list.filter_rows(&self.filter);

        let mut action = None;
        self.toolbar(ui, is_live, &cx);
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
            .frame(egui::Frame::new())
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
            ui.label(RichText::new(egui_phosphor::regular::FUNNEL).color(theme::muted()));
            let width = (ui.available_width() * 0.4).clamp(180.0, 320.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter packets")
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(width),
            )
            .on_hover_text(
                "port N: either port\nip ADDRESS: either address\n\
                 ADDRESS:PORT: that endpoint, either direction\n\
                 proto NAME: the Protocol column\nOther text: found in any column\n\
                 Click an address, port or protocol in the list to filter by it.",
            );
            if let Some(filter) = self.quick_filters(ui) {
                self.filter = filter;
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
        });
        let total = self.list.packets.len();
        if !self.filter.trim().is_empty() || cx.pending {
            ui.horizontal_wrapped(|ui| {
                if cx.pending {
                    ui.add(egui::Spinner::new());
                    ui.colored_label(theme::muted(), "Waiting for the VM...");
                }
                if !self.filter.trim().is_empty() {
                    ui.colored_label(
                        theme::blue(),
                        format!(
                            "Filter {}: {} of {total} packets",
                            self.filter.trim(),
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
        let empty = self.list.packets.is_empty();
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
                    for (port, count) in self.list.counts().ports.iter().take(QUICK_ENTRIES) {
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
                    for (address, count) in self.list.counts().addresses.iter().take(QUICK_ENTRIES)
                    {
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
                    for (protocol, count) in self.list.counts().protocols.iter().take(QUICK_ENTRIES)
                    {
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
                Some("This VM has no network: turn on NAT network in its settings and restart it")
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
                if let Some(active) = cx.active {
                    let selected = self.list.path.as_ref() == Some(&active.file);
                    let loaded = selected.then_some(self.list.packets.len());
                    let title = format!("{} Live capture", egui_phosphor::regular::RECORD);
                    if capture_row(
                        ui,
                        selected,
                        (&title, theme::error()),
                        &capture_detail(active, true, loaded),
                        font_size,
                    )
                    .on_hover_text(active.file.display().to_string())
                    .clicked()
                    {
                        open = Some(active.file.clone());
                    }
                }
                let earlier: Vec<_> = self
                    .captures
                    .iter()
                    .filter(|capture| Some(capture.id.as_str()) != cx.active.map(|a| a.id.as_str()))
                    .collect();
                for capture in &earlier {
                    let selected = self.list.path.as_ref() == Some(&capture.file);
                    // The date in UTC; the zone is in the hover text.
                    let started = format_date(capture.started_ms / 1000);
                    let title = started.trim_end_matches(" UTC");
                    if capture_row(
                        ui,
                        selected,
                        (title, theme::text()),
                        &capture_detail(capture, false, None),
                        font_size,
                    )
                    .on_hover_text(format!(
                        "Started {started}\nBoot {}\n{}",
                        capture.boot_id,
                        capture.file.display()
                    ))
                    .clicked()
                    {
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

    fn packets(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
        if self.list.path.is_none() {
            empty_state(
                ui,
                if !cx.nat {
                    "The VM has no network (NAT is off). With NAT on, a network capture \
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
        if self.list.truncated {
            ui.colored_label(
                theme::warn(),
                format!(
                    "Showing the first {MAX_PACKETS} packets; open the capture in Wireshark for all."
                ),
            );
        }
        let font_size = cx.font_size;
        let mono = theme::mono(font_size - 1.0);
        // Data columns fit their monospace contents; Info gets the rest.
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let chars = |count: f32| count * char_width + 8.0;
        let start = self.list.packets.first().map_or(0, |p| p.time_us);
        let mut clicked = None;
        let mut filter = None;
        let list = &self.list;
        let filtering = !self.filter.trim().is_empty();
        egui::ScrollArea::horizontal()
            .id_salt("network_columns")
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("network_packets")
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
                            let packet = &list.packets[index];
                            let selected = list.selected == Some(index);
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
                                clicked = Some(index);
                            }
                            response.context_menu(|ui| {
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
                if list.packets.is_empty() {
                    "No packets yet"
                } else {
                    "No packets match the filter"
                },
            );
        }
        if let Some(index) = clicked {
            self.list.selected = Some(index);
        }
        if let Some(set) = filter {
            self.filter = set;
        }
    }

    /// The selected packet for the Details panel: its decoded layers on the
    /// left, its bytes on the right with the chosen field's bytes marked.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let Some(packet) = self
            .list
            .selected
            .and_then(|i| self.list.packets.get(i))
            .cloned()
        else {
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
                let frame = network::frame(path, packet.offset);
                self.list.layers = frame
                    .as_ref()
                    .map(|bytes| network::dissect(bytes))
                    .unwrap_or_default();
                self.list.frame = Some((packet.offset, frame));
                self.list.field = None;
            }
        }
        let start = self.list.packets.first().map_or(0, |p| p.time_us);
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
            let filter = Filter::parse(filter);
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
        assert_eq!(Filter::parse("port x"), Filter::Text("port x".into()));
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
