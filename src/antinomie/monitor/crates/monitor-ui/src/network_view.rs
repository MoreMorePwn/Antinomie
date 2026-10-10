//! Network panel: the network captures of the selected VM and the packet list
//! of one of them. While a capture runs, QEMU writes every frame of the VM's
//! network interface to its pcap file, outside the guest; the list follows
//! that file live.
use crate::theme::{self, PacketColor};
use antinomie_monitor_core::network::{self, NetworkCapture, NetworkPacket};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::HashMap,
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
    /// Captures of the selected VM, newest first, and the recording folder
    /// they were listed from.
    captures: Vec<NetworkCapture>,
    captures_for: Option<Option<PathBuf>>,
    /// The running capture (id, file) last seen, to notice a start or stop.
    seen_active: Option<(String, PathBuf)>,
    hide_list: bool,
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

    fn scan(&mut self, recordings: Option<&Path>) {
        self.captures = recordings.map(network::list_captures).unwrap_or_default();
        self.captures_for = Some(recordings.map(Path::to_path_buf));
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
        if self.captures_for.as_ref().map(Option::as_deref) != Some(cx.recordings) {
            // Another VM: show its running capture, else its newest one.
            self.scan(cx.recordings);
            let first = active
                .as_ref()
                .map(|(_, file)| file.clone())
                .or_else(|| self.captures.first().map(|capture| capture.file.clone()));
            self.list = PacketList::new(first);
            self.seen_active = active.clone();
        } else if self.seen_active != active {
            // A capture started or stopped: list it, and show a new one live.
            self.scan(cx.recordings);
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
                .default_width(250.0)
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
            ui.strong("Network");
            let open = self.list.path.as_ref().map(|path| {
                self.captures
                    .iter()
                    .find(|capture| &capture.file == path)
                    .map_or_else(
                        || path.display().to_string(),
                        |capture| capture_title(capture, is_live),
                    )
            });
            ui.label(open.unwrap_or_else(|| "No capture open".into()));
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter: port 80, ip 10.0.2.15, proto DNS, text")
                    .desired_width(210.0),
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
            ui.menu_button("Colors", |ui| {
                for color in PacketColor::ALL {
                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(28.0, 14.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 2.0, color.tint());
                        ui.label(color.label());
                    });
                }
            })
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
                    ui.colored_label(theme::MUTED, "Waiting for the VM...");
                }
                if !self.filter.trim().is_empty() {
                    ui.colored_label(
                        theme::BLUE,
                        format!(
                            "Filter {}: {} of {total} packets",
                            self.filter.trim(),
                            self.list.rows.len()
                        ),
                    );
                    if ui.button("Clear filter").clicked() {
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
        ui.add_enabled_ui(!empty, |ui| {
            egui::ComboBox::from_id_salt("network_ports")
                .selected_text("Ports")
                .width(90.0)
                .height(420.0)
                .show_ui(ui, |ui| {
                    for (port, count) in self.list.counts().ports.iter().take(QUICK_ENTRIES) {
                        if ui
                            .selectable_label(false, format!("Port {port} ({count})"))
                            .clicked()
                        {
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
                        if ui
                            .selectable_label(false, format!("{address} ({count})"))
                            .clicked()
                        {
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
                        if ui
                            .selectable_label(false, format!("{protocol} ({count})"))
                            .clicked()
                        {
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
            .add_enabled(wireshark.is_some(), egui::Button::new("Open in Wireshark"))
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
            ui.strong("Captures");
            if ui
                .add(egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false))
                .on_hover_text("Refresh the list")
                .clicked()
            {
                self.scan(cx.recordings);
            }
        });
        if let Some(active) = cx.active {
            let button = ui
                .add_enabled(
                    !cx.pending,
                    egui::Button::new(format!("{} Stop capture", egui_phosphor::regular::STOP)),
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
                    egui::Button::new(format!("{} Start capture", egui_phosphor::regular::RECORD)),
                )
                .on_hover_text(
                    "Record every packet of the VM's network interface, outside the guest",
                )
                .on_disabled_hover_text(why.unwrap_or("Waiting for the VM"));
            if button.clicked() {
                action = Some(NetworkAction::Start);
            }
        }
        ui.separator();
        let mut open = None;
        egui::ScrollArea::vertical()
            .id_salt("network_capture_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(active) = cx.active {
                    let selected = self.list.path.as_ref() == Some(&active.file);
                    let loaded = selected.then_some(self.list.packets.len());
                    let text = RichText::new(format!(
                        "{} Live capture\n{}",
                        egui_phosphor::regular::RECORD,
                        capture_detail(active, true, loaded)
                    ))
                    .color(if selected { theme::TEXT } else { theme::ERROR });
                    if ui
                        .selectable_label(selected, text)
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
                    let text = format!(
                        "{}\n{}",
                        capture_title(capture, false),
                        capture_detail(capture, false, None)
                    );
                    if ui
                        .selectable_label(selected, text)
                        .on_hover_text(format!(
                            "Boot {}\n{}",
                            capture.boot_id,
                            capture.file.display()
                        ))
                        .clicked()
                    {
                        open = Some(capture.file.clone());
                    }
                }
                if cx.active.is_none() && earlier.is_empty() {
                    ui.colored_label(theme::MUTED, "No network captures for this VM");
                }
            });
        if let Some(path) = open {
            self.open(Some(path));
        }
        action
    }

    fn packets(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
        if self.list.path.is_none() {
            ui.colored_label(
                theme::MUTED,
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
            ui.colored_label(theme::WARN, error);
        }
        if self.list.truncated {
            ui.colored_label(
                theme::WARN,
                format!(
                    "Showing the first {MAX_PACKETS} packets; open the capture in Wireshark for all."
                ),
            );
        }
        let font_size = cx.font_size;
        let start = self.list.packets.first().map_or(0, |p| p.time_us);
        let table_height = (ui.available_height() * 0.62).max(80.0);
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
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .column(Column::exact(70.0))
                    .column(Column::exact(90.0))
                    .column(
                        Column::initial(200.0)
                            .at_least(80.0)
                            .resizable(true)
                            .clip(true),
                    )
                    .column(
                        Column::initial(200.0)
                            .at_least(80.0)
                            .resizable(true)
                            .clip(true),
                    )
                    .column(Column::exact(76.0).clip(true))
                    .column(Column::exact(64.0))
                    .column(Column::remainder().at_least(200.0))
                    .header(font_size + 12.0, |mut header| {
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
                                ui.strong(label);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(font_size + 10.0, list.rows.len(), |mut row| {
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
                                            &packet.source,
                                            packet.src_ip,
                                            packet.src_port,
                                        ),
                                        3 => address_cell(
                                            ui,
                                            &packet.destination,
                                            packet.dst_ip,
                                            packet.dst_port,
                                        ),
                                        4 => link(
                                            ui,
                                            &packet.protocol,
                                            &format!("Filter by protocol {}", packet.protocol),
                                        )
                                        .then(|| format!("proto {}", packet.protocol)),
                                        _ => {
                                            let text = match column {
                                                0 => packet.number.to_string(),
                                                1 => format!("{elapsed:.6}"),
                                                5 => packet.length.to_string(),
                                                _ => packet.info.clone(),
                                            };
                                            ui.add(
                                                egui::Label::new(text).selectable(false).truncate(),
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
        if let Some(index) = clicked {
            self.list.selected = Some(index);
        }
        if let Some(set) = filter {
            self.filter = set;
        }
        ui.separator();
        self.details(ui, start);
    }

    fn details(&mut self, ui: &mut egui::Ui, start: u64) {
        let Some(packet) = self
            .list
            .selected
            .and_then(|i| self.list.packets.get(i))
            .cloned()
        else {
            ui.colored_label(
                theme::MUTED,
                if self.list.packets.is_empty() {
                    "No packets yet"
                } else {
                    "Select a packet to see its bytes"
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
                self.list.frame = Some((packet.offset, network::frame(path, packet.offset)));
            }
        }
        ui.label(
            RichText::new(format!(
                "Frame {}: {} bytes on the wire, {} captured · {:.6} s · {}",
                packet.number,
                packet.length,
                packet.captured,
                packet.time_us.saturating_sub(start) as f64 / 1e6,
                packet.info
            ))
            .strong(),
        );
        match self.list.frame.as_ref().map(|(_, frame)| frame) {
            Some(Ok(bytes)) => {
                egui::ScrollArea::both()
                    .id_salt("network_frame")
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(hex_dump(bytes)).monospace())
                                .selectable(true),
                        );
                    });
            }
            Some(Err(error)) => {
                ui.colored_label(theme::WARN, error);
            }
            None => {}
        }
    }
}

/// Text that sets a filter when clicked.
fn link(ui: &mut egui::Ui, text: &str, hover: &str) -> bool {
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
            egui::Stroke::new(1.0_f32, theme::TEXT),
        );
    }
    response.clicked()
}

/// A Source or Destination cell: its address and port filter separately.
fn address_cell(
    ui: &mut egui::Ui,
    text: &str,
    address: Option<IpAddr>,
    port: Option<u16>,
) -> Option<String> {
    ui.spacing_mut().item_spacing.x = 0.0;
    match (address, port) {
        (Some(address), Some(port)) => {
            let shown = match address {
                IpAddr::V4(_) => address.to_string(),
                IpAddr::V6(_) => format!("[{address}]"),
            };
            let by_address = link(ui, &shown, &format!("Filter by address {address}"));
            let by_port = link(ui, &format!(":{port}"), &format!("Filter by port {port}"));
            if by_address {
                Some(format!("ip {address}"))
            } else {
                by_port.then(|| format!("port {port}"))
            }
        }
        (Some(address), None) => {
            link(ui, text, &format!("Filter by address {address}")).then(|| format!("ip {address}"))
        }
        _ if !text.is_empty() => link(ui, text, &format!("Filter by {text}")).then(|| text.into()),
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

fn format_bytes(bytes: u64) -> String {
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
fn format_date(seconds: u64) -> String {
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

fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let hex: Vec<_> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let text: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {:<47}  {text}", row * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
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
    fn hex_dump_pads_short_rows() {
        let dump = hex_dump(b"GET / HTTP/1.1\r\nHost");
        let lines: Vec<_> = dump.lines().collect();
        assert_eq!(
            lines[0],
            "0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1.."
        );
        assert!(lines[1].starts_with("0010  48 6f 73 74"));
        assert!(lines[1].ends_with("  Host"));
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
}
