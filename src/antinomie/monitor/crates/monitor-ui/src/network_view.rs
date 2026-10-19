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
mod captures;
mod display;
mod packets;
mod toolbar;

use self::{captures::*, display::*, packets::*, toolbar::*};

const MAX_PACKETS: usize = 200_000;
/// Packets read per refresh, so a large file loads over a few frames.
const READ_BATCH: usize = 5_000;
/// Entries of each quick-filter list.
const QUICK_ENTRIES: usize = 100;

/// What the panel asks the app to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NetworkAction {
    Start,
    Stop,
    /// Delete a saved capture, once the user confirms.
    Delete(crate::evidence_delete::Deletion),
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
    /// The running boot: a capture of it that has not stopped is still written.
    pub boot_id: Option<&'a str>,
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
    /// Details shows the clicked capture's record, until a packet is chosen.
    capture_details: Option<(NetworkCapture, bool)>,
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
            // A complete file is looked at four times a second, not every frame.
            last.elapsed() >= Duration::from_secs(1)
                || (!live
                    && last.elapsed() >= Duration::from_millis(250)
                    && self.more_on_disk(&path))
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
    /// An explicit evidence jump reveals the frame even when old filters hide it.
    pub(crate) fn jump_to_evidence(&mut self, frame_number: u64) -> Result<(), String> {
        self.filter.clear();
        self.applied_filter.clear();
        self.display_filter.clear();
        self.reset_display_capture();
        self.jump_to_frame(frame_number)
    }
    /// A deleted capture leaves the list, the packet view and Details.
    pub(crate) fn forget_capture(&mut self, file: &Path) {
        self.captures.retain(|capture| capture.file != file);
        self.record_shown.remove(file);
        if self
            .capture_details
            .as_ref()
            .is_some_and(|(capture, _)| capture.file == file)
        {
            self.capture_details = None;
        }
        if self.list.path.as_deref() == Some(file) {
            self.list = PacketList::new(None);
            self.reset_display_capture();
        }
    }

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

    #[cfg(test)]
    pub(crate) fn loaded_path(&self) -> Option<&Path> {
        self.list.path.as_deref()
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
            crate::activity::warning(ui,
                "Disconnected: network capture is unavailable. Choose Isolated or NAT in VM settings. Saved captures can still be inspected.",
            );
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

pub(crate) fn format_bytes(bytes: u64) -> String {
    crate::values::file_size(bytes)
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
mod tests;
