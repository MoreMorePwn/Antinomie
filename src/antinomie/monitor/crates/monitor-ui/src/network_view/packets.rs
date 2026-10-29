// SPDX-License-Identifier: GPL-3.0-only
//! The packet table (TShark's rows) and the selected packet's details and bytes.
use super::*;
use std::cmp::Ordering;

/// The sort state of the Packets table.
const PACKETS_TABLE: &str = "network_packets";

/// `rows` (indices into `packets`) in the order `sort` picks; unchanged without one.
pub(super) fn ordered_rows(
    rows: &[usize],
    packets: &[NetworkPacket],
    sort: Option<crate::triage::SortSpec>,
) -> Vec<usize> {
    let mut rows = rows.to_vec();
    if let Some(spec) = sort {
        rows.sort_by(|&a, &b| {
            let order = compare_packets(spec.column, &packets[a], &packets[b]);
            if spec.descending {
                order.reverse()
            } else {
                order
            }
        });
    }
    rows
}

/// Packet order for a header column: No., Time, Source, Destination, Protocol,
/// Length, Info. Addresses order by IP then port, packets without one last.
fn compare_packets(column: usize, left: &NetworkPacket, right: &NetworkPacket) -> Ordering {
    let address = |packet: &NetworkPacket, source: bool| {
        let (ip, port, text) = if source {
            (packet.src_ip, packet.src_port, &packet.source)
        } else {
            (packet.dst_ip, packet.dst_port, &packet.destination)
        };
        (ip.is_none(), ip, port, text.to_lowercase())
    };
    match column {
        0 => left.number.cmp(&right.number),
        1 => left.time_us.cmp(&right.time_us),
        2 => address(left, true).cmp(&address(right, true)),
        3 => address(left, false).cmp(&address(right, false)),
        4 => left
            .protocol
            .to_lowercase()
            .cmp(&right.protocol.to_lowercase()),
        5 => left.length.cmp(&right.length),
        _ => left.info.to_lowercase().cmp(&right.info.to_lowercase()),
    }
}

impl NetworkView {
    pub(super) fn packets(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
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
        if self.list.path.is_none() {
            empty_state(
                ui,
                if !cx.nat {
                    "The VM is disconnected. With an Isolated, NAT or Routed network, a capture \
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
            crate::activity::warning(ui, error);
        }
        if let Some(error) = self.tshark_unavailable() {
            tshark_missing_notice(ui, &error, "Frames are shown raw, without decoding.");
        }
        if self.list.truncated && self.raw_frames() {
            crate::activity::warning(ui,
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
        let packets = if self.raw_frames() {
            &list.packets
        } else {
            &self.display_page
        };
        let filtering = !self.filter.trim().is_empty();
        // A header click sorts the rows shown: the page when TShark pages the
        // capture, all of them for raw frames.
        let sort = crate::triage::sort_current(ui.ctx(), PACKETS_TABLE);
        let mut cached = std::mem::take(&mut self.packet_order);
        let key = sort.map(|spec| {
            (
                spec,
                list.rows.len(),
                packets.len(),
                self.display_page_start,
                self.raw_frames(),
            )
        });
        if cached.key != key || cached.rows.len() != list.rows.len() {
            cached.rows = ordered_rows(&list.rows, packets, sort);
            cached.key = key;
        }
        let ordered = &cached.rows;
        egui::ScrollArea::horizontal()
            .id_salt("network_columns")
            .show(ui, |ui| {
                crate::widgets::table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt(("network_packets", self.display_page_start))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .stick_to_bottom(is_live && list.selected.is_none() && sort.is_none())
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
                    .header(
                        crate::widgets::table::header_height(font_size),
                        |mut header| {
                            for (column, label) in [
                                "No.",
                                "Time",
                                "Source",
                                "Destination",
                                "Protocol",
                                "Length",
                                "Info",
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                header.col(|ui| {
                                    crate::table_sort::header(ui, PACKETS_TABLE, column, label)
                                });
                            }
                        },
                    )
                    .body(|body| {
                        body.rows(
                            crate::widgets::table::row_height(font_size),
                            list.rows.len(),
                            |mut row| {
                                let index = ordered[row.index()];
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
                                        if column == 0 {
                                            let mark = if selected {
                                                crate::widgets::table::Mark::Selected
                                            } else if packet
                                                .tcp_flags
                                                .is_some_and(|flags| flags & network::TCP_RST != 0)
                                            {
                                                crate::widgets::table::Mark::Failed
                                            } else {
                                                crate::widgets::table::Mark::None
                                            };
                                            crate::widgets::table::row_mark(ui, mark);
                                        }
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
                                                    0 => {
                                                        (packet.number.to_string(), theme::muted())
                                                    }
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
                                                display_clause_menu(
                                                    ui,
                                                    &clause,
                                                    &mut display_filter,
                                                );
                                            });
                                        }
                                    });
                                    if let Some(set) = filter_menu(ui, packet, filtering) {
                                        filter = Some(set);
                                        ui.close_menu();
                                    }
                                });
                            },
                        );
                    });
            });
        self.packet_order = cached;
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
            self.capture_details = None;
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

    /// The selected packet for the Details panel: TShark's details tree on the
    /// left, the frame's bytes on the right with the chosen line's bytes marked.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui, font_size: f32) {
        if let Some((capture, live)) = self.capture_details.clone() {
            // The record can be taller than the panel; its own scroll area
            // keeps its place while the same capture is shown.
            crate::details_scroll::show(
                ui,
                "network_capture_record_scroll",
                &capture.file,
                |ui, _| self.capture_record_details(ui, &capture, live),
            );
            return;
        }
        let Some(packet) = self.list.selected.clone() else {
            if let Some(note) = &self.display_jump_note {
                ui.colored_label(theme::muted(), note);
            }
            empty_state(
                ui,
                "No packet selected. Select a packet in the Network tab to see its \
                 details and bytes here.",
            );
            return;
        };
        self.poll_detail();
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
                self.list.frame = Some((packet.offset, frame));
                self.detail_node = None;
            }
        }
        self.request_detail(packet.number, ui.ctx());
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
                crate::activity::warning(ui, error);
                return;
            }
            None => return,
        };
        let mut hovered = None;
        // The bytes get the width of a full hex row; the tree the rest.
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let hex_width = char_width * 74.0 + 28.0;
        let available = ui.available_width();
        let tshark_error = self.tshark_unavailable();
        egui::SidePanel::left("packet_tree")
            .resizable(true)
            .default_width((available - hex_width).max(available * 0.45))
            .width_range(160.0..=(ui.available_width() - 160.0).max(161.0))
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 6,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                if let Some(error) = &tshark_error {
                    tshark_missing_notice(ui, error, "Protocol details need TShark.");
                    return;
                }
                let Some(detail) = &self.detail else {
                    return;
                };
                match &detail.state {
                    DetailState::Loading => {
                        theme::loading_colored(
                            ui,
                            theme::muted(),
                            "Asking TShark for the packet details…",
                        );
                    }
                    DetailState::Failed(error) => {
                        crate::activity::warning(ui, error);
                    }
                    DetailState::Ready(ready) => {
                        ui.horizontal(|ui| {
                            if ui.small_button("Expand all").clicked() {
                                set_all(&ready.tree, &mut self.detail_open, true);
                            }
                            if ui.small_button("Collapse all").clicked() {
                                set_all(&ready.tree, &mut self.detail_open, false);
                            }
                            if ready.tree.cut {
                                ui.colored_label(
                                    theme::muted(),
                                    "Deeper or later lines were left out (size limits).",
                                );
                            }
                        });
                        hovered = detail_tree(
                            ui,
                            &ready.tree,
                            &mut self.detail_open,
                            &mut self.detail_node,
                            &mono,
                        );
                    }
                }
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 6,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                let chosen = self.detail_node.and_then(|at| {
                    let DetailState::Ready(ready) = &self.detail.as_ref()?.state else {
                        return None;
                    };
                    let node = ready.tree.nodes.get(at)?;
                    // TShark's range must fit the bytes shown.
                    let range = node.range().filter(|range| range.end <= bytes.len())?;
                    Some((node.label.clone(), range))
                });
                ui.horizontal(|ui| {
                    theme::section(ui, "Bytes");
                    match &chosen {
                        Some((label, range)) => {
                            ui.label(
                                RichText::new(format!(
                                    "{}: {} bytes at 0x{:04x}",
                                    label.chars().take(60).collect::<String>(),
                                    range.len(),
                                    range.start
                                ))
                                .color(theme::muted()),
                            );
                        }
                        None => {
                            ui.colored_label(theme::muted(), format!("{} bytes", bytes.len()));
                        }
                    }
                });
                let marked = chosen.map(|(_, range)| range);
                let hovered = hovered.filter(|range| range.end <= bytes.len());
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

/// What to tell the user when TShark cannot run: the viewer shows frames and
/// bytes but decodes nothing itself.
pub(super) fn tshark_notice(installed: bool, error: &str, what: &str) -> String {
    if installed {
        format!("TShark could not run: {error}. {what}")
    } else {
        format!("TShark not installed — install it from Tools. {what}")
    }
}

pub(super) fn tshark_missing_notice(ui: &mut egui::Ui, error: &str, what: &str) {
    crate::activity::warning(ui, tshark_notice(which("tshark").is_some(), error, what));
}

/// The row color of a packet, by the first matching rule.
pub(super) fn packet_color(packet: &NetworkPacket) -> Option<PacketColor> {
    if let Some(flags) = packet.tcp_flags {
        if flags & network::TCP_RST != 0 {
            return Some(PacketColor::TcpReset);
        }
        if flags & (network::TCP_SYN | network::TCP_FIN) != 0 {
            return Some(PacketColor::TcpSynFin);
        }
    }
    // TShark names the protocol (TLSv1.3, HTTP2, MDNS, ...); the color is
    // only the family it belongs to.
    let protocol = packet.protocol.as_str();
    Some(match protocol {
        _ if protocol.starts_with("HTTP") => PacketColor::Http,
        _ if protocol.starts_with("TLS") || protocol.starts_with("SSL") || protocol == "QUIC" => {
            PacketColor::Tls
        }
        "DNS" | "MDNS" | "LLMNR" => PacketColor::Dns,
        _ if protocol.starts_with("DHCP") => PacketColor::Dhcp,
        "ARP" => PacketColor::Arp,
        _ if protocol.starts_with("ICMP") => PacketColor::Icmp,
        "TCP" => PacketColor::Tcp,
        "UDP" => PacketColor::Udp,
        _ => return None,
    })
}

pub(super) fn text_format(font: egui::FontId, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat::simple(font, color)
}

/// The color of a protocol name.
pub(super) fn protocol_color(protocol: &str) -> egui::Color32 {
    match protocol {
        "DNS" | "MDNS" | "LLMNR" => theme::info(),
        _ if protocol.starts_with("DHCP") => theme::info(),
        _ if protocol.starts_with("HTTP") => theme::good(),
        _ if protocol.starts_with("TLS") || protocol.starts_with("SSL") || protocol == "QUIC" => {
            theme::value(ValueKind::Pointer)
        }
        "TCP" => theme::value(ValueKind::Flags),
        "UDP" => theme::value(ValueKind::Number),
        "ARP" => theme::warn(),
        _ if protocol.starts_with("ICMP") => theme::value(ValueKind::Name),
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

/// A hex dump (offset, 16 bytes, text) with `marked` bytes on the selection
/// color and `hovered` ones on a fainter band.
pub(super) fn hex_job(
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
pub(super) fn link(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>, hover: &str) -> bool {
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
