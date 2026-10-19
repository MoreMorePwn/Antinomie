// SPDX-License-Identifier: MIT
//! The packet table and the selected packet's layers and bytes.
use super::*;

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
        self.refresh_payloads();
        // Protocol coverage and reconstruction counts are not shown; the
        // HTTP and DNS tables carry the rows themselves.
        if self.reconstruction().is_none() {
            if let Some(note) = self.payloads.as_ref().and_then(|cache| cache.note.clone()) {
                ui.colored_label(theme::muted(), note);
            }
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
            crate::activity::warning(ui, error);
        }
        if self.list.truncated && self.display_index.is_none() {
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

    /// The selected packet for the Details panel: its decoded layers on the
    /// left, its bytes on the right with the chosen field's bytes marked.
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

pub(super) fn text_format(font: egui::FontId, color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat::simple(font, color)
}

/// The color of a protocol name.
pub(super) fn protocol_color(protocol: &str) -> egui::Color32 {
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

/// The packet's layers as a collapsible tree of branches; a click chooses a layer or a
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
    let char_width = crate::tree_lines::char_width(ui, mono);
    let root = crate::tree_lines::Prefix::default();
    for (index, layer) in layers.iter().enumerate() {
        let id = ui.make_persistent_id(("packet_layer", &layer.name));
        let mut state =
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true);
        let mut open = state.is_open();
        crate::tree_lines::row(ui, &root, char_width, |ui| {
            open = crate::tree_lines::caret(ui, &mut state);
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
        });
        if !open {
            continue;
        }
        let depths: Vec<_> = layer
            .fields
            .iter()
            .map(|field| usize::from(field.depth) + 1)
            .collect();
        let branches = crate::tree_lines::prefixes(&depths);
        for ((field_index, field), branch) in layer.fields.iter().enumerate().zip(&branches) {
            crate::tree_lines::row(ui, branch, char_width, |ui| {
                let mut job = egui::text::LayoutJob::default();
                job.append(
                    &format!("{}: ", field.name),
                    0.0,
                    text_format(egui::FontId::proportional(font_size), theme::muted()),
                );
                let font = match field.kind {
                    FieldKind::Number | FieldKind::Address | FieldKind::Bytes => mono.clone(),
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
    }
    hovered
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
