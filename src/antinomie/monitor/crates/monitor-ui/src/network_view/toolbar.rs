// SPDX-License-Identifier: MIT
//! Display filter toolbar, quick filters and the Wireshark handoff.
use super::*;

/// Placeholders of the three filter boxes, each a valid example.
const QUICK_SEARCH_HINT: &str = "filter e.g. port 443";
/// Bare examples: the shared filter editor adds the "filter e.g." prefix.
const DISPLAY_FILTER_HINT: &str = "tcp.port == 443";
const RECORD_FILTER_HINT: &str = "packets > 100";
const QUICK_SEARCH_HELP: &str = "Native quick search: port N, ip ADDRESS, ADDRESS:PORT, proto NAME, or column text. Quick search affects only the loaded page; use the display filter for the whole capture.";
const DISPLAY_FILTER_HELP: &str = "Evaluated by installed TShark with two-pass Wireshark display-filter semantics. Field suggestions come from that installation. Example: tcp.port in {80, 443} && ip.addr == 10.0.2.15";

impl NetworkView {
    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui, is_live: bool, cx: &NetworkContext<'_>) {
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
            if let Some(path) = self.list.path.clone() {
                self.wireshark_button(ui, &path, is_live);
            }
            if let Some(filter) = self.quick_filters(ui) {
                self.filter = filter;
            }
        });
        let registry = self.display_worker.as_ref().map(PacketFilterWorker::fields);
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
        let mut edited = false;
        egui::CollapsingHeader::new("Filters")
            .id_salt("network_filters")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("network_filter_rows")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label("Quick Search");
                        let width = ui.available_width().max(100.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.filter)
                                .hint_text(theme::hint_text(QUICK_SEARCH_HINT))
                                .margin(theme::TEXT_EDIT_MARGIN)
                                .desired_width(width),
                        )
                        .on_hover_text(QUICK_SEARCH_HELP);
                        ui.end_row();
                        ui.label("Display Filter");
                        let width = ui.available_width().max(100.0);
                        match &registry {
                            Some(FieldRegistry::Ready(fields)) => {
                                ui.data_mut(|data| {
                                    data.insert_temp(
                                        ui.id()
                                            .with(("filter-edit", DISPLAY_FILTER_HINT))
                                            .with("history"),
                                        self.display_history.clone(),
                                    )
                                });
                                let schema = fields.iter().map(|field| crate::query::FieldSpec {
                                    name: &field.name,
                                    kind: &field.kind,
                                    detail: &field.description,
                                });
                                edited = crate::query::filter_edit_packet_field_iter(
                                    ui,
                                    &mut self.display_filter,
                                    DISPLAY_FILTER_HINT,
                                    width,
                                    schema,
                                    &[],
                                )
                                .on_hover_text(DISPLAY_FILTER_HELP)
                                .changed();
                            }
                            _ => {
                                ui.add_enabled(
                                    false,
                                    egui::TextEdit::singleline(&mut self.display_filter)
                                        .hint_text(theme::hint_text(
                                            "filter e.g. tcp.port == 443 (needs tshark)",
                                        ))
                                        .margin(theme::TEXT_EDIT_MARGIN)
                                        .desired_width(width),
                                );
                            }
                        }
                        ui.end_row();
                        ui.label("Record Filter");
                        ui.data_mut(|data| {
                            data.insert_temp(
                                ui.id()
                                    .with(("filter-edit", RECORD_FILTER_HINT))
                                    .with("history"),
                                self.record_history.clone(),
                            )
                        });
                        let width = ui.available_width().max(100.0);
                        crate::query::filter_edit_fields(
                            ui,
                            &mut self.record_filter,
                            RECORD_FILTER_HINT,
                            width,
                            &fields,
                            &tags,
                        );
                        ui.end_row();
                    });
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
                theme::loading_colored(ui, theme::muted(), "Loading installed TShark fields…");
            }
            Some(FieldRegistry::Unavailable(error)) => {
                crate::activity::warning(ui, error);
            }
            _ => {}
        }
        if let Some(error) = &self.display_worker_error {
            crate::activity::warning(ui, error);
        }
        if let Some(error) = &self.display_error {
            crate::activity::warning(ui, error);
        }
        if let Some(note) = &self.display_jump_note {
            if note.starts_with("Locating frame") {
                theme::loading_colored(ui, theme::muted(), note.as_str());
            } else {
                ui.colored_label(theme::muted(), note);
            }
        }
        if self.display_pending {
            theme::loading_colored(
                ui,
                theme::muted(),
                "Applying display filter… Previous result stays visible.",
            );
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
            crate::activity::warning(ui, error);
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
                    theme::spinner(ui);
                    ui.colored_label(theme::muted(), "Waiting for the VM…");
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
        let label = format!(
            "{} Open in Wireshark",
            egui_phosphor::regular::ARROW_SQUARE_OUT
        );
        let mut button = egui::Button::new(label.clone());
        // A disabled button keeps the plain look, so it reads as disabled.
        if wireshark.is_some() {
            button = egui::Button::new(RichText::new(label).color(theme::palette().primary_text))
                .fill(theme::bright_blue());
        }
        let clicked = ui
            .add_enabled(wireshark.is_some(), button)
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
            match spawned {
                Ok(child) => {
                    reap(child);
                }
                Err(error) => self.list.error = Some(format!("Wireshark: {error}")),
            }
        }
    }
}

/// Wait for a launched program on a detached thread, so it does not stay a
/// zombie until the app exits. The handle is for tests; callers drop it.
pub(super) fn reap(mut child: std::process::Child) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = child.wait();
    })
}

pub(super) fn remember_filter(history: &mut Vec<String>, expression: &str) {
    if !expression.trim().is_empty() && history.first().is_none_or(|prior| prior != expression) {
        history.retain(|prior| prior != expression);
        history.insert(0, expression.into());
        history.truncate(24);
    }
}

pub(super) fn packet_display_clauses(packet: &NetworkPacket) -> Vec<(String, String)> {
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

pub(super) fn display_clause_menu(ui: &mut egui::Ui, clause: &str, filter: &mut String) {
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

/// The row's right-click menu: filters by its endpoints, ports and protocol.
pub(super) fn filter_menu(
    ui: &mut egui::Ui,
    packet: &NetworkPacket,
    filtering: bool,
) -> Option<String> {
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

pub(super) fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|path| path.is_file())
    })
}
