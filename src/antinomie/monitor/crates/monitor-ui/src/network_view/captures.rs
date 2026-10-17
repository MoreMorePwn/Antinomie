// SPDX-License-Identifier: MIT
//! The list of network captures of the selected VM.
use super::*;

impl NetworkView {
    /// The running capture first, then earlier ones; a click opens one.
    pub(super) fn capture_list(
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
                        self.capture_menu(ui, active);
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
                        self.capture_menu(ui, capture);
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

    fn capture_menu(&self, ui: &mut egui::Ui, capture: &NetworkCapture) {
        let directory = capture.file.with_extension("metadata");
        crate::evidence::menu(ui, &directory);
        if ui.button("Open PCAP directory").clicked() {
            if let Some(parent) = capture.file.parent() {
                crate::evidence::reveal(ui.ctx(), parent);
            }
            ui.close_menu();
        }
    }
}

pub(super) fn capture_fields() -> Vec<crate::query::FieldSpec<'static>> {
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

pub(super) fn capture_row_values(
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
pub(super) fn capture_history(current: Option<&Path>, retained: &[PathBuf]) -> Vec<NetworkCapture> {
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

/// The list's name for a capture.
pub(super) fn capture_title(capture: &NetworkCapture, live: bool) -> String {
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
pub(super) fn capture_detail(
    capture: &NetworkCapture,
    live: bool,
    loaded: Option<usize>,
) -> String {
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

pub(super) fn format_duration(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0 => format!("{ms} ms"),
        1..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, seconds / 60 % 60),
    }
}
