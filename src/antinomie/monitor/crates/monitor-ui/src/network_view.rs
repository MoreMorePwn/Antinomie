//! Network panel: the packet list of a boot's network capture (network.pcap,
//! written by QEMU outside the guest), followed live while the VM runs.
use crate::theme;
use antinomie_monitor_core::network::{self, NetworkPacket};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Packets kept in the list; older ones stay in the file (open it in Wireshark).
const MAX_PACKETS: usize = 200_000;
/// Packets read per refresh, so a large file loads over a few frames.
const READ_BATCH: usize = 5_000;

#[derive(Default)]
pub(crate) struct NetworkView {
    path: Option<PathBuf>,
    packets: Vec<NetworkPacket>,
    next_offset: u64,
    next_number: u64,
    truncated: bool,
    error: Option<String>,
    last_read: Option<Instant>,
    selected: Option<usize>,
    frame: Option<(u64, Result<Vec<u8>, String>)>,
    filter: String,
    /// Captures of earlier boots of the selected VM, newest first.
    choices: Vec<(String, PathBuf)>,
    choices_for: Option<PathBuf>,
}

impl NetworkView {
    fn open(&mut self, path: Option<PathBuf>) {
        if self.path != path {
            *self = NetworkView {
                path,
                filter: std::mem::take(&mut self.filter),
                choices: std::mem::take(&mut self.choices),
                choices_for: self.choices_for.take(),
                ..NetworkView::default()
            };
        }
    }

    /// Read new packets: always for a file another boot finished, about once
    /// a second while `live`.
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

    fn scan_choices(&mut self, recordings: Option<&Path>) {
        if self.choices_for.as_deref() == recordings && !self.choices.is_empty() {
            return;
        }
        self.choices_for = recordings.map(Path::to_path_buf);
        self.choices.clear();
        let Some(boots) = recordings.map(|dir| dir.join("boots")) else {
            return;
        };
        let mut found: Vec<_> = std::fs::read_dir(boots)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|boot| {
                let pcap = boot.path().join(network::PCAP_FILE);
                let modified = std::fs::metadata(&pcap).ok()?.modified().ok()?;
                Some((modified, pcap))
            })
            .collect();
        found.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
        self.choices = found
            .into_iter()
            .map(|(modified, pcap)| {
                let when = modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| format_date(d.as_secs()))
                    .unwrap_or_default();
                (format!("Boot of {when}"), pcap)
            })
            .collect();
    }

    /// Draw the panel. `live` is the running boot's capture of the selected
    /// VM; `recordings` is that VM's recording folder.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        live: Option<&Path>,
        recordings: Option<&Path>,
        nat: bool,
        font_size: f32,
    ) {
        if self.path.is_none() || (live.is_some() && self.choices_for.as_deref() != recordings) {
            self.open(live.map(Path::to_path_buf));
        }
        let is_live = live.is_some() && self.path.as_deref() == live;
        self.refresh(is_live);
        if is_live {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
        ui.horizontal_wrapped(|ui| {
            ui.strong("Network");
            let current = if is_live {
                "This boot (live)".to_owned()
            } else {
                self.path
                    .as_ref()
                    .and_then(|path| self.choices.iter().find(|(_, p)| p == path))
                    .map_or_else(|| "Choose a capture".to_owned(), |(label, _)| label.clone())
            };
            let mut choice = None;
            egui::ComboBox::from_id_salt("network_capture")
                .selected_text(current)
                .width(220.0)
                .show_ui(ui, |ui| {
                    if let Some(live) = live {
                        if ui.selectable_label(is_live, "This boot (live)").clicked() {
                            choice = Some(live.to_path_buf());
                        }
                    }
                    self.scan_choices(recordings);
                    for (label, path) in &self.choices {
                        if Some(path.as_path()) != live
                            && ui
                                .selectable_label(self.path.as_ref() == Some(path), label)
                                .clicked()
                        {
                            choice = Some(path.clone());
                        }
                    }
                });
            if let Some(path) = choice {
                self.open(Some(path));
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter")
                    .desired_width(150.0),
            );
            if let Some(path) = self.path.clone() {
                let wireshark = which("wireshark");
                let clicked = ui
                    .add_enabled(wireshark.is_some(), egui::Button::new("Open in Wireshark"))
                    .on_disabled_hover_text("Wireshark is not installed")
                    .on_hover_text(path.display().to_string())
                    .clicked();
                if let (true, Some(wireshark)) = (clicked, wireshark) {
                    if let Err(error) = std::process::Command::new(wireshark)
                        .arg("-r")
                        .arg(&path)
                        .spawn()
                    {
                        self.error = Some(format!("Wireshark: {error}"));
                    }
                }
            }
        });
        if !nat && self.path.is_none() {
            ui.colored_label(
                theme::MUTED,
                "The VM has no network (NAT is off). With NAT on, every packet of \
                 its network interface is recorded here, outside the guest.",
            );
            return;
        }
        if let Some(error) = &self.error {
            ui.colored_label(theme::WARN, error);
        }
        if self.truncated {
            ui.colored_label(
                theme::WARN,
                format!("Showing the first {MAX_PACKETS} packets; open the capture in Wireshark for all."),
            );
        }
        let needle = self.filter.trim().to_lowercase();
        let rows: Vec<usize> = (0..self.packets.len())
            .filter(|&i| {
                let p = &self.packets[i];
                needle.is_empty()
                    || [&p.source, &p.destination, &p.protocol, &p.info]
                        .iter()
                        .any(|text| text.to_lowercase().contains(&needle))
            })
            .collect();
        let start = self.packets.first().map_or(0, |p| p.time_us);
        let table_height = (ui.available_height() * 0.62).max(80.0);
        let mut clicked = None;
        egui::ScrollArea::horizontal()
            .id_salt("network_columns")
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("network_packets")
                    .sense(egui::Sense::click())
                    .striped(true)
                    .stick_to_bottom(is_live && self.selected.is_none())
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .column(Column::exact(70.0))
                    .column(Column::exact(90.0))
                    .column(Column::initial(190.0).at_least(80.0).resizable(true))
                    .column(Column::initial(190.0).at_least(80.0).resizable(true))
                    .column(Column::exact(70.0))
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
                        body.rows(font_size + 10.0, rows.len(), |mut row| {
                            let index = rows[row.index()];
                            let packet = &self.packets[index];
                            row.set_selected(self.selected == Some(index));
                            let elapsed = packet.time_us.saturating_sub(start) as f64 / 1e6;
                            for text in [
                                packet.number.to_string(),
                                format!("{elapsed:.6}"),
                                packet.source.clone(),
                                packet.destination.clone(),
                                packet.protocol.clone(),
                                packet.length.to_string(),
                                packet.info.clone(),
                            ] {
                                row.col(|ui| {
                                    ui.add(egui::Label::new(&text).selectable(false).truncate());
                                });
                            }
                            if row.response().clicked() {
                                clicked = Some(index);
                            }
                        });
                    });
            });
        if let Some(index) = clicked {
            self.selected = Some(index);
        }
        ui.separator();
        let Some(packet) = self.selected.and_then(|i| self.packets.get(i)).cloned() else {
            ui.colored_label(
                theme::MUTED,
                if self.packets.is_empty() {
                    "No packets yet"
                } else {
                    "Select a packet to see its bytes"
                },
            );
            return;
        };
        if self
            .frame
            .as_ref()
            .is_none_or(|(offset, _)| *offset != packet.offset)
        {
            if let Some(path) = &self.path {
                self.frame = Some((packet.offset, network::frame(path, packet.offset)));
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
        match self.frame.as_ref().map(|(_, frame)| frame) {
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

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|path| path.is_file())
    })
}

/// UTC date and time of Unix `seconds`, to the minute.
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
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        seconds / 3600 % 24,
        seconds / 60 % 60
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
        assert_eq!(format_date(1_791_554_943), "2026-10-09 14:09 UTC");
        assert_eq!(format_date(951_782_400), "2000-02-29 00:00 UTC");
    }
}
