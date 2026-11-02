// SPDX-License-Identifier: GPL-3.0-only
//! Export of the IOC tab: CSV, JSON, MISP and STIX 2.1 of the rows listed (or
//! of the selected row), into the data folder's `sample-reports`, created new
//! and private. The export is noted in the sample's custody log like the
//! sample report's. The files are written on a worker thread.
use super::iocs::{key_of, Go, State};
use super::*;
use antinomie_monitor_core::{
    report::sample::{build, misp, stix, SampleReport},
    samples::{ioc_csv, ioc_json, ioc_merged, CustodyEvent, Library, SampleIoc},
};
use std::io::Write;

/// (menu label, id, file suffix, custody name)
const FORMATS: [(&str, &str, &str, &str); 4] = [
    ("CSV", "csv", ".csv", "CSV"),
    ("JSON", "json", ".json", "JSON"),
    ("MISP event", "misp", ".misp.json", "MISP"),
    ("STIX 2.1 bundle", "stix", ".stix.json", "STIX 2.1"),
];

impl MonitorApp {
    pub(super) fn export_menu(
        &mut self,
        ui: &mut egui::Ui,
        state: &mut State,
        rows: &[&SampleIoc],
        go: &mut Option<Go>,
    ) {
        let running = state.job.is_some();
        ui.add_enabled_ui(!running && !rows.is_empty(), |ui| {
            ui.menu_button("Export…", |ui| {
                ui.set_min_width(300.0);
                let selected = state.selected.is_some();
                ui.add_enabled_ui(selected, |ui| {
                    ui.checkbox(&mut state.only_selected, "Only the selected row")
                        .on_disabled_hover_text("Select a row first");
                });
                if !selected {
                    state.only_selected = false;
                }
                ui.label(
                    egui::RichText::new(if state.only_selected {
                        "1 row".to_owned()
                    } else {
                        format!("The {} rows listed", rows.len())
                    })
                    .color(theme::muted()),
                );
                ui.label(
                    egui::RichText::new(if state.defang {
                        "Values are defanged in CSV and JSON; MISP and STIX keep raw values"
                    } else {
                        "Values are written raw"
                    })
                    .small()
                    .color(theme::muted()),
                );
                for (label, id, _, _) in FORMATS {
                    if ui.button(label).clicked() {
                        *go = Some(Go::Export(id));
                        ui.close_menu();
                    }
                }
            });
        });
        if running {
            theme::spinner(ui);
        }
    }

    pub(super) fn iocs_poll(&mut self, ctx: &egui::Context, state: &mut State) {
        let Some(job) = &state.job else { return };
        match job.try_recv() {
            Ok(result) => {
                state.job = None;
                state.status = Some(match result {
                    Ok(text) => (text, false),
                    Err(error) => (error, true),
                });
                // The custody log has a new entry.
                if let Some(detail) = self.samples_page.detail.as_mut() {
                    detail.stale = true;
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => state.job = None,
        }
    }

    pub(super) fn start_ioc_export(&mut self, ctx: &egui::Context, data: &Arc<Data>, id: &str) {
        let Some(&(_, id, suffix, name)) = FORMATS.iter().find(|format| format.1 == id) else {
            return;
        };
        let Some(detail) = self.samples_page.detail.as_mut() else {
            return;
        };
        let state = &mut detail.iocs;
        let rows: Vec<SampleIoc> = {
            let visible = state.visible(data);
            if state.only_selected {
                visible
                    .into_iter()
                    .filter(|row| state.selected.as_ref() == Some(&key_of(row)))
                    .cloned()
                    .collect()
            } else {
                visible.into_iter().cloned().collect()
            }
        };
        if rows.is_empty() {
            state.status = Some(("Nothing to export.".into(), true));
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        state.job = Some(rx);
        state.status = None;
        let defanged = state.defang;
        let data = Arc::clone(data);
        let folder = self.options.data_dir.join("sample-reports");
        let data_dir = self.options.data_dir.clone();
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("sample-ioc-export".into())
            .spawn(move || {
                let result = write(&data, &data_dir, &folder, &rows, id, suffix, name, defanged);
                let _ = tx.send(result);
                wake.request_repaint();
            });
        if spawned.is_err() {
            state.job = None;
            state.status = Some(("Could not start the export.".into(), true));
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

#[allow(clippy::too_many_arguments)]
fn write(
    data: &Data,
    data_dir: &std::path::Path,
    folder: &std::path::Path,
    rows: &[SampleIoc],
    id: &str,
    suffix: &str,
    name: &str,
    defanged: bool,
) -> Result<String, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let now = now_ms();
    let listed = data.iocs.listed.len();
    let refs: Vec<&SampleIoc> = rows.iter().collect();
    let text = match id {
        "csv" => ioc_csv(&refs, listed, defanged),
        "json" => ioc_json(&data.record.sha256, &refs, listed, defanged, now),
        _ => {
            let identity = build::identity(
                &data.record,
                &data.tags,
                &data.aliases,
                &data.origins,
                data.archived,
                &[],
                &data.events,
            );
            let mut report = SampleReport::new(identity, now);
            report.indicators = ioc_merged(rows, listed);
            report.custody = build::custody(&data.chain, &data.events).0;
            if id == "misp" {
                misp::render(&report)?
            } else {
                stix::render(&report)?
            }
        }
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)
        .map_err(|error| format!("{}: {error}", folder.display()))?;
    let short: String = data
        .record
        .sha256
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    let time = antinomie_monitor_core::report::utc(now)
        .replace(['-', ':'], "")
        .replace(' ', "-");
    let base = format!("antinomie-sample-iocs-{short}-{time}");
    let mut path = folder.join(format!("{base}{suffix}"));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = folder.join(format!("{base}-{n}{suffix}"));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let library = Library::open(data_dir)?;
    library.record_event(
        &data.record.sha256,
        "analyst",
        CustodyEvent::Exported {
            format: format!(
                "sample IOC set ({name}, {} indicator{}{})",
                rows.len(),
                if rows.len() == 1 { "" } else { "s" },
                if defanged && matches!(id, "csv" | "json") {
                    ", defanged"
                } else {
                    ""
                }
            ),
            signed: "unsigned".into(),
            head: data.chain.head.clone(),
        },
    )?;
    Ok(format!(
        "Exported {} indicator{} to {}",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        path.display()
    ))
}
