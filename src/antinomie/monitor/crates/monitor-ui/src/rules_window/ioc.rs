// SPDX-License-Identifier: GPL-3.0-only
//! The IOC section of the Rule manager: the abuse.ch datasets kept on this
//! machine (state, size, age, terms), their switches and the manual update,
//! and the list of known false positives. Updates run only from buttons.
use super::{theme, Done, Model};
use crate::widgets::{self, table, Tone};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey},
    ioc::{self, feeds::Feed, FeedStatus, STALE_DAYS},
    known_fp,
    ruleset::{self, Fetcher},
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{path::Path, sync::atomic::AtomicBool};

/// The Rule manager tab this section answers to.
pub(super) const TAB: &str = "ioc";

#[derive(Default)]
pub(super) struct State {
    statuses: Vec<FeedStatus>,
    fp: Vec<known_fp::Entry>,
    /// The key is saved (read with the statuses, never the key itself).
    key_masked: Option<String>,
    loaded: bool,
    /// Re-read the statuses on the next frame.
    stale: bool,
    pick: Option<&'static str>,
    #[cfg(test)]
    pub(super) fetcher: Option<std::sync::Arc<dyn Fetcher + Send + Sync>>,
}

/// Routes a request to the keyed or the plain curl: the Auth-Key goes only to
/// the feeds that need it.
pub(super) struct FeedFetcher {
    plain: ruleset::Curl,
    keyed: ruleset::Curl,
}

impl FeedFetcher {
    pub(super) fn new(key: antinomie_monitor_core::api_keys::Secret) -> Self {
        Self {
            plain: ruleset::Curl::default(),
            keyed: ruleset::Curl::default().with_auth_key(key),
        }
    }
}

impl Fetcher for FeedFetcher {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        max_size: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        let needs_key = ioc::FEEDS
            .iter()
            .any(|feed| feed.url == url && feed.needs_key)
            || ruleset::LIVE_PACKS
                .iter()
                .any(|pack| pack.url == url && pack.needs_key);
        let curl = if needs_key { &self.keyed } else { &self.plain };
        curl.fetch(url, dest, max_size, cancel, progress)
    }
}

fn size_text(bytes: u64) -> String {
    crate::values::file_size(bytes)
}

fn thousands(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (at, c) in text.chars().enumerate() {
        if at > 0 && (text.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl Model {
    /// Open on the IOC tab (the IOC section's Datasets button).
    pub(crate) fn show_ioc(&mut self) {
        self.engine = TAB.into();
        self.ioc.stale = true;
    }

    fn refresh_ioc(&mut self, data_dir: &Path) {
        self.ioc.statuses = ioc::status(data_dir);
        self.ioc.fp = known_fp::load(data_dir);
        self.ioc.key_masked = {
            let key = api_keys::get(data_dir, ApiKey::Abusech);
            (!key.is_empty()).then(|| api_keys::masked(&key))
        };
        self.ioc.loaded = true;
        self.ioc.stale = false;
    }

    /// A job finished: read the datasets again.
    pub(super) fn ioc_done(&mut self, text: String) {
        self.status = text;
        self.ioc.stale = true;
    }

    pub(super) fn ioc_tab(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: &mut bool) {
        if !self.ioc.loaded || self.ioc.stale {
            self.refresh_ioc(data_dir);
        }
        ui.label(
            RichText::new(
                "abuse.ch datasets kept on this machine. Triage > IOC matches a run's indicators \
                 against them offline. They change only when you press Download or Update.",
            )
            .color(theme::text()),
        );
        self.notices(ui, outbound);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("abuse.ch Auth-Key").color(theme::muted()));
            match &self.ioc.key_masked {
                Some(masked) => ui.colored_label(theme::good(), format!("set ({masked})")),
                None => ui.colored_label(theme::warn(), "not set"),
            };
            if ui.button("API keys…").clicked() {
                self.requested = Some(super::RulesAction::ApiKeys);
            }
            ui.weak("ThreatFox and URLhaus need it; Feodo Tracker and SSLBL do not.");
        });
        let now = ioc::feeds::now_unix();
        self.ioc_stale_banner(ui, now);
        let busy = self.job.is_some();
        ui.horizontal_wrapped(|ui| {
            let has_key = self.ioc.key_masked.is_some();
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(
                        RichText::new("Download / Update all").color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
                .on_hover_text(if has_key {
                    "Fetch every dataset that is switched on"
                } else {
                    "Fetches the datasets that need no key; ThreatFox and URLhaus wait for the Auth-Key"
                })
                .clicked()
            {
                self.ioc_update(data_dir, *outbound, None);
            }
            if busy && ui.button("Cancel").clicked() {
                self.cancel_job();
            }
            if ui.button("Open datasets folder").clicked() {
                let root = ioc::feeds::root(data_dir);
                let _ = std::fs::create_dir_all(&root);
                crate::folders::show_detached(root);
            }
            let usable = self.ioc.statuses.iter().filter(|s| s.usable()).count();
            let total: u64 = self
                .ioc
                .statuses
                .iter()
                .filter_map(|s| s.meta.as_ref())
                .map(|m| m.size)
                .sum();
            ui.weak(format!(
                "{usable} of {} loaded · {}",
                self.ioc.statuses.len(),
                size_text(total)
            ));
        });
        self.ioc_table(ui, data_dir, *outbound, now);
        self.ioc_details(ui, data_dir, now);
        ui.add_space(8.0);
        self.fp_section(ui, data_dir);
    }

    fn ioc_stale_banner(&self, ui: &mut egui::Ui, now: u64) {
        let old = self
            .ioc
            .statuses
            .iter()
            .filter(|status| status.usable())
            .filter_map(|status| status.meta.as_ref())
            .map(|meta| meta.age_days(now))
            .max();
        if let Some(days) = old.filter(|days| *days > STALE_DAYS) {
            crate::activity::warning(
                ui,
                format!(
                    "The datasets are up to {days} days old (over {STALE_DAYS}). New reports are \
                     missing, so No match is weaker than usual. Each verdict shows its dataset date."
                ),
            );
        }
        let failed: Vec<_> = self
            .ioc
            .statuses
            .iter()
            .filter(|status| status.last_error.is_some())
            .map(|status| status.feed.name)
            .collect();
        if !failed.is_empty() {
            crate::activity::warning(
                ui,
                format!(
                    "The last update of {} failed; the previous copy is still used.",
                    failed.join(", ")
                ),
            );
        }
    }

    fn ioc_table(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool, now: u64) {
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let rows = self.ioc.statuses.clone();
        let mut picked = None;
        let mut toggle = None;
        let mut update = None;
        let busy = self.job.is_some();
        let has_key = self.ioc.key_masked.is_some();
        let height = table::row_height(font) * (rows.len() as f32 + 1.5) + 8.0;
        egui::ScrollArea::horizontal()
            .id_salt("ioc_feeds_scroll")
            .show(ui, |ui| {
                ui.set_min_width(820.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("ioc_feeds")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::exact(44.0))
                    .column(Column::initial(190.0).at_least(110.0).clip(true))
                    .column(Column::initial(220.0).at_least(90.0).clip(true))
                    .column(Column::exact(90.0))
                    .column(Column::exact(100.0))
                    .column(Column::exact(100.0))
                    .column(Column::exact(60.0))
                    .column(Column::exact(150.0))
                    .column(Column::remainder().at_least(90.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        for title in [
                            "On",
                            "Dataset",
                            "Used for",
                            "Records",
                            "Size",
                            "Downloaded",
                            "Age",
                            "Status",
                            "",
                        ] {
                            header.col(|ui| table::head(ui, title));
                        }
                    })
                    .body(|body| {
                        body.rows(table::row_height(font), rows.len(), |mut row| {
                            let status = &rows[row.index()];
                            let feed = status.feed;
                            row.set_selected(self.ioc.pick == Some(feed.id));
                            row.col(|ui| {
                                let mut on = status.enabled;
                                if ui.checkbox(&mut on, "").changed() {
                                    toggle = Some((feed.id, on));
                                }
                            });
                            row.col(|ui| {
                                let text = format!("{} · {}", feed.name, feed.file);
                                table::cell_click(ui, table::Cell::Text, &text);
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Text, feed.used_for);
                            });
                            row.col(|ui| {
                                let text = status
                                    .meta
                                    .as_ref()
                                    .map_or("—".to_owned(), |meta| thousands(meta.records));
                                table::cell_click(ui, table::Cell::Number, &text);
                            });
                            row.col(|ui| {
                                let text = status
                                    .meta
                                    .as_ref()
                                    .map_or("—".to_owned(), |meta| size_text(meta.size));
                                table::cell_click(ui, table::Cell::Number, &text);
                            });
                            row.col(|ui| {
                                let text = status
                                    .meta
                                    .as_ref()
                                    .map_or("—".to_owned(), |meta| meta.date());
                                table::cell_click(ui, table::Cell::Mono, &text);
                            });
                            row.col(|ui| match &status.meta {
                                Some(meta) => {
                                    let days = meta.age_days(now);
                                    let text = format!("{days} d");
                                    if meta.stale(now) {
                                        table::cell_rich(
                                            ui,
                                            table::Cell::Number,
                                            RichText::new(text).color(theme::warn()),
                                        );
                                    } else {
                                        table::cell_click(ui, table::Cell::Number, &text);
                                    }
                                }
                                None => {
                                    table::cell_click(ui, table::Cell::Number, "—");
                                }
                            });
                            row.col(|ui| {
                                let (text, tone) = state_chip(status, now);
                                widgets::chip(ui, text, tone);
                            });
                            row.col(|ui| {
                                let blocked = feed.needs_key && !has_key;
                                let label = if status.meta.is_some() {
                                    "Update"
                                } else {
                                    "Download"
                                };
                                let mut button = ui.add_enabled(
                                    !busy && !blocked,
                                    egui::Button::new(label).small(),
                                );
                                if blocked {
                                    button = button
                                        .on_disabled_hover_text("Needs the abuse.ch Auth-Key");
                                }
                                if button.clicked() {
                                    update = Some(feed);
                                }
                            });
                            if row.response().clicked() {
                                picked = Some(feed.id);
                            }
                        });
                    });
            });
        if let Some(id) = picked {
            self.ioc.pick = Some(id);
        }
        if let Some((id, on)) = toggle {
            match ioc::feeds::set_enabled(data_dir, id, on) {
                Ok(()) => self.ioc.stale = true,
                Err(error) => self.status = error,
            }
        }
        if let Some(feed) = update {
            self.ioc_update(data_dir, outbound, Some(feed));
        }
    }

    fn ioc_details(&self, ui: &mut egui::Ui, data_dir: &Path, now: u64) {
        let Some(status) = self
            .ioc
            .statuses
            .iter()
            .find(|status| Some(status.feed.id) == self.ioc.pick)
        else {
            ui.weak("Select a dataset for its source and terms.");
            return;
        };
        let feed = status.feed;
        ui.separator();
        ui.label(
            RichText::new(format!("{} · {}", feed.name, feed.file))
                .strong()
                .color(theme::text()),
        );
        let line = |ui: &mut egui::Ui, text: String| {
            ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap());
        };
        line(
            ui,
            format!("Source: {}", feed.url.trim_start_matches("https://")),
        );
        line(
            ui,
            format!(
                "Terms: {} ({})",
                feed.license(),
                feed.home.trim_start_matches("https://")
            ),
        );
        line(ui, format!("Matches: {}", feed.used_for));
        if let Some(meta) = &status.meta {
            line(
                ui,
                format!(
                    "Stored copy: {} records, {}, fetched {} ({} days ago), sha256 {}",
                    thousands(meta.records),
                    size_text(meta.size),
                    meta.date(),
                    meta.age_days(now),
                    &meta.sha256[..meta.sha256.len().min(16)]
                ),
            );
            line(
                ui,
                format!(
                    "File: {}",
                    ioc::feeds::data_path(data_dir, feed)
                        .map_or_else(|| "missing".into(), |path| path.display().to_string())
                ),
            );
        }
        if let Some(error) = &status.last_error {
            crate::activity::warning(ui, format!("Last update failed: {error}"));
        }
    }

    fn fp_section(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        theme::section(ui, "Known false positives");
        ui.weak(
            "Values you marked as harmless in Triage > IOC. A match on one is shown as Known FP \
             with your reason and is not counted as Matched.",
        );
        if self.ioc.fp.is_empty() {
            ui.weak("No entries yet. Use Mark as false positive in an indicator's details.");
            return;
        }
        let mut remove = None;
        egui::ScrollArea::vertical()
            .id_salt("ioc_fp_scroll")
            .max_height(180.0)
            .show(ui, |ui| {
                for entry in &self.ioc.fp {
                    ui.horizontal_wrapped(|ui| {
                        if ui.small_button("Remove").clicked() {
                            remove = Some(entry.clone());
                        }
                        ui.label(RichText::new(&entry.value).monospace().color(theme::text()));
                        ui.label(RichText::new(entry.kind.id()).small().color(theme::muted()));
                        if let Some(dataset) = &entry.dataset {
                            ui.label(RichText::new(dataset).small().color(theme::muted()));
                        }
                        ui.label(RichText::new(&entry.reason).color(theme::muted()));
                    });
                }
            });
        if let Some(entry) = remove {
            match known_fp::remove(data_dir, entry.kind, &entry.value, entry.dataset.as_deref()) {
                Ok(_) => self.ioc.stale = true,
                Err(error) => self.status = error,
            }
        }
    }

    /// Download one dataset, or all that are switched on.
    pub(super) fn ioc_update(
        &mut self,
        data_dir: &Path,
        outbound: bool,
        only: Option<&'static Feed>,
    ) {
        if !outbound {
            self.status = "Allow downloads first. Datasets come from threatfox.abuse.ch, \
                           urlhaus.abuse.ch, feodotracker.abuse.ch and sslbl.abuse.ch."
                .into();
            return;
        }
        let dir = data_dir.to_path_buf();
        let key = api_keys::get(&dir, ApiKey::Abusech);
        let key_present = !key.is_empty();
        #[cfg(test)]
        let injected = self.ioc.fetcher.clone();
        self.status = match only {
            Some(feed) => format!("Downloading {}…", feed.name),
            None => "Downloading the datasets…".into(),
        };
        self.spawn_with_progress(move |cancel, progress| {
            let mut show = |line: &str| {
                if let Ok(mut shown) = progress.lock() {
                    *shown = line.to_owned();
                }
            };
            let real = FeedFetcher::new(key);
            #[cfg(test)]
            let fetcher: &dyn Fetcher = match &injected {
                Some(fetcher) => fetcher.as_ref(),
                None => &real,
            };
            #[cfg(not(test))]
            let fetcher: &dyn Fetcher = &real;
            let outcomes = match only {
                Some(feed) => vec![ioc::Outcome {
                    feed,
                    result: ioc::update_feed(&dir, feed, key_present, fetcher, &cancel, &mut show),
                }],
                None => ioc::update_all(&dir, key_present, fetcher, &cancel, &mut show),
            };
            if outcomes
                .iter()
                .any(|outcome| outcome.feed.needs_key && outcome.result.is_ok())
            {
                api_keys::record_use(&dir, ApiKey::Abusech);
            }
            Ok(Done::Ioc(ioc::update_summary(&outcomes)))
        });
    }
}

fn state_chip(status: &FeedStatus, now: u64) -> (&'static str, Tone) {
    match (&status.meta, status.last_error.is_some(), status.enabled) {
        (_, _, false) => ("Off", Tone::Neutral),
        (None, true, _) => ("Failed to download", Tone::Warn),
        (None, false, _) => ("Not downloaded", Tone::Neutral),
        (Some(_), true, _) => ("Update failed", Tone::Warn),
        (Some(meta), false, _) if meta.stale(now) => ("Old", Tone::Warn),
        (Some(_), false, _) => ("Loaded", Tone::Good),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_window::source_tests::{click, joined, render};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    const SIZE: egui::Vec2 = egui::vec2(1200.0, 1100.0);

    // Small files in the feeds' real formats, with reserved example values.
    const THREATFOX: &str = "# \"first_seen_utc\", \"ioc_id\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"fk_malware\", \"malware_alias\", \"malware_printable\", \"last_seen_utc\", \"confidence_level\"\n\"2026-09-02 10:11:12\", \"1831204\", \"203.0.113.45:443\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\"\n";
    const URLHAUS: &str = "# id,dateadded,url,url_status,last_online,threat,tags\n\"1\",\"2026-10-11 08:00:00\",\"http://198.51.100.77/x\",\"online\",\"\",\"malware_download\",\"mirai\"\n";
    const PAYLOADS: &str = "# firstseen,url,filetype,md5,sha256,signature\n\"2026-10-11 08:00:02\",\"http://x.example/a\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n";
    const FEODO: &str = "[{\"ip_address\":\"203.0.113.45\",\"port\":443,\"status\":\"online\",\"first_seen\":\"2026-08-01 00:00:00\",\"malware\":\"Dridex\"},{\"ip_address\":\"198.51.100.23\",\"port\":8443,\"status\":\"offline\",\"malware\":\"QakBot\"}]";
    const SSLBL_IP: &str = "# Firstseen,DstIP,DstPort\n2026-08-19 10:00:00,203.0.113.45,443\n";
    const SSLBL_JA3: &str = "# ja3_md5,Firstseen,Lastseen,Listingreason\nf6d64cbcb6dead5e8e864400f056fa32,2026-08-19 10:00:00,2026-10-01 10:00:00,Gafgyt C&C\n";
    const SSLBL_CERT: &str = "# Listingdate,SHA1,Listingreason\n2026-08-19 10:00:00,2f22765d04931a078909145ca628d2264c852d7d,Gafgyt C&C\n";

    /// Serves fixtures by URL and counts requests; no network.
    #[derive(Default)]
    struct Served {
        files: BTreeMap<String, Result<Vec<u8>, String>>,
        calls: Mutex<Vec<String>>,
    }

    impl Fetcher for Served {
        fn fetch(
            &self,
            url: &str,
            dest: &Path,
            _max: u64,
            _cancel: &AtomicBool,
            _progress: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            self.calls.lock().unwrap().push(url.to_owned());
            match self.files.get(url) {
                Some(Ok(bytes)) => std::fs::write(dest, bytes).map_err(|e| e.to_string()),
                Some(Err(error)) => Err(error.clone()),
                None => Err(format!("{url} answered HTTP 404")),
            }
        }
    }

    fn served(failing: &[&str]) -> Served {
        let mut served = Served::default();
        for (id, text) in [
            ("threatfox", THREATFOX),
            ("urlhaus", URLHAUS),
            ("urlhaus-payloads", PAYLOADS),
            ("feodo", FEODO),
            ("sslbl-ip", SSLBL_IP),
            ("sslbl-ja3", SSLBL_JA3),
            ("sslbl-cert", SSLBL_CERT),
        ] {
            let url = ioc::feeds::feed(id).unwrap().url.to_owned();
            let body = if failing.contains(&id) {
                Err("download failed: Could not resolve host".to_owned())
            } else {
                Ok(text.as_bytes().to_vec())
            };
            served.files.insert(url, body);
        }
        served
    }

    struct Fixture {
        dir: std::path::PathBuf,
        ctx: egui::Context,
        model: Model,
        outbound: bool,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ant-rules-ioc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let ctx = egui::Context::default();
            crate::theme::install(&ctx);
            // Loading the registry is not under test: mark it done.
            let model = Model {
                engine: TAB.into(),
                loaded: true,
                ..Default::default()
            };
            Self {
                dir,
                ctx,
                model,
                outbound: false,
            }
        }

        fn frame(&mut self) -> String {
            joined(&render(
                &self.ctx,
                &mut self.model,
                &self.dir,
                SIZE,
                Vec::new(),
                &mut self.outbound,
            ))
        }

        fn click(&mut self, label: &str) {
            // Let the layout hold still, then press the first text with this label.
            self.frame();
            let shown = render(
                &self.ctx,
                &mut self.model,
                &self.dir,
                SIZE,
                Vec::new(),
                &mut self.outbound,
            );
            let at = shown
                .iter()
                .find(|(text, _, _)| text == label)
                .unwrap_or_else(|| panic!("no {label}: {}", joined(&shown)))
                .1
                .center();
            click(
                &self.ctx,
                &mut self.model,
                &self.dir,
                SIZE,
                &mut self.outbound,
                at,
            );
        }

        fn until(&mut self, wanted: &str) -> String {
            let start = std::time::Instant::now();
            loop {
                let shown = self.frame();
                if shown.contains(wanted) {
                    return shown;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(120),
                    "{wanted:?} never appeared: {shown}"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn the_section_lists_all_feeds_with_terms_and_asks_for_permission_first() {
        let mut fixture = Fixture::new("list");
        let shown = fixture.frame();
        let shown = if shown.contains("ThreatFox") {
            shown
        } else {
            fixture.frame()
        };
        for feed in ioc::FEEDS {
            assert!(
                shown.contains(feed.name),
                "{} missing in {shown}",
                feed.name
            );
            assert!(shown.contains(feed.file), "{}", feed.file);
        }
        assert!(shown.contains("Not downloaded"), "{shown}");
        assert!(shown.contains("not set"), "{shown}");
        assert!(shown.contains("Downloads are off"), "{shown}");
        assert!(shown.contains("Known false positives"), "{shown}");
        assert!(shown.contains("0 of 7 loaded"), "{shown}");
        // Nothing was fetched or written by looking.
        assert!(!ioc::feeds::root(&fixture.dir).join("feeds").exists());
    }

    #[test]
    fn update_all_downloads_through_the_injected_fetcher_and_names_failures() {
        let mut fixture = Fixture::new("update");
        fixture.outbound = true;
        api_keys::set(&fixture.dir, ApiKey::Abusech, "ioc-test-key-0001").unwrap();
        let server = Arc::new(served(&["sslbl-ja3"]));
        fixture.model.ioc.fetcher = Some(server.clone());
        fixture.frame();
        fixture.click("Download / Update all");
        let shown = fixture.until("Failed: SSLBL JA3");
        assert!(shown.contains("Updated 6 of 7"), "{shown}");
        assert_eq!(server.calls.lock().unwrap().len(), 7);
        let shown = fixture.until("6 of 7 loaded");
        assert!(
            shown.contains("The last update of SSLBL JA3 failed"),
            "{shown}"
        );
        assert!(shown.contains("Loaded"), "{shown}");
        assert!(shown.contains("Failed to download"), "{shown}");
        // The key shows its tail only, and the use time was recorded.
        assert!(shown.contains("(…0001)"), "{shown}");
        assert!(!shown.contains("ioc-test-key"), "{shown}");
        assert!(api_keys::last_used(&fixture.dir, ApiKey::Abusech).is_some());
    }

    #[test]
    fn no_request_is_made_while_downloads_are_not_allowed() {
        let mut fixture = Fixture::new("denied");
        let server = Arc::new(served(&[]));
        fixture.model.ioc.fetcher = Some(server.clone());
        fixture.frame();
        fixture.click("Download / Update all");
        let shown = fixture.frame();
        assert!(shown.contains("Allow downloads first"), "{shown}");
        assert!(server.calls.lock().unwrap().is_empty());
        assert!(fixture.model.job.is_none());
    }

    #[test]
    fn an_old_dataset_is_flagged_and_a_failed_update_says_which_feed() {
        let mut fixture = Fixture::new("old");
        let feed = ioc::feeds::feed("feodo").unwrap();
        let dir = ioc::feeds::root(&fixture.dir).join("feeds").join(feed.id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data-1-a.txt"), FEODO).unwrap();
        let old = ioc::feeds::now_unix() - 41 * 86_400;
        std::fs::write(
            dir.join("meta.json"),
            serde_json::json!({"schema":1,"id":"feodo","file":"data-1-a.txt","fetched_unix":old,
                "records":2,"size":FEODO.len(),"sha256":"ab".repeat(32),"url":feed.url})
            .to_string(),
        )
        .unwrap();
        let shown = fixture.frame();
        let shown = if shown.contains("days old") {
            shown
        } else {
            fixture.frame()
        };
        assert!(shown.contains("up to 41 days old (over 14)"), "{shown}");
        assert!(shown.contains("41 d"), "{shown}");
        assert!(shown.contains("Old"), "{shown}");
    }

    #[test]
    fn false_positive_entries_are_listed_and_can_be_removed() {
        let mut fixture = Fixture::new("fp");
        known_fp::add(
            &fixture.dir,
            ioc::Kind::Domain,
            "pool.ntp.example",
            None,
            "Time pool.",
            1,
        )
        .unwrap();
        let shown = fixture.frame();
        let shown = if shown.contains("pool.ntp.example") {
            shown
        } else {
            fixture.frame()
        };
        assert!(shown.contains("Time pool."), "{shown}");
        fixture.click("Remove");
        let shown = fixture.frame();
        let shown = if shown.contains("No entries yet") {
            shown
        } else {
            fixture.frame()
        };
        assert!(shown.contains("No entries yet"), "{shown}");
        assert!(known_fp::load(&fixture.dir).is_empty());
    }
}
