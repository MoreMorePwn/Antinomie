// SPDX-License-Identifier: GPL-3.0-only
//! The abuse.ch tab of the IDS engine in the Rule manager: six Suricata packs
//! abuse.ch regenerates about every five minutes, with a check for updates
//! (which never asks a pack more often than every five minutes), the age of
//! what is installed, and an update on demand.
use super::{theme, Done, Model};
use crate::widgets::{self, table, Tone};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey},
    ioc::feeds::now_unix,
    ruleset::{self, Fetcher, LiveState, LiveStatus, LIVE_PACKS},
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::path::Path;

#[derive(Default)]
pub(super) struct State {
    pick: Option<&'static str>,
    /// What the last check or install did, kept across the registry reload.
    pub(super) note: String,
}

fn ago(now: u64, then: u64) -> String {
    let seconds = now.saturating_sub(then);
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86_400 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86_400),
    }
}

fn state_chip(state: &LiveState) -> (&'static str, Tone) {
    match state.status {
        LiveStatus::NotInstalled => ("Not installed", Tone::Neutral),
        LiveStatus::Unchecked => ("Not checked", Tone::Neutral),
        LiveStatus::Current => ("Up to date", Tone::Good),
        LiveStatus::UpdateAvailable => ("Update available", Tone::Accent),
        LiveStatus::Retired => ("Retired upstream", Tone::Neutral),
    }
}

impl Model {
    pub(super) fn abusech_tab(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: &mut bool) {
        let now = now_unix();
        let states = ruleset::live_states(data_dir, &self.registry);
        let key = api_keys::get(data_dir, ApiKey::Abusech);
        let has_key = !key.is_empty();
        ui.label(
            RichText::new(
                "Suricata rule packs from abuse.ch. abuse.ch rebuilds them about every five \
                 minutes, so Check for updates compares the live file with what is installed \
                 (at most once in five minutes per pack) and Update installs the newest. \
                 Nothing is fetched until you press a button.",
            )
            .color(theme::text()),
        );
        self.notices(ui, outbound);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("abuse.ch Auth-Key").color(theme::muted()));
            if has_key {
                ui.colored_label(theme::good(), format!("set ({})", api_keys::masked(&key)));
            } else {
                ui.colored_label(theme::warn(), "not set");
            }
            if ui.button("API keys…").clicked() {
                self.requested = Some(super::RulesAction::ApiKeys);
            }
            ui.weak("ThreatFox and URLhaus need it; Feodo Tracker and SSLBL do not.");
        });
        let busy = self.job.is_some();
        if !self.live.note.is_empty() {
            ui.add(egui::Label::new(RichText::new(&self.live.note).color(theme::text())).wrap());
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("Check all for updates"))
                .clicked()
            {
                self.live_run(data_dir, *outbound, None, false);
            }
            if busy && ui.button("Cancel").clicked() {
                self.cancel_job();
            }
        });
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let height = table::row_height(font) * (states.len() as f32 + 1.5) + 8.0;
        let mut picked = None;
        let mut action = None;
        egui::ScrollArea::horizontal()
            .id_salt("abusech_packs_scroll")
            .show(ui, |ui| {
                ui.set_min_width(860.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("abusech_packs")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::initial(230.0).at_least(120.0).clip(true))
                    .column(Column::exact(70.0))
                    .column(Column::exact(100.0))
                    .column(Column::exact(100.0))
                    .column(Column::exact(130.0))
                    .column(Column::remainder().at_least(180.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        for title in ["Pack", "Rules", "Installed", "Checked", "State", ""] {
                            header.col(|ui| table::head(ui, title));
                        }
                    })
                    .body(|body| {
                        body.rows(table::row_height(font), states.len(), |mut row| {
                            let state = &states[row.index()];
                            let pack = state.pack;
                            row.set_selected(self.live.pick == Some(pack.id));
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Text, pack.name);
                            });
                            row.col(|ui| {
                                let rules = state
                                    .installed
                                    .as_ref()
                                    .map(|installed| installed.rules)
                                    .or(state.checked.as_ref().map(|checked| checked.rules));
                                let text =
                                    rules.map_or("—".to_owned(), |rules| rules.to_string());
                                table::cell_click(ui, table::Cell::Number, &text);
                            });
                            row.col(|ui| {
                                let text = state.installed.as_ref().map_or("—".to_owned(), |i| {
                                    if i.fetched_unix == 0 {
                                        "yes".to_owned()
                                    } else {
                                        ago(now, i.fetched_unix)
                                    }
                                });
                                table::cell_click(ui, table::Cell::Text, &text);
                            });
                            row.col(|ui| {
                                let text = state
                                    .checked
                                    .as_ref()
                                    .map_or("—".to_owned(), |checked| ago(now, checked.at_unix));
                                table::cell_click(ui, table::Cell::Text, &text);
                            });
                            row.col(|ui| {
                                let (text, tone) = state_chip(state);
                                widgets::chip(ui, text, tone);
                            });
                            row.col(|ui| {
                                let blocked = pack.needs_key && !has_key;
                                ui.add_enabled_ui(!busy && !blocked, |ui| {
                                    if ui.small_button("Check").clicked() {
                                        action = Some((pack.id, false));
                                    }
                                    let label = match state.status {
                                        LiveStatus::NotInstalled => "Install",
                                        _ => "Update",
                                    };
                                    let enabled = !matches!(
                                        state.status,
                                        LiveStatus::Current | LiveStatus::Retired
                                    );
                                    if ui
                                        .add_enabled(enabled, egui::Button::new(label).small())
                                        .clicked()
                                    {
                                        action = Some((pack.id, true));
                                    }
                                });
                                if blocked {
                                    ui.weak("needs the Auth-Key");
                                }
                            });
                            if row.response().clicked() {
                                picked = Some(pack.id);
                            }
                        });
                    });
            });
        if let Some(id) = picked {
            self.live.pick = LIVE_PACKS
                .iter()
                .find(|pack| pack.id == id)
                .map(|pack| pack.id);
        }
        if let Some((id, install)) = action {
            self.live_run(data_dir, *outbound, Some(id), install);
        }
        let Some(state) = states
            .iter()
            .find(|state| Some(state.pack.id) == self.live.pick)
        else {
            ui.weak("Select a pack for its source and terms.");
            return;
        };
        self.live_details(ui, state, now);
    }

    fn live_details(&self, ui: &mut egui::Ui, state: &LiveState, now: u64) {
        let pack = state.pack;
        ui.separator();
        ui.label(RichText::new(pack.name).strong().color(theme::text()));
        let line = |ui: &mut egui::Ui, text: String| {
            ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap());
        };
        line(ui, format!("Matches: {}", pack.matches));
        line(
            ui,
            format!(
                "Source: {}",
                pack.url_display().trim_start_matches("https://")
            ),
        );
        line(ui, format!("License: {}", pack.license));
        if let Some(installed) = &state.installed {
            line(
                ui,
                format!(
                    "Installed: {} · {} rules · fetched {}{}",
                    installed.version,
                    installed.rules,
                    if installed.fetched_unix == 0 {
                        "at an unknown time".to_owned()
                    } else {
                        ago(now, installed.fetched_unix)
                    },
                    if installed.enabled {
                        ""
                    } else {
                        " · switched off in the Installed tab"
                    }
                ),
            );
        }
        if let Some(checked) = &state.checked {
            line(
                ui,
                format!(
                    "Last snapshot: {} rules, abuse.ch's own time {}, looked at {}{}",
                    checked.rules,
                    checked.stamp,
                    ago(now, checked.at_unix),
                    match checked.wait(now) {
                        0 => String::new(),
                        wait => format!(" · the next look is possible in {wait} s"),
                    }
                ),
            );
        }
        if state.status == LiveStatus::Retired {
            line(
                ui,
                "Retired upstream: abuse.ch now serves this file empty, so there is nothing to install.".to_owned(),
            );
        }
        for limit in pack.limits {
            line(ui, (*limit).to_owned());
        }
    }

    /// Check one pack (or all), and install it when `install` is set.
    pub(super) fn live_run(
        &mut self,
        data_dir: &Path,
        outbound: bool,
        only: Option<&'static str>,
        install: bool,
    ) {
        if !outbound {
            self.status = "Allow downloads first. These packs come from abuse.ch hosts.".into();
            return;
        }
        let dir = data_dir.to_path_buf();
        let key = api_keys::get(&dir, ApiKey::Abusech);
        let key_present = !key.is_empty();
        #[cfg(test)]
        let injected = self.ioc.fetcher.clone();
        self.status = "Asking abuse.ch…".into();
        self.spawn_with_progress(move |cancel, progress| {
            let mut show = |line: &str| {
                if let Ok(mut shown) = progress.lock() {
                    *shown = line.to_owned();
                }
            };
            let real = ruleset::Curl::default();
            #[cfg(test)]
            let fetcher: &dyn Fetcher = match &injected {
                Some(fetcher) => fetcher.as_ref(),
                None => &real,
            };
            #[cfg(not(test))]
            let fetcher: &dyn Fetcher = &real;
            let now = now_unix();
            let mut lines = Vec::new();
            let mut installed_any = false;
            for pack in LIVE_PACKS
                .iter()
                .filter(|pack| only.is_none_or(|id| id == pack.id))
            {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    lines.push("Cancelled.".to_owned());
                    break;
                }
                if pack.needs_key && !key_present {
                    lines.push(format!("{} needs the Auth-Key", pack.name));
                    continue;
                }
                if install {
                    match ruleset::install_live(&dir, pack, &key, fetcher, now, &cancel, &mut show)
                    {
                        Ok(done) => {
                            installed_any = true;
                            lines.push(if done.already_installed {
                                format!("{} is already the newest snapshot", pack.name)
                            } else {
                                format!("{} installed with {} rules", pack.name, done.rules)
                            });
                        }
                        Err(error) => lines.push(error),
                    }
                } else {
                    match ruleset::check_live(&dir, pack, &key, fetcher, now, &cancel, &mut show) {
                        Ok((checked, _)) if pack.retired_if_empty && checked.rules == 0 => lines
                            .push(format!(
                                "{}: retired upstream; abuse.ch now serves an empty file",
                                pack.name
                            )),
                        Ok((checked, true)) => lines.push(format!(
                            "{}: snapshot {} ({} rules)",
                            pack.name, checked.stamp, checked.rules
                        )),
                        Ok((checked, false)) => lines.push(format!(
                            "{}: checked {} s ago; abuse.ch is asked at most once in five minutes",
                            pack.name,
                            now.saturating_sub(checked.at_unix)
                        )),
                        Err(error) => lines.push(error),
                    }
                }
            }
            if pack_uses_key(only, key_present) {
                api_keys::record_use(&dir, ApiKey::Abusech);
            }
            Ok(Done::Live(lines.join(" · "), installed_any))
        });
    }
}

fn pack_uses_key(only: Option<&str>, key_present: bool) -> bool {
    key_present
        && LIVE_PACKS
            .iter()
            .filter(|pack| only.is_none_or(|id| id == pack.id))
            .any(|pack| pack.needs_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_window::{
        page::Tab,
        source_tests::{joined, render},
    };
    use std::{
        sync::{atomic::AtomicBool, Arc, Mutex},
        thread,
        time::Duration,
    };

    const SIZE: egui::Vec2 = egui::vec2(1300.0, 1100.0);
    const SIP: &str = "# abuse.ch SSLBL botnet C2 IP rules (fixture)\n# Last updated: 2026-10-22 10:15:00 UTC\n\
alert tls $HOME_NET any -> [203.0.113.45] 443 (msg:\"ABUSE.ch Botnet C2 (Gafgyt)\"; flow:established,to_server; sid:902202; rev:1;)\n\
alert tls $HOME_NET any -> [198.51.100.23] 8443 (msg:\"ABUSE.ch Botnet C2 (QakBot)\"; flow:established,to_server; sid:902203; rev:1;)\n";

    #[derive(Default)]
    struct Served {
        body: Mutex<String>,
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
            std::fs::write(dest, self.body.lock().unwrap().as_str()).map_err(|e| e.to_string())
        }
    }

    struct Fixture {
        dir: std::path::PathBuf,
        ctx: egui::Context,
        model: Model,
        outbound: bool,
        server: Arc<Served>,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ant-rules-live-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let ctx = egui::Context::default();
            crate::theme::install(&ctx);
            let server = Arc::new(Served::default());
            *server.body.lock().unwrap() = SIP.to_owned();
            let mut model = Model {
                engine: "ids".into(),
                tab: Tab::Abusech,
                loaded: true,
                ..Default::default()
            };
            model.ioc.fetcher = Some(server.clone());
            Self {
                dir,
                ctx,
                model,
                outbound: true,
                server,
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

        fn until(&mut self, wanted: &str) -> String {
            let start = std::time::Instant::now();
            loop {
                let shown = self.frame();
                if shown.contains(wanted) && self.model.job.is_none() {
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
    fn the_ids_engine_lists_the_six_packs_and_fetches_nothing_by_looking() {
        let mut fixture = Fixture::new("list");
        fixture.frame();
        let shown = fixture.frame();
        for pack in LIVE_PACKS {
            assert!(shown.contains(pack.name), "{} missing: {shown}", pack.name);
        }
        assert!(shown.contains("Not installed"), "{shown}");
        assert!(shown.contains("Check all for updates"), "{shown}");
        assert!(shown.contains("not set"), "the Auth-Key line: {shown}");
        assert!(shown.contains("needs the Auth-Key"), "{shown}");
        assert!(fixture.server.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_pack_installs_updates_and_is_not_asked_again_within_five_minutes() {
        let mut fixture = Fixture::new("flow");
        let dir = fixture.dir.clone();
        fixture
            .model
            .live_run(&dir, true, Some("abuse-ch-sslbl-ip"), true);
        let shown = fixture.until("installed with 2 rules");
        assert!(shown.contains("abuse.ch SSLBL botnet C2 IPs"), "{shown}");
        let shown = fixture.until("Up to date");
        assert!(shown.contains("Up to date"), "{shown}");
        assert_eq!(fixture.server.calls.lock().unwrap().len(), 1);
        // A check straight after reuses the answer: no second request.
        fixture
            .model
            .live_run(&dir, true, Some("abuse-ch-sslbl-ip"), false);
        let shown = fixture.until("at most once in five minutes");
        assert!(shown.contains("checked"), "{shown}");
        assert_eq!(fixture.server.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn nothing_is_requested_until_downloads_are_allowed() {
        let mut fixture = Fixture::new("denied");
        fixture.outbound = false;
        let dir = fixture.dir.clone();
        fixture.model.live_run(&dir, false, None, false);
        let shown = fixture.frame();
        assert!(shown.contains("Allow downloads first"), "{shown}");
        assert!(fixture.server.calls.lock().unwrap().is_empty());
        assert!(fixture.model.job.is_none());
    }

    #[test]
    fn a_pack_that_needs_the_key_is_reported_not_requested() {
        let mut fixture = Fixture::new("key");
        let dir = fixture.dir.clone();
        fixture
            .model
            .live_run(&dir, true, Some("abuse-ch-threatfox"), false);
        let shown = fixture.until("needs the Auth-Key");
        assert!(
            shown.contains("abuse.ch ThreatFox needs the Auth-Key"),
            "{shown}"
        );
        assert!(fixture.server.calls.lock().unwrap().is_empty());
    }
}
