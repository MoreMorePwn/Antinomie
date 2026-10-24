// SPDX-License-Identifier: GPL-3.0-only
//! Triage > IOC: the indicators of one run (endpoints, domains, URLs, TLS
//! fingerprints, files), where each came from and whether it matches an
//! abuse.ch dataset on this machine. Matching is offline and the verdict
//! carries the dataset's date. "No match" is never a clean result.
use super::ioc_scan::{self, Capture, IocScan};
use super::*;
use crate::widgets::{self, TabItem, Tone};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey, Secret},
    ioc::{
        export, feeds,
        indicator::{Indicator, Source, Type},
        online,
        verdict::{counts, Counts, OnlineResults, Outcome, Verdict},
    },
    known_fp,
};
use std::collections::BTreeMap;

mod detail;
mod list;
mod summary_tab;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Summary,
    Of(Type),
}

/// What an online check brought back.
struct OnlineDone {
    results: OnlineResults,
    asked: usize,
    found: usize,
    skipped: usize,
    error: Option<String>,
}

#[derive(Default)]
pub(super) struct View {
    tab: Tab,
    drafts: BTreeMap<Type, String>,
    outcome: Option<Outcome>,
    selected: BTreeMap<Type, String>,
    /// What the verdicts below were made from.
    made_from: Option<(usize, u64, usize)>,
    verdicts: Vec<Verdict>,
    counts: BTreeMap<Type, Counts>,
    fp: Vec<known_fp::Entry>,
    /// The answers the online check gave for this run.
    online: OnlineResults,
    /// Bumps whenever the false positives or the online answers change.
    version: u64,
    run_dir: Option<std::path::PathBuf>,
    data_dir: Option<std::path::PathBuf>,
    curl: std::path::PathBuf,
    /// The online check is on for this session; never saved.
    online_on: bool,
    job: Option<(std::sync::mpsc::Receiver<OnlineDone>, Arc<AtomicBool>)>,
    status: Option<(String, bool)>,
    listings: BTreeMap<Type, list::Listing>,
    reason: String,
    open_datasets: bool,
    wants_refresh: bool,
    key_masked: Option<String>,
    key_read: Option<Instant>,
    /// The false-positive file as last seen (size, change time), and when it was looked at.
    fp_seen: Option<(u64, Option<std::time::SystemTime>)>,
    fp_checked: Option<Instant>,
    /// The datasets as last seen: when they change the scan is made again.
    datasets_seen: Option<String>,
    /// The feeds' chips for the status bar: name and whether a copy is loaded.
    chips: Vec<(String, bool)>,
}

impl View {
    pub(super) fn set_curl(&mut self, curl: &std::path::Path) {
        if self.curl != curl {
            self.curl = curl.to_path_buf();
        }
    }

    pub(super) fn set_data_dir(&mut self, dir: &std::path::Path) {
        if self.data_dir.as_deref() != Some(dir) {
            self.data_dir = Some(dir.to_path_buf());
            self.made_from = None;
        }
    }

    /// The Datasets button was pressed.
    pub(super) fn take_open_datasets(&mut self) -> bool {
        std::mem::take(&mut self.open_datasets)
    }

    /// The false positives or the online answers changed: the scan should list
    /// the findings again.
    pub(super) fn take_refresh(&mut self) -> bool {
        std::mem::take(&mut self.wants_refresh)
    }

    /// A different run: nothing of the last one carries over.
    pub(super) fn reset_run(&mut self, run_dir: Option<&std::path::Path>) {
        self.made_from = None;
        self.verdicts.clear();
        self.counts.clear();
        self.online = OnlineResults::default();
        self.selected.clear();
        self.listings.clear();
        self.status = None;
        self.job = None;
        self.run_dir = run_dir.map(std::path::Path::to_path_buf);
        if let Some(dir) = run_dir {
            self.online = online::load(dir);
        }
    }

    fn key_state(&mut self) -> Option<&str> {
        let due = self
            .key_read
            .is_none_or(|read| read.elapsed() > Duration::from_secs(2));
        if due {
            self.key_read = Some(Instant::now());
            self.key_masked = self.data_dir.as_deref().and_then(|dir| {
                let key = api_keys::get(dir, ApiKey::Abusech);
                (!key.is_empty()).then(|| api_keys::masked(&key))
            });
        }
        self.key_masked.as_deref()
    }

    fn false_positive_stat(&self) -> Option<(u64, Option<std::time::SystemTime>)> {
        let dir = self.data_dir.as_ref()?;
        let meta = std::fs::metadata(dir.join("known-false-positives.json")).ok()?;
        Some((meta.len(), meta.modified().ok()))
    }

    /// The list of known false positives can be changed in the Rule manager
    /// too: notice it, so verdicts and findings follow.
    fn watch_false_positives(&mut self) {
        let due = self
            .fp_checked
            .is_none_or(|checked| checked.elapsed() > Duration::from_secs(1));
        if !due {
            return;
        }
        let first = self.fp_checked.is_none();
        self.fp_checked = Some(Instant::now());
        let seen = self.false_positive_stat();
        if !first && seen != self.fp_seen {
            self.version += 1;
            self.wants_refresh = true;
        }
        self.fp_seen = seen;
        // A dataset updated in the Rule manager: match the run again.
        let datasets = self.data_dir.as_deref().map(ioc_scan::signature);
        if !first && datasets != self.datasets_seen {
            self.wants_refresh = true;
        }
        self.datasets_seen = datasets;
        self.chips = self.feed_states();
    }

    /// Make the verdicts for the scan on screen (again, when it, the false
    /// positives or the online answers changed).
    pub(super) fn sync(&mut self, ioc: Option<&IocScan>) {
        self.watch_false_positives();
        let Some(ioc) = ioc else {
            if self.made_from.take().is_some() {
                self.verdicts.clear();
                self.counts.clear();
            }
            return;
        };
        // The scan itself (its address, which a new scan never shares while the
        // old one is held), the false-positive and online version, and its size.
        let wanted = (
            std::ptr::from_ref(ioc) as usize,
            self.version,
            ioc.indicators.len(),
        );
        if self.made_from.as_ref() == Some(&wanted) {
            return;
        }
        if let Some(dir) = &self.data_dir {
            self.fp = known_fp::load(dir);
        }
        self.verdicts = ioc_scan::verdicts(ioc, &self.fp, &self.online);
        self.counts = counts(&ioc.indicators, &self.verdicts);
        self.listings.clear();
        self.made_from = Some(wanted);
    }

    /// Verdict counts of one type, or of all.
    fn count_of(&self, ty: Option<Type>) -> Counts {
        let mut all = Counts::default();
        for (kind, count) in &self.counts {
            if ty.is_none_or(|ty| ty == *kind) {
                all.matched += count.matched;
                all.known_fp += count.known_fp;
                all.no_match += count.no_match;
                all.not_checked += count.not_checked;
            }
        }
        all
    }

    /// What the Summary page and the tab badge say.
    pub(super) fn headline(&self, ioc: Option<&IocScan>) -> Option<(usize, usize, String)> {
        let ioc = ioc?;
        let total = self.count_of(None);
        let date = ioc
            .scan
            .loaded
            .iter()
            .map(|feed| feed.date.clone())
            .min()
            .unwrap_or_default();
        Some((total.matched, total.all(), date))
    }

    fn message(&mut self, text: impl Into<String>, error: bool) {
        self.status = Some((text.into(), error));
    }

    /// Mark a match as a false positive: one entry per dataset that lists it.
    fn mark(&mut self, indicator: &Indicator, verdict: &Verdict) {
        let Some(dir) = self.data_dir.clone() else {
            return;
        };
        let reason = if self.reason.trim().is_empty() {
            "Marked as a false positive in Triage > IOC.".to_owned()
        } else {
            self.reason.trim().to_owned()
        };
        let now = feeds::now_unix();
        let mut done = 0;
        let mut seen = std::collections::BTreeSet::new();
        for found in &verdict.matches {
            let key = (
                found.lookup.kind,
                found.lookup.value.clone(),
                found.record.feed.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            match known_fp::add(
                &dir,
                found.lookup.kind,
                &found.lookup.value,
                Some(&found.record.feed),
                &reason,
                now,
            ) {
                Ok(()) => done += 1,
                Err(error) => {
                    self.message(error, true);
                    return;
                }
            }
        }
        if done > 0 {
            self.reason.clear();
            self.version += 1;
            self.wants_refresh = true;
            self.fp_seen = self.false_positive_stat();
            self.message(
                format!(
                    "{} added to the known false positives. It is no longer counted as matched.",
                    indicator.value
                ),
                false,
            );
        }
    }

    /// Ask abuse.ch about public values with no offline match.
    fn start_online(&mut self, lookups: Vec<antinomie_monitor_core::ioc::indicator::Lookup>) {
        if self.job.is_some() {
            return;
        }
        let Some(dir) = self.data_dir.clone() else {
            return;
        };
        let key: Secret = api_keys::get(&dir, ApiKey::Abusech);
        if key.is_empty() {
            self.message(
                "Online lookups need the abuse.ch Auth-Key (Tools > API keys).",
                true,
            );
            return;
        }
        if lookups.is_empty() {
            self.message(
                "Nothing to send: every public value already has an offline answer.",
                false,
            );
            return;
        }
        let curl = self.curl.clone();
        let mut results = self.online.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let spawned = std::thread::Builder::new()
            .name("ioc-online".into())
            .spawn(move || {
                let transport = online::CurlTransport { curl };
                let done = online::check(
                    &transport,
                    &key,
                    &lookups,
                    feeds::now_unix(),
                    &mut results,
                    &flag,
                );
                if done.asked > 0 {
                    api_keys::record_use(&dir, ApiKey::Abusech);
                }
                let _ = sender.send(OnlineDone {
                    results,
                    asked: done.asked,
                    found: done.found,
                    skipped: done.skipped,
                    error: done.error,
                });
            });
        match spawned {
            Ok(_) => {
                self.job = Some((receiver, cancel));
                self.message("Asking abuse.ch…", false);
            }
            Err(error) => self.message(error.to_string(), true),
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some((receiver, _)) = &self.job else {
            return;
        };
        match receiver.try_recv() {
            Ok(done) => {
                self.job = None;
                if done.asked > 0 {
                    self.online = done.results;
                    if let Some(dir) = &self.run_dir {
                        if let Err(error) = online::save(dir, &self.online) {
                            self.message(error, true);
                        }
                    }
                    self.version += 1;
                    self.wants_refresh = true;
                }
                let mut text = format!(
                    "Online check: {} value{} sent to abuse.ch, {} found.",
                    done.asked,
                    if done.asked == 1 { "" } else { "s" },
                    done.found
                );
                if done.skipped > 0 {
                    text.push_str(&format!(
                        " {} more were left for the next press.",
                        done.skipped
                    ));
                }
                match done.error {
                    Some(error) => self.message(format!("{text} {error}"), true),
                    None => self.message(text, false),
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.job = None;
                self.message("The online check ended without an answer.", true);
            }
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        if let Some((_, cancel)) = &self.job {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

fn outcome_tone(outcome: Outcome) -> Tone {
    match outcome {
        Outcome::Matched => Tone::Error,
        Outcome::KnownFp => Tone::Info,
        Outcome::NoMatch => Tone::Plain,
        Outcome::NotChecked => Tone::Neutral,
    }
}

/// The verdict as a chip.
fn verdict_chip(ui: &mut egui::Ui, verdict: &Verdict) {
    let online = verdict
        .primary()
        .is_some_and(|found| found.online_at.is_some());
    let text = if verdict.outcome == Outcome::Matched && online {
        "Matched · online".to_owned()
    } else {
        verdict.outcome.label().to_owned()
    };
    widgets::chip(ui, text, outcome_tone(verdict.outcome));
}

/// The line under the verdict chip.
fn verdict_line(verdict: &Verdict) -> String {
    match verdict.outcome {
        Outcome::Matched => verdict.primary().map_or_else(String::new, |found| {
            format!(
                "{} · {} · {} · first seen {}",
                if found.record.family.is_empty() {
                    "no family"
                } else {
                    &found.record.family
                },
                ioc_scan::dataset_name(&found.record.feed),
                found
                    .record
                    .confidence
                    .map_or("no confidence".to_owned(), |c| format!("{c}%")),
                found.record.first_seen,
            )
        }),
        Outcome::KnownFp => verdict
            .excused
            .as_ref()
            .map_or_else(String::new, |(found, entry)| {
                format!(
                    "{} · dataset {}",
                    if entry.reason.is_empty() {
                        "known false positive"
                    } else {
                        &entry.reason
                    },
                    verdict
                        .date
                        .clone()
                        .unwrap_or_else(|| ioc_scan::dataset_name(&found.record.feed).to_owned())
                )
            }),
        Outcome::NoMatch => format!(
            "dataset {}{}",
            verdict.date.clone().unwrap_or_default(),
            if verdict.partial() {
                format!(
                    " · {} of {} feeds",
                    verdict.feeds_used, verdict.feeds_needed
                )
            } else {
                String::new()
            }
        ),
        Outcome::NotChecked => verdict.why.clone(),
    }
}

impl TriageView {
    /// Keep the IOC view in step with the scan: the run, the folders, the
    /// verdicts.
    pub(super) fn ioc_tick(&mut self, ctx: &egui::Context) {
        let ioc = self.scan.as_ref().and_then(|scan| scan.ioc.clone());
        self.ioc.poll(ctx);
        self.ioc.sync(ioc.as_deref());
        if self.ioc.take_refresh() {
            self.request_refresh();
        }
    }

    /// The matched count, the total and the oldest dataset date, for the tab
    /// and the Summary.
    pub(super) fn ioc_headline(&self) -> Option<(usize, usize, String)> {
        let ioc = self.scan.as_ref().and_then(|scan| scan.ioc.clone());
        self.ioc.headline(ioc.as_deref())
    }

    /// The Datasets button was pressed.
    pub(crate) fn take_open_datasets(&mut self) -> bool {
        self.ioc.take_open_datasets()
    }

    /// The app's `curl`, for the online check.
    pub(crate) fn set_curl(&mut self, curl: &std::path::Path) {
        self.ioc.set_curl(curl);
    }

    pub(super) fn ioc_section(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        let ioc = self.scan.as_ref().and_then(|scan| scan.ioc.clone());
        presentation::heading(
            ui,
            "Indicators of compromise",
            "Collected from this run's evidence and matched offline against the loaded datasets. No match is not a clean result.",
        );
        let Some(ioc) = ioc else {
            if self.scan_rx.is_some() || self.scan.is_none() {
                theme::loading_weak(ui, "Collecting this run's indicators…");
            } else {
                ui.weak("No indicators are available for this run.");
            }
            return;
        };
        // The scan may have been replaced since the frame began.
        self.ioc.sync(Some(&ioc));
        self.ioc.status_bar(ui, &ioc);
        self.ioc.banners(ui, &ioc, input);
        self.ioc_tabs(ui, &ioc);
        match self.ioc.tab {
            Tab::Summary => {
                if let Some(next) = self.ioc.summary_tab(ui, &ioc) {
                    self.ioc.tab = next;
                }
            }
            Tab::Of(ty) => {
                if let Some(jump) = self.ioc.list_tab(ui, &ioc, ty) {
                    self.ioc_jump(ui.ctx(), jump);
                }
            }
        }
    }

    fn ioc_tabs(&mut self, ui: &mut egui::Ui, ioc: &IocScan) {
        let _ = ioc;
        let mut items = vec![(Tab::Summary, TabItem::new("Summary"))];
        for ty in Type::ALL {
            let all = self.ioc.count_of(Some(ty));
            let tone = if all.matched > 0 {
                Tone::Error
            } else {
                Tone::Plain
            };
            items.push((
                Tab::Of(ty),
                TabItem::new(ty.label()).badge(all.all().to_string(), tone),
            ));
        }
        let mut tab = self.ioc.tab;
        widgets::tabs(ui, items, &mut tab);
        self.ioc.tab = tab;
    }

    fn ioc_jump(&mut self, ctx: &egui::Context, jump: list::Jump) {
        match jump {
            list::Jump::Packet { capture, frame } => {
                ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new("triage-packet-jump"), frame);
                    data.insert_temp(
                        egui::Id::new("triage-packet-capture"),
                        std::path::PathBuf::from(capture),
                    );
                });
            }
            list::Jump::Call {
                stream,
                cookie,
                call,
            } => {
                ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new("triage-call-jump"), (stream, cookie, call));
                });
            }
            list::Jump::Properties => self.section = Section::Properties,
        }
    }
}

impl View {
    fn status_bar(&mut self, ui: &mut egui::Ui, ioc: &IocScan) {
        let now = feeds::now_unix();
        let key = self.key_state().map(str::to_owned);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Datasets").small().color(theme::muted()));
            if ioc.scan.loaded.is_empty() {
                ui.colored_label(theme::warn(), "none loaded");
            } else {
                for (name, loaded) in &self.chips {
                    widgets::chip(
                        ui,
                        name.clone(),
                        if *loaded { Tone::Good } else { Tone::Neutral },
                    );
                }
            }
            ui.separator();
            ui.label(RichText::new("Age").small().color(theme::muted()));
            match ioc.scan.loaded.iter().map(|feed| feed.fetched_unix).min() {
                Some(oldest) => {
                    let days = now.saturating_sub(oldest) / 86_400;
                    let text = format!(
                        "{} · {days} day{} old",
                        feeds::date_text(oldest),
                        if days == 1 { "" } else { "s" }
                    );
                    ui.colored_label(
                        if days > feeds::STALE_DAYS { theme::warn() } else { theme::good() },
                        text,
                    );
                }
                None => {
                    ui.weak("—");
                }
            }
            ui.separator();
            ui.label(RichText::new("Auth-Key").small().color(theme::muted()));
            match &key {
                Some(masked) => ui.colored_label(theme::good(), format!("set ({masked})")),
                None => ui.colored_label(theme::warn(), "missing"),
            };
            ui.separator();
            let mut on = self.online_on && key.is_some();
            let response = ui
                .add_enabled(key.is_some(), egui::Checkbox::new(&mut on, "Online lookups"))
                .on_hover_text(if key.is_some() {
                    "Send public indicators that have no offline match to abuse.ch. Files are never sent."
                } else {
                    "Needs an Auth-Key"
                });
            if response.changed() {
                self.online_on = on;
            }
            if ui.button("Datasets…").clicked() {
                self.open_datasets = true;
            }
            let label = if ioc.scan.loaded.is_empty() { "Download" } else { "Update" };
            if ui
                .button(label)
                .on_hover_text("Opens the datasets in the Rule manager")
                .clicked()
            {
                self.open_datasets = true;
            }
        });
        if let Some((text, error)) = &self.status {
            ui.colored_label(
                if *error {
                    theme::error()
                } else {
                    theme::muted()
                },
                text,
            );
        }
    }

    /// The switched-on feeds as chips: name, and whether the copy is loaded.
    fn feed_states(&self) -> Vec<(String, bool)> {
        let Some(dir) = &self.data_dir else {
            return Vec::new();
        };
        feeds::status(dir)
            .into_iter()
            .filter(|status| status.enabled)
            .map(|status| (status.feed.name.to_owned(), status.usable()))
            .collect()
    }

    fn banners(&mut self, ui: &mut egui::Ui, ioc: &IocScan, input: &TriageInput<'_>) {
        let _ = input;
        let now = feeds::now_unix();
        if ioc.scan.loaded.is_empty() {
            crate::activity::warning(
                ui,
                "No datasets on this machine. Indicators are listed but not checked. Download the abuse.ch feeds (Datasets…) to match them offline.",
            );
        } else {
            let oldest = ioc
                .scan
                .loaded
                .iter()
                .map(|feed| feed.fetched_unix)
                .min()
                .unwrap_or(now);
            let days = now.saturating_sub(oldest) / 86_400;
            if days > feeds::STALE_DAYS {
                crate::activity::warning(
                    ui,
                    format!(
                        "The datasets are {days} days old. New reports are missing, so No match is weaker than usual. Each verdict shows its dataset date ({}).",
                        feeds::date_text(oldest)
                    ),
                );
            }
            let wanted = self.feed_states().len();
            let missing = wanted.saturating_sub(ioc.scan.loaded.len());
            if missing > 0 {
                crate::activity::warning(
                    ui,
                    format!(
                        "{missing} of {wanted} feeds are not loaded. Indicators are checked against the feeds that are."
                    ),
                );
            }
        }
        for (feed, error) in &ioc.scan.errors {
            crate::activity::warning(
                ui,
                format!(
                    "{} could not be read: {error}",
                    ioc_scan::dataset_name(feed)
                ),
            );
        }
        if self.online_on {
            ui.colored_label(
                theme::blue(),
                "Online check is on. Public indicators with no offline match are sent to abuse.ch when you press Check online. Files are never sent. Turn it off again when you are done.",
            );
        }
        match &ioc.capture {
            Capture::Read => {}
            Capture::Off => {
                ui.colored_label(
                    theme::muted(),
                    "Network capture was turned off for this run. Packet-based indicators were not collected; endpoints from system calls, strings in the sample and files are still listed.",
                );
            }
            Capture::Failed(error) => {
                crate::activity::warning(
                    ui,
                    format!("The network capture could not be read: {error}"),
                );
            }
        }
        if ioc.omitted > 0 {
            crate::activity::warning(
                ui,
                format!(
                    "{} observations were left out because a list reached its limit.",
                    ioc.omitted
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests;
