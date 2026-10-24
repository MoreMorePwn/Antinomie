//! Tools → Malware samples: search MalwareBazaar or MalShare, download samples (kept in
//! their encrypted archives) and send them into the running VM, optionally
//! running them there. Nothing is run or unpacked on the host.
mod pending;
mod tables;

use crate::query::{self, FieldSpec, RowValue};
use crate::theme::{self, ValueKind};
use antinomie_monitor_core::{
    malshare::{CatalogProgress, DatedCatalog},
    samples::{self, SampleInfo, Source, StoredSample},
    ExecRequest,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    time::Duration,
};

pub(crate) const WINDOW_ID: &str = "malware_samples";

/// Samples asked of a source per search, the most MalwareBazaar answers.
const SEARCH_LIMIT: u32 = 1000;

const SAMPLE_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text(
        "sample.sha256",
        "Verified/source-provided SHA-256; missing on MD5-only rows",
    ),
    FieldSpec::text("sample.source", "Metadata source credit"),
    FieldSpec::text("sample.type", "Source or analyzed type; unknown is missing"),
    FieldSpec::text("sample.arch", "Analyzed/source architecture"),
    FieldSpec::text("sample.family", "Source family"),
    FieldSpec::number(
        "sample.first_seen_ms",
        "Exact source timestamp unavailable on daily hashes",
    ),
    FieldSpec::text("sample.archive_day", "UTC date-only archive observation"),
    FieldSpec::boolean(
        "sample.cached",
        "Specimen retained in encrypted local storage",
    ),
    FieldSpec::text("entry.name", "Source filename"),
    FieldSpec::tags("entry.tag", "Source tags and archive date"),
    FieldSpec::number("entry.size", "Source/analyzed specimen size in octets"),
];

pub(crate) struct SamplesContext<'a> {
    pub data_dir: &'a Path,
    pub curl: &'a Path,
    /// The selected VM is running: samples can be sent into it.
    pub running: bool,
    pub vm_name: Option<&'a str>,
    /// The selected VM reaches the network.
    pub nat: bool,
    pub font_size: f32,
}

pub(crate) enum SamplesAction {
    /// Send a downloaded sample into the guest; run it after if `run` is set.
    Push {
        sha256: String,
        destination: String,
        run: Option<ExecRequest>,
    },
}

/// Columns of the search results, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Col {
    Seen,
    File,
    Hash,
    Family,
    Type,
    Arch,
    Size,
    Tags,
}

impl Col {
    const ALL: [Col; 8] = [
        Col::Seen,
        Col::File,
        Col::Hash,
        Col::Family,
        Col::Type,
        Col::Arch,
        Col::Size,
        Col::Tags,
    ];
    fn label(self) -> &'static str {
        match self {
            Col::Seen => "Seen / archive day",
            Col::File => "File",
            Col::Hash => "SHA-256",
            Col::Family => "Family",
            Col::Type => "Type",
            Col::Arch => "Architecture",
            Col::Size => "Size",
            Col::Tags => "Tags",
        }
    }
}

/// Results ordered by one column (header clicks: ascending, descending, as
/// MalwareBazaar listed them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sort {
    column: Col,
    descending: bool,
}

impl Drop for SamplesView {
    fn drop(&mut self) {
        if let Some(cancel) = &self.search_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

fn next_sort(sort: Option<Sort>, column: Col) -> Option<Sort> {
    match sort {
        Some(Sort {
            column: current,
            descending: false,
        }) if current == column => Some(Sort {
            column,
            descending: true,
        }),
        Some(Sort {
            column: current,
            descending: true,
        }) if current == column => None,
        _ => Some(Sort {
            column,
            descending: false,
        }),
    }
}

/// A sample's architecture as people write it.
fn arch(sample: &SampleInfo) -> Option<String> {
    if sample.is_script() {
        return Some(SCRIPT.into());
    }
    sample.file_arch.as_deref().map(samples::arch_label)
}

/// The Architecture of a shell script, which has none: it runs in the guests.
const SCRIPT: &str = "script";

/// The Architecture dropdown's entry for samples listed without one
/// (MalwareBazaar's newest uploads leave it out).
const UNKNOWN_ARCH: &str = "unknown";

/// Hash column: SHA-256, otherwise MD5, otherwise SHA-1.
fn listed_hash(sample: &SampleInfo) -> Option<&str> {
    [
        sample.sha256_hash.as_str(),
        sample.md5_hash.as_str(),
        sample.sha1_hash.as_str(),
    ]
    .into_iter()
    .find(|hash| !hash.is_empty())
}

fn sample_date(sample: &SampleInfo) -> &str {
    if !sample.first_seen.is_empty() {
        return &sample.first_seen;
    }
    sample
        .tags
        .iter()
        .find_map(|tag| tag.strip_prefix("archive-date:"))
        .unwrap_or("—")
}

fn sample_values(
    sample: &SampleInfo,
    source: Source,
    stored: &[StoredSample],
) -> Vec<(&'static str, RowValue)> {
    let text = |value: &str| {
        if value.is_empty() || value == "unknown" {
            RowValue::Missing
        } else {
            RowValue::Text(value.into())
        }
    };
    vec![
        ("sample.sha256", text(&sample.sha256_hash)),
        ("sample.source", RowValue::Text(source.label().into())),
        ("sample.type", text(&sample.file_type)),
        (
            "sample.arch",
            arch(sample).map_or(RowValue::Missing, RowValue::Text),
        ),
        (
            "sample.family",
            sample
                .signature
                .clone()
                .map_or(RowValue::Missing, RowValue::Text),
        ),
        (
            "sample.first_seen_ms",
            antinomie_monitor_core::malshare::catalog_timestamp_ms(&sample.first_seen)
                .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
        ),
        (
            "sample.archive_day",
            sample
                .tags
                .iter()
                .find_map(|tag| tag.strip_prefix("archive-date:"))
                .map_or(RowValue::Missing, |day| RowValue::Text(day.into())),
        ),
        (
            "sample.cached",
            RowValue::Bool(
                !sample.sha256_hash.is_empty()
                    && stored
                        .iter()
                        .any(|stored| stored.info.sha256_hash == sample.sha256_hash),
            ),
        ),
        ("entry.name", text(&sample.file_name)),
        ("entry.tag", RowValue::List(sample.tags.clone())),
        (
            "entry.size",
            if sample.file_size == 0 {
                RowValue::Missing
            } else {
                RowValue::Number(i128::from(sample.file_size))
            },
        ),
    ]
}

/// What the dropdowns keep of the results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Filters {
    file_type: Option<String>,
    arch: Option<String>,
    family: Option<String>,
    /// Samples with any of these tags.
    tags: BTreeSet<String>,
}

impl Filters {
    fn keeps(&self, sample: &SampleInfo) -> bool {
        self.file_type
            .as_ref()
            .is_none_or(|kind| sample.file_type.eq_ignore_ascii_case(kind))
            && self
                .arch
                .as_ref()
                .is_none_or(|wanted| arch(sample).unwrap_or_else(|| UNKNOWN_ARCH.into()) == *wanted)
            && self
                .family
                .as_ref()
                .is_none_or(|family| sample.signature.as_ref() == Some(family))
            && (self.tags.is_empty() || sample.tags.iter().any(|tag| self.tags.contains(tag)))
    }
    fn active(&self) -> bool {
        *self != Filters::default()
    }
}

/// The values of one field in `results`, most frequent first.
fn choices(
    results: &[SampleInfo],
    field: impl Fn(&SampleInfo) -> Vec<String>,
) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::<String, usize>::new();
    for sample in results {
        for value in field(sample) {
            if !value.is_empty() {
                *counts.entry(value).or_default() += 1;
            }
        }
    }
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts
}

/// Indices of the results the filters keep, in the order of `sort`.
fn shown(results: &[SampleInfo], filters: &Filters, sort: Option<Sort>) -> Vec<usize> {
    let mut shown: Vec<usize> = (0..results.len())
        .filter(|&index| filters.keeps(&results[index]))
        .collect();
    if let Some(sort) = sort {
        let text = |sample: &SampleInfo| -> String {
            match sort.column {
                Col::Seen => sample_date(sample).to_owned(),
                Col::File => sample.file_name.to_lowercase(),
                Col::Hash => listed_hash(sample).unwrap_or("").to_owned(),
                Col::Family => sample.signature.clone().unwrap_or_default().to_lowercase(),
                Col::Type => sample.file_type.to_lowercase(),
                Col::Arch => arch(sample).unwrap_or_default().to_lowercase(),
                Col::Size => String::new(),
                Col::Tags => sample.tags.join(",").to_lowercase(),
            }
        };
        shown.sort_by(|&a, &b| {
            let (a, b) = (&results[a], &results[b]);
            let order = if sort.column == Col::Size {
                a.file_size.cmp(&b.file_size)
            } else {
                text(a).cmp(&text(b))
            };
            if sort.descending {
                order.reverse()
            } else {
                order
            }
        });
    }
    shown
}

type Found = Result<(String, Vec<SampleInfo>), String>;

enum SearchUpdate {
    Finished(u64, Source, Found),
    Progress(u64, CatalogProgress),
    Catalog(u64, Result<DatedCatalog, String>),
}

#[derive(Default)]
pub(crate) struct SamplesView {
    pub(crate) open: bool,
    key: String,
    key_saved: bool,
    key_loaded: bool,
    /// The person asked for Tools > API keys; the app opens it.
    want_keys: bool,
    /// The warning before first use was accepted in this data folder.
    acknowledged: bool,
    /// The acceptance checkbox of that warning.
    understood: bool,
    text: String,
    /// What the results are, in words ("Newest uploads", "Family Mirai").
    listing: String,
    /// The source searched and downloaded from.
    source: Source,
    /// The source the results came from.
    results_source: Source,
    /// The newest uploads were asked for when the window opened.
    listed: bool,
    results: Vec<SampleInfo>,
    filters: Filters,
    sort: Option<Sort>,
    searching: Option<Receiver<SearchUpdate>>,
    search_generation: u64,
    search_cancel: Option<Arc<AtomicBool>>,
    catalog_progress: Option<CatalogProgress>,
    catalog_errors: Vec<String>,
    offline: bool,
    downloads: BTreeMap<String, Receiver<Result<StoredSample, String>>>,
    stored: Option<Vec<StoredSample>>,
    /// Run pushed samples as root instead of the guest user.
    as_root: bool,
    status: Option<(String, bool)>,
    range_start: String,
    range_end: String,
    /// The upload request and the run that follows it.
    pending: Option<(u64, Option<ExecRequest>)>,
    awaiting: Option<Option<ExecRequest>>,
}

/// What the warning before first use says, one point per line.
const FIRST_USE_POINTS: &[&str] = &[
    "Never run a sample on this computer. Antinomie keeps samples in their \
     encrypted archives and decrypts them only in memory to send them into a VM.",
    "A sample run in a VM with NAT on can reach your network and the Internet: it may \
     spread, attack other machines or contact its operators. Keep NAT off unless you need it.",
    "Use a VM you can throw away, or take a snapshot first. Escaping a VM is rare but \
     possible.",
    "Antivirus software on this computer may flag or quarantine the data folder.",
    "Downloading or keeping malware may be restricted by law or by your organisation. \
     Samples are for research and defence only.",
];

/// A guest path for a sample: its hash prefix and a safe form of its name.
/// `sent` is how many times the sample was sent before: each send gets its
/// own file, as a copy still running in the guest cannot be replaced ("Text
/// file busy").
fn guest_path(sample: &SampleInfo, sent: usize) -> String {
    let name: String = sample
        .file_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let copy = if sent == 0 {
        String::new()
    } else {
        format!("{}-", sent + 1)
    };
    let identity = if sample.sha256_hash.is_empty() {
        sample.md5_hash.as_str()
    } else {
        sample.sha256_hash.as_str()
    };
    format!(
        "/tmp/{}-{copy}{}",
        &identity[..12.min(identity.len())],
        if name.is_empty() {
            "sample".into()
        } else {
            name
        }
    )
}

/// A dropdown of one field's values (with their counts) or all of them.
fn choice(
    ui: &mut egui::Ui,
    id: &str,
    label: &str,
    value: &mut Option<String>,
    options: &[(String, usize)],
) {
    let selected = match value {
        Some(value) => format!("{label}: {value}"),
        None => format!("{label}: all"),
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .height(360.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, "All");
            for (option, count) in options {
                ui.selectable_value(value, Some(option.clone()), format!("{option}  ({count})"));
            }
        });
}

impl SamplesView {
    fn poll(&mut self, ctx: &egui::Context) {
        loop {
            let update = self.searching.as_ref().map(|r| r.try_recv());
            match update {
                Some(Ok(SearchUpdate::Progress(generation, progress))) => {
                    if generation == self.search_generation {
                        self.catalog_progress = Some(progress);
                    }
                }
                Some(Ok(SearchUpdate::Finished(generation, source, found))) => {
                    self.searching = None;
                    self.search_cancel = None;
                    if generation == self.search_generation && source == self.source {
                        self.apply_found(source, found);
                    }
                }
                Some(Ok(SearchUpdate::Catalog(generation, result))) => {
                    self.searching = None;
                    self.search_cancel = None;
                    if generation == self.search_generation && self.source == Source::MalShare {
                        match result {
                            Ok(catalog) => {
                                let listing = catalog.listing();
                                let partial = catalog.cancelled || !catalog.failed_days.is_empty();
                                self.catalog_errors = catalog.failed_days;
                                // Preserve useful previous results when the entire job failed.
                                if catalog.scanned_days > 0 || catalog.requested_days == 0 {
                                    self.apply_found(
                                        Source::MalShare,
                                        Ok((listing.clone(), catalog.samples)),
                                    );
                                }
                                self.status = partial.then_some((listing, true));
                            }
                            Err(error) => self.status = Some((error, true)),
                        }
                    }
                }
                Some(Err(mpsc::TryRecvError::Disconnected)) => {
                    self.searching = None;
                    self.search_cancel = None;
                    self.status =
                        Some(("Catalog job stopped before reporting a result".into(), true));
                }
                _ => break,
            }
        }
        let mut finished = Vec::new();
        self.downloads
            .retain(|hash, receiver| match receiver.try_recv() {
                Ok(result) => {
                    finished.push((hash.clone(), result));
                    false
                }
                Err(mpsc::TryRecvError::Empty) => true,
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        for (hash, result) in finished {
            self.stored = None;
            self.status = Some(match result {
                Ok(sample) => (
                    format!(
                        "Downloaded {} ({}), kept encrypted",
                        sample.info.file_name,
                        sample
                            .info
                            .file_arch
                            .as_deref()
                            .map_or("not an ELF".into(), samples::arch_label)
                    ),
                    false,
                ),
                Err(error) => (format!("{}: {error}", &hash[..12.min(hash.len())]), true),
            });
        }
        if self.searching.is_some() || !self.downloads.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    fn apply_found(&mut self, source: Source, found: Found) {
        match found {
            Ok((listing, found)) => {
                self.listing = listing;
                self.results_source = source;
                self.results = found;
                self.status = None;
            }
            Err(error) => self.status = Some((error, true)),
        }
    }

    /// The source's newest samples of every type.
    fn search_dated(&mut self, cx: &SamplesContext<'_>, all_cached: bool) {
        let (sender, receiver) = mpsc::sync_channel(2);
        let curl = cx.curl.to_path_buf();
        let cache = cx.data_dir.join("malshare-daily");
        let start = self.range_start.clone();
        let end = self.range_end.clone();
        let offline = self.offline || all_cached;
        self.search_generation = self.search_generation.wrapping_add(1);
        let generation = self.search_generation;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        if let Err(error) = std::thread::Builder::new()
            .name("malshare-metadata".into())
            .spawn(move || {
                let result = antinomie_monitor_core::malshare::dated_catalog(
                    &curl,
                    &cache,
                    (!all_cached).then_some((start.as_str(), end.as_str())),
                    offline,
                    SEARCH_LIMIT as usize,
                    &worker_cancel,
                    |progress| {
                        let _ = sender.try_send(SearchUpdate::Progress(generation, progress));
                    },
                );
                let _ = sender.send(SearchUpdate::Catalog(generation, result));
            })
        {
            self.status = Some((format!("Could not start metadata job: {error}"), true));
            return;
        }
        self.searching = Some(receiver);
        self.search_cancel = Some(cancel);
        self.catalog_progress = None;
        self.catalog_errors.clear();
        self.status = None;
    }

    fn search_all(&mut self, cx: &SamplesContext<'_>) {
        let (sender, receiver) = mpsc::channel();
        let (curl, key, source) = (cx.curl.to_path_buf(), self.key.clone(), self.source);
        let data_dir = cx.data_dir.to_path_buf();
        self.search_generation = self.search_generation.wrapping_add(1);
        let generation = self.search_generation;
        std::thread::spawn(move || {
            let found = source.newest_all(&curl, &key, SEARCH_LIMIT);
            if found.is_ok() {
                antinomie_monitor_core::api_keys::record_use(
                    &data_dir,
                    samples::source_api_key(source),
                );
            }
            let _ = sender.send(SearchUpdate::Finished(generation, source, found));
        });
        self.searching = Some(receiver);
        self.status = None;
    }

    /// Search the source for `text` (empty: the newest samples).
    fn search(&mut self, cx: &SamplesContext<'_>, text: String) {
        let (sender, receiver) = mpsc::channel();
        let (curl, key, source) = (cx.curl.to_path_buf(), self.key.clone(), self.source);
        let data_dir = cx.data_dir.to_path_buf();
        self.search_generation = self.search_generation.wrapping_add(1);
        let generation = self.search_generation;
        std::thread::spawn(move || {
            let found = source.find(&curl, &key, &text, SEARCH_LIMIT);
            if found.is_ok() {
                antinomie_monitor_core::api_keys::record_use(
                    &data_dir,
                    samples::source_api_key(source),
                );
            }
            let _ = sender.send(SearchUpdate::Finished(generation, source, found));
        });
        self.searching = Some(receiver);
        self.status = None;
    }

    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        cx: &SamplesContext<'_>,
    ) -> Option<SamplesAction> {
        self.poll(ctx);
        for error in &self.catalog_errors {
            crate::activity::report(ctx, crate::activity::Level::Warn, error);
        }
        crate::toasts::take_failure(ctx, &mut self.status);
        if !self.open {
            // The keys are set elsewhere: read them again when it opens.
            self.key_loaded = false;
            return None;
        }
        if !self.key_loaded {
            self.key = samples::source_key(cx.data_dir, self.source);
            self.key_saved = !self.key.is_empty();
            self.acknowledged = samples::acknowledged(cx.data_dir);
            self.key_loaded = true;
        }
        if !self.acknowledged {
            self.first_use(ctx, cx);
            return None;
        }
        // The newest uploads, as soon as there is a key to ask with.
        if !self.listed && self.key_saved && self.searching.is_none() {
            self.listed = true;
            self.search(cx, String::new());
        }
        let stored = self
            .stored
            .get_or_insert_with(|| samples::stored(cx.data_dir))
            .clone();
        let mut action = None;
        let mut open = true;
        let screen = ctx.screen_rect();
        let largest = egui::vec2(1240.0, 820.0).min(screen.size() - egui::vec2(96.0, 300.0));
        crate::widgets::window("Malware samples")
            .id(egui::Id::new(WINDOW_ID))
            .collapsible(false)
            .resizable(true)
            // The content fills the window, so the window takes its largest
            // size: centre that. Sizes are the content's: the title bar and
            // margins (about 90 points) come on top, below the rect's top.
            .default_rect(egui::Rect::from_center_size(
                screen.center() - egui::vec2(0.0, 42.0),
                largest,
            ))
            .min_size(egui::vec2(720.0, 480.0).min(largest))
            .max_size(largest)
            .open(&mut open)
            .show(ctx, |ui| {
                self.warning(ui, cx);
                ui.add_space(12.0);
                self.source_row(ui, cx);
                ui.add_space(10.0);
                if !self.key_saved {
                    self.key_row(ui);
                    ui.add_space(12.0);
                }
                self.search_bar(ui, cx);
                ui.add_space(10.0);
                self.filter_bar(ui);
                ui.add_space(10.0);
                // The downloaded list keeps room for a few samples; the
                // results take the rest.
                let row = theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
                // Exactly what is drawn below the results: anything taking
                // "the rest" would make the window grow every frame.
                let list = row * stored.len().clamp(1, 4) as f32;
                let below = 14.0 + ui.spacing().interact_size.y + 6.0 + list + 4.0;
                let results = (ui.available_height() - below).max(120.0);
                ui.allocate_ui(egui::vec2(ui.available_width(), results), |ui| {
                    self.results_table(ui, cx, &stored);
                });
                ui.add_space(14.0);
                if let Some(next) = self.stored_list(ui, cx, &stored, list) {
                    action = Some(next);
                }
            });
        if !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
            if let Some(cancel) = &self.search_cancel {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        action
    }

    /// The person asked for Tools > API keys, where the key a source needs is set.
    pub(crate) fn take_open_keys(&mut self) -> bool {
        std::mem::take(&mut self.want_keys)
    }

    /// Shown instead of the window until the user accepts it once.
    fn first_use(&mut self, ctx: &egui::Context, cx: &SamplesContext<'_>) {
        let mut open = true;
        let mut cancel = false;
        crate::widgets::window("Malware samples")
            .id(egui::Id::new(WINDOW_ID).with("first_use"))
            .collapsible(false)
            .resizable(false)
            .default_width(620.0)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .open(&mut open)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(egui_phosphor::regular::BIOHAZARD)
                            .size(cx.font_size * 2.0)
                            .color(theme::warn()),
                    );
                    ui.label(
                        RichText::new("Before you use the malware catalog")
                            .size(cx.font_size * 1.3)
                            .strong()
                            .color(theme::text()),
                    );
                });
                ui.add_space(8.0);
                ui.label(
                    "This window downloads real, live malware from MalwareBazaar (abuse.ch) \
                     or MalShare so you can study it inside a VM.",
                );
                ui.add_space(6.0);
                for point in FIRST_USE_POINTS {
                    // Wrapped lines hang under the text, not the bullet.
                    ui.horizontal_top(|ui| {
                        crate::activity::warning(ui, "•");
                        ui.add(egui::Label::new(*point).wrap());
                    });
                    ui.add_space(2.0);
                }
                ui.add_space(8.0);
                ui.checkbox(
                    &mut self.understood,
                    "I understand these are live malware samples and I am responsible for \
                     handling them safely and lawfully.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.understood, egui::Button::new("Continue"))
                        .clicked()
                    {
                        match samples::acknowledge(cx.data_dir) {
                            Ok(()) => {
                                self.acknowledged = true;
                                self.status = None;
                            }
                            Err(error) => self.status = Some((error, true)),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if !open || cancel || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
            self.understood = false;
        }
    }

    fn warning(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        egui::Frame::new()
            .fill(theme::panel())
            .stroke(egui::Stroke::new(1.0_f32, theme::line()))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.colored_label(theme::warn(), egui_phosphor::regular::BIOHAZARD);
                    crate::activity::warning(ui, "Live malware. Samples stay in encrypted archives in the data \
                             folder and are decrypted only in memory, to be sent into the VM. Nothing is run on this computer. Use a VM you can throw \
                             away, or take a snapshot first.",);
                });
                if cx.nat {
                    ui.add_space(4.0);
                    crate::activity::warning(ui,
                        "NAT is on for this VM: a sample run there can reach your network and \
                         the Internet.",
                    );
                }
                if let Some((message, _)) = &self.status {
                    ui.add_space(4.0);
                    ui.colored_label(theme::good(), message);
                }
            });
    }

    /// The source to search: each has its own key and its own results.
    fn source_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut switch = None;
        crate::widgets::tab_row(ui, |ui| {
            ui.label(RichText::new("Source").color(theme::muted()));
            for source in Source::ALL {
                if crate::widgets::tab(
                    ui,
                    self.source == source,
                    &crate::widgets::TabItem::new(source.label()),
                )
                .on_hover_text(match source {
                    Source::MalwareBazaar => {
                        "abuse.ch's MalwareBazaar: families, tags, architectures"
                    }
                    Source::MalShare => "MalShare: hashes, file types, file names and sources",
                })
                .clicked()
                    && self.source != source
                {
                    switch = Some(source);
                }
            }
        });
        if let Some(source) = switch {
            if let Some(cancel) = &self.search_cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            self.search_generation = self.search_generation.wrapping_add(1);
            self.source = source;
            if source == Source::MalShare && self.range_start.is_empty() {
                if let Ok((start, end)) = antinomie_monitor_core::malshare::recent_date_range(7) {
                    self.range_start = start;
                    self.range_end = end;
                }
            }
            self.key = samples::source_key(cx.data_dir, source);
            self.key_saved = !self.key.is_empty();
            self.results.clear();
            self.listing.clear();
            self.filters = Filters::default();
            self.sort = None;
            self.status = None;
            self.text.clear();
            self.catalog_errors.clear();
            self.catalog_progress = None;
            // The newest samples of the new source, once there is a key.
            self.listed = false;
        }
    }

    /// No key yet: it is set in Tools > API keys, not here.
    fn key_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "{} needs a {}.",
                self.source.label(),
                samples::source_api_key(self.source).label()
            ));
            if ui.button("Open API keys…").clicked() {
                self.want_keys = true;
            }
            ui.hyperlink_to(
                format!("Get a key {}", egui_phosphor::regular::ARROW_SQUARE_OUT),
                self.source.keys_url(),
            );
        });
    }

    /// The key was changed in Tools > API keys: read it again.
    pub(crate) fn key_changed(&mut self) {
        self.key_loaded = false;
        self.listed = false;
    }

    fn search_bar(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut search = None;
        let mut all = false;
        let ready = self.key_saved && self.searching.is_none();
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(format!("{} Key", egui_phosphor::regular::KEY))
                    .on_hover_text(format!(
                        "Change the {} in Tools > API keys",
                        samples::source_api_key(self.source).label()
                    ))
                    .clicked()
                {
                    self.want_keys = true;
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest (all)"))
                    .on_hover_text(match self.source {
                        Source::MalwareBazaar => {
                            "MalwareBazaar's latest 100 uploads of every type (it lists no \
                             architectures for these)"
                        }
                        Source::MalShare => {
                            "This list is the last 24 hours, not an archive (hashes only until \
                             searched or downloaded)"
                        }
                    })
                    .clicked()
                {
                    self.text.clear();
                    all = true;
                }
                if self.source == Source::MalShare
                    && ui
                        .add_enabled(
                            self.searching.is_none(),
                            egui::Button::new("Newest in range"),
                        )
                        .on_hover_text(
                            "Official dated SHA-256 lists. This is separate from the last-24-hours list. Type is unknown until a sample is downloaded.",
                        )
                        .clicked()
                {
                    self.search_dated(cx, false);
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest Linux"))
                    .on_hover_text(match self.source {
                        Source::MalwareBazaar => {
                            "The newest ELF programs and shell scripts: what the VMs run"
                        }
                        Source::MalShare => "This list is the last 24 hours, not an archive",
                    })
                    .clicked()
                {
                    self.text.clear();
                    search = Some(String::new());
                }
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(
                            RichText::new(format!(
                                "{} Search",
                                egui_phosphor::regular::MAGNIFYING_GLASS
                            ))
                            .color(theme::palette().primary_text),
                        )
                        .fill(theme::primary()),
                    )
                    .clicked()
                {
                    search = Some(self.text.clone());
                }
                if self.searching.is_some() {
                    crate::theme::spinner(ui);
                }
                let edit = ui.add_sized(
                    egui::vec2(ui.available_width(), ui.spacing().interact_size.y),
                    egui::TextEdit::singleline(&mut self.text)
                        .hint_text(crate::theme::hint_text(format!(
                            "{}  {}",
                            egui_phosphor::regular::MAGNIFYING_GLASS,
                            match self.source {
                                Source::MalwareBazaar =>
                                    "Family, tag, file type or hash (Mirai, x86-64, elf, a SHA-256…)",
                                Source::MalShare =>
                                    "Hash, file type (elf, pe32) or a word in file names and sources",
                            }
                        )))
                        .margin(theme::TEXT_EDIT_MARGIN),
                );
                if ready
                    && edit.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter))
                {
                    search = Some(self.text.clone());
                }
            });
        });
        ui.add_space(6.0);
        if self.source == Source::MalShare {
            ui.horizontal_wrapped(|ui| {
                for (label, day_count) in [("7 days", 7), ("30 days", 30)] {
                    if ui.button(label).clicked() {
                        match antinomie_monitor_core::malshare::recent_date_range(day_count) {
                            Ok((start, end)) => {
                                self.range_start = start;
                                self.range_end = end;
                            }
                            Err(error) => self.status = Some((error, true)),
                        }
                    }
                }
                ui.label("From");
                ui.add(
                    egui::TextEdit::singleline(&mut self.range_start)
                        .desired_width(120.0)
                        .hint_text(crate::theme::hint_text("YYYY-MM-DD")),
                );
                ui.label("through");
                ui.add(
                    egui::TextEdit::singleline(&mut self.range_end)
                        .desired_width(120.0)
                        .hint_text(crate::theme::hint_text("YYYY-MM-DD")),
                );
                ui.checkbox(&mut self.offline, "Offline");
                if ui
                    .add_enabled(
                        self.searching.is_none(),
                        egui::Button::new("All cached metadata"),
                    )
                    .clicked()
                {
                    self.search_dated(cx, true);
                }
                if self.search_cancel.is_some() && ui.button("Cancel").clicked() {
                    if let Some(cancel) = &self.search_cancel {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
            });
            if let Some(progress) = &self.catalog_progress {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "{}: {}/{} days, {} cached, {} unavailable",
                        progress.day,
                        progress.done_days,
                        progress.total_days,
                        progress.cached_days,
                        progress.failed_days
                    ),
                );
            }
            if !self.catalog_errors.is_empty() {
                egui::CollapsingHeader::new("Unavailable days / retry details").show(ui, |ui| {
                    for error in &self.catalog_errors {
                        crate::activity::warning(ui, error);
                    }
                    ui.label("Retry the range to resume. Successfully cached days are reused.");
                });
            }
            ui.colored_label(
                theme::muted(),
                "MalShare: API lists cover the last 24 hours. Ranges cover up to 366 inclusive UTC days; cached-only mode covers local metadata. Archive dates are date-only observations, not first-seen timestamps. Type and architecture remain unknown.",
            );
            if all {
                self.search_all(cx);
            } else if let Some(text) = search {
                self.search(cx, text);
            }
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Linux families:").color(theme::muted()));
            for (name, about) in samples::STARTERS {
                if ui
                    .add_enabled(ready, egui::Button::new(*name).small())
                    .on_hover_text(*about)
                    .clicked()
                {
                    self.text = (*name).into();
                    search = Some((*name).into());
                }
            }
        });
        if all {
            self.search_all(cx);
        } else if let Some(text) = search {
            self.search(cx, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        name: &str,
        kind: &str,
        arch: &str,
        family: &str,
        tags: &[&str],
        size: u64,
    ) -> SampleInfo {
        SampleInfo {
            sha256_hash: format!("{name:0>64}"),
            file_name: name.into(),
            file_type: kind.into(),
            file_arch: Some(arch.into()),
            signature: Some(family.into()),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            file_size: size,
            ..SampleInfo::default()
        }
    }

    #[test]
    fn unresolved_sample_push_can_be_cleared_without_treating_it_as_rejected() {
        let mut view = SamplesView::default();
        view.awaiting = Some(None);
        view.sent(12);
        assert!(view.pending.is_some());
        assert!(view.cancel_pending(12, "outcome unknown"));
        assert!(view.pending.is_none());
        assert_eq!(view.status.as_ref().unwrap().0, "outcome unknown");
        assert!(view.complete(12, false, "late failure").is_none());
        assert_eq!(view.status.as_ref().unwrap().0, "outcome unknown");
    }

    #[test]
    fn dropdowns_filter_and_headers_sort_the_results() {
        let results = vec![
            sample("a", "elf", "ARM", "Mirai", &["elf", "Mirai"], 300),
            sample("b", "elf", "X86_64", "Mirai", &["elf", "upx"], 100),
            sample("c", "exe", "I386", "AgentTesla", &["exe"], 200),
        ];
        let all = Filters::default();
        assert_eq!(shown(&results, &all, None), [0, 1, 2]);
        let x86_64 = Filters {
            arch: Some("x86-64".into()),
            ..Filters::default()
        };
        assert_eq!(shown(&results, &x86_64, None), [1]);
        let elf_mirai = Filters {
            file_type: Some("elf".into()),
            family: Some("Mirai".into()),
            ..Filters::default()
        };
        assert_eq!(shown(&results, &elf_mirai, None), [0, 1]);
        let tags = Filters {
            tags: ["upx".to_string(), "exe".to_string()].into(),
            ..Filters::default()
        };
        assert_eq!(shown(&results, &tags, None), [1, 2]);
        let by_size = next_sort(None, Col::Size);
        assert_eq!(shown(&results, &all, by_size), [1, 2, 0]);
        let by_size = next_sort(by_size, Col::Size);
        assert_eq!(shown(&results, &all, by_size), [0, 2, 1]);
        assert_eq!(next_sort(by_size, Col::Size), None);
        assert_eq!(
            choices(&results, |s| vec![s.file_type.clone()]),
            [("elf".to_string(), 2), ("exe".to_string(), 1)]
        );
        assert_eq!(
            choices(&results, |s| arch(s).into_iter().collect())
                .into_iter()
                .map(|(arch, _)| arch)
                .collect::<Vec<_>>(),
            ["ARM", "x86", "x86-64"]
        );
    }

    #[test]
    fn the_catalog_waits_for_the_warning_to_be_accepted() {
        let data = std::env::temp_dir().join(format!(
            "ant-samples-view-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&data).unwrap();
        let cx = SamplesContext {
            data_dir: &data,
            curl: Path::new("/usr/bin/curl"),
            running: false,
            vm_name: None,
            nat: false,
            font_size: 14.0,
        };
        let mut view = SamplesView::default();
        view.open = true;
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            assert!(view.show(ctx, &cx).is_none());
        });
        assert!(view.open && !view.acknowledged);
        samples::acknowledge(&data).unwrap();
        let mut view = SamplesView::default();
        view.open = true;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            view.show(ctx, &cx);
        });
        assert!(view.acknowledged);
        // No key: nothing is asked of MalwareBazaar.
        assert!(view.searching.is_none() && !view.listed);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn guest_paths_are_safe_and_unique_per_sample() {
        let sample = SampleInfo {
            sha256_hash: "ab".repeat(32),
            file_name: "../evil name;rm.elf".into(),
            ..SampleInfo::default()
        };
        assert_eq!(
            guest_path(&sample, 0),
            "/tmp/abababababab-.._evil_name_rm.elf"
        );
        assert_eq!(
            guest_path(&sample, 2),
            "/tmp/abababababab-3-.._evil_name_rm.elf"
        );
    }

    #[test]
    fn a_successful_push_starts_its_run_once() {
        let mut view = SamplesView::default();
        let run = ExecRequest {
            path: "/tmp/x".into(),
            ..ExecRequest::default()
        };
        view.awaiting = Some(Some(run.clone()));
        view.sent(7);
        assert!(view.complete(6, true, "other").is_none());
        assert_eq!(
            view.complete(7, true, "uploaded").map(|r| r.path),
            Some(run.path)
        );
        assert!(view.complete(7, true, "again").is_none());
        view.awaiting = Some(Some(ExecRequest::default()));
        view.sent(8);
        assert!(view.complete(8, false, "no room").is_none());
    }
}
