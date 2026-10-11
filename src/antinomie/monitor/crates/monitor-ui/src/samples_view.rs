//! Tools → Malware samples: search MalwareBazaar or MalShare, download samples (kept in
//! their encrypted archives) and send them into the running VM, optionally
//! running them there. Nothing is run or unpacked on the host.
use crate::theme::{self, ValueKind};
use antinomie_monitor_core::{
    samples::{self, SampleInfo, Source, StoredSample},
    ExecRequest,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

pub(crate) const WINDOW_ID: &str = "malware_samples";

/// Samples asked of a source per search, the most MalwareBazaar answers.
const SEARCH_LIMIT: u32 = 1000;

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
            Col::Seen => "First seen",
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
                Col::Seen => sample.first_seen.clone(),
                Col::File => sample.file_name.to_lowercase(),
                Col::Hash => sample.sha256_hash.clone(),
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

#[derive(Default)]
pub(crate) struct SamplesView {
    pub(crate) open: bool,
    key: String,
    key_saved: bool,
    key_loaded: bool,
    /// The saved key is being replaced.
    editing_key: bool,
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
    searching: Option<Receiver<Found>>,
    downloads: BTreeMap<String, Receiver<Result<StoredSample, String>>>,
    stored: Option<Vec<StoredSample>>,
    /// Run pushed samples as root instead of the guest user.
    as_root: bool,
    status: Option<(String, bool)>,
    /// The upload request and the run that follows it.
    pending: Option<(u64, Option<ExecRequest>)>,
    awaiting: Option<Option<ExecRequest>>,
}

fn format_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
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
    format!(
        "/tmp/{}-{copy}{}",
        &sample.sha256_hash[..12.min(sample.sha256_hash.len())],
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
    /// The app sent the upload as request `id`.
    pub(crate) fn sent(&mut self, id: u64) {
        if let Some(run) = self.awaiting.take() {
            self.pending = Some((id, run));
        }
    }

    /// A request finished; returns the run to start after a successful push.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        success: bool,
        message: &str,
    ) -> Option<ExecRequest> {
        let (pending, run) = self.pending.take_if(|(pending, _)| *pending == id)?;
        let _ = pending;
        self.stored = None;
        self.status = Some(if success {
            (format!("Sent into the VM: {message}"), false)
        } else {
            (format!("Could not send the sample: {message}"), true)
        });
        run.filter(|_| success)
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(found) = self.searching.as_ref().and_then(|r| r.try_recv().ok()) {
            self.searching = None;
            match found {
                Ok((listing, found)) => {
                    self.listing = listing;
                    self.results_source = self.source;
                    self.results = found;
                    self.filters = Filters::default();
                    self.sort = None;
                    self.status = None;
                }
                Err(error) => self.status = Some((error, true)),
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

    /// The source's newest samples of every type.
    fn search_all(&mut self, cx: &SamplesContext<'_>) {
        let (sender, receiver) = mpsc::channel();
        let (curl, key, source) = (cx.curl.to_path_buf(), self.key.clone(), self.source);
        std::thread::spawn(move || {
            let _ = sender.send(source.newest_all(&curl, &key, SEARCH_LIMIT));
        });
        self.searching = Some(receiver);
        self.status = None;
    }

    /// Search the source for `text` (empty: the newest samples).
    fn search(&mut self, cx: &SamplesContext<'_>, text: String) {
        let (sender, receiver) = mpsc::channel();
        let (curl, key, source) = (cx.curl.to_path_buf(), self.key.clone(), self.source);
        std::thread::spawn(move || {
            let _ = sender.send(source.find(&curl, &key, &text, SEARCH_LIMIT));
        });
        self.searching = Some(receiver);
        self.status = None;
    }

    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        cx: &SamplesContext<'_>,
    ) -> Option<SamplesAction> {
        if !self.open {
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
        self.poll(ctx);
        let stored = self
            .stored
            .get_or_insert_with(|| samples::stored(cx.data_dir))
            .clone();
        let mut action = None;
        let mut open = true;
        let screen = ctx.screen_rect();
        let largest = egui::vec2(1240.0, 820.0).min(screen.size() - egui::vec2(96.0, 300.0));
        egui::Window::new("Malware samples")
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
                if !self.key_saved || self.editing_key {
                    self.key_row(ui, cx);
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
        }
        action
    }

    /// Shown instead of the window until the user accepts it once.
    fn first_use(&mut self, ctx: &egui::Context, cx: &SamplesContext<'_>) {
        let mut open = true;
        let mut cancel = false;
        egui::Window::new("Malware samples")
            .id(egui::Id::new(WINDOW_ID).with("first_use"))
            .collapsible(false)
            .resizable(false)
            .default_width(620.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
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
                        ui.label(RichText::new("•").color(theme::warn()));
                        ui.add(egui::Label::new(*point).wrap());
                    });
                    ui.add_space(2.0);
                }
                if let Some((message, _)) = &self.status {
                    ui.colored_label(theme::error(), message);
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
                    ui.label(RichText::new(egui_phosphor::regular::BIOHAZARD).color(theme::warn()));
                    ui.add(
                        egui::Label::new(
                            "Live malware. Samples stay in encrypted archives in the data \
                             folder and are decrypted only in memory, to be sent into the VM. Nothing is run on this computer. Use a VM you can throw \
                             away, or take a snapshot first.",
                        )
                        .wrap(),
                    );
                });
                if cx.nat {
                    ui.add_space(4.0);
                    ui.colored_label(
                        theme::warn(),
                        "NAT is on for this VM: a sample run there can reach your network and \
                         the Internet.",
                    );
                }
                if let Some((message, error)) = &self.status {
                    ui.add_space(4.0);
                    ui.colored_label(
                        if *error {
                            theme::error()
                        } else {
                            theme::good()
                        },
                        message,
                    );
                }
            });
    }

    /// The source to search: each has its own key and its own results.
    fn source_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut switch = None;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Source").color(theme::muted()));
            for source in Source::ALL {
                if ui
                    .selectable_label(self.source == source, source.label())
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
            self.source = source;
            self.key = samples::source_key(cx.data_dir, source);
            self.key_saved = !self.key.is_empty();
            self.editing_key = false;
            self.results.clear();
            self.listing.clear();
            self.filters = Filters::default();
            self.sort = None;
            self.status = None;
            self.text.clear();
            // The newest samples of the new source, once there is a key.
            self.listed = false;
        }
    }

    fn key_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        ui.horizontal(|ui| {
            ui.label(format!("{} API key", self.source.label()));
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.key)
                    .password(true)
                    .hint_text(match self.source {
                        Source::MalwareBazaar => "free key from abuse.ch",
                        Source::MalShare => "free key from malshare.com",
                    })
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(340.0),
            );
            if edit.changed() {
                self.key_saved = false;
            }
            if ui
                .add_enabled(
                    !self.key_saved && !self.key.trim().is_empty(),
                    egui::Button::new("Save key"),
                )
                .on_hover_text("Kept in the data folder, readable only by you")
                .clicked()
            {
                match samples::save_source_key(cx.data_dir, self.source, &self.key) {
                    Ok(()) => {
                        self.key_saved = true;
                        self.editing_key = false;
                        self.listed = false;
                        self.status = Some(("API key saved".into(), false));
                    }
                    Err(error) => self.status = Some((error, true)),
                }
            }
            if self.editing_key && ui.button("Cancel").clicked() {
                self.key = samples::source_key(cx.data_dir, self.source);
                self.key_saved = !self.key.is_empty();
                self.editing_key = false;
            }
            ui.hyperlink_to(
                format!("Get a key {}", egui_phosphor::regular::ARROW_SQUARE_OUT),
                self.source.keys_url(),
            );
        });
    }

    fn search_bar(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut search = None;
        let mut all = false;
        let ready = self.key_saved && self.searching.is_none();
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.key_saved
                    && !self.editing_key
                    && ui
                        .button(format!("{} Key", egui_phosphor::regular::KEY))
                        .on_hover_text(format!("Change the {} API key", self.source.label()))
                        .clicked()
                {
                    self.editing_key = true;
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest (all)"))
                    .on_hover_text(match self.source {
                        Source::MalwareBazaar => {
                            "MalwareBazaar's latest 100 uploads of every type (it lists no \
                             architectures for these)"
                        }
                        Source::MalShare => {
                            "MalShare's newest uploads of every type (hashes only until \
                             searched or downloaded)"
                        }
                    })
                    .clicked()
                {
                    self.text.clear();
                    all = true;
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Newest Linux"))
                    .on_hover_text("The newest ELF programs and shell scripts: what the VMs run")
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
                    ui.spinner();
                }
                let edit = ui.add_sized(
                    egui::vec2(ui.available_width(), ui.spacing().interact_size.y),
                    egui::TextEdit::singleline(&mut self.text)
                        .hint_text(format!(
                            "{}  {}",
                            egui_phosphor::regular::MAGNIFYING_GLASS,
                            match self.source {
                                Source::MalwareBazaar =>
                                    "Family, tag, file type or hash (Mirai, x86-64, elf, a SHA-256…)",
                                Source::MalShare =>
                                    "Hash, file type (elf, pe32) or a word in file names and sources",
                            }
                        ))
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
            // MalShare's terms ask that it is credited as the source.
            ui.colored_label(
                theme::muted(),
                "Samples from MalShare (malshare.com), searched by hash, file type, file name \
                 or source; MalShare names no families. Free keys allow 2000 requests a day.",
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

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let types = choices(&self.results, |s| vec![s.file_type.to_lowercase()]);
        let arches = choices(&self.results, |s| {
            vec![arch(s).unwrap_or_else(|| UNKNOWN_ARCH.into())]
        });
        let families = choices(&self.results, |s| s.signature.clone().into_iter().collect());
        let tags = choices(&self.results, |s| s.tags.clone());
        let count = shown(&self.results, &self.filters, None).len();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            choice(
                ui,
                "samples_type",
                "File type",
                &mut self.filters.file_type,
                &types,
            );
            choice(
                ui,
                "samples_arch",
                "Architecture",
                &mut self.filters.arch,
                &arches,
            );
            choice(
                ui,
                "samples_family",
                "Family",
                &mut self.filters.family,
                &families,
            );
            let ticked = &mut self.filters.tags;
            egui::ComboBox::from_id_salt("samples_tags")
                .selected_text(match ticked.len() {
                    0 => "Tags: all".to_string(),
                    1 => format!("Tags: {}", ticked.iter().next().map_or("", String::as_str)),
                    n => format!("Tags: {n} ticked"),
                })
                .height(360.0)
                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                .show_ui(ui, |ui| {
                    if ui
                        .add_enabled(!ticked.is_empty(), egui::Button::new("Clear"))
                        .clicked()
                    {
                        ticked.clear();
                    }
                    for (tag, count) in &tags {
                        let mut on = ticked.contains(tag);
                        if ui.checkbox(&mut on, format!("{tag}  ({count})")).changed() {
                            if on {
                                ticked.insert(tag.clone());
                            } else {
                                ticked.remove(tag);
                            }
                        }
                    }
                })
                .response
                .on_hover_text("Samples with any of the ticked tags");
            if self.filters.active() && ui.button("Clear filters").clicked() {
                self.filters = Filters::default();
            }
            if !self.results.is_empty() {
                ui.colored_label(
                    theme::muted(),
                    format!("{count} of {} · {}", self.results.len(), self.listing),
                );
            }
        });
    }

    fn results_table(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
    ) {
        if self.results.is_empty() {
            let text = if !self.key_saved {
                format!(
                    "Save a {} API key to list the newest samples.",
                    self.source.label()
                )
            } else if self.searching.is_some() {
                format!("Asking {}…", self.source.label())
            } else if self.listing.is_empty() {
                "Search by family, tag, file type or hash.".to_string()
            } else {
                format!("{}: nothing found.", self.listing)
            };
            ui.add_space(8.0);
            ui.colored_label(theme::muted(), text);
            return;
        }
        let order = shown(&self.results, &self.filters, self.sort);
        if order.is_empty() {
            ui.add_space(8.0);
            ui.colored_label(theme::muted(), "No sample matches the filters.");
            return;
        }
        let mono = theme::mono(cx.font_size - 1.0);
        let row_height = theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
        let mut download = None;
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("samples_results")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(190.0))
            .column(Column::initial(200.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(120.0).clip(true))
            .column(Column::initial(70.0))
            .column(Column::initial(110.0))
            .column(Column::initial(90.0))
            .column(Column::initial(200.0).clip(true))
            .column(Column::remainder().at_least(130.0))
            .header(row_height, |mut header| {
                for column in Col::ALL {
                    header.col(|ui| {
                        let mark = match self.sort {
                            Some(sort) if sort.column == column => {
                                if sort.descending {
                                    " ⏷"
                                } else {
                                    " ⏶"
                                }
                            }
                            _ => "",
                        };
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(format!("{}{mark}", column.label()))
                                        .strong()
                                        .color(theme::heading()),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text("Sort; a third click restores the source's order")
                            .clicked()
                        {
                            clicked = Some(column);
                        }
                    });
                }
                header.col(|_| {});
            })
            .body(|body| {
                body.rows(row_height, order.len(), |mut row| {
                    let sample = &self.results[order[row.index()]];
                    row.col(|ui| {
                        ui.label(
                            RichText::new(&sample.first_seen)
                                .font(mono.clone())
                                .color(theme::muted()),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&sample.file_name).font(mono.clone()))
                                .truncate(),
                        )
                        .on_hover_text(&sample.sha256_hash);
                    });
                    row.col(|ui| {
                        let hash = &sample.sha256_hash;
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(format!("{}…", &hash[..16.min(hash.len())]))
                                        .font(mono.clone())
                                        .color(theme::value(ValueKind::Number)),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text(format!("{hash}\nClick to copy"))
                            .clicked()
                        {
                            ui.ctx().copy_text(hash.clone());
                        }
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(sample.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(&sample.file_type);
                    });
                    row.col(|ui| match arch(sample) {
                        Some(label) => {
                            let runs = sample.may_run();
                            ui.label(RichText::new(label).color(if runs {
                                theme::good()
                            } else {
                                theme::text()
                            }))
                            .on_hover_text(if sample.is_script() {
                                "A shell script: runs in the guests through /bin/sh"
                            } else if runs {
                                "Runs in Antinomie's x86-64 guests"
                            } else {
                                "Will not run in the x86-64 guests"
                            });
                        }
                        None => {
                            ui.colored_label(theme::muted(), "?").on_hover_text(
                                "Not listed by the source (MalwareBazaar's newest uploads, \
                                     MalShare): search a family, tag or file type on \
                                     MalwareBazaar, or download the sample to read it",
                            );
                        }
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(if sample.file_size == 0 {
                                "-".to_string()
                            } else {
                                format_size(sample.file_size)
                            })
                            .color(theme::value(ValueKind::Number)),
                        );
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(sample.tags.join(", ")).truncate())
                            .on_hover_text(sample.tags.join(", "));
                    });
                    row.col(|ui| {
                        let hash = &sample.sha256_hash;
                        if stored.iter().any(|s| &s.info.sha256_hash == hash) {
                            ui.colored_label(theme::good(), "Downloaded");
                        } else if self.downloads.contains_key(hash) {
                            ui.spinner();
                        } else if ui
                            .button(format!(
                                "{} Download",
                                egui_phosphor::regular::DOWNLOAD_SIMPLE
                            ))
                            .clicked()
                        {
                            download = Some(sample.clone());
                        }
                    });
                });
            });
        if let Some(column) = clicked {
            self.sort = next_sort(self.sort, column);
        }
        if let Some(sample) = download {
            let (sender, receiver) = mpsc::channel();
            let (curl, key, data): (PathBuf, String, PathBuf) =
                (cx.curl.into(), self.key.clone(), cx.data_dir.into());
            let source = self.results_source;
            let hash = sample.sha256_hash.clone();
            std::thread::spawn(move || {
                let _ = sender.send(source.download(&curl, &key, &data, &sample));
            });
            self.downloads.insert(hash, receiver);
        }
    }

    fn stored_list(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
        height: f32,
    ) -> Option<SamplesAction> {
        let mut action = None;
        let mut delete = None;
        ui.horizontal(|ui| {
            theme::section(ui, &format!("Downloaded ({})", stored.len()));
            ui.add_space(12.0);
            ui.label(RichText::new("Run as").color(theme::muted()));
            ui.selectable_value(&mut self.as_root, false, "guest user");
            ui.selectable_value(&mut self.as_root, true, "root");
            if let Some(name) = cx.vm_name {
                ui.add_space(8.0);
                ui.colored_label(theme::muted(), format!("VM: {name}"));
            }
            if !cx.running {
                ui.colored_label(theme::warn(), "· start the VM to send samples into it");
            }
        });
        ui.add_space(6.0);
        if stored.is_empty() {
            ui.colored_label(theme::muted(), "No samples downloaded yet.");
            return None;
        }
        let pending = self.pending.is_some() || self.awaiting.is_some();
        let mono = theme::mono(cx.font_size - 1.0);
        let row_height = theme::row_height(cx.font_size).max(ui.spacing().interact_size.y + 4.0);
        TableBuilder::new(ui)
            .id_salt("samples_stored")
            .striped(true)
            .auto_shrink([false, true])
            .max_scroll_height(height)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(130.0).clip(true))
            .column(Column::initial(110.0))
            .column(Column::initial(90.0))
            .column(Column::initial(90.0))
            .column(Column::remainder().at_least(380.0))
            .body(|body| {
                body.rows(row_height, stored.len(), |mut row| {
                    let sample = &stored[row.index()];
                    let info = &sample.info;
                    let arch = arch(info);
                    let runs_here = info.is_script() || arch.as_deref() == Some("x86-64");
                    row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(&info.file_name).font(mono.clone())).truncate())
                            .on_hover_text(format!(
                                "SHA-256 {}\nFrom {} · first seen {}",
                                info.sha256_hash, sample.source, info.first_seen
                            ));
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(info.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(arch.as_deref().unwrap_or("not an ELF")).color(if runs_here {
                                theme::good()
                            } else {
                                theme::warn()
                            }),
                        )
                        .on_hover_text(if info.is_script() {
                            "A shell script: runs in the guests through /bin/sh"
                        } else if runs_here {
                            "Runs in Antinomie's x86-64 guests"
                        } else {
                            "Built for another processor or not a Linux program: it will not run in the x86-64 guests"
                        });
                    });
                    row.col(|ui| {
                        ui.colored_label(theme::muted(), format_size(info.file_size));
                    });
                    row.col(|ui| {
                        ui.colored_label(
                            theme::muted(),
                            match sample.pushes.len() {
                                0 => "not sent".to_string(),
                                1 => "sent once".to_string(),
                                n => format!("sent {n}×"),
                            },
                        )
                        .on_hover_text(
                            sample
                                .pushes
                                .iter()
                                .map(|push| format!("{} · {}", push.vm_name, push.path))
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
                    });
                    row.col(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .button(RichText::new("Delete").color(theme::error()))
                                .clicked()
                            {
                                delete = Some(info.sha256_hash.clone());
                            }
                            if ui
                                .button(egui_phosphor::regular::COPY)
                                .on_hover_text("Copy the SHA-256")
                                .clicked()
                            {
                                ui.ctx().copy_text(info.sha256_hash.clone());
                            }
                            let can = cx.running && !pending;
                            let destination = guest_path(info, sample.pushes.len());
                            if ui
                                .add_enabled(can && runs_here, egui::Button::new("Send and run…"))
                                .on_hover_text(format!(
                                    "Send to {destination}, then open Run program with it to choose how it runs"
                                ))
                                .on_disabled_hover_text(if runs_here {
                                    "Start the VM first"
                                } else {
                                    "Only x86-64 Linux programs and shell scripts run in the guests"
                                })
                                .clicked()
                            {
                                let uid = if self.as_root { 0 } else { 1000 };
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination: destination.clone(),
                                    // Scripts through /bin/sh: many have no #! line.
                                    run: Some(ExecRequest {
                                        path: if info.is_script() {
                                            "/bin/sh".into()
                                        } else {
                                            destination.clone()
                                        },
                                        args: if info.is_script() {
                                            vec![destination.clone()]
                                        } else {
                                            Vec::new()
                                        },
                                        uid,
                                        gid: uid,
                                        cwd: "/tmp".into(),
                                        ..ExecRequest::default()
                                    }),
                                });
                            }
                            if ui
                                .add_enabled(can, egui::Button::new("Send to VM"))
                                .on_hover_text(format!(
                                    "Send to {destination} without running it (executable)"
                                ))
                                .on_disabled_hover_text("Start the VM first")
                                .clicked()
                            {
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination,
                                    run: None,
                                });
                            }
                        });
                    });
                });
            });
        if let Some(hash) = delete {
            self.status = Some(match samples::delete(cx.data_dir, &hash) {
                Ok(()) => ("Sample deleted".into(), false),
                Err(error) => (error, true),
            });
            self.stored = None;
        }
        if let Some(SamplesAction::Push { run, .. }) = &action {
            self.awaiting = Some(run.clone());
        }
        action
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
        let mut view = SamplesView {
            open: true,
            ..SamplesView::default()
        };
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            assert!(view.show(ctx, &cx).is_none());
        });
        assert!(view.open && !view.acknowledged);
        samples::acknowledge(&data).unwrap();
        let mut view = SamplesView {
            open: true,
            ..SamplesView::default()
        };
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
