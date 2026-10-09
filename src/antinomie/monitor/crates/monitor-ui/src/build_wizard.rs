//! "Build base" wizard (ANT-T0028): Debian-installer-style questions, then a
//! build that runs natively or in the QEMU builder VM and installs itself.

use crate::theme;
use antinomie_monitor_core::{
    build::{
        self, BuildMode, BuildOptions, BuildRequest, Kind, BUILD_PROFILES, KEYBOARD_LAYOUTS,
        KEYBOARD_VARIANTS, LOCALES, TIMEZONES,
    },
    BuildStatus,
};
use eframe::egui::{self, RichText};

/// Wizard pages; BusyBox skips the Debian-only ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Base,
    Mode,
    Language,
    Keyboard,
    TimeZone,
    Hostname,
    Software,
    Mirror,
    Summary,
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Base => "Base",
            Self::Mode => "Build mode",
            Self::Language => "Language and locale",
            Self::Keyboard => "Keyboard",
            Self::TimeZone => "Time zone",
            Self::Hostname => "Hostname",
            Self::Software => "Software selection",
            Self::Mirror => "Package mirror",
            Self::Summary => "Summary",
        }
    }
}

pub fn pages(kind: Kind) -> &'static [Page] {
    match kind {
        Kind::BusyBox => &[Page::Base, Page::Mode, Page::Hostname, Page::Summary],
        Kind::DebianXfce => &[
            Page::Base,
            Page::Mode,
            Page::Language,
            Page::Keyboard,
            Page::TimeZone,
            Page::Hostname,
            Page::Software,
            Page::Mirror,
            Page::Summary,
        ],
    }
}

/// What the wizard asks the app to do this frame.
pub enum Action {
    Build(Box<BuildRequest>),
    Cancel,
}

pub struct BuildWizard {
    profile: usize,
    page: usize,
    mode: BuildMode,
    options: [BuildOptions; 2],
    search: String,
    /// Show the last build's progress instead of the questions.
    show_status: bool,
    /// What this computer uses, offered as the defaults and marked in lists.
    detected: build::HostLocale,
    /// The page whose list was last scrolled to its selection.
    scrolled: Option<Page>,
}
impl Default for BuildWizard {
    fn default() -> Self {
        Self {
            profile: 0,
            page: 0,
            mode: BuildMode::Automatic,
            options: [
                BuildOptions::defaults(Kind::BusyBox),
                BuildOptions::defaults(Kind::DebianXfce),
            ],
            search: String::new(),
            show_status: true,
            detected: build::HostLocale::detect(),
            scrolled: None,
        }
    }
}

impl BuildWizard {
    fn kind(&self) -> Kind {
        BUILD_PROFILES[self.profile].kind
    }
    fn options(&mut self) -> &mut BuildOptions {
        &mut self.options[self.profile]
    }
    pub fn request(&self) -> BuildRequest {
        BuildRequest {
            profile: BUILD_PROFILES[self.profile].id.to_string(),
            mode: self.mode,
            options: self.options[self.profile].clone(),
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        status: Option<&BuildStatus>,
        data_dir: &std::path::Path,
    ) -> Option<Action> {
        let running = status.is_some_and(|status| !status.finished);
        if let Some(status) = status.filter(|_| running || self.show_status) {
            return self.progress(ui, status);
        }
        let pages = pages(self.kind());
        self.page = self.page.min(pages.len() - 1);
        let page = pages[self.page];
        ui.horizontal_wrapped(|ui| {
            for (index, other) in pages.iter().enumerate() {
                let text = RichText::new(other.title());
                let text = if index == self.page {
                    text.strong().color(theme::BLUE)
                } else if index < self.page {
                    text.color(theme::TEXT)
                } else {
                    text.color(theme::MUTED)
                };
                ui.label(text);
                if index + 1 < pages.len() {
                    ui.label(RichText::new("›").color(theme::MUTED));
                }
            }
        });
        ui.separator();
        let mut action = None;
        let valid = match page {
            Page::Base => self.base(ui),
            Page::Mode => self.mode_page(ui),
            Page::Language => self.language(ui),
            Page::Keyboard => self.keyboard(ui),
            Page::TimeZone => self.time_zone(ui),
            Page::Hostname => self.hostname(ui),
            Page::Software => self.software(ui),
            Page::Mirror => self.mirror(ui),
            Page::Summary => self.summary(ui, build::kernel_cached(data_dir, self.kind())),
        };
        ui.separator();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.page > 0, egui::Button::new("Back"))
                .clicked()
            {
                self.page -= 1;
                self.search.clear();
            }
            if page == Page::Summary {
                let ready = valid
                    && build::resolve_mode(self.kind(), self.mode).is_ok()
                    && self.options[self.profile].validate(self.kind()).is_ok();
                if ui
                    .add_enabled(ready, egui::Button::new(RichText::new("Build").strong()))
                    .clicked()
                {
                    self.show_status = true;
                    action = Some(Action::Build(Box::new(self.request())));
                }
            } else if ui
                .add_enabled(valid, egui::Button::new("Continue"))
                .clicked()
            {
                self.page += 1;
                self.search.clear();
            }
            if status.is_some()
                && ui
                    .add(egui::Button::new("Last build").frame(false))
                    .clicked()
            {
                self.show_status = true;
            }
        });
        action
    }

    fn base(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Which base should be built?");
        for (index, profile) in BUILD_PROFILES.iter().enumerate() {
            let detail = match profile.kind {
                Kind::BusyBox => "Small console guest, fast to build",
                Kind::DebianXfce => "Debian 13 with the desktop you choose, as from the installer",
            };
            ui.radio_value(&mut self.profile, index, profile.label)
                .on_hover_text(detail);
            ui.small(format!("    {detail}"));
        }
        ui.add_space(6.0);
        ui.small(
            "The patched kernel is compiled from the patch series this app carries, so the base \
             always matches this app's revision. The result is installed automatically.",
        );
        true
    }

    fn mode_page(&mut self, ui: &mut egui::Ui) -> bool {
        let kind = self.kind();
        ui.label("Where should the build run?");
        for (mode, label, detail) in [
            (
                BuildMode::Automatic,
                "Automatic",
                "On this host when every tool is installed, otherwise in the QEMU builder VM",
            ),
            (
                BuildMode::Native,
                "On this Linux host",
                "Fastest; needs the kernel and image tool suite",
            ),
            (
                BuildMode::Qemu,
                "In a QEMU builder VM",
                "Needs only QEMU and curl; downloads Debian's cloud image once",
            ),
        ] {
            ui.radio_value(&mut self.mode, mode, label);
            ui.small(format!("    {detail}"));
            if mode != BuildMode::Automatic {
                let missing = build::missing(kind, mode);
                if !missing.is_empty() {
                    ui.colored_label(
                        theme::WARN,
                        format!(
                            "    missing: {}",
                            missing
                                .iter()
                                .map(|tool| tool.tool)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    );
                    ui.small(format!("    {}", build::install_hint(&missing)));
                } else if let Some(obstacle) =
                    build::native_obstacle(kind).filter(|_| mode == BuildMode::Native)
                {
                    ui.colored_label(theme::WARN, format!("    {obstacle}"));
                }
            }
        }
        ui.add_space(6.0);
        match build::resolve_mode(kind, self.mode) {
            Ok(BuildMode::Native) => {
                ui.colored_label(theme::GOOD, "The build will run on this host.");
                true
            }
            Ok(_) => {
                ui.colored_label(theme::GOOD, "The build will run in the QEMU builder VM.");
                if !std::path::Path::new("/dev/kvm").exists() {
                    ui.colored_label(
                        theme::WARN,
                        "No KVM: the builder VM runs without hardware acceleration and can take many hours.",
                    );
                }
                true
            }
            Err(error) => {
                ui.colored_label(theme::ERROR, error);
                false
            }
        }
    }

    /// Scroll a page's list to its selection the first time the page shows.
    fn take_scroll(&mut self, page: Page) -> bool {
        let first = self.scrolled != Some(page);
        self.scrolled = Some(page);
        first
    }

    fn language(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Choose the language and locale of the installed system.");
        let scroll = self.take_scroll(Page::Language);
        let options = &mut self.options[self.profile];
        pick_list(
            ui,
            "locale",
            &mut self.search,
            LOCALES
                .iter()
                .map(|(code, label)| (*code, format!("{label} — {code}"))),
            &mut options.locale,
            scroll,
            self.detected.locale.as_deref(),
        );
        true
    }

    fn keyboard(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Choose the keyboard layout.");
        let scroll = self.take_scroll(Page::Keyboard);
        let options = &mut self.options[self.profile];
        let before = options.keyboard_layout.clone();
        pick_list(
            ui,
            "layout",
            &mut self.search,
            KEYBOARD_LAYOUTS
                .iter()
                .map(|(code, label)| (*code, format!("{label} — {code}"))),
            &mut options.keyboard_layout,
            scroll,
            self.detected.layout.as_deref(),
        );
        if options.keyboard_layout != before {
            options.keyboard_variant.clear();
        }
        let layout = options.keyboard_layout.clone();
        let label = |variant: &str| {
            if variant.is_empty() {
                "Default".to_string()
            } else {
                KEYBOARD_VARIANTS
                    .iter()
                    .find(|(l, v, _)| *l == layout && *v == variant)
                    .map_or(variant.to_string(), |(_, _, label)| label.to_string())
            }
        };
        egui::ComboBox::from_label("Variant")
            .selected_text(label(&options.keyboard_variant))
            .width(360.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut options.keyboard_variant, String::new(), "Default");
                for (_, code, name) in KEYBOARD_VARIANTS.iter().filter(|(l, _, _)| *l == layout) {
                    ui.selectable_value(&mut options.keyboard_variant, code.to_string(), *name);
                }
            });
        true
    }

    fn time_zone(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Choose the time zone of the installed system.");
        let scroll = self.take_scroll(Page::TimeZone);
        let options = &mut self.options[self.profile];
        pick_list(
            ui,
            "timezone",
            &mut self.search,
            TIMEZONES.iter().map(|zone| (*zone, zone.replace('_', " "))),
            &mut options.timezone,
            scroll,
            self.detected.timezone.as_deref(),
        );
        true
    }

    fn hostname(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Hostname of the guest (one word: a-z, 0-9 and '-').");
        let options = self.options();
        ui.add(egui::TextEdit::singleline(&mut options.hostname).desired_width(260.0));
        match build::valid_hostname(&options.hostname) {
            Ok(()) => true,
            Err(error) => {
                ui.colored_label(theme::ERROR, error);
                false
            }
        }
    }

    fn software(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Choose software to install.");
        ui.label(RichText::new("Debian desktop environment").strong());
        let detected = self.detected.desktop.clone();
        let options = &mut self.options[self.profile];
        for desktop in build::DESKTOPS {
            ui.horizontal(|ui| {
                ui.radio_value(&mut options.desktop, desktop.id.to_string(), desktop.label);
                if detected.as_deref() == Some(desktop.id) {
                    ui.colored_label(theme::GOOD, "this computer");
                }
                if !desktop.verified {
                    ui.colored_label(theme::WARN, "untested")
                        .on_hover_text("Offered like the Debian installer, but not yet built and checked to reach its login screen");
                }
            });
        }
        ui.add_space(4.0);
        ui.checkbox(&mut options.standard, "Standard system utilities");
        ui.add_space(6.0);
        ui.small(
            "Not offered, by design: SSH server, guest agents and cloud-init (the monitor uses \
             only its kernel control channel). The user account is set per VM when it is created.",
        );
        true
    }

    fn mirror(&mut self, ui: &mut egui::Ui) -> bool {
        let options = self.options();
        ui.label("Debian archive mirror");
        ui.add(egui::TextEdit::singleline(&mut options.mirror).desired_width(420.0));
        ui.add_space(4.0);
        ui.label("HTTP proxy (leave empty for none)");
        ui.add(
            egui::TextEdit::singleline(&mut options.proxy)
                .desired_width(420.0)
                .hint_text("http://user:password@host:port/"),
        );
        ui.small("The proxy is used while building and is not kept in the image.");
        let mut probe = options.clone();
        probe.hostname = "probe".into();
        match probe.validate(Kind::DebianXfce) {
            Ok(()) => true,
            Err(error) if error.contains("mirror") || error.contains("proxy") => {
                ui.colored_label(theme::ERROR, error);
                false
            }
            Err(_) => true,
        }
    }

    fn summary(&mut self, ui: &mut egui::Ui, kernel_cached: bool) -> bool {
        let kind = self.kind();
        let automatic = build::automatic_base_name(kind, &self.options[self.profile].desktop);
        ui.horizontal(|ui| {
            ui.label("Base name");
            ui.add(
                egui::TextEdit::singleline(&mut self.options[self.profile].name)
                    .desired_width(320.0)
                    .hint_text(&automatic),
            );
        });
        ui.small("Shown in the base list; leave empty for the automatic name.");
        ui.add_space(6.0);
        let options = self.options[self.profile].clone();
        let mode = match build::resolve_mode(kind, self.mode) {
            Ok(BuildMode::Native) => "on this host".to_string(),
            Ok(_) => "in the QEMU builder VM".to_string(),
            Err(error) => error,
        };
        let mut rows = vec![
            ("Base", BUILD_PROFILES[self.profile].label.to_string()),
            (
                "Name",
                if options.name.trim().is_empty() {
                    automatic.clone()
                } else {
                    options.name.trim().to_string()
                },
            ),
            ("Build", mode),
            ("Hostname", options.hostname.clone()),
        ];
        if kind == Kind::DebianXfce {
            rows.extend([
                ("Locale", options.locale.clone()),
                (
                    "Keyboard",
                    if options.keyboard_variant.is_empty() {
                        options.keyboard_layout.clone()
                    } else {
                        format!("{} ({})", options.keyboard_layout, options.keyboard_variant)
                    },
                ),
                ("Time zone", options.timezone.clone()),
                (
                    "Software",
                    format!(
                        "{} desktop{}",
                        build::DESKTOPS
                            .iter()
                            .find(|desktop| desktop.id == options.desktop)
                            .map_or(options.desktop.as_str(), |desktop| desktop.label),
                        if options.standard {
                            ", standard system utilities"
                        } else {
                            ""
                        }
                    ),
                ),
                ("Mirror", options.mirror.clone()),
                (
                    "Proxy",
                    if options.proxy.is_empty() {
                        "none".into()
                    } else {
                        "set".into()
                    },
                ),
            ]);
        }
        egui::Grid::new("build-summary")
            .num_columns(2)
            .spacing([18.0, 4.0])
            .show(ui, |ui| {
                for (name, value) in rows {
                    ui.label(RichText::new(name).color(theme::MUTED));
                    ui.label(value);
                    ui.end_row();
                }
            });
        ui.add_space(6.0);
        ui.small(match (kind, kernel_cached) {
            (Kind::BusyBox, true) => {
                "The kernel for this app version is already built: only the image is made (a few minutes)."
            }
            (Kind::BusyBox, false) => {
                "The kernel is compiled first (about 10 minutes); later builds reuse it."
            }
            (Kind::DebianXfce, true) => {
                "The kernel for this revision is already built: only the system is installed \
                 (mostly package downloads). Needs about 20 GiB of free disk space."
            }
            (Kind::DebianXfce, false) => {
                "The Debian kernel with all its modules is compiled first, which can take one to \
                 two hours; later builds of this revision reuse it. Needs about 50 GiB of free \
                 disk space."
            }
        });
        match options.validate(kind) {
            Ok(()) => true,
            Err(error) => {
                ui.colored_label(theme::ERROR, error);
                false
            }
        }
    }

    fn progress(&mut self, ui: &mut egui::Ui, status: &BuildStatus) -> Option<Action> {
        let mut action = None;
        let stages: &[(&str, &str)] = if status.mode == BuildMode::Qemu {
            &[
                ("prepare", "Kit and kernel source"),
                ("builder", "Builder VM"),
                ("source", "Patch kernel"),
                ("kernel", "Compile kernel"),
                ("image", "Build image"),
                ("install", "Install base"),
            ]
        } else {
            &[
                ("prepare", "Kit and kernel source"),
                ("source", "Patch kernel"),
                ("kernel", "Compile kernel"),
                ("image", "Build image"),
                ("install", "Install base"),
            ]
        };
        ui.label(
            RichText::new(format!(
                "{} — {}",
                status.label,
                if status.mode == BuildMode::Qemu {
                    "QEMU builder VM"
                } else {
                    "this host"
                }
            ))
            .strong(),
        );
        let current = stages
            .iter()
            .position(|(id, _)| *id == status.stage)
            .unwrap_or(if status.stage == "done" {
                stages.len()
            } else {
                0
            });
        ui.horizontal_wrapped(|ui| {
            for (index, (_, label)) in stages.iter().enumerate() {
                let (mark, color) = if status.finished && status.error.is_none() || index < current
                {
                    ("✔", theme::GOOD)
                } else if index == current && status.error.is_some() {
                    ("✖", theme::ERROR)
                } else if index == current && !status.finished {
                    ("●", theme::BLUE)
                } else {
                    ("○", theme::MUTED)
                };
                ui.colored_label(color, format!("{mark} {label}"));
            }
        });
        if let Some(error) = &status.error {
            ui.colored_label(theme::ERROR, error);
        } else if status.finished {
            ui.colored_label(theme::GOOD, "Base built and installed.");
        } else if let Some((_, label)) = stages.get(current) {
            ui.label(format!("{label}…"));
        }
        ui.add_space(6.0);
        // The build output stays inside its own scrolling panel; the lines above
        // carry the progress.
        let footer = ui.spacing().interact_size.y * 2.0 + 24.0;
        let height = (ui.available_height() - footer).max(160.0);
        egui::Frame::new()
            .fill(theme::TERMINAL)
            .stroke(egui::Stroke::new(1.0_f32, theme::LINE))
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_height(height);
                egui::ScrollArea::both()
                    .max_height(height)
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &status.log {
                            ui.label(RichText::new(line).monospace().small().color(theme::MUTED));
                        }
                    });
            });
        if let Some(path) = &status.log_path {
            ui.small(format!("Full log: {}", path.display()));
        }
        ui.horizontal(|ui| {
            if !status.finished {
                if ui.button("Cancel build").clicked() {
                    action = Some(Action::Cancel);
                }
            } else if ui.button("New build…").clicked() {
                self.show_status = false;
                self.page = 0;
            }
        });
        action
    }
}

/// Searchable single-choice list: `items` are (value, label). The current
/// choice is named above the list (marked when it is what this computer
/// uses), and the list scrolls to it when `scroll` is set.
fn pick_list<'a>(
    ui: &mut egui::Ui,
    id: &str,
    search: &mut String,
    items: impl Iterator<Item = (&'a str, String)>,
    selected: &mut String,
    scroll: bool,
    detected: Option<&str>,
) {
    let items: Vec<_> = items.collect();
    let current = items
        .iter()
        .find(|(value, _)| *value == selected.as_str())
        .map_or(selected.clone(), |(_, label)| label.clone());
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Selected:").color(theme::MUTED));
        ui.label(RichText::new(current).strong());
        if detected == Some(selected.as_str()) {
            ui.colored_label(theme::GOOD, "detected from this computer");
        }
    });
    ui.horizontal(|ui| {
        ui.label("Search");
        ui.add(egui::TextEdit::singleline(search).desired_width(240.0));
    });
    let needle = search.to_lowercase();
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(360.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for (value, label) in items {
                if !needle.is_empty() && !label.to_lowercase().contains(&needle) {
                    continue;
                }
                let label = if detected == Some(value) {
                    format!("{label}  (this computer)")
                } else {
                    label
                };
                let response = ui.selectable_label(selected == value, label);
                if response.clicked() {
                    *selected = value.to_string();
                }
                if scroll && selected == value {
                    response.scroll_to_me(Some(egui::Align::Center));
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busybox_asks_only_for_hostname_and_debian_asks_like_the_installer() {
        assert_eq!(
            pages(Kind::BusyBox),
            &[Page::Base, Page::Mode, Page::Hostname, Page::Summary]
        );
        let debian = pages(Kind::DebianXfce);
        assert_eq!(debian.first(), Some(&Page::Base));
        assert_eq!(debian.last(), Some(&Page::Summary));
        for page in [
            Page::Language,
            Page::Keyboard,
            Page::TimeZone,
            Page::Software,
            Page::Mirror,
        ] {
            assert!(debian.contains(&page));
        }
    }

    #[test]
    fn request_carries_the_selected_profile_mode_and_answers() {
        let mut wizard = BuildWizard {
            profile: 1,
            mode: BuildMode::Qemu,
            ..BuildWizard::default()
        };
        wizard.options().hostname = "lab".into();
        let request = wizard.request();
        assert_eq!(request.profile, "debian-xfce");
        assert_eq!(request.mode, BuildMode::Qemu);
        assert_eq!(request.options.hostname, "lab");
        assert_eq!(wizard.options[0].hostname, "localhost");
    }
}
