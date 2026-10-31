//! "Build base" wizard: Debian-installer-style questions, then a
//! build that runs natively or in the QEMU builder VM and installs itself.

use crate::theme;
use antinomie_monitor_core::{
    build::{
        self, BuildMode, BuildOptions, BuildRequest, Kind, BUILD_PROFILES, KEYBOARD_LAYOUTS,
        KEYBOARD_VARIANTS, LOCALES, TIMEZONES,
    },
    toolchain, BuildStatus,
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
        Kind::DebianXfce | Kind::DebianMinimal => &[
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
    /// Answers per `BUILD_PROFILES` entry.
    options: [BuildOptions; 3],
    search: String,
    /// Show the last build's progress instead of the questions.
    show_status: bool,
    /// What this computer uses, offered as the defaults and marked in lists.
    detected: build::HostLocale,
    /// The page whose list was last scrolled to its selection.
    scrolled: Option<Page>,
    /// The builder images each ready engine held, and when that was looked up.
    images: Option<(std::time::Instant, Vec<EngineImages>)>,
}

type EngineImages = (
    antinomie_monitor_core::container::Engine,
    Result<Vec<antinomie_monitor_core::container::ImageInfo>, String>,
);
impl Default for BuildWizard {
    fn default() -> Self {
        Self {
            profile: 0,
            page: 0,
            mode: BuildMode::Automatic,
            options: std::array::from_fn(|index| {
                BuildOptions::defaults(BUILD_PROFILES[index].kind)
            }),
            search: String::new(),
            show_status: true,
            detected: build::HostLocale::detect(),
            scrolled: None,
            images: None,
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
                    text.strong().color(theme::blue())
                } else if index < self.page {
                    text.color(theme::text())
                } else {
                    text.color(theme::muted())
                };
                ui.label(text);
                if index + 1 < pages.len() {
                    ui.label(RichText::new("›").color(theme::muted()));
                }
            }
        });
        ui.separator();
        let mut action = None;
        let valid = match page {
            Page::Base => self.base(ui),
            Page::Mode => self.mode_page(ui, data_dir),
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
                    .add_enabled(
                        ready,
                        egui::Button::new(
                            RichText::new("Build").color(theme::palette().primary_text),
                        )
                        .fill(theme::primary()),
                    )
                    .clicked()
                {
                    self.show_status = true;
                    action = Some(Action::Build(Box::new(self.request())));
                }
            } else if ui
                .add_enabled(
                    valid,
                    egui::Button::new(
                        RichText::new("Continue").color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
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
                Kind::DebianMinimal => {
                    "Debian 13 without a desktop: console login, APT and standard tools; \
                     shares BusyBox's kernel"
                }
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

    fn mode_page(&mut self, ui: &mut egui::Ui, data_dir: &std::path::Path) -> bool {
        let kind = self.kind();
        ui.label("Where should the build run?");
        for (mode, label, detail) in [
            (
                BuildMode::Automatic,
                "Automatic",
                "The first that can run here: on this host, then Podman, then Docker, then the QEMU \
                 builder VM",
            ),
            (
                BuildMode::Native,
                "Native (on this Linux host)",
                "Fastest; needs the kernel and image tool suite. Debian Minimal's kernel is \
                 compiled with Debian 13's toolchain: this host's when it is that, else a \
                 rootless Debian 13 chroot (needs mmdebstrap, unshare and a subordinate UID range)",
            ),
            (
                BuildMode::Podman,
                "Podman container",
                "A pinned Debian 13 container; rootless Podman needs no root access",
            ),
            (
                BuildMode::Docker,
                "Docker container",
                "A pinned Debian 13 container. Docker needs root-equivalent access (membership in \
                 the docker group), which is why Podman comes first",
            ),
            (
                BuildMode::Qemu,
                "QEMU builder",
                "A builder VM; needs only QEMU and curl, and downloads Debian's cloud image once",
            ),
        ] {
            ui.radio_value(&mut self.mode, mode, label);
            ui.small(format!("    {detail}"));
            if mode != BuildMode::Automatic {
                let missing = build::missing(kind, mode).into_iter().filter(|_| mode.engine().is_none());
                let missing: Vec<_> = missing.collect();
                if !missing.is_empty() {
                    crate::activity::warning(
                        ui,
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
                } else if let Some(obstacle) = build::mode_obstacle(kind, mode) {
                    crate::activity::warning(ui, format!("    {obstacle}"));
                } else if let Some(engine) = mode.engine() {
                    let standing = antinomie_monitor_core::container::cached_standing(engine);
                    if let Ok(ready) = standing.ready.as_ref() {
                        ui.small(format!(
                            "    {} {} is ready{}; {}",
                            engine.label(),
                            ready.version,
                            if ready.rootless { " (rootless)" } else { "" },
                            if standing.image == Some(true) {
                                "the builder image is present"
                            } else {
                                "the builder image is built on first use (needs the network once)"
                            }
                        ));
                    }
                }
            }
        }
        ui.add_space(6.0);
        match build::resolve_mode(kind, self.mode) {
            Ok(BuildMode::Native) => {
                ui.colored_label(theme::good(), "The build will run on this host.");
                ui.small(format!(
                    "Kernel {}.",
                    toolchain::describe(kind, &data_dir.join("build"))
                ));
                Self::toolchain_cache(ui, data_dir);
                self.images(ui);
                true
            }
            Ok(mode @ (BuildMode::Podman | BuildMode::Docker)) => {
                ui.colored_label(
                    theme::good(),
                    format!("The build will run in a {} container.", mode.label()),
                );
                if self.mode == BuildMode::Automatic
                    && build::resolve_mode(kind, BuildMode::Qemu).is_ok()
                {
                    ui.small("If the builder image cannot be had (offline), the QEMU builder VM is used instead and the log says why.");
                }
                self.images(ui);
                true
            }
            Ok(_) => {
                ui.colored_label(theme::good(), "The build will run in the QEMU builder VM.");
                if !std::path::Path::new("/dev/kvm").exists() {
                    crate::activity::warning(ui,
                        "No KVM: the builder VM runs without hardware acceleration and can take many hours.",
                    );
                }
                self.images(ui);
                true
            }
            Err(error) => {
                crate::activity::error(ui, error);
                self.images(ui);
                false
            }
        }
    }

    /// The cached Debian 13 toolchain chroot: its size and a way to delete it.
    fn toolchain_cache(ui: &mut egui::Ui, data_dir: &std::path::Path) {
        let dir = toolchain::chroot_dir(&data_dir.join("build"));
        if !dir.exists() {
            return;
        }
        ui.horizontal(|ui| {
            ui.small(format!(
                "Toolchain chroot cache: {} in {}",
                antinomie_monitor_core::byte_size::file_size(toolchain::size(&dir)),
                dir.display()
            ));
            if ui
                .small_button("Delete")
                .on_hover_text(
                    "The next native Debian Minimal build downloads and unpacks it again.",
                )
                .clicked()
                && let Err(error) = toolchain::remove(&dir)
            {
                crate::activity::report(
                    ui.ctx(),
                    crate::activity::Level::Warn,
                    format!("could not delete the toolchain chroot: {error}"),
                );
            }
        });
    }

    /// The builder images the container engines hold, with a way to remove them.
    fn images(&mut self, ui: &mut egui::Ui) {
        use antinomie_monitor_core::container::{self, Engine, SystemRunner};
        let ready: Vec<Engine> = Engine::ALL
            .into_iter()
            .filter(|engine| container::cached_standing(*engine).ready.is_ok())
            .collect();
        if ready.is_empty() {
            return;
        }
        if self
            .images
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() > std::time::Duration::from_secs(20))
        {
            let listed = ready
                .iter()
                .map(|engine| (*engine, container::list_images(*engine, &SystemRunner)))
                .collect();
            self.images = Some((std::time::Instant::now(), listed));
        }
        let mut removed = false;
        egui::CollapsingHeader::new("Builder images")
            .id_salt("build_builder_images")
            .show(ui, |ui| {
                ui.small(
                    "The container builder keeps its Debian 13 image so later builds start fast. \
                     Removing it only means the next container build makes it again.",
                );
                for (engine, listing) in self.images.iter().flat_map(|(_, listed)| listed) {
                    match listing {
                        Ok(images) if images.is_empty() => {
                            ui.small(format!("{}: no builder image", engine.label()));
                        }
                        Ok(images) => {
                            for image in images {
                                ui.horizontal(|ui| {
                                    ui.label(format!(
                                        "{}: {} ({}){}",
                                        engine.label(),
                                        image.tag,
                                        image.size,
                                        if image.current { ", this app's" } else { "" }
                                    ));
                                    if ui.button("Remove").clicked() {
                                        if let Err(error) = container::remove_image(
                                            *engine,
                                            &SystemRunner,
                                            &image.tag,
                                        ) {
                                            crate::activity::report(
                                                ui.ctx(),
                                                crate::activity::Level::Warn,
                                                format!("could not remove {}: {error}", image.tag),
                                            );
                                        }
                                        removed = true;
                                    }
                                });
                            }
                        }
                        Err(error) => {
                            ui.small(format!("{}: cannot list images ({error})", engine.label()));
                        }
                    }
                }
            });
        if removed {
            container::forget_standing();
            self.images = None;
        }
    }

    /// Scroll a page's list to its selection the first time the page shows.
    fn take_scroll(&mut self, page: Page) -> bool {
        let first = self.scrolled != Some(page);
        self.scrolled = Some(page);
        first
    }

    fn language(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Language")
            .on_hover_text("Choose the language and locale of the installed system.");
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
                crate::activity::error(ui, error);
                false
            }
        }
    }

    fn software(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label("Choose software to install.");
        let minimal = self.kind() == Kind::DebianMinimal;
        let detected = self.detected.desktop.clone();
        let options = &mut self.options[self.profile];
        if minimal {
            ui.label(
                "No desktop environment: the guest has a console login on its virtual \
                 terminals, APT and the standard Debian command-line tools.",
            );
        } else {
            ui.label(RichText::new("Debian desktop environment").strong());
        }
        for desktop in build::DESKTOPS.iter().filter(|_| !minimal) {
            ui.horizontal(|ui| {
                ui.radio_value(&mut options.desktop, desktop.id.to_string(), desktop.label);
                if detected.as_deref() == Some(desktop.id) {
                    ui.colored_label(theme::good(), "this computer");
                }
                if !desktop.verified {
                    ui.colored_label(theme::warn(), "untested")
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
                .hint_text(theme::hint_text("http://user:password@host:port/")),
        )
        .on_hover_text("The proxy is used while building and is not kept in the image.");
        let mut probe = options.clone();
        probe.hostname = "probe".into();
        match probe.validate(self.kind()) {
            Ok(()) => true,
            Err(error) if error.contains("mirror") || error.contains("proxy") => {
                crate::activity::error(ui, error);
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
                    .hint_text(crate::theme::hint_text(&automatic)),
            )
            .on_hover_text("Shown in the base list; leave empty for the automatic name.");
        });
        ui.add_space(6.0);
        let options = self.options[self.profile].clone();
        let mode = match build::resolve_mode(kind, self.mode) {
            Ok(BuildMode::Native) => match toolchain::for_kind(kind) {
                toolchain::Toolchain::Host => "on this host".to_string(),
                toolchain::Toolchain::Chroot => {
                    "on this host, in a rootless Debian 13 toolchain chroot".to_string()
                }
            },
            Ok(mode @ (BuildMode::Podman | BuildMode::Docker)) => {
                format!("in a {} container", mode.label())
            }
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
        if kind.is_debian() {
            let software = if kind == Kind::DebianMinimal {
                "Console only, no desktop".to_string()
            } else {
                format!(
                    "{} desktop",
                    build::DESKTOPS
                        .iter()
                        .find(|desktop| desktop.id == options.desktop)
                        .map_or(options.desktop.as_str(), |desktop| desktop.label)
                )
            };
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
                        "{software}{}",
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
                    ui.label(RichText::new(name).color(theme::muted()));
                    ui.label(value);
                    ui.end_row();
                }
            });
        ui.add_space(6.0);
        ui.small(match (kind, kernel_cached) {
            (Kind::BusyBox, true) => "Kernel already built.",
            (Kind::BusyBox, false) => "Kernel build ~10 min (cached afterwards).",
            (Kind::DebianMinimal, true) => "Kernel already built. Needs about 6 GiB free.",
            (Kind::DebianMinimal, false) => {
                "Kernel build ~10 min (cached afterwards). Needs about 11 GiB free."
            }
            (Kind::DebianXfce, true) => "Kernel already built. Needs about 20 GiB free.",
            (Kind::DebianXfce, false) => {
                "Kernel build 1-2 hours (cached afterwards). Needs about 50 GiB free."
            }
        });
        match options.validate(kind) {
            Ok(()) => true,
            Err(error) => {
                crate::activity::error(ui, error);
                false
            }
        }
    }

    fn progress(&mut self, ui: &mut egui::Ui, status: &BuildStatus) -> Option<Action> {
        let mut action = None;
        let stages: &[(&str, &str)] =
            if status.mode == BuildMode::Qemu || status.mode.engine().is_some() {
                &[
                    ("prepare", "Kit and kernel source"),
                    (
                        "builder",
                        if status.mode == BuildMode::Qemu {
                            "Builder VM"
                        } else {
                            "Builder container"
                        },
                    ),
                    ("source", "Patch kernel"),
                    ("kernel", "Compile kernel"),
                    ("symbols", "Memory analysis symbols"),
                    ("image", "Build image"),
                    ("install", "Install base"),
                ]
            } else if status.profile == "debian-minimal"
                && toolchain::for_kind(Kind::DebianMinimal) == toolchain::Toolchain::Chroot
            {
                &[
                    ("prepare", "Kit and kernel source"),
                    ("toolchain", "Debian 13 toolchain"),
                    ("source", "Patch kernel"),
                    ("kernel", "Compile kernel"),
                    ("symbols", "Memory analysis symbols"),
                    ("image", "Build image"),
                    ("install", "Install base"),
                ]
            } else {
                &[
                    ("prepare", "Kit and kernel source"),
                    ("source", "Patch kernel"),
                    ("kernel", "Compile kernel"),
                    ("symbols", "Memory analysis symbols"),
                    ("image", "Build image"),
                    ("install", "Install base"),
                ]
            };
        ui.label(
            RichText::new(format!(
                "{} — {}",
                status.label,
                match status.mode {
                    BuildMode::Qemu => "QEMU builder VM".to_string(),
                    BuildMode::Podman | BuildMode::Docker => {
                        format!("{} container", status.mode.label())
                    }
                    _ => "this host".to_string(),
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
                    ("✔", theme::good())
                } else if index == current && status.error.is_some() {
                    ("✖", theme::error())
                } else if index == current && !status.finished {
                    ("●", theme::blue())
                } else {
                    ("○", theme::muted())
                };
                ui.colored_label(color, format!("{mark} {label}"));
            }
        });
        if let Some(error) = &status.error {
            crate::activity::error_toast(ui, error);
        } else if status.finished {
            ui.colored_label(theme::good(), "Base built and installed.");
        } else if let Some((_, label)) = stages.get(current) {
            ui.label(format!("{label}…"));
        }
        ui.add_space(6.0);
        // The build output stays inside its own scrolling panel; the lines above
        // carry the progress.
        let footer = ui.spacing().interact_size.y * 2.0 + 24.0;
        let height = (ui.available_height() - footer).max(160.0);
        egui::Frame::new()
            .fill(theme::terminal())
            .stroke(egui::Stroke::new(1.0_f32, theme::line()))
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_height(height);
                egui::ScrollArea::both()
                    .max_height(height)
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &status.log {
                            ui.label(
                                RichText::new(line)
                                    .monospace()
                                    .small()
                                    .color(theme::muted()),
                            );
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
        ui.label(RichText::new("Selected:").color(theme::muted()));
        ui.label(RichText::new(current).strong());
        if detected == Some(selected.as_str()) {
            ui.colored_label(theme::good(), "detected from this computer");
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
    fn debian_minimal_asks_like_the_installer_without_a_desktop() {
        assert_eq!(pages(Kind::DebianMinimal), pages(Kind::DebianXfce));
        let wizard = BuildWizard::default();
        assert_eq!(wizard.options.len(), BUILD_PROFILES.len());
        let index = BUILD_PROFILES
            .iter()
            .position(|profile| profile.id == "debian-minimal")
            .unwrap();
        let busybox = BUILD_PROFILES
            .iter()
            .position(|profile| profile.id == "busybox")
            .unwrap();
        assert_eq!(index, busybox + 1, "offered next to BusyBox");
        let wizard = BuildWizard {
            profile: index,
            ..BuildWizard::default()
        };
        let request = wizard.request();
        assert_eq!(request.profile, "debian-minimal");
        request.options.validate(Kind::DebianMinimal).unwrap();
    }

    #[test]
    fn request_carries_the_selected_profile_mode_and_answers() {
        let debian = BUILD_PROFILES
            .iter()
            .position(|profile| profile.id == "debian-xfce")
            .unwrap();
        let mut wizard = BuildWizard {
            profile: debian,
            mode: BuildMode::Qemu,
            ..BuildWizard::default()
        };
        wizard.options().hostname = "lab".into();
        let request = wizard.request();
        assert_eq!(request.profile, "debian-xfce");
        assert_eq!(request.mode, BuildMode::Qemu);
        assert_eq!(request.options.hostname, "lab");
        assert_eq!(wizard.options[0].hostname, "debian");
    }
}
