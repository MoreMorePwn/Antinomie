// SPDX-License-Identifier: GPL-3.0-only
//! Tools > Settings > Network routes: the default route and the configuration of
//! each route (Tor, VPN through wireproxy, a SOCKS5 proxy, InetSim). They
//! are saved in the data folder, owner-only because they can hold a proxy
//! password, and read by the backend when a run starts. Nothing here is
//! written to the settings file that eframe keeps.
use super::dialogs::form_grid;
use super::*;
use crate::{
    tools_page::RouteProgram,
    widgets::{chip, Tone},
};
use antinomie_monitor_core::{
    analysis_tools::ToolStatus,
    route::{self, InetSimMode, RouteConfig, RouteKind, TorMode},
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
};

/// The result of a route test on its worker thread.
type Tested = (RouteKind, Result<String, String>);

fn look_up() -> Vec<RouteProgram> {
    [
        ("tor", "Tor client for the Tor route", "BSD-3-Clause"),
        (
            "wireproxy",
            "userspace WireGuard with a SOCKS5 port, for the VPN route",
            "ISC",
        ),
        (
            "inetsim",
            "fake Internet services, for the InetSim route",
            "GPL-2.0",
        ),
    ]
    .into_iter()
    .map(|(name, purpose, licence)| RouteProgram {
        name,
        purpose,
        licence,
        path: route::tool_on_path(name),
    })
    .collect()
}

pub(super) struct RouteSettings {
    /// What is saved; the Run form and the backend use this.
    pub config: RouteConfig,
    /// What the page edits.
    draft: RouteConfig,
    /// The saved file could not be read; the page then shows the defaults
    /// and says why, and saving replaces the file.
    load_error: Option<String>,
    status: Option<(String, bool)>,
    programs: Vec<RouteProgram>,
    testing: Option<(RouteKind, Receiver<Tested>)>,
    tested: Option<Tested>,
}

impl RouteSettings {
    pub fn load(data_dir: &Path) -> Self {
        let (config, load_error) = match route::load_config(data_dir) {
            Ok(config) => (config, None),
            Err(error) => (RouteConfig::default(), Some(error)),
        };
        Self {
            draft: config.clone(),
            config,
            load_error,
            status: None,
            programs: look_up(),
            testing: None,
            tested: None,
        }
    }

    /// The defaults, with nothing read from disk (tests build an app
    /// without a data folder of their own).
    #[cfg(test)]
    pub fn unloaded() -> Self {
        Self {
            config: RouteConfig::default(),
            draft: RouteConfig::default(),
            load_error: None,
            status: None,
            programs: Vec::new(),
            testing: None,
            tested: None,
        }
    }

    fn detect(&mut self) {
        self.programs = look_up();
    }

    pub fn programs(&self) -> &[RouteProgram] {
        &self.programs
    }

    fn program(&self, name: &str) -> Option<PathBuf> {
        self.programs
            .iter()
            .find(|program| program.name == name)
            .and_then(|program| program.path.clone())
    }

    fn dirty(&self) -> bool {
        self.draft != self.config
    }

    #[cfg(test)]
    pub fn dirty_for_tests(&self) -> bool {
        self.dirty()
    }

    /// Saves the draft owner-only after checking it.
    fn save(&mut self, data_dir: &Path) {
        self.status = Some(match route::save_config(data_dir, &self.draft) {
            Ok(()) => {
                self.config = self.draft.clone();
                self.load_error = None;
                ("Network routes saved".into(), false)
            }
            Err(error) => (error, true),
        });
    }

    fn start_test(&mut self, kind: RouteKind, data_dir: PathBuf, ctx: &egui::Context) {
        let (tx, rx) = mpsc::sync_channel(1);
        let (config, repaint) = (self.draft.clone(), ctx.clone());
        let spawned = std::thread::Builder::new()
            .name("route-test".into())
            .spawn(move || {
                let _ = tx.send((kind, route::test_route(&data_dir, &config, kind)));
                repaint.request_repaint_of(egui::ViewportId::ROOT);
            });
        match spawned {
            Ok(_) => {
                self.testing = Some((kind, rx));
                self.tested = None;
            }
            Err(error) => self.tested = Some((kind, Err(error.to_string()))),
        }
    }

    fn poll_test(&mut self, ctx: &egui::Context) {
        let Some((_, rx)) = &self.testing else { return };
        match rx.try_recv() {
            Ok(done) => {
                self.tested = Some(done);
                self.testing = None;
            }
            Err(mpsc::TryRecvError::Disconnected) => self.testing = None,
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
        }
    }
}

fn hint(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap())
}

fn inetsim_chip(ui: &mut egui::Ui, name: &str, found: &Option<PathBuf>) {
    match found {
        Some(path) => {
            chip(ui, format!("{name} found"), Tone::Good).on_hover_text(path.display().to_string());
        }
        None => {
            chip(ui, format!("{name} not found"), Tone::Warn)
                .on_hover_text("Install it from your distribution; it is looked up on PATH.");
        }
    }
}

impl MonitorApp {
    pub(super) fn open_routes_page(&mut self) {
        self.routes.detect();
    }

    /// Show Tools > Settings > Network routes.
    pub(super) fn open_routes_settings(&mut self) {
        self.settings_open = true;
        self.settings_page = super::settings_window::SettingsPage::NetworkRoutes;
        self.open_routes_page();
    }

    /// The managed tool `id` as the page shows it: a copy found on `PATH`
    /// counts as the system's, as it does when a route starts.
    pub(super) fn route_tool(&self, id: &str) -> Option<ToolStatus> {
        let mut tool = self
            .snapshot
            .analysis_tools
            .iter()
            .find(|tool| tool.id == id)
            .cloned()?;
        if tool.system.is_none() {
            tool.system = self
                .routes
                .program(id)
                .map(|path| path.display().to_string());
        }
        Some(tool)
    }

    /// Install, version and status of a route program, drawn like the other
    /// managed tools.
    fn route_tool_row(&mut self, ui: &mut egui::Ui, id: &str) {
        let Some(tool) = self.route_tool(id) else {
            return;
        };
        let install = self.snapshot.tool_install.clone();
        if let Some(command) =
            crate::tools_page::tool_row(ui, &tool, install.as_ref(), !self.closing)
        {
            self.send(command);
        }
    }

    /// The Test button of one route and what its last test said.
    fn route_test(&mut self, ui: &mut egui::Ui, kind: RouteKind) {
        let busy = self.routes.testing.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("Test"))
                .on_hover_text(
                    "Brings the route up the way a run would and connects through it to the \
                     check target. VPN starts wireproxy, and Tor its own tor, for the test and stops it again.",
                )
                .clicked()
            {
                self.routes.start_test(kind, self.options.data_dir.clone(), ui.ctx());
            }
            if self
                .routes
                .testing
                .as_ref()
                .is_some_and(|(k, _)| *k == kind)
            {
                theme::spinner(ui);
            }
            if let Some((tested, result)) = &self.routes.tested
                && *tested == kind
            {
                match result {
                    Ok(text) => chip(ui, text, Tone::Good),
                    Err(error) => chip(ui, "Not up", Tone::Error).on_hover_text(error),
                };
            }
        });
        if let Some((tested, Err(error))) = &self.routes.tested
            && *tested == kind
        {
            ui.add(egui::Label::new(RichText::new(error).small().color(theme::error())).wrap());
        }
    }

    pub(super) fn routes_page(&mut self, ui: &mut egui::Ui) {
        self.routes.poll_test(ui.ctx());
        if let Some(error) = &self.routes.load_error {
            crate::activity::warning(
                ui,
                format!(
                    "The saved route settings could not be read ({error}). Saving replaces them."
                ),
            );
        }
        hint(ui, "Used by VMs set to Routed; chosen per run.").on_hover_text(
            "Routes apply to VMs whose network is Routed. Each run picks one in the Run form; \
             a route that cannot start stops the run instead of falling back to another. \
             Everything runs as your user: no root, no firewall rules.",
        );
        ui.add_space(6.0);
        let found_inetsim = self.routes.program("inetsim");
        let draft = &mut self.routes.draft;
        form_grid("settings_routes_default", ui).show(ui, |ui| {
            ui.label("Default route");
            ui.vertical(|ui| {
                egui::ComboBox::from_id_salt("route-default")
                    .selected_text(draft.default_route.label())
                    .show_ui(ui, |ui| {
                        for kind in RouteKind::ALL {
                            ui.selectable_value(&mut draft.default_route, kind, kind.label())
                                .on_hover_text(kind.explain());
                        }
                    })
                    .response
                    .on_hover_text(draft.default_route.explain());
                hint(ui, draft.default_route.summary());
            });
            ui.end_row();
            ui.label("Internet");
            ui.vertical(|ui| {
                ui.checkbox(&mut draft.allow_lan, "Allow private network addresses")
                    .on_hover_text(
                        "Off: the Internet route reaches public addresses only, never this \
                         computer or your local network.",
                    );
            });
            ui.end_row();
        });
        ui.separator();
        ui.label(theme::section_title(ui, "Tor"));
        form_grid("settings_routes_tor", ui).show(ui, |ui| {
            ui.label("Tor");
            ui.vertical(|ui| {
                ui.radio_value(
                    &mut draft.tor.mode,
                    TorMode::Own,
                    "Antinomie runs its own tor for each run",
                );
                ui.radio_value(
                    &mut draft.tor.mode,
                    TorMode::Socks,
                    "Use a SOCKS address (a Tor you already run)",
                );
            });
            ui.end_row();
            if draft.tor.mode == TorMode::Own {
                ui.label("tor program");
                ui.vertical(|ui| {
                    ui.add(text_field(&mut draft.tor.program).desired_width(260.0))
                        .on_hover_text(
                            "Path to a tor program; empty uses PATH, then the copy installed below.\n\
                             Started when a run claims the route, on a free port of 127.0.0.1, with \
                             a private data folder of its own and no control port; stopped when the \
                             run ends. The run waits for Tor to finish bootstrapping and does not \
                             start if it cannot.",
                        );
                });
                ui.end_row();
            } else {
                ui.label("SOCKS address");
                ui.vertical(|ui| {
                    ui.add(text_field(&mut draft.tor.socks).desired_width(260.0))
                        .on_hover_text(
                            "Where your Tor listens (a tor service uses 127.0.0.1:9050). Antinomie \
                             does not start it; names are resolved by Tor.",
                        );
                });
                ui.end_row();
            }
            ui.label("Check target");
            ui.add(text_field(&mut draft.tor.probe).desired_width(260.0))
                .on_hover_text("host:port connected through Tor before a run; empty checks only that Tor answers.");
            ui.end_row();
        });
        if self.routes.draft.tor.mode == TorMode::Own {
            self.route_tool_row(ui, "tor");
        }
        self.route_test(ui, RouteKind::Tor);
        ui.separator();
        let draft = &mut self.routes.draft;
        ui.label(
            RichText::new("VPN (WireGuard)")
                .strong()
                .color(theme::heading()),
        );
        form_grid("settings_routes_vpn", ui).show(ui, |ui| {
            ui.label("wireproxy");
            ui.vertical(|ui| {
                ui.add(text_field(&mut draft.vpn.wireproxy).desired_width(260.0))
                    .on_hover_text(
                        "Path to the wireproxy program; empty uses PATH, then the copy installed below.",
                    );
            });
            ui.end_row();
            ui.label("Configuration file");
            ui.vertical(|ui| {
                ui.add(text_field(&mut draft.vpn.config).desired_width(260.0))
                    .on_hover_text(
                        "A wireproxy configuration with your WireGuard peer and a [Socks5] section. \
                         Antinomie starts wireproxy for each run and stops it afterwards. \
                         WireGuard runs in userspace, so no root is needed.",
                    );
                hint(ui, "Needs [Socks5] with BindAddress = 127.0.0.1:25344.");
            });
            ui.end_row();
            ui.label("Check target");
            ui.add(text_field(&mut draft.vpn.probe).desired_width(260.0))
                .on_hover_text(
                    "host:port connected through the tunnel before a run; empty skips it.",
                );
            ui.end_row();
            ui.label("OpenVPN");
            hint(ui, "Not supported.").on_hover_text(
                "OpenVPN needs a TUN device, which needs root. Run it yourself \
                 (for example in a container) with a SOCKS5 front end and use the SOCKS5 route.",
            );
            ui.end_row();
        });
        self.route_tool_row(ui, "wireproxy");
        self.route_test(ui, RouteKind::Vpn);
        ui.separator();
        let draft = &mut self.routes.draft;
        ui.label(
            RichText::new("SOCKS5 proxy")
                .strong()
                .color(theme::heading()),
        );
        form_grid("settings_routes_socks", ui).show(ui, |ui| {
            ui.label("Host");
            ui.add(text_field(&mut draft.socks5.host).desired_width(260.0));
            ui.end_row();
            ui.label("Port");
            ui.add(egui::DragValue::new(&mut draft.socks5.port).range(1..=65535));
            ui.end_row();
            ui.label("User name");
            ui.add(text_field(&mut draft.socks5.username).desired_width(260.0));
            ui.end_row();
            ui.label("Password").on_hover_text(
                "Saved in the data folder, readable by you only. Never logged, shown in run \
                 records or exported.",
            );
            ui.vertical(|ui| {
                super::dialogs::password_input(ui, &mut draft.socks5.password, "route_socks5_password");
            });
            ui.end_row();
            ui.label("Check target");
            ui.add(text_field(&mut draft.socks5.probe).desired_width(260.0))
                .on_hover_text("host:port connected through the proxy before a run; empty checks only the proxy login.");
            ui.end_row();
        });
        self.route_test(ui, RouteKind::Socks5);
        ui.separator();
        let draft = &mut self.routes.draft;
        ui.label(
            RichText::new("InetSim (fake services)")
                .strong()
                .color(theme::heading()),
        );
        form_grid("settings_routes_inetsim", ui).show(ui, |ui| {
            ui.label("Services");
            ui.vertical(|ui| {
                ui.radio_value(
                    &mut draft.inetsim.mode,
                    InetSimMode::Builtin,
                    "Built-in (DNS, HTTP, SMTP; other ports accept and discard)",
                );
                ui.radio_value(
                    &mut draft.inetsim.mode,
                    InetSimMode::External,
                    "A running INetSim of yours",
                );
            });
            ui.end_row();
            if draft.inetsim.mode == InetSimMode::External {
                ui.label("INetSim host");
                ui.add(text_field(&mut draft.inetsim.host).desired_width(260.0));
                ui.end_row();
                ui.label("Port offset");
                ui.vertical(|ui| {
                    ui.add(egui::DragValue::new(&mut draft.inetsim.port_offset).range(0..=60000))
                        .on_hover_text(
                            "A guest connection to port P goes to INetSim's port P plus the offset, \
                             so INetSim can run as your user on high ports (bind its services there).",
                        );
                });
                ui.end_row();
            }
            ui.label("DNS answers");
            ui.add(text_field(&mut draft.inetsim.sinkhole).desired_width(160.0))
                .on_hover_text("Every name resolves to this address. It is never connected to.");
            ui.end_row();
            ui.label("Program");
            inetsim_chip(ui, "inetsim", &found_inetsim);
            ui.end_row();
        });
        ui.add_space(8.0);
        let dirty = self.routes.dirty();
        let data_dir = self.options.data_dir.clone();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(dirty, primary_button("Save routes"))
                .clicked()
            {
                self.routes.save(&data_dir);
            }
            if ui.add_enabled(dirty, egui::Button::new("Revert")).clicked() {
                self.routes.draft = self.routes.config.clone();
                self.routes.status = None;
            }
            if let Some((text, is_error)) = &self.routes.status {
                ui.label(RichText::new(text).color(if *is_error {
                    theme::error()
                } else {
                    theme::good()
                }));
            } else if dirty {
                ui.label(RichText::new("Unsaved changes").color(theme::muted()));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ant-route-ui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_password_is_owner_only_and_a_bad_form_is_not_saved() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("save");
        let mut routes = RouteSettings::load(&dir);
        assert!(!routes.dirty());
        routes.draft.socks5.host = "127.0.0.1".into();
        routes.draft.socks5.username = "u".into();
        routes.draft.socks5.password = "hunter2".into();
        assert!(routes.dirty());
        routes.save(&dir);
        assert_eq!(routes.status.as_ref().map(|s| s.1), Some(false));
        assert_eq!(routes.config.socks5.password, "hunter2");
        let file = dir.join("network").join("routes.json");
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A user name without a password is refused and nothing changes.
        routes.draft.socks5.password.clear();
        routes.save(&dir);
        assert_eq!(routes.status.as_ref().map(|s| s.1), Some(true));
        assert_eq!(routes.config.socks5.password, "hunter2");
        assert_eq!(RouteSettings::load(&dir).config.socks5.username, "u");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_settings_file_is_reported_not_replaced_by_defaults_silently() {
        let dir = scratch("broken");
        std::fs::create_dir_all(dir.join("network")).unwrap();
        std::fs::write(dir.join("network").join("routes.json"), b"{not json").unwrap();
        let routes = RouteSettings::load(&dir);
        assert!(routes.load_error.is_some());
        assert_eq!(routes.config, RouteConfig::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
