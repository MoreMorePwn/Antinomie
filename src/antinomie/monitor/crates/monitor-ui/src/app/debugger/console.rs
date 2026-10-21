// SPDX-License-Identifier: MIT
//! The gdb console of the Debugger tab: host gdb, with GEF (bata24) or
//! pwndbg, on a terminal pane, connected to the session through the RSP
//! loopback server like any external gdb. While it is connected gdb is the
//! controller and the rest of the tab is read-only; the pane starts gdb when
//! it is opened and can restart it.
use super::{pty::Launch, pty::PtyChild, *};
use crate::{terminal::Terminal, widgets};
use antinomie_monitor_core::analysis_tools::{self, ToolStatus};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The gdb front end the console runs. GEF (bata24's fork) unless the user
/// chose pwndbg in Settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum GdbFlavour {
    #[default]
    Gef,
    Pwndbg,
}

impl GdbFlavour {
    pub const ALL: [Self; 2] = [Self::Gef, Self::Pwndbg];

    pub fn label(self) -> &'static str {
        match self {
            Self::Gef => "GEF (bata24)",
            Self::Pwndbg => "pwndbg",
        }
    }

    /// The managed tool that provides it.
    pub fn tool(self) -> &'static str {
        match self {
            Self::Gef => "gef",
            Self::Pwndbg => "pwndbg",
        }
    }
}

/// Whether a managed tool is a gdb front end, an option of the Debugger tab
/// that the first-run tool step leaves to Library, Analysis tools.
pub(crate) fn is_console_tool(id: &str) -> bool {
    GdbFlavour::ALL.iter().any(|flavour| flavour.tool() == id)
}

/// Why the console cannot start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unavailable {
    /// GEF needs gdb with Python from the system.
    NoGdb,
    /// The chosen front end is not installed.
    NoFlavour(GdbFlavour),
}

/// The command line that attaches `flavour` to the session's loopback port.
/// The server speaks plain `target remote`, as `debug-check` drives gdb.
/// `-nx` keeps the user's own gdbinit out of the session and debuginfod
/// stays off, so gdb never goes to the network by itself.
pub(super) fn launch(
    flavour: GdbFlavour,
    port: u16,
    gdb: Option<&Path>,
    tools: &[ToolStatus],
    data_dir: &Path,
) -> Result<Launch, Unavailable> {
    let status = tools.iter().find(|tool| tool.id == flavour.tool());
    let managed = analysis_tools::package(flavour.tool()).map(|package| {
        analysis_tools::tools_dir(data_dir)
            .join(package.id)
            .join(package.entry)
    });
    let connect = format!("target remote 127.0.0.1:{port}");
    let env = vec![("TERM", "xterm-256color"), ("DEBUGINFOD_URLS", "")];
    match flavour {
        GdbFlavour::Gef => {
            let gdb = gdb.ok_or(Unavailable::NoGdb)?;
            let script = status
                .filter(|tool| tool.installed.is_some())
                .and(managed)
                .ok_or(Unavailable::NoFlavour(flavour))?;
            Ok(Launch {
                program: gdb.to_owned(),
                args: vec![
                    "-nx".into(),
                    "-q".into(),
                    "-x".into(),
                    script.display().to_string(),
                    "-ex".into(),
                    connect,
                ],
                env,
                env_remove: Vec::new(),
                home: None,
            })
        }
        GdbFlavour::Pwndbg => {
            // A pwndbg of the system wins over Antinomie's portable copy,
            // which brings its own gdb.
            let program = status
                .and_then(|tool| tool.system.as_deref().map(PathBuf::from))
                .or_else(|| status.filter(|tool| tool.installed.is_some()).and(managed))
                .ok_or(Unavailable::NoFlavour(flavour))?;
            Ok(Launch {
                program,
                args: vec!["-nx".into(), "-q".into(), "-ex".into(), connect],
                env,
                // The portable launcher warns about these.
                env_remove: vec!["LD_LIBRARY_PATH", "LD_PRELOAD"],
                // A portable pwndbg reads the user's `~/.gdbinit` even with
                // `-nx`; one that sources another pwndbg (the usual setup of
                // a pwndbg user) makes it stop at once ("double-loading").
                home: Some(analysis_tools::tools_dir(data_dir).join(CONSOLE_HOME)),
            })
        }
    }
}

/// The home folder the pwndbg console runs with, under the tools folder.
const CONSOLE_HOME: &str = ".console-home";

/// `gdb` in `PATH`, as a shell would find it.
pub(super) fn find_gdb() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("gdb"))
        .find(|candidate| candidate.is_file())
}

/// The console's state in one debugger session. Dropping it ends gdb.
#[derive(Default)]
pub(crate) struct Console {
    terminal: Terminal,
    child: Option<PtyChild>,
    /// How the last gdb ended.
    ended: Option<String>,
    /// A start or restart was asked for and has not been acted on.
    start: bool,
    /// The flavour of the gdb running or last run.
    flavour: Option<GdbFlavour>,
    /// A start that failed (the program would not run).
    problem: Option<String>,
    /// `gdb` in `PATH`, looked up when the pane starts it.
    gdb: Option<Option<PathBuf>>,
    /// Everything gdb printed (tests read past what the screen still shows).
    #[cfg(test)]
    transcript: Vec<u8>,
}

impl Console {
    pub fn running(&self) -> bool {
        self.child.is_some()
    }

    /// Ask for gdb to be (re)started on the next draw.
    pub fn restart(&mut self) {
        self.stop();
        self.start = true;
        self.gdb = None;
    }

    /// End gdb; it detaches from the session on its way out.
    pub fn stop(&mut self) {
        self.child = None;
        self.start = false;
    }

    /// The pane's Stop: end gdb and keep it ended until Restart (a pane
    /// with no gdb and no ending would start one on its next draw).
    pub fn quit(&mut self) {
        self.stop();
        self.ended = Some("stopped".into());
    }

    #[cfg(test)]
    pub fn contents(&self) -> String {
        self.terminal.contents()
    }

    #[cfg(test)]
    pub fn set_gdb(&mut self, path: Option<PathBuf>) {
        self.gdb = Some(path);
    }

    /// Type into gdb's terminal, as keys pressed on the pane do.
    #[cfg(test)]
    pub fn type_text(&mut self, text: &str) {
        if let Some(child) = self.child.as_mut() {
            child.write(text.as_bytes());
        }
    }

    /// All gdb printed since the console started, escapes removed.
    #[cfg(test)]
    pub fn transcript(&self) -> String {
        let text = String::from_utf8_lossy(&self.transcript);
        let mut plain = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // CSI: ESC [ parameters final-byte; OSC: ESC ] ... BEL.
                match chars.peek() {
                    Some('[') => {
                        chars.next();
                        for c in chars.by_ref() {
                            if ('@'..='~').contains(&c) {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        for c in chars.by_ref() {
                            if c == '\u{7}' {
                                break;
                            }
                        }
                    }
                    _ => {
                        chars.next();
                    }
                }
            } else if c != '\r' {
                plain.push(c);
            }
        }
        plain
    }
}

/// What the pane needs from the app.
pub(super) struct Env<'a> {
    pub tools: &'a [ToolStatus],
    pub data_dir: &'a Path,
    pub flavour: GdbFlavour,
    pub port: u16,
    pub ended_session: bool,
}

/// What is wrong with a console that cannot start, in two parts: the
/// problem, and what to do about it.
pub(super) fn unavailable_text(reason: Unavailable) -> (String, String) {
    match reason {
        Unavailable::NoGdb => (
            "gdb was not found in PATH.".to_owned(),
            "GEF runs on this system's gdb: install your distribution's gdb package (with \
             Python support), or choose pwndbg in Settings, which brings its own gdb."
                .to_owned(),
        ),
        Unavailable::NoFlavour(flavour) => (
            format!("{} is not installed.", flavour.label()),
            "Antinomie installs it from its upstream release into its data folder, checked \
             by SHA-256."
                .to_owned(),
        ),
    }
}

/// Draw the pane into the space left in `ui`.
pub(super) fn show(
    ui: &mut egui::Ui,
    console: &mut Console,
    env: &Env<'_>,
    actions: &mut Vec<PanelAction>,
) {
    // The first draw of the pane starts gdb; after that it only restarts on
    // request.
    if console.child.is_none() && console.ended.is_none() && console.problem.is_none() {
        console.start = true;
    }
    let gdb = console.gdb.get_or_insert_with(find_gdb).clone();
    let plan = launch(
        env.flavour,
        env.port,
        gdb.as_deref(),
        env.tools,
        env.data_dir,
    );
    header(ui, console, env, &plan, actions);
    ui.add_space(2.0);
    let launch = match plan {
        Ok(launch) => launch,
        Err(reason) => {
            missing(ui, reason, actions);
            return;
        }
    };
    if env.ended_session {
        ui.weak("The debug session ended.");
        return;
    }
    if console.start && console.child.is_none() {
        console.start = false;
        console.ended = None;
        console.problem = None;
        console.terminal = Terminal::default();
        let ctx = ui.ctx().clone();
        match PtyChild::spawn(&launch, 24, 80, move || ctx.request_repaint()) {
            Ok(child) => {
                console.child = Some(child);
                console.flavour = Some(env.flavour);
            }
            Err(error) => {
                console.problem = Some(format!(
                    "{} did not start: {error}",
                    launch.program.display()
                ));
            }
        }
    }
    if let Some(problem) = &console.problem {
        crate::activity::error(ui, problem);
        return;
    }
    if let Some(child) = console.child.as_mut() {
        let (printed, ended) = child.poll();
        if !printed.is_empty() {
            console.terminal.process(&printed);
            #[cfg(test)]
            console.transcript.extend_from_slice(&printed);
        }
        if let Some(status) = ended {
            console.child = None;
            console.ended = Some(status);
        }
    }
    let running = console.child.is_some();
    if let Some(status) = console.ended.clone() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("gdb ended ({status}).")).color(theme::muted()));
            if widgets::link(ui, "Restart").clicked() {
                console.restart();
            }
        });
    }
    let (typed, resize) = console.terminal.show(ui, running);
    if let Some(child) = console.child.as_mut() {
        if let Some((rows, cols)) = resize {
            child.resize(rows, cols);
        }
        if !typed.is_empty() {
            child.write(&typed);
        }
    }
}

/// The line above the terminal: what runs, and Restart / Stop.
fn header(
    ui: &mut egui::Ui,
    console: &mut Console,
    env: &Env<'_>,
    plan: &Result<Launch, Unavailable>,
    actions: &mut Vec<PanelAction>,
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("gdb").strong().color(theme::heading()));
        ui.label(RichText::new(env.flavour.label()).color(theme::muted()));
        ui.label(
            RichText::new(format!("target remote 127.0.0.1:{}", env.port))
                .monospace()
                .color(theme::muted()),
        )
        .on_hover_text(
            "Opening the console connects gdb to this session. gdb then controls the process \
             and the rest of this tab is read-only until gdb quits.",
        );
        if plan.is_ok() {
            if console.running() {
                if ui
                    .small_button("Stop")
                    .on_hover_text("Quit gdb; the process keeps running")
                    .clicked()
                {
                    console.quit();
                }
            }
            if ui
                .small_button("Restart")
                .on_hover_text("Start gdb again and reconnect it")
                .clicked()
            {
                console.restart();
            }
        }
        if widgets::link(ui, "Settings…")
            .on_hover_text("Choose GEF or pwndbg (Settings, Analysis tools)")
            .clicked()
        {
            actions.push(PanelAction::OpenSettings);
        }
    });
}

/// The pane of a console that cannot start: why, and where to fix it.
fn missing(ui: &mut egui::Ui, reason: Unavailable, actions: &mut Vec<PanelAction>) {
    let (problem, advice) = unavailable_text(reason);
    egui::ScrollArea::vertical()
        .id_salt("debugger-console-missing")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(problem).color(theme::warn()));
                if widgets::link(ui, "Install…")
                    .on_hover_text("Open Library, Analysis tools")
                    .clicked()
                {
                    actions.push(PanelAction::OpenTools);
                }
            });
            ui.add(egui::Label::new(RichText::new(advice).small().color(theme::muted())).wrap());
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(id: &str, system: Option<&str>, installed: bool) -> ToolStatus {
        ToolStatus {
            id: id.into(),
            name: id.into(),
            version: "1".into(),
            system: system.map(str::to_owned),
            installed: installed.then(|| "1".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn gef_is_the_default_flavour_and_round_trips() {
        assert_eq!(GdbFlavour::default(), GdbFlavour::Gef);
        for flavour in GdbFlavour::ALL {
            let text = serde_json::to_string(&flavour).unwrap();
            assert_eq!(serde_json::from_str::<GdbFlavour>(&text).unwrap(), flavour);
        }
        assert_eq!(
            serde_json::to_string(&GdbFlavour::Pwndbg).unwrap(),
            "\"pwndbg\""
        );
    }

    #[test]
    fn gef_runs_the_installed_script_in_the_system_gdb_without_user_init() {
        let data = Path::new("/data");
        let tools = [tool("gef", None, true)];
        let plan = launch(
            GdbFlavour::Gef,
            40123,
            Some(Path::new("/usr/bin/gdb")),
            &tools,
            data,
        )
        .unwrap();
        assert_eq!(plan.program, Path::new("/usr/bin/gdb"));
        assert_eq!(
            plan.args,
            [
                "-nx",
                "-q",
                "-x",
                "/data/tools/gef/gef.py",
                "-ex",
                "target remote 127.0.0.1:40123"
            ]
        );
        assert!(plan.env.contains(&("DEBUGINFOD_URLS", "")));
        assert!(plan.env.contains(&("TERM", "xterm-256color")));
    }

    #[test]
    fn pwndbg_runs_its_portable_launcher_or_the_systems() {
        let data = Path::new("/data");
        let managed = launch(
            GdbFlavour::Pwndbg,
            7,
            None,
            &[tool("pwndbg", None, true)],
            data,
        )
        .unwrap();
        assert_eq!(managed.program, Path::new("/data/tools/pwndbg/bin/pwndbg"));
        assert_eq!(
            managed.args,
            ["-nx", "-q", "-ex", "target remote 127.0.0.1:7"]
        );
        assert!(managed.env_remove.contains(&"LD_LIBRARY_PATH"));
        // No system gdb is needed: the portable build has its own.
        let system = launch(
            GdbFlavour::Pwndbg,
            7,
            None,
            &[tool("pwndbg", Some("/usr/bin/pwndbg"), true)],
            data,
        )
        .unwrap();
        assert_eq!(system.program, Path::new("/usr/bin/pwndbg"));
        // Neither reads an init file of the user's home.
        for plan in [&managed, &system] {
            assert_eq!(
                plan.home.as_deref(),
                Some(Path::new("/data/tools/.console-home"))
            );
        }
    }

    #[test]
    fn a_missing_gdb_or_front_end_is_named() {
        let data = Path::new("/data");
        let gef = [tool("gef", None, true)];
        assert_eq!(
            launch(GdbFlavour::Gef, 1, None, &gef, data).unwrap_err(),
            Unavailable::NoGdb
        );
        let gdb = Some(Path::new("/usr/bin/gdb"));
        assert_eq!(
            launch(GdbFlavour::Gef, 1, gdb, &[tool("gef", None, false)], data).unwrap_err(),
            Unavailable::NoFlavour(GdbFlavour::Gef)
        );
        assert_eq!(
            launch(GdbFlavour::Gef, 1, gdb, &[], data).unwrap_err(),
            Unavailable::NoFlavour(GdbFlavour::Gef)
        );
        assert_eq!(
            launch(
                GdbFlavour::Pwndbg,
                1,
                gdb,
                &[tool("pwndbg", None, false)],
                data
            )
            .unwrap_err(),
            Unavailable::NoFlavour(GdbFlavour::Pwndbg)
        );
        assert!(unavailable_text(Unavailable::NoGdb)
            .0
            .contains("not found in PATH"));
        assert!(unavailable_text(Unavailable::NoGdb).1.contains("pwndbg"));
        assert!(unavailable_text(Unavailable::NoFlavour(GdbFlavour::Pwndbg))
            .0
            .starts_with("pwndbg is not installed"));
    }
}
