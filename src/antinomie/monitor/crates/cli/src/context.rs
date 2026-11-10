// SPDX-License-Identifier: GPL-3.0-only
//! What every command receives: the global flags resolved into engine options,
//! the output format and the logger.
use crate::{
    args::{Global, Mode, expand_tilde},
    logging::Logger,
    output::Format,
};
use antinomie_monitor_core::{BackendOptions, StartSettings};
use std::path::PathBuf;

pub struct Context {
    pub global: Global,
    pub format: Format,
    pub logger: Logger,
    pub options: BackendOptions,
}

impl Context {
    pub fn new(global: Global, stdout_is_terminal: bool, home: Option<PathBuf>) -> Self {
        let format = global
            .format
            .unwrap_or_else(|| Format::default_for(stdout_is_terminal));
        let logger = Logger::from_global(&global);
        let options = backend_options(&global, home.as_deref());
        Self {
            global,
            format,
            logger,
            options,
        }
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.options.data_dir
    }

    pub fn mode(&self) -> Mode {
        self.global.mode()
    }

    /// `--timeout` as a duration: the limit for a waiting command.
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.global.timeout.map(std::time::Duration::from_secs)
    }

    /// The daemon socket, resolved as the daemon does: `--socket`, else
    /// `[daemon] socket` of `<data>/service.toml`, else
    /// `<data>/run/antinomie.sock`.
    pub fn socket(&self) -> PathBuf {
        crate::commands::auto::daemon::client_socket(self.global.socket.as_deref(), self.data_dir())
    }
}

/// The data directory and who owns it, for `doctor` and error details. The
/// lock is probed without waiting; the directory may not exist yet.
pub fn data_dir_value(data_dir: &std::path::Path) -> serde_json::Value {
    use antinomie_monitor_core::data_owner;
    let (owned, owner, problem) = match data_owner::current_owner(data_dir) {
        Ok(Some(owner)) => (true, owner.record, None),
        Ok(None) => (false, None, None),
        Err(error) => (false, None, Some(error)),
    };
    serde_json::json!({
        "path": data_dir,
        "owned": owned,
        "owner": owner,
        "problem": problem,
    })
}

/// The engine options the global flags select. The CLI is headless unless
/// `--no-headless` is given (design 3.1).
pub fn backend_options(global: &Global, home: Option<&std::path::Path>) -> BackendOptions {
    let mut options = BackendOptions::default();
    if let Some(path) = &global.data_dir {
        options.data_dir = expand_tilde(path, home);
    }
    if let Some(path) = &global.bundle {
        options.bundle_dir = expand_tilde(path, home);
    }
    if let Some(path) = &global.qemu {
        options.qemu = path.clone();
    }
    if let Some(path) = &global.qemu_img {
        options.qemu_img = path.clone();
    }
    options.force_tcg = global.tcg;
    options.headless = !global.no_headless;
    options.start = start_settings(global, &options.data_dir);
    options
}

/// The waits of a VM start and a launch: `settings.json`'s `start` section
/// (the one the window's Tools > Settings > Advanced edits), with
/// `--boot-wait` and `--tcg-multiplier` over it. A file that cannot be read
/// gives the defaults here; the commands that read the file report it.
fn start_settings(global: &Global, data_dir: &std::path::Path) -> StartSettings {
    let mut start = antinomie_monitor_core::settings::load(data_dir)
        .ok()
        .flatten()
        .map(|settings| settings.start())
        .unwrap_or_default();
    if let Some(seconds) = global.boot_wait {
        start.boot_wait_secs = seconds;
    }
    if let Some(multiplier) = global.tcg_multiplier {
        start.tcg_multiplier = multiplier;
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Cli;
    use clap::Parser;

    fn global(args: &[&str]) -> Global {
        let mut all = vec!["antinomie-cli"];
        all.extend_from_slice(args);
        all.push("doctor");
        Cli::try_parse_from(all).unwrap().global
    }

    #[test]
    fn flags_select_engine_options_and_the_cli_is_headless_by_default() {
        let home = std::path::Path::new("/home/me");
        let options = backend_options(
            &global(&[
                "--data-dir",
                "~/auto",
                "--tcg",
                "--qemu",
                "/q",
                "--qemu-img",
                "/qi",
            ]),
            Some(home),
        );
        assert_eq!(options.data_dir, std::path::Path::new("/home/me/auto"));
        assert!(options.force_tcg && options.headless);
        assert_eq!(options.qemu, std::path::Path::new("/q"));
        assert_eq!(options.qemu_img, std::path::Path::new("/qi"));
        assert!(!backend_options(&global(&["--no-headless"]), Some(home)).headless);
    }

    #[test]
    fn the_start_waits_come_from_the_settings_file_and_the_flags_win() {
        let dir = std::env::temp_dir().join(format!("ant-cli-start-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.to_str().unwrap();
        // No file: the defaults.
        let options = backend_options(&global(&["--data-dir", data]), None);
        assert_eq!(options.start, StartSettings::default());
        std::fs::write(
            dir.join("settings.json"),
            r#"{"start": {"boot_wait_secs": 90, "tcg_multiplier": 20}}"#,
        )
        .unwrap();
        let options = backend_options(&global(&["--data-dir", data]), None);
        assert_eq!(
            (options.start.boot_wait_secs, options.start.tcg_multiplier),
            (90, 20)
        );
        let options = backend_options(
            &global(&[
                "--data-dir",
                data,
                "--boot-wait",
                "200",
                "--tcg-multiplier",
                "30",
            ]),
            None,
        );
        assert_eq!(
            (options.start.boot_wait_secs, options.start.tcg_multiplier),
            (200, 30)
        );
        // Out of range is refused by the parser.
        for bad in [["--boot-wait", "4"], ["--tcg-multiplier", "0"]] {
            let mut all = vec!["antinomie-cli"];
            all.extend_from_slice(&bad);
            all.push("doctor");
            assert!(Cli::try_parse_from(all).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_socket_defaults_inside_the_data_directory() {
        let context = Context::new(global(&["--data-dir", "/data"]), false, None);
        assert_eq!(
            context.socket(),
            std::path::Path::new("/data/run/antinomie.sock")
        );
        let context = Context::new(
            global(&["--data-dir", "/data", "--socket", "/s"]),
            false,
            None,
        );
        assert_eq!(context.socket(), std::path::Path::new("/s"));
        assert_eq!(context.format, Format::Json);
    }

    #[test]
    fn the_socket_follows_the_flag_then_service_toml_then_the_default() {
        let dir = std::env::temp_dir().join(format!("ant-cli-socket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.to_str().unwrap();
        let default = dir.join("run").join("antinomie.sock");
        let socket = |extra: &[&str]| {
            let mut args = vec!["--data-dir", data];
            args.extend_from_slice(extra);
            Context::new(global(&args), false, None).socket()
        };
        // No service.toml: the default.
        assert_eq!(socket(&[]), default);
        // A file without the key: the default.
        std::fs::write(dir.join("service.toml"), "[queue]\nmax_queued = 5\n").unwrap();
        assert_eq!(socket(&[]), default);
        // The configured socket, as the daemon uses it.
        std::fs::write(
            dir.join("service.toml"),
            "[daemon]\nsocket = \"/run/ant/custom.sock\"\n",
        )
        .unwrap();
        assert_eq!(socket(&[]), std::path::Path::new("/run/ant/custom.sock"));
        // The flag wins over the file.
        assert_eq!(
            socket(&["--socket", "/flag.sock"]),
            std::path::Path::new("/flag.sock")
        );
        // A broken file does not fail a client: the default.
        std::fs::write(dir.join("service.toml"), "[daemon\nsocket =").unwrap();
        assert_eq!(socket(&[]), default);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
