// SPDX-License-Identifier: GPL-3.0-only
//! What every command receives: the global flags resolved into engine options,
//! the output format and the logger.
use crate::{
    args::{Global, Mode, expand_tilde},
    logging::Logger,
    output::Format,
};
use antinomie_monitor_core::BackendOptions;
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

    /// The daemon socket: `--socket` or `<data>/run/antinomie.sock`.
    pub fn socket(&self) -> PathBuf {
        self.global
            .socket
            .clone()
            .unwrap_or_else(|| self.data_dir().join("run").join("antinomie.sock"))
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
    options
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
}
