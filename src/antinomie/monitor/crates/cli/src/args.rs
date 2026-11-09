// SPDX-License-Identifier: GPL-3.0-only
//! Command line grammar: `antinomie-cli [GLOBAL] GROUP COMMAND [FLAGS] [ARGS]`
//! (design section 3). The global flags are accepted before or after the
//! command.
use crate::{
    commands::Command,
    output::{ColorWhen, Format},
};
use clap::{Args, Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "antinomie-cli",
    version = antinomie_monitor_core::api::APP_BUILD,
    about = "Antinomie command line: bases, VMs, runs, Triage and reports without a window",
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

/// How a command that needs the engine reaches it (design 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A daemon if one answers, else the lock.
    Auto,
    Direct,
    Daemon,
}

#[derive(Args, Debug, Clone)]
pub struct Global {
    /// Data directory [default: $HOME/antinomie]; `~` is expanded.
    #[arg(long, global = true, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
    /// Boot bundle folder, for engine commands [default: $ANTINOMIE_BUNDLE or images].
    #[arg(long, global = true, value_name = "PATH")]
    pub bundle: Option<PathBuf>,
    /// Daemon socket [default: <data>/run/antinomie.sock].
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Run the command in this process, taking the data-directory lock, even when a daemon could serve it.
    #[arg(long, global = true, conflicts_with = "daemon")]
    pub direct: bool,
    /// Send the command to the running daemon (an `auto` command, a read such as `run list` or `sample list`); fail when none answers.
    #[arg(long, global = true)]
    pub daemon: bool,
    /// Output format [default: human on a terminal, json otherwise].
    #[arg(short = 'o', long, global = true, value_enum, value_name = "FORMAT")]
    pub format: Option<Format>,
    /// Colour in human output; NO_COLOR is honoured.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "auto",
        value_name = "WHEN"
    )]
    pub color: ColorWhen,
    /// Only errors on stderr; results still print.
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Raise the log level on stderr (-v debug, -vv trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Log line format on stderr.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "text",
        value_name = "FORMAT"
    )]
    pub log_format: LogFormat,
    /// Overall limit for the command.
    #[arg(long, global = true, value_name = "SECONDS")]
    pub timeout: Option<u64>,
    /// Force software emulation (TCG).
    #[arg(long, global = true)]
    pub tcg: bool,
    /// QEMU system emulator [default: qemu-system-x86_64].
    #[arg(long, global = true, value_name = "PATH")]
    pub qemu: Option<PathBuf>,
    /// qemu-img [default: qemu-img].
    #[arg(long, global = true, value_name = "PATH")]
    pub qemu_img: Option<PathBuf>,
    /// Let QEMU open its window (the CLI default is headless).
    #[arg(long, global = true)]
    pub no_headless: bool,
}

impl Global {
    pub fn mode(&self) -> Mode {
        if self.direct {
            Mode::Direct
        } else if self.daemon {
            Mode::Daemon
        } else {
            Mode::Auto
        }
    }
}

/// Replace a leading `~` or `~/` with `home`. Other forms (`~user`) are kept.
pub fn expand_tilde(path: &std::path::Path, home: Option<&std::path::Path>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };
    if path == std::path::Path::new("~") {
        return home.to_path_buf();
    }
    match path.strip_prefix("~") {
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// The `--format` value on the raw command line, read before parsing so that
/// even a usage error is reported in the requested format.
pub fn format_hint(args: &[std::ffi::OsString]) -> Option<Format> {
    let mut found = None;
    let mut iter = args.iter().skip(1).filter_map(|a| a.to_str());
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        let value = if arg == "-o" || arg == "--format" {
            iter.next()
        } else {
            arg.strip_prefix("--format=").or_else(|| {
                arg.strip_prefix("-o")
                    .filter(|value| !value.is_empty() && !arg.starts_with("--"))
            })
        };
        if let Some(value) = value {
            found = Format::from_str(value, true).ok().or(found);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn global_flags_parse_before_and_after_the_command() {
        let before = Cli::try_parse_from(["antinomie-cli", "-o", "json", "-vv", "doctor"]).unwrap();
        let after = Cli::try_parse_from(["antinomie-cli", "doctor", "-o", "json", "-vv"]).unwrap();
        for cli in [before, after] {
            assert_eq!(cli.global.format, Some(Format::Json));
            assert_eq!(cli.global.verbose, 2);
        }
    }

    #[test]
    fn every_global_flag_of_the_design_is_accepted() {
        let cli = Cli::try_parse_from([
            "antinomie-cli",
            "--data-dir",
            "/d",
            "--bundle",
            "/b",
            "--socket",
            "/s",
            "--direct",
            "--format",
            "ndjson",
            "--color",
            "never",
            "--quiet",
            "--log-format",
            "json",
            "--timeout",
            "30",
            "--tcg",
            "--qemu",
            "/q",
            "--qemu-img",
            "/qi",
            "--no-headless",
            "capabilities",
        ])
        .unwrap();
        let g = cli.global;
        assert_eq!(g.data_dir, Some("/d".into()));
        assert_eq!(g.mode(), Mode::Direct);
        assert_eq!(g.format, Some(Format::Ndjson));
        assert_eq!(g.color, ColorWhen::Never);
        assert!(g.quiet && g.tcg && g.no_headless);
        assert_eq!(g.log_format, LogFormat::Json);
        assert_eq!(g.timeout, Some(30));
    }

    #[test]
    fn direct_and_daemon_conflict() {
        assert!(Cli::try_parse_from(["antinomie-cli", "--direct", "--daemon", "doctor"]).is_err());
        let cli = Cli::try_parse_from(["antinomie-cli", "--daemon", "doctor"]).unwrap();
        assert_eq!(cli.global.mode(), Mode::Daemon);
    }

    #[test]
    fn unknown_formats_and_commands_are_usage_errors() {
        assert!(Cli::try_parse_from(["antinomie-cli", "-o", "yaml", "doctor"]).is_err());
        assert!(Cli::try_parse_from(["antinomie-cli", "frobnicate"]).is_err());
        assert!(Cli::try_parse_from(["antinomie-cli"]).is_err());
    }

    #[test]
    fn tilde_is_expanded_against_home() {
        let home = Some(Path::new("/home/me"));
        assert_eq!(expand_tilde(Path::new("~"), home), Path::new("/home/me"));
        assert_eq!(
            expand_tilde(Path::new("~/x/y"), home),
            Path::new("/home/me/x/y")
        );
        assert_eq!(
            expand_tilde(Path::new("~other/x"), home),
            Path::new("~other/x")
        );
        assert_eq!(expand_tilde(Path::new("/a/~"), home), Path::new("/a/~"));
        assert_eq!(expand_tilde(Path::new("~/x"), None), Path::new("~/x"));
    }

    #[test]
    fn the_format_is_found_on_a_command_line_that_does_not_parse() {
        assert_eq!(
            format_hint(&os(&["c", "-o", "json", "bogus"])),
            Some(Format::Json)
        );
        assert_eq!(
            format_hint(&os(&["c", "bogus", "--format=ndjson"])),
            Some(Format::Ndjson)
        );
        assert_eq!(
            format_hint(&os(&["c", "-ojson", "bogus"])),
            Some(Format::Json)
        );
        assert_eq!(
            format_hint(&os(&["c", "--format", "human"])),
            Some(Format::Human)
        );
        assert_eq!(format_hint(&os(&["c", "bogus"])), None);
        assert_eq!(format_hint(&os(&["c", "--", "-o", "json"])), None);
    }
}
