// SPDX-License-Identifier: GPL-3.0-only
//! Parse, run, render: everything `main` does except process exit and the
//! worker hooks, so tests can drive it.
use crate::{
    args::{Cli, format_hint},
    commands,
    context::Context,
    error::CliError,
    exit::Exit,
    output::{Format, Rendered, render_failure, render_success},
};
use clap::Parser;
use std::ffi::OsString;

/// The environment a run sees. Tests build it by hand.
pub struct Environment {
    pub stdout_is_terminal: bool,
    pub stderr_is_terminal: bool,
    pub no_color: bool,
    pub home: Option<std::path::PathBuf>,
}

impl Environment {
    pub fn from_process() -> Self {
        use std::io::IsTerminal;
        Self {
            stdout_is_terminal: std::io::stdout().is_terminal(),
            stderr_is_terminal: std::io::stderr().is_terminal(),
            no_color: std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            home: std::env::var_os("HOME").map(Into::into),
        }
    }
}

pub fn execute(args: Vec<OsString>, environment: &Environment) -> (Exit, Rendered) {
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => return parse_failure(&args, error, environment),
    };
    let color = cli
        .global
        .color
        .enabled(environment.stderr_is_terminal, environment.no_color);
    let context = Context::new(
        cli.global.clone(),
        environment.stdout_is_terminal,
        environment.home.clone(),
    );
    match commands::run(&cli.command, &context) {
        Ok(reply) => (Exit::Ok, render_success(context.format, &reply)),
        Err(error) => finish_failure(context.format, error, color),
    }
}

fn finish_failure(format: Format, error: CliError, color: bool) -> (Exit, Rendered) {
    (error.exit, render_failure(format, &error, color))
}

fn parse_failure(
    args: &[OsString],
    error: clap::Error,
    environment: &Environment,
) -> (Exit, Rendered) {
    use clap::error::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        return (
            Exit::Ok,
            Rendered {
                stdout: error.render().to_string(),
                stderr: String::new(),
            },
        );
    }
    let format =
        format_hint(args).unwrap_or_else(|| Format::default_for(environment.stdout_is_terminal));
    if format == Format::Human {
        return (
            Exit::Usage,
            Rendered {
                stdout: String::new(),
                stderr: error.render().to_string(),
            },
        );
    }
    let text = error.render().to_string();
    let message = text
        .lines()
        .next()
        .unwrap_or("invalid arguments")
        .trim_start_matches("error: ")
        .to_owned();
    let usage = CliError::usage(message);
    finish_failure(format, usage, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn env(tty: bool) -> Environment {
        Environment {
            stdout_is_terminal: tty,
            stderr_is_terminal: tty,
            no_color: false,
            home: None,
        }
    }

    fn run(args: &[&str], tty: bool) -> (Exit, Rendered) {
        let mut all = vec!["antinomie-cli"];
        all.extend_from_slice(args);
        execute(all.into_iter().map(OsString::from).collect(), &env(tty))
    }

    #[test]
    fn config_path_in_json_has_the_envelope_and_exit_zero() {
        let (exit, out) = run(&["--data-dir", "/d", "-o", "json", "config", "path"], true);
        assert_eq!(exit, Exit::Ok);
        let value: Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(value["api_version"], 1);
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"]["settings"], "/d/settings.json");
        assert_eq!(value["result"]["policies"], "/d/policies");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn the_format_defaults_by_terminal() {
        let (_, piped) = run(&["--data-dir", "/d", "config", "path"], false);
        assert!(piped.stdout.starts_with("{\"api_version\":1,\"ok\":true"));
        let (_, terminal) = run(&["--data-dir", "/d", "config", "path"], true);
        assert!(terminal.stdout.starts_with("data_dir:"));
    }

    #[test]
    fn ndjson_config_path_is_one_result_line() {
        let (_, out) = run(
            &["--data-dir", "/d", "-o", "ndjson", "config", "path"],
            true,
        );
        assert_eq!(out.stdout.lines().count(), 1);
        assert!(out.stdout.starts_with("{\"result\":{"));
    }

    #[test]
    fn a_usage_error_exits_two_in_the_requested_format() {
        let (exit, out) = run(&["-o", "json", "frobnicate"], true);
        assert_eq!(exit, Exit::Usage);
        assert_eq!(exit.code(), 2);
        let value: Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "invalid_argument");
        let (exit, human) = run(&["frobnicate"], true);
        assert_eq!(exit.code(), 2);
        assert!(human.stdout.is_empty() && human.stderr.contains("frobnicate"));
    }

    #[test]
    fn doctor_with_an_unknown_tool_is_exit_four() {
        let (exit, out) = run(&["-o", "json", "doctor", "--require", "nope"], false);
        assert_eq!(exit.code(), 4);
        let value: Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(value["error"]["field"], "require");
    }

    #[test]
    fn help_and_version_exit_zero_on_stdout() {
        let (exit, help) = run(&["--help"], false);
        assert_eq!(exit, Exit::Ok);
        assert!(help.stdout.contains("--data-dir") && help.stdout.contains("doctor"));
        let (exit, version) = run(&["--version"], false);
        assert_eq!(exit, Exit::Ok);
        assert!(version.stdout.starts_with("antinomie-cli "));
    }
}
