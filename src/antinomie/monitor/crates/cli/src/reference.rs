// SPDX-License-Identifier: GPL-3.0-only
//! The command reference (`docs/cli-reference.md`), generated from the clap
//! definitions of [`Cli`] so it cannot drift. Test code only: the file is
//! written by `UPDATE_CLI_REFERENCE=1 cargo test -p antinomie-cli`, and the
//! test `the_checked_in_cli_reference_is_current` fails when it is stale.
use crate::args::Cli;
use clap::{Arg, Command, CommandFactory};
use std::fmt::Write;

const REFERENCE_FILE: &str = "docs/cli-reference.md";

/// Escape text for Markdown prose: `<` starts HTML, `|` and `*` format.
/// Text between backticks is kept as it is.
fn prose(text: &str) -> String {
    let mut out = String::new();
    for (i, part) in text.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        if i % 2 == 1 {
            out.push_str(part);
        } else {
            for c in part.chars() {
                match c {
                    '<' | '>' | '*' | '|' | '[' | ']' => {
                        out.push('\\');
                        out.push(c);
                    }
                    _ => out.push(c),
                }
            }
        }
    }
    out
}

/// A help text as paragraphs, one line each.
fn paragraphs(text: &str) -> String {
    text.split("\n\n")
        .map(|p| prose(&p.split_whitespace().collect::<Vec<_>>().join(" ")))
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn about(command: &Command) -> String {
    let text = command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default();
    paragraphs(&text)
}

fn flag_names(arg: &Arg) -> String {
    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("--{long}"));
    }
    let mut text = names.join(", ");
    if arg.get_action().takes_values() {
        let value = arg
            .get_value_names()
            .map(|v| {
                v.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
        let _ = write!(text, " <{value}>");
    }
    format!("`{text}`")
}

fn positional_name(arg: &Arg) -> String {
    let name = arg
        .get_value_names()
        .map(|v| {
            v.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
    let many = arg.get_num_args().is_some_and(|r| r.max_values() > 1);
    format!("`<{name}>{}`", if many { "..." } else { "" })
}

/// One argument as a list item with its facts.
fn argument(arg: &Arg) -> String {
    let head = if arg.is_positional() {
        positional_name(arg)
    } else {
        flag_names(arg)
    };
    let mut line = format!("- {head}");
    if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
        let text = paragraphs(&help.to_string());
        if !text.is_empty() {
            let _ = write!(line, ": {}", text.replace("\n\n", "\n\n  "));
        }
    }
    let mut facts = Vec::new();
    if arg.is_required_set() {
        facts.push("required".to_owned());
    }
    let values: Vec<_> = arg
        .get_possible_values()
        .into_iter()
        .filter(|v| !v.is_hide_set())
        .collect();
    if !values.is_empty() {
        let names: Vec<_> = values
            .iter()
            .map(|v| format!("`{}`", v.get_name()))
            .collect();
        facts.push(format!("values: {}", names.join(", ")));
    }
    let defaults: Vec<_> = if arg.get_action().takes_values() {
        arg.get_default_values()
            .iter()
            .map(|v| format!("`{}`", v.to_string_lossy()))
            .collect()
    } else {
        Vec::new()
    };
    if !defaults.is_empty() {
        facts.push(format!("default: {}", defaults.join(", ")));
    }
    if !facts.is_empty() {
        let _ = write!(line, " ({})", facts.join("; "));
    }
    for value in values.iter().filter(|v| v.get_help().is_some()) {
        let help = value
            .get_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        let _ = write!(line, "\n  - `{}`: {}", value.get_name(), paragraphs(&help));
    }
    line
}

fn is_listed(arg: &Arg) -> bool {
    !matches!(arg.get_id().as_str(), "help" | "version") && !arg.is_hide_set()
}

fn section(out: &mut String, command: &Command, path: &str, depth: usize) {
    let hashes = "#".repeat(depth.min(5));
    let _ = writeln!(out, "{hashes} {path}\n");
    let text = about(command);
    if !text.is_empty() {
        let _ = writeln!(out, "{text}\n");
    }
    let mut usage = command.clone();
    let usage = usage.render_usage().to_string();
    let _ = writeln!(out, "```text\n{}\n```\n", usage.trim_end());
    let subs: Vec<_> = command
        .get_subcommands()
        .filter(|s| s.get_name() != "help" && !s.is_hide_set())
        .collect();
    let own: Vec<_> = command
        .get_arguments()
        .filter(|a| is_listed(a) && !a.is_global_set())
        .collect();
    let positionals: Vec<_> = own.iter().filter(|a| a.is_positional()).collect();
    let options: Vec<_> = own.iter().filter(|a| !a.is_positional()).collect();
    if !positionals.is_empty() {
        let _ = writeln!(out, "Arguments:\n");
        for arg in positionals {
            let _ = writeln!(out, "{}", argument(arg));
        }
        out.push('\n');
    }
    if !options.is_empty() {
        let _ = writeln!(out, "Options:\n");
        for arg in options {
            let _ = writeln!(out, "{}", argument(arg));
        }
        out.push('\n');
    }
    if !subs.is_empty() {
        let _ = writeln!(out, "Commands:\n");
        for sub in &subs {
            let summary = sub
                .get_about()
                .map(|a| paragraphs(&a.to_string()))
                .unwrap_or_default();
            let summary = summary.split("\n\n").next().unwrap_or("").to_owned();
            let _ = writeln!(out, "- `{} {}`: {summary}", path, sub.get_name());
        }
        out.push('\n');
    }
    for sub in subs {
        section(out, sub, &format!("{path} {}", sub.get_name()), depth + 1);
    }
}

pub fn render() -> String {
    let mut root = Cli::command();
    root.build();
    let mut out = String::new();
    out.push_str(
        "<!-- SPDX-License-Identifier: GPL-3.0-only -->\n\
         <!-- Generated from the command definitions of antinomie-cli. Do not edit: run\n\
         UPDATE_CLI_REFERENCE=1 cargo test --release -p antinomie-cli the_checked_in_cli_reference_is_current -->\n\n\
         # Command reference\n\n\
         Every command of `antinomie-cli`, with its arguments and options. The file is generated from the\n\
         program's own command definitions, so it matches the build it comes from; a test fails when it\n\
         is stale. For a guide by task, read the [command-line guide](cli.md).\n\n",
    );
    let _ = writeln!(
        out,
        "Written for `antinomie-cli {}`.\n",
        env!("CARGO_PKG_VERSION")
    );
    out.push_str("## Global options\n\n");
    out.push_str("Global options go before or after the command. They apply to every command.\n\n");
    for arg in root.get_arguments().filter(|a| is_listed(a)) {
        let _ = writeln!(out, "{}", argument(arg));
    }
    out.push('\n');
    out.push_str("## Commands\n\n");
    let groups: Vec<_> = root
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();
    for group in &groups {
        let summary = group
            .get_about()
            .map(|a| paragraphs(&a.to_string()))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "- `{}`: {}",
            group.get_name(),
            summary.replace("\n\n", " ")
        );
    }
    out.push('\n');
    for group in groups {
        section(
            &mut out,
            group,
            &format!("antinomie-cli {}", group.get_name()),
            3,
        );
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../..")
            .join(REFERENCE_FILE)
    }

    #[test]
    fn the_checked_in_cli_reference_is_current() {
        let current = render();
        if std::env::var_os("UPDATE_CLI_REFERENCE").is_some() {
            std::fs::write(file(), &current).unwrap();
        }
        let stored = std::fs::read_to_string(file()).unwrap_or_else(|e| {
            panic!("{}: {e}; run with UPDATE_CLI_REFERENCE=1", file().display())
        });
        assert!(
            stored == current,
            "docs/cli-reference.md is stale; regenerate it with UPDATE_CLI_REFERENCE=1"
        );
    }

    #[test]
    fn the_reference_covers_every_group_and_the_global_options() {
        let text = render();
        for name in ["doctor", "auto submit", "recording export", "vm create"] {
            assert!(text.contains(&format!("antinomie-cli {name}")), "{name}");
        }
        assert!(text.contains("`--data-dir <PATH>`"));
    }
}
