// SPDX-License-Identifier: GPL-3.0-only
//! `doctor`: the tool checks of `dependencies::check`, exit 20 when a required
//! one is missing.
use crate::{
    context::{Context, data_dir_value},
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use antinomie_monitor_core::dependencies::{self, Check, Dependency};
use clap::Args;
use serde_json::{Value, json};

#[derive(Args, Debug)]
pub struct Doctor {
    /// Tools that must be present, comma separated (see the `tool` column);
    /// default: every check the app treats as required.
    #[arg(long, value_delimiter = ',', value_name = "TOOL")]
    pub require: Vec<String>,
}

/// The name a person types after `--require`.
pub fn slug(dependency: Dependency) -> &'static str {
    match dependency {
        Dependency::Qemu => "qemu",
        Dependency::QemuImg => "qemu-img",
        Dependency::Gtk => "gtk",
        Dependency::Kvm => "kvm",
        Dependency::Curl => "curl",
        Dependency::DebianAccount => "debian-account",
        Dependency::Bubblewrap => "bubblewrap",
        Dependency::Tshark => "tshark",
        Dependency::Prlimit => "prlimit",
        Dependency::Suricata => "suricata",
        Dependency::PythonVenv => "python-venv",
        Dependency::Wireshark => "wireshark",
        Dependency::Binwalk => "binwalk",
        Dependency::FileChooser => "file-chooser",
    }
}

const ALL: [Dependency; 14] = [
    Dependency::Qemu,
    Dependency::QemuImg,
    Dependency::Gtk,
    Dependency::Kvm,
    Dependency::Curl,
    Dependency::DebianAccount,
    Dependency::Bubblewrap,
    Dependency::Tshark,
    Dependency::Prlimit,
    Dependency::Suricata,
    Dependency::PythonVenv,
    Dependency::Wireshark,
    Dependency::Binwalk,
    Dependency::FileChooser,
];

fn parse_required(names: &[String]) -> Result<Vec<Dependency>, CliError> {
    names
        .iter()
        .map(|name| {
            ALL.iter()
                .copied()
                .find(|dependency| slug(*dependency) == name.trim().to_ascii_lowercase())
                .ok_or_else(|| {
                    let known: Vec<&str> = ALL.iter().map(|d| slug(*d)).collect();
                    CliError::invalid(format!(
                        "unknown tool {name:?}; known tools: {}",
                        known.join(", ")
                    ))
                    .with_field("require")
                })
        })
        .collect()
}

fn check_value(check: &Check, required: bool) -> Value {
    json!({
        "tool": slug(check.dependency),
        "name": check.name,
        "ok": check.problem.is_none(),
        "required": required,
        "warning": check.is_warning(),
        "problem": check.problem,
        "hint": check.hint,
    })
}

/// The checks as rows, and the tools that are required and not ready.
pub fn evaluate(
    report: &dependencies::Report,
    explicit: &[Dependency],
) -> (Vec<Value>, Vec<&'static str>) {
    let mut missing = Vec::new();
    let values = report
        .checks
        .iter()
        .map(|check| {
            let required = if explicit.is_empty() {
                !check.optional && !check.is_warning()
            } else {
                explicit.contains(&check.dependency)
            };
            if required && check.problem.is_some() {
                missing.push(slug(check.dependency));
            }
            check_value(check, required)
        })
        .collect();
    (values, missing)
}

fn human(values: &[Value]) -> String {
    let rows: Vec<Vec<String>> = values
        .iter()
        .map(|v| {
            let text = |key: &str| v[key].as_str().unwrap_or("").to_owned();
            let status = match (v["ok"].as_bool(), v["warning"].as_bool()) {
                (Some(true), _) => "ready".to_owned(),
                (_, Some(true)) => format!("warning: {}", text("problem")),
                _ => format!("MISSING: {}. {}", text("problem"), text("hint")),
            };
            vec![text("tool"), status]
        })
        .collect();
    table(&["tool", "status"], &rows)
}

pub fn run(arguments: &Doctor, context: &Context) -> Result<Reply, CliError> {
    let explicit = parse_required(&arguments.require)?;
    context.logger.debug("probing runtime dependencies");
    let report = dependencies::check(&context.options);
    let (values, missing) = evaluate(&report, &explicit);
    let data_dir = data_dir_value(context.data_dir());
    let mut text = human(&values);
    if let Some(owner) = data_dir["owner"]
        .as_object()
        .filter(|_| data_dir["owned"] == true)
    {
        text.push_str(&format!(
            "\ndata directory {} is owned by pid {} ({})\n",
            context.data_dir().display(),
            owner["pid"],
            owner["kind"].as_str().unwrap_or("?")
        ));
    } else if data_dir["owned"] == true {
        text.push_str(&format!(
            "\ndata directory {} is owned by a process without an owner record\n",
            context.data_dir().display()
        ));
    }
    if missing.is_empty() {
        return Ok(
            Reply::value(json!({"ready": true, "checks": values, "data_dir": data_dir}))
                .with_human(text),
        );
    }
    Err(CliError::new(
        ErrorCode::DependencyMissing,
        format!("missing: {}", missing.join(", ")),
    )
    .with_details(json!({"missing": missing, "checks": values, "data_dir": data_dir}))
    .with_human_output(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(dependency: Dependency, problem: Option<&str>, optional: bool) -> Check {
        Check {
            dependency,
            name: "n",
            purpose: "p",
            problem: problem.map(str::to_owned),
            hint: "h",
            optional,
            wrong_version: false,
        }
    }

    fn report(checks: Vec<Check>) -> dependencies::Report {
        dependencies::Report {
            checks,
            ..Default::default()
        }
    }

    #[test]
    fn slugs_are_unique_and_parse_back() {
        let mut slugs: Vec<&str> = ALL.iter().map(|d| slug(*d)).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), ALL.len());
        assert_eq!(
            parse_required(&["QEMU".into(), "qemu-img".into()]).unwrap(),
            vec![Dependency::Qemu, Dependency::QemuImg]
        );
        let error = parse_required(&["nope".into()]).unwrap_err();
        assert_eq!(error.exit.code(), 4);
    }

    #[test]
    fn default_requirement_is_every_non_optional_non_warning_check() {
        let report = report(vec![
            check(Dependency::Qemu, Some("not found"), false),
            check(Dependency::Kvm, Some("no access"), false),
            check(Dependency::Suricata, Some("absent"), true),
        ]);
        let (values, missing) = evaluate(&report, &[]);
        assert_eq!(missing, vec!["qemu"]);
        assert_eq!(values[1]["warning"], json!(true));
        assert_eq!(values[1]["required"], json!(false));
    }

    #[test]
    fn explicit_requirement_replaces_the_default() {
        let report = report(vec![
            check(Dependency::Qemu, Some("not found"), false),
            check(Dependency::Suricata, Some("absent"), true),
        ]);
        let (_, missing) = evaluate(&report, &[Dependency::Suricata]);
        assert_eq!(missing, vec!["suricata"]);
        let (_, none) = evaluate(&report, &[Dependency::Curl]);
        assert!(none.is_empty());
    }

    #[test]
    fn a_missing_requirement_is_exit_20_and_lists_the_checks() {
        let report = report(vec![check(Dependency::Qemu, Some("not found"), false)]);
        let (values, missing) = evaluate(&report, &[]);
        let error = CliError::new(ErrorCode::DependencyMissing, "x")
            .with_details(json!({"missing": missing, "checks": values}));
        assert_eq!(error.exit.code(), 20);
        assert_eq!(error.details["checks"].as_array().unwrap().len(), 1);
    }
}
