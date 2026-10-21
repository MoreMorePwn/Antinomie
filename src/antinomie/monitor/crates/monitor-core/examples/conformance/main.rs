// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Guest conformance suite (tests/monitor/conformance/README.md).
//!
//! ```text
//! conformance trace BASE_DIR OUT_DIR [--bless] [--groups G,G] [--recheck] [--no-render] [--no-build]
//! conformance dump RUN_DIR
//! ```
//!
//! `trace` builds the fixtures, boots a new disposable VM from the base for
//! each fixture group, runs the group's program, keeps its recording and
//! checks it: every call the fixture describes against its record, every
//! other call for warnings and errors, the loss counters against the packets
//! saved, the Syscall Trace view's rendering (through the app's own code) and
//! the golden files. It prints a pass/fail matrix and writes JSON reports to
//! OUT_DIR. `--bless` rewrites the golden files; `--recheck` checks the runs
//! already in OUT_DIR without booting anything; `--groups` limits the groups;
//! `--no-build` uses the fixtures already in OUT_DIR/bin.
//! `dump` prints every call of a recording as one JSON line.
//!
//! A part is one subject of the suite (the syscall trace log now; file
//! lifecycle, process tree, network and Suspicious activity later): it names
//! its fixture groups and checks their runs. Add one in `parts()`.
mod attribution;
mod golden;
mod judge;
mod matrix;
mod oracle;
mod recording;
mod render;
mod stress;
mod trace;
mod vm;

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

/// One fixture group: a program run in its own VM.
#[derive(Clone, Debug)]
pub struct Group {
    pub name: String,
    pub plan: vm::VmPlan,
    pub kind: GroupKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// A fixture that prints ANT_EXPECT lines for every call.
    Oracle,
    /// A load generator: every record must be well formed and every loss
    /// accounted for.
    Stress,
    /// A program whose run status is the subject: who wrote its io_uring
    /// entries, as the run says it.
    Attribution,
}

/// Paths every part shares.
pub struct Context {
    pub repo: PathBuf,
    pub base: PathBuf,
    pub out: PathBuf,
    pub bless: bool,
    pub render: bool,
}

impl Context {
    pub fn bin(&self) -> PathBuf {
        self.out.join("bin")
    }
    pub fn group_dir(&self, group: &str) -> PathBuf {
        self.out.join("groups").join(group)
    }
}

/// A part's checked result: a line per row of its matrix and whether all of
/// it passed.
pub struct Outcome {
    pub passed: bool,
    pub summary: Vec<String>,
}

pub trait Part {
    fn name(&self) -> &'static str;
    fn groups(&self, context: &Context) -> Vec<Group>;
    fn check(&self, context: &Context, runs: &[(Group, vm::GroupRun)]) -> Result<Outcome, String>;
}

fn parts() -> Vec<Box<dyn Part>> {
    vec![Box::new(trace::TracePart)]
}

fn repo_root() -> PathBuf {
    // crates/monitor-core → crates → monitor → antinomie → src → repository
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(5)
        .expect("repository root")
        .to_path_buf()
}

fn build_fixtures(context: &Context) -> Result<(), String> {
    let script = context
        .repo
        .join("tests/monitor/conformance/build-fixtures.sh");
    let status = std::process::Command::new("bash")
        .arg(&script)
        .arg(context.bin())
        .status()
        .map_err(|e| format!("{}: {e}", script.display()))?;
    if !status.success() {
        return Err(format!("fixture build failed: {status}"));
    }
    Ok(())
}

/// The saved summary of a group run, so `--recheck` needs no VM.
fn save_run(dir: &Path, run: &vm::GroupRun) -> Result<(), String> {
    let value = serde_json::json!({
        "run": run.run,
        "recorder_stats": run.recorder_stats,
        "health": run.health,
        "errors": run.errors,
        "boot_seconds": run.boot_seconds,
        "run_seconds": run.run_seconds,
        "stop_seconds": run.stop_seconds,
    });
    std::fs::write(
        dir.join("group-run.json"),
        serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn load_run(dir: &Path) -> Result<vm::GroupRun, String> {
    let text =
        std::fs::read(dir.join("group-run.json")).map_err(|e| format!("{}: {e}", dir.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
    Ok(vm::GroupRun {
        run: serde_json::from_value(value["run"].clone()).map_err(|e| e.to_string())?,
        recorder_stats: serde_json::from_value(value["recorder_stats"].clone()).ok(),
        health: serde_json::from_value(value["health"].clone()).map_err(|e| e.to_string())?,
        errors: serde_json::from_value(value["errors"].clone()).unwrap_or_default(),
        boot_seconds: value["boot_seconds"].as_f64().unwrap_or(0.0),
        run_seconds: value["run_seconds"].as_f64().unwrap_or(0.0),
        stop_seconds: value["stop_seconds"].as_f64().unwrap_or(0.0),
    })
}

fn run_part(
    part: &dyn Part,
    context: &Context,
    only: Option<&[String]>,
    recheck: bool,
) -> Result<Outcome, String> {
    let groups: Vec<Group> = part
        .groups(context)
        .into_iter()
        .filter(|group| only.is_none_or(|only| only.contains(&group.name)))
        .collect();
    let mut runs = Vec::new();
    let mut failures = Vec::new();
    for group in groups {
        let dir = context.group_dir(&group.name);
        let started = std::time::Instant::now();
        let run = if recheck {
            load_run(&dir)
        } else {
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            eprintln!(
                "conformance: {} {}: booting a new VM",
                part.name(),
                group.name
            );
            let result = vm::run_group(&context.base, &dir.join("data"), &group.plan);
            vm::discard_vm_files(&dir.join("data"));
            if let Ok(run) = &result {
                save_run(&dir, run)?;
            }
            result
        };
        match run {
            Ok(run) => {
                eprintln!(
                    "conformance: {} {}: ran in {:.0} s (boot {:.0} s, stop {:.1} s)",
                    part.name(),
                    group.name,
                    started.elapsed().as_secs_f64(),
                    run.boot_seconds,
                    run.stop_seconds
                );
                runs.push((group, run));
            }
            Err(error) => failures.push(format!("{}: {error}", group.name)),
        }
    }
    let mut outcome = part.check(context, &runs)?;
    if !failures.is_empty() {
        outcome.passed = false;
        outcome.summary.extend(
            failures
                .into_iter()
                .map(|failure| format!("FAIL group {failure}")),
        );
    }
    Ok(outcome)
}

fn dump(run: &Path) -> Result<(), String> {
    let (calls, issues) = recording::invocations(run)?;
    for issue in issues {
        println!("{}", serde_json::json!({ "page_issue": issue }));
    }
    for call in calls {
        println!(
            "{}",
            serde_json::to_string(&call).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: conformance trace BASE_DIR OUT_DIR [--bless] [--groups G,G] [--recheck] [--no-render] [--no-build]\n       conformance dump RUN_DIR"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("dump") if args.len() == 2 => match dump(Path::new(&args[1])) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conformance: {error}");
                ExitCode::FAILURE
            }
        },
        Some(name) if args.len() >= 3 && parts().iter().any(|part| part.name() == name) => {
            let mut bless = false;
            let mut recheck = false;
            let mut render = true;
            let mut build = true;
            let mut only = None;
            let mut rest = args[3..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--bless" => bless = true,
                    "--recheck" => recheck = true,
                    "--no-render" => render = false,
                    "--no-build" => build = false,
                    "--groups" => match rest.next() {
                        Some(list) => {
                            only = Some(list.split(',').map(str::to_owned).collect::<Vec<_>>())
                        }
                        None => return usage(),
                    },
                    _ => return usage(),
                }
            }
            // Absolute: the rendering step runs cargo in the workspace.
            let (base, out) = match (std::path::absolute(&args[1]), std::path::absolute(&args[2])) {
                (Ok(base), Ok(out)) => (base, out),
                (Err(error), _) | (_, Err(error)) => {
                    eprintln!("conformance: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let context = Context {
                repo: repo_root(),
                base,
                out,
                bless,
                render,
            };
            if let Err(error) = std::fs::create_dir_all(&context.out) {
                eprintln!("conformance: {}: {error}", context.out.display());
                return ExitCode::FAILURE;
            }
            // The app's own settings, data and caches stay private to this
            // run: the backend reads XDG locations besides its data folder.
            for (name, dir) in [
                ("XDG_DATA_HOME", "data"),
                ("XDG_CONFIG_HOME", "config"),
                ("XDG_CACHE_HOME", "cache"),
                ("XDG_STATE_HOME", "state"),
            ] {
                let path = context.out.join("xdg").join(dir);
                if let Err(error) = std::fs::create_dir_all(&path) {
                    eprintln!("conformance: {}: {error}", path.display());
                    return ExitCode::FAILURE;
                }
                // SAFETY: still single-threaded: no backend, worker or
                // subprocess exists yet, so nothing else reads or writes the
                // environment.
                unsafe { std::env::set_var(name, path) };
            }
            let started = std::time::Instant::now();
            if !recheck
                && build
                && let Err(error) = build_fixtures(&context)
            {
                eprintln!("conformance: {error}");
                return ExitCode::FAILURE;
            }
            let parts = parts();
            let part = parts
                .iter()
                .find(|part| part.name() == name)
                .expect("part checked above");
            match run_part(part.as_ref(), &context, only.as_deref(), recheck) {
                Ok(outcome) => {
                    for line in &outcome.summary {
                        println!("{line}");
                    }
                    println!(
                        "{} {name} in {:.0} s",
                        if outcome.passed { "PASS" } else { "FAIL" },
                        started.elapsed().as_secs_f64()
                    );
                    if outcome.passed {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    eprintln!("conformance: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}
