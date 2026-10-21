// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The Syscall Trace view's rendering of the recorded runs, made by the app's
//! own code: the opt-in test `conformance_trace_render` of the monitor-ui
//! crate renders every call and reports where the view falls back to raw
//! values. This module runs it and reads what it wrote.
use crate::{Context, GroupKind, judge::Key, vm::GroupRun};
use std::{
    collections::{BTreeMap, HashMap},
    io::BufRead,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ArgumentView {
    pub name: String,
    pub text: String,
    pub raw: Option<String>,
    pub data: Option<String>,
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CallView {
    pub key: Key,
    pub nr: u64,
    pub name: String,
    pub tid: u32,
    pub entry_ns: Option<u64>,
    pub cells: Vec<String>,
    pub info: String,
    pub arguments: Vec<ArgumentView>,
    pub result: Option<String>,
    pub fields: Vec<serde_json::Value>,
    pub warnings: Vec<String>,
    pub fallbacks: Vec<String>,
}

/// Views by group, then by call identity. Stress groups keep only calls with
/// warnings or fallbacks, and their totals.
pub type Views = BTreeMap<String, GroupViews>;

#[derive(Default)]
pub struct GroupViews {
    pub calls: HashMap<Key, CallView>,
    pub rendered: u64,
    pub summary: Option<serde_json::Value>,
}

pub fn render(context: &Context, runs: &[(crate::Group, GroupRun)]) -> Result<Views, String> {
    let output = context.out.join("render");
    if output.exists() {
        std::fs::remove_dir_all(&output).map_err(|e| e.to_string())?;
    }
    let list: Vec<String> = runs
        .iter()
        .map(|(group, run)| format!("{}={}", group.name, run.run.directory.display()))
        .collect();
    let summarized: Vec<&str> = runs
        .iter()
        .filter(|(group, _)| group.kind != GroupKind::Oracle)
        .map(|(group, _)| group.name.as_str())
        .collect();
    let workspace = context.repo.join("src/antinomie/monitor");
    eprintln!(
        "conformance: rendering {} runs with the app's trace view",
        runs.len()
    );
    let started = std::time::Instant::now();
    let status =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(&workspace)
            .args([
                "test",
                "--release",
                "--locked",
                "-j",
                "2",
                "-p",
                "antinomie-monitor-ui",
                "--bin",
                "antinomie-monitor",
                "--",
                "--ignored",
                "--exact",
                "trace::conformance::conformance_trace_render",
            ])
            .env("ANTINOMIE_CONFORMANCE_RENDER_RUNS", list.join(";"))
            .env("ANTINOMIE_CONFORMANCE_RENDER_SUMMARY", summarized.join(","))
            .env("ANTINOMIE_CONFORMANCE_RENDER_OUT", &output)
            .status()
            .map_err(|e| format!("cargo: {e}"))?;
    if !status.success() {
        return Err(format!("the trace view rendering test failed: {status}"));
    }
    eprintln!(
        "conformance: rendered in {:.0} s",
        started.elapsed().as_secs_f64()
    );
    let mut views = Views::new();
    for (group, _) in runs {
        let path = output.join(format!("{}.jsonl", group.name));
        let file = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut group_views = GroupViews::default();
        for line in std::io::BufReader::new(file).lines() {
            let line = line.map_err(|e| e.to_string())?;
            let value: serde_json::Value =
                serde_json::from_str(&line).map_err(|e| format!("{}: {e}", path.display()))?;
            if let Some(summary) = value.get("summary") {
                group_views.rendered = summary["rendered"].as_u64().unwrap_or(0);
                group_views.summary = Some(summary.clone());
                continue;
            }
            let view: CallView =
                serde_json::from_value(value).map_err(|e| format!("{}: {e}", path.display()))?;
            group_views.rendered += u64::from(group.kind == GroupKind::Oracle);
            group_views.calls.insert(view.key, view);
        }
        views.insert(group.name.clone(), group_views);
    }
    Ok(views)
}

/// Stress and attribution groups: the rendering test drew the inspector
/// without a panic; its totals must have no fallback the view should never
/// take.
pub fn stress_warnings(runs: &[(crate::Group, GroupRun)], views: &Views) -> Vec<String> {
    let mut problems = Vec::new();
    for (group, _) in runs
        .iter()
        .filter(|(group, _)| group.kind != GroupKind::Oracle)
    {
        let Some(summary) = views
            .get(&group.name)
            .and_then(|views| views.summary.as_ref())
        else {
            problems.push(format!("{}: no rendering summary", group.name));
            continue;
        };
        for kind in ["syscall-name", "generic-name", "uncaptured"] {
            if let Some(count) = summary["totals"][kind].as_u64().filter(|count| *count > 0) {
                problems.push(format!("{}: view fallback {kind} ×{count}", group.name));
            }
        }
    }
    problems
}
