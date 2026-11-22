// SPDX-License-Identifier: GPL-3.0-only
//! The preset keys 0.9.0 reserves, a run's option checks and the node ceilings.

use super::{MAX_RUN_S, MAX_SAMPLE_MIB, Problem, Sink, check_preset};
use crate::api::spec::RunIn;
use crate::config::{
    locate::Locator,
    preset::{Preset, ProgramSource, RecordScope, ReportSections},
};

/// A preset key 0.9.0 accepts only at its default, and why.
pub type Reserved = (&'static str, String);

fn arrives(default: &str) -> String {
    format!("arrives in a later version; this version accepts only {default}")
}

/// The keys of `preset` that 0.9.0 cannot act on yet and that are not at
/// their default (the specification's "Preset keys 0.9.0 reserves"). A live
/// route and `vm.keep_on_failure` are node refusals, not listed here.
pub fn reserved(preset: &Preset) -> Vec<Reserved> {
    let mut out = Vec::new();
    let p = &preset.program;
    let mut check = |held: bool, key: &'static str, default: &str| {
        if !held {
            out.push((key, arrives(default)));
        }
    };
    check(
        p.source == ProgramSource::Upload,
        "program.source",
        "upload",
    );
    check(p.executable.is_empty(), "program.executable", "\"\"");
    check(p.preload.is_empty(), "program.preload", "[]");
    check(p.extra_files.is_empty(), "program.extra_files", "[]");
    check(
        p.run_in == RunIn::AppTerminal,
        "program.run_in",
        "app_terminal",
    );
    check(
        preset.record.scope == RecordScope::Program,
        "record.scope",
        "program",
    );
    check(
        !preset.network.private_addresses,
        "network.private_addresses",
        "false",
    );
    check(preset.network.abuse_filter, "network.abuse_filter", "true");
    check(!preset.dumps.disk_dump, "dumps.disk_dump", "false");
    let s = &preset.static_analysis;
    check(
        s.rebuilt_file_mib == 16,
        "static_analysis.rebuilt_file_mib",
        "16",
    );
    check(
        s.rebuilt_run_mib == 256,
        "static_analysis.rebuilt_run_mib",
        "256",
    );
    let t = &preset.triage;
    check(
        t.written_per_file_mib == 64,
        "triage.written_per_file_mib",
        "64",
    );
    check(
        t.written_per_run_mib == 1024,
        "triage.written_per_run_mib",
        "1024",
    );
    check(
        t.earlier_per_file_mib == 64,
        "triage.earlier_per_file_mib",
        "64",
    );
    check(
        t.earlier_per_run_mib == 1024,
        "triage.earlier_per_run_mib",
        "1024",
    );
    check(
        preset.detection.scan_every_min == 0,
        "detection.scan_every_min",
        "0 (off)",
    );
    check(
        preset.report.sections == ReportSections::default(),
        "report.sections",
        "\"all\"",
    );
    out
}

/// The checks of a run's options after its overrides (the file checks
/// without the reserved keys and the node): every problem with its key.
pub fn check_options(preset: &Preset) -> Vec<Problem> {
    let locator = Locator::new("");
    let mut sink = Sink {
        file: "overrides",
        locator: &locator,
        problems: Vec::new(),
    };
    check_preset(preset, &mut sink);
    sink.problems
}

/// A value of a preset above a node ceiling: the key, the value and the
/// ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AboveCeiling {
    pub key: String,
    pub value: u64,
    pub ceiling: u64,
}

/// The values of `preset` above a node ceiling: the run time, the largest
/// sample and the static size limits. A preset file with one is an error of
/// [`check_options`]; a Custom run with one is refused `limit_exceeded`
/// with `source: "node"` (access specification, step 7).
pub fn above_node_ceilings(preset: &Preset) -> Vec<AboveCeiling> {
    let mut out = Vec::new();
    let mut add = |key: String, value: u32, ceiling: u32| {
        if value > ceiling {
            out.push(AboveCeiling {
                key,
                value: u64::from(value),
                ceiling: u64::from(ceiling),
            });
        }
    };
    add(
        "program.run_time_s".into(),
        preset.program.run_time_s,
        MAX_RUN_S,
    );
    add(
        "accepts.max_sample_mib".into(),
        preset.accepts.max_sample_mib,
        MAX_SAMPLE_MIB,
    );
    let fields = antinomie_monitor_core::analysis::LIMIT_FIELDS;
    for (key, setting, value) in preset.static_analysis.limits.entries() {
        if let Some(field) = fields.iter().find(|f| f.setting == setting) {
            add(format!("static_analysis.limits.{key}"), value, field.max);
        }
    }
    out
}
