// SPDX-License-Identifier: GPL-3.0-only
//! The checks of a preset's program, dump and static-analysis tables.

use super::*;
use crate::config::preset::User;

pub(super) fn absolute(path: &str) -> bool {
    path.starts_with('/') && !path.contains('\0') && path.len() <= 4096
}

pub(super) fn check_program(p: &preset::Program, sink: &mut Sink<'_>) {
    if !absolute(&p.guest_path) || p.guest_path.ends_with('/') {
        sink.error(
            "program.guest_path",
            "an absolute path of a file (`{name}` is the sample's file name)",
        );
    }
    if !absolute(&p.working_directory) {
        sink.error("program.working_directory", "must be an absolute path");
    }
    if p.arguments.len() > 64
        || p.arguments
            .iter()
            .any(|a| a.len() > 4096 || a.contains('\0'))
    {
        sink.error(
            "program.arguments",
            "at most 64 arguments of 4096 bytes, no NUL",
        );
    }
    if p.environment.len() > 64
        || p.environment
            .iter()
            .any(|e| e.contains('\0') || e.split_once('=').is_none_or(|(k, _)| k.is_empty()))
    {
        sink.error(
            "program.environment",
            "at most 64 entries of the form NAME=value",
        );
    }
    if p.user != User::Custom && (p.uid != 1000 || p.gid != 1000) {
        sink.warn(
            "program.uid",
            "uid and gid apply with user = \"custom\" only",
        );
    }
    if !(MIN_RUN_S..=MAX_RUN_S).contains(&p.run_time_s) {
        sink.error(
            "program.run_time_s",
            format!("{MIN_RUN_S} to {MAX_RUN_S} seconds (the node ceiling)"),
        );
    }
}

pub(super) fn check_dumps(preset: &Preset, sink: &mut Sink<'_>) {
    let d = &preset.dumps;
    if !(MIN_CORE_MIB..=MAX_CORE_MIB).contains(&d.core_budget_mib) {
        sink.error(
            "dumps.core_budget_mib",
            format!("{MIN_CORE_MIB} to {MAX_CORE_MIB} MiB"),
        );
    }
    let deadline_max = antinomie_monitor_core::core_limits::CORE_TIMEOUT_MAX_MS;
    if !(1..=deadline_max).contains(&d.core_deadline_ms) {
        sink.error("dumps.core_deadline_ms", format!("1 to {deadline_max} ms"));
    }
    let most = antinomie_monitor_core::dump_trigger::DumpTrigger::MAX_DUMPS;
    if !(1..=most).contains(&d.max_dumps) {
        sink.error("dumps.max_dumps", format!("1 to {most}"));
    }
    if d.dumps_apart_s > 3600 {
        sink.error("dumps.dumps_apart_s", "0 to 3600 seconds");
    }
    if d.dump_when_suspicious && !d.trigger_memory_dump && !d.trigger_core {
        sink.error(
            "dumps.dump_when_suspicious",
            "takes nothing: turn on trigger_memory_dump or trigger_core",
        );
    }
    if d.read_non_resident_pages && !d.trigger().is_some_and(|t| t.core) {
        sink.warn(
            "dumps.read_non_resident_pages",
            "has no effect without a trigger core (an exit core reads resident pages only)",
        );
    }
}

pub(super) fn check_static(preset: &Preset, sink: &mut Sink<'_>) {
    let s = &preset.static_analysis;
    for check in &s.triage_checks {
        if !preset::TRIAGE_CHECKS.contains(check) {
            sink.error(
                "static_analysis.triage_checks",
                format!("{check:?} is a deep check: list it in deep_checks").to_lowercase(),
            );
        }
    }
    for check in &s.deep_checks {
        if !preset::DEEP_CHECKS.contains(check) {
            sink.error(
                "static_analysis.deep_checks",
                "takes disassembly, decompilation and floss only",
            );
        }
    }
    if s.time_limit_per_tool_min > MAX_STATIC_MINUTES {
        sink.error(
            "static_analysis.time_limit_per_tool_min",
            format!("0 to {MAX_STATIC_MINUTES}"),
        );
    }
    let fields = antinomie_monitor_core::analysis::LIMIT_FIELDS;
    for (key, setting, value) in s.limits.entries() {
        if let Some(field) = fields.iter().find(|f| f.setting == setting)
            && !(field.min..=field.max).contains(&value)
        {
            sink.error(
                &format!("static_analysis.limits.{key}"),
                format!(
                    "{} to {} {} (the node ceiling)",
                    field.min, field.max, field.unit
                ),
            );
        }
    }
}
