// SPDX-License-Identifier: GPL-3.0-only
//! Bounded live tool status, kept separately from immutable evidence listings.
use super::*;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, io::Read};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activity {
    schema: u32,
    report_id: String,
    kind: AnalysisKind,
    tool: String,
    stage_started_ms: u64,
    tool_started_ms: u64,
}
struct Current {
    directory: PathBuf,
    activity: Activity,
}
thread_local! {
    // Only the isolated worker owner thread reports tools. Other tool users
    // (detection, debugger, version discovery) have no active context.
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().min(u128::from(u64::MAX)) as u64)
}
fn write(current: &Current) {
    let result = (|| -> Result<(), String> {
        let encoded = serde_json::to_vec(&current.activity).map_err(|e| e.to_string())?;
        let tmp = current.directory.join(".current.tmp");
        fs::write(&tmp, encoded)
            .and_then(|_| fs::rename(tmp, current.directory.join("current.json")))
            .map_err(|e| e.to_string())
    })();
    if let Err(error) = result {
        eprintln!("analysis progress: {error}");
    }
}
/// Clear worker-local context even when a section exits early.
pub(in crate::analysis) struct Stage;
impl Stage {
    pub(in crate::analysis) fn begin(
        directory: &Path,
        report: &AnalysisReport,
        index: usize,
    ) -> Self {
        let kind = report.sections[index].kind;
        let now = now_ms();
        let tool = match kind {
            AnalysisKind::Rules => "YARA-X",
            AnalysisKind::Capabilities => "Checking capa availability",
            AnalysisKind::Decompilation => "Checking decompiler availability",
            AnalysisKind::Embedded => "Checking binwalk availability",
            AnalysisKind::Floss => "Checking FLOSS availability",
            _ => "Built-in analysis",
        };
        CURRENT.with(|slot| {
            let current = Current {
                directory: directory.to_owned(),
                activity: Activity {
                    schema: 1,
                    report_id: report.id.clone(),
                    kind,
                    tool: tool.into(),
                    stage_started_ms: now,
                    tool_started_ms: now,
                },
            };
            write(&current);
            *slot.borrow_mut() = Some(current);
        });
        Self
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        CURRENT.with(|slot| *slot.borrow_mut() = None);
    }
}
/// Called immediately before a real tool invocation; version queries do not
/// replace the useful active-tool name with their short-lived subprocess.
pub(in crate::analysis) fn tool_started(path: &str, args: &[&str]) {
    if args.iter().any(|a| matches!(*a, "--version" | "-version")) {
        return;
    }
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Tool");
    CURRENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(current) = slot.as_mut() else {
            return;
        };
        current.activity.tool = match name {
            "analyzeHeadless" => "Ghidra",
            "floss" => "FLOSS",
            "diec" | "die" => "Detect It Easy",
            "tar" if current.activity.kind == AnalysisKind::Capabilities => "Preparing capa rules",
            other => other,
        }
        .chars()
        .take(128)
        .collect();
        current.activity.tool_started_ms = now_ms();
        write(current);
    });
}
/// Overlay only bounded, identity-checked activity onto an already validated
/// progress report. Missing or malformed status never invalidates results.
pub(in crate::analysis) fn annotate(directory: &Path, report: &mut AnalysisReport) {
    let activity = (|| -> Option<Activity> {
        let mut encoded = Vec::new();
        crate::archive_io::open_regular(directory, &directory.join("current.json"))
            .ok()?
            .take(4097)
            .read_to_end(&mut encoded)
            .ok()?;
        if encoded.len() > 4096 {
            return None;
        }
        serde_json::from_slice(&encoded).ok()
    })();
    let Some(a) = activity else {
        return;
    };
    let now = now_ms();
    if a.schema != 1
        || a.report_id != report.id
        || a.tool.is_empty()
        || a.tool.len() > 256
        || a.tool.chars().any(char::is_control)
        || a.stage_started_ms == 0
        || a.stage_started_ms > a.tool_started_ms
        || a.tool_started_ms > now
    {
        return;
    }
    if let Some(section) = report
        .sections
        .iter_mut()
        .find(|s| s.kind == a.kind && s.state == AnalysisSectionState::Running)
    {
        section.tools = vec![a.tool.clone()];
        section.summary = format!(
            "{} · tool {}s · check {}s elapsed",
            a.tool,
            (now - a.tool_started_ms) / 1000,
            (now - a.stage_started_ms) / 1000
        );
    }
}

#[cfg(test)]
mod tests;
