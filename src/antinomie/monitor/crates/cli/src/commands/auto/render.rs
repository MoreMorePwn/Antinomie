// SPDX-License-Identifier: GPL-3.0-only
//! The exit code of a waited run (design 3.3, audit G27) and the human text of
//! runs and the queue. Text that came from a sample or the guest (names,
//! warnings, the basis sentence) is shown with control characters and escape
//! sequences removed (abuse case A13); `json` and `ndjson` carry it as data.
use crate::exit::Exit;
use antinomie_service::api::{
    assessment::Label,
    run::{Run, RunState},
};
use serde_json::Value;
use std::fmt::Write as _;

/// The exit code of a run a command waited for. The run's state comes first:
/// `failed` 10, `partial` 11, `cancelled` 12, `rejected` 13, still running
/// (the wait ran out) 14. Only a `succeeded` run looks at its label, and only
/// with `--verdict-exit`: `suspicious` 30, `malicious` 31, `inconclusive` 32,
/// `clean_observed` or none 0.
pub fn job_exit(job: &Run, verdict_exit: bool) -> Exit {
    match job.state {
        RunState::Succeeded if verdict_exit => {
            match job.assessment.as_ref().and_then(|a| a.label) {
                Some(Label::Suspicious) => Exit::Suspicious,
                Some(Label::Malicious) => Exit::Malicious,
                Some(Label::Inconclusive) => Exit::Inconclusive,
                Some(Label::CleanObserved) | None => Exit::Ok,
            }
        }
        RunState::Succeeded => Exit::Ok,
        RunState::Partial => Exit::RunPartial,
        RunState::Failed => Exit::RunFailed,
        RunState::Cancelled => Exit::RunCancelled,
        RunState::Rejected => Exit::RunRejected,
        RunState::Queued | RunState::Running | RunState::Cancelling => Exit::WaitTimeout,
    }
}

/// The worst of several waited runs (`auto wait A B`): the highest code.
pub fn worst(exits: &[Exit]) -> Exit {
    exits
        .iter()
        .copied()
        .max_by_key(|exit| exit.code())
        .unwrap_or(Exit::Ok)
}

/// Untrusted text for a terminal: C0 and C1 controls (ESC among them) and
/// DEL become a space, so a name cannot move the cursor or change colours.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn word(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(text) => clean(text),
        other => clean(&other.to_string()),
    }
}

/// `key: value` lines of one run.
pub fn job_text(job: &Value) -> String {
    let mut out = String::new();
    let line = |out: &mut String, key: &str, value: String| {
        let _ = writeln!(out, "{key:<11} {value}");
    };
    line(&mut out, "run:", word(&job["id"]));
    let mut state = word(&job["state"]);
    if let Some(stage) = job["stage"].as_str() {
        state.push_str(&format!(" ({stage})"));
    }
    if let Some(waiting) = job["waiting_for"].as_str() {
        state.push_str(&format!(", waiting for {waiting}"));
    }
    line(&mut out, "state:", state);
    if !job["sample"].is_null() {
        line(
            &mut out,
            "sample:",
            format!(
                "{} {} ({} bytes, {})",
                word(&job["sample"]["sha256"])
                    .chars()
                    .take(16)
                    .collect::<String>(),
                word(&job["sample"]["name"]),
                word(&job["sample"]["size"]),
                word(&job["sample"]["type"])
            ),
        );
    }
    line(
        &mut out,
        "preset:",
        format!(
            "{}, attempt {} of {}",
            word(&job["preset"]["name"]),
            word(&job["attempt"]),
            word(&job["max_attempts"])
        ),
    );
    if let Some(run) = job.get("program").filter(|r| !r.is_null()) {
        line(
            &mut out,
            "program:",
            format!(
                "{} ended {} exit {}",
                word(&run["id"]),
                word(&run["end_reason"]),
                word(&run["exit"])
            ),
        );
    }
    if let Some(a) = job.get("assessment").filter(|a| !a.is_null()) {
        line(
            &mut out,
            "label:",
            format!(
                "{} (score {}, {}, highest tier {})",
                word(&a["label"]),
                word(&a["score"]),
                word(&a["assessment"]),
                word(&a["highest_tier"])
            ),
        );
        line(&mut out, "basis:", word(&a["basis"]));
    }
    if let Some(failure) = job.get("failure").filter(|f| !f.is_null()) {
        line(
            &mut out,
            "failure:",
            format!("{}: {}", word(&failure["code"]), word(&failure["message"])),
        );
    }
    for item in job["host_work"].as_array().into_iter().flatten() {
        line(
            &mut out,
            "host item:",
            format!(
                "{} {} (expected {} s, {}, limit {} s){}",
                word(&item["name"]),
                word(&item["state"]),
                word(&item["expected_s"]),
                word(&item["basis"]),
                word(&item["limit_s"]),
                item["note"]
                    .as_str()
                    .map(|note| format!(": {}", clean(note)))
                    .unwrap_or_default()
            ),
        );
    }
    for warning in job["warnings"].as_array().into_iter().flatten() {
        line(
            &mut out,
            "warning:",
            format!("{}: {}", word(&warning["code"]), word(&warning["text"])),
        );
    }
    out
}

/// One table row of `auto list`.
pub fn job_row(job: &Value) -> Vec<String> {
    vec![
        word(&job["id"]),
        word(&job["state"]),
        word(&job["stage"]),
        word(&job["assessment"]["label"]),
        word(&job["sample"]["name"]),
        word(&job["preset"]["name"]),
    ]
}

/// `auto status` without a run: the queue.
pub fn queue_text(status: &Value) -> String {
    let mut out = format!(
        "queue:      {} queued, {} running{}\nowner:      {}\n",
        word(&status["queued"]),
        word(&status["running"]),
        match status["pause_reason"].as_str() {
            Some(reason) => format!(", paused ({reason})"),
            None => String::new(),
        },
        word(&status["owner"])
    );
    if let Some(pool) = status.get("host_pool").filter(|p| !p.is_null()) {
        let _ = writeln!(
            out,
            "host pool:  {} queued, {} running of {} worker(s), {} run(s){}",
            word(&pool["queued"]),
            word(&pool["running"]),
            word(&pool["workers"]),
            word(&pool["runs"]),
            pool["waiting_for"]
                .as_str()
                .map(|why| format!(", waiting for {}", clean(why)))
                .unwrap_or_default()
        );
    }
    for lane in status["lanes"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "{:<11} {} vm {} run {} disk layer {}{}",
            format!("{}:", word(&lane["lane"])),
            word(&lane["state"]),
            word(&lane["vm_id"]),
            word(&lane["run_id"]),
            word(&lane["disk_layer"]),
            // Why a quarantined lane is out of service (A46).
            lane["reason"]
                .as_str()
                .map(|why| format!(" reason {}", clean(why)))
                .unwrap_or_default()
        );
    }
    out
}

/// A preset as `preset.get` gives it (its name, digest and `built_in`
/// beside the tables of the file), as the TOML of a preset file
/// (`auto preset show`, ANT-T0556): save it as `presets/<name>.toml` under
/// another name to start a preset from it. The name and digest are comments;
/// a nested table is a `[table.sub]` header and a table inside a list an
/// inline table, as in the file format.
pub fn preset_toml(preset: &Value) -> String {
    let mut out = String::new();
    let Some(map) = preset.as_object() else {
        return out;
    };
    let name = map.get("name").and_then(Value::as_str).unwrap_or("");
    let _ = writeln!(out, "# preset {}", clean(name));
    if let Some(digest) = map.get("digest").and_then(Value::as_str) {
        let _ = writeln!(out, "# digest {}", clean(digest));
    }
    if map.get("built_in") == Some(&Value::Bool(true)) {
        out.push_str(
            "# built in and read-only: save this as presets/<another name>.toml to change it\n",
        );
    }
    let settings: serde_json::Map<String, Value> = map
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "name" | "digest" | "built_in"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    toml_table(&mut out, "", &settings);
    out
}

fn toml_table(out: &mut String, path: &str, map: &serde_json::Map<String, Value>) {
    for (key, value) in map {
        if value.is_object() || value.is_null() {
            continue;
        }
        let _ = writeln!(out, "{} = {}", toml_key(key), toml_value(value));
    }
    for (key, value) in map {
        let Value::Object(table) = value else {
            continue;
        };
        let path = if path.is_empty() {
            toml_key(key)
        } else {
            format!("{path}.{}", toml_key(key))
        };
        let _ = write!(out, "\n[{path}]\n");
        toml_table(out, &path, table);
    }
}

fn toml_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        key.to_owned()
    } else {
        toml_string(key)
    }
}

/// A TOML basic string: JSON's escapes are TOML's, and no control character
/// reaches the terminal unescaped.
fn toml_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

fn toml_value(value: &Value) -> String {
    match value {
        Value::String(text) => toml_string(text),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .filter(|item| !item.is_null())
                .map(toml_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(map) => format!(
            "{{ {} }}",
            map.iter()
                .filter(|(_, item)| !item.is_null())
                .map(|(key, item)| format!("{} = {}", toml_key(key), toml_value(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Null => "\"\"".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_service::api::assessment::Assessment;

    fn job(state: RunState, label: Option<Label>) -> Run {
        let mut value = serde_json::json!({
            "api_version": 1, "id": "j_01ARZ3NDEKTSV4RRFFQ69G5FAV", "state": "queued",
            "stage": null, "waiting_for": null, "outcome": null, "created_ms": 1,
            "started_ms": null, "finished_ms": null, "queue_position": null,
            "attempt": 1, "max_attempts": 2, "client_id": "local:1",
            "request": {"sample": {"sha256": "aa".repeat(32)}},
            "sample": null, "preset": {"name": "default", "digest": "d"}, "lane": null,
            "vm": null, "run": null, "recording": null, "assessment": null,
            "artifacts": [], "warnings": [], "failure": null, "repeat_of": null, "labels": {}
        });
        value["state"] = serde_json::to_value(state).unwrap();
        let mut job: Run = serde_json::from_value(value).unwrap();
        job.assessment = label.map(|label| Assessment {
            label: Some(label),
            ..serde_json::from_value(serde_json::json!({
                "assessment": "no_findings", "highest_tier": "none", "label": null,
                "score": null, "families": [], "key_behaviours": [],
                "counts": {"processes": 0, "findings": 0, "indicators": 0, "indicators_matched": 0,
                    "techniques": 0, "files_changed": 0, "files_opened": 0, "endpoints": 0, "domains": 0},
                "detections": [], "techniques": [], "ioc_dataset_count": 0, "basis": "b"
            }))
            .unwrap()
        });
        job
    }

    #[test]
    fn the_job_state_comes_first_and_the_label_only_counts_on_success_with_verdict_exit() {
        use RunState::*;
        let cases = [
            (Succeeded, None, false, 0),
            (Succeeded, Some(Label::Malicious), false, 0),
            (Succeeded, Some(Label::CleanObserved), true, 0),
            (Succeeded, None, true, 0),
            (Succeeded, Some(Label::Suspicious), true, 30),
            (Succeeded, Some(Label::Malicious), true, 31),
            (Succeeded, Some(Label::Inconclusive), true, 32),
            // A partial or failed run is never read as a verdict.
            (Partial, Some(Label::Malicious), true, 11),
            (Failed, Some(Label::Malicious), true, 10),
            (Cancelled, None, true, 12),
            (Rejected, None, true, 13),
            (Running, None, true, 14),
            (Queued, None, false, 14),
        ];
        for (state, label, verdict, code) in cases {
            assert_eq!(
                job_exit(&job(state, label), verdict).code(),
                code,
                "{state:?} {label:?} {verdict}"
            );
        }
        assert_eq!(
            worst(&[Exit::Ok, Exit::RunPartial, Exit::Suspicious]).code(),
            30
        );
        assert_eq!(worst(&[]).code(), 0);
    }

    #[test]
    fn untrusted_text_cannot_steer_the_terminal() {
        assert_eq!(clean("a\x1b[31mred\x07\u{9b}x\n"), "a [31mred  x ");
        let text = job_text(&serde_json::json!({
            "id": "j_1", "state": "succeeded", "sample": {"sha256": "ab", "name": "evil\x1b]0;pwn\x07", "size": 1, "type": "sh"},
            "preset": {"name": "default"}, "attempt": 1, "max_attempts": 2,
            "warnings": [{"code": "w", "text": "line1\nline2"}]
        }));
        assert!(!text.contains('\x1b') && !text.contains('\x07'));
        assert!(text.contains("line1 line2"));
    }

    #[test]
    fn host_items_and_the_pool_are_shown() {
        let text = job_text(&serde_json::json!({
            "id": "j_1", "state": "running", "stage": "analyse",
            "preset": {"name": "default"}, "attempt": 1, "max_attempts": 2, "warnings": [],
            "host_work": [
                {"name": "static:floss", "state": "running", "expected_s": 150, "basis": "estimate", "limit_s": 300},
                {"name": "report", "state": "queued", "expected_s": 30, "basis": "median", "limit_s": 60, "note": "x\x1by"}
            ]
        }));
        assert!(
            text.contains("static:floss running (expected 150 s, estimate, limit 300 s)"),
            "{text}"
        );
        assert!(
            text.contains("report queued (expected 30 s, median, limit 60 s): x y"),
            "{text}"
        );
        let queue = queue_text(&serde_json::json!({
            "queued": 3, "running": 1, "owner": "daemon", "lanes": [],
            "host_pool": {"workers": 2, "queued": 5, "running": 2, "runs": 2, "waiting_for": null}
        }));
        assert!(
            queue.contains("host pool:  5 queued, 2 running of 2 worker(s), 2 run(s)"),
            "{queue}"
        );
    }

    /// A46: a quarantined lane says why in `queue status`.
    #[test]
    fn a_quarantined_lane_shows_its_reason() {
        let queue = queue_text(&serde_json::json!({
            "queued": 0, "running": 0, "owner": "daemon",
            "lanes": [
                {"lane": "lane-1", "state": "idle", "vm_id": "v1", "run_id": null, "disk_layer": "none"},
                {"lane": "lane-2", "state": "quarantined", "vm_id": "v2", "run_id": null,
                 "disk_layer": "pending",
                 "reason": "revert_failed: the lane VM did not stop and settle after a forced stop"}
            ]
        }));
        assert!(
            queue.contains("lane-2:     quarantined vm v2 run - disk layer pending reason revert_failed: the lane VM did not stop and settle after a forced stop"),
            "{queue}"
        );
        assert!(
            !queue
                .lines()
                .find(|l| l.starts_with("lane-1"))
                .unwrap()
                .contains("reason")
        );
    }

    #[test]
    fn preset_show_prints_a_preset_file_that_loads_as_the_same_preset() {
        let set = antinomie_service::config::PresetSet::built_in();
        let names: Vec<String> = set.names().map(str::to_owned).collect();
        assert_eq!(names.len(), 6);
        for name in names {
            let detail = serde_json::to_value(set.detail(&name).unwrap()).unwrap();
            let text = preset_toml(&detail);
            // The old line was not TOML: `static_analysis.limits = {"rows_per_check":2048,...}`.
            assert!(text.contains("\n[static_analysis.limits]\n"), "{text}");
            assert!(text.contains("rows_per_check = 2048"), "{text}");
            assert!(
                text.starts_with(&format!("# preset {name}\n# digest ")),
                "{text}"
            );
            let (copy, problems) = antinomie_service::config::validate::parse_preset(
                "copy",
                "presets/copy.toml",
                &text,
            );
            // Live network's Tor route is a node matter in 0.9.0 (live
            // routes arrives in a later version), not a fault of the printed TOML.
            let errors: Vec<_> = problems
                .iter()
                .filter(|p| p.severity == antinomie_service::config::Severity::Error)
                .filter(|p| {
                    !(p.key.as_deref() == Some("network.route")
                        && p.message.contains("live routes arrives in a later version"))
                })
                .collect();
            assert!(errors.is_empty(), "{name}: {errors:?}\n{text}");
            let original = antinomie_service::config::PresetLookup::get(&set, &name).unwrap();
            assert_eq!(copy.unwrap().preset, original.preset, "{name}");
        }
        // A table in a list is an inline table, a key that is not bare is quoted.
        let text = preset_toml(&serde_json::json!({
            "name": "x", "digest": "d", "built_in": false,
            "verdict": {"rule": [{"when": "a \"b\"", "label": "malicious"}]},
            "odd key": "\u{1b}[31m"
        }));
        assert!(
            text.contains("rule = [{ when = \"a \\\"b\\\"\", label = \"malicious\" }]"),
            "{text}"
        );
        assert!(text.contains("\"odd key\" = \"\\u001b[31m\""), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}
