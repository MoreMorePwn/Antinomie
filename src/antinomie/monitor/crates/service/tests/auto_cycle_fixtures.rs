// SPDX-License-Identifier: GPL-3.0-only
//! The traces recorded by the P0-1 spike (`monitor-core/examples/auto-cycle.rs`)
//! on a real VM: the `Command` / `Notification` sequence and timings of full
//! unattended cycles, which the `FakeEngine` of card P3-4a replays. These tests
//! only guard the format the replayer will rely on.

use serde_json::Value;
use std::{collections::BTreeSet, fs, path::PathBuf};

fn fixtures() -> Vec<(String, Vec<Value>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auto-cycle");
    let mut found = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|x| x == "jsonl") {
            let rows = fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(|line| {
                    serde_json::from_str(line).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                })
                .collect();
            found.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                rows,
            ));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

#[test]
fn every_trace_is_ordered_in_time_and_uses_the_known_kinds() {
    let traces = fixtures();
    assert!(traces.len() >= 5, "the spike recorded at least five cases");
    for (name, rows) in traces {
        let mut last = 0.0;
        for row in &rows {
            let t = row["t"]
                .as_f64()
                .unwrap_or_else(|| panic!("{name}: row without t"));
            assert!(t >= last, "{name}: time goes back at {row}");
            last = t;
            match row["dir"].as_str() {
                Some("command") => {
                    assert!(
                        row["id"].is_u64() && row["name"].is_string(),
                        "{name}: {row}"
                    )
                }
                Some("note") => assert!(
                    matches!(
                        row["kind"].as_str(),
                        Some(
                            "snapshot"
                                | "command_result"
                                | "run_started"
                                | "analysis_updated"
                                | "terminal"
                                | "terminal_screen"
                                | "run_layer_file"
                        )
                    ),
                    "{name}: {row}"
                ),
                Some("meta") => {}
                other => panic!("{name}: unknown dir {other:?}"),
            }
        }
    }
}

#[test]
fn every_command_that_got_an_id_gets_exactly_one_result_except_terminal_reads() {
    for (name, rows) in fixtures() {
        // `TerminalRead` has no `CommandResult`: the engine answers it with the
        // `Terminal` notifications and a successful empty reply is not sent.
        let sent: BTreeSet<u64> = rows
            .iter()
            .filter(|r| r["dir"] == "command" && r["name"] != "TerminalRead")
            .filter_map(|r| r["id"].as_u64())
            .collect();
        let mut answered = BTreeSet::new();
        for row in rows.iter().filter(|r| r["kind"] == "command_result") {
            let id = row["id"].as_u64().unwrap();
            // The engine also emits results with id 0 for its own events.
            if id != 0 {
                assert!(answered.insert(id), "{name}: command {id} answered twice");
            }
        }
        let missing: Vec<_> = sent.difference(&answered).collect();
        assert!(missing.is_empty(), "{name}: {missing:?} never answered");
        for id in &answered {
            assert!(
                sent.contains(id) || rows.iter().any(|r| r["dir"] == "command" && r["id"] == *id),
                "{name}: result {id} for a command that was never sent"
            );
        }
    }
}

#[test]
fn a_cycle_runs_through_the_documented_notifications() {
    for (name, rows) in fixtures() {
        let begins = rows.iter().filter(|r| r["kind"] == "cycle_begin").count();
        let ends = rows.iter().filter(|r| r["kind"] == "cycle_end").count();
        assert_eq!(begins, ends, "{name}");
        assert!(begins >= 1, "{name}: no cycle");
        let kinds: Vec<_> = rows.iter().filter_map(|r| r["kind"].as_str()).collect();
        for needed in [
            "run_started",
            "terminal",
            "run_layer_file",
            "command_result",
            "snapshot",
        ] {
            assert!(kinds.contains(&needed), "{name}: no {needed}");
        }
        let states: BTreeSet<_> = rows
            .iter()
            .filter(|r| r["kind"] == "snapshot")
            .filter_map(|r| r["digest"]["state"].as_str())
            .collect();
        assert!(
            states.contains("Running") && states.contains("Stopped"),
            "{name}: {states:?}"
        );
    }
}
