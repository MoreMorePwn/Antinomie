// SPDX-License-Identifier: MIT
//! Opt-in check of Triage over real guest recordings made by
//! `tracer-check record` (see its documentation): the hashes of written files
//! and of the launched program, the guest's user names, and a run recorded
//! across a transport reconnect.
//!
//! ```text
//! tracer-check record BUNDLE NEW_DATA_DIR FIXTURE   # prints RUN label=dir, FIXTURE_SHA256
//! ANTINOMIE_TRACER_RUNS='writes=DIR;reconnect=DIR;analyst=DIR;nobody=DIR' \
//! ANTINOMIE_TRACER_FIXTURE_SHA256=HEX ANTINOMIE_TRACER_DATA=NEW_DATA_DIR \
//! ANTINOMIE_DISK_READER=target/release/antinomie-monitor \
//!     cargo test --release -p antinomie-monitor-ui recorded_tracer_triage -- --ignored
//! ```
//!
//! The names come from the base the VM's disk came from, read by the disk
//! reader program `ANTINOMIE_DISK_READER` (this test binary cannot serve it).
use super::*;
use antinomie_monitor_core::guest_names::{self, GuestNames};

fn run_of(directory: &Path) -> antinomie_monitor_core::RunSummary {
    serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap()
}

/// The guest's names for a run: its base, read by the disk reader program.
fn names(directory: &Path) -> Option<Arc<GuestNames>> {
    let data = std::env::var_os("ANTINOMIE_TRACER_DATA")?;
    let reader = std::env::var_os("ANTINOMIE_DISK_READER")?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).ok()?).ok()?;
    let identity = manifest["disk_base_identity"].as_str()?;
    let image = Path::new(&data)
        .join("bases")
        .join(identity)
        .join("base.qcow2");
    let names = guest_names::read_base(&image, Some(reader.into())).unwrap();
    Some(Arc::new(names))
}

/// Scan `directory` as the app does; `whole` reads every recording segment,
/// otherwise only this one (what Triage did before). The run's own capture of
/// this segment is the pcap, as the app finds it.
fn scan(directory: &Path, whole: bool) -> ArchiveScan {
    let run = run_of(directory);
    let pcap = antinomie_monitor_core::RunArtifacts::load(directory)
        .ok()
        .flatten()
        .and_then(|artifacts| artifacts.network_captures.last().cloned());
    let request = ScanRequest {
        root_cookie: run.root_task_cookie,
        clock_anchor: run.clock_anchor,
        started_ms: run.started_ms,
        run_finished: true,
        identity: whole.then(|| (run.vm_id.clone(), run.boot_id.clone(), run.id.clone())),
        guest_names: names(directory),
        ..Default::default()
    };
    scan_archive_query(
        directory,
        pcap.as_deref(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap()
}

/// The detection journal the last whole scan wrote: its events.
fn journal(directory: &Path) -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string(
        directory.join(antinomie_monitor_core::analysis::detection::JOURNAL_FILE),
    )
    .unwrap();
    data.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|line| line["kind"] == "event")
        .map(|line| line["event"].clone())
        .collect()
}

fn pattern_sha(seed: u64, size: u64) -> String {
    let bytes: Vec<u8> = (0..size).map(|i| (i * 31 + seed) as u8).collect();
    antinomie_monitor_core::storage::sha256_hex(&bytes)
}

static MISSED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn expect(ok: bool, what: String) {
    if ok {
        println!("OK {what}");
    } else {
        MISSED.lock().unwrap().push(what);
    }
}

fn changed_rows(scan: &ArchiveScan) -> Vec<String> {
    scan.changed
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| cell.text.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect()
}

fn event_for<'a>(
    events: &'a [serde_json::Value],
    category: &str,
    field: &str,
    value: &str,
) -> Option<&'a serde_json::Value> {
    events
        .iter()
        .find(|event| event["category"] == category && event["fields"][field] == value)
}

#[test]
#[ignore = "requires ANTINOMIE_TRACER_RUNS from `tracer-check record`"]
fn recorded_tracer_triage() {
    let runs = std::env::var("ANTINOMIE_TRACER_RUNS").expect("ANTINOMIE_TRACER_RUNS");
    let runs: std::collections::BTreeMap<_, _> = runs
        .split(';')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (label, directory) = entry.split_once('=').expect("label=directory");
            (label.to_owned(), std::path::PathBuf::from(directory))
        })
        .collect();
    let fixture = std::env::var("ANTINOMIE_TRACER_FIXTURE_SHA256").unwrap_or_default();

    if let Some(writes) = runs.get("writes") {
        let found = scan(writes, true);
        let events = journal(writes);
        let run = run_of(writes);
        // The launched program's own process creation, with its image hash.
        let root = events
            .iter()
            .find(|event| {
                event["category"] == "process_creation"
                    && event["fields"]["ProcessId"] == run.pid
                    && event["fields"]["Image"] == "/tmp/tracer-fixture"
            })
            .cloned();
        match &root {
            Some(root) => {
                println!("ROOT {}", root["fields"]);
                expect(
                    root["fields"]["Hashes"] == format!("SHA256={fixture}"),
                    format!("root process_creation Hashes {}", root["fields"]["Hashes"]),
                );
                expect(
                    root["fields"]["CommandLine"] == "/tmp/tracer-fixture writes",
                    format!("root CommandLine {}", root["fields"]["CommandLine"]),
                );
                expect(
                    root["fields"]["User"] == "root",
                    format!("root User {}", root["fields"]["User"]),
                );
            }
            None => expect(false, "no process_creation for the launched program".into()),
        }
        // The dropped copy's exec names its parent by the launched image.
        let dropped = event_for(&events, "process_creation", "Image", "/tmp/tracer/dropped");
        if let Some(dropped) = dropped {
            println!("DROPPED {}", dropped["fields"]);
        }
        expect(
            dropped.is_some_and(|event| event["fields"]["ParentImage"] == "/tmp/tracer-fixture"),
            format!(
                "dropped exec ParentImage {}",
                dropped.map_or(serde_json::Value::Null, |event| event["fields"]
                    ["ParentImage"]
                    .clone())
            ),
        );
        // Created files carry the hash of their last close.
        for (path, seed, size) in [
            ("/tmp/tracer/new", 1, 100_000),
            ("/tmp/tracer/two", 2, 8192),
            ("/tmp/tracer/child", 3, 8192),
            ("/tmp/tracer/exit", 4, 5000),
            ("/tmp/tracer/before", 6, 3000),
            ("/tmp/tracer/gone", 7, 2000),
        ] {
            let event = event_for(&events, "file_event", "TargetFilename", path);
            let want = format!("SHA256={}", pattern_sha(seed, size));
            expect(
                event.is_some_and(|event| event["fields"]["Hashes"] == want.as_str()),
                format!(
                    "file_event {path} Hashes {}",
                    event.map_or(serde_json::Value::Null, |event| event["fields"]["Hashes"]
                        .clone())
                ),
            );
        }
        let big = event_for(&events, "file_event", "TargetFilename", "/tmp/tracer/big");
        expect(
            big.and_then(|event| event["fields"]["HashSkipped"].as_str())
                .is_some_and(|why| why.contains("over the 16 MiB limit")),
            format!(
                "file_event big HashSkipped {}",
                big.map_or(serde_json::Value::Null, |event| event["fields"]
                    ["HashSkipped"]
                    .clone())
            ),
        );
        // auditd keeps numbers and adds the interpreted names.
        let syscall = events.iter().find(|event| {
            event["category"] == "auditd"
                && event["fields"]["type"] == "SYSCALL"
                && event["fields"]["pid"]
                    .as_str()
                    .and_then(|pid| pid.parse::<u32>().ok())
                    == Some(run.pid)
        });
        expect(
            syscall.is_some_and(|event| {
                event["fields"]["uid"] == "0" && event["fields"]["UID"] == "root"
            }),
            format!(
                "auditd SYSCALL uid/UID {:?}",
                syscall.map(|event| (
                    event["fields"]["uid"].clone(),
                    event["fields"]["UID"].clone()
                ))
            ),
        );
        // Triage › Files shows the hash in the file's lifecycle.
        let rows = changed_rows(&found);
        let new_hash = pattern_sha(1, 100_000);
        let row = rows
            .iter()
            .find(|row| row.contains("/tmp/tracer/new") && row.contains(&new_hash[..12]));
        if let Some(row) = row {
            println!("ROW Changed: {row}");
        }
        expect(
            row.is_some(),
            "Changed row of /tmp/tracer/new with its hash".into(),
        );
        let root_node = found
            .process
            .iter()
            .find(|node| node.pid == run.pid && node.cookie == run.root_task_cookie);
        expect(
            root_node.is_some_and(|node| node.comm == "/tmp/tracer-fixture"),
            format!("root process named {:?}", root_node.map(|node| &node.comm)),
        );
    }

    if let Some(reconnect) = runs.get("reconnect") {
        // Before: only the newest segment.
        let newest = scan(reconnect, false);
        let before = changed_rows(&newest);
        // Now: every segment, oldest first.
        let whole = scan(reconnect, true);
        let after = changed_rows(&whole);
        println!("COVERAGE {}", whole.coverage);
        let count =
            |rows: &[String], name: &str| rows.iter().filter(|row| row.contains(name)).count();
        println!(
            "SEGMENTS newest only: {} changed files, slow-0 {}; whole run: {} changed files, slow-0 {}",
            before.len(),
            count(&before, "/tmp/tracer/slow-0 "),
            after.len(),
            count(&after, "/tmp/tracer/slow-0 ")
        );
        expect(
            whole.coverage.contains("read 2 recording segments"),
            "the scan read both segments".into(),
        );
        expect(
            count(&after, "/tmp/tracer/slow-0 ") == 1 && count(&after, "/tmp/tracer/slow-29 ") == 1,
            "files of both segments are listed".into(),
        );
        expect(
            count(&before, "/tmp/tracer/slow-0 ") == 0,
            "the newest segment alone misses the first files (the earlier behaviour)".into(),
        );
        let long = after.iter().find(|row| row.contains("/tmp/tracer/long"));
        if let Some(row) = long {
            println!("ROW Changed: {row}");
        }
        expect(
            long.is_some_and(|row| row.contains("reconnected")),
            "the file written across the reconnect shows the boundary".into(),
        );
        let events = journal(reconnect);
        let run = run_of(reconnect);
        expect(
            events.iter().any(|event| {
                event["category"] == "process_creation" && event["fields"]["ProcessId"] == run.pid
            }),
            "the launch, in the first segment, is in the journal".into(),
        );
        for name in ["/tmp/tracer/slow-0", "/tmp/tracer/slow-29"] {
            expect(
                event_for(&events, "file_event", "TargetFilename", name).is_some(),
                format!("file_event {name} in the journal"),
            );
        }
        // The DNS queries of both segments' captures: a Sigma input.
        let queried = |scan: &ArchiveScan, name: &str| {
            scan.dns
                .iter()
                .any(|row| row.iter().any(|cell| cell.text.contains(name)))
        };
        println!(
            "DNS whole run: tick-0 {} tick-29 {}",
            queried(&whole, "tick-0.tracer.test"),
            queried(&whole, "tick-29.tracer.test")
        );
        expect(
            queried(&whole, "tick-0.tracer.test") && queried(&whole, "tick-29.tracer.test"),
            "DNS rows of both segments' captures".into(),
        );
        for name in ["tick-0.tracer.test", "tick-29.tracer.test"] {
            expect(
                event_for(&events, "dns_query", "QueryName", name).is_some(),
                format!("dns_query {name} in the journal"),
            );
        }
    }

    // A base from before the hashes: nothing is held back or explained.
    if let Some(legacy) = runs.get("legacy") {
        let found = scan(legacy, true);
        let events = journal(legacy);
        let created = event_for(&events, "file_event", "TargetFilename", "/tmp/tracer/new");
        println!(
            "LEGACY file_event {:?}",
            created.map(|event| &event["fields"])
        );
        expect(
            created.is_some_and(|event| {
                event["fields"].get("Hashes").is_none()
                    && event["fields"].get("HashSkipped").is_none()
            }),
            "legacy: a creation without the guest's hash says nothing about one".into(),
        );
        let root = events.iter().find(|event| {
            event["category"] == "process_creation"
                && event["fields"]["Image"] == "/tmp/tracer-fixture"
        });
        expect(
            root.is_some_and(|event| event["fields"].get("Hashes").is_none()),
            "legacy: the launched program is listed, without an image hash".into(),
        );
        expect(
            !changed_rows(&found)
                .iter()
                .any(|row| row.contains("closed after write")),
            "legacy: no hash in the Changed files".into(),
        );
    }

    for (label, user) in [("analyst", "analyst"), ("nobody", "65534")] {
        let Some(directory) = runs.get(label) else {
            continue;
        };
        scan(directory, true);
        let events = journal(directory);
        let root = events
            .iter()
            .find(|event| event["category"] == "process_creation");
        expect(
            root.is_some_and(|event| event["fields"]["User"] == user),
            format!(
                "{label}: process_creation User {}",
                root.map_or(serde_json::Value::Null, |event| event["fields"]["User"]
                    .clone())
            ),
        );
    }
    let missed = MISSED.lock().unwrap();
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}
