// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in check of Triage over real guest recordings made by
//! `tracer-check record` (see its documentation): the hashes of written files
//! and of the launched program, the guest's user names, and a run recorded
//! across a transport reconnect.
//!
//! ```text
//! tracer-check record BUNDLE NEW_DATA_DIR FIXTURE   # prints RUN label=dir, FIXTURE_SHA256
//! ANTINOMIE_TRACER_RUNS='writes=DIR;reconnect=DIR;user=DIR;nobody=DIR' \
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
    // Nothing to check is not a pass: a run list without a run this test
    // knows (tracer-check failed before printing any) fails here.
    const LABELS: [&str; 6] = [
        "writes",
        "reconnect",
        "user",
        "nobody",
        "legacy",
        "versions",
    ];
    let unknown: Vec<_> = runs
        .keys()
        .filter(|label| !LABELS.contains(&label.as_str()))
        .collect();
    assert!(unknown.is_empty(), "unknown run labels {unknown:?}");
    assert!(
        !runs.is_empty(),
        "ANTINOMIE_TRACER_RUNS names no run; tracer-check printed none"
    );
    for (label, directory) in &runs {
        assert!(
            directory.join("run.json").is_file(),
            "the {label} run has no recording at {}",
            directory.display()
        );
    }
    let fixture = std::env::var("ANTINOMIE_TRACER_FIXTURE_SHA256").unwrap_or_default();
    if runs.contains_key("writes") || runs.contains_key("versions") {
        assert!(
            fixture.len() == 64,
            "the writes and versions runs need ANTINOMIE_TRACER_FIXTURE_SHA256, got {fixture:?}"
        );
    }

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

    if let Some(directory) = runs.get("versions") {
        versions(&scan(directory, true), &fixture);
    }

    for (label, user) in [("user", "user"), ("nobody", "65534")] {
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

/// The SHA-256 of `bytes`.
fn sha(bytes: &[u8]) -> String {
    antinomie_monitor_core::storage::sha256_hex(bytes)
}

/// `pattern(seed)` over `[from, from + len)`, as the fixture writes it.
fn pattern(seed: u64, from: u64, len: u64) -> Vec<u8> {
    (from..from + len).map(|i| (i * 31 + seed) as u8).collect()
}

/// The digest after every step of `file`'s history, from an empty start (the
/// run created each of these files), with `None` where a byte is unknown.
fn digests(file: &super::file_activity::FileActivity) -> Vec<Option<String>> {
    use antinomie_monitor_core::file_reconstruct::{Reconstruction, Start};
    let mut map = Reconstruction::new(Start::empty(), &file.timeline);
    (0..=file.timeline.steps().len())
        .map(|count| {
            map.goto(count);
            map.sha256().ok()
        })
        .collect()
}

/// The digest of `file` as it was when its first `kind` call happened.
fn digest_at(
    file: &super::file_activity::FileActivity,
    kind: super::file_activity::Kind,
) -> Option<String> {
    use antinomie_monitor_core::file_reconstruct::{Reconstruction, Start};
    let event = file.events.iter().find(|event| event.kind == kind)?;
    let mut map = Reconstruction::new(Start::empty(), &file.timeline);
    map.goto(map.steps_until(event.time));
    map.sha256().ok()
}

/// The `versions` run: a file whose real payload is a version that does not
/// survive the run, a file read in its middle version, partial overwrites,
/// appends, a rename over a file, shared-mapping writes and two writers.
/// Every version must be recoverable from the recording, the version that
/// was executed or read must be the one shown at that call, and the files
/// must stay listed after they were deleted or emptied.
fn versions(found: &ArchiveScan, fixture: &str) {
    let activity = &found.file_activity;
    let file = |name: &str| {
        let path = format!("/tmp/tracer-v/{name}");
        activity
            .files
            .iter()
            .filter(|file| file.path == path || file.names.contains(&path))
            .collect::<Vec<_>>()
    };
    let has = |digests: &[Option<String>], wanted: &str| {
        digests
            .iter()
            .any(|digest| digest.as_deref() == Some(wanted))
    };
    for name in [
        "payload", "data", "partial", "append", "target", "mapped", "shared",
    ] {
        let found = file(name);
        println!(
            "VERSIONS {name}: {} file(s), steps {:?}",
            found.len(),
            found
                .iter()
                .map(|file| file.timeline.steps().len())
                .collect::<Vec<_>>()
        );
    }

    // payload: decoy, the program (executed), decoy, deleted.
    let payload = file("payload");
    let (v1, v3) = (sha(&pattern(31, 0, 6000)), sha(&pattern(33, 0, 3000)));
    let steps: Vec<_> = payload.iter().flat_map(|file| digests(file)).collect();
    expect(
        has(&steps, &v1),
        "versions payload: v1 (decoy) recoverable".into(),
    );
    expect(
        has(&steps, fixture),
        "versions payload: v2 (the executed program) recoverable".into(),
    );
    expect(
        has(&steps, &v3),
        "versions payload: v3 (decoy) recoverable".into(),
    );
    let executed: Vec<_> = payload
        .iter()
        .filter_map(|file| digest_at(file, super::file_activity::Kind::Exec))
        .collect();
    expect(
        executed.iter().any(|digest| digest == fixture),
        format!("versions payload: the version shown at the exec is v2 ({executed:?})"),
    );
    expect(
        payload.iter().any(|file| {
            file.hashes
                .iter()
                .any(|hash| hash.moment == "exec image" && hash.sha256.as_deref() == Some(fixture))
        }),
        "versions payload: the guest's exec image hash is v2".into(),
    );
    expect(
        payload.iter().any(|file| file.deleted),
        "versions payload: listed as deleted, not dropped".into(),
    );

    // data: v1, v2 (read back), truncated to nothing.
    let data = file("data");
    let steps: Vec<_> = data.iter().flat_map(|file| digests(file)).collect();
    let (d1, d2) = (sha(&pattern(41, 0, 4096)), sha(&pattern(42, 0, 4096)));
    expect(has(&steps, &d1), "versions data: v1 recoverable".into());
    expect(has(&steps, &d2), "versions data: v2 recoverable".into());
    let read: Vec<_> = data
        .iter()
        .filter_map(|file| digest_at(file, super::file_activity::Kind::Read))
        .collect();
    expect(
        read.contains(&d2),
        format!("versions data: the version shown at the read is v2 ({read:?})"),
    );
    expect(
        steps.last().cloned().flatten() == Some(sha(b"")),
        format!("versions data: ends empty ({:?})", steps.last()),
    );

    // partial: the base with two pwrite ranges over it.
    let mut partial = pattern(51, 0, 16384);
    partial[4096..4608].copy_from_slice(&pattern(52, 4096, 512));
    partial[15000..15100].copy_from_slice(&pattern(53, 15000, 100));
    let steps: Vec<_> = file("partial")
        .iter()
        .flat_map(|file| digests(file))
        .collect();
    expect(
        has(&steps, &sha(&pattern(51, 0, 16384))),
        "versions partial: the first version recoverable".into(),
    );
    expect(
        steps.last().cloned().flatten() == Some(sha(&partial)),
        "versions partial: the pwrites land at their offsets".into(),
    );

    // append: three appends end to end.
    let steps: Vec<_> = file("append")
        .iter()
        .flat_map(|file| digests(file))
        .collect();
    expect(
        steps.last().cloned().flatten() == Some(sha(&pattern(61, 0, 3000))),
        format!(
            "versions append: the appends end to end ({:?})",
            steps.last()
        ),
    );
    expect(
        has(&steps, &sha(&pattern(61, 0, 1000))),
        "versions append: the first append recoverable".into(),
    );

    // renamed: the old target and the new file renamed over it.
    let target = file("target");
    let steps: Vec<_> = target.iter().flat_map(|file| digests(file)).collect();
    expect(
        has(&steps, &sha(&pattern(71, 0, 2000))),
        "versions renamed: the replaced target recoverable".into(),
    );
    expect(
        has(&steps, &sha(&pattern(72, 0, 2500))),
        "versions renamed: the file renamed over it recoverable".into(),
    );
    expect(
        target.iter().any(|file| {
            file.path.ends_with("/target.new")
                || file.names.iter().any(|name| name.ends_with("/target.new"))
        }),
        "versions renamed: the new file keeps both names".into(),
    );

    // mapped: the pages the guest copied at msync.
    let steps: Vec<_> = file("mapped")
        .iter()
        .flat_map(|file| digests(file))
        .collect();
    expect(
        has(&steps, &sha(&pattern(81, 0, 8192))),
        format!(
            "versions mapped: the mapping's pages recoverable ({:?})",
            steps.last()
        ),
    );

    // shared: a child and its parent wrote one half each.
    let mut both = pattern(91, 0, 4096);
    both.extend(pattern(92, 4096, 4096));
    let shared = file("shared");
    let steps: Vec<_> = shared.iter().flat_map(|file| digests(file)).collect();
    expect(
        steps.last().cloned().flatten() == Some(sha(&both)),
        "versions shared: both writers' halves in place".into(),
    );
    let writers: std::collections::BTreeSet<_> = shared
        .iter()
        .flat_map(|file| &file.events)
        .filter(|event| event.kind == super::file_activity::Kind::Write)
        .map(|event| event.process)
        .collect();
    expect(
        writers.len() >= 2,
        format!("versions shared: two writing processes ({writers:?})"),
    );
}
