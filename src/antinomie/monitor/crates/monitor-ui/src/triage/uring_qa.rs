// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in check of Triage over real guest recordings of io_uring, AIO and
//! plain file work, made by `uring-check record` (see its documentation):
//!
//! ```text
//! uring-check record BUNDLE NEW_DATA_DIR WORKLOAD FIXTURE   # prints RUN label=dir
//! ANTINOMIE_URING_RUNS='files=DIR;regfiles=DIR;syncfiles=DIR;aio=DIR;sqfiles=DIR;morefiles=DIR;script=DIR;async-io=DIR' \
//!     cargo test --release -p antinomie-monitor-ui recorded_uring_triage -- --ignored
//! ```
//!
//! Each assertion names what the fixture did (`tests/monitor/uring-fixture.c`)
//! and what Triage must then show, from the guest's records alone.
use super::*;

fn scan(directory: &Path) -> ArchiveScan {
    let run: antinomie_monitor_core::RunSummary =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap();
    let request = ScanRequest {
        root_cookie: run.root_task_cookie,
        clock_anchor: run.clock_anchor,
        started_ms: run.started_ms,
        run_finished: true,
        identity: Some((run.vm_id.clone(), run.boot_id.clone(), run.id.clone())),
        ..Default::default()
    };
    scan_archive_query(
        directory,
        None,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap()
}

/// The rows of a file tab, one text per row.
fn rows(scan: &ArchiveScan, tab: FileTab) -> Vec<String> {
    let table: &[Vec<Cell>] = match tab {
        FileTab::Opened => &scan.opened,
        FileTab::Read => &scan.read,
        FileTab::Changed => &scan.changed,
        other => &scan.file_tabs[other.slot() - 8].rows,
    };
    table
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| cell.text.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect()
}

/// Every expectation that did not hold, so one run reports them all.
static MISSED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn miss(message: String) {
    MISSED.lock().unwrap().push(message);
}

/// Each row that met an expectation is printed (`--nocapture`), so a run
/// shows the rows Triage produced, not only that they matched.
fn has(scan: &ArchiveScan, tab: FileTab, needles: &[&str]) {
    let found = rows(scan, tab);
    if let Some(row) = found
        .iter()
        .find(|row| needles.iter().all(|needle| row.contains(needle)))
    {
        println!("ROW {}: {row}", tab.title());
    } else {
        miss(format!(
            "no row of the {} tab holds {needles:?}; rows:\n{}",
            tab.title(),
            found.join("\n")
        ));
    }
}

#[test]
#[ignore = "requires ANTINOMIE_URING_RUNS from `uring-check record`"]
fn recorded_uring_triage() {
    let runs = std::env::var("ANTINOMIE_URING_RUNS").expect("ANTINOMIE_URING_RUNS");
    let mut scans = std::collections::BTreeMap::new();
    for entry in runs.split(';').filter(|entry| !entry.is_empty()) {
        let (label, directory) = entry.split_once('=').expect("label=directory");
        scans.insert(label.to_owned(), scan(Path::new(directory)));
    }
    let get = |label: &str| scans.get(label).unwrap_or_else(|| panic!("no run {label}"));
    let mut checked = 0;
    // A recording of a base from before the file identity records: the
    // requests are still read, and names are all there is.
    if let Some(legacy) = scans.get("legacy-async-io") {
        has(legacy, FileTab::Written, &["(io_uring)", "async.dat"]);
        has(
            legacy,
            FileTab::Read,
            &["By descriptor (io_uring)", "async.dat"],
        );
        checked += 1;
    }
    if !scans.contains_key("files") {
        assert!(checked > 0, "no runs to check");
        let missed = MISSED.lock().unwrap();
        assert!(missed.is_empty(), "{}", missed.join("\n\n"));
        return;
    }

    // io_uring file operations: each request is read as the call it stands for.
    let uring = get("files");
    has(
        uring,
        FileTab::Opened,
        &["openat2 (io_uring)", "/tmp/uring-files.a"],
    );
    has(
        uring,
        FileTab::Written,
        &["(io_uring)", "/tmp/uring-files.a"],
    );
    has(
        uring,
        FileTab::Read,
        &[
            "By descriptor (io_uring)",
            "/tmp/uring-files.a",
            "uring file contents",
        ],
    );
    has(
        uring,
        FileTab::Renamed,
        &[
            "renameat2 (io_uring)",
            "/tmp/uring-files.a → /tmp/uring-files.b",
        ],
    );
    has(
        uring,
        FileTab::Deleted,
        &["unlinkat (io_uring)", "/tmp/uring-files.b"],
    );
    has(
        uring,
        FileTab::Deleted,
        &["unlinkat (io_uring)", "/tmp/uring-files.c"],
    );
    has(
        uring,
        FileTab::Other,
        &["linkat (io_uring)", "/tmp/uring-files.c"],
    );
    // One file, followed through its rename and its hard link by inode.
    let changed = rows(uring, FileTab::Changed);
    let story: Vec<_> = changed
        .iter()
        .filter(|row| row.contains("/tmp/uring-files"))
        .collect();
    if story.len() != 1 {
        miss(format!("one file, not one per name: {changed:#?}"));
    }
    for row in &story {
        println!("ROW Changed (files): {row}");
    }
    for step in [
        "renamed → /tmp/uring-files.b",
        "hard-linked → /tmp/uring-files.c",
        "name removed (1 link remains)",
        "deleted",
    ] {
        if !story.iter().any(|row| row.contains(step)) {
            miss(format!("{step:?} missing from {story:#?}"));
        }
    }

    // OPENAT, vectors, registered buffers, a registered file and an open
    // straight into the registered table.
    let registered = get("regfiles");
    has(
        registered,
        FileTab::Opened,
        &["openat (io_uring)", "/tmp/uring-reg.a"],
    );
    has(
        registered,
        FileTab::Opened,
        &["openat (io_uring)", "/tmp/uring-reg.d"],
    );
    has(
        registered,
        FileTab::Written,
        &["pwritev (io_uring)", "/tmp/uring-reg.a"],
    );
    has(
        registered,
        FileTab::Read,
        &["By descriptor (io_uring)", "/tmp/uring-reg.a", "vector one"],
    );
    has(
        registered,
        FileTab::Read,
        &[
            "By descriptor (io_uring)",
            "/tmp/uring-reg.a",
            "fixed buffer data",
        ],
    );
    // WRITE_FIXED (17 bytes), and the WRITE on registered slot 0 (11 bytes),
    // which only the file identity ties to the file.
    for size in ["17 bytes written", "11 bytes written"] {
        has(
            registered,
            FileTab::Written,
            &[
                "pwrite64 (io_uring)",
                "/tmp/uring-reg.a",
                size,
                "By descriptor",
            ],
        );
    }
    // The open straight into slot 1 and the write through that slot.
    has(
        registered,
        FileTab::Written,
        &[
            "pwrite64 (io_uring)",
            "/tmp/uring-reg.d",
            "7 bytes written",
            "By descriptor",
        ],
    );
    for name in ["/tmp/uring-reg.a", "/tmp/uring-reg.d"] {
        has(registered, FileTab::Deleted, &["unlinkat (io_uring)", name]);
    }

    // The same story with plain system calls, and a name reused by a new file.
    let plain = get("syncfiles");
    let changed = rows(plain, FileTab::Changed);
    let first: Vec<_> = changed
        .iter()
        .filter(|row| row.contains("renamed → /tmp/sync-files.b"))
        .collect();
    if first.len() != 1 {
        miss(format!("the linked file: {changed:#?}"));
    }
    for row in &first {
        println!("ROW Changed (syncfiles, linked file): {row}");
    }
    for step in [
        "hard-linked → /tmp/sync-files.c",
        "name removed (1 link remains)",
        "deleted",
    ] {
        if !first.iter().any(|row| row.contains(step)) {
            miss(format!("{step:?} missing from {first:#?}"));
        }
    }
    // The write through the descriptor opened before the rename reaches the
    // same file, after the other name was removed. The hash the guest took
    // for that removal is its step, and on several vCPUs it can find the
    // file changing under the write.
    if !first.iter().any(|row| {
        row.split_once("name removed (1 link remains)")
            .is_some_and(|(_, after)| after.contains("→ written"))
    }) {
        miss(format!(
            "the write through the first descriptor: {first:#?}"
        ));
    }
    let second: Vec<_> = changed
        .iter()
        .filter(|row| row.contains("/tmp/sync-files.a") && !row.contains("renamed"))
        .collect();
    if second.len() != 1 {
        miss(format!("the reused name is a second file: {changed:#?}"));
    }
    for row in &second {
        println!("ROW Changed (syncfiles, reused name): {row}");
    }

    // AIO.
    let aio = get("aio");
    has(
        aio,
        FileTab::Written,
        &["pwrite64 (AIO)", "/tmp/uring-aio.dat"],
    );
    has(
        aio,
        FileTab::Read,
        &["By descriptor (AIO)", "/tmp/uring-aio.dat", "AAAA"],
    );
    has(
        aio,
        FileTab::Written,
        &["pwritev (AIO)", "/tmp/uring-aio.dat"],
    );
    has(
        aio,
        FileTab::Read,
        &[
            "By descriptor (AIO)",
            "/tmp/uring-aio.dat",
            "aio vector one",
        ],
    );

    // An SQPOLL ring: its kernel thread submitted the requests, which the
    // guest attributes to the ring's creator with no call of its own.
    let sqpoll = get("sqfiles");
    has(
        sqpoll,
        FileTab::Written,
        &["(io_uring)", "/tmp/uring-sq.a", "27 bytes written"],
    );
    has(
        sqpoll,
        FileTab::Deleted,
        &["unlinkat (io_uring)", "/tmp/uring-sq.b"],
    );

    // Sync, attribute, splice and directory requests, and a plain rmdir.
    let more = get("morefiles");
    has(
        more,
        FileTab::Attributes,
        &["fsetxattr (io_uring)", "/tmp/uring-more.a", "user.tag"],
    );
    has(
        more,
        FileTab::Attributes,
        &["setxattr (io_uring)", "/tmp/uring-more.a", "user.colour"],
    );
    has(
        more,
        FileTab::Other,
        &["splice (io_uring)", "/tmp/uring-more.a"],
    );
    has(
        more,
        FileTab::Deleted,
        &["unlinkat (io_uring)", "/tmp/uring-more.d", "directory"],
    );
    has(
        more,
        FileTab::Deleted,
        &["rmdir", "/tmp/uring-more.e", "directory"],
    );
    // The removed directories are known by identity, not only by name.
    for name in ["/tmp/uring-more.d", "/tmp/uring-more.e"] {
        let row = more
            .changed
            .iter()
            .find(|row| row.iter().any(|cell| cell.text == name));
        let identified = row.is_some_and(|row| {
            row[0]
                .values
                .iter()
                .any(|(field, value)| *field == "file.inode" && matches!(value, RowValue::Text(_)))
        });
        if identified {
            println!("ROW Changed (morefiles, by inode): {name}");
        } else {
            miss(format!(
                "{name} is not known by its inode: {:#?}",
                rows(more, FileTab::Changed)
            ));
        }
    }

    // A script shows the interpreter its #! line named.
    let script = get("script");
    has(
        script,
        FileTab::Executed,
        &["script run through /bin/sh", "/tmp/uring-script.sh"],
    );

    // The workload module: its linked write/read pairs on async.dat.
    let workload = get("async-io");
    has(workload, FileTab::Written, &["(io_uring)", "async.dat"]);
    has(
        workload,
        FileTab::Read,
        &["By descriptor (io_uring)", "async.dat"],
    );
    let missed = MISSED.lock().unwrap();
    assert!(missed.is_empty(), "{}", missed.join("\n\n"));
}
