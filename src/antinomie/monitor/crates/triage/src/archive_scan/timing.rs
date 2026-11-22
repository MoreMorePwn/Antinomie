// SPDX-License-Identifier: GPL-3.0-only
//! A timing harness for the whole-run index and the report built from it,
//! run by hand on a copy of a real recording:
//! `ANT_TIMING_RUN=<run dir> XDG_CACHE_HOME=<empty dir> cargo test --release -p
//! antinomie-triage archive_scan::timing -- --ignored --nocapture`.
//! The directory needs `run.json` and `telemetry.raw` (a link is fine). Nothing
//! in it is modified except for the files a scan writes beside the recording.
use super::*;
use std::time::Instant;

fn request_of(run: &serde_json::Value) -> ScanRequest {
    let text = |key: &str| run[key].as_str().unwrap_or_default().to_owned();
    ScanRequest {
        root_cookie: run["root_task_cookie"].as_u64().unwrap_or(0),
        run_finished: true,
        started_ms: run["started_ms"].as_u64(),
        identity: Some((text("vm_id"), text("boot_id"), text("id"))),
        ..ScanRequest::default()
    }
}

#[test]
#[ignore = "needs ANT_TIMING_RUN"]
fn time_the_stages_of_a_whole_run_index() {
    let Some(dir) = std::env::var_os("ANT_TIMING_RUN") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
    let request = request_of(&run);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut at = Instant::now();
    let mut lap = |name: &str| {
        eprintln!("TIMING {name}: {:.1} s", at.elapsed().as_secs_f64());
        at = Instant::now();
    };
    let recording = antinomie_monitor_core::recording::Recording {
        directory: dir.clone(),
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let calls = recording
        .invocation_count_cancellable(None, &cancel)
        .unwrap();
    lap(&format!("1 index the telemetry ({calls} calls)"));
    let mut scan = stages::open_scan(&dir, None, false, &cancel, &request).unwrap();
    lap("2 open_scan (first pass, rules)");
    let mut files = scan.read_files(&cancel, &request).unwrap();
    lap("3 read_files (second pass)");
    let network = scan
        .read_network(&mut files.pending, None, false, &cancel, &request)
        .unwrap();
    lap("4 read_network");
    let _scan = scan
        .finish(files, network, None, false, &cancel, &request)
        .unwrap();
    lap("5 finish (findings, IOC, graph)");
    // The same again, as the export does it: the index exists, the journal is cached.
    let again = scan_archive_query(&dir, None, false, &cancel, &request).unwrap();
    lap("6 a second whole scan, as the export's");
    drop(again);
}

/// CPU seconds this process has used (user, system).
fn cpu_seconds() -> (f64, f64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = stat.rsplit(')').next().unwrap_or_default();
    let fields: Vec<&str> = after.split_whitespace().collect();
    let tick = |at: usize| {
        fields
            .get(at)
            .and_then(|f| f.parse::<f64>().ok())
            .unwrap_or(0.0)
            / 100.0
    };
    (tick(11), tick(12))
}

fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("VmHWM:").map(str::to_owned))
        })
        .and_then(|rest| {
            rest.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
        .map_or(0, |kib| kib / 1024)
}

/// `ANT_TIMING_MODE=plain`: a first scan that keeps nothing (the cost of the
/// scan before ANT-T0590); `tapped`: a first scan that keeps its rows, then
/// filter, sort and page changes answered from them; `verify` adds a full
/// scan of one such request to compare with. Each mode is its own process, so
/// the peak memory is its own.
#[test]
#[ignore = "needs ANT_TIMING_RUN"]
fn time_a_filter_change_on_a_kept_index() {
    let Some(dir) = std::env::var_os("ANT_TIMING_RUN") else {
        return;
    };
    let mode = std::env::var("ANT_TIMING_MODE").unwrap_or_else(|_| "tapped".into());
    let dir = std::path::PathBuf::from(dir);
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
    let mut request = request_of(&run);
    request.keep_index = mode != "plain";
    let cancel = Arc::new(AtomicBool::new(false));
    let at = Instant::now();
    let first = scan_archive_query(&dir, None, false, &cancel, &request).unwrap();
    eprintln!(
        "TIMING {mode}: first scan {:.1} s, cpu user/sys {:?} s, peak {} MiB",
        at.elapsed().as_secs_f64(),
        cpu_seconds(),
        peak_rss_mib()
    );
    let Some(rows) = first.rows.clone() else {
        eprintln!("TIMING no rows kept ({mode})");
        return;
    };
    eprintln!(
        "TIMING kept: {} logged rows, {} MiB of row bytes on disk, {} findings, {} changed files, {} read rows shown",
        rows.row_count(),
        rows.tap.bytes() >> 20,
        rows.findings.len(),
        rows.changes.len(),
        first.read.len()
    );
    let change = |edit: &dyn Fn(&mut ScanRequest)| {
        let mut next = request.clone();
        edit(&mut next);
        next
    };
    let spec = |column, descending| Some(sorting::Spec { column, descending });
    let requests = [
        (
            "filter Read by path",
            change(&|r| r.filters[5] = "file.path contains \"/etc\"".into()),
        ),
        (
            "filter and sort Read, page 2",
            change(&|r| {
                r.filters[5] = "file.path contains \"/etc\"".into();
                r.sorts[5] = spec(0, true);
                r.offsets[5] = 500;
            }),
        ),
        (
            "filter Suspicious, sort",
            change(&|r| {
                r.filters[0] = "finding.tier == \"high\"".into();
                r.sorts[0] = spec(1, true);
            }),
        ),
        (
            "filter Opened",
            change(&|r| r.filters[1] = "file.path contains \"/tmp\"".into()),
        ),
        (
            "filter Changed",
            change(&|r| r.filters[2] = "file.path contains \"/tmp\"".into()),
        ),
        ("back to no filter", request.clone()),
    ];
    let mut last = None;
    for (name, next) in &requests {
        let at = Instant::now();
        let reads = READS.with(std::cell::Cell::get);
        let done = scan_archive_query(&dir, None, false, &cancel, next).unwrap();
        eprintln!(
            "TIMING {name}: {:.2} s ({} scans), read {} rows, findings {}, peak {} MiB",
            at.elapsed().as_secs_f64(),
            READS.with(std::cell::Cell::get) - reads,
            done.read.len(),
            done.findings.len(),
            peak_rss_mib()
        );
        last = Some((next.clone(), done));
    }
    if mode == "verify" {
        let next = change(&|r| {
            r.filters[5] = "file.path contains \"/etc\"".into();
            r.sorts[5] = spec(0, true);
            r.filters[0] = "finding.tier == \"high\"".into();
            r.sorts[0] = spec(1, true);
            r.offsets[5] = 100;
        });
        let derived = scan_archive_query(&dir, None, false, &cancel, &next).unwrap();
        let mut plain = next.clone();
        plain.keep_index = false;
        let at = Instant::now();
        let full = scan_archive_uncached(&dir, None, false, &cancel, &plain).unwrap();
        eprintln!(
            "TIMING verify: full scan {:.1} s",
            at.elapsed().as_secs_f64()
        );
        let differences = requery::differences(&derived, &full);
        eprintln!("TIMING verify differences: {differences:?}");
        assert!(differences.is_empty());
    }
    drop(last);
}
