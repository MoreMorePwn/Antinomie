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
