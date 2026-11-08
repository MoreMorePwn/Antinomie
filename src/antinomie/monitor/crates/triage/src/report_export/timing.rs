// SPDX-License-Identifier: GPL-3.0-only
//! Times the export job on a copy of a real recording, by hand:
//! `ANT_TIMING_RUN=<run dir> XDG_CACHE_HOME=<empty dir> cargo test --release -p
//! antinomie-triage report_export::timing -- --ignored --nocapture`.
use super::*;
use antinomie_monitor_core::report::Format;
use std::time::Instant;

#[test]
#[ignore = "needs ANT_TIMING_RUN"]
fn time_the_export_job() {
    let Some(dir) = std::env::var_os("ANT_TIMING_RUN") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
    let text = |key: &str| run[key].as_str().unwrap_or_default().to_owned();
    let request = ScanRequest {
        root_cookie: run["root_task_cookie"].as_u64().unwrap_or(0),
        run_finished: true,
        started_ms: run["started_ms"].as_u64(),
        identity: Some((text("vm_id"), text("boot_id"), text("id"))),
        ..ScanRequest::default()
    };
    let mut choices = Choices::default();
    for format in Format::ALL {
        choices.set_format(format, true);
    }
    let job = Job {
        archive: dir.clone(),
        pcap: None,
        request,
        choices,
        run: report::RunInfo {
            vm_id: text("vm_id"),
            boot_id: text("boot_id"),
            run_id: text("id"),
            started_ms: run["started_ms"].as_u64(),
            finished: true,
            ..report::RunInfo::default()
        },
        sample: None,
        clock: None,
        data_dir: None,
        now_ms: crate::time_format::now_ms(),
        folder: dir.join("report-out"),
    };
    let began = Instant::now();
    let last = std::sync::Mutex::new(Instant::now());
    let status = |phase: &str| {
        let mut last = last.lock().unwrap();
        eprintln!(
            "TIMING [{:7.1} s] {phase} (previous phase took {:.1} s)",
            began.elapsed().as_secs_f64(),
            last.elapsed().as_secs_f64()
        );
        *last = Instant::now();
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let written = run_job(&job, &cancel, &status);
    eprintln!(
        "TIMING total {:.1} s, last phase {:.1} s: {:?}",
        began.elapsed().as_secs_f64(),
        last.lock().unwrap().elapsed().as_secs_f64(),
        written.map(|w| w.files.len())
    );
}

/// A recording of `ANT_SYNTH_CALLS` calls spread over `ANT_SYNTH_TASKS` tasks,
/// written by the fixtures' own writer, exported twice without and twice with
/// the kept index (`TIMING table` lines): `ANT_SYNTH_CALLS=300000
/// ANT_SYNTH_TASKS=500 XDG_CACHE_HOME=<empty dir> cargo test --release -p
/// antinomie-triage report_export::timing::time_a_synthetic -- --ignored
/// --nocapture`. `ANT_SYNTH_STAGES=1` also times the stages of the index.
#[test]
#[ignore = "needs ANT_SYNTH_CALLS"]
fn time_a_synthetic_recording() {
    let calls: u64 = match std::env::var("ANT_SYNTH_CALLS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(calls) => calls,
        None => return,
    };
    let tasks: u64 = std::env::var("ANT_SYNTH_TASKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let temp = PacketSpool::new().unwrap();
    let dir = temp.directory.clone();
    let mut raw =
        std::io::BufWriter::new(std::fs::File::create(dir.join("telemetry.raw")).unwrap());
    crate::tests::write_rwx_tasks(&mut raw, 0..calls, |call| {
        if call % 7 == 0 {
            55
        } else {
            1000 + (call % tasks) as u32
        }
    });
    std::io::Write::flush(&mut raw).unwrap();
    drop(raw);
    let size = std::fs::metadata(dir.join("telemetry.raw")).unwrap().len();
    eprintln!("TIMING synthetic recording: {calls} calls, {size} bytes");
    let mut job = fixtures::job(&temp, &dir.join("none.pcap"), Choices::default());
    job.pcap = None;
    job.choices = fixtures::all_formats();
    job.choices.bundle = false;
    let cancel = Arc::new(AtomicBool::new(false));
    if std::env::var_os("ANT_SYNTH_STAGES").is_some() {
        // The stages of the index, one by one (the second pass is the files').
        let request = job.request.clone();
        let mut at = Instant::now();
        let mut lap = |name: &str| {
            eprintln!("TIMING stage {name}: {:.1} s", at.elapsed().as_secs_f64());
            at = Instant::now();
        };
        let mut scan =
            crate::archive_scan::stages::open_scan(&dir, None, false, &cancel, &request).unwrap();
        lap("open_scan (index + first pass)");
        let mut files = scan.read_files(&cancel, &request).unwrap();
        lap("read_files (second pass)");
        let network = scan
            .read_network(&mut files.pending, None, false, &cancel, &request)
            .unwrap();
        lap("read_network");
        let _ = scan
            .finish(files, network, None, false, &cancel, &request)
            .unwrap();
        lap("finish");
    }
    // Two exports of the same recording, as the app did them (each reads the
    // recording whole: no kept index) and as it does them now.
    for (name, keep) in [
        ("before: no kept index", false),
        ("after: kept index", true),
    ] {
        scan_cache::forget();
        let mut job = job.clone();
        job.request.keep_index = keep;
        for number in 1..=2 {
            let began = Instant::now();
            let said = std::sync::Mutex::new(String::new());
            let written = run_job(&job, &cancel, &|text| {
                let mut said = said.lock().unwrap();
                if said.is_empty() {
                    *said = text.to_owned();
                }
            });
            eprintln!(
                "TIMING table | {name} | export {number} | {:.2} s | {} | {:?}",
                began.elapsed().as_secs_f64(),
                said.lock().unwrap(),
                written.map(|w| w.files.len())
            );
        }
    }
}
