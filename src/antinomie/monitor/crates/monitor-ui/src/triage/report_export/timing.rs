// SPDX-License-Identifier: GPL-3.0-only
//! Times the export job on a copy of a real recording, by hand:
//! `ANT_TIMING_RUN=<run dir> XDG_CACHE_HOME=<empty dir> cargo test --release -p
//! antinomie-monitor-ui report_export::timing -- --ignored --nocapture`.
use super::*;
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
