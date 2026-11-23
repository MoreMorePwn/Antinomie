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
        rows.variants[0].findings.len(),
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
        // ANT-T0592: the sort of the whole Read table, and the chips.
        (
            "sort the whole Read table",
            change(&|r| r.sorts[5] = spec(0, false)),
        ),
        (
            "sort the whole Read table, descending, page 3",
            change(&|r| {
                r.sorts[5] = spec(0, true);
                r.offsets[5] = 200;
            }),
        ),
        (
            "chip: Hide libraries toggled",
            change(&|r| r.file_visibility.hide_libraries = !r.file_visibility.hide_libraries),
        ),
        (
            "chip: Hide standard I/O toggled",
            change(&|r| r.file_visibility.hide_standard_io = !r.file_visibility.hide_standard_io),
        ),
        (
            "chip: Failed attempts toggled",
            change(&|r| r.file_visibility.show_failed = !r.file_visibility.show_failed),
        ),
        (
            "chip: Show INFO",
            change(&|r| r.finding_view.show_info = !r.finding_view.show_info),
        ),
        ("back to no filter", request.clone()),
    ];
    let mut last = None;
    let chips = std::env::var_os("ANT_TIMING_CHIPS").is_some();
    for (name, next) in &requests {
        // A chip is a full scan (minutes) until ANT-T0592's chips are answered
        // from the rows: only with `ANT_TIMING_CHIPS=1`.
        if name.starts_with("chip:") && !chips {
            continue;
        }
        let at = Instant::now();
        let reads = READS.with(std::cell::Cell::get);
        let done = scan_archive_query(&dir, None, false, &cancel, next).unwrap();
        eprintln!(
            "TIMING {name}: {:.2} s ({} scans), read {} rows ({} omitted), findings {}, peak {} MiB",
            at.elapsed().as_secs_f64(),
            READS.with(std::cell::Cell::get) - reads,
            done.read.len(),
            done.read_omitted,
            done.findings.len(),
            peak_rss_mib()
        );
        // With `ANT_TIMING_VERIFY=<part of a name>`: the answers of the
        // requests whose name has it are checked against a scan that keeps
        // nothing (a full scan each).
        if std::env::var("ANT_TIMING_VERIFY").is_ok_and(|part| name.contains(part.as_str())) {
            let mut plain = next.clone();
            plain.keep_index = false;
            let full = scan_archive_uncached(&dir, None, false, &cancel, &plain).unwrap();
            let differences = requery::differences(&done, &full);
            eprintln!("TIMING {name}: differences from a full scan: {differences:?}");
            assert!(differences.is_empty(), "{name}: {differences:?}");
        }
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

/// ANT-T0592: every Files chip combination and Show INFO on and off, each
/// answered from the rows of one scan and compared with a full scan of the
/// same request (`ANT_TIMING_COMBOS=<n>` runs only the first n of the 16).
#[test]
#[ignore = "needs ANT_TIMING_RUN"]
fn every_chip_combination_is_what_a_full_scan_makes() {
    let Some(dir) = std::env::var_os("ANT_TIMING_RUN") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
    let mut request = request_of(&run);
    request.keep_index = true;
    let cancel = Arc::new(AtomicBool::new(false));
    let at = Instant::now();
    let first = scan_archive_query(&dir, None, false, &cancel, &request).unwrap();
    let rows = first.rows.clone().expect("the first scan kept its rows");
    eprintln!(
        "TIMING first scan {:.1} s, {} logged rows, {} MiB of row bytes, peak {} MiB",
        at.elapsed().as_secs_f64(),
        rows.row_count(),
        rows.tap.bytes() >> 20,
        peak_rss_mib()
    );
    let only: usize = std::env::var("ANT_TIMING_COMBOS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(16);
    for bits in 0..only as u32 {
        let mut chips = request.clone();
        chips.finding_view.show_info = bits & 1 != 0;
        chips.file_visibility.hide_standard_io = bits & 2 != 0;
        chips.file_visibility.hide_libraries = bits & 4 != 0;
        chips.file_visibility.show_failed = bits & 8 != 0;
        let (scans, at) = (READS.with(std::cell::Cell::get), Instant::now());
        let derived = scan_archive_query(&dir, None, false, &cancel, &chips).unwrap();
        eprintln!(
            "TIMING combination {bits} (info {}, stdio {}, libs {}, failed {}): {:.2} s from the rows ({} scans), reads {} opened {} changed {} void {}",
            chips.finding_view.show_info,
            chips.file_visibility.hide_standard_io,
            chips.file_visibility.hide_libraries,
            chips.file_visibility.show_failed,
            at.elapsed().as_secs_f64(),
            READS.with(std::cell::Cell::get) - scans,
            derived.counts.reads,
            derived.counts.opened,
            derived.counts.changed,
            derived.rows.is_none()
        );
        assert_eq!(READS.with(std::cell::Cell::get), scans, "no scan");
        let mut plain = chips.clone();
        plain.keep_index = false;
        let at = Instant::now();
        let full = scan_archive_uncached(&dir, None, false, &cancel, &plain).unwrap();
        let differences = requery::differences(&derived, &full);
        eprintln!(
            "TIMING combination {bits}: full scan {:.1} s, differences {differences:?}",
            at.elapsed().as_secs_f64()
        );
        assert!(
            differences.is_empty(),
            "combination {bits}: {differences:?}"
        );
    }
}

fn rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("VmRSS:").map(str::to_owned))
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

/// ANT-T0602, `ANT_TIMING_MODE=live`: the recording of `ANT_TIMING_RUN`
/// replayed in `ANT_TIMING_CHUNKS` (default 6) chunks into a growing copy in
/// `ANT_TIMING_LIVE_DIR` (a scratch folder, made and emptied of the run's
/// files), refreshed after each chunk as the window refreshes a live run,
/// and compared with a full scan of the same bytes. Every chunk must give no
/// difference. The chunks end anywhere: the index stops before a packet that
/// is cut off, as it does while the guest writes.
#[test]
#[ignore = "needs ANT_TIMING_RUN and ANT_TIMING_LIVE_DIR"]
fn a_live_refresh_is_what_a_full_scan_makes() {
    use std::io::{Read, Seek, SeekFrom, Write};
    let (Some(dir), Some(live)) = (
        std::env::var_os("ANT_TIMING_RUN"),
        std::env::var_os("ANT_TIMING_LIVE_DIR"),
    ) else {
        return;
    };
    let (dir, live) = (
        std::path::PathBuf::from(dir),
        std::path::PathBuf::from(live),
    );
    let chunks: u64 = std::env::var("ANT_TIMING_CHUNKS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(6);
    std::fs::create_dir_all(&live).unwrap();
    for name in [
        "run.json",
        "manifest.json",
        "artifacts.json",
        "inetsim.json",
    ] {
        let _ = std::fs::remove_file(live.join(name));
        if dir.join(name).is_file() {
            std::fs::copy(dir.join(name), live.join(name)).unwrap();
        }
    }
    let objects = live.join("objects");
    let _ = std::fs::remove_dir_all(&objects);
    std::fs::create_dir_all(&objects).unwrap();
    if let Ok(entries) = std::fs::read_dir(dir.join("objects")) {
        for entry in entries.flatten() {
            std::fs::hard_link(entry.path(), objects.join(entry.file_name()))
                .or_else(|_| {
                    std::fs::copy(entry.path(), objects.join(entry.file_name())).map(|_| ())
                })
                .unwrap();
        }
    }
    let raw = live.join("telemetry.raw");
    let _ = std::fs::remove_file(&raw);
    let mut source = std::fs::File::open(dir.join("telemetry.raw")).unwrap();
    let total = source.metadata().unwrap().len();
    let mut target = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&raw)
        .unwrap();
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("run.json")).unwrap()).unwrap();
    let mut request = request_of(&run);
    request.run_finished = false;
    request.recording_open = true;
    request.keep_index = true;
    let cancel = Arc::new(AtomicBool::new(false));
    let mut written = 0u64;
    for step in 1..=chunks {
        let end = total * step / chunks;
        source.seek(SeekFrom::Start(written)).unwrap();
        std::io::copy(&mut (&mut source).take(end - written), &mut target).unwrap();
        target.flush().unwrap();
        written = end;
        let resumes = live::RESUMES.with(std::cell::Cell::get);
        let at = Instant::now();
        let refreshed = scan_archive_query(&live, None, false, &cancel, &request).unwrap();
        let refresh_s = at.elapsed().as_secs_f64();
        let resumed = live::RESUMES.with(std::cell::Cell::get) > resumes;
        let rss = rss_mib();
        let mut plain = request.clone();
        plain.keep_index = false;
        let at = Instant::now();
        let full = scan_archive_uncached(&live, None, false, &cancel, &plain).unwrap();
        let full_s = at.elapsed().as_secs_f64();
        let differences = requery::differences(&refreshed, &full);
        eprintln!(
            "TIMING live chunk {step}/{chunks} ({} MiB, {} calls): refresh {refresh_s:.1} s ({}), full scan {full_s:.1} s, rss after refresh {rss} MiB, peak {} MiB, findings {}, differences {differences:?}",
            end >> 20,
            full.counts.calls,
            if resumed { "from the snapshot" } else { "whole" },
            peak_rss_mib(),
            full.counts.findings,
        );
        assert!(differences.is_empty(), "chunk {step}: {differences:?}");
        assert_eq!(refreshed.counts.calls, full.counts.calls);
        assert_eq!(refreshed.process.len(), full.process.len());
    }
}
