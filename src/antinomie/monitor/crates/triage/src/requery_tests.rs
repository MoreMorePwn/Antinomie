// SPDX-License-Identifier: GPL-3.0-only
//! A filter, sort or page answered from the kept rows is what a scan makes
//! (ANT-T0590), and it does not read the recording.
use super::*;
use crate::archive_scan::READS;
use crate::tests::{http_pcap, write_rwx_calls, write_rwx_tasks};

fn reads() -> u64 {
    READS.with(std::cell::Cell::get)
}

/// A recording of 300 tasks that each map memory read-write-execute (one
/// finding row per task) and an HTTP capture when `tshark` is there.
fn run(tasks: u64) -> (PacketSpool, Option<std::path::PathBuf>) {
    let temp = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
    write_rwx_tasks(&mut raw, 0..tasks, |call| 1000 + (call % 120) as u32);
    raw.sync_all().unwrap();
    let pcap = report_export::fixtures::have_tshark().then(|| {
        let pcap = temp.directory.join("run.pcap");
        std::fs::write(&pcap, http_pcap()).unwrap();
        pcap
    });
    (temp, pcap)
}

fn request() -> ScanRequest {
    ScanRequest {
        root_cookie: 55,
        run_finished: true,
        keep_index: true,
        page_rows: 100,
        ..ScanRequest::default()
    }
}

fn spec(column: usize, descending: bool) -> Option<sorting::Spec> {
    Some(sorting::Spec { column, descending })
}

#[test]
fn the_kept_rows_answer_every_filter_sort_and_page_as_a_scan_does() {
    let (temp, pcap) = run(300);
    let cancel = Arc::new(AtomicBool::new(false));
    let first =
        scan_archive_query(&temp.directory, pcap.as_deref(), false, &cancel, &request()).unwrap();
    assert!(
        first.rows.is_some(),
        "a complete scan that keeps its index has rows"
    );
    let mut requests = Vec::new();
    let mut with = |change: &dyn Fn(&mut ScanRequest)| {
        let mut next = request();
        change(&mut next);
        requests.push(next);
    };
    with(&|r| r.filters[0] = "finding.rule == \"memory.rwx\"".into());
    with(&|r| r.filters[0] = "finding.rule == \"nothing-matches-this\"".into());
    with(&|r| r.filters[0] = "finding.rule == \"memory.rwx\" && finding.success == true".into());
    with(&|r| r.sorts[0] = spec(1, true));
    with(&|r| r.sorts[0] = spec(5, false));
    with(&|r| r.sorts[0] = spec(7, true));
    with(&|r| r.offsets[0] = 100);
    with(&|r| {
        r.offsets[0] = 100;
        r.sorts[0] = spec(3, false);
        r.filters[0] = "finding.rule == \"memory.rwx\"".into();
    });
    with(&|r| r.finding_view.tiers = 1 << rules::Tier::High.index());
    with(&|r| r.finding_view.show_hidden = true);
    with(&|r| r.finding_view.tiers = 1 << rules::Tier::Low.index());
    with(&|r| r.filters[2] = "file.path contains \"/tmp\"".into());
    with(&|r| r.filters[5] = "file.path contains \"/etc\"".into());
    with(&|r| r.sorts[5] = spec(0, true));
    with(&|r| r.filters[3] = "http.method == \"GET\"".into());
    with(&|r| r.filters[3] = "http.method == \"POST\"".into());
    with(&|r| r.sorts[3] = spec(0, true));
    with(&|r| r.offsets[3] = 1);
    with(&|r| r.filters[ENDPOINT_SLOT] = "network.port == 80".into());
    with(&|r| r.sorts[DOMAIN_SLOT] = spec(0, true));
    with(&|r| r.sorts[TLS_SLOT] = spec(1, false));
    with(&|r| {
        r.filters[8] = "file.path contains \"a\"".into();
        r.sorts[1] = spec(0, false);
    });
    for (at, next) in requests.iter().enumerate() {
        let before = reads();
        let derived =
            scan_archive_query(&temp.directory, pcap.as_deref(), false, &cancel, next).unwrap();
        assert_eq!(reads(), before, "request {at} read the recording");
        let mut plain = next.clone();
        plain.keep_index = false;
        let full = scan_archive_uncached(&temp.directory, pcap.as_deref(), false, &cancel, &plain)
            .unwrap();
        assert_eq!(reads(), before + 1);
        let differences = requery::differences(&derived, &full);
        assert!(differences.is_empty(), "request {at}: {differences:?}");
        // The rest of the index is the first scan's own.
        assert_eq!(derived.counts.findings, full.counts.findings);
        assert_eq!(derived.counts.calls, full.counts.calls);
        assert_eq!(derived.process.len(), full.process.len());
        assert_eq!(derived.stamp, full.stamp);
    }
    assert!(first.findings.len() > 1 && first.findings.len() < 300);
}

#[test]
fn a_whole_run_report_after_a_filtered_screen_is_answered_from_its_rows() {
    let (temp, pcap) = run(150);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut screen = request();
    screen.filters[0] = "finding.rule == \"nothing-matches-this\"".into();
    screen.offsets[0] = 50;
    let on_screen =
        scan_archive_query(&temp.directory, pcap.as_deref(), false, &cancel, &screen).unwrap();
    assert!(!on_screen.whole_run);
    let before = reads();
    let whole = whole_run_request(&screen);
    let report = scan_cache::recall(&temp.directory, pcap.as_deref(), false, &whole)
        .expect("the rows hold the whole run");
    assert_eq!(reads(), before);
    assert!(report.whole_run);
    let mut plain = whole.clone();
    plain.keep_index = false;
    let full =
        scan_archive_uncached(&temp.directory, pcap.as_deref(), false, &cancel, &plain).unwrap();
    assert!(requery::differences(&report, &full).is_empty());
}

#[test]
fn another_toggle_or_a_changed_recording_scans_again() {
    let (temp, _) = run(60);
    let cancel = Arc::new(AtomicBool::new(false));
    scan_archive_query(&temp.directory, None, false, &cancel, &request()).unwrap();
    let before = reads();
    let mut info = request();
    info.finding_view.show_info = true;
    scan_archive_query(&temp.directory, None, false, &cancel, &info).unwrap();
    assert_eq!(reads(), before + 1, "Show INFO changes the rows");
    let mut visibility = request();
    visibility.file_visibility.show_failed = false;
    scan_archive_query(&temp.directory, None, false, &cancel, &visibility).unwrap();
    assert_eq!(reads(), before + 2, "a Files chip changes the counts");
    // The recording grew: whatever the request says, it is read again.
    let mut raw = std::fs::OpenOptions::new()
        .append(true)
        .open(temp.directory.join("telemetry.raw"))
        .unwrap();
    write_rwx_calls(&mut raw, 500..501);
    drop(raw);
    let mut filtered = request();
    filtered.filters[0] = "finding.rule == \"memory.rwx\"".into();
    scan_archive_query(&temp.directory, None, false, &cancel, &filtered).unwrap();
    assert_eq!(reads(), before + 3);
    // A timer refresh of an unchanged recording is still told so.
    let kept = scan_archive_query(&temp.directory, None, false, &cancel, &filtered).unwrap();
    let mut timer = filtered.clone();
    timer.unchanged_since = Some(kept.stamp.clone());
    timer.filters[0].clear();
    let answer = scan_archive_query(&temp.directory, None, false, &cancel, &timer);
    assert_eq!(answer.err().as_deref(), Some(UNCHANGED));
}

#[test]
fn a_scan_that_does_not_keep_its_index_or_ran_to_a_budget_has_no_rows() {
    let (temp, _) = run(30);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut plain = request();
    plain.keep_index = false;
    let scan = scan_archive_query(&temp.directory, None, false, &cancel, &plain).unwrap();
    assert!(scan.rows.is_none());
    let mut stopped = request();
    stopped.stop = Some(Arc::new(scan_progress::ScanStop::new(
        u64::MAX,
        std::time::Duration::from_secs(3600),
    )));
    let scan = scan_archive_query(&temp.directory, None, false, &cancel, &stopped).unwrap();
    assert!(scan.rows.is_none());
}

#[test]
fn an_index_past_its_cap_is_void_and_the_scan_goes_on_unchanged() {
    let (temp, _) = run(60);
    let cancel = Arc::new(AtomicBool::new(false));
    let tap = row_index::Tap::with_limit(1).unwrap();
    let mut capped = request();
    capped.tap = Some(tap.clone());
    let row = vec![cell("x", tone::text(), false)];
    tap.push(5, &row);
    tap.push(5, &row);
    assert!(tap.failed(), "past its cap");
    let scan = scan_archive_uncached(&temp.directory, None, false, &cancel, &capped).unwrap();
    assert!(scan.rows.is_none(), "a void index is not kept");
    assert!(!scan.findings.is_empty(), "the scan itself is not affected");
}

fn read_row(path: &str, fd: i128, ns: i128) -> Vec<Cell> {
    let mut row = vec![
        cell(path, tone::text(), true),
        cell(fd.to_string(), tone::text(), false),
    ];
    row[0].values = vec![
        ("file.path", RowValue::Text(path.to_owned())),
        ("file.fd", RowValue::Number(fd)),
        ("event.time_ns", RowValue::Number(ns)),
    ];
    row
}

#[test]
fn a_table_log_replays_its_rows_in_scan_order_through_the_scans_own_pages() {
    let tap = row_index::Tap::new().unwrap();
    let rows: Vec<_> = (0..350)
        .map(|n| {
            let dir = ["/etc", "/tmp", "/var/log", "/proc"][n as usize % 4];
            read_row(&format!("{dir}/f{}", (n * 7) % 31), n % 9, n * 10)
        })
        .collect();
    for row in &rows {
        tap.push(5, row);
    }
    tap.keep_changes(Vec::new());
    let index = tap
        .seal(&ScanRequest::default(), Vec::new(), Vec::new(), Vec::new())
        .unwrap();
    assert_eq!(index.row_count(), 350);
    let cancel = Arc::new(AtomicBool::new(false));
    for (filter, sort, offset) in [
        ("", None, 0),
        ("file.path contains \"/etc\"", None, 0),
        ("file.path contains \"/tmp\"", spec(0, true), 100),
        ("file.fd == 3", spec(1, false), 0),
        ("file.fd < 4", spec(1, true), 20),
        ("file.path contains \"nothing\"", spec(0, false), 0),
    ] {
        let mut request = ScanRequest {
            page_rows: 100,
            ..ScanRequest::default()
        };
        request.filters[5] = filter.into();
        request.sorts[5] = sort;
        request.offsets[5] = offset;
        let query = query::compile_table(&request.filters[5], FILE_FIELDS);
        // The scan's way: the filter then the page, as the rows arrive.
        let mut streamed = sorting::Page::<Vec<Cell>>::new(&request, 5, &cancel);
        for row in &rows {
            if query.keep_table(&row[0].values) {
                streamed.push(row.clone()).unwrap();
            }
        }
        let (want, want_omitted, want_total) = streamed.finish().unwrap();
        // The kept way.
        let mut kept = sorting::Page::<Vec<Cell>>::new(&request, 5, &cancel);
        index
            .each(5, &cancel, |row| {
                if query.keep_table(&row[0].values) {
                    kept.push(row)?;
                }
                Ok(())
            })
            .unwrap();
        let (got, got_omitted, got_total) = kept.finish().unwrap();
        let text = |rows: &[Vec<Cell>]| -> Vec<String> {
            rows.iter()
                .map(|row| format!("{}|{:?}", row[0].text, row[0].values))
                .collect()
        };
        assert_eq!(text(&got), text(&want), "{filter} {sort:?} {offset}");
        assert_eq!((got_omitted, got_total), (want_omitted, want_total));
    }
}

#[test]
fn the_logs_of_a_process_that_is_gone_are_swept_and_a_live_one_is_left() {
    let folder = PacketSpool::new().unwrap();
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let make = |pid: u32| {
        let dir = folder.directory.join(format!("antinomie-triage-{pid}-7"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rows.sqlite"), b"x").unwrap();
        dir
    };
    let (stale, own, other) = (
        make(dead),
        make(std::process::id()),
        folder.directory.join("antinomie-triage-notapid-1"),
    );
    std::fs::create_dir_all(&other).unwrap();
    row_index::sweep_dead_spools(&folder.directory);
    assert!(!stale.exists(), "a gone process's folder is removed");
    assert!(own.exists(), "this process's folder stays");
    assert!(other.exists(), "a name that is not ours stays");
}
