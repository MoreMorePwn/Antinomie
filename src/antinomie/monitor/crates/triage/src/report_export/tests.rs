// SPDX-License-Identifier: GPL-3.0-only
//! The report built and written without a window.
use super::fixtures::{all_formats, fixture, have_tshark, job, read};
use super::*;
use crate::tests::{call, captured, http_pcap, path_call};
use antinomie_monitor_core::report::bundle::{self, BundleInput};
use antinomie_monitor_core::report::{Format, Part};
use std::collections::BTreeSet;

#[test]
fn a_whole_run_exports_every_format_whatever_the_screen_filters_say() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let mut job = job(&temp, &pcap, all_formats());
    // The screen's filters and page must not shape the report.
    let mut screen = job.request.clone();
    screen.filters[0] = "finding.rule == \"nothing-matches-this\"".into();
    screen.offsets[0] = 1000;
    screen.file_visibility.hide_libraries = false;
    job.request = whole_run_request(&screen);
    let written = run_job(&job, &Arc::new(AtomicBool::new(false)), &|_| {}).unwrap();
    let path = |label: &str| {
        written
            .files
            .iter()
            .find(|(l, _)| l == label)
            .unwrap_or_else(|| panic!("{label} written"))
            .1
            .clone()
    };
    let json: serde_json::Value = serde_json::from_str(&read(&path("JSON"))).unwrap();
    assert_eq!(json["schema"], report::SCHEMA);
    assert!(
        !json["findings"]["rows"].as_array().unwrap().is_empty(),
        "findings of the whole run"
    );
    assert!(!json["processes"]["rows"].as_array().unwrap().is_empty());
    let urls = json["network"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "URLs")
        .unwrap();
    assert_eq!(urls["table"]["rows"].as_array().unwrap().len(), 1);
    assert!(json["indicators"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["kind"] == "url"));
    assert!(json["summary"]["counts"]["findings"].as_u64().unwrap() >= 1);
    assert_eq!(json["sample"]["sha256"], "ab".repeat(32));
    assert_eq!(json["detections"][0]["author"], "Jane Rule");
    assert_eq!(json["detections"][0]["license"], "DRL 1.1");
    assert_eq!(
        json["detections"][0]["reference"],
        "https://example.org/rule"
    );
    // The recorded run's report links its entries, and every link resolves.
    let parsed: report::Report = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(report::refs::problems(&parsed), Vec::<String>::new());
    assert_eq!(json["schema_version"], 2);
    let process_ids: Vec<&str> = json["processes"]["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["id"].as_str())
        .collect();
    assert!(
        process_ids.iter().all(|id| id.starts_with("proc-")) && !process_ids.is_empty(),
        "{process_ids:?}"
    );
    assert!(json["findings"]["data"][0]["process_ref"]
        .as_str()
        .is_some_and(|id| id.starts_with("proc-")));
    let key = &json["summary"]["key_findings"];
    assert!(key.as_array().is_some_and(|k| !k.is_empty()), "{key}");
    assert!(key[0]["finding_ref"]
        .as_str()
        .is_some_and(|id| id.starts_with("finding-")));
    let html = read(&path("HTML"));
    let anchors: Vec<&str> = html
        .split(" id=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    assert!(
        anchors.iter().all(|id| seen.insert(*id)),
        "anchors are unique"
    );
    for link in html
        .split("href=\"#")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
    {
        assert!(anchors.contains(&link), "#{link} resolves");
    }
    assert!(html.contains("<caption>Key findings</caption>"));
    let markdown = read(&path("Markdown"));
    let (ids, links) = report::markdown::anchors_and_links(&markdown);
    for link in links {
        assert!(ids.contains(&link), "#{link} resolves in the Markdown");
    }
    assert!(html.contains("Jane Rule") && html.contains("DRL 1.1"));
    assert!(html.contains("<h2>Processes</h2>") && html.contains("example[.]com"));
    let pdf = std::fs::read(path("PDF")).unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    let misp: serde_json::Value = serde_json::from_str(&read(&path("MISP"))).unwrap();
    assert!(misp["Event"]["Attribute"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["type"] == "url"));
    assert!(read(&path("MISP")).contains("Jane Rule"));
    assert!(read(&path("STIX 2.1")).contains("Jane Rule"));
    let stix: serde_json::Value = serde_json::from_str(&read(&path("STIX 2.1"))).unwrap();
    assert_eq!(stix["type"], "bundle");

    // The bundle holds the capture, and every hash in it checks.
    let bundle = written.bundle.as_ref().expect("bundle");
    let listed = bundle::verify(&path("Evidence bundle")).unwrap();
    let capture = listed
        .iter()
        .find(|f| f.path == "capture/fixture.pcap")
        .unwrap();
    assert_eq!(
        capture.sha256,
        antinomie_monitor_core::storage::sha256_hex(&http_pcap())
    );
    assert!(
        bundle
            .skipped
            .iter()
            .any(|(what, _)| what == "custody export"),
        "no library: said so"
    );

    if let Ok(out) = std::env::var("ANTINOMIE_REPORT_OUT") {
        std::fs::create_dir_all(&out).unwrap();
        for (_, from) in &written.files {
            std::fs::copy(from, Path::new(&out).join(from.file_name().unwrap())).unwrap();
        }
    }
}

#[test]
fn unchecked_sections_and_formats_are_left_out_and_defanging_touches_only_html_and_pdf() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let mut choices = Choices {
        formats: vec![Format::Html, Format::Json],
        defang: true,
        ..Choices::default()
    };
    choices.set(Part::Network, false);
    choices.set(Part::Files, false);
    // A final manifest that counted lost telemetry: the report says so first.
    std::fs::write(
        temp.directory.join("manifest.json"),
        r#"{"telemetry_loss":{"received_packets":95,"lost_packets":5}}"#,
    )
    .unwrap();
    let written = run_job(
        &job(&temp, &pcap, choices),
        &Arc::new(AtomicBool::new(false)),
        &|_| {},
    )
    .unwrap();
    assert_eq!(written.files.len(), 2);
    assert!(written.bundle.is_none());
    let json = read(&written.files.iter().find(|(l, _)| l == "JSON").unwrap().1);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value["network"].is_null() && value["files"].is_null());
    assert!(value["processes"].is_object());
    assert!(
        value["notes"][0]
            .as_str()
            .unwrap()
            .starts_with("Telemetry lost: 5.0 % of this run's telemetry never reached the host"),
        "{}",
        value["notes"]
    );
    let html = read(&written.files.iter().find(|(l, _)| l == "HTML").unwrap().1);
    assert!(html.contains("Telemetry lost: 5.0 %"));
    assert!(!html.contains(">Network<") && !html.contains(">Files<"));
    // The fixture's indicators: raw in the JSON, defanged in the HTML.
    assert!(json.contains("example.com"));
    assert!(html.contains("example[.]com") && !html.contains("example.com"));
    if let Ok(keep) = std::env::var("ANTINOMIE_REPORT_OUT") {
        let keep = Path::new(&keep).join("limited-defanged");
        std::fs::create_dir_all(&keep).unwrap();
        for (_, from) in &written.files {
            std::fs::copy(from, keep.join(from.file_name().unwrap())).unwrap();
        }
    }
}

fn operation(id: u64, nr: u64, name: &str, ret: i64, args: [u64; 6]) -> InvocationSummary {
    let mut row = call(1, nr, name, ret);
    row.call_id = id;
    row.entry.as_mut().unwrap().call_id = id;
    row.entry.as_mut().unwrap().args = Some(args);
    row.exit.as_mut().unwrap().call_id = id;
    row
}

fn stored_write(
    id: u64,
    fd: u64,
    offset: u64,
    bytes: &[u8],
    dir: &Path,
    name: &str,
) -> InvocationSummary {
    std::fs::write(dir.join("objects").join(name), bytes).unwrap();
    let size = bytes.len() as u64;
    let mut row = operation(id, 18, "pwrite64", size as i64, [fd, 0, size, offset, 0, 0]);
    let mut field = captured("arg1.data", "", b"");
    field.raw_path = Some(PathBuf::from(format!("objects/{name}")));
    field.logical_len = Some(size);
    field.ranges = vec![(0, size)];
    row.entry.as_mut().unwrap().fields.push(field);
    row
}

#[test]
fn dropped_files_are_hashed_listed_and_written_into_the_password_zip() {
    if !have_tshark() {
        return;
    }
    let (temp, pcap) = fixture();
    let dir = temp.directory.clone();
    std::fs::create_dir_all(dir.join("objects")).unwrap();
    let open = |id: u64, path: &str, fd: i64| {
        let mut row = path_call(1, 2, "open", fd, path);
        row.call_id = id;
        row.entry.as_mut().unwrap().call_id = id;
        row.exit.as_mut().unwrap().call_id = id;
        row.entry.as_mut().unwrap().args = Some([0, 0x41, 0, 0, 0, 0]);
        row
    };
    let calls = [
        open(2, "/tmp/dropped.sh", 4),
        stored_write(3, 4, 0, b"#!/bin/sh\n", &dir, "a.raw"),
        stored_write(4, 4, 10, b"id\n", &dir, "b.raw"),
        // Over the per-file cap: only the first 8 bytes are kept.
        open(5, "/tmp/big.bin", 5),
        stored_write(6, 5, 0, b"12345678", &dir, "c.raw"),
        stored_write(7, 5, 8, b"abcdefgh", &dir, "d.raw"),
    ];
    let mut index = files::FileIndex::default();
    index.set_write_limits(antinomie_monitor_core::file_writes::Limits {
        per_file: 13,
        per_run: 1 << 20,
    });
    let mut state = FdState::default();
    let cookies = task_cookies(&calls);
    for row in &calls {
        let event = trace::representative(row).unwrap();
        remember_cwd(&mut state, row, event);
        remember_open(&mut state, row, event);
        apply_dup(&mut state, row, event);
        forget_closed(&mut state, row, event);
        inherit_open_fds(&mut state, row, event, &cookies);
        index.observe(&state, row, event, Some(&dir));
    }
    let activity = index.finish_all().1;
    let scan_job = job(&temp, &pcap, all_formats());
    let mut scan = scan_archive_query(
        &dir,
        Some(&pcap),
        false,
        &Arc::new(AtomicBool::new(false)),
        &scan_job.request,
    )
    .unwrap();
    scan.file_activity = Arc::new(activity);
    let built = build::build(&scan, &scan_job).unwrap();
    let records = built.report.file_activity.as_ref().unwrap();
    let dropped = records
        .iter()
        .find(|r| r.path == "/tmp/dropped.sh")
        .unwrap();
    let want = antinomie_monitor_core::storage::sha256_hex(b"#!/bin/sh\nid\n");
    assert_eq!(dropped.reconstruction, "complete");
    assert_eq!(dropped.final_size, Some(13));
    assert_eq!(
        dropped.bundle_entry,
        format!("dropped-files.zip/{want}.bin")
    );
    let big = records.iter().find(|r| r.path == "/tmp/big.bin").unwrap();
    assert_eq!(big.reconstruction, "incomplete");
    assert!(big.bytes_not_captured > 0 && big.bundle_entry.is_empty());
    let input: BundleInput = built.bundle.unwrap();
    assert_eq!(input.dropped.len(), 1);
    assert!(input
        .skipped
        .iter()
        .any(|(path, why)| path == "/tmp/big.bin" && why.contains("no recorded value")));

    let out = dir.join("b.zip");
    let bundled = bundle::write(&out, &dir.join("i.tmp"), input).unwrap();
    assert_eq!(bundled.dropped[0].0, "/tmp/dropped.sh");
    bundle::verify(&out).unwrap();
    let got = bundle::open_dropped(&out, &format!("dropped-files.zip/{want}.bin")).unwrap();
    if let Ok(keep) = std::env::var("ANTINOMIE_REPORT_OUT") {
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::copy(&out, Path::new(&keep).join("dropped-bundle.zip")).unwrap();
    }
    assert_eq!(got, b"#!/bin/sh\nid\n");
}

/// One frame of the dialog at `time`, with `events`.

#[test]
fn a_run_without_a_loss_count_gets_no_loss_line() {
    let temp = PacketSpool::new().unwrap();
    assert_eq!(super::build::telemetry_loss_note(&temp.directory), None);
    std::fs::write(temp.directory.join("manifest.json"), r#"{"packets":3}"#).unwrap();
    assert_eq!(super::build::telemetry_loss_note(&temp.directory), None);
    std::fs::write(
        temp.directory.join("manifest.json"),
        r#"{"telemetry_loss":{"received_packets":3,"lost_packets":0}}"#,
    )
    .unwrap();
    assert_eq!(super::build::telemetry_loss_note(&temp.directory), None);
}

fn read_table() -> report::Table {
    let row = |path: &str, text: &str| {
        vec![
            "17:00:01".to_owned(),
            path.to_owned(),
            "cat".to_owned(),
            text.to_owned(),
            "ok".to_owned(),
        ]
    };
    report::Table {
        columns: ["Time", "Path", "Process", "Transferred / content", "Result"]
            .map(String::from)
            .to_vec(),
        rows: vec![
            row(
                "/etc/shadow",
                "4096 B: root:$6$salt$hash:19000:0:99999:7:::",
            ),
            row("/usr/share/dict/words", "4096 B: aardvark\\nabacus"),
            row("/tmp/own-copy", "29863 B: \\x7fELF\\x02\\x01"),
            row(
                "/proc/1/environ",
                "9 B: kernel transfer; bytes not captured",
            ),
        ],
        ..report::Table::default()
    }
}

#[test]
fn what_a_sample_read_is_not_copied_into_the_report() {
    let written: BTreeSet<String> = ["/tmp/own-copy".to_owned()].into();
    let mut table = read_table();
    build::transferred(&mut table, false, &written);
    assert_eq!(table.columns[3], "Transferred");
    let text = format!("{:?}", table.rows);
    for secret in ["root:$6$", "aardvark", "ELF"] {
        assert!(!text.contains(secret), "{secret} was copied");
    }
    assert_eq!(table.rows[0][3], "4096 B");
    assert_eq!(table.rows[3][3], "9 B");
}

#[test]
fn the_option_keeps_a_clipped_escaped_preview_but_never_of_a_file_the_run_wrote() {
    let written: BTreeSet<String> = ["/tmp/own-copy".to_owned()].into();
    let mut table = read_table();
    table.rows[1][3] = format!("4096 B: {}", "a\u{1}".repeat(100));
    build::transferred(&mut table, true, &written);
    assert!(table.rows[0][3].contains("root:$6$"), "asked for");
    assert!(
        table.rows[1][3].ends_with("..."),
        "clipped: {}",
        table.rows[1][3]
    );
    assert!(table.rows[1][3].contains("\\x01") && !table.rows[1][3].contains('\u{1}'));
    assert_eq!(
        table.rows[2][3], "29863 B",
        "a file the run wrote is never copied"
    );
    assert!(table.rows[3][3].contains("kernel transfer"));
}

fn json_only() -> Choices {
    Choices {
        formats: vec![Format::Json],
        ..Choices::default()
    }
}

/// The statuses a job reports, to tell an index it made from one it reused.
fn statuses(job: &Job) -> (Vec<String>, std::path::PathBuf) {
    let said = std::sync::Mutex::new(Vec::new());
    let written = run_job(job, &Arc::new(AtomicBool::new(false)), &|text| {
        said.lock().unwrap().push(text.to_owned());
    })
    .unwrap();
    let json = written
        .files
        .iter()
        .find(|(l, _)| l == "JSON")
        .unwrap()
        .1
        .clone();
    (said.into_inner().unwrap(), json)
}

#[test]
fn an_unchanged_recording_is_not_read_again_for_the_next_export() {
    let (temp, pcap) = fixture();
    let mut job = job(&temp, &pcap, json_only());
    job.pcap = None;
    job.request.keep_index = true;
    let (first, first_json) = statuses(&job);
    assert_eq!(first[0], "Indexing the whole run...");
    let first_text = read(&first_json);
    // The same recording again, even for a later export: the kept index.
    job.now_ms += 1;
    let (second, second_json) = statuses(&job);
    assert_eq!(second[0], "Using the index Triage already made...");
    let value = |text: &str| -> serde_json::Value {
        let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
        value["generated_ms"] = serde_json::Value::Null;
        value["generated"] = serde_json::Value::Null;
        value
    };
    assert_eq!(value(&first_text), value(&read(&second_json)));
    // A recording that grew is read again.
    let mut raw = std::fs::OpenOptions::new()
        .append(true)
        .open(temp.directory.join("telemetry.raw"))
        .unwrap();
    crate::tests::write_rwx_calls(&mut raw, 3..4);
    drop(raw);
    let (third, _) = statuses(&job);
    assert_eq!(third[0], "Indexing the whole run...");
}

#[test]
fn an_export_that_asked_for_no_kept_index_leaves_none() {
    let (temp, pcap) = fixture();
    let mut job = job(&temp, &pcap, json_only());
    job.pcap = None;
    job.request.keep_index = false;
    assert_eq!(statuses(&job).0[0], "Indexing the whole run...");
    assert_eq!(statuses(&job).0[0], "Indexing the whole run...");
}

#[test]
fn a_filtered_screen_index_is_never_the_report_input() {
    let (temp, pcap) = fixture();
    let mut job = job(&temp, &pcap, json_only());
    job.pcap = None;
    job.request.keep_index = true;
    let mut filtered = job.request.clone();
    filtered.filters[0] = "finding.rule == \"nothing-matches-this\"".into();
    let cancel = Arc::new(AtomicBool::new(false));
    let screen = scan_archive_query(&temp.directory, None, false, &cancel, &filtered).unwrap();
    assert!(!screen.whole_run);
    assert_eq!(statuses(&job).0[0], "Indexing the whole run...");
}

#[test]
fn a_recording_over_a_gigabyte_is_warned_about_with_an_estimate() {
    let (temp, pcap) = fixture();
    let job = job(&temp, &pcap, json_only());
    assert_eq!(large_run(&job), None, "the fixture is a few kilobytes");
    // A sparse file: 3.5 GB long, no disk used.
    let raw = std::fs::OpenOptions::new()
        .write(true)
        .open(temp.directory.join("telemetry.raw"))
        .unwrap();
    raw.set_len(3_500_000_000).unwrap();
    drop(raw);
    let large = large_run(&job).expect("a 3.5 GB recording is large");
    assert_eq!(large.bytes, 3_500_000_000);
    // 3.5 GB at the measured rate is about 69 minutes.
    assert_eq!(large.seconds, 3_500_000_000 / INDEX_BYTES_PER_SECOND);
    let text = large.warning();
    assert!(text.contains("3.3 GiB"), "{text}");
    assert!(
        text.contains("69 minutes") && text.contains("estimate"),
        "{text}"
    );
    // Quick when an index of it is at hand.
    let mut reuse = job.clone();
    let small = job_with_small_scan();
    reuse.request.reuse = Some(small);
    assert_eq!(large_run(&reuse), None);
}

fn job_with_small_scan() -> ArchiveScan {
    let (temp, _) = fixture();
    let cancel = Arc::new(AtomicBool::new(false));
    scan_archive_query(
        &temp.directory,
        None,
        false,
        &cancel,
        &ScanRequest {
            root_cookie: 55,
            ..ScanRequest::default()
        },
    )
    .unwrap()
}

#[test]
fn the_warning_gives_hours_for_a_very_large_recording() {
    let large = LargeRun {
        bytes: 40_000_000_000,
        seconds: 40_000_000_000 / INDEX_BYTES_PER_SECOND,
    };
    assert!(large.warning().contains("hours"), "{}", large.warning());
}

#[test]
fn a_run_with_timed_screenshots_says_so_in_the_report_notes() {
    let run = std::env::temp_dir().join(format!(
        "ant-shots-note-{}",
        std::process::id() * 1000 + 487
    ));
    let shots = run.join("screenshots");
    std::fs::create_dir_all(&shots).unwrap();
    assert_eq!(super::build::timed_shots_note(&run, true), None);
    for name in ["t+000005.0s.png", "t+000065.4s.png"] {
        std::fs::write(shots.join(name), b"png").unwrap();
    }
    std::fs::write(
        shots.join("series.json"),
        br#"{"every_s":5,"taken":2,"unchanged":3,"dropped":0,"no_screen":0,"bytes":6}"#,
    )
    .unwrap();
    let bundled = super::build::timed_shots_note(&run, true).unwrap();
    assert!(bundled.contains("2 pictures"), "{bundled}");
    assert!(
        bundled.contains("+5.0 s") && bundled.contains("+1 min 5.4 s"),
        "{bundled}"
    );
    assert!(bundled.contains("every 5 s; 3 skipped"), "{bundled}");
    assert!(bundled.contains("in the evidence bundle under screenshots/"));
    let unbundled = super::build::timed_shots_note(&run, false).unwrap();
    assert!(unbundled.contains("the evidence bundle includes them"));
    std::fs::remove_dir_all(&run).unwrap();
}
