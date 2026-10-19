// SPDX-License-Identifier: MIT
use super::*;
use crate::analysis::detection::{EventJournal, Moment};
use std::{fs, path::Path};

fn identity() -> Identity {
    Identity {
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        run_id: "run".into(),
        root_cookie: 7,
    }
}

fn temp() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("ant-journal-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&directory).unwrap();
    directory
}

fn call(call: u64) -> Evidence {
    Evidence::Call {
        stream: 1,
        cookie: 7,
        call,
    }
}

fn event(category: &str, image: &str, evidence: Evidence) -> Event {
    Event {
        category: category.into(),
        fields: BTreeMap::from([("Image".into(), image.into())]),
        evidence,
        time: Some(Moment::GuestNs(5)),
        inferred: Vec::new(),
    }
}

/// A finished journal of `count` events alternating two categories.
fn journal(directory: &Path, count: u64) -> String {
    let mut journal = EventJournal::new(directory, &identity()).unwrap();
    for index in 1..=count {
        let (category, image) = if index % 2 == 1 {
            ("process_creation", format!("/bin/sh{index}"))
        } else {
            ("file_event", format!("/tmp/file{index}"))
        };
        journal.push(event(category, &image, call(index))).unwrap();
    }
    journal.finish(true).unwrap().sha256
}

fn query(directory: &Path) -> Query {
    Query {
        directory: directory.to_path_buf(),
        identity: identity(),
        scanned: None,
        category: String::new(),
        text: String::new(),
        offset: 0,
        focus: None,
    }
}

fn read(query: &Query) -> Result<Page, String> {
    read_page(query, &AtomicBool::new(false))
}

#[test]
fn a_page_carries_the_header_end_record_and_whole_journal_counts() {
    let directory = temp();
    let digest = journal(&directory, 250);
    let mut request = query(&directory);
    request.scanned = Some(digest.clone());
    let page = read(&request).unwrap();
    assert_eq!(page.rows.len(), PAGE_SIZE, "one bounded page of 250 events");
    assert_eq!((page.rows[0].id, page.rows[99].id), (1, 100));
    assert_eq!((page.events, page.matching, page.omitted()), (250, 250, 0));
    assert_eq!(page.categories["process_creation"], 125);
    assert_eq!(page.sha256, digest);
    assert_eq!(page.scanned_match, Some(true));
    assert!(page.complete() && page.warnings.is_empty());
    assert_eq!(
        category_detail(&page.categories),
        "250 events · file_event 125 · process_creation 125"
    );
    assert_eq!(page.rows[0].event.time, Some(Moment::GuestNs(5)));
    request.offset = 200;
    let last = read(&request).unwrap();
    assert_eq!((last.rows.len(), last.rows[0].id), (50, 201));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_category_filter_and_text_search_page_over_matching_events_only() {
    let directory = temp();
    journal(&directory, 250);
    let mut request = query(&directory);
    request.category = "file_event".into();
    let page = read(&request).unwrap();
    assert_eq!((page.matching, page.events), (125, 250));
    assert!(
        page.rows
            .iter()
            .all(|row| row.event.category == "file_event")
    );
    assert_eq!(page.rows[0].id, 2, "ordinals still count the whole journal");
    request.offset = 100;
    let second = read(&request).unwrap();
    assert_eq!((second.rows.len(), second.rows[0].id), (25, 202));
    request.offset = 0;
    request.text = "SH24".into();
    request.category.clear();
    let found = read(&request).unwrap();
    let ids: Vec<_> = found.rows.iter().map(|row| row.id).collect();
    assert_eq!(ids, [241, 243, 245, 247, 249], "field values, any case");
    assert_eq!(found.matching, 5);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn focusing_an_event_returns_its_page_and_refuses_a_different_journal() {
    let directory = temp();
    let digest = journal(&directory, 250);
    let mut request = query(&directory);
    request.scanned = Some(digest);
    request.focus = Some(Focus::Event(150));
    let page = read(&request).unwrap();
    assert_eq!(page.offset, 100);
    assert!(page.rows.iter().any(|row| row.id == 150));
    assert_eq!(page.rows.len(), PAGE_SIZE);
    request.focus = Some(Focus::Event(999));
    assert!(read(&request).unwrap_err().contains("not in this journal"));
    request.focus = Some(Focus::Event(1));
    request.scanned = Some("00".repeat(32));
    assert!(
        read(&request)
            .unwrap_err()
            .contains("changed after this scan")
    );
    request.focus = None;
    let shown = read(&request).unwrap();
    assert_eq!(
        shown.scanned_match,
        Some(false),
        "viewing is allowed, labelled"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_source_focus_finds_the_first_event_and_counts_ambiguous_sources() {
    let directory = temp();
    let mut writer = EventJournal::new(&directory, &identity()).unwrap();
    writer
        .push(event("process_creation", "/bin/a", call(1)))
        .unwrap();
    writer
        .push(event("file_access", "/bin/a", call(2)))
        .unwrap();
    writer.push(event("file_event", "/bin/a", call(2))).unwrap();
    writer.finish(true).unwrap();
    let mut request = query(&directory);
    request.focus = Some(Focus::Source(call(2)));
    let page = read(&request).unwrap();
    assert_eq!(page.source_matches, 2, "one call produced two events");
    assert_eq!(page.rows.len(), 3);
    request.focus = Some(Focus::Source(call(1)));
    assert_eq!(read(&request).unwrap().source_matches, 1);
    request.focus = Some(Focus::Source(call(9)));
    assert!(read(&request).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn omitted_events_and_a_missing_or_inconsistent_end_are_never_reported_complete() {
    let directory = temp();
    let mut writer = EventJournal::new(&directory, &identity()).unwrap();
    writer
        .push(event("process_creation", "/bin/a", call(1)))
        .unwrap();
    writer
        .push(event(&"x".repeat(65), "/bin/b", call(2)))
        .unwrap();
    writer.finish(true).unwrap();
    let partial = read(&query(&directory)).unwrap();
    assert_eq!((partial.omitted(), partial.complete()), (1, false));

    let path = directory.join(JOURNAL_FILE);
    let text = fs::read_to_string(&path).unwrap();
    let body: Vec<_> = text.lines().collect();
    fs::write(&path, body[..2].join("\n") + "\n").unwrap();
    let open = read(&query(&directory)).unwrap();
    assert!(open.end.is_none() && !open.complete());
    assert!(open.warnings[0].contains("no end record"));

    let wrong = body[..2].join("\n")
        + "\n{\"kind\":\"end\",\"complete\":true,\"events\":9,\"omitted\":0}\n";
    fs::write(&path, wrong).unwrap();
    let inconsistent = read(&query(&directory)).unwrap();
    assert!(!inconsistent.complete());
    assert!(inconsistent.warnings[0].contains("counts 9 events"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn damaged_files_keep_a_labelled_prefix_and_the_digest_of_the_whole_file() {
    let directory = temp();
    journal(&directory, 4);
    let path = directory.join(JOURNAL_FILE);
    let good = fs::read_to_string(&path).unwrap();
    let lines: Vec<_> = good.lines().collect();
    // A corrupt third record: the prefix stays, the rest is hashed but not shown.
    let broken = format!("{}\n{}\nnot json\n{}\n", lines[0], lines[1], lines[3]);
    fs::write(&path, &broken).unwrap();
    let page = read(&query(&directory)).unwrap();
    assert_eq!(page.rows.len(), 1);
    assert!(page.warnings[0].contains("invalid"), "{:?}", page.warnings);
    assert_eq!(page.sha256, crate::storage::sha256_hex(broken.as_bytes()));
    assert!(!page.complete());
    // An unfinished last record.
    fs::write(
        &path,
        format!("{}\n{}\n{{\"kind\":\"ev", lines[0], lines[1]),
    )
    .unwrap();
    let cut = read(&query(&directory)).unwrap();
    assert_eq!(cut.rows.len(), 1);
    assert!(cut.warnings[0].contains("unfinished"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn another_run_a_missing_header_and_oversized_records_are_errors() {
    let directory = temp();
    journal(&directory, 2);
    let mut request = query(&directory);
    request.identity.run_id = "other".into();
    assert!(read(&request).unwrap_err().contains("another run"));
    let path = directory.join(JOURNAL_FILE);
    fs::write(&path, "{\"kind\":\"event\"}\n").unwrap();
    assert!(read(&query(&directory)).is_err());
    fs::write(&path, vec![b'a'; MAX_LINE as usize + 10]).unwrap();
    assert!(
        read(&query(&directory))
            .unwrap_err()
            .contains("exceeds its bound")
    );
    request.category = "c".repeat(65);
    assert!(read(&request).unwrap_err().contains("bounds"));
    fs::remove_file(&path).unwrap();
    assert!(read(&query(&directory)).is_err(), "no journal yet");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn the_journal_is_opened_only_inside_its_run_folder_and_cancel_stops_the_read() {
    let directory = temp();
    journal(&directory, 3);
    let outside = temp();
    fs::rename(directory.join(JOURNAL_FILE), outside.join("real.jsonl")).unwrap();
    std::os::unix::fs::symlink(outside.join("real.jsonl"), directory.join(JOURNAL_FILE)).unwrap();
    assert!(
        read(&query(&directory)).is_err(),
        "a link out of the folder is refused"
    );
    fs::remove_file(directory.join(JOURNAL_FILE)).unwrap();
    journal(&directory, 3);
    let cancelled = AtomicBool::new(true);
    assert!(
        read_page(&query(&directory), &cancelled)
            .unwrap_err()
            .contains("cancelled")
    );
    fs::remove_dir_all(directory).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn a_version_one_journal_still_reads_and_version_two_keeps_the_inferred_list() {
    let directory = temp();
    let mut writer = EventJournal::new(&directory, &identity()).unwrap();
    let mut named = event("network_connection", "/bin/nc", call(1));
    named.inferred = vec!["DestinationHostname".into()];
    writer.push(named).unwrap();
    writer.finish(true).unwrap();
    let page = read(&query(&directory)).unwrap();
    assert_eq!(page.format_version, JOURNAL_VERSION);
    assert_eq!(page.rows[0].event.inferred, ["DestinationHostname"]);
    let path = directory.join(JOURNAL_FILE);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"_inferred\":[\"DestinationHostname\"]"));
    // A journal written before the list existed has neither the header
    // version nor the list; it still loads, with nothing inferred.
    let old = text
        .replace("\"format_version\":2", "\"format_version\":1")
        .replace(",\"_inferred\":[\"DestinationHostname\"]", "");
    fs::write(&path, old).unwrap();
    let page = read(&query(&directory)).unwrap();
    assert_eq!(page.format_version, 1);
    assert!(page.rows[0].event.inferred.is_empty());
    fs::write(
        &path,
        fs::read_to_string(&path)
            .unwrap()
            .replace("\"format_version\":1", "\"format_version\":3"),
    )
    .unwrap();
    assert!(
        read(&query(&directory)).is_err(),
        "a newer format is refused"
    );
    fs::remove_dir_all(directory).unwrap();
}
