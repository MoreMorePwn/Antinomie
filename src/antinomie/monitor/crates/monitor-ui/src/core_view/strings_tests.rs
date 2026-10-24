// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::core_view::tests::Fixture;
use crate::table_sort::testing;
use std::sync::Mutex;

/// Make the fixture's core memory `strings` (zero separated) and return its record.
fn with_strings(fixture: &mut Fixture, strings: &[String]) -> CoreRecord {
    let mut memory = Vec::new();
    for text in strings {
        memory.extend_from_slice(text.as_bytes());
        memory.push(0);
    }
    let mut record = fixture.view.selected.clone().unwrap();
    fs::write(&record.core.source, &memory).unwrap();
    record.core.source_size = memory.len() as u64;
    record.core.mappings[0].captured_size = memory.len() as u64;
    record.core.mappings[0].available_size = memory.len() as u64;
    record
}

fn named(strings: &[&str]) -> Vec<String> {
    strings.iter().map(|text| (*text).to_owned()).collect()
}

/// Run frames until `done` holds for the painted texts; panics after a while.
fn pump(
    ctx: &egui::Context,
    state: &mut StringsState,
    record: &CoreRecord,
    done: impl Fn(&[(String, egui::Rect)]) -> bool,
) -> Vec<(String, egui::Rect)> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let shown = testing::frame(ctx, vec![], &mut |ui: &mut egui::Ui| {
            state.show(ui, record);
        });
        if done(&shown) {
            return shown;
        }
        assert!(Instant::now() < deadline, "never settled: {shown:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn has(shown: &[(String, egui::Rect)], text: &str) -> bool {
    shown.iter().any(|(shown, _)| shown == text)
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    ctx
}

#[test]
fn the_search_runs_on_a_worker_thread_while_the_view_shows_the_shared_spinner() {
    let ctx = context();
    let fixture = Fixture::new();
    let record = fixture.view.selected.clone().unwrap();
    let mut state = StringsState::default();
    let (release, wait) = mpsc::sync_channel::<()>(0);
    let worker = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&worker);
    state.start_with(2048, move |_, progress| {
        *seen.lock().unwrap() = Some(std::thread::current().id());
        progress.store(1024, Ordering::Relaxed);
        wait.recv().unwrap();
        Ok(Extracted {
            source: PathBuf::from("/synthetic"),
            strings: Vec::new(),
            names: Vec::new(),
            scanned: 2048,
            stopped: None,
        })
    });
    let before = Instant::now();
    state.poll();
    assert!(
        before.elapsed() < Duration::from_secs(30),
        "polling a running search must not wait for it"
    );
    assert!(state.running() && state.count().is_none());
    let shown = testing::frame(&ctx, vec![], &mut |ui: &mut egui::Ui| {
        state.show(ui, &record);
    });
    assert!(
        shown
            .iter()
            .any(|(text, _)| text.starts_with("Searching the core's memory for strings…")),
        "{shown:?}"
    );
    assert!(has(&shown, "Cancel"), "{shown:?}");
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while state.running() {
        state.poll();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(state.count(), Some(0));
    let worker = worker.lock().unwrap().unwrap();
    assert_ne!(worker, std::thread::current().id());
}

#[test]
fn cancelling_or_resetting_stops_the_search_and_keeps_no_result() {
    let (told, heard) = mpsc::sync_channel::<bool>(1);
    let mut state = StringsState::default();
    state.start_with(10, move |cancel, _| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !cancel.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        told.send(cancel.load(Ordering::Relaxed)).unwrap();
        Ok(Extracted {
            source: PathBuf::new(),
            strings: Vec::new(),
            names: Vec::new(),
            scanned: 0,
            stopped: Some(Stopped::Cancelled),
        })
    });
    state.reset();
    assert!(heard.recv_timeout(Duration::from_secs(5)).unwrap());
    assert!(!state.running() && state.count().is_none());
}

#[test]
fn strings_show_their_virtual_address_file_offset_and_mapping_name() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let record = with_strings(&mut fixture, &named(&["first-string", "second-string"]));
    let mut state = StringsState::default();
    let shown = pump(&ctx, &mut state, &record, |shown| {
        has(shown, "second-string")
    });
    // The mapping starts at 0x400000 and holds the file from offset 0.
    assert!(
        has(&shown, "0x400000") && has(&shown, "0x40000d"),
        "{shown:?}"
    );
    assert!(has(&shown, "0xd"), "{shown:?}");
    assert!(
        has(&shown, "sample"),
        "the NT_FILE name of the mapping: {shown:?}"
    );
    assert!(has(&shown, "ASCII") && has(&shown, "12") && has(&shown, "13"));
    assert!(shown.iter().any(|(text, _)| text == "2 of 2 strings"));
    let unnamed = {
        let mut core = record.core.clone();
        core.files.clear();
        segment_name(&core, &core.mappings[0])
    };
    assert_eq!(unnamed, "[anonymous r-x]");
}

#[test]
fn utf16_strings_are_found_with_their_encoding() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let mut record = with_strings(&mut fixture, &[]);
    let wide: Vec<u8> = "wide text"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    fs::write(&record.core.source, &wide).unwrap();
    record.core.mappings[0].available_size = wide.len() as u64;
    let mut state = StringsState::default();
    let shown = pump(&ctx, &mut state, &record, |shown| has(shown, "wide text"));
    assert!(has(&shown, "UTF-16LE"));
}

#[test]
fn the_filter_keeps_matching_strings_and_runs_off_the_ui_thread() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let record = with_strings(
        &mut fixture,
        &named(&["alpha-one", "beta-two", "gamma-three", "alpha-four"]),
    );
    let mut state = StringsState::default();
    pump(&ctx, &mut state, &record, |shown| has(shown, "gamma-three"));
    state.query = "string.text contains alpha".into();
    let shown = pump(&ctx, &mut state, &record, |shown| {
        has(shown, "2 of 4 strings") && !has(shown, "beta-two")
    });
    assert!(has(&shown, "alpha-one") && has(&shown, "alpha-four"));
    assert!(!has(&shown, "gamma-three"));
    state.query = "string.segment == \"nowhere\"".into();
    pump(&ctx, &mut state, &record, |shown| {
        has(shown, "0 of 4 strings")
    });
    // A filter that does not compile keeps the last one that did.
    state.query = "string.text contains (".into();
    let shown = pump(&ctx, &mut state, &record, |shown| {
        has(shown, "0 of 4 strings")
    });
    assert!(!has(&shown, "alpha-one"));
}

#[test]
fn a_header_click_sorts_ascending_then_descending() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let record = with_strings(
        &mut fixture,
        &named(&["mango-fruit", "apple-fruit", "zebra-animal"]),
    );
    let mut state = StringsState::default();
    // The table, and its headers, appear once the worker has read the strings.
    pump(&ctx, &mut state, &record, |shown| has(shown, "Text"));
    let names = ["mango-fruit", "apple-fruit", "zebra-animal"];
    let mut show = |ui: &mut egui::Ui| {
        state.show(ui, &record);
    };
    let order = |shown: &[(String, egui::Rect)]| testing::column_order(shown, &names);
    let shown = testing::click(&ctx, "Text", &mut show);
    let wanted = ["apple-fruit", "mango-fruit", "zebra-animal"];
    let mut shown = shown;
    let deadline = Instant::now() + Duration::from_secs(60);
    while order(&shown) != wanted && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
        shown = testing::frame(&ctx, vec![], &mut show);
    }
    assert_eq!(order(&shown), wanted, "ascending by text");
    let mut shown = testing::click(&ctx, "Text", &mut show);
    let wanted = ["zebra-animal", "mango-fruit", "apple-fruit"];
    let deadline = Instant::now() + Duration::from_secs(60);
    while order(&shown) != wanted && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
        shown = testing::frame(&ctx, vec![], &mut show);
    }
    assert_eq!(order(&shown), wanted, "descending by text");
}

#[test]
fn every_column_sorts_the_derived_order() {
    let strings = ["bb-second", "aaaa-first", "c-third"];
    let extracted = Extracted {
        source: PathBuf::new(),
        strings: [(0x30u64, "ASCII"), (0x10, "UTF-16LE"), (0x20, "ASCII")]
            .into_iter()
            .zip(strings)
            .enumerate()
            .map(|(index, ((address, encoding), text))| CoreString {
                address,
                file_offset: 0x1000 - address,
                encoding,
                byte_len: text.len() as u64,
                mapping: index % 2,
                text: text.into(),
            })
            .collect(),
        names: vec!["zlib".into(), "app".into()],
        scanned: 0,
        stopped: None,
    };
    let order = |column, descending| {
        derive_order(
            &extracted,
            &Key {
                filter: String::new(),
                sort: Some((column, descending)),
            },
        )
    };
    assert_eq!(order(0, false), [1, 2, 0], "address");
    assert_eq!(order(1, false), [0, 2, 1], "file offset");
    assert_eq!(order(2, false), [0, 2, 1], "encoding, equal ones in order");
    assert_eq!(order(3, false), [2, 0, 1], "length");
    assert_eq!(order(4, false), [1, 0, 2], "segment, then extraction order");
    assert_eq!(order(5, false), [1, 0, 2], "text");
    assert_eq!(order(5, true), [2, 0, 1]);
}

#[test]
fn a_large_result_shows_one_page_at_a_time() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let strings: Vec<String> = (0..PAGE_ROWS * 2 + 3)
        .map(|n| format!("entry-{n:05}"))
        .collect();
    let record = with_strings(&mut fixture, &strings);
    let mut state = StringsState::default();
    let shown = pump(&ctx, &mut state, &record, |shown| has(shown, "entry-00000"));
    assert!(has(&shown, "Page 1 of 3"), "{shown:?}");
    assert!(has(
        &shown,
        &format!("{} of {} strings", strings.len(), strings.len())
    ));
    assert!(
        !has(&shown, &format!("entry-{:05}", PAGE_ROWS)),
        "second page row"
    );
    let mut show = |ui: &mut egui::Ui| {
        state.show(ui, &record);
    };
    let shown = testing::click(&ctx, "Next", &mut show);
    assert!(has(&shown, "Page 2 of 3"), "{shown:?}");
    assert!(has(&shown, &format!("entry-{:05}", PAGE_ROWS)));
    assert!(!has(&shown, "entry-00000"));
    testing::click(&ctx, "Next", &mut show);
    let shown = testing::click(&ctx, "Next", &mut show);
    assert!(
        has(&shown, "Page 3 of 3"),
        "the last page has no next: {shown:?}"
    );
}

#[test]
fn choosing_a_string_hands_its_fields_to_the_details_panel() {
    let ctx = context();
    let mut fixture = Fixture::new();
    let record = with_strings(&mut fixture, &named(&["details-target"]));
    let mut state = StringsState::default();
    pump(&ctx, &mut state, &record, |shown| {
        has(shown, "details-target")
    });
    let chosen = std::cell::RefCell::new(None);
    let mut show = |ui: &mut egui::Ui| {
        if let Some(detail) = state.show(ui, &record) {
            *chosen.borrow_mut() = Some(detail);
        }
    };
    testing::click(&ctx, "details-target", &mut show);
    let detail = chosen.into_inner().expect("a click chooses the row");
    assert_eq!((detail.what, detail.from), ("String", "Strings"));
    let field = |name| {
        detail
            .fields
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(field("Address"), "0x400000");
    assert_eq!(field("Segment"), "sample");
    assert_eq!(field("Length"), "14 octets");
}
