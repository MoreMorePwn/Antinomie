// SPDX-License-Identifier: GPL-3.0-only
//! The Files and Process tables keep their rows between frames, and say what
//! drops them.
use super::layout::{context, draw, has, settle, view};
use super::*;

fn path_row(path: &str, id: u64) -> Vec<Cell> {
    let mut row: Vec<Cell> = file_category::EVENT_HEADERS
        .iter()
        .map(|header| cell(*header, tone::text(), false))
        .collect();
    row[0].values = vec![("event.id", RowValue::Number(id))];
    row[3].text = path.into();
    row
}

fn kept(view: &TriageView) -> Option<table_cache::Rows> {
    view.table_cache
        .files(
            FileTab::Opened.slot(),
            view.scan.as_ref().unwrap().clock_anchor,
        )
        .map(|rows| Arc::clone(&rows.shown))
}

#[test]
fn a_files_table_is_made_once_and_again_for_a_new_index() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Files);
    view.files = FileTab::Opened;
    view.scan.as_mut().unwrap().opened = vec![path_row("/tmp/first-index", 1)];
    let out = settle(&ctx, &mut view);
    assert!(has(&out, "/tmp/first-index"));
    let made = kept(&view).expect("the rows were kept");
    for frame in 4..8 {
        draw(&ctx, &mut view, vec![], f64::from(frame) * 0.02);
    }
    assert!(
        Arc::ptr_eq(&made, &kept(&view).unwrap()),
        "later frames reuse the rows of the first"
    );
    // Another index: the view counts it, as the refresh does, and the new
    // rows are shown.
    let mut again = antinomie_triage::ArchiveScan::new((*view.scan.as_ref().unwrap().0).clone());
    again.opened = vec![path_row("/tmp/second-index", 2)];
    view.scan = Some(again);
    view.scan_serial += 1;
    let out = settle(&ctx, &mut view);
    assert!(
        has(&out, "/tmp/second-index"),
        "{:?}",
        crate::app::tests::texts(&out)
    );
    assert!(!has(&out, "/tmp/first-index"));
    assert!(!Arc::ptr_eq(&made, &kept(&view).unwrap()));
}

#[test]
fn every_tab_has_its_own_kept_rows() {
    let ctx = context();
    let (_temp, mut view) = view(Section::Files);
    view.scan.as_mut().unwrap().opened = vec![path_row("/tmp/opened-only", 1)];
    view.files = FileTab::Opened;
    settle(&ctx, &mut view);
    let opened = kept(&view).unwrap();
    view.files = FileTab::Read;
    let out = settle(&ctx, &mut view);
    assert!(!has(&out, "/tmp/opened-only"));
    view.files = FileTab::Opened;
    let out = settle(&ctx, &mut view);
    assert!(has(&out, "/tmp/opened-only"));
    assert!(
        Arc::ptr_eq(&opened, &kept(&view).unwrap()),
        "back on Opened the rows are the ones kept"
    );
}

#[test]
fn the_cache_follows_the_index_and_the_clock() {
    let (_temp, view) = view(Section::Files);
    let scan = view.scan.as_ref().unwrap();
    let mut cache = table_cache::ShownCache::default();
    cache.bind(1, scan);
    let anchor = antinomie_monitor_core::HostClockAnchor {
        guest_ns: 1,
        host_us: 2,
    };
    cache.keep_files(0, None, None, Arc::default());
    cache.keep_process(None, true, Arc::default());
    assert!(cache.files(0, None).is_some());
    assert!(cache.files(0, Some(anchor)).is_none(), "another clock");
    assert!(cache.process(None, true).is_some());
    assert!(cache.process(None, false).is_none(), "threads folded");
    let stamp = cache.stamp("triage-opened", None);
    // The same index again keeps everything.
    cache.bind(1, scan);
    assert!(cache.files(0, None).is_some());
    assert_eq!(cache.stamp("triage-opened", None), stamp);
    // One the view counted as another drops the rows and changes the stamp.
    cache.bind(2, scan);
    assert!(cache.files(0, None).is_none() && cache.process(None, true).is_none());
    assert_ne!(cache.stamp("triage-opened", None), stamp);
}
