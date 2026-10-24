// SPDX-License-Identifier: GPL-3.0-only
use super::super::finding::Pick;
use super::super::tests::{each_galley_rect, frames, rendered_text};
use super::*;
use crate::triage::PacketSpool;
use antinomie_monitor_core::analysis::detection::{Engine, EventJournal, Evidence, Finding};
use antinomie_monitor_core::analysis::detection::{InputKind, ScannedInput};
use std::time::Instant;

fn identity() -> Identity {
    Identity {
        vm_id: "v".into(),
        boot_id: "b".into(),
        run_id: "r".into(),
        root_cookie: 7,
    }
}

fn call(call: u64) -> Evidence {
    Evidence::Call {
        stream: 1,
        cookie: 7,
        call,
    }
}

/// Four events: two process_creation and two file_event, the middle two from call 2.
fn fixture() -> (PacketSpool, String) {
    let spool = PacketSpool::new().unwrap();
    let mut writer = EventJournal::new(&spool.directory, &identity()).unwrap();
    let events = [
        ("process_creation", "/bin/sh", 1),
        ("file_event", "/tmp/dropped", 2),
        ("file_access", "/tmp/dropped", 2),
        ("process_creation", "/bin/ls", 3),
    ];
    for (category, image, number) in events {
        writer
            .push(Event {
                category: category.into(),
                fields: [("Image".to_owned(), image.into())].into(),
                evidence: call(number),
                time: Some(Moment::GuestNs(1_000 * number)),
                inferred: Vec::new(),
            })
            .unwrap();
    }
    let digest = writer.finish(true).unwrap().sha256;
    (spool, digest)
}

fn view_for(spool: &PacketSpool) -> View {
    let mut view = View::default();
    view.identity = Some((spool.directory.clone(), identity()));
    view
}

/// Frames until `ready`, so the worker thread has delivered its page.
fn pump(view: &mut View, ctx: &egui::Context, ready: impl Fn(&Viewer) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let shapes = frames(ctx, 2, |ctx| {
            view.journal.show(ctx, view.identity.as_ref(), None)
        });
        if ready(&view.journal) || Instant::now() > deadline {
            return rendered_text(&shapes);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn click(ctx: &egui::Context, text: &str, run: &mut impl FnMut(&egui::Context)) {
    let mut position = None;
    for shape in frames(ctx, 2, &mut *run) {
        each_galley_rect(&shape.shape, &mut |shown, rect| {
            if shown == text {
                position = Some(rect.center());
            }
        });
    }
    let position = position.unwrap_or_else(|| panic!("{text} not drawn"));
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 800.0),
                )),
                events: vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            &mut *run,
        );
    }
}

#[test]
fn the_event_journal_row_routes_to_the_viewer() {
    let (spool, digest) = fixture();
    let path = spool.directory.join(JOURNAL_FILE);
    let mut row = ScannedInput::new(InputKind::EventJournal, &path);
    assert_eq!(
        super::super::inputs::target(&row),
        Some(super::super::inputs::Route::Journal(None))
    );
    row.sha256 = Some(digest.clone());
    row.detail = "4 events".into();
    let mut view = view_for(&spool);
    let mut result = super::super::tests::report(vec![]);
    result.inputs = Some(vec![row]);
    view.results[0] = Some(Ok(result));
    view.inputs_open[0] = true;
    assert!(!view.journal.is_open());

    let ctx = egui::Context::default();
    click(&ctx, "triage-events.jsonl", &mut |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
    });
    assert!(view.journal.is_open(), "clicking the row opens the viewer");
    assert_eq!(view.journal.scanned.as_deref(), Some(digest.as_str()));
    let text = pump(&mut view, &ctx, |viewer| viewer.page.is_some());
    for expected in [
        "Complete",
        "4 events · process_creation 2 · file_access 1 · file_event 1",
        "Identical to the journal this scan read.",
        "/bin/sh",
        "/tmp/dropped",
        "Open file",
        "Copy path",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn a_category_filter_pages_over_matching_events_and_selection_shows_all_fields() {
    let (spool, digest) = fixture();
    let mut view = view_for(&spool);
    let ctx = egui::Context::default();
    view.journal.open(&ctx, Some(digest), None);
    pump(&mut view, &ctx, |viewer| viewer.page.is_some());
    assert_eq!(view.journal.page.as_ref().unwrap().rows.len(), 4);

    view.journal.category = "process_creation".into();
    view.journal.restart(0);
    let text = pump(&mut view, &ctx, |viewer| {
        viewer.page.as_ref().is_some_and(|page| page.matching == 2)
    });
    let page = view.journal.page.as_ref().unwrap();
    let ids: Vec<_> = page.rows.iter().map(|row| row.id).collect();
    assert_eq!(ids, [1, 4]);
    assert!(
        text.contains("Events 1–2 of 2 matching, of 4 in the journal"),
        "{text}"
    );
    assert!(!text.contains("/tmp/dropped"), "{text}");

    view.journal.selected = Some(4);
    let text = pump(&mut view, &ctx, |_| true);
    for expected in [
        "Event #4 · process_creation",
        "Image",
        "/bin/ls",
        "3000 ns on the guest clock",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn a_finding_event_opens_the_viewer_on_that_event_and_links_to_its_call() {
    let (spool, digest) = fixture();
    let mut sigma = super::super::tests::finding("rule", "Dropper", vec![call(2), call(3)]);
    sigma.events = vec![3, 4];
    assert_eq!(
        super::super::finding::journal_focus(Engine::Sigma, &sigma, 0),
        Some(Focus::Event(3))
    );
    sigma.events.clear();
    let older = super::super::finding::journal_focus(Engine::Sigma, &sigma, 1);
    assert_eq!(
        older,
        Some(Focus::Source(call(3))),
        "source-only results still open"
    );
    assert_eq!(
        super::super::finding::journal_focus(Engine::Yara, &sigma, 0),
        None
    );
    let bytes = Evidence::Bytes {
        path: "/x".into(),
        offset: None,
        address: None,
        report_id: None,
        block: None,
    };
    let mut other: Finding = super::super::tests::finding("r", "t", vec![bytes]);
    assert_eq!(
        super::super::finding::journal_focus(Engine::Sigma, &other, 0),
        None
    );
    other.events = vec![1];
    assert_eq!(
        super::super::finding::journal_focus(Engine::Sigma, &other, 0),
        Some(Focus::Event(1))
    );

    let mut view = view_for(&spool);
    let ctx = egui::Context::default();
    view.open_pick(&ctx, Some(digest), Pick::Journal(Focus::Event(3)));
    pump(&mut view, &ctx, |viewer| viewer.page.is_some());
    assert_eq!(view.journal.selected, Some(3));
    let selected = view
        .journal
        .page
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|row| row.id == 3)
        .unwrap();
    assert_eq!(selected.event.category, "file_access");

    // The event's Source button leaves the call for Syscall Trace.
    click(&ctx, "Open syscall 1/7/2", &mut |ctx| {
        view.journal.show(ctx, view.identity.as_ref(), None)
    });
    let jump = ctx.data_mut(|data| {
        data.get_temp::<crate::trace::InvocationKey>(egui::Id::new("triage-call-jump"))
    });
    assert_eq!(jump, Some((1, 7, 2)));
}

#[test]
fn an_older_finding_labels_a_source_shared_by_several_events() {
    let (spool, _) = fixture();
    let mut view = view_for(&spool);
    let ctx = egui::Context::default();
    view.open_pick(&ctx, None, Pick::Journal(Focus::Source(call(2))));
    let text = pump(&mut view, &ctx, |viewer| viewer.page.is_some());
    assert_eq!(
        view.journal.selected,
        Some(2),
        "the first event of the call"
    );
    assert!(
        text.contains("2 events were recorded for this one call or packet"),
        "{text}"
    );
}

#[test]
fn a_changed_journal_refuses_event_numbers_and_a_run_switch_cancels_the_read() {
    let (spool, _) = fixture();
    let mut view = view_for(&spool);
    let ctx = egui::Context::default();
    view.journal
        .open(&ctx, Some("00".repeat(32)), Some(Focus::Event(1)));
    let text = pump(&mut view, &ctx, |viewer| viewer.error.is_some());
    assert!(text.contains("changed after this scan"), "{text}");

    view.journal.open(&ctx, None, None);
    let _ = frames(&ctx, 1, |ctx| {
        view.journal.show(ctx, view.identity.as_ref(), None)
    });
    let cancel = Arc::clone(&view.journal.job.as_ref().expect("a read is running").cancel);
    view.reset();
    assert!(
        cancel.load(Ordering::Relaxed),
        "the old run's read is cancelled"
    );
    assert!(!view.journal.is_open() && view.journal.page.is_none());
    // Without a run the viewer closes itself.
    view.journal.open(&ctx, None, None);
    let _ = frames(&ctx, 1, |ctx| view.journal.show(ctx, None, None));
    assert!(!view.journal.is_open());
}
