// SPDX-License-Identifier: MIT
//! Trace filters and archive scans.
use super::*;

#[test]
fn invalid_syscall_filter_keeps_the_previous_applied_filter() {
    let mut app = app();
    let invocation = InvocationSummary {
        stream_id: 1,
        task_cookie: 3,
        call_id: 2,
        entry: Some(event(1, 0)),
        exit: None,
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
    };
    assert_eq!(app.applied_filter, "");
    assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));

    app.filter = "read".into();
    let note = app.commit_trace_filter();
    assert!(note.error.is_none());
    assert_eq!(app.applied_filter, "read");
    assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));

    app.filter = "syscall.typo == 9".into();
    let note = app.commit_trace_filter();
    assert!(note.error.is_some());
    assert_eq!(app.applied_filter, "read");
    assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));
    assert!(!crate::query::compile_note(&app.filter).keep(&invocation));
}

#[test]
fn archive_filter_changes_cancel_old_scan_preserve_page_and_reject_invalid_draft() {
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    let old_generation = app.archive_generation;
    let old_cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
    app.archive_page = pair_events(&[event(1, 0)]);
    app.archive_previous = vec![0, 100];
    app.selected_event = Some(trace::key(&app.archive_page[0]));
    app.filter = "syscall.num == 9".into();
    assert!(app.commit_trace_filter().error.is_none());
    assert!(old_cancel.load(Ordering::Relaxed));
    assert!(app.archive_previous.is_empty());
    assert_eq!(app.archive_page.len(), 1);
    assert!(app.selected_event.is_none());
    assert!(
        matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, query, .. }) if query == "syscall.num == 9")
    );
    let generation = app.archive_generation;
    app.filter = "syscall.num ==".into();
    assert!(app.commit_trace_filter().error.is_some());
    assert_eq!(app.applied_filter, "syscall.num == 9");
    assert_eq!(app.archive_generation, generation);
    assert!(!app
        .archive_read_cancel
        .as_ref()
        .unwrap()
        .load(Ordering::Relaxed));
    app.handle_archive_answer(Answer::Invocations {
        generation: old_generation,
        offset: 99,
        total: Some(9),
        source_total: Some(350),
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: Vec::new(),
            next_offset: None,
            issues: Vec::new(),
        }),
    });
    assert_eq!(app.archive_page.len(), 1);
    assert!(app.archive_pending);
    let selected_cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
    app.select_process(captures::ProcessSelection::Process(99));
    assert!(selected_cancel.load(Ordering::Relaxed));
    assert!(
        matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, pid: Some(99), query, .. }) if query == "syscall.num == 9")
    );
}

#[test]
fn archive_category_predicate_restarts_global_matches_and_retains_visible_selection() {
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.archive_page = pair_events(&[event(1, 0)]);
    let selected = trace::key(&app.archive_page[0]);
    app.selected_event = Some(selected);
    app.filter = "syscall.num == 0".into();
    assert!(app.commit_trace_filter().error.is_none());
    assert_eq!(app.selected_event, Some(selected));
    let cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
    let group = SyscallGroup::of("read").unwrap();
    app.settings.hidden_trace_categories = vec![group];
    app.refresh_archive_matches(&crate::query::compile_note(&app.applied_filter));
    assert!(cancel.load(Ordering::Relaxed));
    assert!(app.selected_event.is_none());
    assert_eq!(app.archive_page.len(), 1);
    assert!(
        matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, hidden_categories, .. }) if hidden_categories == &[group])
    );
}
