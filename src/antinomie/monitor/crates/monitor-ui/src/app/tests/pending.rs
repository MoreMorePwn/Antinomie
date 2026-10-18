// SPDX-License-Identifier: MIT
use super::*;

fn launch_pending() -> (MonitorApp, ExecRequest) {
    let mut app = app();
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.boot_id = Some("boot".into());
    app.snapshot.state = VmState::Running;
    app.selected = Some("vm".into());
    let request = ExecRequest::default();
    app.pending_launch = Some(77);
    app.pending_launch_context = Some(PendingLaunch {
        id: 77,
        vm_id: Some("vm".into()),
        boot_id: Some("boot".into()),
        request: request.clone(),
        runs_before: BTreeSet::new(),
        preview_run: None,
    });
    app.pending_sessions.insert(
        77,
        PendingSession {
            vm_id: Some("vm".into()),
            boot_id: Some("boot".into()),
            vm_only: false,
        },
    );
    (app, request)
}

#[test]
fn launch_success_and_run_started_preview_wait_for_authoritative_snapshot() {
    let (mut app, request) = launch_pending();
    resolve_launch_result(&mut app.pending_launch, 77, true);
    assert_eq!(app.pending_launch, Some(77));

    let mut started = run("new-run");
    started.request = request.clone();
    let mut activity = Vec::new();
    app.accept_run_started(started.clone(), &mut activity);
    assert_eq!(app.pending_launch, Some(77));
    assert_eq!(
        app.pending_launch_context
            .as_ref()
            .and_then(|pending| pending.preview_run.as_deref()),
        Some("new-run")
    );

    let mut authoritative = app.snapshot.clone();
    authoritative.runs = vec![started];
    app.accept_snapshot(authoritative, &mut activity);
    assert!(app.pending_launch.is_none());
    assert!(app.pending_launch_context.is_none());
    assert!(!app.pending_sessions.contains_key(&77));
}

#[test]
fn snapshot_without_run_started_preview_confirms_only_a_new_matching_request() {
    let (mut app, request) = launch_pending();
    resolve_launch_result(&mut app.pending_launch, 77, true);
    let mut unrelated = run("other-new-run");
    unrelated.request.path = "/bin/false".into();
    let mut next = app.snapshot.clone();
    next.runs = vec![unrelated];
    let mut activity = Vec::new();
    app.accept_snapshot(next, &mut activity);
    assert_eq!(app.pending_launch, Some(77));

    let mut launched = run("matching-new-run");
    launched.request = request;
    let mut next = app.snapshot.clone();
    next.runs = vec![launched];
    app.accept_snapshot(next, &mut activity);
    assert!(app.pending_launch.is_none());
}

#[test]
fn changing_session_releases_pending_controls_and_suppresses_late_result() {
    let (mut app, _) = launch_pending();
    app.pending_observer = Some(88);
    app.pending_sessions.insert(
        88,
        PendingSession {
            vm_id: Some("vm".into()),
            boot_id: Some("boot".into()),
            vm_only: false,
        },
    );
    let mut next = app.snapshot.clone();
    next.active_vm = Some("other".into());
    next.boot_id = Some("new-boot".into());
    next.state = VmState::Running;
    let mut activity = Vec::new();
    app.accept_snapshot(next, &mut activity);

    assert!(app.pending_launch.is_none());
    assert!(app.pending_observer.is_none());
    assert!(app.stale_command_ids.contains(&77));
    assert!(app.stale_command_ids.contains(&88));
    assert!(app.status.contains("outcome unknown"));
}

#[test]
fn backend_disconnect_clears_pending_controls_without_retrying() {
    let (mut app, _) = launch_pending();
    app.pending_core = Some(89);
    app.process_picker.pending = Some(90);
    app.pending_sessions.insert(
        89,
        PendingSession {
            vm_id: Some("vm".into()),
            boot_id: Some("boot".into()),
            vm_only: false,
        },
    );
    app.resolve_backend_disconnect();
    assert!(app.backend_disconnected);
    assert!(app.pending_launch.is_none());
    assert!(app.pending_core.is_none());
    assert!(app.process_picker.pending.is_none());
    assert!(app.status.contains("No commands were retried"));
}

#[test]
fn pending_binding_cap_rejects_before_submitting_another_control() {
    let mut app = app();
    for id in 1..=PENDING_SESSION_LIMIT as u64 {
        app.pending_sessions.insert(
            id,
            PendingSession {
                vm_id: Some("vm".into()),
                boot_id: Some("boot".into()),
                vm_only: false,
            },
        );
    }

    assert!(app.send_request(Command::ReconnectTransport).is_none());
    assert!(app.submitted.is_empty());
    assert!(app.status.contains("Too many pending VM operations"));
    assert_eq!(app.pending_sessions.len(), PENDING_SESSION_LIMIT);
}
