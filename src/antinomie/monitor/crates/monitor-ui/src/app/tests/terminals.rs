// SPDX-License-Identifier: MIT
//! Terminal journals and launch slots.
use super::*;

#[test]
fn missing_final_screen_preserves_a_valid_terminal_journal_prefix() {
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!("terminal fixture cleanup: {error}");
            }
        }
    }
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture = Fixture(
        std::env::temp_dir().join(format!("ant-ui-terminal-{}-{unique}", std::process::id())),
    );
    std::fs::create_dir(&fixture.0).unwrap();
    std::fs::write(fixture.0.join("manifest.json"), b"{}").unwrap();
    std::fs::write(fixture.0.join("events.json"), b"[]").unwrap();
    let data = b"retained prefix\r\n";
    let mut journal = vec![1];
    journal.extend((data.len() as u32).to_le_bytes());
    journal.extend(data);
    std::fs::write(fixture.0.join("terminal.journal"), journal).unwrap();
    assert!(!fixture.0.join("terminal-screen.ansi").exists());
    let worker = ArchiveWorker::new(None).unwrap();
    let mut app = app();
    let mut history = run("partial");
    history.state = RunState::Finalized;
    history.directory = fixture.0.clone();
    app.reopen(history);
    let generation = app.terminals["partial"].generation;
    worker
        .request(Request::Terminal {
            run_id: "partial".into(),
            generation,
            directory: fixture.0.clone(),
            offset: 0,
        })
        .unwrap();
    let answer = worker
        .wait_answer(Duration::from_secs(5))
        .expect("archive worker must finish the small fixture");
    app.handle_archive_answer(answer);
    assert!(app.terminals["partial"]
        .terminal
        .contents()
        .contains("retained prefix"));
    assert_eq!(app.terminals["partial"].replay_offset, None);
    assert!(app.status.contains("Final terminal screen unavailable"));
    assert!(app.terminals["partial"]
        .replay_error
        .as_ref()
        .unwrap()
        .contains("Final terminal screen unavailable"));
}

#[test]
fn launch_rejects_full_open_history_without_evicting_a_view() {
    let mut app = app();
    for index in 0..TERMINAL_VIEW_LIMIT {
        let mut history = run(&format!("history-{index}"));
        history.state = RunState::Finalized;
        app.terminals
            .insert(history.id.clone(), RunTerminal::new(history));
    }
    assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 0);
    app.send(Command::Execute(ExecRequest::default()));
    assert!(app.status.contains("close a history window"));
    assert!(app.pending_launch.is_none());
    assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
    assert!(app.terminals.values().all(|terminal| terminal.open));
}

#[test]
fn pending_launch_reserves_last_slot_against_history_reopen() {
    let mut app = app();
    for index in 0..TERMINAL_VIEW_LIMIT - 1 {
        let mut history = run(&format!("history-{index}"));
        history.state = RunState::Finalized;
        app.terminals
            .insert(history.id.clone(), RunTerminal::new(history));
    }
    assert!(app.launch_admission().is_ok());
    app.pending_launch = Some(77);
    let mut extra = run("extra-history");
    extra.state = RunState::Finalized;
    app.reopen(extra.clone());
    assert!(!app.terminals.contains_key(&extra.id));
    assert!(app.status.contains("close a history window"));
    resolve_launch_result(&mut app.pending_launch, 77, true);
    assert_eq!(app.pending_launch, Some(77));
    app.reopen(extra);
    assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT - 1);
    let launched = run("launched");
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.runs = vec![launched];
    sync_runs(&mut app.terminals, &app.snapshot);
    assert!(app.terminals["launched"].open);
    assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
}

#[test]
fn closed_history_slot_is_reclaimable_but_cannot_be_reopened_while_reserved() {
    let mut app = app();
    for index in 0..TERMINAL_VIEW_LIMIT {
        let mut history = run(&format!("history-{index}"));
        history.state = RunState::Finalized;
        app.terminals
            .insert(history.id.clone(), RunTerminal::new(history));
    }
    let closed = app.terminals["history-0"].run.clone();
    app.terminals.get_mut(&closed.id).unwrap().close_view();
    assert!(app.launch_admission().is_ok());
    app.pending_launch = Some(77);
    app.reopen(closed.clone());
    assert!(!app.terminals[&closed.id].open);
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.runs = vec![run("launched")];
    sync_runs(&mut app.terminals, &app.snapshot);
    assert!(app.terminals["launched"].open);
    assert!(!app.terminals.contains_key(&closed.id));
    assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
}

#[test]
fn failed_launch_releases_its_reservation_only_for_the_matching_command() {
    let mut app = app();
    for index in 0..TERMINAL_VIEW_LIMIT - 1 {
        let mut history = run(&format!("history-{index}"));
        history.state = RunState::Finalized;
        app.terminals
            .insert(history.id.clone(), RunTerminal::new(history));
    }
    app.pending_launch = Some(77);
    resolve_launch_result(&mut app.pending_launch, 76, false);
    assert_eq!(app.pending_launch, Some(77));
    resolve_launch_result(&mut app.pending_launch, 77, false);
    assert!(app.pending_launch.is_none());
    assert!(app.launch_admission().is_ok());
    let mut extra = run("extra-history");
    extra.state = RunState::Finalized;
    app.reopen(extra);
    assert!(app.terminals["extra-history"].open);
    assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
}
