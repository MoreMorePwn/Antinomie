// SPDX-License-Identifier: GPL-3.0-only
use super::{session_runs::*, *};
use std::collections::BTreeSet;

fn notification_backend() -> (Backend, SyncSender<Notification>) {
    let (commands, _) = mpsc::sync_channel(1);
    let (sender, notifications) = mpsc::sync_channel(4);
    let (_completion_sender, completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    (
        Backend {
            commands,
            notifications,
            completions,
            completion_credits: Arc::new(CompletionCredits::default()),
            admission: Mutex::new(()),
            receive_cursor: AtomicUsize::new(0),
            thread: None,
            data_owner: None,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            owner_failed: Arc::new(AtomicBool::new(false)),
            sequence: AtomicU64::new(0),
            guest_epoch: Arc::new(AtomicU64::new(0)),
            latest_snapshot: Arc::new(Mutex::new(None)),
            debug_link: DebugService::new().1,
        },
        sender,
    )
}

/// The backend handle, the worker's command queue, and its notification and
/// completion senders.
type AdmissionParts = (
    Backend,
    Receiver<(u64, u64, Command)>,
    SyncSender<Notification>,
    SyncSender<Notification>,
);

fn admission_backend() -> AdmissionParts {
    let (commands, queued) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let (sender, notifications) = mpsc::sync_channel(64);
    let (completion_sender, completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let thread = thread::spawn(|| {});
    (
        Backend {
            commands,
            notifications,
            completions,
            completion_credits: Arc::new(CompletionCredits::default()),
            admission: Mutex::new(()),
            receive_cursor: AtomicUsize::new(0),
            thread: Some(thread),
            data_owner: None,
            closing: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            owner_failed: Arc::new(AtomicBool::new(false)),
            sequence: AtomicU64::new(0),
            guest_epoch: Arc::new(AtomicU64::new(0)),
            latest_snapshot: Arc::new(Mutex::new(None)),
            debug_link: DebugService::new().1,
        },
        queued,
        sender,
        completion_sender,
    )
}

#[test]
fn accepted_commands_reserve_bounded_completion_slots_until_results_are_read() {
    let (backend, queued, _preview_sender, completion_sender) = admission_backend();
    for _ in 0..COMMAND_COMPLETION_CAPACITY {
        backend
            .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
            .unwrap();
    }
    assert_eq!(
        backend.completion_credits.in_use(),
        COMMAND_COMPLETION_CAPACITY
    );
    assert_eq!(
        backend
            .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
            .unwrap_err(),
        "backend command completion capacity full"
    );
    assert_eq!(
        backend.completion_credits.in_use(),
        COMMAND_COMPLETION_CAPACITY
    );

    for id in 1..=COMMAND_COMPLETION_CAPACITY as u64 {
        completion_sender
            .try_send(Notification::CommandResult {
                id,
                success: true,
                message: "done".into(),
            })
            .unwrap();
    }
    let mut received = BTreeSet::new();
    for _ in 0..COMMAND_COMPLETION_CAPACITY {
        let Some(Notification::CommandResult { id, .. }) = backend.try_recv_status().unwrap()
        else {
            panic!("an accepted command result was not available");
        };
        assert!(received.insert(id), "duplicate result for command {id}");
    }
    assert_eq!(received.len(), COMMAND_COMPLETION_CAPACITY);
    assert_eq!(backend.completion_credits.in_use(), 0);

    // The queue itself is still full: a rejected send must return its
    // temporary credit. Once the owner has room, admission succeeds again.
    assert_eq!(
        backend
            .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
            .unwrap_err(),
        "backend command queue full"
    );
    assert_eq!(backend.completion_credits.in_use(), 0);
    queued.try_recv().unwrap();
    backend
        .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
        .unwrap();
    assert_eq!(backend.completion_credits.in_use(), 1);
}

#[test]
fn closing_owner_returns_a_result_for_each_accepted_queued_command() {
    let root = std::env::temp_dir().join(format!("ant-close-results-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let (command_sender, receiver) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let (sender, _notifications) = mpsc::sync_channel(64);
    let (completion_sender, completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let completion_credits = Arc::new(CompletionCredits::default());
    for id in 1..=3 {
        assert!(completion_credits.reserve());
        command_sender
            .send((id, 0, Command::RefreshVmSnapshots { vm_id: "vm".into() }))
            .unwrap();
    }
    let owner_failed = Arc::new(AtomicBool::new(false));
    let worker = Worker {
        options: BackendOptions {
            data_dir: root.clone(),
            bundle_dir: root.join("missing-bundle"),
            ..BackendOptions::default()
        },
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender,
        completion_credits: completion_credits.clone(),
        closing: Arc::new(AtomicBool::new(true)),
        stopping: Arc::new(AtomicBool::new(true)),
        owner_failed: owner_failed.clone(),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        wake: None,
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
    };
    worker.run();
    drop(command_sender);

    let results = completions.try_iter().collect::<Vec<_>>();
    assert_eq!(results.len(), 3);
    for (expected, result) in (1..=3).zip(results) {
        assert!(matches!(
            result,
            Notification::CommandResult {
                id,
                success: false,
                ref message,
            } if id == expected && message.contains("outcome cancelled")
        ));
    }
    assert!(!owner_failed.load(Ordering::Acquire));
    assert_eq!(completion_credits.in_use(), 3);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn completion_polling_remains_fair_with_preview_and_coalesced_snapshot_traffic() {
    let (backend, _queued, preview_sender, completion_sender) = admission_backend();
    let id = backend
        .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
        .unwrap();
    for _ in 0..64 {
        preview_sender
            .try_send(Notification::CommandResult {
                id: 0,
                success: true,
                message: "preview".into(),
            })
            .unwrap();
    }
    completion_sender
        .send(Notification::CommandResult {
            id,
            success: true,
            message: "done".into(),
        })
        .unwrap();
    *backend.latest_snapshot.lock().unwrap() = Some(Snapshot::default());
    let mut seen = Vec::new();
    for _ in 0..3 {
        if let Some(notification) = backend.try_recv_status().unwrap() {
            seen.push(notification);
        }
    }
    assert!(
        seen.iter()
            .any(|notification| matches!(notification, Notification::CommandResult { id: 1, .. }))
    );
    assert!(
        seen.iter()
            .any(|notification| matches!(notification, Notification::Snapshot(_)))
    );
}

#[test]
fn inconsistent_completion_credit_enters_explicit_owner_failure_instead_of_wrapping() {
    let (backend, _queued, preview_sender, completion_sender) = admission_backend();
    completion_sender
        .send(Notification::CommandResult {
            id: 999,
            success: true,
            message: "injected invariant violation".into(),
        })
        .unwrap();
    assert!(matches!(
        backend.try_recv_status().unwrap(),
        Some(Notification::CommandResult { id: 999, .. })
    ));
    assert!(backend.owner_failed.load(Ordering::Acquire));
    assert!(
        backend
            .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
            .unwrap_err()
            .contains("owner failed")
    );
    drop(preview_sender);
    drop(completion_sender);
    assert!(
        backend
            .try_recv_status()
            .unwrap_err()
            .contains("remaining outcomes are unknown")
    );
    assert_eq!(backend.completion_credits.in_use(), 0);
}

#[test]
fn full_completion_lane_surfaces_terminal_failure_for_an_accepted_command() {
    let (commands, receiver) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let (sender, notifications) = mpsc::sync_channel(64);
    let (completion_sender, completions) = mpsc::sync_channel(1);
    let completion_credits = Arc::new(CompletionCredits::default());
    let closing = Arc::new(AtomicBool::new(false));
    let stopping = Arc::new(AtomicBool::new(false));
    let owner_failed = Arc::new(AtomicBool::new(false));
    let mut backend = Backend {
        commands,
        notifications,
        completions,
        completion_credits: completion_credits.clone(),
        admission: Mutex::new(()),
        receive_cursor: AtomicUsize::new(0),
        thread: Some(thread::spawn(|| {})),
        data_owner: None,
        closing: closing.clone(),
        stopping: stopping.clone(),
        owner_failed: owner_failed.clone(),
        sequence: AtomicU64::new(0),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        latest_snapshot: Arc::new(Mutex::new(None)),
        debug_link: DebugService::new().1,
    };
    let id = backend
        .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
        .unwrap();
    assert_eq!(id, 1);
    let mut worker = Worker {
        options: BackendOptions::default(),
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender: completion_sender.clone(),
        completion_credits,
        closing,
        stopping,
        owner_failed: owner_failed.clone(),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        wake: None,
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
    };
    completion_sender
        .try_send(Notification::CommandResult {
            id: 999,
            success: true,
            message: "injected lane saturation".into(),
        })
        .unwrap();
    worker.emit(Notification::CommandResult {
        id,
        success: true,
        message: "completed".into(),
    });
    assert!(owner_failed.load(Ordering::Acquire));
    drop(worker);
    drop(completion_sender);

    assert!(matches!(
        backend.try_recv_status().unwrap(),
        Some(Notification::CommandResult { id: 999, .. })
    ));
    assert!(
        backend
            .try_recv_status()
            .unwrap_err()
            .contains("remaining outcomes are unknown")
    );
    assert!(
        backend
            .send(Command::RefreshVmSnapshots { vm_id: "vm".into() })
            .unwrap_err()
            .contains("owner failed")
    );
    backend.shutdown().unwrap();
}

#[test]
fn backend_recv_timeout_distinguishes_quiet_owner_from_disconnection() {
    let (backend, sender) = notification_backend();
    assert!(
        backend
            .recv_timeout(Duration::from_millis(1))
            .unwrap()
            .is_none()
    );
    sender
        .send(Notification::CommandResult {
            id: 42,
            success: true,
            message: "base installed".into(),
        })
        .unwrap();
    drop(sender);
    assert!(matches!(
        backend.recv_timeout(Duration::ZERO).unwrap(),
        Some(Notification::CommandResult {
            id: 42,
            success: true,
            ..
        })
    ));
    assert_eq!(
        backend.recv_timeout(Duration::ZERO).err().as_deref(),
        Some("backend owner disconnected")
    );
}

#[test]
fn backend_recv_timeout_preserves_queue_priority_and_final_coalesced_snapshot() {
    let (backend, sender) = notification_backend();
    *backend.latest_snapshot.lock().unwrap() = Some(Snapshot::default());
    sender
        .send(Notification::CommandResult {
            id: 42,
            success: true,
            message: "base installed".into(),
        })
        .unwrap();
    drop(sender);
    assert!(matches!(
        backend.recv_timeout(Duration::ZERO).unwrap(),
        Some(Notification::CommandResult { id: 42, .. })
    ));
    assert!(matches!(
        backend.recv_timeout(Duration::ZERO).unwrap(),
        Some(Notification::Snapshot(_))
    ));
    assert!(backend.recv_timeout(Duration::ZERO).is_err());
}

fn late_status_owner() -> RunStatusOwner {
    RunStatusOwner {
        cookie: 2,
        run_id: "artifact-run".into(),
        generation: 1,
    }
}

fn late_status_payload(cookie: u64, generation: u64) -> Vec<u8> {
    let mut reply = vec![0; 64];
    for (offset, value) in [(0, cookie), (8, generation), (16, 1), (48, 1)] {
        reply[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    reply[32..36].copy_from_slice(&8u32.to_le_bytes());
    reply
}

#[test]
fn late_status_routes_exact_timeout_while_another_command_is_waiting() {
    let mut poll = RunStatusPoll::default();
    let error = "guest command 364 timed out; outcome unknown".to_string();
    poll.timed_out(364, late_status_owner(), error.clone());
    // A terminal waiter 365 remains unrelated. Repeated unmatched replies
    // neither consume the owner nor grow status correlation state.
    for id in [365, 366, 367] {
        assert!(
            poll.late_reply(id, 0, &[], |_| panic!("unrelated owner checked"))
                .is_none()
        );
        assert_eq!(poll.pending.as_ref().unwrap().0, 364);
    }
    let (owner, execution) = poll
        .late_reply(364, 0, &late_status_payload(2, 2), |owner| {
            owner.cookie == 2 && owner.run_id == "artifact-run" && owner.generation == 1
        })
        .unwrap()
        .unwrap();
    assert_eq!(crate::execution::state(&execution), RunState::Running);
    assert_eq!(execution.generation, 2);
    assert!(poll.pending.is_none());
    let mut last_error = Some(error);
    poll.recovered(owner.cookie, &owner.run_id, &mut last_error);
    assert!(last_error.is_none());
    // A duplicate reply does not become a new exception to mismatch handling.
    assert!(
        poll.late_reply(364, 0, &late_status_payload(2, 2), |_| true)
            .is_none()
    );
}

#[test]
fn late_status_validates_cookie_generation_status_and_exact_wire_extent() {
    for (status, payload) in [
        (0, late_status_payload(3, 2)),
        (0, late_status_payload(2, 0)),
        (-2, late_status_payload(2, 2)),
        (1, late_status_payload(2, 2)),
        (0, vec![0; 63]),
    ] {
        let mut poll = RunStatusPoll::default();
        poll.timed_out(364, late_status_owner(), "timeout".into());
        assert!(
            poll.late_reply(364, status, &payload, |_| true)
                .unwrap()
                .is_err()
        );
        assert!(poll.pending.is_none());
    }
}

#[test]
fn late_status_owner_drift_cannot_overwrite_a_newer_or_different_run() {
    let _disk = storage::slow_disk::SlowDisk::install();
    let root = std::env::temp_dir().join(format!("ant-status-owner-{}", storage::unique_id()));
    let mut run = ProgramRun::new(artifact_run(root.clone()), 1024).unwrap();
    run.execution_generation = 1;
    let owner = late_status_owner();
    assert!(owner.matches(&run));
    for mutation in 0..3 {
        run.summary.id = "artifact-run".into();
        run.summary.root_task_cookie = 2;
        run.execution_generation = 1;
        match mutation {
            0 => run.summary.id = "replacement-run".into(),
            1 => run.summary.root_task_cookie = 3,
            _ => run.execution_generation = 2,
        }
        let mut poll = RunStatusPoll::default();
        poll.timed_out(364, owner.clone(), "timeout".into());
        let error = poll
            .late_reply(364, 0, &late_status_payload(2, 3), |owner| {
                owner.matches(&run)
            })
            .unwrap()
            .err()
            .unwrap();
        assert!(error.contains("owner or execution generation changed"));
        assert_eq!(run.summary.state, RunState::Running);
    }
    drop(run);
    storage::flush_json().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn late_status_reconnect_discards_old_id_but_retains_timeout_recovery_ownership() {
    let mut poll = RunStatusPoll::default();
    poll.timed_out(364, late_status_owner(), "status timeout".into());
    poll.forget_unanswered();
    // A checkpoint-stage failure may keep this Session after the attachment
    // changed. Old IDs must not route into it; fresh polling can resume.
    assert!(poll.pending.is_none());
    assert!(
        poll.late_reply(364, 0, &late_status_payload(2, 2), |_| true)
            .is_none()
    );
    let mut last_error = Some("status timeout".into());
    poll.recovered(2, "artifact-run", &mut last_error);
    assert!(last_error.is_none());

    poll.timed_out(400, late_status_owner(), "status timeout".into());
    poll.forget_unanswered();
    last_error = Some("reconnect checkpoint persistence failed".into());
    poll.recovered(2, "artifact-run", &mut last_error);
    assert_eq!(
        last_error.as_deref(),
        Some("reconnect checkpoint persistence failed")
    );
}

#[test]
fn late_status_recovery_clears_only_the_owned_diagnostic_for_the_same_run() {
    let mut poll = RunStatusPoll::default();
    poll.timed_out(364, late_status_owner(), "status timeout".into());
    let mut last_error = Some("status timeout".into());
    poll.recovered(3, "artifact-run", &mut last_error);
    poll.recovered(2, "different-run", &mut last_error);
    assert_eq!(last_error.as_deref(), Some("status timeout"));
    assert!(poll.diagnostic.is_some());
    last_error = Some("unmatched command reply 999; awaiting 365".into());
    poll.recovered(2, "artifact-run", &mut last_error);
    assert_eq!(
        last_error.as_deref(),
        Some("unmatched command reply 999; awaiting 365")
    );
    assert!(poll.diagnostic.is_none());
    // Session recreation starts with no correlation or diagnostic ownership.
    let fresh = RunStatusPoll::default();
    assert!(fresh.pending.is_none() && fresh.diagnostic.is_none());
}

#[test]
fn lifecycle_qmp_reconciliation_uses_payload_and_preserves_unknown_dump_outcomes() {
    let direct = serde_json::json!([{"name":"manual","type":"child<filter-dump>"}, {"name":"owned","type":"child<filter-dump>"}]);
    assert!(network_filter_present(&direct, "owned").unwrap());
    assert!(!network_filter_present(&direct, "already-deleted").unwrap());
    assert!(network_filter_present(&serde_json::json!({"return":direct}), "owned").is_err());
    assert!(network_filter_present(&serde_json::json!([{}]), "owned").is_err());
    assert!(!qmp_outcome_unknown("QMP error: command rejected"));
    assert!(qmp_outcome_unknown("QMP read: timed out"));
    assert!(qmp_outcome_unknown("QMP connect: socket missing"));
    assert_eq!(
        memory_query_status(&serde_json::json!({"status":"active","completed":3,"total":9}))
            .unwrap(),
        crate::memory::DumpStatus::Active {
            completed: 3,
            total: 9
        }
    );
    assert_eq!(
        memory_query_status(&serde_json::json!({"status":"none"})).unwrap(),
        crate::memory::DumpStatus::None
    );
    assert_eq!(
        memory_query_status(&serde_json::json!({"status":"failed"})).unwrap(),
        crate::memory::DumpStatus::Failed
    );
    assert!(memory_query_status(&serde_json::json!({})).is_err());
    assert!(memory_query_status(&serde_json::json!({"status":"active"})).is_err());
}

#[test]
fn lifecycle_completed_dump_requires_a_regular_nonempty_elf_core() {
    let root = std::env::temp_dir().join(format!("ant-dump-check-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let dump = crate::memory::MemoryDump {
        dir: root.clone(),
        file: "memory.elf".into(),
        ..Default::default()
    };
    assert!(completed_memory_dump_size(&dump).is_err());
    fs::write(dump.path(), b"").unwrap();
    assert!(completed_memory_dump_size(&dump).is_err());
    fs::write(dump.path(), vec![0; 256]).unwrap();
    assert!(completed_memory_dump_size(&dump).is_err());
    let mut elf = vec![0; 128];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&4u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[72..80].copy_from_slice(&120u64.to_le_bytes());
    elf[96..104].copy_from_slice(&8u64.to_le_bytes());
    elf[104..112].copy_from_slice(&8u64.to_le_bytes());
    fs::write(dump.path(), &elf).unwrap();
    assert_eq!(completed_memory_dump_size(&dump).unwrap(), 128);
    // Observed on the installed QEMU physical-memory producer.
    elf[52..54].copy_from_slice(&8u16.to_le_bytes());
    fs::write(dump.path(), &elf).unwrap();
    assert_eq!(completed_memory_dump_size(&dump).unwrap(), 128);
    elf[96..104].copy_from_slice(&32u64.to_le_bytes());
    elf[104..112].copy_from_slice(&32u64.to_le_bytes());
    fs::write(dump.path(), &elf).unwrap();
    assert!(
        completed_memory_dump_size(&dump)
            .unwrap_err()
            .contains("truncated")
    );
    fs::remove_file(dump.path()).unwrap();
    fs::create_dir(dump.path()).unwrap();
    assert!(completed_memory_dump_size(&dump).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn artifact_run(directory: PathBuf) -> RunSummary {
    RunSummary {
        environment: None,
        started_ms: None,
        clock_anchor: None,
        id: "artifact-run".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 2,
        pid: 3,
        request: ExecRequest {
            memory_dump_on_exit: true,
            capture_network: true,
            ..Default::default()
        },
        directory,
        terminal_eof: true,
        state: RunState::Running,
        recording_error: None,
        notes: Vec::new(),
        machine: None,
        route: None,
        execution: None,
        analysis: None,
    }
}

#[test]
fn a_run_started_without_capture_records_that_capture_was_off() {
    let mut run = artifact_run(PathBuf::new());
    assert!(!RunArtifactOwner::new(&run).summary.network_off);
    run.request.capture_network = false;
    let owner = RunArtifactOwner::new(&run);
    assert!(owner.summary.network_off);
    assert_eq!(owner.summary.network_state, RunArtifactState::Disabled);
    // Saved, then read back by the detector; absent on a capturing run.
    let saved = serde_json::to_value(&owner.summary).unwrap();
    assert_eq!(saved["network_off"], true);
    let on = serde_json::to_value(&RunArtifactOwner::new(&artifact_run(PathBuf::new())).summary);
    assert!(on.unwrap().get("network_off").is_none());
    let old: RunArtifacts = serde_json::from_str(
        r#"{"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[],"network_state":"disabled"}"#,
    )
    .unwrap();
    assert!(!old.network_off);
}

#[test]
fn a_runs_route_is_copied_into_its_artifacts_and_old_runs_have_none() {
    let mut run = artifact_run(PathBuf::new());
    assert!(RunArtifactOwner::new(&run).summary.route.is_none());
    run.route = Some(crate::route::RouteRecord {
        kind: crate::route::RouteKind::Tor,
        label: "Tor via 127.0.0.1:9050".into(),
        via: crate::route::RouteVia::Gateway,
        checked_ms: Some(1),
        stats: None,
    });
    let owner = RunArtifactOwner::new(&run);
    assert_eq!(owner.summary.route, run.route);
    // The run that holds no claim has nothing to release.
    assert!(owner.route_claim.is_none());
}

#[test]
fn run_artifacts_wait_for_descendants_and_async_drain_then_queue_once() {
    let run = artifact_run(PathBuf::new());
    let mut owner = RunArtifactOwner::new(&run);
    // Terminal EOF and root exit occur while a detached child still runs.
    let mut status = RunExecution {
        generation: 1,
        live_task_count: 1,
        pending_async_count: 0,
        flags: 1,
        root_wait_status: Some(0),
        root_exit: Some(WaitStatus::Exited { code: 0 }),
        async_loss_count: 0,
        total_task_count: 2,
    };
    assert!(!owner.observe(None));
    assert!(!owner.observe(Some(&status)));
    assert_eq!(
        owner.summary.memory_state,
        RunArtifactState::WaitingForTreeExit
    );
    status.live_task_count = 0;
    status.pending_async_count = 1;
    status.flags = 3;
    assert!(!owner.observe(Some(&status)));
    status.pending_async_count = 0;
    // OBSERVATION_INCOMPLETE without ASYNC_COMPLETE, as every io_uring run
    // reports: the observation was partial, but the tree ended with nothing
    // outstanding, so the exit artifacts go ahead.
    status.flags = 19;
    assert!(owner.observe(Some(&status)));
    assert_eq!(owner.summary.memory_state, RunArtifactState::Queued);
    owner.summary.memory_state = RunArtifactState::Complete;
    assert!(!owner.observe(Some(&status)));
    assert_eq!(owner.summary.memory_state, RunArtifactState::Complete);
}

#[test]
fn run_artifacts_sidecar_load_is_optional_bounded_and_retains_failures() {
    let _disk = storage::slow_disk::SlowDisk::install();
    let root = std::env::temp_dir().join(format!("ant-artifacts-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    assert_eq!(RunArtifacts::load(&root).unwrap(), None);
    let run = artifact_run(root.clone());
    let mut owner = RunArtifactOwner::new(&run);
    owner.summary.memory_dump = Some(root.join("memory/evidence"));
    owner.summary.memory_state = RunArtifactState::Failed;
    owner.issue("disk full".into());
    owner.save().unwrap();
    storage::flush_json().unwrap();
    assert_eq!(RunArtifacts::load(&root).unwrap(), Some(owner.summary));
    fs::write(root.join("artifacts.json"), b"{broken").unwrap();
    assert!(RunArtifacts::load(&root).is_err());
    fs::write(root.join("artifacts.json"), vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(
        RunArtifacts::load(&root)
            .unwrap_err()
            .contains("size limit")
    );
    fs::remove_dir_all(root).unwrap();
}

pub(super) fn download_worker(root: PathBuf) -> Worker {
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(1);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    Worker {
        options: BackendOptions {
            bundle_dir: root.join("missing-bundle"),
            data_dir: root,
            ..BackendOptions::default()
        },
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
        wake: None,
    }
}

#[test]
fn frontend_is_woken_for_worker_notifications_without_holding_snapshot_lock() {
    let mut worker = download_worker(std::env::temp_dir());
    let snapshot = Arc::clone(&worker.latest_snapshot);
    let wakes = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&wakes);
    worker.wake = Some(Arc::new(move || {
        assert!(
            snapshot.try_lock().is_ok(),
            "callback must not run under the snapshot lock"
        );
        observed.fetch_add(1, Ordering::Relaxed);
    }));
    worker.publish();
    worker.emit(Notification::CommandResult {
        id: 0,
        success: true,
        message: "ready".into(),
    });
    assert_eq!(wakes.load(Ordering::Relaxed), 2);
}

fn attach_waiting_download(worker: &mut Worker) -> Arc<AtomicBool> {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let (sender, done) = mpsc::channel();
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !worker_cancel.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            worker_cancel.load(Ordering::Relaxed),
            "download was never cancelled"
        );
        worker_stopped.store(true, Ordering::Relaxed);
        sender.send(Err("download cancelled".into())).unwrap();
    });
    worker.download = Some(DownloadJob {
        identity: "test".into(),
        label: "Test".into(),
        total: 100,
        progress: Arc::new(Mutex::new((20, false))),
        cancel,
        done,
        thread,
    });
    worker.snapshot.download = Some(DownloadStatus {
        identity: "test".into(),
        label: "Test".into(),
        received: 20,
        total: 100,
        ..DownloadStatus::default()
    });
    stopped
}

#[test]
fn snapshot_epoch_cancels_queued_guest_effects_and_keeps_host_actions() {
    let root = std::env::temp_dir().join(format!("ant-epoch-{}", storage::unique_id()));
    let mut worker = download_worker(root);
    let epoch = worker.guest_epoch.load(Ordering::Acquire);
    let transition = worker.begin_guest_transition().unwrap();
    let during = worker.guest_epoch.load(Ordering::Acquire);
    drop(transition);
    let error = worker
        .command_at_epoch(
            epoch,
            Command::Upload {
                source: "unused".into(),
                destination: "/tmp/unused".into(),
                overwrite: false,
                executable: false,
            },
        )
        .unwrap_err();
    assert!(error.contains("cancelled at snapshot/reconnect boundary"));
    assert_eq!(
        worker
            .command_at_epoch(epoch, Command::CancelDownload)
            .unwrap_err(),
        "no base download is running"
    );
    let error = worker
        .command_at_epoch(during, Command::CaptureAll)
        .unwrap_err();
    assert!(error.contains("cancelled at snapshot/reconnect boundary"));
    assert_eq!(worker.guest_epoch.load(Ordering::Acquire), epoch + 2);
}
#[test]
fn data_owner_excludes_other_app_and_releases_on_drop() {
    let root = std::env::temp_dir().join(format!("ant-owner-{}", storage::unique_id()));
    fs::create_dir(&root).unwrap();
    let owner = acquire_data_owner(&root).unwrap();
    assert!(acquire_data_owner(&root).is_err());
    drop(owner);
    assert!(acquire_data_owner(&root).is_ok());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cancel_download_finishes_without_an_error_alert() {
    let root = std::env::temp_dir().join(format!("ant-cancel-{}", storage::unique_id()));
    let mut worker = download_worker(root);
    attach_waiting_download(&mut worker);
    worker.command(Command::CancelDownload).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while worker.download.is_some() && Instant::now() < deadline {
        worker.poll_remote();
        thread::sleep(Duration::from_millis(5));
    }
    assert!(worker.download.is_none());
    let status = worker.snapshot.download.unwrap();
    assert!(status.finished);
    assert_eq!(status.error.as_deref(), Some("download cancelled"));
    assert!(worker.snapshot.last_error.is_none());
}

#[test]
fn shutdown_cancels_and_joins_the_download_worker() {
    let root = std::env::temp_dir().join(format!("ant-close-download-{}", storage::unique_id()));
    let mut worker = download_worker(root);
    let stopped = attach_waiting_download(&mut worker);
    worker.closing.store(true, Ordering::Relaxed);
    worker.run();
    assert!(stopped.load(Ordering::Relaxed));
}

#[test]
fn cancellation_and_installation_have_an_exclusive_transition() {
    let progress = Mutex::new((100, false));
    let cancel = AtomicBool::new(true);
    assert_eq!(
        begin_base_install(&progress, &cancel).unwrap_err(),
        "download cancelled"
    );
    assert!(!progress.lock().unwrap().1);
    cancel.store(false, Ordering::Relaxed);
    begin_base_install(&progress, &cancel).unwrap();
    assert!(progress.lock().unwrap().1);
    let root = std::env::temp_dir().join(format!("ant-install-gate-{}", storage::unique_id()));
    let mut worker = download_worker(root);
    attach_waiting_download(&mut worker);
    let job = worker.download.as_ref().unwrap();
    begin_base_install(&job.progress, &job.cancel).unwrap();
    assert!(
        worker
            .command(Command::CancelDownload)
            .unwrap_err()
            .contains("installation")
    );
    assert!(
        !worker
            .download
            .as_ref()
            .unwrap()
            .cancel
            .load(Ordering::Relaxed)
    );
    worker.closing.store(true, Ordering::Relaxed);
    worker.run();
}

#[test]
fn startup_base_error_is_published_after_backend_construction() {
    let root = std::env::temp_dir().join(format!("ant-base-startup-{}", storage::unique_id()));
    fs::create_dir_all(root.join("bases/bad")).unwrap();
    fs::write(root.join("bases/bad/bundle.json"), b"invalid json").unwrap();
    let mut backend = Backend::new(BackendOptions {
        data_dir: root.clone(),
        bundle_dir: root.join("missing"),
        ..BackendOptions::default()
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let snapshot = loop {
        if let Some(Notification::Snapshot(snapshot)) = backend.try_recv()
            && !snapshot.bases_checking
        {
            break snapshot;
        }
        assert!(Instant::now() < deadline, "base check never completed");
        thread::sleep(Duration::from_millis(5));
    };
    assert!(snapshot.bases.is_empty());
    assert!(snapshot.last_error.unwrap().starts_with("base images:"));
    backend.shutdown().unwrap();
    fs::remove_dir_all(root).unwrap();
}

fn history_event(sequence: u64, path: &str) -> EventSummary {
    EventSummary {
        root_task_cookie: 99,
        stream_id: 1,
        task_cookie: 2,
        call_id: 3,
        event_seq: sequence,
        phase: 1,
        syscall_nr: 1,
        syscall_name: "write".into(),
        pid: 7,
        tid: 7,
        cpu: 0,
        timestamp_ns: sequence,
        args: None,
        result: None,
        complete: false,
        issues: Vec::new(),
        fields: vec![FieldSummary {
            arg: None,
            object_id: 1,
            key: "buffer".into(),
            layout: "bytes".into(),
            logical_len: Some(1),
            captured_len: 1,
            status: None,
            capture_error: 0,
            complete: true,
            preview: vec![1],
            raw_path: Some(path.into()),
            ranges: vec![(0, 1)],
            recapture: None,
            encoding: None,
        }],
    }
}
#[test]
fn canonical_history_deduplicates_pre_ack_packets_and_prefers_run_artifacts() {
    let boot = history_event(1, "boot/object");
    let mut run = history_event(1, "run/object");
    run.cpu = 3;
    run.complete = true;
    let mut exit = history_event(1, "run/exit-object");
    exit.phase = 2;
    let mut other_task = history_event(1, "run/other-task");
    other_task.task_cookie = 8;
    let events = canonical_live_history(vec![boot], [vec![run, exit, other_task]]);
    assert_eq!(events.len(), 3);
    let entry = events
        .iter()
        .find(|event| event.task_cookie == 2 && event.phase == 1)
        .unwrap();
    assert!(entry.complete);
    assert_eq!(entry.cpu, 3);
    assert_eq!(
        entry.fields[0].raw_path.as_deref(),
        Some(std::path::Path::new("run/object"))
    );
}
#[test]
fn capture_preview_drops_oldest_evicted_rows_at_the_total_limit() {
    let mut events: Vec<_> = (0..2112)
        .map(|sequence| history_event(sequence, "capture/object"))
        .collect();
    events.reverse();
    let preview = bounded_live_history(events);
    assert_eq!(preview.len(), 2048);
    assert_eq!(preview.first().unwrap().event_seq, 64);
    assert_eq!(preview.last().unwrap().event_seq, 2111);
}
#[test]
fn invalid_launch_settings_are_rejected_before_lifecycle_io() {
    let root = std::env::temp_dir().join(format!("ant-launch-invalid-{}", storage::unique_id()));
    let vm = VmConfig {
        id: "invalid-launch".into(),
        launch: VmLaunchOptions {
            acceleration: VmAcceleration::Kvm,
            cpu_model: VmCpuModel::Host,
            ..VmLaunchOptions::default()
        },
        ..VmConfig::default()
    };
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(1);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let mut worker = Worker {
        options: BackendOptions {
            data_dir: root.clone(),
            force_tcg: true,
            ..BackendOptions::default()
        },
        snapshot: Snapshot {
            vms: vec![vm.clone()],
            ..Snapshot::default()
        },
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
        wake: None,
    };
    for command in [
        Command::Create(VmConfig {
            id: "new-launch".into(),
            ..vm.clone()
        }),
        Command::Save(vm.clone()),
        Command::Start {
            vm_id: vm.id.clone(),
        },
        Command::Duplicate {
            vm_id: vm.id.clone(),
            name: "Copy".into(),
        },
    ] {
        assert!(
            worker
                .command(command)
                .unwrap_err()
                .contains("requires KVM")
        );
        assert_eq!(worker.snapshot.vms, vec![vm.clone()]);
        assert!(worker.snapshot.active_vm.is_none());
        assert!(!root.exists());
    }
    let mut explicit_tcg = vm.clone();
    explicit_tcg.launch.acceleration = VmAcceleration::Tcg;
    worker.options.force_tcg = false;
    assert!(
        worker
            .command(Command::Save(explicit_tcg))
            .unwrap_err()
            .contains("requires KVM")
    );
}

#[test]
fn fixed_display_guards_selected_boot_without_changing_pinned_disk() {
    let root = std::env::temp_dir().join(format!("ant-fixed-capability-{}", storage::unique_id()));
    let source = root.join("source");
    storage::private_dir(&source).unwrap();
    fs::write(source.join("kernel"), b"fixture kernel").unwrap();
    assert!(
        std::process::Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(source.join("base.qcow2"))
            .arg("1M")
            .output()
            .unwrap()
            .status
            .success()
    );
    let options = BackendOptions {
        data_dir: root.join("data"),
        headless: true,
        ..BackendOptions::default()
    };
    let legacy: Bundle = serde_json::from_value(serde_json::json!({
        "kernel": source.join("kernel"), "base_disk": source.join("base.qcow2"),
        "kernel_version": "6.12.94", "initrd": null
    }))
    .unwrap();
    let legacy = legacy.install(&options).unwrap();
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(1);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let mut worker = Worker {
        options,
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
        wake: None,
    };
    worker
        .command(Command::Create(VmConfig {
            id: "old-disk".into(),
            ..VmConfig::default()
        }))
        .unwrap();
    let mut vm = worker.snapshot.vms[0].clone();
    vm.launch.resolution = crate::DisplayResolution::R1280x720;
    let directory = storage::vm_dir(&worker.options, &vm.id).unwrap();
    storage::atomic_json(&directory.join("config.json"), &vm).unwrap();
    worker.snapshot.vms[0] = vm.clone();
    let config = fs::read(directory.join("config.json")).unwrap();
    let disk = fs::read(directory.join("disk.qcow2")).unwrap();
    for command in [
        Command::Create(VmConfig {
            id: "rejected-fixed".into(),
            ..vm.clone()
        }),
        Command::Save(vm.clone()),
        Command::Start {
            vm_id: vm.id.clone(),
        },
        Command::Duplicate {
            vm_id: vm.id.clone(),
            name: "Rejected duplicate".into(),
        },
    ] {
        assert!(
            worker
                .command(command)
                .unwrap_err()
                .contains("does not support fixed display")
        );
        assert_eq!(worker.snapshot.vms, vec![vm.clone()]);
        assert!(worker.snapshot.active_vm.is_none());
        assert!(worker.session.is_none());
        assert_eq!(fs::read(directory.join("config.json")).unwrap(), config);
        assert_eq!(fs::read(directory.join("disk.qcow2")).unwrap(), disk);
    }
    let mut capable = legacy.clone();
    capable.fixed_display = true;
    let capable = capable.install(&worker.options).unwrap();
    assert_ne!(capable.base_identity, legacy.base_identity);
    vm.base_identity = capable.base_identity;
    worker.command(Command::Save(vm.clone())).unwrap();
    let pinned: Bundle = storage::read_json(&directory.join("bundle.json")).unwrap();
    assert_eq!(pinned.base_identity, legacy.base_identity);
    assert!(!pinned.fixed_display);
    assert_eq!(fs::read(directory.join("disk.qcow2")).unwrap(), disk);
    worker
        .command(Command::Duplicate {
            vm_id: vm.id.clone(),
            name: "Compatible copy".into(),
        })
        .unwrap();
    assert!(
        worker
            .snapshot
            .vms
            .iter()
            .all(|item| item.launch == vm.launch && item.base_identity == vm.base_identity)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn base_import_and_failed_credential_creation_preserve_published_state() {
    let root = std::env::temp_dir().join(format!("ant-credential-create-{}", storage::unique_id()));
    let options = BackendOptions {
        data_dir: root.join("data"),
        ..BackendOptions::default()
    };
    storage::private_dir(&options.data_dir).unwrap();
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(1);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let mut worker = Worker {
        options,
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
        wake: None,
    };
    for guest in [false, true] {
        let source = root.join(if guest { "debian" } else { "busybox" });
        storage::private_dir(&source).unwrap();
        fs::write(source.join("kernel"), b"kernel fixture").unwrap();
        assert!(
            std::process::Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(source.join("base.qcow2"))
                .arg("1M")
                .output()
                .unwrap()
                .status
                .success()
        );
        let bundle = Bundle {
            kernel: source.join("kernel"),
            base_disk: source.join("base.qcow2"),
            initrd: None,
            kernel_append: String::new(),
            kernel_version: "6.12.94".into(),
            schema_id: 1,
            base_identity: None,
            guest: guest.then(|| GuestProfile {
                id: "debian-xfce".into(),
                label: "Debian 13 (Xfce)".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                requires_credentials: true,
                graphical: true,
            }),
            fixed_display: false,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
            symbols: None,
            stealth_support: Vec::new(),
            uefi: Default::default(),
        };
        storage::atomic_json(&source.join("bundle.json"), &bundle).unwrap();
        worker
            .command(Command::ImportBase { directory: source })
            .unwrap();
    }
    assert_eq!(worker.snapshot.bases.len(), 2);
    let newer = root.join("busybox");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(newer.join("bundle.json")).unwrap()).unwrap();
    manifest["antinomie_revision"] = (APP_REVISION + 1).into();
    manifest["antinomie_source"] = "e".repeat(64).into();
    fs::write(
        newer.join("bundle.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let error = worker
        .command(Command::ImportBase { directory: newer })
        .unwrap_err();
    assert!(error.contains("update Antinomie"), "{error}");
    assert_eq!(worker.snapshot.bases.len(), 2);
    assert!(
        crate::locations::boot_bundle(&worker.options, None)
            .unwrap()
            .guest
            .is_none()
    );
    let identity = worker
        .snapshot
        .bases
        .iter()
        .find(|base| base.guest.is_some())
        .unwrap()
        .id
        .clone();
    let vm = VmConfig {
        id: "new-debian".into(),
        base_identity: Some(identity),
        ..VmConfig::default()
    };
    assert!(
        worker
            .command(Command::Create(vm.clone()))
            .unwrap_err()
            .contains("required")
    );
    crate::guest_account::fail_next_provision();
    let secret = "private-creation-password";
    let error = worker
        .command(Command::CreateWithCredentials {
            vm: vm.clone(),
            credentials: GuestCredentials::new("analyst".into(), secret.into()).unwrap(),
        })
        .unwrap_err();
    assert!(!error.contains(secret));
    assert!(!worker.options.data_dir.join(&vm.id).exists());
    assert!(worker.snapshot.vms.is_empty());
    assert!(storage::load_vms(&worker.options).unwrap().is_empty());
    assert_eq!(
        crate::locations::installed_bases(&worker.options)
            .unwrap()
            .len(),
        2
    );
    assert!(root.join("debian/base.qcow2").is_file());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn running_vm_duplicate_and_delete_guards_preserve_data() {
    let root = std::env::temp_dir().join(format!("ant-vm-guards-{}", storage::unique_id()));
    let options = BackendOptions {
        data_dir: root.clone(),
        ..BackendOptions::default()
    };
    let vm = VmConfig {
        id: "source".into(),
        ..VmConfig::default()
    };
    storage::private_dir(&root.join(&vm.id)).unwrap();
    storage::atomic_json(&root.join(&vm.id).join("config.json"), &vm).unwrap();
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(1);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    let mut worker = Worker {
        options,
        snapshot: Snapshot {
            vms: vec![vm.clone()],
            active_vm: Some(vm.id.clone()),
            state: VmState::Running,
            ..Snapshot::default()
        },
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: DebugService::new().0,
        evidence: Default::default(),
        wake: None,
    };
    assert!(
        worker
            .command(Command::Create(VmConfig::default()))
            .unwrap_err()
            .contains("stop")
    );
    assert!(
        worker
            .command(Command::CreateWithCredentials {
                vm: VmConfig::default(),
                credentials: GuestCredentials::new("analyst".into(), "fixturepassword".into())
                    .unwrap(),
            })
            .unwrap_err()
            .contains("stop")
    );
    assert!(
        worker
            .command(Command::ImportBase {
                directory: root.join("missing-base"),
            })
            .unwrap_err()
            .contains("stop")
    );
    assert!(
        worker
            .command(Command::Duplicate {
                vm_id: vm.id.clone(),
                name: "Copy".into()
            })
            .unwrap_err()
            .contains("stop")
    );
    assert!(
        worker
            .command(Command::Delete {
                vm_id: vm.id.clone(),
                confirmed: false
            })
            .unwrap_err()
            .contains("confirmation")
    );
    assert!(
        worker
            .command(Command::Delete {
                vm_id: vm.id.clone(),
                confirmed: true
            })
            .unwrap_err()
            .contains("stop")
    );
    worker
        .command(Command::Rename {
            vm_id: vm.id.clone(),
            name: "Renamed".into(),
        })
        .unwrap();
    assert_eq!(worker.snapshot.vms[0].id, vm.id);
    assert_eq!(worker.snapshot.vms[0].name, "Renamed");
    assert!(root.join(&vm.id).join("config.json").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn pending_raw_copy_quota_failure_stops_existing_and_acknowledged_runs() {
    let root =
        std::env::temp_dir().join(format!("ant-pending-copy-quota-{}", storage::unique_id()));
    let mut capture = RawCapture::new(root.join("unassigned"), 1024).unwrap();
    let mut assembler = Assembler::new(capture.directory.join("objects"), 1024).unwrap();
    let create = |cookie: u64| {
        ProgramRun::new(
            RunSummary {
                environment: None,
                started_ms: None,
                clock_anchor: None,
                id: cookie.to_string(),
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                session_id: cookie,
                root_task_cookie: cookie,
                pid: cookie as u32,
                request: ExecRequest::default(),
                directory: root.join(cookie.to_string()),
                terminal_eof: false,
                state: RunState::Running,
                recording_error: None,
                notes: Vec::new(),
                machine: None,
                route: None,
                execution: None,
                analysis: None,
            },
            1024,
        )
        .unwrap()
    };
    let mut runs = BTreeMap::from([(1, create(1))]);
    let mut pending = create(2);
    assert!(capture.append(&[0; 696]));
    let packet = [1; 236];
    assert!(capture.append(&packet));
    let retained = fs::read(capture.directory.join("telemetry.raw")).unwrap();
    assert!(!pending.capture.append_with_reserved(&packet, capture.bytes));
    let error = pending.capture.error.clone().unwrap();
    pending.storage_error(error.clone());
    stop_capture_saving(&mut capture, &mut assembler, &mut runs, error.clone());
    assert!(pending.assembler.saving_error().is_none());
    runs.insert(2, pending);
    for run in runs.values_mut() {
        assert!(run.output(b"still live", 84).is_err());
        assert_eq!(run.summary.recording_error.as_deref(), Some(error.as_str()));
        assert_eq!(run.capture.bytes, 0);
    }
    assert!(!capture.append(b"later"));
    assert_eq!(
        fs::read(capture.directory.join("telemetry.raw")).unwrap(),
        retained
    );
    let mut health = Health::default();
    refresh_storage_health(&mut health, &capture, assembler.stored_len(), &runs);
    assert_eq!(health.persisted_len, 940);
    assert_eq!(health.persistence_error.as_deref(), Some(error.as_str()));
    drop(runs);
    drop(capture);
    // Run summaries are written in the background; settle them first.
    storage::settle_json_under(&root);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn object_saving_failure_preserves_raw_and_globally_denies_terminal_saving() {
    for run_owned in [false, true] {
        for io_failure in [false, true] {
            let test_writer = crate::writer::held::SlowWriter::install();
            test_writer.pause();
            let root = std::env::temp_dir()
                .join(format!("ant-global-object-saving-{}", storage::unique_id()));
            let mut capture = RawCapture::new(root.join("unassigned"), 1024).unwrap();
            let mut assembler = Assembler::new(capture.directory.join("objects"), 1024).unwrap();
            let mut runs = BTreeMap::new();
            for cookie in 1..=2 {
                let run = ProgramRun::new(
                    RunSummary {
                        environment: None,
                        started_ms: None,
                        clock_anchor: None,
                        id: cookie.to_string(),
                        vm_id: "vm".into(),
                        boot_id: "boot".into(),
                        session_id: cookie,
                        root_task_cookie: cookie,
                        pid: cookie as u32,
                        request: ExecRequest::default(),
                        directory: root.join(cookie.to_string()),
                        terminal_eof: false,
                        state: RunState::Running,
                        recording_error: None,
                        notes: Vec::new(),
                        machine: None,
                        route: None,
                        execution: None,
                        analysis: None,
                    },
                    1024,
                )
                .unwrap();
                runs.insert(cookie, run);
            }
            assert!(capture.append_with_reserved(&[0; 696], 0));
            let mut packet = vec![0; 236];
            packet[..4].copy_from_slice(b"ANTT");
            packet[4..6].copy_from_slice(&1u16.to_le_bytes());
            packet[6..8].copy_from_slice(&1u16.to_le_bytes());
            packet[8..10].copy_from_slice(&136u16.to_le_bytes());
            packet[10..12].copy_from_slice(&1u16.to_le_bytes());
            packet[12..16].copy_from_slice(&236u32.to_le_bytes());
            packet[20..24].copy_from_slice(&1u32.to_le_bytes());
            packet[96..98].copy_from_slice(&1u16.to_le_bytes());
            packet[98] = 1;
            packet[99] = 3;
            packet[100..104].copy_from_slice(&1u32.to_le_bytes());
            packet[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
            packet[120..124].copy_from_slice(&100u32.to_le_bytes());
            packet[128..136].copy_from_slice(&(if run_owned { 1u64 } else { 0 }).to_le_bytes());
            let target = if run_owned {
                let run = runs.get_mut(&1).unwrap();
                assert!(run.capture.append_with_reserved(&packet, 700));
                &mut run.assembler
            } else {
                assert!(capture.append_with_reserved(&packet, 0));
                &mut assembler
            };
            target.set_storage_limit(if io_failure { 1024 } else { 84 });
            let event = target.ingest(&packet).unwrap().unwrap();
            // A queued write failure arrives after ingest has reported the range.
            assert_eq!(event.fields[0].ranges.is_empty(), !io_failure);
            target.flush();
            if io_failure {
                crate::writer::fail_next_write_at();
            }
            test_writer.resume();
            crate::writer::barrier();
            propagate_object_saving_failure(&mut capture, &mut assembler, &mut runs);
            let error = capture.error.clone().unwrap_or_else(|| {
                panic!("capture error missing for run_owned={run_owned}, io_failure={io_failure}")
            });
            assert!(error.contains(if io_failure { "persistence" } else { "quota" }));
            let mut health = Health::default();
            refresh_storage_health(&mut health, &capture, assembler.stored_len(), &runs);
            // A chunk's payload and packed index records are counted when queued.
            assert_eq!(health.persisted_len, if io_failure { 1123 } else { 940 });
            assert_eq!(health.persistence_error.as_deref(), Some(error.as_str()));
            for run in runs.values_mut() {
                assert_eq!(run.summary.recording_error.as_deref(), Some(error.as_str()));
                assert!(run.output(b"ten bytes!", 84).is_err());
                assert_eq!(
                    fs::metadata(run.summary.directory.join("terminal.journal"))
                        .unwrap()
                        .len(),
                    0
                );
                run.finalize(84, "stopped", &health).unwrap_err();
                let manifest: serde_json::Value = serde_json::from_reader(
                    File::open(run.summary.directory.join("manifest.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(manifest["persistence_error"], error);
                assert_eq!(manifest["health"]["persistence_error"], error);
            }
            assert!(!capture.append_with_reserved(b"later", 0));
            assert!(capture.flush());
            crate::writer::barrier();
            assert_eq!(
                capture.bytes + runs.values().map(|run| run.capture.bytes).sum::<u64>(),
                940
            );
            assert_eq!(
                fs::metadata(capture.directory.join("telemetry.raw"))
                    .unwrap()
                    .len(),
                capture.bytes
            );
            drop(runs);
            drop(capture);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
#[test]
fn final_health_counts_screen_and_keeps_errors_scoped_to_run() {
    let root = std::env::temp_dir().join(format!("ant-final-health-{}", storage::unique_id()));
    let capture = RawCapture::new(root.join("unassigned"), 65536).unwrap();
    let create = |id: &str, cookie: u64| {
        ProgramRun::new(
            RunSummary {
                environment: None,
                started_ms: None,
                clock_anchor: None,
                id: id.into(),
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                session_id: cookie,
                root_task_cookie: cookie,
                pid: cookie as u32,
                request: ExecRequest::default(),
                directory: root.join(id),
                terminal_eof: false,
                state: RunState::Running,
                recording_error: None,
                notes: Vec::new(),
                machine: None,
                route: None,
                execution: None,
                analysis: None,
            },
            65536,
        )
        .unwrap()
    };
    let mut healthy = create("healthy", 1);
    healthy.output(b"retained", 65536).unwrap();
    let before = healthy.stored_len();
    healthy
        .finalize(65536, "clean", &Health::default())
        .unwrap();
    let screen_len = fs::metadata(healthy.summary.directory.join("terminal-screen.ansi"))
        .unwrap()
        .len();
    assert_eq!(healthy.stored_len(), before + screen_len);
    let mut failed = create("failed", 2);
    failed.storage_error("only this run failed");
    let mut runs = BTreeMap::from([(1, healthy), (2, failed)]);
    let mut health = Health {
        persisted_len: before,
        ..Health::default()
    };
    refresh_storage_health(&mut health, &capture, 0, &runs);
    assert_eq!(health.persisted_len, before + screen_len);
    assert_eq!(
        health.persistence_error.as_deref(),
        Some("only this run failed")
    );
    assert!(runs.get(&1).unwrap().summary.recording_error.is_none());
    let mut capture = capture;
    capture.final_health = Some(health.clone());
    let bundle = Bundle {
        kernel: "kernel".into(),
        base_disk: "base".into(),
        initrd: None,
        kernel_append: String::new(),
        kernel_version: String::new(),
        schema_id: 1,
        base_identity: None,
        guest: None,
        fixed_display: false,
        build_provenance: None,
        antinomie_revision: None,
        antinomie_source: None,
        built_with: None,
        min_app_version: None,
        name: None,
        symbols: None,
        stealth_support: Vec::new(),
        uefi: Default::default(),
    };
    capture
        .manifest(&VmConfig::default(), &bundle, &bundle, "clean")
        .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_reader(File::open(capture.directory.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["health"]["persisted_len"], before + screen_len);
    assert_eq!(
        manifest["health"]["persistence_error"],
        "only this run failed"
    );
    assert!(manifest["persistence_error"].is_null());
    runs.clear();
    drop(capture);
    // Queued writes of the runs land before their folders go.
    crate::writer::barrier();
    storage::settle_json_under(&root);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn backend_close_joins_owner_without_a_vm() {
    let data_dir = std::env::temp_dir().join(format!("ant-backend-{}", storage::unique_id()));
    let mut backend = Backend::new(BackendOptions {
        data_dir: data_dir.clone(),
        ..BackendOptions::default()
    })
    .unwrap();
    backend.shutdown().unwrap();
    assert!(backend.thread.is_none());
    assert!(backend.send(Command::Stop).is_err());
    fs::remove_dir_all(data_dir).unwrap();
}
#[test]
fn shutdown_request_budget_saturates_at_shared_deadline() {
    let now = Instant::now();
    assert!(
        remaining_request_budget(now - Duration::from_millis(1), Duration::from_secs(2)).is_zero()
    );
    assert!(
        remaining_request_budget(now + Duration::from_millis(100), Duration::from_secs(2))
            <= Duration::from_millis(100)
    );
    assert_eq!(
        remaining_request_budget(now + Duration::from_secs(10), Duration::from_secs(1)),
        Duration::from_secs(1)
    );
}

#[test]
fn stopping_ends_a_pending_reconnection_of_the_boot() {
    let root = std::env::temp_dir().join(format!("ant-reconnect-{}", storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    let mut worker = download_worker(root.clone());
    // Failed attempts and a scheduled retry left over from a stalled boot.
    worker.reconnect = (3, Some(Instant::now()));
    worker.stop().unwrap();
    assert_eq!(
        worker.reconnect,
        (0, None),
        "the next boot starts without the stalled boot's reconnection"
    );
    let _ = std::fs::remove_dir_all(root);
}

fn command_answer(backend: &Backend, id: u64) -> (bool, String) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(Notification::CommandResult {
            id: answered,
            success,
            message,
        }) = backend.try_recv()
            && answered == id
        {
            return (success, message);
        }
        assert!(Instant::now() < deadline, "no answer to the command");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn delete_evidence_runs_in_the_backend_inside_the_vms_recording_folder() {
    let root = std::env::temp_dir().join(format!("ant-delete-evidence-{}", storage::unique_id()));
    let recordings = root.join("vm-a");
    let network = recordings.join("boots/b1/network");
    fs::create_dir_all(&network).unwrap();
    fs::write(network.join("c1.pcap"), vec![7u8; 512]).unwrap();
    fs::write(network.join("c1.json"), b"{}").unwrap();
    let vm = VmConfig {
        id: "vm-a".into(),
        ..VmConfig::default()
    };
    storage::atomic_json(&recordings.join("config.json"), &vm).unwrap();
    let outside = root.join("victim.pcap");
    fs::write(&outside, b"keep").unwrap();
    let mut backend = Backend::new(BackendOptions {
        data_dir: root.clone(),
        bundle_dir: root.join("missing"),
        ..BackendOptions::default()
    })
    .unwrap();
    let item = |file: PathBuf| crate::EvidenceItem::NetworkCapture { file };
    let send = |file: PathBuf, confirmed: bool| {
        backend
            .send(Command::DeleteEvidence {
                vm_id: "vm-a".into(),
                item: item(file),
                confirmed,
            })
            .unwrap()
    };
    let id = send(network.join("c1.pcap"), false);
    let (success, message) = command_answer(&backend, id);
    assert!(!success && message.contains("confirmation"), "{message}");
    assert!(network.join("c1.pcap").exists());
    let id = send(outside.clone(), true);
    let (success, message) = command_answer(&backend, id);
    assert!(!success && message.contains("outside"), "{message}");
    assert!(outside.exists());
    // A run record that names the capture is rewritten by the deletion. The
    // disk waits for it (unlink, fsync) happen on the deletion thread, never
    // on the thread that drains telemetry and answers commands.
    let run = recordings.join("runs/r1");
    fs::create_dir_all(&run).unwrap();
    storage::atomic_json(
        &run.join("artifacts.json"),
        &RunArtifacts {
            boot_id: "b1".into(),
            network_captures: vec![network.join("c1.pcap")],
            network_state: RunArtifactState::Complete,
            ..RunArtifacts::default()
        },
    )
    .unwrap();
    let sync_writes = storage::transport_sync_writes();
    let id = send(network.join("c1.pcap"), true);
    // A second deletion queued behind it answers in order, with its own result.
    let again = send(network.join("c1.pcap"), true);
    let (success, message) = command_answer(&backend, id);
    assert!(success, "{message}");
    assert!(message.contains("Deleted network capture c1"), "{message}");
    let (success, message) = command_answer(&backend, again);
    assert!(!success, "{message}");
    assert!(!network.join("c1.pcap").exists() && !network.join("c1.json").exists());
    let artifacts = RunArtifacts::load(&run).unwrap().unwrap();
    assert!(artifacts.network_captures.is_empty() && artifacts.network_deleted);
    assert_eq!(
        storage::transport_sync_writes(),
        sync_writes,
        "DeleteEvidence did not fsync on the transport thread"
    );
    backend.shutdown().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_guest_lost_counter_reaches_health_and_never_goes_down() {
    use crate::kernel_notes::tests::lost_note;
    let mut health = Health::default();
    for lost in [3, 9, 4] {
        note_guest_loss(&mut health, Some(&lost_note(lost)));
    }
    note_guest_loss(&mut health, None);
    assert_eq!(health.guest_note_lost, 9);
}

#[test]
fn only_the_launched_images_own_exec_hash_can_vouch_for_a_host_copy() {
    use crate::kernel_notes::tests::lost_note;
    let mut event = lost_note(0);
    // The hash of a file some later call executed is not the launch image's.
    assert!(session_transport::launch_image_hash(&event).is_none());
    event.call_id = 0;
    let hash = session_transport::launch_image_hash(&event).unwrap();
    assert!(hash.sha256_hex().is_some_and(|hex| hex.len() == 64));
    // A script's interpreter, or a file that changed while it was read, does
    // not name the file that was uploaded.
    for flag in [1, 2] {
        let mut other = event.clone();
        other.fields[0].preview[3] = flag;
        let hash = session_transport::launch_image_hash(&other).unwrap();
        assert!(hash.sha256_hex().is_none());
    }
    // A delete record is not an exec record.
    event.fields[0].preview[0] = 2;
    assert!(session_transport::launch_image_hash(&event).is_none());
}
