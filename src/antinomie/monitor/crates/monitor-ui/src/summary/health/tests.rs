// SPDX-License-Identifier: MIT
use super::*;
use antinomie_monitor_core::{ExecRequest, RunExecution, RunState};

fn run(id: &str, boot: &str) -> RunSummary {
    RunSummary {
        started_ms: None,
        clock_anchor: None,
        id: id.into(),
        vm_id: "vm".into(),
        boot_id: boot.into(),
        session_id: 1,
        root_task_cookie: 7,
        pid: 8,
        request: ExecRequest {
            path: "/bin/sample".into(),
            ..Default::default()
        },
        directory: std::path::PathBuf::new(),
        terminal_eof: true,
        state: RunState::Unknown,
        recording_error: None,
        notes: vec![],
        analysis: None,
        execution: Some(RunExecution {
            generation: 1,
            live_task_count: 0,
            pending_async_count: 0,
            flags: 19,
            root_wait_status: Some(0),
            root_exit: None,
            async_loss_count: 3,
            total_task_count: 1,
        }),
    }
}

fn snapshot() -> Snapshot {
    Snapshot {
        active_vm: Some("vm".into()),
        boot_id: Some("boot".into()),
        health: Health {
            recorder_stats: Some([0; 10]),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn failed_sends_change_health_even_when_all_other_drop_counters_are_zero() {
    let mut snapshot = snapshot();
    snapshot.health.recorder_stats.as_mut().unwrap()[6] = 3209;
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Loss observed"
    );
    assert_eq!(
        (
            snapshot.health.dropped,
            snapshot.health.ui_dropped,
            snapshot.health.storage_dropped_packets
        ),
        (0, 0, 0)
    );
    snapshot.health.recorder_stats = Some([0; 10]);
    for index in [7, 8, 9] {
        snapshot.health.recorder_stats.as_mut().unwrap()[index] = 100;
    }
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "No recorded losses"
    );
}

#[test]
fn unavailable_recorder_statistics_are_not_presented_as_zero_loss() {
    let mut snapshot = snapshot();
    snapshot.health.recorder_stats = None;
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Recorder health pending"
    );
    snapshot.health.recorder_stats_error = Some("reply overdue".into());
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Recorder health unavailable"
    );
    snapshot.health.persistence_error = Some("disk full".into());
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Recording error"
    );
}

#[test]
fn async_loss_uses_exact_vm_and_boot_and_survives_missing_execution_status() {
    let mut snapshot = snapshot();
    let mut foreign = run("foreign-vm", "boot");
    foreign.vm_id = "other-vm".into();
    snapshot.runs = vec![run("old-boot", "old"), foreign];
    assert!(Facts::new(&snapshot, &[]).async_runs.is_empty());
    let current = run("current", "boot");
    snapshot.runs.push(current.clone());
    assert_eq!(
        Facts::new(&snapshot, std::slice::from_ref(&current))
            .async_runs
            .len(),
        1
    );
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Loss observed"
    );
    let current = snapshot.runs.last_mut().unwrap();
    current.execution.as_mut().unwrap().async_loss_count = 0;
    assert!(
        !current.has_async_loss(),
        "OBSERVATION_INCOMPLETE alone is unproven attribution, not loss"
    );
    assert!(Facts::new(&snapshot, &[]).async_runs.is_empty());
    let current = snapshot.runs.last_mut().unwrap();
    current
        .notes
        .push("Async observation loss reported: last guest count 3".into());
    current.execution = None;
    assert_eq!(Facts::new(&snapshot, &[]).async_runs.len(), 1);
    snapshot.boot_id = None;
    assert!(Facts::new(&snapshot, &[]).async_runs.is_empty());
}

#[test]
fn activity_notices_do_not_repeat_as_loss_counters_increase() {
    let ctx = egui::Context::default();
    let mut journal = activity::Journal::default();
    let mut snapshot = snapshot();
    snapshot.runs.push(run("current", "boot"));
    for count in 1..=5 {
        snapshot.health.recorder_stats.as_mut().unwrap()[6] = count;
        snapshot.runs[0]
            .execution
            .as_mut()
            .unwrap()
            .async_loss_count = count;
        for message in notices(&snapshot, &[]) {
            activity::report(&ctx, activity::Level::Warn, message);
        }
        journal.ingest(&ctx);
    }
    assert_eq!(journal.counts(), (2, 0));
    snapshot.boot_id = Some("new-boot".into());
    snapshot.runs[0].boot_id = "new-boot".into();
    for message in notices(&snapshot, &[]) {
        activity::report(&ctx, activity::Level::Warn, message);
    }
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (4, 0));
}

#[test]
fn health_loss_rows_wrap_at_narrow_width_and_large_text() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let mut snapshot = snapshot();
    snapshot.runs.push(run("current", "boot"));
    snapshot.health.recorder_stats.as_mut().unwrap()[6] = 3209;
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(420.0, 1200.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| Facts::new(&snapshot, &[]).show(ui, &snapshot));
            },
        );
    }
    for shape in output.shapes {
        if let egui::Shape::Text(text) = shape.shape {
            assert!(
                text.visual_bounding_rect().right() <= 421.0,
                "{}: {:?}",
                text.galley.text(),
                text.visual_bounding_rect()
            );
        }
    }
}

#[test]
fn guest_hash_and_credential_drops_count_as_observed_loss() {
    let mut snapshot = snapshot();
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "No recorded losses"
    );
    snapshot.health.guest_note_lost = 2;
    assert_eq!(
        Facts::new(&snapshot, &[]).state(&snapshot.health).0,
        "Loss observed"
    );
}

#[test]
fn the_writer_hold_time_is_shown_only_when_there_was_one() {
    let mut health = Health::default();
    assert_eq!(held_text(&health), None);
    health.writer_held_ns = 2_500_000_000;
    health.writer_held_longest_ns = 1_200_000_000;
    assert_eq!(
        held_text(&health).as_deref(),
        Some("2.5 s in all, 1.2 s at the longest")
    );
    health.writer_held_ns = 4_000_000;
    health.writer_held_longest_ns = 3_000_000;
    assert_eq!(
        held_text(&health).as_deref(),
        Some("4 ms in all, 3 ms at the longest")
    );
}
