// SPDX-License-Identifier: GPL-3.0-only
//! Start on a VM with no snapshot asks first, and the toolbar keeps the VM's
//! name apart from its state word.
use super::*;
use antinomie_monitor_core::{
    VmCheckpoint, VmConfig, VmSnapshotConsistency, VmSnapshotMode, VmSnapshotTree,
};

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn stopped_vm(app: &mut MonitorApp, snapshots: Option<&[bool]>) {
    observer_fixture(app);
    app.snapshot.active_vm = None;
    app.snapshot.state = VmState::Stopped;
    if let Some(count) = snapshots {
        app.snapshot.vm_snapshot_trees.insert(
            "vm".into(),
            VmSnapshotTree {
                vm_id: "vm".into(),
                nodes: count
                    .iter()
                    .enumerate()
                    .map(|(at, &deleted)| VmCheckpoint {
                        id: format!("s{at}"),
                        parent_id: None,
                        name: format!("Snapshot {at}"),
                        description: String::new(),
                        created_unix_ms: at as u64,
                        mode: VmSnapshotMode::Disk,
                        consistency: VmSnapshotConsistency::Stopped,
                        config: VmConfig::default(),
                        disk_size: 0,
                        memory_size: 0,
                        compatible: true,
                        compatibility_note: None,
                        deleted,
                        stealth: None,
                        profile: Default::default(),
                    })
                    .collect(),
                ..VmSnapshotTree::default()
            },
        );
    }
}

fn shown(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn start_without_a_snapshot_asks_and_start_anyway_starts() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    stopped_vm(&mut app, Some(&[]));
    app.new_run();
    assert!(app.submitted.is_empty(), "{:?}", app.submitted);
    assert!(app.dialog_open(Dialog::Confirm));
    let text = shown(&mut app, &ctx).join("\n");
    assert!(text.contains("No snapshot to restore"), "{text}");
    assert!(text.contains("stays in the VM's disk"), "{text}");
    assert!(
        text.contains("Don't ask me again") && text.contains("Cancel"),
        "{text}"
    );
    click_label(&mut app, &ctx, SIZE, "Start anyway");
    assert!(matches!(app.submitted.last(), Some(Command::Start { vm_id }) if vm_id == "vm"));
    assert!(app.settings.warn_no_snapshot, "nothing was ticked");
    // Cancel starts nothing.
    app.submitted.clear();
    app.new_run();
    click_label(&mut app, &ctx, SIZE, "Cancel");
    assert!(app.submitted.is_empty() && !app.dialog_open(Dialog::Confirm));
}

#[test]
fn a_vm_with_a_snapshot_or_an_unlisted_one_starts_without_asking() {
    let mut app = app();
    stopped_vm(&mut app, Some(&[false]));
    app.new_run();
    assert!(matches!(app.submitted.last(), Some(Command::Start { .. })));
    assert!(!app.dialog_open(Dialog::Confirm));
    let mut app = self::app();
    stopped_vm(&mut app, None);
    app.new_run();
    assert!(matches!(app.submitted.last(), Some(Command::Start { .. })));
    // A snapshot that was deleted does not count.
    let mut app = self::app();
    stopped_vm(&mut app, Some(&[true]));
    app.new_run();
    assert!(app.submitted.is_empty() && app.dialog_open(Dialog::Confirm));
}

#[test]
fn dont_ask_me_again_is_saved_in_settings_and_settings_turn_it_back_on() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    stopped_vm(&mut app, Some(&[]));
    app.new_run();
    click_label(&mut app, &ctx, SIZE, "Don't ask me again");
    click_label(&mut app, &ctx, SIZE, "Start anyway");
    assert!(matches!(app.submitted.last(), Some(Command::Start { .. })));
    assert!(!app.settings.warn_no_snapshot);
    let back: Settings =
        serde_json::from_str(&serde_json::to_string(&app.settings).unwrap()).unwrap();
    assert!(!back.warn_no_snapshot);
    app.submitted.clear();
    app.new_run();
    assert!(matches!(app.submitted.last(), Some(Command::Start { .. })));
    // Settings > Notifications offers it again.
    app.settings_open = true;
    app.settings_page = crate::app::settings_window::SettingsPage::Notifications;
    let text = shown(&mut app, &ctx).join("\n");
    assert!(
        text.contains("Warn before starting a VM with no snapshot"),
        "{text}"
    );
}

#[test]
fn the_vm_name_keeps_a_gap_from_its_state_word() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    for (state, word) in [
        (VmState::Running, "Running"),
        (VmState::Stopping, "Stopping"),
    ] {
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.state = state;
        for _ in 0..3 {
            render(&mut app, &ctx, SIZE);
        }
        let all = texts(&render(&mut app, &ctx, SIZE));
        let find = |wanted: &str| {
            all.iter()
                .find(|(text, _)| text == wanted)
                .unwrap_or_else(|| panic!("no {wanted} in {all:?}"))
                .1
        };
        let (name, word_rect) = (find("Capture QA"), find(word));
        let gap = word_rect.left() - name.right();
        assert!(
            gap >= 12.0,
            "{word}: {gap} points between the name and the state"
        );
    }
}
