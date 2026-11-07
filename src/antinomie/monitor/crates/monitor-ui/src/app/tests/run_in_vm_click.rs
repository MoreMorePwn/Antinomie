// SPDX-License-Identifier: GPL-3.0-only
//! "Run in VM…" in a sample's window sends the sample on the first click,
//! also when the VM has just come back from a snapshot restore (B2 of the
//! evaluation: the first click was said to be ignored).
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1400.0, 820.0);

#[test]
fn the_first_run_in_vm_click_after_a_restore_sends_the_sample() {
    let root = super::samples_list::temp("run-in-vm");
    let (script, _, _) = super::samples_list::fixture(&root);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.options.data_dir = root.clone();
    app.rules_ui.set_packs_for_test(Vec::new());
    app.open_library(crate::workspace::LibraryPage::Samples);
    let deadline = Instant::now() + Duration::from_secs(120);
    while !app.samples_page.is_loaded() && Instant::now() < deadline {
        render(&mut app, &ctx, SIZE);
        std::thread::sleep(Duration::from_millis(10));
    }
    app.samples_page.open_detail(&script);
    // The VM was restored from a snapshot: it was Starting for a while, and
    // the restore left its result in the Snapshots state.
    observer_fixture(&mut app);
    app.snapshot.state = VmState::Starting;
    app.vm_snapshots.result = Some((true, "Restored".into()));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let shown = texts(&render(&mut app, &ctx, SIZE));
        if shown.iter().any(|(text, _)| text == "Run in VM…") || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    app.snapshot.state = VmState::Running;
    app.submitted.clear();
    click_label(&mut app, &ctx, SIZE, "Run in VM…");
    assert!(
        app.submitted
            .iter()
            .any(|command| matches!(command, Command::UploadSample { .. })),
        "nothing was sent: {:?}",
        app.submitted
    );
    let _ = std::fs::remove_dir_all(root);
}
