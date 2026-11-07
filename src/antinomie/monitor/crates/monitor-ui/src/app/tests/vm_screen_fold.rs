// SPDX-License-Identifier: GPL-3.0-only
//! The VM screen tab folds Details and Activity away while it shows, in the
//! rendered app and opened the way the app opens it.
use super::*;

fn split(app: &MonitorApp) -> f32 {
    app.layout.work_share()
}

fn running_with_screen(app: &mut MonitorApp) {
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.vm_screen = Some(PathBuf::from("/tmp/ant-test/vnc.sock"));
}

#[test]
fn the_vm_screen_tab_folds_details_when_a_vm_with_a_screen_starts() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let before = split(&app);
    assert!(before < 0.8, "{before}");
    running_with_screen(&mut app);
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    assert!(
        app.layout.has_tab(&Panel::VmScreen),
        "a new boot opens the tab"
    );
    assert!(split(&app) > 0.9, "folded: {}", split(&app));
    // The Details tab strip sits at the bottom of the window.
    let output = render(&mut app, &ctx, size);
    let details = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "Details")
        .expect("Details tab strip")
        .1;
    assert!(details.top() > size.y * 0.85, "{details:?}");
}

#[test]
fn the_vm_screen_tab_folds_details_when_opened_from_the_view_menu() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    app.set_vm_screen_closed(true);
    running_with_screen(&mut app);
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    assert!(!app.layout.has_tab(&Panel::VmScreen));
    app.run_action(&ctx, Action::Go(Panel::VmScreen));
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    assert!(app.layout.has_tab(&Panel::VmScreen));
    assert!(split(&app) > 0.9, "folded: {}", split(&app));
}

#[test]
fn a_vm_with_no_screen_gets_the_tab_only_when_asked_and_it_says_how_to_change_it() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    app.snapshot.vms = vec![VmConfig {
        id: "vm".into(),
        name: "Quiet VM".into(),
        launch: antinomie_monitor_core::VmLaunchOptions {
            screen: antinomie_monitor_core::VmScreen::NoScreen,
            ..Default::default()
        },
        ..VmConfig::default()
    }];
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    assert!(
        !app.layout.has_tab(&Panel::VmScreen),
        "a boot with no screen opens no tab"
    );
    assert!(app
        .action_unavailable(&Action::Go(Panel::VmScreen))
        .is_none());
    app.run_action(&ctx, Action::Go(Panel::VmScreen));
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    assert!(app.layout.has_tab(&Panel::VmScreen));
    let shown = texts(&render(&mut app, &ctx, size));
    let said = shown
        .iter()
        .any(|(text, _)| text.starts_with("This VM has no screen"));
    assert!(said, "{shown:?}");
    // The tab goes with the VM.
    app.snapshot.state = VmState::Stopped;
    app.snapshot.active_vm = None;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    assert!(!app.layout.has_tab(&Panel::VmScreen));
}
