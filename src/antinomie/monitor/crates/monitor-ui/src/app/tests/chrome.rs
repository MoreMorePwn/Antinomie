// SPDX-License-Identifier: MIT
//! Dialog stacking, toolbar, menus and sidebar.
use super::*;

#[test]
fn escape_closes_the_topmost_dialog_first() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    observer_fixture(&mut app);
    app.settings_open = true;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    // Opened later, so drawn on top.
    app.upload_open = true;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    press(
        &mut app,
        &ctx,
        size,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.upload_open, "Escape closes the window on top");
    assert!(app.settings_open, "and only that one");
    render(&mut app, &ctx, size);
    press(
        &mut app,
        &ctx,
        size,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.settings_open);

    // A confirmation is modal: Escape cancels it and leaves its dialog.
    app.snapshot.active_vm = None;
    app.new_image();
    app.confirm = Some(Confirm::Nat {
        vm: Box::new(app.draft.clone()),
        creating: true,
    });
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    press(
        &mut app,
        &ctx,
        size,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(app.confirm.is_none());
    assert!(app.create_open);
    assert!(app.submitted.is_empty());
    render(&mut app, &ctx, size);
    press(
        &mut app,
        &ctx,
        size,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.create_open);

    // Every dialog Escape knows about closes.
    for dialog in Dialog::ALL {
        let mut app = super::tests::app();
        match dialog {
            Dialog::Confirm => app.confirm = Some(Confirm::Delete("vm".into())),
            Dialog::Name => app.name_action = Some(("vm".into(), false, "VM".into())),
            Dialog::Transport => {
                app.new_image();
                app.transport_open = true;
            }
            Dialog::Stealth => {
                app.new_image();
                app.stealth_open = true;
            }
            Dialog::Vm => app.new_image(),
            Dialog::Launch => app.launch_open = true,
            Dialog::Upload => app.upload_open = true,
            Dialog::Settings => app.settings_open = true,
            Dialog::Import => app.import_open = true,
            Dialog::Download => app.download_open = true,
            Dialog::Tools => app.tools_open = true,
            Dialog::Rules => app.rules_open = true,
            Dialog::Samples => app.samples.open = true,
            Dialog::Dependencies => app.dependencies.open = true,
            Dialog::Performance => app.performance.open = true,
            Dialog::About => app.about_open = true,
            Dialog::Build => app.build_open = true,
            Dialog::Attach => app.process_picker.open = true,
            Dialog::Snapshots => app.vm_snapshots.bind("vm", "VM"),
            Dialog::SnapshotDecision => {
                app.vm_snapshots.bind("vm", "VM");
                app.vm_snapshots.ask_create();
            }
        }
        let ctx = egui::Context::default();
        theme::install(&ctx);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        assert!(app.dialog_open(dialog), "{dialog:?}");
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Escape,
            egui::Modifiers::NONE,
        );
        assert!(!app.dialog_open(dialog), "Escape left {dialog:?} open");
    }
}

#[test]
fn toolbar_keeps_the_main_actions_and_menus_reach_the_rest() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.vms[0].nat = true;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let shown = texts(&output);
    let run = shown
        .iter()
        .find(|(text, _)| text.ends_with("Run program"))
        .expect("Run program on the toolbar")
        .1;
    let toolbar: Vec<String> = shown
        .iter()
        .filter(|(text, rect)| {
            (rect.center().y - run.center().y).abs() < 6.0 && text.chars().count() > 1
        })
        .map(|(text, _)| text.chars().filter(|c| c.is_ascii()).collect())
        .collect();
    assert_eq!(
        toolbar,
        [
            "Start",
            "Stop",
            "Snapshots",
            "Kill",
            "Run program",
            "Capture all",
            "Capture network",
            "Dump memory",
            "Dump core"
        ],
        "{shown:?}"
    );
    // Running VM: Stop is red and Start is grayed out.
    let colored = |label: &str| {
        text_color(
            &output,
            &shown
                .iter()
                .find(|(text, _)| text.ends_with(label))
                .unwrap()
                .0,
        )
    };
    assert_eq!(colored("Stop"), Some(theme::error()));
    assert_eq!(colored("Start"), Some(theme::muted()));
    assert_eq!(colored("Run program"), Some(theme::blue()));

    // The actions that left the toolbar are in the menus.
    for (menu, items) in [
        ("File", vec!["New VM…", "Exit"]),
        (
            "VM",
            vec![
                "Start VM",
                "Stop VM",
                "Configuration…",
                "Reset disk to base…",
            ],
        ),
        (
            "Run",
            vec![
                "Run program…",
                "Upload file…",
                "Attach to process…",
                "Capture all",
                "Stop capture",
                "Capture network",
            ],
        ),
        (
            "Tools",
            vec!["Settings…", "Analysis tools…", "App dependencies…"],
        ),
    ] {
        click_label(&mut app, &ctx, size, menu);
        let output = render(&mut app, &ctx, size);
        let shown = texts(&output);
        for item in items {
            assert!(
                shown.iter().any(|(text, _)| text == item),
                "{menu} menu lacks {item}: {shown:?}"
            );
        }
        click_label(&mut app, &ctx, size, menu);
    }
    assert!(app.submitted.is_empty());

    // Shortcuts open the dialogs and stop the VM.
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = super::tests::app();
    observer_fixture(&mut app);
    render(&mut app, &ctx, size);
    press(
        &mut app,
        &ctx,
        size,
        egui::Key::Comma,
        egui::Modifiers::COMMAND,
    );
    assert!(app.settings_open);
    press(&mut app, &ctx, size, egui::Key::R, egui::Modifiers::COMMAND);
    assert!(app.launch_open);
    press(&mut app, &ctx, size, egui::Key::U, egui::Modifiers::COMMAND);
    assert!(app.upload_open);
    press(&mut app, &ctx, size, egui::Key::F5, egui::Modifiers::SHIFT);
    assert!(matches!(app.submitted.as_slice(), [Command::Stop]));
    // F5 starts the selected VM once none runs.
    app.snapshot.active_vm = None;
    app.snapshot.state = VmState::Stopped;
    press(&mut app, &ctx, size, egui::Key::F5, egui::Modifiers::NONE);
    assert!(matches!(app.submitted.last(), Some(Command::Start { vm_id }) if vm_id == "vm"));
}

#[test]
fn sidebar_shows_each_vm_state_resources_and_latest_run() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.bases.push(test_base("base", true));
    app.snapshot.vms[0].base_identity = Some("base".into());
    app.snapshot.vms[0].cpus = 2;
    app.snapshot.vms[0].ram_mib = 1024;
    app.snapshot.vms.push(VmConfig {
        id: "idle".into(),
        name: "Idle VM".into(),
        ..VmConfig::default()
    });
    let mut sample = run("run-1");
    sample.request.path = "/usr/bin/sample".into();
    app.snapshot.runs.push(sample);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let shown = texts(&output);
    let title = shown
        .iter()
        .find(|(text, _)| text == "Virtual machines")
        .unwrap()
        .1;
    let sidebar: Vec<&(String, egui::Rect)> = shown
        .iter()
        .filter(|(_, rect)| rect.right() <= title.left() + 260.0 && rect.top() > title.bottom())
        .collect();
    let row = |name: &str| {
        sidebar
            .iter()
            .find(|(text, _)| text == name)
            .unwrap_or_else(|| panic!("missing {name}: {sidebar:?}"))
            .1
    };
    let state_beside = |name: &str, state: &str| {
        let name = row(name);
        sidebar
            .iter()
            .find(|(text, rect)| text == state && (rect.center().y - name.center().y).abs() < 6.0)
            .unwrap_or_else(|| panic!("no {state} beside {name:?}"))
            .1
    };
    state_beside("Capture QA", "Running");
    state_beside("Idle VM", "Stopped");
    assert_eq!(text_color(&output, "Running"), Some(theme::good()));
    let details: Vec<&String> = sidebar.iter().map(|(text, _)| text).collect();
    assert!(
        details.iter().any(|text| text.starts_with("Linux 6.12.94")
            && text.contains("2 CPU")
            && text.contains("1024 MiB")),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|text| text.contains("sample") && text.contains("just now")),
        "{details:?}"
    );
    assert!(details.iter().any(|text| text.as_str() == "No recent run"));
    assert_eq!(
        app.settings
            .last_runs
            .get("vm")
            .map(|last| last.program.as_str()),
        Some("/usr/bin/sample")
    );

    // The base section folds away.
    assert!(details
        .iter()
        .any(|text| text.contains("Linux 6.12.94 · Antinomie")));
    click_label(&mut app, &ctx, size, "Base images");
    assert!(app.settings.bases_collapsed);
    let output = render(&mut app, &ctx, size);
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| text.contains("Linux 6.12.94 · Antinomie")));
    assert!(app.selected_base.is_none() && app.submitted.is_empty());
}

#[test]
fn relative_times_and_program_names_read_briefly() {
    assert_eq!(relative_time(5), "just now");
    assert_eq!(relative_time(125), "2 min ago");
    assert_eq!(relative_time(7300), "2 h ago");
    assert_eq!(relative_time(3 * 86400), "3 d ago");
    assert_eq!(program_name("/usr/bin/sample"), "sample");
    assert_eq!(program_name("/bin/"), "bin");
    assert_eq!(program_name("ls"), "ls");
}
