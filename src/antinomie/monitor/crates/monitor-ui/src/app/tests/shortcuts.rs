// SPDX-License-Identifier: GPL-3.0-only
//! Keyboard shortcuts: the palette, the tab keys, the shortcut list, and the
//! rule that text fields and the terminal keep their keys.
use super::*;
use crate::app::{
    actions::Action,
    palette::{fuzzy_score, Target},
};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 820.0);

fn raw(events: Vec<egui::Event>, modifiers: egui::Modifiers) -> egui::RawInput {
    egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
        events: std::iter::once(egui::Event::ModifiersChanged(modifiers))
            .chain(events)
            .collect(),
        ..Default::default()
    }
}

fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
    egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    }
}

/// A frame of the whole app with `events` typed.
fn frame(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
    modifiers: egui::Modifiers,
) -> egui::FullOutput {
    ctx.run_ui(raw(events, modifiers), |root| app.draw(root))
}

fn ready() -> (MonitorApp, egui::Context) {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    (app, ctx)
}

fn running_app() -> (MonitorApp, egui::Context) {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    observer_fixture(&mut app);
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    (app, ctx)
}

fn ctrl(app: &mut MonitorApp, ctx: &egui::Context, key: egui::Key) {
    press(app, ctx, SIZE, key, egui::Modifiers::COMMAND);
}

/// Type into whatever has the keyboard.
fn type_text(app: &mut MonitorApp, ctx: &egui::Context, text: &str) {
    frame(
        app,
        ctx,
        vec![egui::Event::Text(text.into())],
        egui::Modifiers::NONE,
    );
}

/// What holds the keyboard in a frame: egui drops the focus of a widget that
/// is not drawn, so each frame draws it again.
#[derive(Clone, Copy)]
enum Holder {
    Field(egui::Id),
    Button(egui::Id),
    Terminal(egui::Id),
}

impl Holder {
    fn draw(self, root: &mut egui::Ui, text: &mut String) {
        egui::CentralPanel::default().show(root, |ui| match self {
            Holder::Field(id) => {
                ui.add(egui::TextEdit::singleline(text).id(id))
                    .request_focus();
            }
            Holder::Button(id) | Holder::Terminal(id) => {
                let response = ui.interact(
                    egui::Rect::from_min_size(egui::pos2(20.0, 20.0), egui::vec2(40.0, 20.0)),
                    id,
                    egui::Sense::click(),
                );
                response.request_focus();
                if matches!(self, Holder::Terminal(_)) {
                    crate::typing::mark_terminal(ui.ctx(), id);
                }
            }
        });
    }
}

/// Run `events` through the shortcuts while `holder` has the keyboard.
fn held(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    holder: Holder,
    events: Vec<egui::Event>,
    mods: egui::Modifiers,
) {
    let mut text = String::new();
    // Two frames so the focus has settled.
    for events in [Vec::new(), events] {
        let _ = ctx.run_ui(raw(events, mods), |root| {
            let ctx = &root.ctx().clone();
            holder.draw(root, &mut text);
            app.shortcuts(ctx);
        });
    }
}

fn held_key(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    holder: Holder,
    key: egui::Key,
    mods: egui::Modifiers,
) {
    held(app, ctx, holder, vec![key_event(key, mods)], mods);
}

fn nothing_held(app: &mut MonitorApp, ctx: &egui::Context, key: egui::Key, mods: egui::Modifiers) {
    let _ = ctx.run_ui(raw(vec![key_event(key, mods)], mods), |root| {
        let ctx = &root.ctx().clone();
        app.shortcuts(ctx)
    });
}

#[test]
fn ctrl_digits_show_the_work_tabs_in_their_visible_order() {
    let (mut app, ctx) = ready();
    let tabs = app.layout.work_tabs();
    assert_eq!(tabs, Panel::MAIN.to_vec());
    for (at, key) in keys::TAB_KEYS.into_iter().enumerate() {
        ctrl(&mut app, &ctx, key);
        render(&mut app, &ctx, SIZE);
        assert_eq!(
            app.layout.active_work_tab().as_ref(),
            tabs.get(at),
            "Ctrl+{} shows tab {}",
            at + 1,
            at + 1
        );
    }
    // The bottom bar (Details, Activity) is not part of the digits.
    assert!(!app.layout.work_tabs().contains(&Panel::Details));
    // A tab opened after the ninth has no digit.
    app.open_library(LibraryPage::Rules);
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let tabs = app.layout.work_tabs();
    assert_eq!(tabs.len(), 10);
    assert_eq!(app.layout.tab_key_position(&tabs[9]), None);
    ctrl(&mut app, &ctx, egui::Key::Num1);
    render(&mut app, &ctx, SIZE);
    assert_eq!(app.layout.active_work_tab(), Some(Panel::Summary));
}

#[test]
fn ctrl_digits_follow_a_reordered_bar() {
    let (mut app, ctx) = ready();
    // Move Triage to the front the way the tab bar does.
    app.layout.move_to_front_for_test(&Panel::Triage);
    ctrl(&mut app, &ctx, egui::Key::Num1);
    render(&mut app, &ctx, SIZE);
    assert_eq!(app.layout.active_work_tab(), Some(Panel::Triage));
    assert_eq!(app.layout.tab_key_position(&Panel::Summary), Some(1));
    ctrl(&mut app, &ctx, egui::Key::Num2);
    render(&mut app, &ctx, SIZE);
    assert_eq!(app.layout.active_work_tab(), Some(Panel::Summary));
}

#[test]
fn ctrl_r_runs_a_program_only_while_the_vm_runs() {
    let (mut app, ctx) = ready();
    ctrl(&mut app, &ctx, egui::Key::R);
    assert!(!app.launch_open, "no VM runs");
    let (mut app, ctx) = running_app();
    ctrl(&mut app, &ctx, egui::Key::R);
    assert!(app.launch_open);
}

#[test]
fn ctrl_d_opens_the_debugger_picker_when_it_is_available() {
    let (mut app, ctx) = running_app();
    ctrl(&mut app, &ctx, egui::Key::D);
    assert!(!app.process_picker.open, "the base is too old to debug");
    assert!(app.debugger_unavailable().is_some());
    app.snapshot.guest_kernel = Some(antinomie_monitor_core::GuestKernel {
        revision: Some(17),
        ..Default::default()
    });
    ctrl(&mut app, &ctx, egui::Key::D);
    assert!(app.process_picker.open);
    assert!(matches!(
        app.submitted.last(),
        Some(Command::ListProcesses { after_pid: 0 })
    ));
}

#[test]
fn text_fields_and_the_terminal_keep_their_keys() {
    let (mut app, ctx) = running_app();
    let ctrl_mods = egui::Modifiers::COMMAND;
    let field = Holder::Field(egui::Id::new("a_dialog_field"));
    for key in [
        egui::Key::R,
        egui::Key::U,
        egui::Key::D,
        egui::Key::K,
        egui::Key::Num2,
        egui::Key::Comma,
    ] {
        held_key(&mut app, &ctx, field, key, ctrl_mods);
    }
    held_key(&mut app, &ctx, field, egui::Key::F5, egui::Modifiers::SHIFT);
    // `?` is a letter to a text field.
    held(
        &mut app,
        &ctx,
        field,
        vec![
            egui::Event::Text("?".into()),
            key_event(egui::Key::Questionmark, egui::Modifiers::SHIFT),
        ],
        egui::Modifiers::SHIFT,
    );
    assert!(crate::typing::typing(&ctx));
    assert!(!app.launch_open && !app.upload_open && !app.settings_open);
    assert!(!app.process_picker.open);
    assert!(!app.shortcut_ui.palette.open && !app.shortcut_ui.list_open);
    assert!(app.focus_panel.is_none());
    assert!(app.submitted.is_empty());

    // The terminal marks its pane each frame it has the focus.
    let terminal = Holder::Terminal(egui::Id::new("a_terminal_pane"));
    for key in [egui::Key::R, egui::Key::K, egui::Key::D, egui::Key::Num1] {
        held_key(&mut app, &ctx, terminal, key, ctrl_mods);
    }
    assert!(crate::typing::typing(&ctx));
    assert!(!app.launch_open && !app.shortcut_ui.palette.open && !app.process_picker.open);
    assert!(app.focus_panel.is_none());

    // Once the focus leaves, the shortcuts work again.
    ctx.memory_mut(|memory| memory.surrender_focus(egui::Id::new("a_terminal_pane")));
    let _ = ctx.run_ui(raw(Vec::new(), egui::Modifiers::NONE), |_| {});
    assert!(!crate::typing::typing(&ctx));
    nothing_held(&mut app, &ctx, egui::Key::R, ctrl_mods);
    assert!(app.launch_open);
}

#[test]
fn a_focused_button_does_not_block_the_shortcuts() {
    // Before, any focused widget (a button reached with Tab) disabled them.
    let (mut app, ctx) = running_app();
    let button = Holder::Button(egui::Id::new("a_button"));
    held_key(
        &mut app,
        &ctx,
        button,
        egui::Key::R,
        egui::Modifiers::COMMAND,
    );
    assert!(!crate::typing::typing(&ctx));
    assert!(app.launch_open);
}

#[test]
fn question_mark_opens_the_list_and_escape_closes_it() {
    let (mut app, ctx) = ready();
    frame(
        &mut app,
        &ctx,
        vec![
            egui::Event::Text("?".into()),
            key_event(egui::Key::Questionmark, egui::Modifiers::SHIFT),
        ],
        egui::Modifiers::SHIFT,
    );
    assert!(app.shortcut_ui.list_open);
    render(&mut app, &ctx, SIZE);
    let output = render(&mut app, &ctx, SIZE);
    let shown: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    // The window scrolls; the other areas are checked through `shortcut_rows`.
    for shown_text in ["Keyboard shortcuts", "Application", "Ctrl+R"] {
        assert!(
            shown.iter().any(|text| text == shown_text),
            "{shown_text}: {shown:?}"
        );
    }
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.shortcut_ui.list_open);
    // With a modifier it is not the shortcut list.
    frame(
        &mut app,
        &ctx,
        vec![key_event(egui::Key::Questionmark, egui::Modifiers::COMMAND)],
        egui::Modifiers::COMMAND,
    );
    assert!(!app.shortcut_ui.list_open);
}

#[test]
fn help_menu_opens_the_shortcut_list_and_names_the_keys() {
    let (mut app, ctx) = running_app();
    click_label(&mut app, &ctx, SIZE, "Help");
    let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(shown.iter().any(|text| text == "Command palette"));
    assert!(shown.iter().any(|text| text == "Ctrl+K"), "{shown:?}");
    assert!(shown.iter().any(|text| text == "?"), "{shown:?}");
    click_label(&mut app, &ctx, SIZE, "Keyboard shortcuts");
    assert!(app.shortcut_ui.list_open);
}

#[test]
fn menus_show_the_shortcuts() {
    let (mut app, ctx) = running_app();
    for (menu, expected) in [
        ("Run", vec!["Ctrl+R", "Ctrl+U", "Ctrl+D"]),
        ("View", vec!["Ctrl+1", "Ctrl+3", "Ctrl+9"]),
        ("File", vec!["Ctrl+N", "Ctrl+Q"]),
        ("VM", vec!["F5", "Shift+F5"]),
    ] {
        click_label(&mut app, &ctx, SIZE, menu);
        let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        for keys in expected {
            assert!(
                shown.iter().any(|text| text == keys),
                "{menu} lacks {keys}: {shown:?}"
            );
        }
        click_label(&mut app, &ctx, SIZE, menu);
    }
}

#[test]
fn the_palette_opens_searches_and_runs() {
    let (mut app, ctx) = running_app();
    ctrl(&mut app, &ctx, egui::Key::K);
    assert!(app.shortcut_ui.palette.open);
    // Typing goes into the query once the field has the focus.
    for _ in 0..2 {
        render(&mut app, &ctx, SIZE);
    }
    type_text(&mut app, &ctx, "sett");
    assert_eq!(app.shortcut_ui.palette.query, "sett");
    let results = app.palette_results(&ctx, "sett");
    assert_eq!(results[0].target, Target::Action(Action::Settings));
    let output = render(&mut app, &ctx, SIZE);
    assert!(texts(&output).iter().any(|(text, _)| text == "Settings…"));
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::Enter,
        egui::Modifiers::NONE,
    );
    assert!(app.settings_open, "Enter runs the highlighted entry");
    assert!(!app.shortcut_ui.palette.open);

    // Escape closes it without doing anything; so does Ctrl+K again.
    app.settings_open = false;
    ctrl(&mut app, &ctx, egui::Key::K);
    assert!(app.shortcut_ui.palette.open);
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.shortcut_ui.palette.open && !app.settings_open);
    ctrl(&mut app, &ctx, egui::Key::K);
    render(&mut app, &ctx, SIZE);
    render(&mut app, &ctx, SIZE);
    ctrl(&mut app, &ctx, egui::Key::K);
    assert!(!app.shortcut_ui.palette.open);
}

#[test]
fn the_palette_arrows_choose_and_a_click_runs() {
    let (mut app, ctx) = running_app();
    ctrl(&mut app, &ctx, egui::Key::K);
    app.shortcut_ui.palette.query = "run".into();
    let results = app.palette_results(&ctx, "run");
    assert!(results.len() > 2);
    render(&mut app, &ctx, SIZE);
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::ArrowDown,
        egui::Modifiers::NONE,
    );
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::ArrowDown,
        egui::Modifiers::NONE,
    );
    assert_eq!(app.shortcut_ui.palette.cursor, 2);
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::ArrowUp,
        egui::Modifiers::NONE,
    );
    assert_eq!(app.shortcut_ui.palette.cursor, 1);
    // The first entry for "run program" is Run program; a click on its row runs it.
    app.shortcut_ui.palette.query = "run program".into();
    app.shortcut_ui.palette.cursor = 0;
    let first = app.palette_results(&ctx, "run program")[0].label.clone();
    let output = render(&mut app, &ctx, SIZE);
    let at = texts(&output)
        .into_iter()
        .find(|(text, _)| *text == first)
        .unwrap_or_else(|| panic!("{first} is not shown"))
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run_ui(
            raw(
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                egui::Modifiers::NONE,
            ),
            |root| app.draw(root),
        );
    }
    assert!(
        !app.shortcut_ui.palette.open,
        "a click runs the entry and closes the palette"
    );
    assert!(app.launch_open, "the entry ran: {first}");
}

#[test]
fn the_palette_explains_what_cannot_run() {
    let (mut app, ctx) = ready();
    let results = app.palette_results(&ctx, "run program");
    let run = results
        .iter()
        .find(|item| item.target == Target::Action(Action::RunProgram))
        .expect("Run program is offered");
    let reason = run.unavailable.clone().expect("no VM runs");
    assert!(
        reason.contains("Select a VM") || reason.contains("Start"),
        "{reason}"
    );
    assert_eq!(run.detail, "Ctrl+R");
    ctrl(&mut app, &ctx, egui::Key::K);
    app.shortcut_ui.palette.query = "run program".into();
    render(&mut app, &ctx, SIZE);
    // The reason is on the row.
    let output = render(&mut app, &ctx, SIZE);
    assert!(
        texts(&output)
            .iter()
            .any(|(text, _)| text.contains(&reason)),
        "the row shows {reason}"
    );
    // Enter on it does not run it, and the palette stays open with the reason.
    let first_is_run =
        app.palette_results(&ctx, "run program")[0].target == Target::Action(Action::RunProgram);
    assert!(first_is_run);
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::Enter,
        egui::Modifiers::NONE,
    );
    assert!(app.shortcut_ui.palette.open);
    assert!(!app.launch_open);
    assert!(app
        .shortcut_ui
        .palette
        .notice
        .as_deref()
        .is_some_and(|n| n.contains(&reason)));

    // Running VM: the same entry is available.
    let (app, ctx) = running_app();
    let results = app.palette_results(&ctx, "run program");
    assert!(results[0].unavailable.is_none());
}

#[test]
fn the_palette_finds_tabs_machines_runs_and_samples() {
    let (mut app, ctx) = running_app();
    app.snapshot.vms.push(VmConfig {
        id: "second".into(),
        name: "Analysis box".into(),
        ..VmConfig::default()
    });
    let mut sample = run("run-77aa");
    sample.vm_id = "vm".into();
    sample.request.path = "/tmp/dropper.bin".into();
    sample.started_ms = Some(1_700_000_000_000);
    app.snapshot.runs.push(sample);

    let tab = app.palette_results(&ctx, "triage");
    assert_eq!(tab[0].target, Target::Tab(Panel::Triage));
    assert_eq!(tab[0].detail, "Ctrl+3");
    assert_eq!(tab[0].kind, "Tab");

    let machine = app.palette_results(&ctx, "analysis box");
    assert_eq!(machine[0].target, Target::Machine("second".into()));
    let item = machine[0].clone();
    assert!(app.palette_run(&ctx, &item));
    assert_eq!(app.selected.as_deref(), Some("second"));

    let found = app.palette_results(&ctx, "dropper");
    assert_eq!(found[0].target, Target::Run("run-77aa".into()));
    assert_eq!(found[0].kind, "Run");
    let item = found[0].clone();
    assert!(app.palette_run(&ctx, &item));
    assert!(
        app.samples_page.open_run_pending(),
        "the run is opened in its machine"
    );

    // Tabs jump through the same focus the menus use.
    let item = tab[0].clone();
    assert!(app.palette_run(&ctx, &item));
    render(&mut app, &ctx, SIZE);
    assert_eq!(app.layout.active_work_tab(), Some(Panel::Triage));
}

#[test]
fn fuzzy_matching_prefers_word_starts_and_runs() {
    assert!(fuzzy_score("rp", "Run program…").is_some());
    assert!(fuzzy_score("zq", "Run program…").is_none());
    assert!(fuzzy_score("", "anything").is_some());
    let exact = fuzzy_score("settings", "Settings…").unwrap();
    let loose = fuzzy_score("settings", "Show everything, then tune things in…").unwrap();
    assert!(exact > loose);
    let start = fuzzy_score("cap", "Capture all").unwrap();
    let inside = fuzzy_score("cap", "Escape a pod").unwrap();
    assert!(start > inside);
    // Case does not matter; spaces separate nothing inside a word.
    assert_eq!(
        fuzzy_score("RUN", "run program"),
        fuzzy_score("run", "RUN PROGRAM")
    );
}

#[test]
fn every_shortcut_is_listed_and_none_is_bound_twice() {
    let (app, ctx) = ready();
    let mut seen: Vec<egui::KeyboardShortcut> = Vec::new();
    let mut bound: Vec<(String, egui::KeyboardShortcut)> = Action::PALETTE
        .iter()
        .filter_map(|action| action.shortcut().map(|s| (action.label(&app), s)))
        .collect();
    for position in 0..9 {
        bound.push((
            format!("tab {position}"),
            keys::tab_shortcut(position).unwrap(),
        ));
    }
    for (name, shortcut) in &bound {
        assert!(
            !seen.contains(shortcut),
            "{name} reuses {}",
            ctx.format_shortcut(shortcut)
        );
        seen.push(*shortcut);
    }
    // The terminal passes Ctrl+letters to the guest and text fields edit with
    // them; the application's Ctrl shortcuts all wait while those have the
    // keyboard (text_fields_and_the_terminal_keep_their_keys). F5 is unmodified
    // on purpose: nothing else uses it.
    let rows = app.shortcut_rows(&ctx);
    for (name, shortcut) in &bound {
        // The tab keys are one row, "Ctrl+1 to Ctrl+9".
        if matches!(
            name.as_str(),
            "tab 1" | "tab 2" | "tab 3" | "tab 4" | "tab 5" | "tab 6" | "tab 7"
        ) {
            continue;
        }
        let text = ctx.format_shortcut(shortcut);
        assert!(
            rows.iter()
                .any(|row| row.keys == text || row.keys.contains(&text)),
            "{name} ({text}) is not in the shortcut list"
        );
    }
    assert!(rows.iter().any(|row| row.keys == "?"));
    let areas: std::collections::BTreeSet<&str> =
        rows.iter().map(|row| row.area.as_str()).collect();
    for area in [
        "Application",
        "Workspace tabs",
        "Terminal",
        "Triage graph",
        "Run history and Captures",
    ] {
        assert!(areas.contains(area), "{area}");
    }
}

#[test]
fn the_palette_and_the_list_have_no_widget_id_clash() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx.options_mut(|options| options.warn_on_id_clash = true);
    let mut app = app();
    observer_fixture(&mut app);
    app.shortcut_ui.list_open = true;
    app.shortcut_ui.open_palette();
    for query in ["", "run", "tri", "zzzz"] {
        app.shortcut_ui.palette.query = query.into();
        for size in [SIZE, egui::vec2(1100.0, 700.0)] {
            for _ in 0..3 {
                let output = render(&mut app, &ctx, size);
                let clashes: Vec<String> = texts(&output)
                    .into_iter()
                    .map(|(text, _)| text)
                    .filter(|text| text.contains('🔥'))
                    .collect();
                assert!(clashes.is_empty(), "{query:?} at {size:?}: {clashes:?}");
            }
        }
    }
}
