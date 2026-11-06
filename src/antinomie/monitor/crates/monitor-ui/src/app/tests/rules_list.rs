// SPDX-License-Identifier: GPL-3.0-only
//! The Detection rules page in the real app frame, at the size of a small
//! screen: the pack's "Rules" button opens the rules window, and a click on a
//! rule in its list shows the rule's details in the same window's right pane. A pack's rules once sat in a
//! table at the foot of the page, which a small window squeezed to its header
//! row, so no rule could be clicked.
use super::*;

const SMALL: egui::Vec2 = egui::vec2(1280.0, 820.0);
const RULES: &str = "rule Zeta_Rule\n{\n  meta:\n    description = \"the zeta rule\"\n  strings:\n    $a = \"zeta\"\n  condition:\n    $a\n}\n\nrule Alpha_Rule\n{\n  meta:\n    description = \"the alpha rule\"\n  strings:\n    $a = \"alpha\"\n  condition:\n    $a\n}\n";

fn frame(app: &mut MonitorApp, ctx: &egui::Context, events: Vec<egui::Event>) -> String {
    let output = draw_input(
        app,
        ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SMALL)),
            events,
            ..Default::default()
        },
    );
    texts(&output)
        .into_iter()
        .map(|(text, rect)| format!("{text}@{:.0},{:.0}", rect.left(), rect.top()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Frames until `wanted` is drawn (workers answer in the background).
fn until(app: &mut MonitorApp, ctx: &egui::Context, wanted: &str) -> String {
    let start = Instant::now();
    loop {
        let shown = frame(app, ctx, Vec::new());
        if shown.contains(wanted) {
            return shown;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{wanted:?} never appeared: {shown}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Scrolls the page with the wheel until `label` is drawn and not clipped.
fn reveal(app: &mut MonitorApp, ctx: &egui::Context, label: &str) {
    let start = Instant::now();
    let over = egui::pos2(700.0, 400.0);
    loop {
        let shown = frame(app, ctx, vec![egui::Event::PointerMoved(over)]);
        if shown.contains(label) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{label:?} never came into view: {shown}"
        );
        frame(
            app,
            ctx,
            vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -120.0),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Presses the first text that contains `label`, drawn where a click lands.
fn click_on(app: &mut MonitorApp, ctx: &egui::Context, label: &str) {
    let shown = frame(app, ctx, Vec::new());
    let output = draw_input(
        app,
        ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SMALL)),
            ..Default::default()
        },
    );
    let at = texts(&output)
        .into_iter()
        .find(|(text, _)| text.contains(label))
        .unwrap_or_else(|| panic!("no {label}: {shown}"))
        .1
        .center();
    for pressed in [true, false] {
        frame(
            app,
            ctx,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    frame(app, ctx, Vec::new());
}

#[test]
fn a_rule_of_a_pack_shows_its_details_beside_the_list_in_the_app_at_a_small_size() {
    let root = std::env::temp_dir().join(format!("ant-rules-list-app-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    crate::rules_window::source_tests::install_fixture_pack(
        &root,
        "fixture",
        "yara",
        "rules.yar",
        RULES,
    );
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.options.data_dir = root.clone();
    app.open_library(LibraryPage::Rules);
    until(&mut app, &ctx, "Detection rules");
    reveal(&mut app, &ctx, " Rules@");
    let page = frame(&mut app, &ctx, Vec::new());
    assert!(page.contains("Fixture fixture 1"), "{page}");
    // The page has the pack's details and no rule table.
    assert!(!page.contains("Alpha_Rule"), "{page}");
    assert!(!page.contains("Severity"), "{page}");
    // The list window opens from the button and shows its rows, which a
    // table inside the page could not at this size.
    click_on(&mut app, &ctx, " Rules");
    let list = until(&mut app, &ctx, "Alpha_Rule");
    assert!(
        list.contains("Zeta_Rule") && list.contains("2 of 2 rules"),
        "{list}"
    );
    assert!(list.contains("Rules \u{b7} Fixture fixture"), "{list}");
    // A click on a rule shows its details in the same window's right pane:
    // no second window opens.
    click_on(&mut app, &ctx, "Alpha_Rule");
    let details = until(&mut app, &ctx, "$a = \"alpha\"");
    assert!(
        !details.contains("Rule \u{b7} Alpha_Rule"),
        "no separate window: {details}"
    );
    assert!(details.contains("Source text"), "{details}");
    assert!(details.contains("the alpha rule"), "{details}");
    assert!(
        details.contains("Rules \u{b7} Fixture fixture"),
        "{details}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
