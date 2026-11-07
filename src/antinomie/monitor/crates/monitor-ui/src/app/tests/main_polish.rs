// SPDX-License-Identifier: GPL-3.0-only
//! ANT-T0305, the main window's polish: the sidebar button's hover, the pane
//! arrow, the sidebar VM line, the Settings pages without paragraphs, and the
//! "Use TCG when KVM is unavailable" default.
use super::*;
use crate::app::settings_window::SettingsPage;

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx.global_style_mut(|style| {
        style.interaction.tooltip_delay = 0.0;
        style.interaction.tooltip_grace_time = 0.0;
    });
    ctx
}

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);

fn input(events: Vec<egui::Event>) -> egui::RawInput {
    egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
        events,
        ..Default::default()
    }
}

fn settle(app: &mut MonitorApp, ctx: &egui::Context) -> egui::FullOutput {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    render(app, ctx, SIZE)
}

fn click_at(app: &mut MonitorApp, ctx: &egui::Context, pos: egui::Pos2) {
    for pressed in [true, false] {
        let _ = draw_input(
            app,
            ctx,
            input(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]),
        );
    }
}

fn hover_at(app: &mut MonitorApp, ctx: &egui::Context, pos: egui::Pos2) -> egui::FullOutput {
    let mut output = egui::FullOutput::default();
    for _ in 0..12 {
        output = draw_input(app, ctx, input(vec![egui::Event::PointerMoved(pos)]));
    }
    output
}

fn rects_filled_with(output: &egui::FullOutput, colour: egui::Color32) -> Vec<egui::Rect> {
    fn walk(shape: &egui::Shape, colour: egui::Color32, out: &mut Vec<egui::Rect>) {
        match shape {
            egui::Shape::Rect(rect) if rect.fill == colour => out.push(rect.rect),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, colour, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, colour, &mut out));
    out
}

fn glyph_rects(output: &egui::FullOutput, glyph: &str) -> Vec<egui::Rect> {
    texts(output)
        .into_iter()
        .filter(|(text, _)| text == glyph)
        .map(|(_, rect)| rect)
        .collect()
}

#[test]
fn the_sidebar_button_lights_on_hover_like_the_other_toolbar_buttons() {
    let ctx = context();
    let mut app = app();
    let at = settle(&mut app, &ctx);
    let glyph = *glyph_rects(&at, egui_phosphor::regular::SIDEBAR_SIMPLE)
        .first()
        .expect("the sidebar button");
    let hover = theme::palette().hover;
    assert!(
        !rects_filled_with(&at, hover)
            .iter()
            .any(|rect| rect.contains(glyph.center())),
        "no tint at rest"
    );
    let hovered = hover_at(&mut app, &ctx, glyph.center());
    assert!(
        rects_filled_with(&hovered, hover)
            .iter()
            .any(|rect| rect.contains(glyph.center())),
        "the hover tint sits under the button"
    );
}

#[test]
fn an_arrow_at_the_right_end_of_the_pane_tabs_hides_and_shows_the_pane() {
    let ctx = context();
    let mut app = app();
    app.layout = WorkspaceLayout::default();
    let output = settle(&mut app, &ctx);
    assert!(!app.layout.bottom_folded());
    let down = glyph_rects(&output, egui_phosphor::regular::CARET_DOWN)
        .into_iter()
        .filter(|rect| rect.center().y > SIZE.y * 0.5)
        .max_by(|a, b| a.center().x.total_cmp(&b.center().x))
        .expect("a down arrow in the lower tab strip");
    assert!(down.center().x > SIZE.x * 0.5, "at the right end: {down:?}");
    let tip = texts(&hover_at(&mut app, &ctx, down.center()));
    assert!(
        tip.iter().any(
            |(text, _)| text.starts_with("Hide Details, Activity and Jobs")
                && text.contains("Ctrl+J")
        ),
        "{tip:?}"
    );
    click_at(&mut app, &ctx, down.center());
    assert!(app.layout.bottom_folded(), "the down arrow folds the pane");
    let output = settle(&mut app, &ctx);
    let up = glyph_rects(&output, egui_phosphor::regular::CARET_UP)
        .into_iter()
        .filter(|rect| rect.center().y > SIZE.y * 0.5)
        .max_by(|a, b| a.center().x.total_cmp(&b.center().x))
        .expect("an up arrow while folded");
    let tip = texts(&hover_at(&mut app, &ctx, up.center()));
    assert!(
        tip.iter()
            .any(|(text, _)| text.starts_with("Show Details, Activity and Jobs")),
        "{tip:?}"
    );
    click_at(&mut app, &ctx, up.center());
    assert!(!app.layout.bottom_folded(), "the up arrow shows it again");
}

#[test]
fn the_sidebar_vm_line_is_the_base_image_name_and_the_architecture() {
    let ctx = context();
    let mut app = app();
    let mut base = test_base("debian", false);
    base.label = "Debian 13 (Minimal)".into();
    app.snapshot.bases = vec![base];
    app.snapshot.vms = vec![VmConfig {
        id: "vm".into(),
        name: "Analysis VM".into(),
        base_identity: Some("debian".into()),
        cpus: 6,
        ram_mib: 3072,
        ..VmConfig::default()
    }];
    app.selected = Some("vm".into());
    let shown = texts(&settle(&mut app, &ctx));
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Debian 13 (Minimal) · x86-64"),
        "{shown:?}"
    );
    assert!(
        !shown.iter().any(|(text, _)| text.contains("MiB")),
        "no CPU and memory on the line: {shown:?}"
    );
}

#[test]
fn the_sidebar_vm_line_names_an_arm64_base_as_arm64() {
    let ctx = context();
    let mut app = app();
    let mut base = test_base("debian-arm64", false);
    base.label = "Debian 13 (Minimal)".into();
    base.arch = antinomie_monitor_core::GuestArch::AARCH64;
    app.snapshot.bases = vec![base];
    app.snapshot.vms = vec![VmConfig {
        id: "vm".into(),
        name: "Arm VM".into(),
        base_identity: Some("debian-arm64".into()),
        ..VmConfig::default()
    }];
    app.selected = Some("vm".into());
    let shown = texts(&settle(&mut app, &ctx));
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Debian 13 (Minimal) · arm64"),
        "{shown:?}"
    );
}

#[test]
fn settings_pages_keep_no_paragraph_only_short_lines() {
    let ctx = context();
    let mut longs: Vec<String> = Vec::new();
    for page in SettingsPage::ALL {
        let mut app = app();
        app.settings_open = true;
        app.settings_page = page;
        let shown = texts(&settle(&mut app, &ctx));
        for (text, _) in &shown {
            if text.chars().count() > 70 && !text.starts_with('/') {
                longs.push(format!("{page:?}: {text}"));
            }
        }
        assert!(
            !shown
                .iter()
                .any(|(text, _)| text.contains("Appearance applies at once")),
            "{page:?}"
        );
    }
    assert!(
        longs.is_empty(),
        "long texts left on Settings pages:\n{}",
        longs.join("\n")
    );
}

#[test]
fn the_tcg_explanation_is_in_the_tooltip_of_a_short_line() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::Advanced;
    let shown = texts(&settle(&mut app, &ctx));
    let line = shown
        .iter()
        .find(|(text, _)| text.starts_with("With TCG a start waits up to"))
        .unwrap_or_else(|| panic!("{shown:?}"))
        .1;
    assert!(!shown
        .iter()
        .any(|(text, _)| text.contains("Raise the multiplier")));
    let tip = texts(&hover_at(&mut app, &ctx, line.center()));
    assert!(
        tip.iter()
            .any(|(text, _)| text.contains("Raise the multiplier when a slow TCG boot")),
        "{tip:?}"
    );
}

#[test]
fn use_tcg_when_kvm_is_unavailable_is_on_for_a_new_install_and_an_old_choice_stays() {
    assert!(Settings::default().start.kvm_fallback);
    let fresh: Settings = serde_json::from_str("{}").unwrap();
    assert!(fresh.start.kvm_fallback);
    let off: Settings =
        serde_json::from_str(r#"{"start": {"kvm_fallback": false, "tcg_multiplier": 10}}"#)
            .unwrap();
    assert!(!off.start.kvm_fallback);
    let unset: Settings = serde_json::from_str(r#"{"start": {"tcg_multiplier": 12}}"#).unwrap();
    assert!(unset.start.kvm_fallback);
}

#[test]
fn a_time_limit_row_has_no_default_text_and_its_reset_tooltip_names_the_default() {
    use antinomie_monitor_core::analysis_tools::ToolStatus;
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::AnalysisTools;
    app.snapshot.analysis_tools = vec![ToolStatus {
        id: "capa".into(),
        name: "capa".into(),
        version: "1".into(),
        installed: Some("1".into()),
        ..Default::default()
    }];
    let shown = texts(&settle(&mut app, &ctx));
    assert!(!shown.iter().any(|(text, _)| text.starts_with("Default (")));
    let reset = shown
        .iter()
        .find(|(text, _)| text == "Reset")
        .expect("a Reset button")
        .1;
    let tip = texts(&hover_at(&mut app, &ctx, reset.center()));
    assert!(
        tip.iter()
            .any(|(text, _)| text.contains("default time (240 s)")),
        "{tip:?}"
    );
}
