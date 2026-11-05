// SPDX-License-Identifier: GPL-3.0-only
//! The main window's chrome: the Explorer's folder button, the File menu, the
//! status bar, the Overview tab and the state dots.
use super::*;
use egui_phosphor::regular as glyph;

fn circles(output: &egui::FullOutput) -> Vec<egui::epaint::CircleShape> {
    fn walk(shape: &egui::Shape, found: &mut Vec<egui::epaint::CircleShape>) {
        match shape {
            egui::Shape::Circle(circle) => found.push(*circle),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut found));
    found
}

fn settled(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2) -> egui::FullOutput {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    render(app, ctx, size)
}

fn overview_app(active: bool) -> MonitorApp {
    let mut app = app();
    app.snapshot.vms = vec![VmConfig {
        id: "vm".into(),
        name: "Analysis VM".into(),
        cpus: 6,
        ram_mib: 3072,
        ..VmConfig::default()
    }];
    app.selected = Some("vm".into());
    if active {
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
    }
    app.layout.focus(Panel::Summary);
    app
}

#[test]
fn the_explorer_has_a_folder_button_and_no_choose_folder_button() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx.global_style_mut(|style| {
        style.interaction.tooltip_delay = 0.0;
        style.interaction.tooltip_grace_time = 0.0;
    });
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    let shown = texts(&settled(&mut app, &ctx, size));
    assert!(
        !shown.iter().any(|(text, _)| text.contains("Choose folder")),
        "{shown:?}"
    );
    let explorer = shown.iter().find(|(text, _)| text == "Explorer").unwrap().1;
    let folder = shown
        .iter()
        .find(|(text, _)| text == glyph::FOLDER_OPEN)
        .unwrap_or_else(|| panic!("no folder icon: {shown:?}"))
        .1;
    assert!(
        (folder.center().y - explorer.center().y).abs() < 4.0,
        "on the Explorer's title row: {folder:?} {explorer:?}"
    );
    assert!(folder.left() > explorer.right(), "at the right end");
    // The old "+" is gone from that header: only the VM header has one.
    let pluses = shown.iter().filter(|(text, _)| text == glyph::PLUS).count();
    assert_eq!(pluses, 1, "{shown:?}");
    let mut output = egui::FullOutput::default();
    for _ in 0..12 {
        output = draw_input(
            &mut app,
            &ctx,
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![egui::Event::PointerMoved(folder.center())],
                ..Default::default()
            },
        );
    }
    let tip = texts(&output);
    assert!(
        tip.iter()
            .any(|(text, _)| text.starts_with("Choose Explorer folder")),
        "{tip:?}"
    );
}

#[test]
fn the_file_menu_has_open_folder_and_import_sample() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    click_label(&mut app, &ctx, size, "File");
    let shown = texts(&render(&mut app, &ctx, size));
    let rect = |name: &str| {
        shown
            .iter()
            .find(|(text, _)| text == name)
            .unwrap_or_else(|| panic!("no {name}: {shown:?}"))
            .1
    };
    let (new_vm, open, import, quit) = (
        rect("New VM…"),
        rect("Open folder…"),
        rect("Import sample…"),
        rect("Exit"),
    );
    assert!(new_vm.top() < open.top() && open.top() < import.top() && import.top() < quit.top());
    assert_eq!(Action::ExplorerFolder.label(&app), "Open folder…");
    assert_eq!(Action::AddSampleFile.label(&app), "Import sample…");
    assert_eq!(Action::ExplorerFolder.group(), "File");
}

fn rects_at_bottom(output: &egui::FullOutput, height: f32) -> Vec<(egui::Rect, egui::Color32)> {
    fn walk(shape: &egui::Shape, height: f32, out: &mut Vec<(egui::Rect, egui::Color32)>) {
        match shape {
            egui::Shape::Rect(rect) if rect.rect.bottom() >= height - 2.0 => {
                out.push((rect.rect, rect.fill))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, height, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, height, &mut out));
    out
}

#[test]
fn every_item_of_the_status_bar_shares_one_middle_line() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    app.status = "Review the upload destination".into();
    let output = settled(&mut app, &ctx, size);
    let shown = texts(&output);
    let items: Vec<_> = shown
        .iter()
        .filter(|(text, rect)| {
            rect.center().y > size.y - 60.0
                && (["TRL", "UIL", "STL", "0"].contains(&text.as_str())
                    || text.starts_with("Antinomie ")
                    || text.starts_with("CAP ")
                    || text.starts_with("Review the"))
        })
        .collect();
    assert!(items.len() >= 7, "{items:?}");
    // The bar: the raised fill that ends at the window's bottom.
    let bars: Vec<_> = rects_at_bottom(&output, size.y)
        .into_iter()
        .filter(|(rect, fill)| *fill == theme::raised() && rect.height() < 80.0)
        .collect();
    let bar = bars
        .iter()
        .map(|(rect, _)| *rect)
        .min_by(|a, b| a.height().partial_cmp(&b.height()).unwrap())
        .unwrap_or_else(|| panic!("no status bar: {:?}", rects_at_bottom(&output, size.y)));
    // The ink of a text with a descender or a slash reaches lower, so the
    // top of the letters is what is compared: one line for every item.
    let top = items[0].1.top();
    for (text, rect) in &items {
        assert!(
            (rect.top() - top).abs() <= 1.5,
            "{text} starts at {} not {top}: {items:?}",
            rect.top()
        );
    }
    // And the figures (no descenders) are in the middle of the bar's height.
    let figure = items.iter().find(|(text, _)| text == "TRL").unwrap().1;
    assert!(
        (figure.center().y - bar.center().y).abs() <= 1.5,
        "TRL at {}, the bar {bar:?} (middle {})",
        figure.center().y,
        bar.center().y
    );
}

#[test]
fn the_summary_window_is_the_overview_window() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = overview_app(false);
    let shown = texts(&settled(&mut app, &ctx, size));
    assert!(
        shown.iter().any(|(text, _)| text == "Overview"),
        "{shown:?}"
    );
    assert!(
        !shown.iter().any(|(text, _)| text == "Summary"),
        "{shown:?}"
    );
    assert_eq!(Panel::Summary.title(), "Overview");
    // The saved arrangement keeps its id.
    let saved = serde_json::to_string(&Panel::Summary).unwrap();
    assert_eq!(saved, "\"Summary\"");
    click_label(&mut app, &ctx, size, "View");
    let menu = texts(&render(&mut app, &ctx, size));
    assert!(menu.iter().any(|(text, _)| text == "Overview"), "{menu:?}");
    assert!(!menu.iter().any(|(text, _)| text == "Summary"), "{menu:?}");
}

#[test]
fn the_overview_shows_vcpu_and_ram_together_and_a_gap_before_the_state() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = overview_app(false);
    let shown = texts(&settled(&mut app, &ctx, size));
    let find = |name: &str| {
        shown
            .iter()
            .filter(|(text, _)| text == name)
            .map(|(_, rect)| *rect)
            .collect::<Vec<_>>()
    };
    let vcpu = find("6 vCPU");
    let ram = find("3.0 GiB RAM");
    assert_eq!(vcpu.len(), 1, "the header no longer repeats it: {shown:?}");
    assert_eq!(ram.len(), 1, "{shown:?}");
    assert!(
        (vcpu[0].center().y - ram[0].center().y).abs() < 3.0,
        "side by side: {vcpu:?} {ram:?}"
    );
    assert!(ram[0].left() > vcpu[0].right());
    assert!(
        !shown.iter().any(|(text, _)| text.starts_with("Network: ")),
        "the header has no network line"
    );
    // The VM name and the state: room between them.
    let name = find("Analysis VM")[0];
    let state = find("Stopped")[0];
    assert!(state.left() - name.right() >= 14.0, "{name:?} {state:?}");
}

/// A dot beside one of the texts `label`, centred on that text's middle.
fn assert_dot_beside(output: &egui::FullOutput, label: &str) {
    let shown = texts(output);
    let dots = circles(output);
    let mut seen = Vec::new();
    for (_, text) in shown.iter().filter(|(text, _)| text == label) {
        let beside = dots
            .iter()
            .filter(|dot| {
                dot.center.x < text.left()
                    && text.left() - dot.center.x < 30.0
                    && (dot.center.y - text.center().y).abs() < 10.0
            })
            .min_by(|a, b| {
                (text.left() - a.center.x)
                    .partial_cmp(&(text.left() - b.center.x))
                    .unwrap()
            });
        if let Some(dot) = beside {
            seen.push((dot.center.y, text.center().y));
            if (dot.center.y - text.center().y).abs() <= 1.5 {
                return;
            }
        }
    }
    panic!("{label}: no dot on the middle of its text (dot y, text y): {seen:?}");
}

#[test]
fn state_dots_sit_on_the_middle_of_their_text() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    // The Overview's state, the sidebar row of the VM and the toolbar status.
    for active in [false, true] {
        let mut app = overview_app(active);
        let output = settled(&mut app, &ctx, size);
        let word = if active { "Running" } else { "Stopped" };
        assert_dot_beside(&output, word);
        assert_dot_beside(&output, "Analysis VM");
    }
    // A bigger text keeps the dot on the middle too.
    theme::text_size(&ctx, 22.0);
    let mut app = overview_app(false);
    let output = settled(&mut app, &ctx, size);
    assert_dot_beside(&output, "Stopped");
}
