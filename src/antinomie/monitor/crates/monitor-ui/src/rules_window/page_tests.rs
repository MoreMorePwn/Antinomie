// SPDX-License-Identifier: GPL-3.0-only
//! The Detection rules page: engine tabs, Installed and Catalog tabs, a
//! pack's rules and a rule's details, driven with local fixtures only.
use super::source_tests::{catalog_value, click, joined, model_for, render};
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1100.0, 1400.0);
const YARA: &str = "rule Zeta_Rule\n{\n  meta:\n    description = \"the zeta rule\"\n  strings:\n    $a = \"zeta\"\n  condition:\n    $a\n}\n\nrule Alpha_Rule\n{\n  meta:\n    description = \"the alpha rule\"\n  strings:\n    $a = \"alpha\"\n  condition:\n    $a\n}\n";

struct Fixture {
    dir: std::path::PathBuf,
    ctx: egui::Context,
    model: Model,
    outbound: bool,
    size: egui::Vec2,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("ant-rules-page-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        Self {
            dir,
            ctx,
            model: Model::default(),
            outbound: false,
            size: SIZE,
        }
    }

    fn frame(&mut self) -> Vec<(String, egui::Rect, egui::Rect)> {
        render(
            &self.ctx,
            &mut self.model,
            &self.dir,
            self.size,
            Vec::new(),
            &mut self.outbound,
        )
    }

    /// Render until `wanted` is painted (workers answer in the background).
    fn until(&mut self, wanted: &str) -> Vec<(String, egui::Rect, egui::Rect)> {
        let start = std::time::Instant::now();
        loop {
            let shown = self.frame();
            if joined(&shown).contains(wanted) {
                return shown;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "{wanted:?} never appeared: {}",
                joined(&shown)
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Render until the registry is read and no worker runs, so the layout
    /// holds still between the frames of a click.
    fn settle(&mut self) {
        let start = std::time::Instant::now();
        loop {
            self.frame();
            if self.model.loaded && self.model.job.is_none() {
                self.frame();
                return;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "never settled");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn click(&mut self, label: &str) {
        self.settle();
        let shown = self.frame();
        // A sorted header carries an arrow after its name.
        let at = shown
            .iter()
            .find(|(text, _, _)| text == label)
            .or_else(|| {
                shown.iter().rev().find(|(text, _, _)| {
                    text.starts_with(label) && text.chars().count() <= label.chars().count() + 2
                })
            })
            .unwrap_or_else(|| panic!("no {label}: {}", joined(&shown)))
            .1
            .center();
        click(
            &self.ctx,
            &mut self.model,
            &self.dir,
            self.size,
            &mut self.outbound,
            at,
        );
    }

    /// A custom group of one engine from a file of rules.
    fn group(&self, name: &str, engine: &str, file: &str, text: &str) {
        let path = self.dir.join(file);
        std::fs::write(&path, text).unwrap();
        ruleset::import_group(&self.dir, name, engine, &path).unwrap();
    }

    /// A hosted-archive pack, built by Python's tarfile.
    fn pack(&self, id: &str, engine: &str, file: &str, text: &str) {
        super::source_tests::install_fixture_pack(&self.dir, id, engine, file, text);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn top_of(shown: &[(String, egui::Rect, egui::Rect)], text: &str) -> f32 {
    shown
        .iter()
        .find(|(shown, _, _)| shown == text)
        .unwrap_or_else(|| panic!("no {text}"))
        .1
        .top()
}

/// The page's "Rules" button: the open-in-window icon, then the word.
fn rules_button(shown: &[(String, egui::Rect, egui::Rect)]) -> Option<egui::Rect> {
    shown
        .iter()
        .find(|(text, _, _)| {
            text.ends_with(" Rules") && text.starts_with(egui_phosphor::regular::ARROW_SQUARE_OUT)
        })
        .map(|shown| shown.1)
}

impl Fixture {
    /// Press the page's "Rules" button.
    fn open_list(&mut self) {
        let start = std::time::Instant::now();
        loop {
            self.settle();
            let shown = self.frame();
            if let Some(button) = rules_button(&shown) {
                click(
                    &self.ctx,
                    &mut self.model,
                    &self.dir,
                    self.size,
                    &mut self.outbound,
                    button.center(),
                );
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no Rules button: {}",
                joined(&shown)
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn engines_have_installed_and_catalog_tabs_and_keep_the_chosen_one() {
    let mut f = Fixture::new("tabs");
    let shown = f.until("Installed");
    for label in ["YARA", "IDS", "Sigma", "Installed", "Catalog"] {
        assert!(
            shown.iter().any(|(text, _, _)| text.starts_with(label)),
            "{label}: {}",
            joined(&shown)
        );
    }
    assert!(f.model.tab == Tab::Installed);
    f.click("Catalog");
    assert!(f.model.tab == Tab::Catalog);
    assert!(joined(&f.frame()).contains("no catalog has been checked yet"));
    f.click("IDS");
    assert_eq!(f.model.engine, "ids");
    assert!(
        f.model.tab == Tab::Catalog,
        "the tab survives an engine change"
    );
    f.click("Installed");
    assert!(f.model.tab == Tab::Installed);
    assert!(joined(&f.frame()).contains("None installed."));
}

#[test]
fn a_status_line_stays_on_the_page_it_happened_on() {
    let mut f = Fixture::new("scope");
    f.settle();
    f.click("IOC");
    f.model.status = "The last update of ThreatFox failed".into();
    assert!(joined(&f.frame()).contains("ThreatFox failed"));
    f.click("Sigma");
    let shown = joined(&f.frame());
    assert!(!shown.contains("ThreatFox failed"), "{shown}");
    // It is still the IOC page's when the person goes back.
    f.click("IOC");
    assert!(joined(&f.frame()).contains("ThreatFox failed"));
    // A result the next job writes shows where that job started.
    f.click("Sigma");
    f.model.status = "Catalog updated.".into();
    assert!(joined(&f.frame()).contains("Catalog updated."));
}

#[test]
fn a_pack_lists_all_its_rules_and_a_rule_shows_its_details_and_source() {
    let mut f = Fixture::new("pack");
    f.pack("fixture", "yara", "rules.yar", YARA);
    // The pack is the first set of the engine: it is selected and its rules
    // are counted without a click; they are listed in a window of their own.
    let shown = f.until("2 rules");
    let text = joined(&shown);
    assert!(text.contains("Fixture fixture"), "{text}");
    assert!(
        !text.contains("Alpha_Rule"),
        "the page has no inline rule table: {text}"
    );
    f.open_list();
    let shown = f.until("Alpha_Rule");
    let text = joined(&shown);
    assert!(
        text.contains("Zeta_Rule") && text.contains("2 rules"),
        "{text}"
    );
    assert!(
        top_of(&shown, "Zeta_Rule") < top_of(&shown, "Alpha_Rule"),
        "file order until a header is clicked"
    );
    // The header sorts the rules.
    f.click("Rule");
    let shown = f.frame();
    assert!(top_of(&shown, "Alpha_Rule") < top_of(&shown, "Zeta_Rule"));
    f.click("Rule");
    let shown = f.frame();
    assert!(top_of(&shown, "Zeta_Rule") < top_of(&shown, "Alpha_Rule"));
    // A click on a rule shows its details beside the list, with the source text.
    assert!(!joined(&shown).contains("Source text"));
    assert!(!f.model.rule_lists[0].has_selection());
    f.click("Alpha_Rule");
    let shown = f.until("$a = \"alpha\"");
    let text = joined(&shown);
    for wanted in ["File", "rules.yar", "Description", "the alpha rule"] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    assert!(text.contains("Source text"), "{text}");
    assert!(!text.contains("$a = \"zeta\""), "only the chosen rule");
}

#[test]
fn custom_groups_list_ids_and_sigma_rules_too() {
    let mut f = Fixture::new("engines");
    f.group(
        "Net",
        "ids",
        "net.rules",
        "alert tcp any any -> any 80 (msg:\"First beacon\"; sid:1001; rev:1;)\nalert tcp any any -> any 81 (msg:\"Second beacon\"; sid:1002; rev:1;)\n",
    );
    f.group(
        "Logs",
        "sigma",
        "log.yml",
        "title: Odd shell\nid: 11111111-1111-1111-1111-111111111111\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    Image: /bin/sh\n  condition: selection\nlevel: high\n",
    );
    f.click("IDS");
    f.open_list();
    f.until("Second beacon");
    f.click("Second beacon");
    let text = joined(&f.until("sid:1002"));
    assert!(!text.contains("sid:1001;"), "{text}");
    // The IDS list sits over the page's buttons: close it first.
    f.model.rule_lists.clear();
    f.click("Sigma");
    f.open_list();
    f.until("Odd shell");
    f.click("Odd shell");
    let text = joined(&f.until("condition: selection"));
    assert!(text.contains("Source text"), "{text}");
}

#[test]
fn a_catalog_pack_shows_its_metadata_and_that_its_rules_come_after_install() {
    let dir = std::env::temp_dir().join(format!("ant-rules-page-catalog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (catalog, _) = catalog_value();
    let mut model = model_for(&dir, &catalog);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut outbound = false;
    render(&ctx, &mut model, &dir, SIZE, Vec::new(), &mut outbound);
    let shown = render(&ctx, &mut model, &dir, SIZE, Vec::new(), &mut outbound);
    let text = joined(&shown);
    assert!(text.contains("Forge Core"), "{text}");
    assert!(text.contains("Available"), "{text}");
    assert!(text.contains("License: Each rule's own license"), "{text}");
    // Nothing follows the pack details, so no "Rules" heading ends the pane.
    let last = shown
        .iter()
        .max_by(|a, b| a.1.bottom().total_cmp(&b.1.bottom()))
        .map(|(text, _, _)| text.as_str());
    assert_ne!(last, Some("Rules"), "{text}");
    assert!(model.job.is_none(), "nothing was fetched");
    assert!(model.rows.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strings_regex_adds_patterns_with_grey_hints_and_a_full_width_expression() {
    let mut fixture = Fixture::new("regex-add");
    fixture.model.engine = "regex".into();
    let shown = fixture.until("Add patterns");
    let all = joined(&shown);
    assert!(!all.contains("Your patterns"), "{all}");
    assert!(!all.contains("These patterns find"), "{all}");
    assert!(!all.contains("A change applies to the next scan"), "{all}");
    // The placeholders are the grey hint colour, and the expression field
    // spans the page.
    let output = {
        let model = &mut fixture.model;
        let (dir, outbound) = (&fixture.dir, &mut fixture.outbound);
        let mut detection = antinomie_monitor_core::analysis::detection::Settings::default();
        let tools = ruleset::ToolConfig::default();
        fixture.ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let _ = model.page(ui, dir, outbound, &tools, &mut detection);
                });
            },
        )
    };
    fn hints(
        shape: &egui::epaint::Shape,
        clip: egui::Rect,
        out: &mut Vec<(String, egui::Color32, egui::Rect, egui::Rect)>,
    ) {
        match shape {
            egui::epaint::Shape::Text(text) => {
                if let Some(section) = text.galley.job.sections.first() {
                    out.push((
                        text.galley.text().to_owned(),
                        section.format.color,
                        clip,
                        egui::Rect::from_min_size(text.pos, text.galley.size()),
                    ));
                }
            }
            egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| hints(s, clip, out)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    for clipped in &output.shapes {
        hints(&clipped.shape, clipped.clip_rect, &mut found);
    }
    // egui 0.36 paints a field's hint through the panel's clip, not one of its
    // own, so the field is the smallest painted rectangle around the hint.
    fn frames(shape: &egui::epaint::Shape, out: &mut Vec<egui::Rect>) {
        match shape {
            egui::epaint::Shape::Rect(rect) => out.push(rect.rect),
            egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| frames(s, out)),
            _ => {}
        }
    }
    let mut rectangles = Vec::new();
    for clipped in &output.shapes {
        frames(&clipped.shape, &mut rectangles);
    }
    for entry in &mut found {
        let hint = entry.3;
        if let Some(field) = rectangles
            .iter()
            .filter(|rect| rect.expand(1.0).contains_rect(hint))
            .min_by(|a, b| a.area().total_cmp(&b.area()))
        {
            entry.2 = *field;
        }
    }
    for start in ["Name, e.g.", "Regular expression, such as"] {
        let (text, color, clip, rect) = found
            .iter()
            .find(|(text, _, _, _)| text.starts_with(start))
            .unwrap_or_else(|| panic!("no {start} hint"));
        assert_eq!(*color, crate::theme::hint(), "{text}");
        // The whole hint shows: the field is as wide as the hint is long.
        assert!(
            clip.right() >= rect.right(),
            "{text} is cut: {rect:?} in {clip:?}"
        );
    }
    // One row: the name, the expression and Add side by side, the expression
    // taking what the others leave.
    let rect_of = |start: &str| {
        found
            .iter()
            .find(|(text, _, _, _)| text.starts_with(start))
            .map(|(_, _, clip, rect)| (*clip, *rect))
            .unwrap()
    };
    let (_, name) = rect_of("Name, e.g.");
    let (wide_clip, wide) = rect_of("Regular expression, such as");
    assert!(
        (name.center().y - wide.center().y).abs() < 4.0,
        "the name {name:?} and the expression {wide:?} share a row"
    );
    assert!(wide.left() > name.right(), "{name:?} then {wide:?}");
    assert!(wide_clip.width() > SIZE.x * 0.45, "{wide_clip:?}");
    let (_, _, _, add) = *found
        .iter()
        .find(|(text, _, _, _)| text == "Add")
        .expect("the Add button");
    assert!(
        (add.center().y - wide.center().y).abs() < 6.0 && add.left() >= wide_clip.right() - 1.0,
        "Add {add:?} ends the row of {wide_clip:?}"
    );
    assert!(add.right() <= SIZE.x, "{add:?}");
}

/// The Strings regex tab in a real window, for screenshots.
/// ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1100x700.
#[test]
#[ignore = "requires X11 native rendering; exits after 12 seconds"]
fn native_regex_tab_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct App {
        model: Model,
        dir: std::path::PathBuf,
        outbound: bool,
        deadline: std::time::Instant,
    }
    impl eframe::App for App {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            egui::CentralPanel::default().show(root, |ui| {
                let mut detection =
                    antinomie_monitor_core::analysis::detection::Settings::default();
                let tools = ruleset::ToolConfig::default();
                let _ = self
                    .model
                    .page(ui, &self.dir, &mut self.outbound, &tools, &mut detection);
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => crate::theme::Theme::Light,
        "blue" => crate::theme::Theme::Blue,
        _ => crate::theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1100.0, 700.0));
    let dir = std::env::temp_dir().join(format!("ant-qa-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let model = Model {
        engine: "regex".into(),
        ..Model::default()
    };
    eframe::run_native(
        "Antinomie Rules QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::apply_theme(&cc.egui_ctx, theme_choice);
            if let Ok(size) = var("ANTINOMIE_QA_FONT").parse::<f32>() {
                crate::theme::text_size(&cc.egui_ctx, size);
            }
            Ok(Box::new(App {
                model,
                dir,
                outbound: false,
                deadline: std::time::Instant::now()
                    + Duration::from_secs(var("ANTINOMIE_QA_SECONDS").parse().unwrap_or(12)),
            }))
        }),
    )
    .unwrap();
}

/// The Detection rules page in a real window with an installed pack of
/// long rule names and the catalogue, for screenshots.
/// ANTINOMIE_QA_TAB = installed | catalog (default installed), ANTINOMIE_QA_ONLINE = 1
/// allows downloads, ANTINOMIE_QA_THEME and ANTINOMIE_QA_SIZE as above.
#[test]
#[ignore = "requires X11 native rendering; exits after 12 seconds"]
fn native_rules_pack_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct App {
        model: Model,
        dir: std::path::PathBuf,
        outbound: bool,
        deadline: std::time::Instant,
        /// Removes the data directory when the window closes.
        _fixture: Fixture,
    }
    impl eframe::App for App {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            egui::CentralPanel::default().show(root, |ui| {
                let mut detection =
                    antinomie_monitor_core::analysis::detection::Settings::default();
                let tools = ruleset::ToolConfig::default();
                let _ = self
                    .model
                    .page(ui, &self.dir, &mut self.outbound, &tools, &mut detection);
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => crate::theme::Theme::Light,
        "blue" => crate::theme::Theme::Blue,
        _ => crate::theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1100.0, 700.0));
    let fixture = Fixture::new("native");
    let rules: String = [
        "Windows_Trojan_Generic_Credential_Stealer_Browser_Profiles",
        "Linux_Cryptominer_Xmrig_Miner_Configuration_Strings",
        "MAL_Ransomware_Linux_Encrypts_Home_Directory_Files",
    ]
    .iter()
    .map(|name| {
        format!("rule {name}\n{{\n  meta:\n    description = \"{name}\"\n  strings:\n    $a = \"{name}\"\n  condition:\n    $a\n}}\n\n")
    })
    .collect();
    fixture.pack("signature-base", "yara", "rules.yar", &rules);
    let (catalog, _) = catalog_value();
    ruleset::store_catalog(&fixture.dir, &ruleset::validate_catalog(&catalog).unwrap()).unwrap();
    let model = Model {
        engine: "yara".into(),
        tab: if var("ANTINOMIE_QA_TAB") == "catalog" {
            Tab::Catalog
        } else {
            Tab::Installed
        },
        catalog_pick: "forge-core".into(),
        catalog: ruleset::load_catalog(&fixture.dir).unwrap(),
        ..Model::default()
    };
    let dir = fixture.dir.clone();
    let outbound = var("ANTINOMIE_QA_ONLINE") == "1";
    eframe::run_native(
        "Antinomie Rules QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::apply_theme(&cc.egui_ctx, theme_choice);
            if let Ok(size) = var("ANTINOMIE_QA_FONT").parse::<f32>() {
                crate::theme::text_size(&cc.egui_ctx, size);
            }
            Ok(Box::new(App {
                model,
                dir,
                outbound,
                deadline: std::time::Instant::now()
                    + Duration::from_secs(var("ANTINOMIE_QA_SECONDS").parse().unwrap_or(12)),
                _fixture: fixture,
            }))
        }),
    )
    .unwrap();
}

#[test]
fn a_pack_rule_list_holds_still_frame_after_frame() {
    // Item 21: the rule table of a chosen pack shrank and grew by a few
    // points every frame. Long rule names and file names, at a fractional
    // text size, in a narrow and a wide window: no header may move.
    let mut rules = String::new();
    for index in 0..40 {
        rules.push_str(&format!(
            "rule A_Very_Long_Rule_Name_For_Layout_Checks_Number_{index:02}_With_More_Words\n{{\n  meta:\n    description = \"{}\"\n  strings:\n    $a = \"x{index}\"\n  condition:\n    $a\n}}\n\n",
            "a long description ".repeat(8)
        ));
    }
    for (width, font) in [(1100.0, 18.0), (760.0, 18.0), (1600.0, 16.0), (720.0, 20.0)] {
        let mut f = Fixture::new(&format!("still-{width}"));
        crate::theme::text_size(&f.ctx, font);
        f.pack(
            "fixture",
            "yara",
            "a_rather_long_file_name_for_the_rules.yar",
            &rules,
        );
        let size = egui::vec2(width, 1000.0);
        f.open_list();
        f.until("Number_00");
        let mut first: Option<Vec<f32>> = None;
        for frame in 0..100 {
            let shown = render(
                &f.ctx,
                &mut f.model,
                &f.dir,
                size,
                Vec::new(),
                &mut f.outbound,
            );
            let mut edges: Vec<f32> = ["Severity", "State", "File"]
                .iter()
                .filter_map(|title| {
                    shown
                        .iter()
                        .find(|(text, _, _)| text.starts_with(title))
                        .map(|(_, rect, _)| rect.left())
                })
                .collect();
            // Every column is on screen: none is pushed past the table's edge.
            assert_eq!(
                edges.len(),
                3,
                "a column header is cut off at {width}/{font}: {}",
                joined(&shown)
            );
            edges.push(
                shown
                    .iter()
                    .filter(|(text, _, _)| text.contains("Number_"))
                    .map(|(_, rect, clip)| rect.right().min(clip.right()))
                    .fold(0.0, f32::max),
            );
            match &first {
                None if frame >= 5 => first = Some(edges),
                Some(first) => assert!(
                    first.iter().zip(&edges).all(|(a, b)| (a - b).abs() < 0.01),
                    "the rule table moves at {width}/{font}, frame {frame}: {first:?} -> {edges:?}"
                ),
                None => {}
            }
            for (_, rect, clip) in &shown {
                assert!(
                    rect.right().min(clip.right()) <= width + 0.5,
                    "text past the window at {width}/{font}"
                );
            }
        }
    }
}

#[test]
fn the_header_counts_packs_groups_and_patterns_in_the_right_number() {
    let mut f = Fixture::new("counts");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.group(
        "Net",
        "ids",
        "net.rules",
        "alert tcp any any -> any 80 (msg:\"First beacon\"; sid:1001; rev:1;)\n",
    );
    f.settle();
    let patterns = f.model.regex.active_count();
    let text = joined(&f.frame());
    assert!(
        text.contains(&format!(
            "1 pack · 1 enabled · 1 custom group · {patterns} string patterns"
        )),
        "{text}"
    );
    // The engine tab repeats the counts for its own rules, in the IOC style.
    assert!(
        text.contains("1 of 1 pack enabled · 0 custom groups"),
        "{text}"
    );
}

#[test]
fn long_explanations_are_a_tooltip_and_not_on_the_page() {
    let mut f = Fixture::new("tooltips");
    f.ctx
        .all_styles_mut(|style| style.interaction.tooltip_delay = 0.0);
    f.settle();
    f.click("IOC");
    let shown = f.until("abuse.ch datasets kept on this machine.");
    let text = joined(&shown);
    assert!(!text.contains("They change only when you press"), "{text}");
    f.settle();
    let label = "abuse.ch datasets kept on this machine.";
    let mut shown = f.frame();
    let mut hovered = String::new();
    for _ in 0..8 {
        let at = shown
            .iter()
            .find(|(text, _, _)| text == label)
            .unwrap()
            .1
            .center();
        shown = render(
            &f.ctx,
            &mut f.model,
            &f.dir,
            f.size,
            vec![egui::Event::PointerMoved(at)],
            &mut f.outbound,
        );
        hovered = joined(&shown);
        if hovered.contains("They change only when") {
            break;
        }
    }
    assert!(
        hovered.contains("They change only when you press Download or Update."),
        "{hovered}"
    );
}

type Texts = Vec<(String, egui::Rect, egui::Rect)>;

fn fills(f: &mut Fixture) -> (Texts, Vec<(egui::Color32, egui::Rect)>) {
    fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(egui::Color32, egui::Rect)>) {
        match shape {
            egui::epaint::Shape::Rect(rect) => out.push((rect.fill, rect.rect)),
            egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut detection = antinomie_monitor_core::analysis::detection::Settings::default();
    let tools = ruleset::ToolConfig::default();
    let output = f.ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let _ = f
                    .model
                    .page(ui, &f.dir, &mut f.outbound, &tools, &mut detection);
            });
            let ctx = root.ctx().clone();
            f.model.show_rule_lists(&ctx, &f.dir);
        },
    );
    let mut rects = Vec::new();
    for shape in &output.shapes {
        walk(&shape.shape, &mut rects);
    }
    (super::source_tests::texts(&output), rects)
}

#[test]
fn clicking_a_rule_shows_it_in_the_same_window_and_the_code_sits_on_a_filled_block() {
    let mut f = Fixture::new("rule-window");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    f.until("Alpha_Rule");
    f.click("Alpha_Rule");
    f.until("$a = \"alpha\"");
    assert_eq!(f.model.rule_lists.len(), 1);
    // Another rule replaces the details in the same window: no second window.
    f.click("Zeta_Rule");
    let shown = f.until("$a = \"zeta\"");
    assert_eq!(f.model.rule_lists.len(), 1);
    assert!(!joined(&shown).contains("$a = \"alpha\""));
    f.click("Alpha_Rule");
    f.until("$a = \"alpha\"");
    let (shown, rects) = fills(&mut f);
    let code = shown
        .iter()
        .find(|(text, _, _)| text.contains("$a = \"alpha\""))
        .expect("the code is drawn")
        .1;
    let background = f.ctx.global_style().visuals.code_bg_color;
    let block = rects
        .iter()
        .find(|(fill, rect)| *fill == background && rect.contains_rect(code))
        .expect("the code sits on the code background")
        .1;
    assert!(
        block.min.x < code.min.x && block.max.x > code.max.x,
        "padded"
    );
    assert!(
        block.min.y < code.min.y && block.max.y > code.max.y,
        "padded"
    );
}

#[test]
fn the_list_rules_stay_within_its_window_and_are_one_pixel_wide() {
    let mut f = Fixture::new("rules-lines");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    f.until("Alpha_Rule");
    f.settle();
    let output = f.ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            ..Default::default()
        },
        |root| {
            // Only the rules window: the page behind it has table lines too.
            let ctx = root.ctx().clone();
            f.model.show_rule_lists(&ctx, &f.dir);
        },
    );
    fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(egui::Pos2, egui::Pos2, f32)>) {
        match shape {
            egui::epaint::Shape::LineSegment { points, stroke } => {
                out.push((points[0], points[1], stroke.width))
            }
            egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    let window = f
        .ctx
        .memory(|memory| memory.area_rect(f.model.rule_lists[0].id()))
        .expect("the list window is placed");
    let mut lines = Vec::new();
    for shape in &output.shapes {
        walk(&shape.shape, &mut lines);
    }
    let rules: Vec<_> = lines
        .iter()
        .filter(|(a, b, _)| a.y == b.y && b.x - a.x > 100.0 && window.contains(*a))
        .collect();
    assert!(!rules.is_empty());
    // A header cell reaches half of the theme's column spacing past the table
    // and no more; the table stays inside its window.
    let reach = f.ctx.global_style().spacing.item_spacing.x / 2.0 + 0.01;
    for (a, b, width) in &rules {
        assert!(*width <= 1.0, "rule {width} wide");
        assert!(
            a.x >= window.left() - reach && b.x <= window.right() + reach,
            "{a:?} {b:?} in {window:?}"
        );
    }
}

#[test]
fn a_rule_window_stays_drawn_when_the_rules_page_is_not() {
    let mut f = Fixture::new("rule-window-stays");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    f.until("Alpha_Rule");
    f.click("Alpha_Rule");
    f.until("$a = \"alpha\"");
    // Another page is showing: the app draws only the spawned windows.
    let mut shown = String::new();
    for _ in 0..3 {
        let output = f.ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    ui.label("Another page");
                });
                let ctx = root.ctx().clone();
                f.model.show_rule_lists(&ctx, &f.dir);
            },
        );
        shown = joined(&super::source_tests::texts(&output));
    }
    assert!(shown.contains("Another page"), "{shown}");
    assert!(shown.contains("$a = \"alpha\""), "{shown}");
    assert!(
        shown.contains("Zeta_Rule"),
        "the rule list stays too: {shown}"
    );
    assert_eq!(f.model.rule_lists.len(), 1);
}

#[test]
fn the_page_has_only_the_pack_details_and_a_rules_button_left_of_export_manifest() {
    let mut f = Fixture::new("button");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.until("2 rules");
    f.settle();
    let shown = f.frame();
    let text = joined(&shown);
    // No inline rule table: no rule names, no filter box, no table headers.
    for gone in [
        "Alpha_Rule",
        "Zeta_Rule",
        "filter e.g. credential",
        "Severity",
        "Open details",
    ] {
        assert!(!text.contains(gone), "{gone} is still on the page: {text}");
    }
    assert!(f.model.rule_lists.is_empty());
    let button = rules_button(&shown).expect("a Rules button");
    let export = shown
        .iter()
        .find(|(text, _, _)| text == "Export manifest")
        .expect("Export manifest")
        .1;
    assert!(button.right() < export.left(), "{button:?} {export:?}");
    assert!(
        (button.center().y - export.center().y).abs() < 4.0,
        "same row: {button:?} {export:?}"
    );
}

#[test]
fn the_rules_button_opens_one_list_window_per_pack_with_a_filter_and_a_count() {
    let mut f = Fixture::new("list");
    f.ctx
        .all_styles_mut(|style| style.interaction.tooltip_delay = 0.0);
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    let shown = f.until("Alpha_Rule");
    let text = joined(&shown);
    assert_eq!(f.model.rule_lists.len(), 1);
    assert!(text.contains("Rules · Fixture fixture"), "{text}");
    assert!(text.contains("2 of 2 rules"), "{text}");
    assert!(text.contains("filter e.g. credential"), "{text}");
    assert!(!text.contains("Open details"), "{text}");
    assert!(text.contains("Zeta_Rule"), "{text}");
    // The button again brings the window forward; it is still one.
    f.open_list();
    f.frame();
    assert_eq!(f.model.rule_lists.len(), 1);
    // The filter narrows the list and the count follows.
    f.model.rule_lists[0].filter = "alpha".into();
    let shown = f.frame();
    let text = joined(&shown);
    assert!(text.contains("1 of 2 rules"), "{text}");
    assert!(!text.contains("Zeta_Rule"), "{text}");
}

const CAPITAL: &str = "rule Cap_Rule\n{\n  meta:\n    Description = \"capital desc\"\n    Author = \"Ann Analyst\"\n    License = \"MIT\"\n    reference = \"https://example.test/cap\"\n  strings:\n    $a = \"cap\"\n  condition:\n    $a\n}\n";

fn window_rect(f: &Fixture) -> egui::Rect {
    f.ctx
        .memory(|memory| memory.area_rect(f.model.rule_lists[0].id()))
        .expect("the rules window is placed")
}

#[test]
fn the_details_sit_in_the_right_pane_of_the_same_window() {
    let mut f = Fixture::new("right-pane");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    let before = f.until("Alpha_Rule");
    assert!(
        joined(&before).contains("Select a rule"),
        "{}",
        joined(&before)
    );
    f.click("Alpha_Rule");
    let shown = f.until("$a = \"alpha\"");
    let window = window_rect(&f);
    let find = |label: &str| {
        shown
            .iter()
            .find(|(text, _, _)| text == label)
            .unwrap_or_else(|| panic!("no {label}: {}", joined(&shown)))
            .1
    };
    // The list stays at the left; the details start right of the divider.
    assert!(find("Zeta_Rule").right() < window.center().x + 40.0);
    for label in ["ID", "File", "Source text"] {
        assert!(find(label).left() > window.center().x - 0.15 * window.width());
        assert!(find(label).left() > find("Zeta_Rule").left() + 100.0);
    }
    assert_eq!(f.model.rule_lists.len(), 1, "no window of its own");
}

#[test]
fn the_window_opens_within_the_content_area_and_does_not_grow() {
    let mut f = Fixture::new("size");
    f.pack("fixture", "yara", "rules.yar", YARA);
    f.open_list();
    f.until("Alpha_Rule");
    f.click("Alpha_Rule");
    f.until("$a = \"alpha\"");
    for _ in 0..4 {
        f.frame();
    }
    let area = crate::title_bar::content_rect(&f.ctx);
    let first = window_rect(&f);
    assert!(first.width() <= area.width(), "{first:?} in {area:?}");
    assert!(first.height() <= area.height(), "{first:?} in {area:?}");
    assert!(first.width() <= area.width() * 0.70 + 60.0, "{first:?}");
    assert!(first.height() <= area.height() * 0.75 + 60.0, "{first:?}");
    // Frames later it is the same size: a table that fed its height back to
    // the window made it grow until it hit the edge.
    for _ in 0..30 {
        f.frame();
    }
    assert_eq!(window_rect(&f).size(), first.size());
}

#[test]
fn the_details_grid_has_labels_with_room_between_rows_and_a_capital_description() {
    let mut f = Fixture::new("grid");
    f.pack("fixture", "yara", "rules.yar", CAPITAL);
    f.open_list();
    f.until("Cap_Rule");
    f.click("Cap_Rule");
    f.until("$a = \"cap\"");
    // The grid sizes its columns from the frame before: let it settle.
    for _ in 0..4 {
        f.frame();
    }
    let shown = f.frame();
    let window = window_rect(&f);
    let at = |label: &str| {
        shown
            .iter()
            .filter(|(text, rect, _)| text == label && window.contains(rect.min))
            .map(|(_, rect, _)| *rect)
            .max_by(|a, b| a.left().total_cmp(&b.left()))
            .unwrap_or_else(|| panic!("no {label}: {}", joined(&shown)))
    };
    let labels = ["ID", "File", "Author", "License", "State"];
    let labels: Vec<_> = labels
        .iter()
        .filter(|label| shown.iter().any(|(text, _, _)| text == *label))
        .collect();
    for needed in ["ID", "File", "Author", "License", "State"] {
        assert!(labels.contains(&&needed), "{needed}: {}", joined(&shown));
    }
    let rows: Vec<_> = labels.iter().map(|label| at(label)).collect();
    for pair in rows.windows(2) {
        assert!(
            (pair[0].left() - pair[1].left()).abs() < 1.0,
            "one column {rows:?}"
        );
        assert!(
            pair[1].top() - pair[0].bottom() >= super::rule_details::ROW_GAP - 1.0,
            "{pair:?}\n{:?}",
            shown
                .iter()
                .map(|(t, r, _)| format!("{t:?} {r:?}"))
                .collect::<Vec<_>>()
        );
    }
    // The capitalised key is the description; the value sits right of its label.
    let text = joined(&shown);
    assert!(text.contains("capital desc"), "{text}");
    assert!(text.contains("Ann Analyst"), "{text}");
    assert!(at("capital desc").left() > at("Description").right());
    assert!(text.contains("https://example.test/cap"), "{text}");
}

/// A rule with a 900-character source line, a very long reference and a
/// long unbroken description.
fn long_rule() -> String {
    let long = "x".repeat(900);
    format!(
        "rule Long_Rule\n{{\n  meta:\n    description = \"{long}\"\n    reference = \"https://example.test/{long}\"\n  strings:\n    $a = \"{long}\"\n  condition:\n    $a\n}}\n"
    )
}

#[test]
fn a_long_rule_neither_widens_nor_lengthens_the_window_and_its_code_scrolls() {
    for size in [egui::vec2(1100.0, 1400.0), egui::vec2(900.0, 700.0)] {
        let mut f = Fixture::new("long");
        f.size = size;
        f.pack("fixture", "yara", "rules.yar", &long_rule());
        f.open_list();
        f.until("Long_Rule");
        f.click("Long_Rule");
        f.until("Evidence");
        for _ in 0..40 {
            f.frame();
        }
        let window = window_rect(&f);
        let area = crate::title_bar::content_rect(&f.ctx);
        assert!(
            window.width() <= area.width() * 0.8 + 1.0,
            "{window:?} in {area:?}"
        );
        assert!(
            window.height() <= area.height() * 0.8 + 1.0,
            "{window:?} in {area:?}"
        );
        assert!(window.width() >= 280.0, "{window:?}");
    }
}

/// A rule with a long name, a long reference and a source line of 600 characters.
fn long_name_rule() -> String {
    let long = "x".repeat(600);
    let name = format!("Long_Rule_{}", "n".repeat(120));
    format!("rule {name}\n{{\n  meta:\n    description = \"{long}\"\n    reference = \"https://example.test/{long}\"\n  strings:\n    $a = \"{long}\"\n  condition:\n    $a\n}}\n")
}

#[test]
fn a_long_rule_never_takes_the_window_past_its_cap_and_the_list_takes_40_percent() {
    for size in [egui::vec2(1280.0, 800.0), egui::vec2(1920.0, 1080.0)] {
        let mut f = Fixture::new("long-rule");
        f.size = size;
        f.pack("fixture", "yara", "rules.yar", &long_name_rule());
        f.open_list();
        f.until("Long_Rule_");
        f.settle();
        f.model.rule_lists[0].select(0);
        f.until("Compatibility");
        for _ in 0..30 {
            f.frame();
        }
        let area = crate::title_bar::content_rect(&f.ctx);
        let cap = crate::widgets::cap_size(area) + crate::widgets::frame_extra(&f.ctx);
        let window = window_rect(&f);
        assert!(
            window.width() <= cap.x + 0.5 && window.height() <= cap.y + 0.5,
            "{size:?}: {window:?} over {cap:?}"
        );
        assert!(
            area.expand(0.5).contains_rect(window),
            "{window:?} in {area:?}"
        );
        let before = window.size();
        for _ in 0..30 {
            f.frame();
        }
        assert_eq!(window_rect(&f).size(), before);
        // Nothing the window draws reaches past its edge.
        let shown = f.frame();
        for (text, rect, clip) in &shown {
            if text.starts_with("xxx")
                || text.starts_with("https://example.test/")
                || text.starts_with("Long_Rule_")
            {
                assert!(
                    clip.right() <= window.right() + 0.5,
                    "{size:?}: {text:?} {rect:?} clip {clip:?} past {window:?}"
                );
            }
        }
        // 40:60: the divider sits at about 40% of the window's contents.
        let shown = f.frame();
        let at = |label: &str| {
            shown
                .iter()
                .find(|(text, _, _)| text == label)
                .unwrap_or_else(|| panic!("no {label}: {}", joined(&shown)))
                .1
        };
        let share = (at("ID").left() - window.left()) / window.width();
        assert!(
            (0.38..=0.46).contains(&share),
            "{size:?}: details start at {share}"
        );
    }
}
