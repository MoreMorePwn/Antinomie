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
        }
    }

    fn frame(&mut self) -> Vec<(String, egui::Rect, egui::Rect)> {
        render(
            &self.ctx,
            &mut self.model,
            &self.dir,
            SIZE,
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
            SIZE,
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
        let source = self.dir.join(format!("{id}.src"));
        std::fs::write(&source, text).unwrap();
        let archive = self.dir.join(format!("{id}.tar.gz"));
        let script = r#"
import gzip, io, sys, tarfile
source, destination, member = sys.argv[1:4]
data = open(source, "rb").read()
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
    info = tarfile.TarInfo(member)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))
with open(destination, "wb") as output:
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        compressed.write(raw.getvalue())
"#;
        let status = std::process::Command::new("python3")
            .args(["-c", script])
            .args([&source, &archive])
            .arg(file)
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&archive).unwrap();
        let entry = ruleset::PackEntry {
            id: id.into(),
            engine: engine.into(),
            name: format!("Fixture {id}"),
            version: "1".into(),
            upstream_revision: "r1".into(),
            upstream_url: "https://example.invalid/".into(),
            download_url: "https://example.invalid/p.tar.gz".into(),
            sha256: antinomie_monitor_core::storage::sha256_hex(&bytes),
            size: bytes.len() as u64,
            app: ">=0.6.2".into(),
            engine_requirement: "YARA-X 1.21".into(),
            rules: 2,
            helpers: 0,
            license: "MIT".into(),
            evidence: vec!["sample".into()],
            limits: Vec::new(),
        };
        ruleset::install_archive(&self.dir, &entry, &bytes).unwrap();
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
fn a_pack_lists_all_its_rules_and_a_rule_shows_its_details_and_source() {
    let mut f = Fixture::new("pack");
    f.pack("fixture", "yara", "rules.yar", YARA);
    // The pack is the first set of the engine: it is selected and its rules
    // are read without a click.
    let shown = f.until("Alpha_Rule");
    let text = joined(&shown);
    assert!(text.contains("Fixture fixture"), "{text}");
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
    // A click on a rule shows its details and its source text.
    assert!(joined(&shown).contains("Select a rule."));
    f.click("Alpha_Rule");
    let shown = f.until("$a = \"alpha\"");
    let text = joined(&shown);
    assert!(text.contains("File: rules.yar"), "{text}");
    assert!(text.contains("Description: the alpha rule"), "{text}");
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
    f.until("Second beacon");
    f.click("Second beacon");
    let text = joined(&f.until("sid:1002"));
    assert!(!text.contains("sid:1001;"), "{text}");
    f.click("Sigma");
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
        fixture.ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
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
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
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
            Ok(Box::new(App {
                model,
                dir,
                outbound: false,
                deadline: std::time::Instant::now() + Duration::from_secs(12),
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
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
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
            Ok(Box::new(App {
                model,
                dir,
                outbound,
                deadline: std::time::Instant::now() + Duration::from_secs(12),
                _fixture: fixture,
            }))
        }),
    )
    .unwrap();
}
