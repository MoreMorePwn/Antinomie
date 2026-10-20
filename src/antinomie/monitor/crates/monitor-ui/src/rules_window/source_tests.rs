// SPDX-License-Identifier: MIT
//! The Rule manager's schema 2 view, driven with local fixtures only.
use super::*;
use antinomie_monitor_core::ruleset::{Fetcher, PackEntry};

const URL: &str = "https://github.com/example/forge/releases/download/1/rules.yar";
const MEMBER: &str = "rules.yar";

fn rules_text() -> String {
    let set = |name: &str, repository: &str, license: &str, body: &str| {
        format!(
            "/*\n * YARA Rule Set\n * Repository Name: {name}\n * Repository: {repository}\n *\n * LICENSE\n * \n * {license}\n */\n\n{body}\n"
        )
    };
    let rule = |name: &str| {
        format!("rule {name}\n{{\n\tmeta:\n\t\tdescription = \"{name}\"\n\tstrings:\n\t\t$a = \"{name}\"\n\tcondition:\n\t\t$a\n}}\n")
    };
    format!(
        "{}{}",
        set(
            "Open",
            "https://github.com/example/open-rules",
            "MIT License. Permission is hereby granted.",
            &rule("Open_One"),
        ),
        set(
            "Closed",
            "https://github.com/example/closed-rules",
            "NO LICENSE SET",
            &rule("Closed_One"),
        ),
    )
}

struct Served(Vec<u8>);

impl Fetcher for Served {
    fn fetch(
        &self,
        _url: &str,
        dest: &Path,
        _max: u64,
        _cancel: &AtomicBool,
        _progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        std::fs::write(dest, &self.0).map_err(|error| error.to_string())
    }
}

fn catalog_value() -> (serde_json::Value, Vec<u8>) {
    let text = rules_text();
    let archive = text.clone().into_bytes();
    let sha = |bytes: &[u8]| antinomie_monitor_core::storage::sha256_hex(bytes);
    let value = serde_json::json!({"schema": 2, "packs": [{
        "id": "forge-core", "engine": "yara", "name": "Forge Core",
        "homepage": "https://github.com/example/forge",
        "license": "Each rule's own license, or its repository's license",
        "license_url": "https://github.com/example/forge/blob/main/LICENSE",
        "revision": "1", "revision_kind": "release", "app": ">=0.6.2",
        "engine_requirement": "YARA-X 1.21", "rules": 2,
        "sources": [{"url": URL, "format": "file", "size": archive.len(),
            "sha256": sha(&archive),
            "files": [{"path": MEMBER, "sha256": sha(text.as_bytes())}]}],
        "filter": {"kind": "yara-forge",
            "allowed_licenses": ["MIT"],
            "allowed_repository_licenses": ["MIT"],
            "repository_licenses": {
                "https://github.com/example/open-rules": {"license": "MIT"}}},
        "options": [{"id": "include-unlicensed",
            "label": "Include rules from repositories without a license",
            "default": false,
            "warning": "All rights reserved; local use only."}]
    }]});
    (value, archive)
}

fn render(
    ctx: &egui::Context,
    model: &mut Model,
    dir: &Path,
    size: egui::Vec2,
    events: Vec<egui::Event>,
    outbound: &mut bool,
) -> Vec<(String, egui::Rect, egui::Rect)> {
    let mut detection = antinomie_monitor_core::analysis::detection::Settings::default();
    let tools = ruleset::ToolConfig::default();
    ctx.style_mut(|style| style.animation_time = 0.0);
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = model.page(ui, dir, outbound, &tools, &mut detection);
            });
        },
    );
    texts(&output)
}

fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect, egui::Rect)> {
    fn collect(
        shape: &egui::epaint::Shape,
        clip: egui::Rect,
        out: &mut Vec<(String, egui::Rect, egui::Rect)>,
    ) {
        match shape {
            egui::epaint::Shape::Text(text) => out.push((
                text.galley.text().to_owned(),
                egui::Rect::from_min_size(text.pos, text.galley.size()),
                clip,
            )),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, clip, out);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, shape.clip_rect, &mut found);
    }
    found
}

fn joined(shown: &[(String, egui::Rect, egui::Rect)]) -> String {
    shown
        .iter()
        .map(|(text, _, _)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn click(
    ctx: &egui::Context,
    model: &mut Model,
    dir: &Path,
    size: egui::Vec2,
    outbound: &mut bool,
    at: egui::Pos2,
) {
    for pressed in [None, Some(true), Some(false)] {
        let mut events = vec![egui::Event::PointerMoved(at)];
        if let Some(pressed) = pressed {
            events.push(egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            });
        }
        render(ctx, model, dir, size, events, outbound);
    }
}

fn model_for(dir: &Path, catalog: &serde_json::Value) -> Model {
    ruleset::store_catalog(dir, &ruleset::validate_catalog(catalog).unwrap()).unwrap();
    Model {
        loaded: true,
        engine: "yara".into(),
        catalog: ruleset::load_catalog(dir).unwrap(),
        registry: ruleset::load_registry(dir).unwrap(),
        ..Default::default()
    }
}

#[test]
fn the_manager_shows_source_license_hosts_and_the_off_by_default_option() {
    let dir = std::env::temp_dir().join(format!("ant-rules-src-ui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (catalog, archive) = catalog_value();
    let mut model = model_for(&dir, &catalog);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut outbound = false;
    let wide = egui::vec2(900.0, 1400.0);
    render(&ctx, &mut model, &dir, wide, Vec::new(), &mut outbound);
    let shown = render(&ctx, &mut model, &dir, wide, Vec::new(), &mut outbound);
    let text = joined(&shown);
    // The catalog entry: name, pin, source, license and the hosts.
    assert!(
        text.contains("Forge Core · release 1 · about 2 rules"),
        "{text}"
    );
    assert!(text.contains("Source: github.com/example/forge"), "{text}");
    assert!(text.contains("License: Each rule's own license"), "{text}");
    assert!(text.contains("from github.com"), "{text}");
    // The consent names the hosts before downloads are allowed.
    assert!(text.contains("Downloads are off"), "{text}");
    assert!(text.contains("Rule downloads contact only:"), "{text}");
    assert!(text.contains("codeload.github.com"), "{text}");
    assert!(text.contains("huggingface.co"), "{text}");
    // The no-license option exists, is off, and shows no warning yet.
    assert!(
        text.contains("Include rules from repositories without a license"),
        "{text}"
    );
    assert!(text.contains("Off by default."), "{text}");
    assert!(
        !text.contains("All rights reserved; local use only."),
        "{text}"
    );
    assert!(text.contains("Download and install"), "{text}");
    assert!(model
        .choices
        .get("forge-core")
        .is_some_and(BTreeSet::is_empty));

    // Without permission the button explains instead of contacting anyone.
    let button = shown
        .iter()
        .find(|(text, _, _)| text == "Download and install")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut model, &dir, wide, &mut outbound, button);
    assert!(model.job.is_none());
    assert!(
        model.status.contains("Allow downloads first"),
        "{}",
        model.status
    );
    assert!(model.status.contains("github.com"), "{}", model.status);

    // Ticking the option shows its warning.
    let shown = render(&ctx, &mut model, &dir, wide, Vec::new(), &mut outbound);
    let checkbox = shown
        .iter()
        .find(|(text, _, _)| text.contains("Include rules from repositories"))
        .unwrap()
        .1
        .left_center()
        - egui::vec2(18.0, 0.0);
    click(&ctx, &mut model, &dir, wide, &mut outbound, checkbox);
    let text = joined(&render(
        &ctx,
        &mut model,
        &dir,
        wide,
        Vec::new(),
        &mut outbound,
    ));
    assert!(
        text.contains("All rights reserved; local use only."),
        "{text}"
    );
    assert!(model.choices["forge-core"].contains("include-unlicensed"));

    // Install two ways through the core and look at the installed card.
    let pack = model.catalog.as_ref().unwrap().sources[0].clone();
    let options = BTreeSet::new();
    ruleset::install_source(
        &dir,
        &pack,
        &options,
        &Served(archive),
        &AtomicBool::new(false),
        &mut |_| {},
    )
    .unwrap();
    model.registry = ruleset::load_registry(&dir).unwrap();
    model.choices.clear();
    let text = joined(&render(
        &ctx,
        &mut model,
        &dir,
        wide,
        Vec::new(),
        &mut outbound,
    ));
    assert!(text.contains("Forge Core"), "{text}");
    assert!(
        text.contains("github.com/example/forge · release 1 ·"),
        "{text}"
    );
    assert!(text.contains("installed"), "{text}");
    assert!(text.contains("Remove"), "{text}");
    assert!(text.contains("Source, license and hashes"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn source_details_fit_a_narrow_pane_in_both_themes() {
    let dir = std::env::temp_dir().join(format!("ant-rules-src-narrow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (catalog, _) = catalog_value();
    let mut model = model_for(&dir, &catalog);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut outbound = false;
    let narrow = egui::vec2(420.0, 2200.0);
    for light in [false, true] {
        crate::theme::apply(&ctx, light);
        crate::theme::text_size(&ctx, 22.0);
        render(&ctx, &mut model, &dir, narrow, Vec::new(), &mut outbound);
        let shown = render(&ctx, &mut model, &dir, narrow, Vec::new(), &mut outbound);
        assert!(joined(&shown).contains("Forge Core"));
        let overflow: Vec<String> = shown
            .iter()
            .filter(|(_, rect, clip)| {
                let visible = rect.intersect(*clip);
                visible.right() > narrow.x + 1.0
                    || visible.left() < -1.0
                    || (rect.right() > narrow.x + 1.0 && clip.right() >= narrow.x - 1.0)
            })
            .map(|(text, rect, _)| format!("{rect:?} {text}"))
            .collect();
        assert!(overflow.is_empty(), "past the pane: {overflow:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_hosted_archive_catalog_still_lists_its_packs() {
    let dir = std::env::temp_dir().join(format!("ant-rules-v1-ui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let v1 = serde_json::json!({"schema": 1, "packs": [{
        "id": "old-pack", "engine": "yara", "name": "Old Pack", "version": "7",
        "upstream_revision": "r7", "upstream_url": "https://example.invalid/",
        "download_url": "https://example.invalid/p.tar.gz",
        "sha256": "a".repeat(64), "size": 5, "app": ">=0.6.2",
        "engine_requirement": "YARA-X 1.21", "rules": 3, "helpers": 0,
        "license": "per-rule", "evidence": [], "limits": []}]});
    let mut model = model_for(&dir, &v1);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut outbound = false;
    let size = egui::vec2(900.0, 1200.0);
    render(&ctx, &mut model, &dir, size, Vec::new(), &mut outbound);
    let text = joined(&render(
        &ctx,
        &mut model,
        &dir,
        size,
        Vec::new(),
        &mut outbound,
    ));
    assert!(text.contains("Old Pack 7 · 3 rules, 0 helpers"), "{text}");
    assert!(text.contains("Download"), "{text}");
    assert!(!text.contains("Download and install"), "{text}");
    let _ = PackEntry::clone;
    let _ = std::fs::remove_dir_all(&dir);
}
