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
    assert!(joined(&f.frame()).contains("No pack installed for this engine"));
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
    assert!(joined(&shown).contains("Select a rule for its details"));
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
    assert!(
        text.contains("The rule list is available only after install"),
        "{text}"
    );
    assert!(model.job.is_none(), "nothing was fetched");
    assert!(model.rows.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
