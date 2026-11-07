// SPDX-License-Identifier: GPL-3.0-only
//! The rules window in a real window, for screenshots. Needs an X11 display;
//! exits by itself.
//!
//! ANTINOMIE_QA_SELECT = 1 selects the second rule, ANTINOMIE_QA_SIZE =
//! 1280x820, ANTINOMIE_QA_SECONDS = 12, ANTINOMIE_QA_THEME = dark | light | blue.
use super::{source_tests::install_fixture_pack, Model};
use crate::theme;
use eframe::egui;

const RULES: &str = "rule Alpha_Rule\n{\n  meta:\n    Description = \"Finds the alpha dropper by its mutex name and its install path\"\n    Author = \"Ann Analyst\"\n    License = \"MIT\"\n    reference = \"https://example.test/alpha\"\n  strings:\n    $a = \"alpha\"\n  condition:\n    $a\n}\n\nrule Zeta_Rule\n{\n  meta:\n    description = \"the zeta rule\"\n  strings:\n    $a = \"zeta\"\n  condition:\n    $a\n}\n";

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_rules_window_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        model: Model,
        dir: std::path::PathBuf,
        select: bool,
        filter: String,
        frame: u64,
        deadline: std::time::Instant,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = root.ctx().clone();
            let mut outbound = false;
            let mut detection = antinomie_monitor_core::analysis::detection::Settings::default();
            let tools = antinomie_monitor_core::ruleset::ToolConfig::default();
            egui::CentralPanel::default().show(root, |ui| {
                let _ = self
                    .model
                    .page(ui, &self.dir, &mut outbound, &tools, &mut detection);
            });
            self.frame += 1;
            if self.frame == 20 && self.model.loaded {
                self.model
                    .open_rule_list(&self.dir, "yara", "fixture", "", "Fixture fixture");
            }
            if self.frame == 60 && self.select {
                if let Some(list) = self.model.rule_lists.first_mut() {
                    list.select(1);
                }
            }
            if self.frame == 70 && !self.filter.is_empty() {
                if let Some(list) = self.model.rule_lists.first_mut() {
                    list.set_filter_for_test(&self.filter);
                }
            }
            self.model.show_rule_lists(&ctx, &self.dir);
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => theme::Theme::Light,
        "blue" => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(12);
    let dir = std::env::temp_dir().join(format!("ant-rules-qa-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // ANTINOMIE_QA_LONG = 1 adds a rule with a very long source line and
    // reference; ANTINOMIE_QA_FILTER types that text into the list's filter.
    let rules = if var("ANTINOMIE_QA_LONG") == "1" {
        let long = "x".repeat(900);
        format!("{RULES}\nrule Long_Rule\n{{\n  meta:\n    description = \"{long}\"\n    reference = \"https://example.test/{long}\"\n  strings:\n    $a = \"{long}\"\n  condition:\n    $a\n}}\n")
    } else {
        RULES.to_owned()
    };
    install_fixture_pack(&dir, "fixture", "yara", "rules.yar", &rules);
    let filter = var("ANTINOMIE_QA_FILTER");
    let select = var("ANTINOMIE_QA_SELECT") == "1";
    eframe::run_native(
        "Antinomie Rules QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            Ok(Box::new(Fixture {
                model: Model::default(),
                dir,
                select,
                filter,
                frame: 0,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native rules fixture");
}
