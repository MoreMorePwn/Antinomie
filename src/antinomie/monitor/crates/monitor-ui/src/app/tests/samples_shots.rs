// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for Library › Samples, for screenshots in each theme. Needs
//! an X11 display; exits by itself. The library lives in ANTINOMIE_QA_DATA
//! (a throwaway folder; never the user's data).
//!
//! ANTINOMIE_QA_SCENE = list | tags | add | edit,
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1400x820,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;
use antinomie_monitor_core::samples::Library;

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_samples_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1400.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let scene = var("ANTINOMIE_QA_SCENE");
    let data = PathBuf::from(var("ANTINOMIE_QA_DATA"));
    assert!(
        !data.as_os_str().is_empty(),
        "set ANTINOMIE_QA_DATA to a throwaway folder"
    );
    std::fs::create_dir_all(&data).unwrap();
    let (script, _, _) = super::samples_list::fixture(&data);
    eframe::run_native(
        "Antinomie Samples QA",
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
            let mut app = app();
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            app.options.data_dir = data.clone();
            app.rules_ui.set_packs_for_test(Vec::new());
            app.layout = WorkspaceLayout::default();
            app.open_library(crate::workspace::LibraryPage::Samples);
            match scene.as_str() {
                "tags" => app.samples_page.show_tag_filter(true),
                "add" => {
                    let file = data.join("update-helper");
                    std::fs::write(
                        &file,
                        b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0not a program",
                    )
                    .unwrap();
                    app.samples_page.open_add(Some(&file));
                }
                "edit" => {
                    let tags = Library::open(&data).unwrap().tags(&script).unwrap();
                    app.samples_page.edit_tags_of(&script, "install.sh", &tags);
                }
                _ => {}
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native samples fixture");
}
