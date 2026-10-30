// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for Library › Samples, for screenshots in each theme. Needs
//! an X11 display; exits by itself. The library lives in ANTINOMIE_QA_DATA
//! (a throwaway folder; never the user's data).
//!
//! ANTINOMIE_QA_SCENE = list | tags | add | edit | detail | detail2 | regex | identity | lineage | lineage2 | outputs | viewer | promote | similar | runs | runs_details | custody | custody_broken | custody_all | custody_all_broken | export,
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1400x820,
//! ANTINOMIE_QA_SECONDS = 25, ANTINOMIE_QA_FONT = 16 (the font size setting).
use super::*;
use crate::app::samples_page::SamplesPage;
use crate::theme::Theme;
use antinomie_monitor_core::samples::Library;

fn archive_worker(ctx: &egui::Context) -> Option<crate::archive::ArchiveWorker> {
    crate::archive::ArchiveWorker::new(Some(ctx.clone())).ok()
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_samples_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        /// Open the file viewer once the window has read the sample.
        open_viewer: bool,
        /// Open Add to Samples… once the window has read the sample.
        open_promote: Option<PathBuf>,
        /// Open Export custody record… once the window has read the sample.
        open_export: bool,
        /// Select the newest run on the Runs tab once the window has read it.
        select_run: bool,
        /// A scene that needs the sample read first (see `samples_features`).
        later: Option<String>,
        /// The Summary section the scene shows, asked for again every frame
        /// for a while: the rows above it arrive as the page reads them.
        section: Option<(&'static str, Instant)>,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if let Some((title, until)) = self.section {
                if Instant::now() < until {
                    SamplesPage::scroll_detail_to(ctx, title);
                } else {
                    self.section = None;
                }
            }
            if self.open_viewer && self.app.samples_page.detail_probe().is_some() {
                self.open_viewer = false;
                self.app.samples_page.view_content(ctx);
            }
            if self.app.samples_page.detail_probe().is_some() {
                if let Some(dir) = self.open_promote.take() {
                    self.app.samples_page.open_promote_for_test(&dir);
                }
            }
            if self.select_run && self.app.samples_page.detail_probe().is_some() {
                self.select_run = false;
                self.app.samples_page.select_detail_run(0);
            }
            if self.later.is_some() && self.app.samples_page.detail_probe().is_some() {
                if let Some(scene) = self.later.take() {
                    super::samples_features::qa_after(&mut self.app, ctx, &scene);
                }
            }
            if self.open_export && self.app.samples_page.detail_custody().is_some() {
                self.open_export = false;
                self.app.samples_page.open_export_for_test();
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
            if let Ok(size) = var("ANTINOMIE_QA_FONT").parse::<f32>() {
                app.settings.font_size = size;
                theme::text_size(&cc.egui_ctx, size);
            }
            // The archive worker the real app starts at launch; without it the
            // pages that read runs show "Archive worker unavailable".
            app.archive = archive_worker(&cc.egui_ctx);
            if app.archive.is_some() {
                app.refresh_history();
            }
            if scene == "similar" {
                // A text file and a near copy of it, so the Summary has a row.
                let mut base = String::new();
                for line in 0..400 {
                    base.push_str(&format!(
                        "line {line}: value {} /usr/lib/lib{}.so connect to host-{}.example.test\n",
                        line * 7 % 9973,
                        line % 17,
                        line % 101
                    ));
                }
                let mut library = Library::open(&data).unwrap();
                let add = |library: &mut Library, text: &str, name: &str| {
                    library
                        .add_bytes(
                            text.as_bytes(),
                            antinomie_monitor_core::samples::NewSample {
                                name: name.into(),
                                ..Default::default()
                            },
                        )
                        .unwrap()
                        .sha256
                };
                let me = add(&mut library, &base, "loader.sh");
                add(
                    &mut library,
                    &format!("{base}# only the variant\n"),
                    "loader-2.sh",
                );
                app.options.data_dir = data.clone();
                app.open_library(crate::workspace::LibraryPage::Samples);
                app.samples_page.open_detail(&me);
            }
            app.open_library(crate::workspace::LibraryPage::Samples);
            if matches!(
                scene.as_str(),
                "detail"
                    | "detail2"
                    | "regex"
                    | "identity"
                    | "lineage"
                    | "lineage2"
                    | "outputs"
                    | "viewer"
                    | "promote"
                    | "runs"
                    | "runs_details"
                    | "custody"
                    | "custody_broken"
                    | "custody_all"
                    | "custody_all_broken"
                    | "export"
                    | "notes"
                    | "note_editor"
                    | "delete_run"
                    | "kinds"
            ) {
                // Runs that exist on disk, one with a static report.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let first =
                    super::samples_detail::save_run(&data, &script, "install.sh", "r1", now, true);
                let second = super::samples_detail::save_run(
                    &data,
                    &script,
                    "install.sh",
                    "r2",
                    now + 8_000,
                    false,
                );
                super::samples_detail::save_artifacts(&first);
                super::samples_detail::save_digest(&first, "medium", false);
                super::samples_detail::save_digest(&second, "high", true);
                app.snapshot.vms.push(VmConfig {
                    id: "vm".into(),
                    name: "Debian".into(),
                    ..VmConfig::default()
                });
                super::samples_features::qa_data(&data, &script, &scene, &first);
                app.samples_page.open_detail(&script);
                if scene.ends_with("broken") {
                    // The second entry was edited, and a later one removed
                    // from the sample that was dropped by it.
                    let connection =
                        rusqlite::Connection::open(data.join("samples/library.sqlite")).unwrap();
                    connection
                        .execute(
                            "UPDATE custody_entry SET detail=replace(detail,'tags','tags, verdict') \
                             WHERE seq=2 AND sha256=?1",
                            [&script],
                        )
                        .unwrap();
                }
                app.samples_page.show_detail_tab(match scene.as_str() {
                    "runs" | "runs_details" => "runs",
                    "notes" | "note_editor" => "notes",
                    "custody" | "custody_broken" | "export" => "custody",
                    _ => "summary",
                });
                if scene.starts_with("custody_all") {
                    app.samples_page.close_detail();
                    app.samples_page.open_custody_all();
                }
                if scene == "lineage2" {
                    app.samples_page.set_lineage(2, 3, false);
                }
            }
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
            // Every scene says where it is: the section it shows.
            let section = match scene.as_str() {
                "regex" => Some("Regex matches"),
                "detail2" => Some("Indicators"),
                "identity" => Some("Identity"),
                "outputs" | "kinds" => Some("Artifacts"),
                "lineage" | "lineage2" => Some("Lineage"),
                "similar" => Some("Similar samples"),
                _ => None,
            }
            .map(|title| (title, Instant::now() + Duration::from_secs(12)));
            Ok(Box::new(QaApp {
                section,
                app,
                open_viewer: scene == "viewer",
                open_promote: (scene == "promote").then(|| data.clone()),
                open_export: scene == "export",
                select_run: scene == "runs_details",
                later: matches!(scene.as_str(), "note_editor" | "delete_run")
                    .then(|| scene.clone()),
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native samples fixture");
}
