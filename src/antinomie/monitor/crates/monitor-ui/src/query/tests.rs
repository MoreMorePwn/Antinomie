// SPDX-License-Identifier: GPL-3.0-only
use super::*;

const TABLE_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("name", "Displayed name"),
    FieldSpec::number("address", "Address"),
    FieldSpec::boolean("complete", "Completeness"),
    FieldSpec::tags("tag", "Annotation tags"),
];

#[test]
fn incomplete_table_drafts_keep_the_last_applied_filter() {
    let ctx = egui::Context::default();
    let row = [("address", RowValue::Number(9))];
    for (draft, expected) in [
        ("address == 9", true),
        ("address ==", true),
        ("address == 10", false),
        ("address == 10 &&", false),
        ("", true),
    ] {
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let compiled = applied_table(ui, draft, TABLE_FIELDS, "retention");
                assert!(compiled.keep_table(&row) == expected, "{draft}");
            });
        });
    }
}

#[test]
#[ignore = "native X11 filter popup; stays open long enough to cover a 30s refresh"]
fn native_filter_autocomplete() {
    use std::time::{Duration, Instant};
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct App {
        syscall: String,
        history: String,
        packet: String,
        frames: u64,
        started: Instant,
        deadline: Instant,
        focused: bool,
    }
    impl eframe::App for App {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            self.frames += 1;
            let elapsed = self.started.elapsed().as_secs();
            egui::CentralPanel::default().show(root, |ui| {
                ui.label(format!("refresh {elapsed}s · frame {}", self.frames));
                ui.label("Syscall filter");
                let syscall = crate::query::filter_edit(
                    ui,
                    &mut self.syscall,
                    "Filter syscalls",
                    ui.available_width(),
                    FilterScope::Syscall,
                );
                ui.label("Run history filter");
                let _ = crate::query::filter_edit(
                    ui,
                    &mut self.history,
                    "Filter runs",
                    ui.available_width(),
                    FilterScope::Record,
                );
                ui.label("Packet filter");
                let _ = crate::query::filter_edit(
                    ui,
                    &mut self.packet,
                    "Filter packets",
                    ui.available_width(),
                    FilterScope::Packet,
                );
                if !self.focused {
                    syscall.request_focus();
                    self.focused = true;
                }
            });
            let _ = std::fs::write(
                "/tmp/antinomie-filter-refresh",
                format!("{elapsed} {}\n", self.frames),
            );
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let wide = std::env::var_os("ANTINOMIE_FILTER_QA_WIDE").is_some();
    let font = std::env::var("ANTINOMIE_FILTER_QA_FONT")
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .unwrap_or(if wide { 16.0 } else { 24.0 });
    let seconds = std::env::var("ANTINOMIE_FILTER_QA_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(35)
        .clamp(1, 90);
    eframe::run_native(
        "Antinomie Filter QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size(if wide {
                    [1100.0, 720.0]
                } else {
                    [420.0, 760.0]
                })
                .with_position([80.0, 60.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::text_size(&cc.egui_ctx, font);
            Ok(Box::new(App {
                syscall: "syscall.num == 9 && args.pr".into(),
                history: "entry.na".into(),
                packet: "tcp.f".into(),
                frames: 0,
                started: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(seconds),
                focused: false,
            }))
        }),
    )
    .unwrap();
}

/// Runs one filter-editor frame at a fixed time and returns the completion
/// list's scroll offset (`None` while no popup is open).
fn filter_frame(ctx: &egui::Context, text: &mut String, events: Vec<egui::Event>) -> Option<f32> {
    let mut raw = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(600.0, 600.0),
        )),
        events,
        ..Default::default()
    };
    let frame = ctx.data_mut(|data| {
        let frame: &mut u32 = data.get_temp_mut_or_default(egui::Id::new("test-frame"));
        *frame += 1;
        *frame
    });
    raw.time = Some(f64::from(frame) * 0.05);
    let mut offset = None;
    let _ = ctx.run_ui(raw, |root| {
        egui::CentralPanel::default().show(root, |ui| {
            let response = filter_edit(ui, text, "Filter", 300.0, FilterScope::Syscall);
            if !response.has_focus() {
                response.request_focus();
            }
            let id = ui.id().with(("filter-edit", "Filter")).with("offset");
            offset = ui.data(|data| data.get_temp::<f32>(id));
        });
    });
    offset
}

#[test]
fn completion_list_keeps_the_scroll_position_the_user_chose() {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        filter_frame(&ctx, &mut text, Vec::new());
    }
    // Hover the popup (just below the editor) and wheel down.
    let wheel = vec![
        egui::Event::PointerMoved(egui::pos2(60.0, 80.0)),
        egui::Event::MouseWheel {
            phase: egui::TouchPhase::Move,
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, -400.0),
            modifiers: egui::Modifiers::NONE,
        },
    ];
    filter_frame(&ctx, &mut text, wheel);
    let mut settled = 0.0;
    for _ in 0..20 {
        settled = filter_frame(&ctx, &mut text, Vec::new()).expect("popup is open");
    }
    assert!(settled > 5.0, "wheel scrolled the list down: {settled}");
    for _ in 0..10 {
        let offset = filter_frame(&ctx, &mut text, Vec::new()).expect("popup is open");
        assert_eq!(offset, settled, "list jumped back by itself");
    }
}

/// The texts and colors of one frame's text shapes.
fn shown_texts(output: &egui::FullOutput) -> Vec<(String, egui::Color32)> {
    fn collect(shape: &egui::Shape, texts: &mut Vec<(String, egui::Color32)>) {
        match shape {
            egui::Shape::Text(text) => {
                let color = text
                    .galley
                    .job
                    .sections
                    .first()
                    .map_or(egui::Color32::PLACEHOLDER, |section| section.format.color);
                texts.push((text.galley.text().to_owned(), color));
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, texts)),
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut texts);
    }
    texts
}

#[test]
fn empty_filter_boxes_show_a_muted_filter_e_g_placeholder() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut text = String::new();
    let mut table = String::new();
    let output = ctx.run_ui(egui::RawInput::default(), |root| {
        egui::CentralPanel::default().show(root, |ui| {
            filter_edit(
                ui,
                &mut text,
                "syscall == openat",
                300.0,
                FilterScope::Syscall,
            );
            filter_edit_fields(ui, &mut table, "name == nginx", 300.0, TABLE_FIELDS, &[]);
        });
    });
    let shown = shown_texts(&output);
    for placeholder in ["filter e.g. syscall == openat", "filter e.g. name == nginx"] {
        let (_, color) = shown
            .iter()
            .find(|(text, _)| text == placeholder)
            .unwrap_or_else(|| panic!("{placeholder} missing from {shown:?}"));
        assert_eq!(*color, crate::theme::hint());
        assert_ne!(*color, crate::theme::muted());
    }
    assert!(compile_note("syscall == openat").error.is_none());
}

#[test]
fn help_lists_schema_argument_names() {
    assert!(guide_has("args.filename"));
    assert!(guide_has("execve"));
    assert!(guide_has("http.request.method"));
    assert!(guide_has("dns.qry.name"));
}
