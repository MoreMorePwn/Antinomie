// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships box's Full view as a tree you open: what shows at
//! first, the arrows, and the box that stays where it was when it opens.
use super::*;

const RIGHT: &str = egui_phosphor::regular::CARET_RIGHT;
const DOWN: &str = egui_phosphor::regular::CARET_DOWN;

fn full(view: &mut TriageView, ctx: &egui::Context) -> egui::FullOutput {
    let out = settle(ctx, view, WIDE, None);
    click(ctx, view, WIDE, find(&out, "Full").center());
    settle(ctx, view, WIDE, None)
}

/// "N of M nodes" of the note above the graph.
fn counts(out: &egui::FullOutput) -> (usize, usize) {
    let (line, _) = texts(out)
        .into_iter()
        .find(|(text, _)| text.contains(" nodes. Each process"))
        .expect("the count line");
    let words: Vec<&str> = line.split_whitespace().collect();
    let number = |word: &str| word.replace(',', "").parse().unwrap();
    (number(words[0]), number(words[2]))
}

/// An arrow of a box that has something under it, closed, with its box's text.
fn closed_arrow(out: &egui::FullOutput) -> (egui::Rect, String, egui::Rect) {
    texts(out)
        .into_iter()
        .filter(|(text, rect)| text == RIGHT && rect.min.y > 0.0)
        .find_map(|(_, arrow)| {
            texts(out)
                .into_iter()
                .find(|(text, rect)| {
                    text.starts_with(egui_phosphor::regular::CPU)
                        && (rect.center().y - arrow.center().y).abs() < 3.0
                        && rect.max.x <= arrow.min.x + 2.0
                })
                .map(|(text, rect)| (arrow, text, rect))
        })
        .expect("a closed process with an arrow")
}

#[test]
fn full_starts_closed_so_a_big_run_is_not_a_wall_of_nodes() {
    let (_files, mut view) = sprawl(300);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(!has(&out, "Expand all") && !has(&out, "Collapse all"));
    let out = full(&mut view, &ctx);
    assert!(has(&out, "Expand all") && has(&out, "Collapse all"));
    let (drawn, total) = counts(&out);
    assert!(total > 300, "{total}");
    assert!(drawn * 3 < total, "{drawn} of {total} drawn at first");
    assert!(has(&out, RIGHT), "a closed box has its arrow");
    // The badge says how many nodes are under a closed box.
    assert!(
        texts(&out)
            .iter()
            .any(|(t, _)| t.starts_with('+')
                && t[1..].chars().all(|c| c.is_ascii_digit() || c == ',')),
        "{:?}",
        texts(&out)
    );
}

#[test]
fn a_click_on_an_arrow_opens_the_next_level_and_the_box_stays_in_place() {
    let (_files, mut view) = sprawl(300);
    let ctx = context(16.0);
    let out = full(&mut view, &ctx);
    let (drawn, _) = counts(&out);
    let (arrow, text, rect) = closed_arrow(&out);
    click(&ctx, &mut view, WIDE, arrow.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let (after, _) = counts(&out);
    assert!(after > drawn, "{drawn} then {after}: its children show");
    // The same box, within a few points of where it was.
    let moved = texts(&out)
        .into_iter()
        .find(|(t, _)| *t == text)
        .map(|(_, r)| r)
        .expect("the box is still drawn");
    assert!(
        (moved.min - rect.min).length() < 4.0,
        "from {rect:?} to {moved:?}"
    );
    assert!(has(&out, DOWN), "it is open now");
    // Opening is one level: more arrows stay closed below it.
    assert!(has(&out, RIGHT));
    // A click on the arrow again closes it.
    let open = texts(&out)
        .into_iter()
        .find(|(t, r)| t == DOWN && (r.center().y - arrow.center().y).abs() < 3.0)
        .map(|(_, r)| r)
        .expect("its arrow");
    click(&ctx, &mut view, WIDE, open.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(counts(&out).0, drawn);
}

#[test]
fn expand_all_opens_everything_and_collapse_all_goes_back_to_how_full_starts() {
    let (_files, mut view) = sprawl(300);
    let ctx = context(16.0);
    let out = full(&mut view, &ctx);
    let (start, total) = counts(&out);
    click(&ctx, &mut view, WIDE, find(&out, "Expand all").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let (all, _) = counts(&out);
    assert!(all > start * 2, "{start} then {all}");
    assert!(all <= total);
    click(&ctx, &mut view, WIDE, find(&out, "Collapse all").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(counts(&out).0, start);
}

/// The Summary with a run of 300 more processes, in Full, for screenshots
/// under Xvfb. `ANTINOMIE_QA_EXPAND=1` opens everything first (how Full
/// drew before it was a tree).
#[test]
#[ignore = "requires owned isolated X11; Relationships screenshot fixture"]
fn native_relations_fold_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        deadline: std::time::Instant,
        expand: bool,
        _files: PacketSpool,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = root.ctx().clone();
            egui::CentralPanel::default().show(root, |ui| {
                let input = TriageInput::empty();
                show(&mut self.view, ui, &input);
            });
            if self.expand {
                if let Some(built) = self.view.summary_state.built.as_mut() {
                    built.expand_all();
                    self.expand = false;
                }
            }
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    let (files, mut view) = sprawl(300);
    view.section = Section::Summary;
    view.summary_state.mode = super::super::state::Mode::Full;
    eframe::run_native(
        "Antinomie relationships QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1000.0, 1500.0])
                .with_position([16.0, 16.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::text_size(&cc.egui_ctx, theme::qa_text_size(15.0));
            Ok(Box::new(Fixture {
                view,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(25),
                expand: std::env::var_os("ANTINOMIE_QA_EXPAND").is_some(),
                _files: files,
            }))
        }),
    )
    .unwrap();
}
