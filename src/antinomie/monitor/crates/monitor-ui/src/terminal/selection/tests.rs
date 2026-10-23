// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn selection(start: (usize, u16), end: (usize, u16)) -> Selection {
    Selection {
        anchor: Point {
            row: start.0,
            col: start.1,
        },
        head: Point {
            row: end.0,
            col: end.1,
        },
    }
}

#[test]
fn plain_text_joins_soft_wraps_preserves_newlines_and_wide_combining_cells() {
    let mut terminal = Terminal::default();
    terminal.replay_resize(4, 8);
    terminal.process("abc界e\u{301}fgHI\r\nsecond".as_bytes());
    assert_eq!(
        terminal
            .selection_text(selection((0, 0), (2, 8)), 0)
            .unwrap(),
        "abc界e\u{301}fgHI\nsecond"
    );
    assert_eq!(
        terminal
            .selection_text(selection((0, 4), (0, 5)), 0)
            .unwrap(),
        "界"
    );
    assert_eq!(
        terminal
            .selection_text(selection((2, 6), (2, 0)), 0)
            .unwrap(),
        "second"
    );
    assert_eq!(terminal.parser.screen().scrollback(), 0);
}

#[test]
fn scrollback_selection_survives_appending_and_clears_on_overwrite_or_eviction() {
    let mut terminal = Terminal::default();
    terminal.replay_resize(3, 20);
    terminal.process(b"oldest\r\nsecond\r\nthird\r\nfourth");
    let history = terminal.history();
    assert_eq!(history, 1);
    terminal.selection = Some(selection((0, 0), (0, 6)));
    terminal.process(b"\r\nfifth\r\nsixth");
    let history = terminal.history();
    assert_eq!(
        terminal
            .selection_text(terminal.selection.unwrap(), history)
            .unwrap(),
        "oldest"
    );
    terminal.selection = Some(selection((history + 2, 0), (history + 2, 5)));
    terminal.process(b"\rOTHER");
    assert!(
        terminal.selection.is_none(),
        "changed cells cannot retain an old highlight"
    );
    terminal.selection = Some(selection((0, 0), (0, 6)));
    terminal.process("\r\nx".repeat(SCROLLBACK + 1).as_bytes());
    assert!(
        terminal.selection.is_none(),
        "evicted bytes cannot be copied as new output"
    );
}

#[test]
fn full_history_moves_selection_with_eviction_and_resize_invalidates_it() {
    let mut terminal = Terminal::default();
    terminal.replay_resize(3, 20);
    terminal.process("x\r\n".repeat(SCROLLBACK + 3).as_bytes());
    assert_eq!(terminal.history(), SCROLLBACK);
    terminal.selection = Some(selection((10, 0), (10, 1)));
    terminal.process(b"x\r\n");
    assert_eq!(terminal.selection.unwrap().anchor.row, 9);
    terminal.replay_resize(3, 10);
    assert!(terminal.selection.is_none());
}

fn draw(
    ctx: &egui::Context,
    terminal: &mut Terminal,
    events: Vec<egui::Event>,
    enabled: bool,
) -> (egui::FullOutput, Vec<u8>) {
    let mut input = Vec::new();
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(640.0, 320.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE)
                .show(ctx, |ui| {
                    input = terminal.show_grid(ui, enabled, false).0;
                });
        },
    );
    (output, input)
}

fn pointer(pos: egui::Pos2, pressed: bool) -> egui::Event {
    egui::Event::PointerButton {
        pos,
        pressed,
        button: egui::PointerButton::Primary,
        modifiers: egui::Modifiers::NONE,
    }
}

fn focus(ctx: &egui::Context, terminal: &mut Terminal, enabled: bool) {
    draw(ctx, terminal, vec![], enabled);
    let pos = egui::pos2(2.0, 4.0);
    draw(
        ctx,
        terminal,
        vec![egui::Event::PointerMoved(pos), pointer(pos, true)],
        enabled,
    );
    draw(ctx, terminal, vec![pointer(pos, false)], enabled);
}

fn copied(output: &egui::FullOutput) -> Option<&str> {
    output
        .platform_output
        .commands
        .iter()
        .find_map(|command| match command {
            egui::OutputCommand::CopyText(text) => Some(text.as_str()),
            _ => None,
        })
}

#[test]
fn mouse_selection_copies_from_live_and_read_only_terminals_without_guest_input() {
    for enabled in [true, false] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = Terminal::default();
        terminal.replay_resize(6, 80);
        terminal.process(b"COPY terminal output");
        focus(&ctx, &mut terminal, enabled);
        let font = TextStyle::Monospace.resolve(&ctx.style());
        let cell = ctx.fonts(|fonts| fonts.glyph_width(&font, 'M'));
        let start = egui::pos2(0.1, 4.0);
        let end = egui::pos2(4.0 * cell, 4.0);
        draw(
            &ctx,
            &mut terminal,
            vec![egui::Event::PointerMoved(start), pointer(start, true)],
            enabled,
        );
        draw(
            &ctx,
            &mut terminal,
            vec![egui::Event::PointerMoved(end)],
            enabled,
        );
        draw(&ctx, &mut terminal, vec![pointer(end, false)], enabled);
        let (output, input) = draw(&ctx, &mut terminal, vec![egui::Event::Copy], enabled);
        assert_eq!(copied(&output), Some("COPY"));
        assert!(input.is_empty(), "copy must not send a terminal interrupt");
        let (output, input) = draw(
            &ctx,
            &mut terminal,
            vec![egui::Event::Key {
                key: Key::C,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: true,
                    shift: true,
                    ..Default::default()
                },
            }],
            enabled,
        );
        assert_eq!(copied(&output), Some("COPY"));
        assert!(input.is_empty());
    }
}

#[test]
fn unselected_copy_event_interrupts_live_terminal_and_shift_copy_does_not() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut terminal = Terminal::default();
    focus(&ctx, &mut terminal, true);
    assert_eq!(
        draw(&ctx, &mut terminal, vec![egui::Event::Copy], true).1,
        vec![3]
    );
    assert!(draw(
        &ctx,
        &mut terminal,
        vec![egui::Event::Key {
            key: Key::C,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers {
                ctrl: true,
                shift: true,
                ..Default::default()
            },
        }],
        true
    )
    .1
    .is_empty());
    assert!(draw(&ctx, &mut terminal, vec![egui::Event::Copy], false)
        .1
        .is_empty());
}

#[test]
#[ignore = "requires isolated X11 and external mouse/clipboard automation; exits after 15 seconds"]
fn native_terminal_clipboard_roundtrip() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Qa {
        terminal: Terminal,
        start: Instant,
        received: Vec<u8>,
    }
    impl eframe::App for Qa {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE)
                .show(ctx, |ui| {
                    ui.heading("Terminal clipboard QA");
                    ui.label("Drag a word, Ctrl+Shift+C, then Ctrl+Shift+V");
                    self.received.extend(self.terminal.show(ui, true).0);
                });
            if self.start.elapsed() > Duration::from_secs(15) {
                assert_eq!(
                    String::from_utf8_lossy(&self.received),
                    "terminal-copy-test"
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(30));
        }
    }
    eframe::run_native("Terminal clipboard QA", eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 440.0]),
        persist_window: false,
        event_loop_builder: Some(Box::new(|builder| { builder.with_x11().with_any_thread(true); })),
        ..Default::default()
    }, Box::new(|cc| {
        theme::install(&cc.egui_ctx);
        let mut terminal = Terminal::default();
        terminal.process(b"\x1b[32manalyst@busybox\x1b[0m:\x1b[34m/tmp\x1b[0m$ echo terminal-copy-test\r\nterminal-copy-test\r\n");
        Ok(Box::new(Qa { terminal, start: Instant::now(), received: Vec::new() }))
    })).expect("native terminal QA");
}
