// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn frame(
    ctx: &egui::Context,
    terminal: &mut Terminal,
    events: Vec<egui::Event>,
    focus: bool,
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
                    if focus {
                        let id = ui.next_auto_id();
                        ui.memory_mut(|memory| memory.request_focus(id));
                    }
                    input = terminal.show_grid(ui, true, false).0;
                });
        },
    );
    (output, input)
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

/// Every string the frame painted, in paint order.
fn painted(output: &egui::FullOutput) -> String {
    output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn copied(output: &egui::FullOutput) -> Option<String> {
    output
        .platform_output
        .commands
        .iter()
        .find_map(|command| match command {
            egui::OutputCommand::CopyText(text) => Some(text.clone()),
            _ => None,
        })
}

fn select_all(terminal: &mut Terminal) {
    let evicted = terminal.raw.evicted();
    let last = terminal.raw.lines().len() - 1;
    terminal.raw_view.selection = Some(RawSelection {
        anchor: Place {
            line: evicted,
            col: 0,
        },
        head: Place {
            line: evicted + last,
            col: terminal.raw.lines()[last].chars,
        },
    });
}

#[test]
fn raw_view_writes_the_escapes_out_and_formatted_does_not() {
    let ctx = context();
    let mut terminal = Terminal::default();
    terminal.process(b"plain \x1b[31mred\x1b[0m\r\nnext");
    let (formatted, _) = frame(&ctx, &mut terminal, vec![], false);
    assert!(!painted(&formatted).contains("\\e[31m"));
    terminal.set_view(View::Raw);
    let (raw, _) = frame(&ctx, &mut terminal, vec![], false);
    let text = painted(&raw);
    assert!(text.contains("\\e[31m"), "{text}");
    assert!(text.contains("\\e[0m"), "{text}");
    assert!(text.contains("\\r\\n"), "{text}");
    assert!(text.contains("next"), "{text}");
}

#[test]
fn hidden_output_is_visible_and_marked_in_raw() {
    let mut terminal = Terminal::default();
    // The password is overwritten by a carriage return, by cursor up, by a
    // conceal attribute and sent to the clipboard.
    terminal.process(b"password: hunter2\rXXXXXXXXXXXXXXXXX\r\n");
    terminal.process(b"second line\r\n\x1b[Aoverwrite\r\n");
    terminal.process(b"\x1b[8mconcealed\x1b[0m\r\n");
    terminal.process(b"\x1b]52;c;aHVudGVyMg==\x07\r\n");
    terminal.process(b"\x1b[?1049h");
    // Formatted shows none of the hidden text.
    let screen = terminal.parser.screen().contents();
    assert!(!screen.contains("hunter2") && !screen.contains("second line"));
    // Raw has all of it, with the hiding escapes marked.
    let raw: String = terminal
        .raw
        .lines()
        .iter()
        .map(|line| line.text.as_str())
        .collect();
    for part in ["hunter2", "second line", "concealed", "aHVudGVyMg=="] {
        assert!(raw.contains(part), "{part}");
    }
    let hiding: Vec<_> = terminal
        .raw
        .lines()
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.mark))
        .filter(|mark| mark.hides())
        .collect();
    for mark in [
        Mark::Overwrite,
        Mark::Cursor,
        Mark::Conceal,
        Mark::Clipboard,
        Mark::AltScreen,
    ] {
        assert!(hiding.contains(&mark), "{mark:?} in {hiding:?}");
    }
}

#[test]
fn copy_gives_plain_text_from_formatted_and_the_escaped_form_from_raw() {
    let ctx = context();
    let mut terminal = Terminal::default();
    terminal.replay_resize(3, 40);
    terminal.process(b"\x1b[1;31mred\x1b[0m ok\r\nline2");
    frame(&ctx, &mut terminal, vec![], true);
    terminal.selection = Some(Selection {
        anchor: selection::Point { row: 0, col: 0 },
        head: selection::Point { row: 1, col: 40 },
    });
    let (output, _) = frame(&ctx, &mut terminal, vec![egui::Event::Copy], true);
    assert_eq!(copied(&output).as_deref(), Some("red ok\nline2"));

    terminal.set_view(View::Raw);
    frame(&ctx, &mut terminal, vec![], true);
    select_all(&mut terminal);
    let (output, input) = frame(&ctx, &mut terminal, vec![egui::Event::Copy], true);
    assert_eq!(
        copied(&output).as_deref(),
        Some("\\e[1;31mred\\e[0m ok\\r\\n\nline2")
    );
    assert!(input.is_empty(), "a copy does not interrupt the program");
}

#[test]
fn raw_view_scrolls_the_same_history_and_follows_new_output() {
    let ctx = context();
    let mut terminal = Terminal::default();
    for n in 0..300 {
        terminal.process(format!("line{n}\r\n").as_bytes());
    }
    terminal.set_view(View::Raw);
    let (output, _) = frame(&ctx, &mut terminal, vec![], false);
    let text = painted(&output);
    assert!(
        text.contains("line299") && !text.contains("line0\\r"),
        "{text}"
    );
    let wheel = vec![
        egui::Event::PointerMoved(egui::pos2(100.0, 100.0)),
        egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, 1000.0),
            modifiers: egui::Modifiers::NONE,
        },
    ];
    let (output, _) = frame(&ctx, &mut terminal, wheel, false);
    let text = painted(&output);
    assert!(
        text.contains("line0\\r") && !text.contains("line299"),
        "{text}"
    );
    assert!(terminal.offset > 0);
    let before = terminal.offset;
    terminal.process(b"newest\r\n");
    frame(&ctx, &mut terminal, vec![], false);
    assert_eq!(terminal.offset, before + 1, "the view stays where it was");
}

#[test]
fn find_lists_matches_and_moves_between_them() {
    let ctx = context();
    let mut terminal = Terminal::default();
    for n in 0..200 {
        terminal.process(format!("row {n} Needle\r\n").as_bytes());
    }
    terminal.set_view(View::Raw);
    terminal.raw_view.find = "needle".into();
    terminal.refresh_matches();
    assert_eq!(terminal.raw_view.matches.len(), 200);
    assert_eq!(terminal.raw_view.matches[3].line, 3);
    terminal.raw_view.current = 5;
    terminal.raw_view.jump = true;
    let (output, _) = frame(&ctx, &mut terminal, vec![], false);
    assert!(painted(&output).contains("row 5 Needle"));
    assert!(terminal.offset > 0, "the match is scrolled into view");
    terminal.raw_view.find = "absent".into();
    terminal.refresh_matches();
    assert!(terminal.raw_view.matches.is_empty());
}

#[test]
fn switching_views_keeps_the_screen_and_the_raw_text() {
    let ctx = context();
    let mut terminal = Terminal::default();
    terminal.process(b"before\x1b[31m");
    terminal.set_view(View::Raw);
    terminal.process(b"during\r\n");
    terminal.set_view(View::Formatted);
    terminal.process(b"after");
    let (formatted, _) = frame(&ctx, &mut terminal, vec![], false);
    assert_eq!(terminal.contents(), "beforeduring\nafter");
    terminal.set_view(View::Raw);
    let (raw, _) = frame(&ctx, &mut terminal, vec![], false);
    assert!(painted(&raw).contains("before\\e[31mduring"));
    let _ = formatted;
}

#[test]
fn bold_is_drawn_heavier_and_italic_slanted() {
    let ctx = context();
    let mut terminal = Terminal::default();
    terminal.replay_resize(2, 20);
    terminal.process(b"\x1b[1mB\x1b[0m \x1b[3mI\x1b[0m n");
    let (output, _) = frame(&ctx, &mut terminal, vec![], false);
    let texts: Vec<_> = output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some(text),
            _ => None,
        })
        .collect();
    let at = |glyph: &str| -> Vec<&egui::epaint::TextShape> {
        texts
            .iter()
            .copied()
            .filter(|text| text.galley.text() == glyph)
            .collect()
    };
    let bold = at("B");
    assert_eq!(bold.len(), 2, "bold draws the glyph twice");
    assert!((bold[1].pos.x - bold[0].pos.x - BOLD_SHIFT).abs() < 0.01);
    assert_eq!(at("n").len(), 1);
    let italic = at("I");
    assert_eq!(italic.len(), 1);
    assert!(italic[0].galley.job.sections[0].format.italics);
    assert!(!at("n")[0].galley.job.sections[0].format.italics);
}
