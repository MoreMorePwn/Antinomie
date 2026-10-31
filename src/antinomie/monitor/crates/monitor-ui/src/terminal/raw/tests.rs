// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn fed(bytes: &[u8]) -> RawLog {
    let mut log = RawLog::default();
    log.push(bytes);
    log
}

fn text(log: &RawLog) -> String {
    log.lines()
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("|")
}

/// The marks of line `index`, with the text each covers.
fn marks(log: &RawLog, index: usize) -> Vec<(String, Mark)> {
    let line = &log.lines()[index];
    line.spans
        .iter()
        .map(|span| {
            (
                line.text
                    .chars()
                    .skip(span.start)
                    .take(span.end - span.start)
                    .collect(),
                span.mark,
            )
        })
        .collect()
}

fn hiding(log: &RawLog) -> Vec<Mark> {
    log.lines()
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.mark))
        .filter(|mark| mark.hides())
        .collect()
}

#[test]
fn escapes_and_control_bytes_are_written_out() {
    let log = fed(b"a\x1b[31mb\x07\x01\t\\ \x7f\xff");
    assert_eq!(text(&log), "a\\e[31mb\\a\\x01\\t\\\\ \\x7f\\xff");
}

#[test]
fn carriage_return_and_line_feed_are_kept_and_end_the_line() {
    let log = fed(b"one\r\ntwo\nthree");
    assert_eq!(text(&log), "one\\r\\n|two\\n|three");
    assert!(hiding(&log).is_empty(), "CR LF is an ordinary line end");
}

#[test]
fn a_lone_carriage_return_and_a_backspace_are_overwrites() {
    let log = fed(b"10%\r20%\rdone\x08x");
    assert_eq!(
        marks(&log, 0),
        vec![
            ("\\r".to_string(), Mark::Overwrite),
            ("\\r".to_string(), Mark::Overwrite),
            ("\\b".to_string(), Mark::Overwrite),
        ]
    );
}

#[test]
fn a_carriage_return_split_from_its_line_feed_is_still_a_line_end() {
    let mut log = RawLog::default();
    log.push(b"x\r");
    log.push(b"\ny");
    assert!(hiding(&log).is_empty());
    assert_eq!(text(&log), "x\\r\\n|y");
}

#[test]
fn cursor_moves_and_erases_are_marked() {
    let log = fed(b"\x1b[2Aup\x1b[Hhome\x1b[2K\x1b[J\x1b[10;5H\x1bc");
    assert_eq!(
        hiding(&log),
        vec![
            Mark::Cursor,
            Mark::Cursor,
            Mark::Erase,
            Mark::Erase,
            Mark::Cursor,
            Mark::Erase,
        ]
    );
}

#[test]
fn colors_are_plain_and_do_not_count_as_hiding() {
    let log = fed(b"\x1b[1;31mred\x1b[0m\x1b[38;5;8mgray\x1b[48;2;8;8;8m\x1b[?25l");
    assert!(hiding(&log).is_empty());
    assert!(log.lines()[0]
        .spans
        .iter()
        .all(|span| span.mark == Mark::Plain));
}

#[test]
fn conceal_is_found_by_attribute_not_by_color_index() {
    let hides = |sgr: &str| !hiding(&fed(format!("\x1b[{sgr}mx").as_bytes())).is_empty();
    assert!(hides("8"));
    assert!(hides("1;8"));
    assert!(hides("31;8;4"));
    assert!(!hides("38;5;8"));
    assert!(!hides("48;5;8"));
    assert!(!hides("38;2;8;8;8"));
    assert!(!hides("38:5:8"));
    assert!(hides("38;5;8;8"));
}

#[test]
fn osc_52_is_a_clipboard_write_and_other_oscs_are_control_strings() {
    let log = fed(b"\x1b]52;c;aGk=\x07\x1b]0;title\x1b\\\x1b]8;;http://x\x07");
    assert_eq!(
        hiding(&log),
        vec![Mark::Clipboard, Mark::Osc, Mark::Osc],
        "{}",
        text(&log)
    );
    assert_eq!(marks(&log, 0)[0].0, "\\e]52;c;aGk=\\a");
}

#[test]
fn alternate_screen_switches_are_marked() {
    let log = fed(b"\x1b[?1049h\x1b[?1049l\x1b[?47h\x1b[?25h");
    assert_eq!(
        hiding(&log),
        vec![Mark::AltScreen, Mark::AltScreen, Mark::AltScreen]
    );
}

#[test]
fn a_sequence_cut_between_chunks_is_still_one_mark() {
    let mut log = RawLog::default();
    for chunk in [&b"\x1b"[..], b"]5", b"2;c;", b"abc\x1b", b"\\after"] {
        log.push(chunk);
    }
    assert_eq!(hiding(&log), vec![Mark::Clipboard]);
    assert!(text(&log).ends_with("after"));
}

#[test]
fn utf8_text_stays_text_and_broken_bytes_are_escaped() {
    let mut log = RawLog::default();
    log.push("héllo 界".as_bytes());
    assert_eq!(text(&log), "héllo 界");
    let mut split = RawLog::default();
    split.push(&"é".as_bytes()[..1]);
    split.push(&"é".as_bytes()[1..]);
    assert_eq!(text(&split), "é");
    assert_eq!(text(&fed(b"\xc3(")), "\\xc3(");
    assert_eq!(text(&fed("\u{9b}31m".as_bytes())), "\\u{9b}31m");
}

#[test]
fn long_lines_and_unending_strings_stay_bounded() {
    let log = fed(&vec![b'a'; LINE_MAX * 2 + 5]);
    assert!(log.lines().iter().all(|line| line.chars <= LINE_MAX));
    let mut runaway = b"\x1b]0;".to_vec();
    runaway.extend(vec![b'x'; SEQ_LIMIT * 2]);
    assert_eq!(hiding(&fed(&runaway))[0], Mark::Osc);
}

#[test]
fn only_the_newest_lines_are_kept_and_the_dropped_ones_are_counted() {
    let log = fed("x\n".repeat(MAX_LINES + 10).as_bytes());
    assert_eq!(log.lines().len(), MAX_LINES);
    assert_eq!(log.evicted(), 11);
}

#[test]
fn a_note_is_its_own_line_and_not_output() {
    let mut log = RawLog::default();
    log.push(b"abc");
    log.note("[gap]");
    log.push(b"def");
    assert_eq!(text(&log), "abc|[gap]|def");
    assert!(log.lines()[1].note && !log.lines()[0].note);
}
