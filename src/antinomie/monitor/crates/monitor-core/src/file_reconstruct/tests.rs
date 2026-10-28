// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use sha2::{Digest, Sha256};

fn kept(offset: u64, bytes: &[u8]) -> Extent {
    Extent {
        offset,
        len: bytes.len() as u64,
        piece: Piece::Kept(Source::Inline(bytes.to_vec())),
    }
}

fn missing(offset: u64, len: u64, gap: Gap) -> Extent {
    Extent {
        offset,
        len,
        piece: Piece::NotCaptured(gap),
    }
}

fn step(time_ns: u64, action: Action) -> Step {
    Step {
        time_ns,
        event: None,
        order: None,
        action,
    }
}

fn timeline(steps: Vec<Step>) -> Timeline {
    let mut timeline = Timeline::default();
    for step in steps {
        assert!(timeline.push(step));
    }
    timeline
}

fn start_with(bytes: &[u8]) -> Start {
    Start {
        size: Some(bytes.len() as u64),
        source: Some(Source::Inline(bytes.to_vec())),
    }
}

fn states(map: &Reconstruction) -> Vec<(u64, u64, State)> {
    map.spans()
}

fn shown(map: &Reconstruction) -> String {
    map.row(0, map.size() as usize)
        .iter()
        .map(|cell| match (cell.state.glyph(), cell.byte) {
            (Some(glyph), _) => glyph.to_owned(),
            (None, Some(byte)) => format!("{byte:02x}"),
            (None, None) => "!!".into(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_file_the_run_created_starts_empty_and_fills_with_writes() {
    let line = timeline(vec![
        step(10, Action::Write(vec![kept(0, b"ab")])),
        step(20, Action::Write(vec![kept(2, b"cd")])),
    ]);
    let mut map = Reconstruction::new(Start::empty(), &line);
    assert_eq!(map.size(), 0);
    map.goto(1);
    assert_eq!(shown(&map), "61 62");
    map.goto(2);
    assert_eq!(map.bytes(0, 4).unwrap(), b"abcd");
    assert!(map.complete());
    assert_eq!(map.counts().written, 4);
}

#[test]
fn a_modified_file_is_the_before_image_with_the_writes_laid_over_it() {
    let line = timeline(vec![step(5, Action::Write(vec![kept(1, b"XY")]))]);
    let mut map = Reconstruction::new(start_with(b"hello"), &line);
    assert_eq!(map.bytes(0, 5).unwrap(), b"hello");
    assert_eq!(map.counts().before, 5);
    map.goto(1);
    assert_eq!(map.bytes(0, 5).unwrap(), b"hXYlo");
    assert_eq!(
        states(&map),
        vec![
            (0, 1, State::Before),
            (1, 2, State::Written),
            (3, 2, State::Before)
        ]
    );
    // Stepping back restores the earlier map.
    map.goto(0);
    assert_eq!(map.bytes(0, 5).unwrap(), b"hello");
}

#[test]
fn unknown_bytes_stay_unknown_until_a_read_shows_them() {
    let line = timeline(vec![
        step(1, Action::Write(vec![kept(4, b"Z")])),
        step(2, Action::Read(vec![kept(0, b"abcd")])),
    ]);
    let mut map = Reconstruction::new(Start::default(), &line);
    map.goto(1);
    assert_eq!(shown(&map), "?? ?? ?? ?? 5a");
    map.goto(2);
    assert_eq!(map.bytes(0, 5).unwrap(), b"abcdZ");
    assert_eq!(map.counts().read, 4);
    assert_eq!(map.counts().written, 1);
    // The size of a file with no known start is what the calls reached.
    assert!(!map.size_known());
}

#[test]
fn a_read_of_bytes_already_known_changes_nothing() {
    let line = timeline(vec![
        step(1, Action::Write(vec![kept(0, b"new")])),
        step(2, Action::Read(vec![kept(0, b"new")])),
    ]);
    let mut map = Reconstruction::new(start_with(b"old"), &line);
    map.goto(2);
    assert_eq!(map.counts().written, 3);
    assert_eq!(map.row(0, 3)[0].learned, 0);
}

#[test]
fn a_write_without_its_payload_is_not_captured_and_a_read_can_still_reveal_it() {
    let line = timeline(vec![
        step(1, Action::Write(vec![missing(0, 3, Gap::FileCap)])),
        step(2, Action::Read(vec![kept(1, b"b")])),
    ]);
    let mut map = Reconstruction::new(start_with(b"abc"), &line);
    map.goto(1);
    assert_eq!(shown(&map), "## ## ##");
    assert_eq!(map.bytes(0, 3), Err(ReadError::NotCaptured(0)));
    assert!(!map.complete());
    map.goto(2);
    assert_eq!(shown(&map), "## 62 ##");
}

#[test]
fn a_shared_mapping_hides_the_bytes_until_something_shows_them_again() {
    let line = timeline(vec![
        step(1, Action::Mapping { offset: 1, len: 2 }),
        step(2, Action::Write(vec![kept(1, b"Q")])),
    ]);
    let mut map = Reconstruction::new(start_with(b"abcd"), &line);
    map.goto(1);
    assert_eq!(shown(&map), "61 ~~ ~~ 64");
    assert_eq!(map.counts().mapping, 2);
    assert_eq!(map.bytes(0, 4), Err(ReadError::Unknown(1)));
    map.goto(2);
    assert_eq!(shown(&map), "61 51 ~~ 64");
}

#[test]
fn a_resize_cuts_and_extends_with_zeros() {
    let line = timeline(vec![
        step(1, Action::Resize(2)),
        step(2, Action::Resize(4)),
        step(3, Action::Zero { offset: 0, len: 1 }),
    ]);
    let mut map = Reconstruction::new(start_with(b"abcd"), &line);
    map.goto(1);
    assert_eq!(map.bytes(0, 2).unwrap(), b"ab");
    assert_eq!(map.size(), 2);
    map.goto(2);
    assert_eq!(map.bytes(0, 4).unwrap(), b"ab\0\0");
    map.goto(3);
    assert_eq!(map.bytes(0, 4).unwrap(), b"\0b\0\0");
    assert_eq!(map.counts().before, 1);
}

#[test]
fn a_change_whose_bytes_were_not_seen_is_not_captured() {
    let line = timeline(vec![step(
        1,
        Action::Changed {
            offset: 2,
            len: u64::MAX,
        },
    )]);
    let mut map = Reconstruction::new(start_with(b"abcd"), &line);
    map.goto(1);
    assert_eq!(shown(&map), "61 62 ## ##");
}

#[test]
fn each_byte_remembers_when_it_was_learned() {
    let line = timeline(vec![
        step(100, Action::Read(vec![kept(0, b"ab")])),
        step(200, Action::Write(vec![kept(1, b"X")])),
    ]);
    let mut map = Reconstruction::new(Start::default(), &line);
    map.goto(2);
    let row = map.row(0, 2);
    assert_eq!((row[0].state, row[0].learned), (State::Read, 0));
    assert_eq!((row[1].state, row[1].learned), (State::Written, 1));
    assert_eq!(map.steps()[row[1].learned].time_ns, 200);
    let history = map.history(1);
    assert_eq!(
        history,
        vec![
            History {
                step: 0,
                event: Event::Read,
                byte: Some(b'b')
            },
            History {
                step: 1,
                event: Event::Written,
                byte: Some(b'X')
            },
        ]
    );
    map.goto(1);
    assert_eq!(map.history(1).len(), 1);
}

#[test]
fn the_history_starts_at_the_before_image_and_ends_at_a_cut() {
    let line = timeline(vec![
        step(1, Action::Write(vec![kept(0, b"N")])),
        step(2, Action::Resize(0)),
    ]);
    let mut map = Reconstruction::new(start_with(b"o"), &line);
    map.goto(2);
    let events: Vec<Event> = map.history(0).iter().map(|entry| entry.event).collect();
    assert_eq!(events, [Event::Start, Event::Written, Event::Cut]);
    assert_eq!(map.size(), 0);
}

#[test]
fn a_late_write_that_lost_a_race_goes_under_the_one_the_file_system_applied_later() {
    let mut line = Timeline::default();
    let numbered = |order, bytes: &[u8]| Step {
        time_ns: order,
        event: None,
        order: Some(order),
        action: Action::Write(vec![kept(0, bytes)]),
    };
    line.push(numbered(7, b"B"));
    line.push(numbered(5, b"A"));
    let mut map = Reconstruction::new(Start::empty(), &line);
    map.goto(2);
    assert_eq!(map.bytes(0, 1).unwrap(), b"B");
}

#[test]
fn the_step_list_is_bounded_and_counts_what_it_dropped() {
    let mut line = Timeline::default();
    for index in 0..STEPS_PER_FILE as u64 + 3 {
        line.push(step(index, Action::Resize(0)));
    }
    assert_eq!(line.steps().len(), STEPS_PER_FILE);
    assert_eq!(line.unlisted, 3);
}

#[test]
fn a_save_fills_unknown_bytes_with_zero_and_says_which_in_the_mask() {
    let line = timeline(vec![
        step(
            1,
            Action::Write(vec![kept(0, b"A"), missing(1, 1, Gap::RunCap)]),
        ),
        step(2, Action::Mapping { offset: 3, len: 1 }),
        step(3, Action::Write(vec![kept(4, b"E")])),
    ]);
    let mut map = Reconstruction::new(Start::empty(), &line);
    map.goto(3);
    let (mut data, mut mask) = (Vec::new(), Vec::new());
    let saved = map.save(&mut data, Some(&mut mask)).unwrap();
    assert_eq!(data, b"A\0\0\0E");
    assert_eq!(mask, [0, 2, 1, 3, 0]);
    assert_eq!(
        saved,
        Saved {
            bytes: 5,
            filled: 3,
            unreadable: 0
        }
    );
}

#[test]
fn the_hash_is_taken_only_when_every_byte_is_known_and_matches_the_content() {
    let line = timeline(vec![
        step(1, Action::Write(vec![kept(0, b"abc")])),
        step(2, Action::Write(vec![missing(3, 1, Gap::FileCap)])),
    ]);
    let mut map = Reconstruction::new(Start::empty(), &line);
    map.goto(1);
    let expected: String = Sha256::digest(b"abc")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(map.sha256().unwrap(), expected);
    map.goto(2);
    assert_eq!(map.sha256(), Err(Incomplete::Missing(1)));
    let unknown = Reconstruction::new(Start::default(), &Timeline::default());
    assert_eq!(unknown.sha256(), Err(Incomplete::SizeUnknown));
}

#[test]
fn steps_until_gives_the_story_at_a_moment() {
    let line = timeline(vec![
        step(10, Action::Resize(1)),
        step(20, Action::Resize(2)),
        step(30, Action::Resize(3)),
    ]);
    let map = Reconstruction::new(Start::empty(), &line);
    assert_eq!(map.steps_until(5), 0);
    assert_eq!(map.steps_until(20), 2);
    assert_eq!(map.steps_until(99), 3);
}

#[test]
fn text_needs_every_byte_and_valid_text() {
    let line = timeline(vec![step(1, Action::Write(vec![kept(0, b"a\nb\n")]))]);
    let mut map = Reconstruction::new(Start::empty(), &line);
    map.goto(1);
    assert_eq!(map.text(100).unwrap(), "a\nb\n");
    assert_eq!(map.text(2), Err(TextError::TooLarge(4)));
    let line = timeline(vec![step(1, Action::Write(vec![kept(0, &[0xff, 0xfe])]))]);
    let mut map = Reconstruction::new(Start::empty(), &line);
    map.goto(1);
    assert_eq!(map.text(100), Err(TextError::NotText));
}

#[test]
fn a_line_diff_keeps_common_lines_and_marks_the_changes() {
    let diff = line_diff("a\nb\nc\n", "a\nB\nc\nd\n");
    let marks: Vec<(Change, &str)> = diff.iter().map(|l| (l.change, l.text.as_str())).collect();
    assert_eq!(
        marks,
        [
            (Change::Same, "a"),
            (Change::Removed, "b"),
            (Change::Added, "B"),
            (Change::Same, "c"),
            (Change::Added, "d"),
        ]
    );
    assert!(
        line_diff("same\n", "same\n")
            .iter()
            .all(|l| l.change == Change::Same)
    );
}
