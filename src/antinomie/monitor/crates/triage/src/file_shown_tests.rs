// SPDX-License-Identifier: GPL-3.0-only
//! The columns, badges and times the Files tables draw.
use super::file_shown::{self, Notes};
use super::*;

pub fn headers_of(tab: FileTab, stored: &[&'static str]) -> Vec<&'static str> {
    file_tabs::shown_columns(tab.slot())
        .iter()
        .map(|&index| stored[index])
        .collect()
}

#[test]
pub fn each_files_table_draws_these_columns() {
    use file_category::EVENT_HEADERS;
    assert_eq!(
        headers_of(FileTab::Opened, EVENT_HEADERS),
        ["Time", "Path", "Process", "Result"]
    );
    for tab in [
        FileTab::Created,
        FileTab::Written,
        FileTab::Deleted,
        FileTab::Renamed,
        FileTab::Executed,
        FileTab::Attributes,
        FileTab::Probed,
        FileTab::Other,
    ] {
        assert_eq!(
            headers_of(tab, EVENT_HEADERS),
            [
                "Time",
                "Category",
                "Operation",
                "Path",
                "Detail",
                "Process",
                "Result",
                "Access"
            ]
        );
    }
    assert_eq!(
        headers_of(FileTab::Read, file_tabs::READ_HEADERS),
        ["Time", "Path", "Process", "Transferred / content", "Result"]
    );
    assert_eq!(
        headers_of(FileTab::Changed, file_tabs::CHANGED_HEADERS),
        [
            "Time",
            "Path",
            "Process",
            "Lifecycle",
            "Changes",
            "Type",
            "SHA-256"
        ]
    );
    // Nothing is named Evidence, Location or Diff count any more.
    for header in EVENT_HEADERS
        .iter()
        .chain(file_tabs::READ_HEADERS)
        .chain(file_tabs::CHANGED_HEADERS)
    {
        assert_ne!(*header, "Diff count");
    }
    for tab in FileTab::ALL {
        let stored = match tab {
            FileTab::Read => file_tabs::READ_HEADERS,
            FileTab::Changed => file_tabs::CHANGED_HEADERS,
            _ => EVENT_HEADERS,
        };
        let shown = headers_of(tab, stored);
        assert!(!shown.contains(&"Evidence") && !shown.contains(&"Location"));
    }
    // A sort on a drawn column sorts the stored one behind it.
    assert_eq!(file_tabs::full_column(1, 1), 3);
    assert_eq!(file_tabs::full_column(1, 3), 6);
    assert_eq!(file_tabs::full_column(5, 4), 4);
    assert_eq!(file_tabs::full_column(8, 7), 8);
    assert_eq!(file_tabs::full_column(2, 5), 7);
}

#[test]
pub fn a_task_is_its_name_and_two_bare_numbers() {
    assert_eq!(
        process_cells::task_label(412, 412, Some("/tmp/x/dropper")),
        "dropper (412 \u{b7} 412)"
    );
    assert_eq!(
        process_cells::task_label(7, 9, None),
        "unknown (7 \u{b7} 9)"
    );
    assert_eq!(
        process_cells::task_label(7, 9, Some("?")),
        "unknown (7 \u{b7} 9)"
    );
}

pub fn stored_row(path: &str, time_ns: u64) -> Vec<Cell> {
    let mut row: Vec<Cell> = file_category::EVENT_HEADERS
        .iter()
        .map(|header| cell(*header, tone::text(), false))
        .collect();
    row[0].text = "~12:00:01.000".into();
    row[3].text = path.into();
    row[0].values = vec![
        ("event.time_ns", RowValue::Number(i128::from(time_ns))),
        ("file.path", RowValue::Text(path.into())),
        (
            "file.location",
            RowValue::List(vec!["temp".into(), "hidden".into()]),
        ),
        (
            "file.names",
            RowValue::List(vec![path.into(), "/tmp/b".into(), "/tmp/c".into()]),
        ),
        ("event.id", RowValue::Number(5)),
    ];
    row
}

#[test]
pub fn a_path_is_only_the_path_and_its_tags_are_in_the_next_column() {
    let mut flagged = file_shown::Flags::new();
    let mut flag = |rule| file_shown::flag(&mut flagged, "/tmp/.x", rules::Tier::Medium, rule);
    flag("evasion.hidden_artifact");
    let notes = Notes {
        start: Some(1_000_000_000),
        flagged: &flagged,
    };
    let rows = vec![
        stored_row("/tmp/.x", 2_204_000_000),
        stored_row("/tmp/y", 3_000_000_000),
    ];
    let shown = file_shown::shown(8, &rows, &notes);
    // One column more than the stored selection: Tags, after the Path.
    assert_eq!(shown[0].len(), file_tabs::OPERATION_COLUMNS.len() + 1);
    let headers = file_shown::headers(8, file_category::EVENT_HEADERS);
    assert_eq!(headers.len(), shown[0].len());
    assert_eq!(headers[3], "Path");
    assert_eq!(headers[4], "Tags");
    // The time is from the start of the run, the absolute one on hover.
    assert_eq!(shown[0][0].text, "+1.204 s");
    assert_eq!(shown[0][0].note.as_deref(), Some("~12:00:01.000"));
    // The row keeps what it is found by.
    assert!(shown[0][0].values.iter().any(|(key, _)| *key == "event.id"));
    let path = &shown[0][3];
    assert_eq!(path.text, "/tmp/.x");
    assert!(path.badges.is_empty());
    let tags =
        |row: &Vec<Cell>| -> Vec<String> { row[4].badges.iter().map(|b| b.text.clone()).collect() };
    assert_eq!(
        tags(&shown[0]),
        [
            "/tmp",
            "hidden",
            "+2 names",
            "Medium \u{b7} Hidden file created"
        ]
    );
    // No finding names the other path: no finding tag.
    assert_eq!(tags(&shown[1]), ["/tmp", "hidden", "+2 names"]);
    // Several findings: their number and the worst tier.
    file_shown::flag(
        &mut flagged,
        "/tmp/.x",
        rules::Tier::High,
        "execution.temp_exec",
    );
    file_shown::flag(
        &mut flagged,
        "/tmp/.x",
        rules::Tier::Low,
        "evasion.dumpable_off",
    );
    let notes = Notes {
        start: None,
        flagged: &flagged,
    };
    let shown = file_shown::shown(8, &rows[..1], &notes);
    assert_eq!(tags(&shown[0]).last().unwrap(), "3 findings \u{b7} High");
    // The row without a start of the run keeps its absolute time.
    assert_eq!(shown[0][0].text, "~12:00:01.000");
    // No table draws a warning sign.
    for slot in [1, 2, 5, 8] {
        let stored: Vec<Cell> = (0..10).map(|_| cell("x", tone::text(), false)).collect();
        let drawn = file_shown::shown(slot, &[stored], &notes);
        assert!(drawn[0].iter().all(|cell| !cell.text.contains('\u{26a0}')
            && cell
                .badges
                .iter()
                .all(|badge| !badge.text.contains('\u{26a0}'))));
    }
}

#[test]
pub fn a_digest_is_cut_with_the_whole_one_on_hover() {
    assert_eq!(
        file_shown::short_hash(&"ab".repeat(32)),
        "abababababab\u{2026}"
    );
    assert_eq!(file_shown::short_hash("abc"), "abc");
    assert_eq!(file_shown::size_text(0), "0 B");
    assert_eq!(file_shown::size_text(812 * 1024), "812 KiB");
}

#[test]
pub fn locations_have_a_short_badge_word() {
    use file_location::{classify, Location};
    let tag = |path: &str| classify(path, &[]).first().map(|l| l.tag());
    assert_eq!(tag("/home/user/note"), Some("home"));
    assert_eq!(Location::badge("temp"), "/tmp");
    assert_eq!(Location::badge("pseudo-fs"), "proc");
    assert_eq!(Location::badge("system"), "system");
}
