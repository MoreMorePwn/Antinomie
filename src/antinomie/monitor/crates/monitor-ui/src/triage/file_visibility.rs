// SPDX-License-Identifier: GPL-3.0-only
//! Optional presentation filters; never discard file reconstruction evidence.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FileVisibility {
    pub hide_standard_io: bool,
    pub hide_libraries: bool,
    /// List calls the kernel refused, in every Files table. On by default.
    /// They are never counted as changes.
    pub show_failed: bool,
}

impl Default for FileVisibility {
    fn default() -> Self {
        Self {
            hide_standard_io: true,
            hide_libraries: true,
            show_failed: true,
        }
    }
}

impl FileVisibility {
    pub fn keeps(self, row: &[Cell]) -> bool {
        self.keeps_with(row, self.show_failed)
    }

    /// Like [`Self::keeps`], with `show_failed` decided by the caller.
    pub fn keeps_with(self, row: &[Cell], show_failed: bool) -> bool {
        if !show_failed && Self::failed(row) {
            return false;
        }
        let (stdio, library) = Self::classes(row);
        !(self.hide_standard_io && stdio) && !(self.hide_libraries && library)
    }

    /// The call the row stands for was refused by the kernel.
    pub fn failed(row: &[Cell]) -> bool {
        row.first().is_some_and(|first| {
            first.values.iter().any(|(key, value)| {
                *key == "file.result" && matches!(value, RowValue::Text(text) if text == "failed")
            })
        })
    }

    /// Whether the row is standard input/output, and whether it is a library,
    /// whatever the toggles say: what each chip would hide.
    pub fn classes(row: &[Cell]) -> (bool, bool) {
        let Some(first) = row.first() else {
            return (false, false);
        };
        let stdio = first.values.iter().any(|(key, value)| {
            matches!((*key, value), ("file.standard_io", RowValue::Bool(true)))
                || (*key == "file.fd" && matches!(value, RowValue::Number(0..=2)))
        });
        let library = first.values.iter().any(|(key, value)| {
            *key == "file.path" && matches!(value, RowValue::Text(path) if library_path(path))
        });
        (stdio, library)
    }
}

/// What the visibility chips hide in one Files table, counted over the whole
/// run so the chips and the tab can show the real numbers.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct VisibilityCount {
    /// Rows the table could list before the chips.
    pub total: u64,
    /// Rows the table lists with the chips as they are.
    pub shown: u64,
    /// Rows that are standard input/output, and rows that are libraries.
    pub stdio: u64,
    pub library: u64,
    /// Rows for calls the kernel refused, whether the chip lists them or not.
    pub failed: u64,
}

impl VisibilityCount {
    /// Count a refused call's row; [`Self::add`] counts it only when listed.
    pub(super) fn note_failed(&mut self, row: &[Cell]) {
        self.failed += u64::from(FileVisibility::failed(row));
    }

    pub(super) fn add(&mut self, visibility: FileVisibility, row: &[Cell], show_failed: bool) {
        let (stdio, library) = FileVisibility::classes(row);
        self.total += 1;
        self.stdio += u64::from(stdio);
        self.library += u64::from(library);
        self.shown += u64::from(visibility.keeps_with(row, show_failed));
    }
}

/// Where a Files table's visibility counts are kept: Opened, Read, Changed,
/// then the operation tabs in slot order.
pub(super) fn visibility_slot(tab: FileTab) -> usize {
    match tab {
        FileTab::Opened => 0,
        FileTab::Read => 1,
        FileTab::Changed => 2,
        other => 3 + other.slot() - 8,
    }
}

pub(super) fn library_path(path: &str) -> bool {
    path.split('/')
        .any(|component| matches!(component, "lib" | "lib32" | "lib64" | "libx32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_preserve_unknown_paths_and_similar_names_and_can_be_disabled() {
        let mut row = vec![cell("path", theme::text(), true)];
        let visibility = FileVisibility::default();
        for path in [
            "/usr/lib/a.so",
            "/lib64/ld-linux.so",
            "lib/a.so",
            "/usr/local/lib/a.so",
        ] {
            row[0].values = vec![("file.path", RowValue::Text(path.into()))];
            assert!(!visibility.keeps(&row), "{path}");
        }
        for path in ["/tmp/liberation.txt", "/tmp/mylib/a", "/tmp/a.so"] {
            row[0].values = vec![("file.path", RowValue::Text(path.into()))];
            assert!(visibility.keeps(&row), "{path}");
        }
        row[0].values = vec![("file.path", RowValue::Missing)];
        assert!(visibility.keeps(&row));
        row[0].values.push(("file.fd", RowValue::Number(1)));
        assert!(!visibility.keeps(&row));
        assert!(FileVisibility {
            hide_standard_io: false,
            hide_libraries: false,
            show_failed: false
        }
        .keeps(&row));
        row[0].values = vec![("file.standard_io", RowValue::Bool(true))];
        assert!(!visibility.keeps(&row));
    }

    #[test]
    fn failed_attempts_are_listed_by_default_and_hidden_when_the_chip_is_off() {
        let mut row = vec![cell("path", theme::text(), true)];
        row[0].values = vec![
            ("file.path", RowValue::Text("/tmp/a".into())),
            ("file.result", RowValue::Text("failed".into())),
        ];
        assert!(FileVisibility::default().show_failed);
        assert!(FileVisibility::default().keeps(&row));
        let hidden = FileVisibility {
            show_failed: false,
            ..FileVisibility::default()
        };
        assert!(!hidden.keeps(&row));
        row[0].values[1].1 = RowValue::Text("no exit".into());
        assert!(hidden.keeps(&row));
        row[0].values[1].1 = RowValue::Text("succeeded".into());
        assert!(hidden.keeps(&row));
    }
}
