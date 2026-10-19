// SPDX-License-Identifier: MIT
//! Optional presentation filters; never discard file reconstruction evidence.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct FileVisibility {
    pub hide_standard_io: bool,
    pub hide_libraries: bool,
    /// List calls the kernel refused. They are never counted as changes.
    pub show_failed: bool,
}

impl Default for FileVisibility {
    fn default() -> Self {
        Self {
            hide_standard_io: true,
            hide_libraries: true,
            show_failed: false,
        }
    }
}

impl FileVisibility {
    pub fn keeps(self, row: &[Cell]) -> bool {
        self.keeps_with(row, self.show_failed)
    }

    /// Like [`Self::keeps`], with `show_failed` decided by the caller: the
    /// Opened and Read tables always list failed attempts.
    pub fn keeps_with(self, row: &[Cell], show_failed: bool) -> bool {
        let Some(first) = row.first() else {
            return true;
        };
        if !show_failed
            && first.values.iter().any(|(key, value)| {
                *key == "file.result" && matches!(value, RowValue::Text(text) if text == "failed")
            })
        {
            return false;
        }
        if self.hide_standard_io
            && first.values.iter().any(|(key, value)| {
                matches!((*key, value), ("file.standard_io", RowValue::Bool(true)))
                    || (*key == "file.fd" && matches!(value, RowValue::Number(0..=2)))
            })
        {
            return false;
        }
        !self.hide_libraries
            || !first.values.iter().any(|(key, value)| {
                *key == "file.path" && matches!(value, RowValue::Text(path) if library_path(path))
            })
    }
}

fn library_path(path: &str) -> bool {
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
    fn failed_attempts_are_hidden_until_asked_for() {
        let mut row = vec![cell("path", theme::text(), true)];
        row[0].values = vec![
            ("file.path", RowValue::Text("/tmp/a".into())),
            ("file.result", RowValue::Text("failed".into())),
        ];
        assert!(!FileVisibility::default().keeps(&row));
        let shown = FileVisibility {
            show_failed: true,
            ..FileVisibility::default()
        };
        assert!(shown.keeps(&row));
        row[0].values[1].1 = RowValue::Text("no exit".into());
        assert!(FileVisibility::default().keeps(&row));
        row[0].values[1].1 = RowValue::Text("succeeded".into());
        assert!(FileVisibility::default().keeps(&row));
    }
}
