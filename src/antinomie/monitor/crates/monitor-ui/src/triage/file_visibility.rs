// SPDX-License-Identifier: MIT
//! Optional presentation filters; never discard file reconstruction evidence.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct FileVisibility {
    pub hide_standard_io: bool,
    pub hide_libraries: bool,
}

impl Default for FileVisibility {
    fn default() -> Self {
        Self {
            hide_standard_io: true,
            hide_libraries: true,
        }
    }
}

impl FileVisibility {
    pub fn keeps(self, row: &[Cell]) -> bool {
        let Some(first) = row.first() else {
            return true;
        };
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
            hide_libraries: false
        }
        .keeps(&row));
        row[0].values = vec![("file.standard_io", RowValue::Bool(true))];
        assert!(!visibility.keeps(&row));
    }
}
