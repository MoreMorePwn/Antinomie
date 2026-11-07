// SPDX-License-Identifier: GPL-3.0-only
//! Where an export goes when the person has not said, and the word it gives
//! back. An export defaults to the folder the last one went to, else a folder
//! of its own kind under the data directory: never the home directory, where a
//! custody record or an analysis dump would land among personal files.
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LAST: Mutex<Option<PathBuf>> = Mutex::new(None);

/// The folder an export of `kind` ("custody", "static") opens with: `last`
/// when it is a folder that still exists, else `<data>/exports/<kind>`.
pub(crate) fn choose(data_dir: &Path, kind: &str, last: Option<&Path>) -> PathBuf {
    match last {
        Some(folder) if folder.is_dir() => folder.to_path_buf(),
        _ => data_dir.join("exports").join(kind),
    }
}

/// [`choose`] with the folder of the last export this session.
pub(crate) fn default_folder(data_dir: &Path, kind: &str) -> PathBuf {
    let last = LAST.lock().ok().and_then(|last| last.clone());
    choose(data_dir, kind, last.as_deref())
}

/// An export wrote `file`: the next one opens in its folder.
pub(crate) fn remember(file: &Path) {
    if let Some(folder) = file.parent().filter(|f| !f.as_os_str().is_empty()) {
        if let Ok(mut last) = LAST.lock() {
            *last = Some(folder.to_path_buf());
        }
    }
}

/// The one naming scheme of every export: `antinomie-<kind>-<subject>-<time>.<ext>`,
/// the subject cut to 8 letters or digits (a run or sample id), the time
/// `yyyymmdd-hhmmss` in UTC. `ms` is the Unix time in milliseconds.
pub(crate) fn stamped_at(kind: &str, subject: &str, ext: &str, ms: u64) -> String {
    let subject: String = subject
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    let time = antinomie_monitor_core::report::utc(ms)
        .replace(['-', ':'], "")
        .replace(' ', "-");
    if subject.is_empty() {
        format!("antinomie-{kind}-{time}.{ext}")
    } else {
        format!("antinomie-{kind}-{subject}-{time}.{ext}")
    }
}

/// [`stamped_at`] for now.
pub(crate) fn stamped(kind: &str, subject: &str, ext: &str) -> String {
    stamped_at(kind, subject, ext, crate::time_format::now_ms())
}

/// The size as people read it: `5.4 KiB`.
fn size_text(bytes: u64) -> String {
    antinomie_monitor_core::byte_size::short_size(bytes)
}

/// The words for a finished export: what was written, its size and where.
pub(crate) fn wrote_text(what: &str, path: &Path) -> String {
    let size = std::fs::metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len());
    match size {
        Some(size) => format!(
            "{what} written: {} ({}) in {}",
            file_name(path),
            size_text(size),
            folder_text(path)
        ),
        None => format!("{what} written: {}", path.display()),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn folder_text(path: &Path) -> String {
    path.parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

/// Tell the person: an Activity row and a toast naming the file, its size and
/// its folder. Also remembers the folder for the next export.
pub(crate) fn wrote(ctx: &eframe::egui::Context, what: &str, path: &Path) {
    remember(path);
    reported(ctx, what, path);
}

/// [`wrote`] for a file that belongs to its run's folder: told, not remembered
/// as the place the next export opens in.
pub(crate) fn reported(ctx: &eframe::egui::Context, what: &str, path: &Path) {
    crate::activity::report(ctx, crate::activity::Level::Info, wrote_text(what, path));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_export_opens_in_the_last_folder_that_exists_else_under_the_data_directory() {
        let data = Path::new("/d");
        assert_eq!(
            choose(data, "custody", None),
            Path::new("/d/exports/custody")
        );
        assert_eq!(
            choose(data, "static", Some(Path::new("/nonexistent/x"))),
            Path::new("/d/exports/static")
        );
        let temp = std::env::temp_dir();
        assert_eq!(choose(data, "static", Some(&temp)), temp);
    }

    #[test]
    fn every_export_is_named_kind_subject_time() {
        // 2026-11-08 00:49:54 UTC.
        let ms = 1_794_098_994_000;
        assert_eq!(
            stamped_at("indicators", "f9c3d854-aaaa", "json", ms),
            "antinomie-indicators-f9c3d854-20261108-004954.json"
        );
        assert_eq!(
            stamped_at("custody", "", "json", ms),
            "antinomie-custody-20261108-004954.json"
        );
    }

    #[test]
    fn the_word_for_a_written_file_names_its_size_and_folder() {
        let dir = std::env::temp_dir().join(format!("ant-export-dirs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.json");
        std::fs::write(&file, vec![b'a'; 2048]).unwrap();
        let text = wrote_text("Indicators", &file);
        assert!(
            text.contains("x.json")
                && text.contains("2.0 KiB")
                && text.contains(&dir.display().to_string()),
            "{text}"
        );
        assert!(wrote_text("Indicators", &dir.join("gone")).contains("gone"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
