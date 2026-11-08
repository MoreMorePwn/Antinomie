// SPDX-License-Identifier: GPL-3.0-only
//! Host paths never reach a remote reply (design 5.12.7, class Local): engine
//! text that may carry one has the data directory and the home directory
//! replaced before it is sent.

use serde_json::Value;
use std::path::Path;

/// What to remove from engine text.
#[derive(Clone, Debug, Default)]
pub struct Scrub {
    /// `(path text, replacement)`, longest path first.
    roots: Vec<(String, &'static str)>,
}

impl Scrub {
    /// `data_dir` becomes `<data>`, `$HOME` becomes `~`, and any extra
    /// directory (a recording folder outside the data directory) `<recording>`.
    pub fn new(data_dir: &Path, extra: &[&Path]) -> Self {
        let mut roots: Vec<(String, &'static str)> = Vec::new();
        let mut add = |path: &Path, replacement: &'static str| {
            let text = path.to_string_lossy().into_owned();
            if text.len() > 1 && !roots.iter().any(|(known, _)| *known == text) {
                roots.push((text, replacement));
            }
            if let Ok(canonical) = path.canonicalize() {
                let text = canonical.to_string_lossy().into_owned();
                if text.len() > 1 && !roots.iter().any(|(known, _)| *known == text) {
                    roots.push((text, replacement));
                }
            }
        };
        add(data_dir, "<data>");
        for path in extra {
            add(path, "<recording>");
        }
        if let Some(home) = std::env::var_os("HOME") {
            add(Path::new(&home), "~");
        }
        roots.sort_by_key(|(text, _)| std::cmp::Reverse(text.len()));
        Self { roots }
    }

    /// `text` with every known host path replaced.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (root, replacement) in &self.roots {
            if out.contains(root.as_str()) {
                out = out.replace(root.as_str(), replacement);
            }
        }
        out
    }

    /// Every string of a JSON value, in place.
    pub fn value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.text(text),
            Value::Array(items) => items.iter_mut().for_each(|item| self.value(item)),
            Value::Object(map) => map.values_mut().for_each(|item| self.value(item)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_directory_paths_are_replaced_longest_first() {
        let scrub = Scrub::new(Path::new("/srv/ant"), &[Path::new("/srv/ant/vm/rec")]);
        assert_eq!(
            scrub.text("open /srv/ant/vm/rec/runs/r1/x: denied"),
            "open <recording>/runs/r1/x: denied"
        );
        assert_eq!(scrub.text("/srv/ant/bases"), "<data>/bases");
        let mut value = serde_json::json!({"a": ["/srv/ant/x", 3], "b": {"c": "/srv/ant"}});
        scrub.value(&mut value);
        assert_eq!(value["a"][0], "<data>/x");
        assert_eq!(value["b"]["c"], "<data>");
    }
}
