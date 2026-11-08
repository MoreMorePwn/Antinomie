// SPDX-License-Identifier: GPL-3.0-only
//! Where a key is in a TOML file, for error messages: the line and column of
//! the key (the first line of the file when the key is not written).

use std::collections::HashMap;
use toml::de::{DeTable, DeValue};

pub struct Locator {
    line_starts: Vec<usize>,
    keys: HashMap<String, usize>,
}

impl Locator {
    /// Index the keys of `text`. A file that does not parse has no key index:
    /// every lookup answers the first line.
    pub fn new(text: &str) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(at, _)| at + 1),
        );
        let mut keys = HashMap::new();
        if let Ok(root) = DeTable::parse(text) {
            walk(root.get_ref(), "", &mut keys);
        }
        Self { line_starts, keys }
    }

    /// Line and column (both from 1) of a byte offset.
    pub fn line_col(&self, offset: usize) -> (u32, u32) {
        let line = match self.line_starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index - 1,
        };
        (
            line as u32 + 1,
            (offset - self.line_starts[line]) as u32 + 1,
        )
    }

    /// Where `path` (dotted, array elements by index: `inbox.watch.0.policy`)
    /// is written; the nearest written parent when it is not.
    pub fn find(&self, path: &str) -> (u32, u32) {
        let mut path = path;
        loop {
            if let Some(offset) = self.keys.get(path) {
                return self.line_col(*offset);
            }
            match path.rfind('.') {
                Some(dot) => path = &path[..dot],
                None => return (1, 1),
            }
        }
    }
}

fn walk(table: &DeTable<'_>, prefix: &str, keys: &mut HashMap<String, usize>) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.get_ref().to_string()
        } else {
            format!("{prefix}.{}", key.get_ref())
        };
        keys.insert(path.clone(), key.span().start);
        match value.get_ref() {
            DeValue::Table(inner) => walk(inner, &path, keys),
            DeValue::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let at = format!("{path}.{index}");
                    keys.insert(at.clone(), item.span().start);
                    if let DeValue::Table(inner) = item.get_ref() {
                        walk(inner, &at, keys);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_keys_and_array_elements() {
        let text = "a = 1\n[net]\nroute = \"drop\"\n\n[[w]]\np = 1\n[[w]]\np = 2\n";
        let locator = Locator::new(text);
        assert_eq!(locator.find("a"), (1, 1));
        assert_eq!(locator.find("net.route"), (3, 1));
        assert_eq!(locator.find("w.1.p"), (8, 1));
        // A key that is not written falls back to its parent, then to line 1.
        assert_eq!(locator.find("net.missing"), (2, 2));
        assert_eq!(locator.find("nothing"), (1, 1));
    }
}
