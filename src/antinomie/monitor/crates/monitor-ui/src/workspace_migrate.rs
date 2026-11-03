// SPDX-License-Identifier: GPL-3.0-only
//! Dock layouts saved by 0.8.1 and earlier (egui_dock 0.16) still load.
//!
//! egui_dock 0.21 holds a leaf's or split's fields in a struct of their own
//! (`Leaf(LeafNode)`, `Vertical(SplitNode)`), which RON writes with one more
//! pair of parentheses than the old `Leaf { rect, tabs, .. }`. A saved layout
//! in the old shape is rewritten to the new one before it is read, so the
//! person keeps their tabs, splits and windows.
use super::WorkspaceLayout;

const KEY: &str = "workspace_layout";

/// The saved layout: written by this version, or by an older one.
pub(crate) fn load(storage: Option<&dyn eframe::Storage>) -> Option<WorkspaceLayout> {
    let storage = storage?;
    if let Some(layout) = eframe::get_value(storage, KEY) {
        return Some(layout);
    }
    let old = storage.get_string(KEY)?;
    let upgraded = Upgraded(upgrade(&old));
    eframe::get_value(&upgraded, KEY)
}

/// A one-value storage holding the rewritten layout.
struct Upgraded(String);

impl eframe::Storage for Upgraded {
    fn get_string(&self, _: &str) -> Option<String> {
        Some(self.0.clone())
    }
    fn set_string(&mut self, _: &str, _: String) {}
    fn remove_string(&mut self, _: &str) {}
    fn flush(&mut self) {}
}

/// Wraps the fields of every `Leaf(`, `Vertical(` and `Horizontal(` node
/// that is still in the old shape (`Leaf(rect: ..)`) in one more pair of
/// parentheses. Text in quotes is copied as it is.
fn upgrade(old: &str) -> String {
    let mut out = String::with_capacity(old.len() + 64);
    // For every open parenthesis: whether this rewrite added a second one.
    let mut wrapped = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (at, ch) in old.char_indices() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '(' => {
                let node = ["Leaf", "Vertical", "Horizontal"]
                    .iter()
                    .any(|name| names_node(&out, name));
                let old_shape = old[at + 1..].starts_with("rect:");
                out.push('(');
                if node && old_shape {
                    out.push('(');
                }
                wrapped.push(node && old_shape);
            }
            ')' => {
                out.push(')');
                if wrapped.pop() == Some(true) {
                    out.push(')');
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Whether `text` ends with the variant name `name` as a whole word.
fn names_node(text: &str, name: &str) -> bool {
    text.strip_suffix(name)
        .is_some_and(|rest| !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
}
