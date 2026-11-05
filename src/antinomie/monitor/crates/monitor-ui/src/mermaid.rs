// SPDX-License-Identifier: GPL-3.0-only
//! Mermaid text for the diagrams the app draws, so each can be pasted into a
//! README, an issue or a report. Every diagram is a `flowchart`: graphs and
//! trees alike. A node's id comes from the key the caller gives it (a hash, a
//! task cookie, a snapshot id), not from the order it is added in, so the
//! same diagram gives the same text and a pasted diagram keeps its ids when
//! a node is added later. Labels are quoted and escaped.
use eframe::egui;

/// A flowchart under construction.
pub(crate) struct Flowchart {
    direction: &'static str,
    /// `(key, id, label)` in the order the nodes were added.
    nodes: Vec<(String, String, String)>,
    /// `(from id, to id, label)`.
    edges: Vec<(String, String, Option<String>)>,
}

impl Flowchart {
    /// `direction` is a Mermaid one: "LR", "TD".
    pub(crate) fn new(direction: &'static str) -> Self {
        Self {
            direction,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add the node `key` with `label`, or return the id it already has (its
    /// label is then kept). The id is `n` and eight hex digits of a hash of
    /// the key; a clash with another key's id takes a counter.
    pub(crate) fn node(&mut self, key: &str, label: &str) -> String {
        if let Some((_, id, _)) = self.nodes.iter().find(|(known, _, _)| known == key) {
            return id.clone();
        }
        let mut id = format!("n{:08x}", fnv1a(key));
        let mut counter = 1;
        while self.nodes.iter().any(|(_, taken, _)| *taken == id) {
            id = format!("n{:08x}_{counter}", fnv1a(key));
            counter += 1;
        }
        self.nodes
            .push((key.to_owned(), id.clone(), label.to_owned()));
        id
    }

    /// Add an arrow between two nodes already added (by key). An edge whose
    /// end is not a node is left out.
    pub(crate) fn edge(&mut self, from: &str, to: &str, label: Option<&str>) {
        let id = |key: &str| {
            self.nodes
                .iter()
                .find(|(known, _, _)| known == key)
                .map(|(_, id, _)| id.clone())
        };
        if let (Some(from), Some(to)) = (id(from), id(to)) {
            self.edges.push((from, to, label.map(str::to_owned)));
        }
    }

    /// The Mermaid text.
    pub(crate) fn render(&self) -> String {
        let mut text = format!("flowchart {}\n", self.direction);
        for (_, id, label) in &self.nodes {
            text.push_str(&format!("    {id}[\"{}\"]\n", escape(label)));
        }
        for (from, to, label) in &self.edges {
            match label {
                Some(label) if !label.is_empty() => {
                    text.push_str(&format!("    {from} -->|\"{}\"| {to}\n", escape(label)))
                }
                _ => text.push_str(&format!("    {from} --> {to}\n")),
            }
        }
        text
    }
}

/// A node of [`tree`]: its key, its label and its parent's key.
pub(crate) struct TreeNode {
    pub key: String,
    pub label: String,
    pub parent: Option<String>,
}

/// A tree (a process tree, a snapshot tree) as a top-down flowchart, a parent
/// pointing at each child. A parent that is not in `nodes` leaves its child
/// a root.
pub(crate) fn tree(nodes: &[TreeNode]) -> String {
    let mut chart = Flowchart::new("TD");
    for node in nodes {
        chart.node(&node.key, &node.label);
    }
    for node in nodes {
        if let Some(parent) = &node.parent {
            chart.edge(parent, &node.key, None);
        }
    }
    chart.render()
}

/// A label for inside `["..."]`: Mermaid's entity codes for what would end
/// the quote or start markup, `<br/>` for a line break, no control
/// characters.
pub(crate) fn escape(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        match c {
            '"' => out.push_str("#quot;"),
            '<' => out.push_str("#lt;"),
            '>' => out.push_str("#gt;"),
            '&' => out.push_str("#amp;"),
            '#' => out.push_str("#35;"),
            '`' => out.push_str("#96;"),
            '|' => out.push_str("#124;"),
            '\n' => out.push_str("<br/>"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// FNV-1a, 32 bits: stable across runs and builds, unlike `DefaultHasher`.
fn fnv1a(text: &str) -> u32 {
    text.bytes().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

/// The "Copy as Mermaid" item of a context menu: `text` goes to the
/// clipboard and the menu closes.
pub(crate) fn menu_item(ui: &mut egui::Ui, text: impl FnOnce() -> String) {
    if ui
        .button("Copy as Mermaid")
        .on_hover_text("Put this diagram on the clipboard as a Mermaid flowchart")
        .clicked()
    {
        ui.ctx().copy_text(text());
        ui.close();
    }
}

/// A small "Copy as Mermaid" button, for a diagram with no context menu.
pub(crate) fn button(ui: &mut egui::Ui, text: impl FnOnce() -> String) -> egui::Response {
    let response = ui
        .button(format!("{} Mermaid", egui_phosphor::regular::COPY))
        .on_hover_text("Copy this diagram to the clipboard as a Mermaid flowchart");
    if response.clicked() {
        ui.ctx().copy_text(text());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_cannot_leave_its_quotes_or_start_markup() {
        assert_eq!(
            escape(r#"say "hi" <b>&</b>"#),
            "say #quot;hi#quot; #lt;b#gt;#amp;#lt;/b#gt;"
        );
        assert_eq!(escape("a|b `c` #d"), "a#124;b #96;c#96; #35;d");
        assert_eq!(escape("one\ntwo\u{7}"), "one<br/>two");
        assert_eq!(escape("/tmp/x [1] (y) {z}"), "/tmp/x [1] (y) {z}");
    }

    #[test]
    fn ids_come_from_the_key_not_the_order() {
        let mut one = Flowchart::new("LR");
        let a = one.node("sha-a", "A");
        one.node("sha-b", "B");
        let mut two = Flowchart::new("LR");
        two.node("sha-b", "B");
        assert_eq!(two.node("sha-a", "A"), a);
        // The same key again is the same node.
        assert_eq!(one.node("sha-a", "other"), a);
        assert_eq!(one.render().matches('[').count(), 2);
    }

    #[test]
    fn a_flowchart_renders_nodes_then_labelled_edges() {
        let mut chart = Flowchart::new("LR");
        let a = chart.node("a", "dropper \"x\"");
        let b = chart.node("b", "payload");
        chart.edge("a", "b", Some("dropped ×2 | executed"));
        chart.edge("b", "a", None);
        chart.edge("a", "missing", None);
        assert_eq!(
            chart.render(),
            format!(
                "flowchart LR\n    {a}[\"dropper #quot;x#quot;\"]\n    {b}[\"payload\"]\n    \
                 {a} -->|\"dropped ×2 #124; executed\"| {b}\n    {b} --> {a}\n"
            )
        );
    }

    #[test]
    fn a_tree_points_each_parent_at_its_children() {
        let node = |key: &str, label: &str, parent: Option<&str>| TreeNode {
            key: key.into(),
            label: label.into(),
            parent: parent.map(str::to_owned),
        };
        let text = tree(&[
            node("1", "init", None),
            node("2", "sh", Some("1")),
            node("3", "ls", Some("2")),
            node("4", "orphan", Some("99")),
        ]);
        assert!(text.starts_with("flowchart TD\n"));
        assert_eq!(text.matches(" --> ").count(), 2, "{text}");
        assert!(text.contains("[\"orphan\"]"));
    }
}
