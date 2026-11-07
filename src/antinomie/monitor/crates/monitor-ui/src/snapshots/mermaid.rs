// SPDX-License-Identifier: GPL-3.0-only
//! The snapshot graph as Mermaid text: the base image at the root, each
//! checkpoint under its parent, and "You are here" under the checkpoint the
//! next snapshot attaches to.
use super::mode_label;
use antinomie_monitor_core::VmSnapshotTree;

/// `tree` as a left-to-right Mermaid flowchart.
pub(super) fn of(tree: &VmSnapshotTree) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    chart.node("base", "Base image\nInitial disk");
    for node in &tree.nodes {
        let name = if node.deleted {
            "Hidden checkpoint"
        } else {
            node.name.as_str()
        };
        chart.node(&node.id, &format!("{name}\n{}", mode_label(node.mode)));
    }
    chart.node("here", "You are here\nUnsaved changes");
    for node in &tree.nodes {
        let parent = node
            .parent_id
            .as_deref()
            .filter(|id| *id != node.id && tree.nodes.iter().any(|other| other.id == *id))
            .unwrap_or("base");
        chart.edge(parent, &node.id, None);
    }
    let attach = tree
        .active_parent_id
        .as_deref()
        .filter(|id| tree.nodes.iter().any(|node| node.id == *id))
        .unwrap_or("base");
    chart.edge(attach, "here", None);
    chart.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_has_the_base_every_checkpoint_and_the_you_are_here_node() {
        let tree = super::super::tests::fixture();
        let text = of(&tree);
        assert!(text.starts_with("flowchart LR\n"));
        for name in [
            "Base image",
            "Desktop ready",
            "Before sample",
            "Experiment A",
            "Experiment B",
            "You are here",
        ] {
            assert!(text.contains(name), "{name}: {text}");
        }
        // Base -> desktop -> sample -> A and B, and B -> here.
        assert_eq!(text.matches(" --> ").count(), 5, "{text}");
        assert_eq!(text, of(&tree));
    }
}
