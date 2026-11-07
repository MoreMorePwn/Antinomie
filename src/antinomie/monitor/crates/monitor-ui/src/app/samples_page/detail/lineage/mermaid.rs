// SPDX-License-Identifier: GPL-3.0-only
//! The lineage graph as Mermaid text: a left-to-right flowchart, each node
//! keyed by its SHA-256 (or its `cmd:` or `lost:` id), each edge labelled
//! with what happened, the way the picture labels it.
use antinomie_monitor_core::samples::{LineageGraph, NodeKind};

/// `graph` as a Mermaid flowchart.
pub(super) fn of(graph: &LineageGraph) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    for node in &graph.nodes {
        let kind = match &node.kind {
            NodeKind::Sample => "sample",
            NodeKind::Library { .. } => "library",
            NodeKind::Captured => "captured file",
            NodeKind::Lost => "file without a hash",
            NodeKind::Command => "command",
            NodeKind::System => "system program",
        };
        let label = if node.label.is_empty() {
            &node.path
        } else {
            &node.label
        };
        chart.node(&node.id, &format!("{label}\n({kind})"));
    }
    for edge in &graph.edges {
        let kinds = edge
            .kinds
            .iter()
            .map(|(kind, count)| {
                if *count > 1 {
                    format!("{} ×{count}", kind.label())
                } else {
                    kind.label().to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        chart.edge(&edge.from, &edge.to, Some(&kinds));
    }
    chart.render()
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::{EdgeKind, LineageEdge, LineageNode};

    fn node(id: &str, label: &str, kind: NodeKind, level: i32) -> LineageNode {
        LineageNode {
            id: id.into(),
            kind,
            label: label.into(),
            path: String::new(),
            sha256: String::new(),
            hash_note: String::new(),
            level,
            hidden_parents: 0,
            hidden_children: 0,
        }
    }

    #[test]
    fn the_graph_is_a_flowchart_with_labelled_edges_and_escaped_names() {
        let graph = LineageGraph {
            nodes: vec![
                node("aa", "dropper \"v2\"", NodeKind::Sample, 0),
                node("bb", "payload.bin", NodeKind::Captured, 1),
            ],
            edges: vec![LineageEdge {
                from: "aa".into(),
                to: "bb".into(),
                kinds: [(EdgeKind::Dropped, 2), (EdgeKind::Executed, 1)].into(),
                runs: vec![1],
                per_run: Default::default(),
            }],
            ..Default::default()
        };
        let text = of(&graph);
        assert!(text.starts_with("flowchart LR\n"), "{text}");
        assert!(
            text.contains("dropper #quot;v2#quot;<br/>(sample)"),
            "{text}"
        );
        assert!(text.contains("payload.bin<br/>(captured file)"), "{text}");
        assert!(text.contains("-->|\"dropped ×2, executed\"|"), "{text}");
        // Same graph, same text.
        assert_eq!(text, of(&graph));
    }
}
