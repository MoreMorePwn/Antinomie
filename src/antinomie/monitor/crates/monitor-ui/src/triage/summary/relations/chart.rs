// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph as Mermaid text, for "Mermaid" in the box.
use super::model::Graph;

/// `graph` as a left-to-right flowchart: a node's id comes from its identity,
/// so the same run gives the same text. `shown` limits it to those nodes.
pub(in crate::triage) fn mermaid(graph: &Graph, shown: &[usize]) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    let key = |at: usize| graph.nodes[at].kind.id();
    let keep: std::collections::HashSet<usize> = shown.iter().copied().collect();
    for &at in shown {
        let node = &graph.nodes[at];
        let mut label = node.label.clone();
        if let Some(tier) = node.tier {
            label.push_str(&format!("\n[{}]", tier.tag().to_uppercase()));
        }
        chart.node(&key(at), &label);
    }
    for edge in &graph.edges {
        if keep.contains(&edge.from) && keep.contains(&edge.to) {
            let label = if edge.count > 1 {
                format!("{} \u{d7}{}", edge.kind.label(), edge.count)
            } else {
                edge.kind.label().to_owned()
            };
            chart.edge(&key(edge.from), &key(edge.to), Some(&label));
        }
    }
    chart.render()
}

#[cfg(test)]
mod tests {
    use super::super::model::tests::fixture;
    use super::*;

    #[test]
    fn mermaid_has_a_node_per_shown_node_and_labelled_edges() {
        let graph = Graph::build(&fixture());
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let text = mermaid(&graph, &all);
        assert!(text.starts_with("flowchart LR\n"), "{text}");
        assert_eq!(text.matches("[\"").count(), graph.nodes.len(), "{text}");
        assert_eq!(text.matches(" -->|").count(), graph.edges.len(), "{text}");
        assert!(!text.contains('\u{26a0}'), "{text}");
        assert!(text.contains("[HIGH]"), "{text}");
        assert!(text.contains("|\"inject\"|"), "{text}");
        assert_eq!(text, mermaid(&graph, &all), "stable");
        // A subset leaves out the edges that lose an end.
        let two = mermaid(&graph, &all[..2]);
        assert_eq!(two.matches("[\"").count(), 2);
        assert!(two.matches("-->|").count() <= 1);
    }
}
