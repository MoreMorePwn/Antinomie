// SPDX-License-Identifier: GPL-3.0-only
//! Folding a crowd of children: a sample that writes hundreds of files gives
//! a parent hundreds of children, which no zoom makes readable. A parent with
//! more than [`CROWD`] children keeps the [`SHOWN`] that say most and counts
//! the rest in its `+N` badge, the badge every node already has for
//! neighbours left out; expanding the node shows them all, `−` folds them
//! again. Pure, so it can be tested without egui.
use antinomie_monitor_core::samples::{EdgeKind, LineageGraph, NodeKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// More children than this fold.
pub(super) const CROWD: usize = 24;
/// How many children a folded parent keeps.
pub(super) const SHOWN: usize = 16;

/// Fold every crowd of children whose parent is not in `expanded`; nodes
/// left without a path to `sample` go with them.
pub(super) fn fold(graph: &mut LineageGraph, expanded: &BTreeSet<String>, sample: &str) {
    let level: BTreeMap<&str, i32> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.level))
        .collect();
    let mut has_children: BTreeSet<&str> = BTreeSet::new();
    for edge in &graph.edges {
        if level.get(edge.to.as_str()) > level.get(edge.from.as_str()) {
            has_children.insert(edge.from.as_str());
        }
    }
    let order: BTreeMap<&str, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect();
    let mut folded: BTreeMap<String, usize> = BTreeMap::new();
    let mut gone: BTreeSet<String> = BTreeSet::new();
    for parent in &graph.nodes {
        if expanded.contains(&parent.id) {
            continue;
        }
        let mut children: Vec<(&str, u8)> = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.from == parent.id
                    && level
                        .get(edge.to.as_str())
                        .is_some_and(|l| *l > parent.level)
            })
            .map(|edge| {
                let node = graph.nodes.iter().find(|node| node.id == edge.to);
                let rank = match node.map(|node| &node.kind) {
                    Some(NodeKind::Library { .. }) => 0,
                    Some(NodeKind::Command) => 1,
                    _ if edge.kinds.contains_key(&EdgeKind::Executed)
                        || edge.kinds.contains_key(&EdgeKind::Downloaded) =>
                    {
                        2
                    }
                    _ if has_children.contains(edge.to.as_str()) => 3,
                    _ => 4,
                };
                (edge.to.as_str(), rank)
            })
            .collect();
        children.sort_by_key(|(id, _)| *id);
        children.dedup_by_key(|(id, _)| *id);
        if children.len() <= CROWD {
            continue;
        }
        children.sort_by_key(|(id, rank)| (*rank, order.get(id).copied().unwrap_or(usize::MAX)));
        let hidden = &children[SHOWN..];
        folded.insert(parent.id.clone(), hidden.len());
        gone.extend(hidden.iter().map(|(id, _)| (*id).to_owned()));
    }
    if gone.is_empty() {
        return;
    }
    gone.remove(sample);
    graph
        .edges
        .retain(|edge| !gone.contains(&edge.from) && !gone.contains(&edge.to));
    // Keep what still reaches the sample, either way along the edges.
    let mut seen: BTreeSet<String> = BTreeSet::from([sample.to_owned()]);
    let mut queue = VecDeque::from([sample.to_owned()]);
    while let Some(id) = queue.pop_front() {
        for edge in &graph.edges {
            let next = if edge.from == id {
                &edge.to
            } else if edge.to == id {
                &edge.from
            } else {
                continue;
            };
            if seen.insert(next.clone()) {
                queue.push_back(next.clone());
            }
        }
    }
    graph.nodes.retain(|node| seen.contains(&node.id));
    graph
        .edges
        .retain(|edge| seen.contains(&edge.from) && seen.contains(&edge.to));
    for node in &mut graph.nodes {
        if let Some(count) = folded.get(&node.id) {
            node.hidden_children += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::{LineageEdge, LineageNode};

    fn node(id: &str, level: i32, kind: NodeKind) -> LineageNode {
        LineageNode {
            id: id.into(),
            kind,
            label: id.into(),
            path: String::new(),
            sha256: String::new(),
            hash_note: String::new(),
            level,
            hidden_parents: 0,
            hidden_children: 0,
        }
    }

    fn edge(from: &str, to: &str, kind: EdgeKind) -> LineageEdge {
        LineageEdge {
            from: from.into(),
            to: to.into(),
            kinds: BTreeMap::from([(kind, 1)]),
            runs: vec![1],
            per_run: BTreeMap::new(),
        }
    }

    /// The sample wrote 300 files, ran one of them, and one written file
    /// has a child of its own.
    fn crowded() -> LineageGraph {
        let mut nodes = vec![node("s", 0, NodeKind::Sample)];
        let mut edges = Vec::new();
        for i in 0..300 {
            let id = format!("d{i:03}");
            nodes.push(node(&id, 1, NodeKind::Lost));
            edges.push(edge("s", &id, EdgeKind::Dropped));
        }
        nodes.push(node("run-me", 1, NodeKind::Captured));
        edges.push(edge("s", "run-me", EdgeKind::Executed));
        nodes.push(node("grandchild", 2, NodeKind::Lost));
        edges.push(edge("d299", "grandchild", EdgeKind::Dropped));
        LineageGraph {
            nodes,
            edges,
            ..LineageGraph::default()
        }
    }

    #[test]
    fn a_crowd_of_children_folds_into_the_parents_badge_keeping_what_says_most() {
        let mut graph = crowded();
        fold(&mut graph, &BTreeSet::new(), "s");
        let ids: BTreeSet<&str> = graph.nodes.iter().map(|node| node.id.as_str()).collect();
        // The sample, its 16 kept children and the grandchild of a kept one.
        assert_eq!(graph.nodes.len(), 1 + SHOWN + 1, "{ids:?}");
        assert!(ids.contains("run-me"), "the executed file is kept first");
        assert!(
            ids.contains("d299"),
            "a file with a child of its own is kept"
        );
        assert!(ids.contains("grandchild"));
        assert!(ids.contains("d000"), "then the first in the graph's order");
        assert!(!ids.contains("d200"));
        let sample = graph.nodes.iter().find(|node| node.id == "s").unwrap();
        assert_eq!(sample.hidden_children, 301 - SHOWN);
        assert!(graph
            .edges
            .iter()
            .all(|edge| ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str())));
    }

    #[test]
    fn an_expanded_parent_or_a_small_family_shows_every_child() {
        let mut graph = crowded();
        fold(&mut graph, &BTreeSet::from(["s".to_owned()]), "s");
        assert_eq!(graph.nodes.len(), crowded().nodes.len());
        let mut small = crowded();
        small.nodes.truncate(1 + CROWD);
        small.edges.truncate(CROWD);
        let before = small.clone();
        fold(&mut small, &BTreeSet::new(), "s");
        assert_eq!(small, before);
    }
}
