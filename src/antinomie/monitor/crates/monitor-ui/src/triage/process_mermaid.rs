// SPDX-License-Identifier: GPL-3.0-only
//! The process tree as Mermaid text, for "Copy as Mermaid" beside the tree.
//! A task's node id is made from its pid and recording cookie, so the same
//! tree gives the same ids however the rows are filtered or folded.
use super::*;

/// The tasks in `nodes` as a top-down Mermaid flowchart, a parent pointing at
/// each child it started. A task whose parent is not in the trace is a root.
pub(super) fn process_tree_mermaid(nodes: &[ProcessNode]) -> String {
    let key = |pid: u32, cookie: u64| format!("{pid}:{cookie}");
    let tree: Vec<crate::mermaid::TreeNode> = nodes
        .iter()
        .map(|node| crate::mermaid::TreeNode {
            key: key(node.pid, node.cookie),
            label: format!(
                "{}\n{}",
                if node.comm.is_empty() {
                    "?"
                } else {
                    &node.comm
                },
                process_tree::process_label(node)
            ),
            parent: node.parent.map(|parent| key(parent.pid, parent.cookie)),
        })
        .collect();
    crate::mermaid::tree(&tree)
}

/// The small "Copy as Mermaid" button above the Process tree.
pub(super) fn copy_button(ui: &mut egui::Ui, nodes: &[ProcessNode]) {
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            crate::mermaid::button(ui, || process_tree_mermaid(nodes));
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::rules::tests::support::exec;
    use crate::triage::tests::call;

    #[test]
    fn each_task_is_a_node_under_its_parent_with_a_stable_id() {
        let as_task = |mut row: InvocationSummary, tid: u32, cookie: u64| {
            row.task_cookie = cookie;
            for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
                event.pid = 7;
                event.tid = tid;
                event.task_cookie = cookie;
            }
            row
        };
        let calls = vec![
            as_task(exec(7, "/tmp/kaiji", &["kaiji", "-x"]), 7, 70),
            as_task(call(7, 202, "futex", 0), 8, 78),
        ];
        let nodes = process_nodes(&calls);
        let text = process_tree_mermaid(&nodes);
        assert!(text.starts_with("flowchart TD\n"), "{text}");
        assert_eq!(text.matches("[\"").count(), 2, "{text}");
        assert_eq!(text.matches(" --> ").count(), 1, "{text}");
        assert!(text.contains("PID 7"), "{text}");
        assert!(text.contains("thread"), "{text}");
        assert_eq!(text, process_tree_mermaid(&nodes));
    }

    #[test]
    fn labels_with_markup_are_escaped() {
        let mut nodes = process_nodes(&[exec(9, "/tmp/a\"b<c>", &["x"])]);
        nodes[0].comm = "a\"b<c>".into();
        let text = process_tree_mermaid(&nodes);
        assert!(text.contains("a#quot;b#lt;c#gt;"), "{text}");
        assert!(!text.contains("<c>"));
    }
}
