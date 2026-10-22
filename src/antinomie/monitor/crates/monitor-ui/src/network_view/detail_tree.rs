// SPDX-License-Identifier: GPL-3.0-only
//! The packet details tree exactly as TShark printed it, with expand and
//! collapse. The viewer only draws it: every line, nesting level and byte
//! range comes from TShark.
use super::*;
use antinomie_monitor_core::packet_filter::{DetailNode, PacketTree};

/// The key a line's expanded state is remembered under: its kind of node
/// (`ip.flags`), so a line stays open in the next packet too.
fn key(node: &DetailNode) -> &str {
    if node.name.is_empty() {
        &node.label
    } else {
        &node.name
    }
}

/// Whether the line at `at` is shown expanded: the user's choice for its kind
/// of line, else only the last protocol (the innermost layer, which is what
/// the packet is about) is open, as in Wireshark's fresh details pane.
fn is_open(tree: &PacketTree, at: usize, open: &HashMap<String, bool>) -> bool {
    let node = &tree.nodes[at];
    open.get(key(node)).copied().unwrap_or_else(|| {
        node.depth == 0 && tree.nodes[at + 1..].iter().all(|later| later.depth != 0)
    })
}

/// Indices of the lines shown: a collapsed line hides its descendants.
pub(super) fn visible(tree: &PacketTree, open: &HashMap<String, bool>) -> Vec<usize> {
    let mut rows = Vec::new();
    let mut at = 0;
    while at < tree.nodes.len() {
        rows.push(at);
        let node = &tree.nodes[at];
        at = if node.has_children(at) && !is_open(tree, at, open) {
            node.end
        } else {
            at + 1
        };
    }
    rows
}

/// Open or close every line that has lines below it.
pub(super) fn set_all(tree: &PacketTree, open: &mut HashMap<String, bool>, value: bool) {
    for (at, node) in tree.nodes.iter().enumerate() {
        if node.has_children(at) {
            open.insert(key(node).to_owned(), value);
        }
    }
}

/// The lines of `tree` with carets for the ones that nest others; a click
/// chooses a line (`chosen`). Returns the byte range under the pointer.
pub(super) fn detail_tree(
    ui: &mut egui::Ui,
    tree: &PacketTree,
    open: &mut HashMap<String, bool>,
    chosen: &mut Option<usize>,
    mono: &egui::FontId,
) -> Option<std::ops::Range<usize>> {
    let mut hovered = None;
    let font_size = mono.size + 1.0;
    let font = egui::FontId::proportional(font_size);
    let rows = visible(tree, open);
    let depths: Vec<_> = rows
        .iter()
        .map(|&at| usize::from(tree.nodes[at].depth))
        .collect();
    let branches = crate::tree_lines::prefixes(&depths);
    let char_width = crate::tree_lines::char_width(ui, mono);
    // Dense rows, as in Wireshark's details tree.
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.spacing_mut().button_padding.y = 1.0;
    let row_height = theme::row_height(font_size) - 2.0;
    ui.spacing_mut().interact_size.y = row_height;
    let mut toggled = None;
    egui::ScrollArea::both()
        .id_salt("packet_tree_scroll")
        .auto_shrink([false, false])
        .min_scrolled_height(row_height * 3.0)
        .show_rows(ui, row_height, rows.len(), |ui, range| {
            for shown in range {
                let at = rows[shown];
                let node = &tree.nodes[at];
                crate::tree_lines::row(ui, &branches[shown], char_width, |ui| {
                    let caret = if !node.has_children(at) {
                        // The width of a caret keeps the labels aligned.
                        ui.label(
                            RichText::new(egui_phosphor::regular::CARET_RIGHT)
                                .color(egui::Color32::TRANSPARENT),
                        );
                        None
                    } else {
                        let is_open = is_open(tree, at, open);
                        let icon = if is_open {
                            egui_phosphor::regular::CARET_DOWN
                        } else {
                            egui_phosphor::regular::CARET_RIGHT
                        };
                        Some((
                            is_open,
                            ui.add(
                                egui::Label::new(RichText::new(icon).color(theme::muted()))
                                    .selectable(false)
                                    .sense(egui::Sense::click()),
                            )
                            .on_hover_cursor(egui::CursorIcon::PointingHand),
                        ))
                    };
                    if let Some((was_open, response)) = caret {
                        if response.clicked() {
                            toggled = Some((key(node).to_owned(), !was_open));
                        }
                    }
                    let color = if node.depth == 0 {
                        theme::heading()
                    } else {
                        theme::text()
                    };
                    let mut job = egui::text::LayoutJob::default();
                    job.append(&node.label, 0.0, text_format(font.clone(), color));
                    let response = ui.selectable_label(*chosen == Some(at), job);
                    if response.clicked() {
                        *chosen = Some(at);
                    }
                    if response.double_clicked() && node.has_children(at) {
                        toggled = Some((key(node).to_owned(), !is_open(tree, at, open)));
                    }
                    if response.hovered() {
                        hovered = node.range();
                    }
                });
            }
        });
    if let Some((name, value)) = toggled {
        open.insert(name, value);
    }
    hovered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(depth: u8, name: &str, end: usize) -> DetailNode {
        DetailNode {
            depth,
            label: format!("line {name}"),
            name: name.into(),
            start: 0,
            len: 0,
            end,
        }
    }

    fn tree() -> PacketTree {
        // frame            0
        //   frame.len      1
        // ip               2
        //   ip.flags       3
        //     ip.flags.df  4
        //   ip.ttl         5
        PacketTree {
            nodes: vec![
                node(0, "frame", 2),
                node(1, "frame.len", 2),
                node(0, "ip", 6),
                node(1, "ip.flags", 5),
                node(2, "ip.flags.df", 5),
                node(1, "ip.ttl", 6),
            ],
            cut: false,
        }
    }

    #[test]
    fn only_the_last_protocol_starts_open() {
        let rows = visible(&tree(), &HashMap::new());
        assert_eq!(rows, [0, 2, 3, 5]);
    }

    #[test]
    fn a_collapsed_line_hides_its_whole_subtree_and_the_choice_is_per_kind() {
        let mut open = HashMap::new();
        open.insert("ip".to_owned(), false);
        assert_eq!(visible(&tree(), &open), [0, 2]);
        open.insert("ip".to_owned(), true);
        open.insert("frame".to_owned(), true);
        open.insert("ip.flags".to_owned(), true);
        assert_eq!(visible(&tree(), &open), [0, 1, 2, 3, 4, 5]);
        set_all(&tree(), &mut open, false);
        assert_eq!(visible(&tree(), &open), [0, 2]);
        set_all(&tree(), &mut open, true);
        assert_eq!(visible(&tree(), &open), [0, 1, 2, 3, 4, 5]);
    }
}
