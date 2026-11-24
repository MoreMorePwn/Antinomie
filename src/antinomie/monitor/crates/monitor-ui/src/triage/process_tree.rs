// SPDX-License-Identifier: GPL-3.0-only
//! The process tree table. The tree is built in `antinomie_triage::process_tree`.
use super::*;

pub(super) use antinomie_triage::process_tree::*;

pub fn process_tree_nodes(
    ui: &mut egui::Ui,
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    suspicious: &Suspicious,
) {
    process_tree_cached(ui, nodes, clock, suspicious, None);
}

/// [`process_tree_nodes`] with the rows of the index kept in `cache` (see
/// `table_cache`); `None` makes them every frame.
pub(super) fn process_tree_cached(
    ui: &mut egui::Ui,
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    suspicious: &Suspicious,
    mut cache: Option<&mut super::table_cache::ShownCache>,
) {
    // Thread tasks fold into "+N threads" on their process once there are many
    // of them; the chip lists them. The user's choice is kept for the session.
    let thread_count = nodes.iter().filter(|node| node.thread).count();
    let thread_id = egui::Id::new("triage-process-threads");
    // One row: Show threads on the left, Copy as Mermaid on the right, both
    // centred on the row's middle.
    ui.horizontal(|ui| {
        if thread_count > 0 {
            let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
            let expanded = stored.unwrap_or(thread_count < THREAD_FOLD);
            let label = format!("Show threads ({thread_count})");
            if crate::widgets::hover_help(ui, "Thread tasks of a process, one per recorded thread. Off, they fold into +N threads on their process.", |ui| crate::widgets::toggle_chip(ui, &label, expanded, None))
                .clicked()
            {
                ui.ctx().data_mut(|data| data.insert_temp(thread_id, !expanded));
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            super::process_mermaid::copy_button(ui, nodes);
        });
    });
    let expanded = thread_count == 0 || {
        let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
        stored.unwrap_or(thread_count < THREAD_FOLD)
    };
    // The rows of the process table: every process, or with the threads folded
    // into their process; one set per index and choice.
    let build = || {
        let mut rows = process_rows(nodes, clock, suspicious);
        if !expanded {
            let mut folded: std::collections::BTreeMap<(u32, u64), usize> = Default::default();
            for node in nodes.iter().filter(|node| node.thread) {
                if let Some(parent) = node.parent {
                    *folded.entry((parent.pid, parent.cookie)).or_default() += 1;
                }
            }
            for (row, node) in rows.iter_mut().zip(nodes) {
                if let Some(count) = folded.get(&(node.pid, node.cookie)) {
                    row[0].text.push_str(&format!("  +{count} threads"));
                }
            }
            let keep: Vec<bool> = nodes.iter().map(|node| !node.thread).collect();
            let mut keep = keep.into_iter();
            rows.retain(|_| keep.next().unwrap_or(true));
        }
        std::sync::Arc::new(rows)
    };
    let rows = match cache.as_deref_mut() {
        Some(cache) => match cache.process(clock, expanded) {
            Some(kept) => std::sync::Arc::clone(kept),
            None => {
                let rows = build();
                cache.keep_process(clock, expanded, std::sync::Arc::clone(&rows));
                rows
            }
        },
        None => build(),
    };
    ui.ctx().data_mut(|data| {
        data.insert_temp(
            egui::Id::new(("triage-filter-target", "triage-process")),
            ui.id().with(("table-filter", "triage-process")),
        )
    });
    let compiled = query::table_filter(
        ui,
        "triage-process",
        "process.exe contains bash",
        PROCESS_FIELDS,
        &[],
    );
    let total = rows.len();
    let kept: Vec<bool> = rows
        .iter()
        .map(|row| compiled.keep_table(&row[0].values))
        .collect();
    // Without a filter every row stays and the kept rows are used as they are.
    let all_kept = kept.iter().all(|keep| *keep);
    let narrowed: Vec<Vec<Cell>>;
    let filtered: &[Vec<Cell>] = if all_kept {
        &rows
    } else {
        narrowed = rows
            .iter()
            .zip(&kept)
            .filter(|(_, keep)| **keep)
            .map(|(row, _)| row.clone())
            .collect();
        &narrowed
    };
    let group = antinomie_monitor_core::analysis::detection::group_digits;
    ui.colored_label(
        theme::muted(),
        format!(
            "{} / {} rows",
            group(filtered.len() as u64),
            group(total as u64)
        ),
    );
    // The tree is of the rows that are left: a filter leaves gaps, not stale
    // branches.
    let depths = filtered
        .iter()
        .map(|row| files::number(&row[0].values, "process.depth").map_or(0, |depth| depth as usize))
        .collect::<Vec<_>>();
    let stamp = cache.as_deref().filter(|_| all_kept).and_then(|cache| {
        cache.stamp(
            if expanded {
                "process"
            } else {
                "process-folded"
            },
            clock,
        )
    });
    sorting::same_rows(ui.ctx(), "triage-process", stamp);
    table_with(
        ui,
        "triage-process",
        &PROCESS_HEADERS,
        filtered,
        Some(&crate::tree_lines::prefixes(&depths)),
    );
}
