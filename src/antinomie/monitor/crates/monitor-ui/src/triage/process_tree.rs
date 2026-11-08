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
    let mut rows = process_rows(nodes, clock, suspicious);
    // Thread tasks fold into "+N threads" on their process once there are many
    // of them; the chip lists them. The user's choice is kept for the session.
    let thread_count = nodes.iter().filter(|node| node.thread).count();
    let thread_id = egui::Id::new("triage-process-threads");
    let expanded = if thread_count == 0 {
        true
    } else {
        let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
        let expanded = stored.unwrap_or(thread_count < THREAD_FOLD);
        ui.horizontal(|ui| {
            let label = format!("Show threads ({thread_count})");
            if crate::widgets::toggle_chip(ui, &label, expanded, None)
                .on_hover_text(
                    "Thread tasks of a process, one per recorded thread. Off, they fold into +N threads on their process.",
                )
                .clicked()
            {
                ui.ctx().data_mut(|data| data.insert_temp(thread_id, !expanded));
            }
        });
        let stored: Option<bool> = ui.ctx().data(|data| data.get_temp(thread_id));
        stored.unwrap_or(thread_count < THREAD_FOLD)
    };
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
    let filtered = rows
        .into_iter()
        .filter(|row| compiled.keep_table(&row[0].values))
        .collect::<Vec<_>>();
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
    table_with(
        ui,
        "triage-process",
        &PROCESS_HEADERS,
        &filtered,
        Some(&crate::tree_lines::prefixes(&depths)),
    );
}
