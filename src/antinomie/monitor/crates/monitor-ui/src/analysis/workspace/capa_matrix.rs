// SPDX-License-Identifier: GPL-3.0-only
//! The Capa Matrix: capa's capabilities arranged by ATT&CK tactic or MBC
//! objective, with the capabilities behind a selected technique below.
use super::*;
use std::collections::BTreeMap;

/// Enterprise ATT&CK tactics in matrix order; others follow by name.
const TACTICS: &[&str] = &[
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];

#[derive(Default)]
pub(in crate::analysis) struct CapaState {
    /// Show the MBC matrix instead of ATT&CK.
    mbc: bool,
    /// Show capa's capabilities as a table instead of a matrix.
    pub(super) table: bool,
    selected: Option<(String, String)>,
}

/// One cell of the matrix: a technique and the capabilities that map to it.
struct Technique<'a> {
    label: String,
    capabilities: Vec<&'a str>,
}

/// "Tactic::Technique::Sub-technique [ID]" as (tactic, "Technique / Sub [ID]").
fn split(mapping: &str) -> (String, String) {
    let (path, id) = match mapping.rsplit_once(" [") {
        Some((path, id)) => (path, format!(" [{}", id)),
        None => (mapping, String::new()),
    };
    let mut parts = path.split("::");
    let tactic = parts.next().unwrap_or_default().trim().to_owned();
    let technique: Vec<_> = parts.map(str::trim).collect();
    let technique = if technique.is_empty() {
        "(tactic only)".to_owned()
    } else {
        technique.join(" / ")
    };
    (tactic, format!("{technique}{id}"))
}

fn matrix(section: &AnalysisSection, mbc: bool) -> Vec<(String, Vec<Technique<'_>>)> {
    let mut columns: BTreeMap<String, BTreeMap<String, Vec<&str>>> = BTreeMap::new();
    for entry in &section.entries {
        let Some(AnalysisData::Capability {
            name,
            attack,
            mbc: behaviors,
            ..
        }) = entry.record.as_ref().map(|record| &record.data)
        else {
            continue;
        };
        for mapping in if mbc { behaviors } else { attack } {
            let (tactic, technique) = split(mapping);
            columns
                .entry(tactic)
                .or_default()
                .entry(technique)
                .or_default()
                .push(name);
        }
    }
    let mut columns: Vec<_> = columns
        .into_iter()
        .map(|(tactic, techniques)| {
            let techniques = techniques
                .into_iter()
                .map(|(label, mut capabilities)| {
                    capabilities.sort_unstable();
                    capabilities.dedup();
                    Technique {
                        label,
                        capabilities,
                    }
                })
                .collect();
            (tactic, techniques)
        })
        .collect();
    let rank = |tactic: &str| {
        TACTICS
            .iter()
            .position(|known| known.eq_ignore_ascii_case(tactic))
            .unwrap_or(TACTICS.len())
    };
    columns.sort_by(|(left, _), (right, _)| {
        rank(left).cmp(&rank(right)).then_with(|| left.cmp(right))
    });
    columns
}

pub(super) fn toggle(ui: &mut egui::Ui, state: &mut CapaState) {
    use crate::widgets::{tab, tab_row, TabItem};
    tab_row(ui, |ui| {
        let attack = TabItem::new(format!("{} ATT&CK", egui_phosphor::regular::GRID_FOUR));
        if tab(ui, !state.table && !state.mbc, &attack).clicked() {
            state.table = false;
            state.mbc = false;
        }
        let mbc = TabItem::new(format!("{} MBC", egui_phosphor::regular::GRID_FOUR));
        if tab(ui, !state.table && state.mbc, &mbc).clicked() {
            state.table = false;
            state.mbc = true;
        }
        let table = TabItem::new(format!("{} Table", egui_phosphor::regular::TABLE));
        if tab(ui, state.table, &table).clicked() {
            state.table = true;
        }
    });
}

pub(super) fn show(ui: &mut egui::Ui, section: &AnalysisSection, state: &mut CapaState) {
    toggle(ui, state);
    ui.add(egui::Label::new(egui::RichText::new(&section.summary).weak()).wrap());
    let columns = matrix(section, state.mbc);
    if columns.is_empty() {
        ui.label(if state.mbc {
            "No capability maps to a Malware Behavior Catalog behavior."
        } else {
            "No capability maps to an ATT&CK technique."
        });
    }
    if state.selected.as_ref().is_some_and(|(tactic, label)| {
        !columns
            .iter()
            .any(|(t, cells)| t == tactic && cells.iter().any(|cell| &cell.label == label))
    }) {
        state.selected = None;
    }
    let height = (ui.available_height() * 0.6).max(160.0);
    if !columns.is_empty() {
        egui::ScrollArea::both()
            .id_salt(("capa-matrix", state.mbc))
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    for (tactic, techniques) in &columns {
                        ui.allocate_ui_with_layout(
                            egui::vec2(210.0, 0.0),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                ui.set_width(210.0);
                                egui::Frame::group(ui.style()).show(ui, |ui| {
                                    ui.set_width(196.0);
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(tactic)
                                                .strong()
                                                .color(crate::theme::heading()),
                                        )
                                        .wrap(),
                                    );
                                    ui.weak(format!(
                                        "{} {}",
                                        techniques.len(),
                                        if techniques.len() == 1 {
                                            "technique"
                                        } else {
                                            "techniques"
                                        }
                                    ));
                                    ui.separator();
                                    for technique in techniques {
                                        let key = (tactic.clone(), technique.label.clone());
                                        let selected = state.selected.as_ref() == Some(&key);
                                        let text = format!(
                                            "{} ({})",
                                            technique.label,
                                            technique.capabilities.len()
                                        );
                                        let response = ui.add(
                                            egui::Button::new(egui::RichText::new(text))
                                                .selected(selected)
                                                .wrap(),
                                        );
                                        let response = response
                                            .on_hover_text(technique.capabilities.join("\n"));
                                        if response.clicked() {
                                            state.selected = (!selected).then_some(key);
                                        }
                                    }
                                });
                            },
                        );
                    }
                });
            });
        ui.separator();
    }
    let (heading, names): (String, Vec<&str>) = match &state.selected {
        Some((tactic, label)) => (
            format!("{tactic} › {label}"),
            columns
                .iter()
                .filter(|(t, _)| t == tactic)
                .flat_map(|(_, cells)| cells.iter().filter(|cell| &cell.label == label))
                .flat_map(|cell| cell.capabilities.iter().copied())
                .collect(),
        ),
        None => (
            if columns.is_empty() {
                "All capabilities".into()
            } else {
                "All capabilities — select a technique to narrow the list".into()
            },
            section
                .entries
                .iter()
                .filter_map(
                    |entry| match entry.record.as_ref().map(|record| &record.data) {
                        Some(AnalysisData::Capability { name, .. }) => Some(name.as_str()),
                        _ => None,
                    },
                )
                .collect(),
        ),
    };
    ui.strong(heading);
    egui::ScrollArea::vertical()
        .id_salt("capa-capabilities")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("capa-capability-rows")
                .striped(true)
                .num_columns(2)
                .show(ui, |ui| {
                    for name in names {
                        let namespace = section
                            .entries
                            .iter()
                            .find_map(|entry| {
                                match entry.record.as_ref().map(|record| &record.data) {
                                    Some(AnalysisData::Capability {
                                        name: n, namespace, ..
                                    }) if n == name => Some(namespace.as_str()),
                                    _ => None,
                                }
                            })
                            .unwrap_or("");
                        ui.label(name);
                        ui.weak(namespace);
                        ui.end_row();
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{AnalysisRecord, AnalysisSectionState};

    fn capability(name: &str, attack: &[&str], mbc: &[&str]) -> AnalysisEntry {
        AnalysisEntry {
            label: name.into(),
            value: String::new(),
            offset: None,
            record: Some(AnalysisRecord {
                revision: 1,
                id: 1,
                location: None,
                data: AnalysisData::Capability {
                    name: name.into(),
                    namespace: "host-interaction".into(),
                    attack: attack.iter().map(|s| (*s).to_owned()).collect(),
                    mbc: mbc.iter().map(|s| (*s).to_owned()).collect(),
                },
            }),
        }
    }

    #[test]
    fn capabilities_group_by_tactic_in_matrix_order() {
        let section = AnalysisSection {
            kind: AnalysisKind::Capabilities,
            state: AnalysisSectionState::Complete,
            summary: String::new(),
            tools: Vec::new(),
            listing: None,
            entries: vec![
                capability("encode data using XOR", &["Defense Evasion::Obfuscated Files or Information [T1027]"], &["Defense Evasion::Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]"]),
                capability("create process on Linux", &["Execution::Command and Scripting Interpreter::Unix Shell [T1059.004]"], &[]),
                capability("check for debugger", &["Defense Evasion::Debugger Evasion [T1622]"], &[]),
                capability("xor again", &["Defense Evasion::Obfuscated Files or Information [T1027]"], &[]),
            ], limits: Vec::new(),
        };
        let columns = matrix(&section, false);
        let tactics: Vec<_> = columns.iter().map(|(tactic, _)| tactic.as_str()).collect();
        assert_eq!(tactics, ["Execution", "Defense Evasion"]);
        let evasion = &columns[1].1;
        assert_eq!(evasion[1].label, "Obfuscated Files or Information [T1027]");
        assert_eq!(
            evasion[1].capabilities,
            ["encode data using XOR", "xor again"]
        );
        assert_eq!(
            columns[0].1[0].label,
            "Command and Scripting Interpreter / Unix Shell [T1059.004]"
        );
        let mbc = matrix(&section, true);
        assert_eq!(mbc.len(), 1);
        assert_eq!(
            mbc[0].1[0].label,
            "Obfuscated Files or Information / Encoding-Standard Algorithm [E1027.m02]"
        );
    }

    #[test]
    fn the_matrix_toggle_is_a_thin_bordered_tab_row_that_switches_views() {
        use crate::table_sort::testing;
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let state = std::cell::RefCell::new(CapaState::default());
        let mut show = |ui: &mut egui::Ui| toggle(ui, &mut state.borrow_mut());
        testing::click(
            &ctx,
            &format!("{} MBC", egui_phosphor::regular::GRID_FOUR),
            &mut show,
        );
        assert!(state.borrow().mbc && !state.borrow().table);
        testing::click(
            &ctx,
            &format!("{} Table", egui_phosphor::regular::TABLE),
            &mut show,
        );
        assert!(state.borrow().table);
    }
}
