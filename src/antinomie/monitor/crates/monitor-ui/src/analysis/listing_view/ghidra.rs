// SPDX-License-Identifier: GPL-3.0-only
//! The Disassembly tab's two sources: the built-in rows (iced-x86, or objdump
//! for other architectures) and, once it is there, Ghidra's listing with its
//! labels, call and jump targets and cross references. The source line says
//! which one is on screen and for which architecture; an address in a row
//! jumps to its row.
use super::*;
use crate::widgets::{chip, Tone};
use antinomie_monitor_core::{
    analysis::ARCHITECTURE_MARK, AnalysisDisassembly, AnalysisReference, AnalysisReferenceKind,
    AnalysisSectionState,
};

/// The most targets a row shows beside its instruction; the rest are in the
/// hover.
const TARGETS_SHOWN: usize = 2;

/// Name of the tool that made the built-in rows.
fn builtin_name(section: &AnalysisSection) -> String {
    match section.tools.first().map(String::as_str) {
        Some(tool) if tool.starts_with("iced-x86") => "iced-x86".into(),
        Some(tool) if tool.to_ascii_lowercase().contains("objdump") => "objdump".into(),
        Some(tool) => tool.into(),
        None => "Built-in".into(),
    }
}

/// The architecture the built-in rows were made for: what the disassembly
/// wrote into its summary, or else what the Metadata check read.
fn builtin_architecture(report: &AnalysisReport, section: &AnalysisSection) -> Option<String> {
    section
        .summary
        .split_once(ARCHITECTURE_MARK)
        .map(|(_, architecture)| architecture.trim().to_owned())
        .or_else(|| metadata_architecture(report))
}

/// The architecture the Metadata check read, when the report has one.
fn metadata_architecture(report: &AnalysisReport) -> Option<String> {
    let value = |label: &str| {
        report
            .sections
            .iter()
            .filter(|section| section.kind == AnalysisKind::Metadata)
            .flat_map(|section| &section.entries)
            .find(|entry| entry.label == label)
            .map(|entry| entry.value.clone())
    };
    let architecture = value("Architecture")?;
    Some(match (value("Class"), value("Endianness")) {
        (Some(class), Some(endian)) => format!("{architecture} · {class} · {endian}"),
        (Some(class), None) => format!("{architecture} · {class}"),
        _ => architecture,
    })
}

/// "ARM:LE:32:v8 · little-endian · 32-bit".
fn ghidra_architecture(disassembly: &AnalysisDisassembly) -> String {
    format!(
        "{} · {}-endian · {}-bit",
        disassembly.language, disassembly.endian, disassembly.pointer_bits
    )
}

/// Ghidra's listing is still to come: the analysis runs and will start Ghidra
/// (with Decompilation, or alone for the Disassembly check, unless Settings
/// turned that off).
fn ghidra_expected(report: &AnalysisReport) -> bool {
    if !super::super::in_progress(report) || report.ghidra_disassembly().is_some() {
        return false;
    }
    let decompiling = report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Decompilation);
    match decompiling {
        Some(section) => matches!(
            section.state,
            AnalysisSectionState::Pending | AnalysisSectionState::Running
        ),
        None => report.limits.unwrap_or_default().ghidra_disassembly,
    }
}

/// The line above the Disassembly rows: the tool that made them, the
/// architecture, what Ghidra found, and the way to the other source.
pub(super) fn source_bar(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    section: &AnalysisSection,
    state: &mut ListingState,
) {
    let ghidra = report.ghidra_disassembly();
    let builtin = section.listing.is_some();
    ui.horizontal_wrapped(|ui| {
        match ghidra.filter(|_| !state.builtin || !builtin) {
            Some(disassembly) => {
                chip(ui, disassembly.tool.clone(), Tone::Accent)
                    .on_hover_text("These rows are Ghidra's listing of the whole program");
                ui.label(ghidra_architecture(disassembly));
                ui.weak(format!(
                    "{} functions · {} instructions",
                    crate::values::thousands(disassembly.functions),
                    crate::values::thousands(disassembly.instructions)
                ));
                if builtin
                    && ui
                        .small_button(format!("Show {} rows", builtin_name(section)))
                        .on_hover_text("Switch to the built-in disassembler's rows")
                        .clicked()
                {
                    state.builtin = true;
                }
            }
            None => {
                chip(ui, builtin_name(section), Tone::Info)
                    .on_hover_text("The built-in disassembler made these rows");
                if let Some(architecture) = builtin_architecture(report, section) {
                    ui.label(architecture);
                }
                if let Some(disassembly) = ghidra {
                    if ui
                        .small_button(format!("Show {} listing", disassembly.tool))
                        .on_hover_text("Switch to Ghidra's listing with labels and references")
                        .clicked()
                    {
                        state.builtin = false;
                    }
                } else if ghidra_expected(report) {
                    ui.weak(
                        "When the analysis finishes, Ghidra's listing replaces these rows if Ghidra is installed.",
                    );
                }
            }
        }
    });
    if let Some(disassembly) = ghidra.filter(|d| !d.note.is_empty()) {
        ui.add(egui::Label::new(egui::RichText::new(&disassembly.note).weak()).wrap());
    }
}

fn kind_word(kind: AnalysisReferenceKind) -> &'static str {
    match kind {
        AnalysisReferenceKind::Call => "call",
        AnalysisReferenceKind::Jump => "jump",
        AnalysisReferenceKind::Data => "data",
        AnalysisReferenceKind::Other => "reference",
    }
}

/// An address that jumps to its row when clicked.
fn address_link(
    ui: &mut egui::Ui,
    reference: &AnalysisReference,
    arrow: &str,
    mono: &FontId,
    jump: &mut Option<u64>,
) {
    let text = mono_text(
        format!("{arrow} {:x}", reference.address),
        mono,
        theme::blue(),
    );
    if ui
        .add(egui::Label::new(text).sense(egui::Sense::click()))
        .on_hover_text(format!(
            "{} at {:x}: click to go there",
            kind_word(reference.kind),
            reference.address
        ))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        *jump = Some(reference.address);
    }
}

/// The cells of one Ghidra instruction row: address, bytes, the instruction
/// with its label and targets, and the references that point at it.
pub(super) fn instruction_cells(
    row: &mut egui_extras::TableRow,
    entry: &AnalysisEntry,
    mono: &FontId,
    jump: &mut Option<u64>,
) {
    let Some(AnalysisData::Instruction {
        address,
        bytes,
        mnemonic,
        operands,
        label,
        targets,
        xrefs,
        ..
    }) = entry.record.as_ref().map(|record| &record.data)
    else {
        return;
    };
    row.col(|ui| {
        ui.label(mono_text(format!("{address:x}"), mono, theme::muted()));
    });
    row.col(|ui| {
        ui.add(egui::Label::new(mono_text(bytes.clone(), mono, theme::muted())).truncate());
    });
    row.col(|ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            if let Some(label) = label {
                ui.add(
                    egui::Label::new(mono_text(format!("{label}:"), mono, theme::blue()))
                        .truncate(),
                );
            }
            let job = crate::code_listing::instruction(mnemonic, operands, mono);
            ui.add(egui::Label::new(job).truncate())
                .on_hover_text(format!("{mnemonic} {operands}"));
            for target in targets.iter().take(TARGETS_SHOWN) {
                address_link(ui, target, "→", mono, jump);
            }
            if targets.len() > TARGETS_SHOWN {
                ui.weak(format!("+{}", targets.len() - TARGETS_SHOWN))
                    .on_hover_text(
                        targets
                            .iter()
                            .map(|t| format!("{} {:x}", kind_word(t.kind), t.address))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
            }
        });
    });
    row.col(|ui| {
        if xrefs.is_empty() {
            return;
        }
        ui.menu_button(
            format!("{} {}", egui_phosphor::regular::ARROW_UP, xrefs.len()),
            |ui| {
                ui.label(format!("Referenced from {} place(s)", xrefs.len()));
                for xref in xrefs {
                    if ui
                        .button(format!("{} {:x}", kind_word(xref.kind), xref.address))
                        .clicked()
                    {
                        *jump = Some(xref.address);
                        ui.close_menu();
                    }
                }
            },
        )
        .response
        .on_hover_text("Where this address is called, jumped to or read from");
    });
}

/// The complete text of the four cells, for the row menu.
pub(super) fn texts(entry: &AnalysisEntry) -> Vec<String> {
    let Some(AnalysisData::Instruction {
        address,
        bytes,
        mnemonic,
        operands,
        label,
        xrefs,
        ..
    }) = entry.record.as_ref().map(|record| &record.data)
    else {
        return Vec::new();
    };
    vec![
        format!("{address:x}"),
        bytes.clone(),
        match label {
            Some(label) => format!("{label}: {mnemonic} {operands}"),
            None => format!("{mnemonic} {operands}"),
        },
        xrefs
            .iter()
            .map(|x| format!("{:x}", x.address))
            .collect::<Vec<_>>()
            .join(", "),
    ]
}
