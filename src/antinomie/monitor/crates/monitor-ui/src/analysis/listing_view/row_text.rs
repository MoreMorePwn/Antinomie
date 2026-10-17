// SPDX-License-Identifier: MIT
//! The complete text of each cell of a listing row, for its context menu.
use super::*;

/// One value per column `show` lays out for `kind`, in column order.
/// Function headers put the symbol in the last column.
pub(super) fn texts(
    kind: AnalysisKind,
    scope: Option<Structure>,
    entry: &AnalysisEntry,
) -> Vec<String> {
    let data = entry.record.as_ref().map(|record| &record.data);
    if let (AnalysisKind::Structures, Some(scope)) = (kind, scope) {
        return records::columns(kind, scope, false)
            .iter()
            .map(|column| column.text(entry))
            .collect();
    }
    match (kind, data) {
        (
            _,
            Some(AnalysisData::Function {
                name,
                address,
                size,
            }),
        ) => {
            let title = if *size > 0 {
                format!(
                    "{name}  ·  0x{address:x}, {}",
                    crate::values::file_size(*size)
                )
            } else {
                format!("{name}  ·  0x{address:x}")
            };
            match kind {
                AnalysisKind::Decompilation => vec![String::new(), title],
                _ => vec![format!("{address:x}"), String::new(), title],
            }
        }
        (
            AnalysisKind::Disassembly,
            Some(AnalysisData::Instruction {
                address,
                bytes,
                mnemonic,
                operands,
                ..
            }),
        ) => vec![
            format!("{address:x}"),
            bytes.clone(),
            format!("{mnemonic} {operands}"),
        ],
        (AnalysisKind::Decompilation, Some(AnalysisData::SourceLine { line, .. })) => {
            vec![line.to_string(), entry.value.clone()]
        }
        (
            AnalysisKind::Strings,
            Some(AnalysisData::String {
                encoding, byte_len, ..
            }),
        ) => vec![
            format!("{:x}", entry.offset.unwrap_or(0)),
            encoding.clone(),
            crate::values::file_size(*byte_len),
            entry.value.clone(),
        ],
        _ => vec![entry.label.clone(), entry.value.clone()],
    }
}
