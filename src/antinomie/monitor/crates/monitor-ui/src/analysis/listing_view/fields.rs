// SPDX-License-Identifier: GPL-3.0-only
//! The query fields of each listing category and the typed projection of a
//! row onto them.
use super::*;

/// Registry used both by the listing input and the whole retained listing reader.
pub(crate) fn listing_fields(kind: AnalysisKind) -> Vec<crate::query::FieldSpec<'static>> {
    use crate::query::FieldSpec as F;
    let mut fields = vec![
        F::text("name", "Row label"),
        F::text("value", "Complete retained row value"),
        F::number("offset", "File offset in bytes"),
        F::number("record.id", "Structured record identity"),
        F::text("kind", "Structured record kind"),
    ];
    fields.extend(crate::query::LABEL_FIELDS);
    fields.extend(crate::query::ANALYSIS_FIELDS);
    fields.extend(match kind {
        AnalysisKind::Disassembly => vec![
            F::number("address", "Original instruction or function address"),
            F::text("bytes", "Instruction bytes as hex text"),
            F::text("mnemonic", "Instruction mnemonic"),
            F::text("operands", "Instruction operands"),
            F::text("function", "Containing function name"),
            F::number("size", "Function extent in bytes"),
        ],
        AnalysisKind::Decompilation => vec![
            F::number("address", "Original function address"),
            F::text("function", "Function name"),
            F::number("line", "Source line number"),
            F::text("code", "Retained source text"),
            F::number("size", "Function extent in bytes"),
        ],
        AnalysisKind::Strings => vec![
            F::text("encoding", "String encoding"),
            F::number("length", "Observed string extent in bytes"),
            F::number("retained_len", "Retained text extent in bytes"),
            F::text("text", "Retained string text"),
        ],
        AnalysisKind::Structures => vec![
            F::text("group", "Metadata group"),
            F::text("scope", "Symbol scope"),
            F::text("symbol.kind", "Symbol kind"),
            F::boolean("undefined", "Undefined symbol"),
            F::text("library", "Import library"),
            F::number("ordinal", "Import/export ordinal"),
            F::number("address", "Recorded object address"),
            F::number("size", "Symbol or virtual section extent in bytes"),
            F::number("file_size", "Section extent in file bytes"),
            F::tags("flags", "Decoded section flags"),
            F::text("raw_flags", "Original section flags"),
        ],
        AnalysisKind::Entropy => vec![
            F::number("length", "Sampled range extent in bytes"),
            F::number(
                "milli_bits",
                "Shannon entropy in thousandths of a bit per byte",
            ),
        ],
        AnalysisKind::Hardening => vec![
            F::text("scope", "Property scope"),
            F::text("observed", "Observed property"),
            F::text("evidence", "Property evidence"),
        ],
        AnalysisKind::Rules => vec![
            F::text("rule", "Rule name"),
            F::text("namespace", "Rule namespace"),
            F::tags("rule.tags", "Tags emitted by the rule engine"),
            F::text("ruleset", "Source rule set"),
        ],
        AnalysisKind::Capabilities => vec![
            F::text("namespace", "Capability namespace"),
            F::tags("attack", "ATT&CK references"),
            F::tags("mbc", "Malware behavior references"),
        ],
        AnalysisKind::Identification => vec![
            F::text("category", "Identification category"),
            F::text("version", "Identified version, when present"),
        ],
        AnalysisKind::Metadata => vec![F::text("group", "Metadata group")],
        // The regex matches are read from the strings, not listed on their own.
        AnalysisKind::Regex => Vec::new(),
        AnalysisKind::Embedded => vec![F::text("description", "binwalk signature description")],
        AnalysisKind::Unpacking => vec![
            F::number(
                "layer",
                "Position in the unpack chain; the file as it came is 0",
            ),
            F::text("method", "original, UPX or UPX (header repaired)"),
            F::text("sha256", "SHA-256 of the layer"),
            F::number("size", "Layer size in bytes"),
            F::text("packer", "Packer found in the layer"),
        ],
        AnalysisKind::Floss => vec![
            F::text("origin", "decoded, stack, tight or language"),
            F::text("encoding", "String encoding"),
            F::number(
                "routine",
                "Address FLOSS reports for the routine that built the string",
            ),
            F::number(
                "seen_at",
                "Address FLOSS reports for where the string was seen",
            ),
            F::text("text", "Retained string text"),
        ],
    });
    fields
}

/// An unavailable legacy/typed field remains missing instead of becoming zero or a placeholder.
pub(crate) fn listing_row_with(
    entry: &AnalysisEntry,
    context: &[(&'static str, crate::query::RowValue)],
) -> Vec<(&'static str, crate::query::RowValue)> {
    let mut row = listing_row(entry);
    row.extend(
        context
            .iter()
            .filter(|(field, _)| {
                crate::query::LABEL_FIELDS
                    .iter()
                    .chain(crate::query::ANALYSIS_FIELDS)
                    .any(|spec| spec.name == *field)
            })
            .cloned(),
    );
    row
}

/// A category's own row fields, without evidence annotation metadata.
pub(crate) fn listing_row(entry: &AnalysisEntry) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let number =
        |value: Option<u64>| value.map_or(V::Missing, |value| V::Number(i128::from(value)));
    let text = |value: &Option<String>| {
        value
            .as_ref()
            .map_or(V::Missing, |value| V::Text(value.clone()))
    };
    let mut row = vec![
        ("name", V::Text(entry.label.clone())),
        ("value", V::Text(entry.value.clone())),
        ("offset", number(entry.offset)),
    ];
    let Some(record) = &entry.record else {
        return row;
    };
    row.push(("record.id", number(Some(record.id))));
    let kind = match &record.data {
        AnalysisData::Field { group } => {
            row.push(("group", V::Text(group.clone())));
            "field"
        }
        AnalysisData::Section {
            name,
            address,
            virtual_size,
            file_size,
            raw_flags,
            flags,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("address", number(Some(*address))),
                ("size", number(Some(*virtual_size))),
                ("file_size", number(*file_size)),
                ("raw_flags", V::Text(raw_flags.clone())),
                ("flags", V::List(flags.clone())),
            ]);
            if entry.label == "Segment" {
                "segment"
            } else {
                "section"
            }
        }
        AnalysisData::Symbol {
            name,
            kind,
            scope,
            undefined,
            address,
            size,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("symbol.kind", V::Text(kind.clone())),
                ("scope", V::Text(scope.clone())),
                ("undefined", V::Bool(*undefined)),
                ("address", number(*address)),
                ("size", number(Some(*size))),
            ]);
            "symbol"
        }
        AnalysisData::Import {
            name,
            library,
            ordinal,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", text(name)),
                ("library", text(library)),
                ("ordinal", number(*ordinal)),
            ]);
            "import"
        }
        AnalysisData::Export {
            name,
            ordinal,
            address,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", text(name)),
                ("ordinal", number(*ordinal)),
                ("address", number(*address)),
            ]);
            "export"
        }
        AnalysisData::String {
            encoding,
            byte_len,
            retained_len,
        } => {
            row.extend([
                ("encoding", V::Text(encoding.clone())),
                ("length", number(Some(*byte_len))),
                ("retained_len", number(Some(*retained_len))),
                ("text", V::Text(entry.value.clone())),
            ]);
            "string"
        }
        AnalysisData::Entropy { range, milli_bits } => {
            row.retain(|(name, _)| *name != "offset");
            row.extend([
                ("offset", number(Some(range.offset))),
                ("length", number(Some(range.len))),
                ("milli_bits", V::Number(i128::from(*milli_bits))),
            ]);
            "entropy"
        }
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            row.extend([
                ("scope", V::Text(scope.clone())),
                ("observed", V::Text(observed.clone())),
                ("evidence", V::Text(evidence.clone())),
            ]);
            "property"
        }
        AnalysisData::Instruction {
            address,
            bytes,
            mnemonic,
            operands,
            function,
            ..
        } => {
            row.extend([
                ("address", number(Some(*address))),
                ("bytes", V::Text(bytes.clone())),
                ("mnemonic", V::Text(mnemonic.clone())),
                ("operands", V::Text(operands.clone())),
                ("function", text(function)),
            ]);
            "instruction"
        }
        AnalysisData::Function {
            name,
            address,
            size,
        } => {
            row.extend([
                ("address", number(Some(*address))),
                ("function", V::Text(name.clone())),
                ("size", number(Some(*size))),
            ]);
            "function"
        }
        AnalysisData::SourceLine {
            function,
            address,
            line,
        } => {
            row.extend([
                ("address", number(*address)),
                ("function", V::Text(function.clone())),
                ("line", V::Number(i128::from(*line))),
                ("code", V::Text(entry.value.clone())),
            ]);
            "source_line"
        }
        AnalysisData::Layer {
            index,
            method,
            sha256,
            size,
            packer,
            ..
        } => {
            row.extend([
                ("layer", V::Number(i128::from(*index))),
                ("method", V::Text(method.clone())),
                ("sha256", V::Text(sha256.clone())),
                ("size", number(Some(*size))),
                ("packer", text(packer)),
            ]);
            "layer"
        }
        AnalysisData::FlossString {
            origin,
            encoding,
            function,
            address,
        } => {
            row.extend([
                ("origin", V::Text(origin.clone())),
                ("encoding", V::Text(encoding.clone())),
                ("routine", number(*function)),
                ("seen_at", number(*address)),
                ("text", V::Text(entry.value.clone())),
            ]);
            "floss_string"
        }
        AnalysisData::Signature {
            offset,
            description,
        } => {
            row.retain(|(name, _)| *name != "offset");
            row.extend([
                ("offset", number(Some(*offset))),
                ("description", V::Text(description.clone())),
            ]);
            "signature"
        }
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            row.extend([
                ("rule", V::Text(rule.clone())),
                ("namespace", V::Text(namespace.clone())),
                ("rule.tags", V::List(tags.clone())),
                ("ruleset", V::Text(ruleset.clone())),
            ]);
            "rule_match"
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("namespace", V::Text(namespace.clone())),
                ("attack", V::List(attack.clone())),
                ("mbc", V::List(mbc.clone())),
            ]);
            "capability"
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("category", V::Text(category.clone())),
                ("version", text(version)),
            ]);
            "identification"
        }
    };
    row.push(("kind", V::Text(kind.into())));
    row
}
