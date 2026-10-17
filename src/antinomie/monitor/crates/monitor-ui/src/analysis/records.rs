//! Typed row projections. Legacy values are displayed, never reverse-parsed.
use antinomie_monitor_core::{
    AnalysisAddressKind, AnalysisData, AnalysisEntry, AnalysisKind, AnalysisRange,
};
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Structure {
    #[default]
    All,
    Headers,
    Sections,
    Segments,
    Imports,
    Exports,
    Symbols,
}

impl Structure {
    pub const FILTERS: [Self; 6] = [
        Self::Headers,
        Self::Sections,
        Self::Segments,
        Self::Imports,
        Self::Exports,
        Self::Symbols,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All structures",
            Self::Headers => "Headers",
            Self::Sections => "Sections",
            Self::Segments => "Segments",
            Self::Imports => "Imports",
            Self::Exports => "Exports",
            Self::Symbols => "Symbols",
        }
    }
    /// The listing filter that keeps this view's rows; see the `kind`
    /// field of `listing_view::listing_row`.
    pub fn kind_query(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Headers => "kind == \"field\"",
            Self::Sections => "kind == \"section\"",
            Self::Segments => "kind == \"segment\"",
            Self::Imports => "kind == \"import\"",
            Self::Exports => "kind == \"export\"",
            Self::Symbols => "kind == \"symbol\"",
        }
    }
    pub fn accepts(self, entry: &AnalysisEntry) -> bool {
        // Segments are recorded with the shape of a section.
        let segment = entry.label == "Segment";
        match self {
            Self::Sections if segment => return false,
            Self::Segments => {
                return segment
                    && matches!(
                        entry.record.as_ref().map(|record| &record.data),
                        Some(AnalysisData::Section { .. })
                    );
            }
            _ => {}
        }
        matches!(
            (self, entry.record.as_ref().map(|record| &record.data)),
            (Self::All, _)
                | (Self::Headers, Some(AnalysisData::Field { .. }))
                | (Self::Sections, Some(AnalysisData::Section { .. }))
                | (Self::Imports, Some(AnalysisData::Import { .. }))
                | (Self::Exports, Some(AnalysisData::Export { .. }))
                | (Self::Symbols, Some(AnalysisData::Symbol { .. }))
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Column {
    Name,
    Value,
    Offset,
    Address,
    VirtualSize,
    FileSize,
    Flags,
    Library,
    Ordinal,
    Encoding,
    Size,
    Retained,
    Entropy,
    Scope,
    Kind,
    Defined,
    Tags,
    Source,
    Category,
    Version,
    Attack,
}
impl Column {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name / field",
            Self::Value => "Value",
            Self::Offset => "File offset",
            Self::Address => "Object / RVA",
            Self::VirtualSize => "Virtual size",
            Self::FileSize => "File size",
            Self::Flags => "Flags",
            Self::Library => "Library",
            Self::Ordinal => "Ordinal",
            Self::Encoding => "Encoding",
            Self::Size => "Byte length",
            Self::Retained => "Retained",
            Self::Entropy => "Bits/octet",
            Self::Scope => "Scope",
            Self::Kind => "Kind",
            Self::Defined => "Defined",
            Self::Tags => "Tags",
            Self::Source => "Rule set",
            Self::Category => "Category",
            Self::Version => "Version",
            Self::Attack => "ATT&CK",
        }
    }
    pub fn number(self, entry: &AnalysisEntry) -> Option<u64> {
        let record = entry.record.as_ref();
        match self {
            Self::Offset => record
                .and_then(|r| r.location.as_ref())
                .and_then(|l| l.file_range)
                .map(|r| r.offset)
                .or(entry.offset)
                .or_else(|| match &record?.data {
                    AnalysisData::Signature { offset, .. } => Some(*offset),
                    _ => None,
                }),
            Self::Address => record
                .and_then(|r| r.location.as_ref())
                .filter(|l| l.kind != AnalysisAddressKind::FileOffset)
                .map(|l| l.value)
                .or_else(|| match &record?.data {
                    AnalysisData::Section { address, .. } => Some(*address),
                    AnalysisData::Symbol { address, .. } | AnalysisData::Export { address, .. } => {
                        *address
                    }
                    _ => None,
                }),
            _ => match (&record?.data, self) {
                (AnalysisData::Section { address, .. }, Self::Address) => Some(*address),
                (AnalysisData::Section { virtual_size, .. }, Self::VirtualSize) => {
                    Some(*virtual_size)
                }
                (AnalysisData::Section { file_size, .. }, Self::FileSize) => *file_size,
                (AnalysisData::Symbol { size, .. }, Self::Size) => Some(*size),
                (
                    AnalysisData::Import { ordinal, .. } | AnalysisData::Export { ordinal, .. },
                    Self::Ordinal,
                ) => *ordinal,
                (AnalysisData::String { byte_len, .. }, Self::Size) => Some(*byte_len),
                (AnalysisData::String { retained_len, .. }, Self::Retained) => Some(*retained_len),
                (AnalysisData::Entropy { milli_bits, .. }, Self::Entropy) => {
                    Some(u64::from(*milli_bits))
                }
                (AnalysisData::Entropy { range, .. }, Self::Size) => Some(range.len),
                _ => None,
            },
        }
    }
    pub fn text(self, entry: &AnalysisEntry) -> String {
        if let Some(number) = self.number(entry) {
            return match self {
                Self::Address | Self::Offset => format!("0x{number:x}"),
                Self::Entropy => format!("{}.{:03}", number / 1000, number % 1000),
                _ => number.to_string(),
            };
        }
        match self {
            Self::Name => {
                return match entry.record.as_ref().map(|r| &r.data) {
                    Some(
                        AnalysisData::Section { name, .. }
                        | AnalysisData::Symbol { name, .. }
                        | AnalysisData::Capability { name, .. }
                        | AnalysisData::Identification { name, .. }
                        | AnalysisData::Function { name, .. },
                    ) => name.clone(),
                    Some(AnalysisData::RuleMatch { rule, .. }) => rule.clone(),
                    Some(
                        AnalysisData::Import {
                            name: Some(name), ..
                        }
                        | AnalysisData::Export {
                            name: Some(name), ..
                        },
                    ) => name.clone(),
                    _ => entry.label.clone(),
                };
            }
            Self::Value => return entry.value.clone(),
            _ => {}
        }
        let Some(record) = &entry.record else {
            return "-".into();
        };
        match (&record.data, self) {
            (
                AnalysisData::Section {
                    raw_flags, flags, ..
                },
                Self::Flags,
            ) => format!("{raw_flags} {}", flags.join(" | ")),
            (AnalysisData::Import { library, .. }, Self::Library) => {
                library.clone().unwrap_or_else(|| "-".into())
            }
            (AnalysisData::String { encoding, .. }, Self::Encoding) => encoding.clone(),
            (
                AnalysisData::Symbol { scope, .. } | AnalysisData::Property { scope, .. },
                Self::Scope,
            ) => scope.clone(),
            (AnalysisData::Symbol { kind, .. }, Self::Kind) => kind.clone(),
            (AnalysisData::Symbol { undefined, .. }, Self::Defined) => {
                if *undefined { "Undefined" } else { "Defined" }.into()
            }
            (AnalysisData::RuleMatch { tags, .. }, Self::Tags) => tags.join(", "),
            (AnalysisData::RuleMatch { ruleset, .. }, Self::Source) => ruleset.clone(),
            (AnalysisData::Capability { namespace, .. }, Self::Scope) => namespace.clone(),
            (AnalysisData::Capability { attack, .. }, Self::Attack) => attack.join(", "),
            (AnalysisData::Identification { category, .. }, Self::Category) => category.clone(),
            (
                AnalysisData::Identification {
                    version: Some(version),
                    ..
                },
                Self::Version,
            ) => version.clone(),
            _ => "-".into(),
        }
    }
    pub fn compare(self, left: &AnalysisEntry, right: &AnalysisEntry) -> Ordering {
        match (self.number(left), self.number(right)) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            _ => self.text(left).cmp(&self.text(right)),
        }
    }
}

pub(super) fn columns(kind: AnalysisKind, filter: Structure, legacy: bool) -> &'static [Column] {
    use Column::*;
    if legacy {
        return &[Name, Value, Offset];
    }
    match (kind, filter) {
        (AnalysisKind::Structures, Structure::Sections | Structure::Segments) => {
            &[Name, Address, Offset, VirtualSize, FileSize, Flags]
        }
        (AnalysisKind::Structures, Structure::Imports) => &[Name, Library, Ordinal],
        (AnalysisKind::Structures, Structure::Exports) => &[Name, Ordinal, Address],
        (AnalysisKind::Structures, Structure::Symbols) => {
            &[Name, Kind, Scope, Defined, Address, Size]
        }
        (AnalysisKind::Strings, _) => &[Offset, Encoding, Size, Retained, Value],
        (AnalysisKind::Entropy, _) => &[Name, Offset, Size, Entropy],
        (AnalysisKind::Rules, _) => &[Name, Tags, Value, Source],
        (AnalysisKind::Identification, _) => &[Category, Name, Version, Value],
        (AnalysisKind::Capabilities, _) => &[Name, Scope, Attack, Value],
        (AnalysisKind::Hardening, _) => &[Name, Scope, Value],
        (AnalysisKind::Embedded, _) => &[Offset, Value],
        _ => &[Name, Value, Offset],
    }
}

pub(super) fn identity(index: usize, entry: &AnalysisEntry) -> (bool, u64) {
    entry
        .record
        .as_ref()
        .map(|r| (true, r.id))
        .unwrap_or((false, index as u64))
}

pub(super) fn file_range(
    entry: &AnalysisEntry,
    specimen_len: Option<u64>,
) -> Option<AnalysisRange> {
    let range = entry.record.as_ref()?.location.as_ref()?.file_range?;
    let end = range.offset.checked_add(range.len)?;
    (range.len > 0 && end <= specimen_len?).then_some(range)
}

pub(super) fn searchable(entry: &AnalysisEntry) -> String {
    let mut value = format!("{} {}", entry.label, entry.value);
    if let Some(record) = &entry.record {
        value.push_str(&format!(" {:?}", record.data));
    }
    value.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{AnalysisAddressKind, AnalysisLocation, AnalysisRecord};
    fn entry(id: u64, offset: u64) -> AnalysisEntry {
        AnalysisEntry {
            label: "name".into(),
            value: "text".into(),
            offset: Some(offset),
            record: Some(AnalysisRecord {
                revision: 1,
                id,
                location: Some(AnalysisLocation {
                    kind: AnalysisAddressKind::FileOffset,
                    value: offset,
                    file_range: Some(AnalysisRange { offset, len: 8 }),
                }),
                data: AnalysisData::String {
                    encoding: "ASCII".into(),
                    byte_len: 8,
                    retained_len: 4,
                },
            }),
        }
    }
    #[test]
    fn typed_numeric_order_and_stable_identity_do_not_parse_formatted_text() {
        let left = entry(55, 2);
        let right = entry(88, 16);
        assert_eq!(Column::Offset.compare(&left, &right), Ordering::Less);
        assert_eq!(identity(100, &left), identity(0, &left));
        assert!(searchable(&left).contains("ascii"));
    }
    #[test]
    fn byte_navigation_requires_a_proven_complete_checked_range() {
        assert_eq!(
            file_range(&entry(1, 10), Some(18)),
            Some(AnalysisRange { offset: 10, len: 8 })
        );
        assert!(file_range(&entry(1, 10), Some(17)).is_none());
        assert!(file_range(&entry(1, u64::MAX), Some(u64::MAX)).is_none());
        let mut legacy = entry(1, 10);
        legacy.record = None;
        assert!(file_range(&legacy, Some(100)).is_none());
        assert_eq!(
            columns(AnalysisKind::Strings, Structure::All, true),
            &[Column::Name, Column::Value, Column::Offset]
        );
    }
}
