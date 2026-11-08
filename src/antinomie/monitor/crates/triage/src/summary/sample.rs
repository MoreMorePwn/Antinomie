// SPDX-License-Identifier: GPL-3.0-only
//! What the Summary's header says of the sample: name, ELF type and
//! architecture, static or dynamic, packed, size and SHA-256, all read from
//! the run's Static analysis report.
use antinomie_monitor_core::{AnalysisKind, AnalysisReport};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SampleInfo {
    pub name: String,
    /// "ELF 64-bit x86-64"; empty when the analysis did not say.
    pub kind: String,
    /// "static" or "dynamic" when the analysis said so.
    pub linking: Option<&'static str>,
    /// The packer Static analysis found, "UPX" or "UPX (headers modified)".
    pub packer: Option<String>,
    pub size: Option<u64>,
    pub sha256: Option<String>,
}

/// "ELF 64-bit x86-64" and the linking from `file`'s magic text.
pub fn describe_magic(magic: &str) -> (String, Option<&'static str>) {
    let linking = if magic.contains("statically linked") || magic.contains("static-pie") {
        Some("static")
    } else if magic.contains("dynamically linked") {
        Some("dynamic")
    } else {
        None
    };
    let mut parts = magic.split(',').map(str::trim);
    let first = parts.next().unwrap_or("");
    if !first.starts_with("ELF") {
        return (String::new(), linking);
    }
    let bits = first.split_whitespace().nth(1).unwrap_or("");
    let arch = parts.next().unwrap_or("");
    let kind = [
        ("ELF", true),
        (bits, bits.ends_with("-bit")),
        (arch, !arch.is_empty()),
    ]
    .iter()
    .filter(|(_, on)| *on)
    .map(|(text, _)| *text)
    .collect::<Vec<_>>()
    .join(" ");
    (kind, linking)
}

impl SampleInfo {
    pub fn of(report: &AnalysisReport) -> Self {
        let entry = |kind: AnalysisKind, label: &str| {
            report
                .sections
                .iter()
                .filter(|section| section.kind == kind)
                .flat_map(|section| &section.entries)
                .find(|entry| entry.label == label)
                .map(|entry| entry.value.as_str())
        };
        let (mut kind, linking) = entry(AnalysisKind::Identification, "format: file magic")
            .map(describe_magic)
            .unwrap_or_default();
        if kind.is_empty() {
            let format = entry(AnalysisKind::Metadata, "Format").unwrap_or("");
            let arch = entry(AnalysisKind::Metadata, "Architecture").unwrap_or("");
            kind = [format, arch]
                .iter()
                .filter(|part| !part.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
        }
        let packer = antinomie_monitor_core::packer_verdict(report).map(|verdict| {
            if verdict.modified {
                format!("{} (headers modified)", verdict.packer)
            } else {
                verdict.packer
            }
        });
        Self {
            name: crate::process_cells::file_name(&report.source_path).to_owned(),
            kind,
            linking,
            packer,
            size: report.specimen_len,
            sha256: report.specimen_sha256.clone(),
        }
    }
}

/// "812 KiB" for a size in bytes.
pub fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// The first and last characters of a hash: "3f9a…c21e".
pub fn short_hash(hash: &str) -> String {
    if hash.len() <= 12 {
        hash.to_owned()
    } else {
        format!("{}\u{2026}{}", &hash[..4], &hash[hash.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_gives_the_elf_kind_and_the_linking() {
        assert_eq!(
            describe_magic(
                "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped"
            ),
            ("ELF 64-bit x86-64".to_owned(), Some("static"))
        );
        assert_eq!(
            describe_magic("ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so"),
            ("ELF 32-bit ARM".to_owned(), Some("dynamic"))
        );
        assert_eq!(describe_magic("POSIX shell script, ASCII text").0, "");
        assert_eq!(
            describe_magic("ELF 64-bit LSB shared object, x86-64").1,
            None
        );
    }

    #[test]
    fn sizes_and_hashes_are_short() {
        assert_eq!(size_text(812 * 1024), "812 KiB");
        assert_eq!(size_text(12), "12 B");
        assert_eq!(size_text(3 << 20), "3 MiB");
        assert_eq!(short_hash(&"3f9a".repeat(16)), "3f9a\u{2026}3f9a");
        assert_eq!(short_hash("abc"), "abc");
    }
}
