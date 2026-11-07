// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Writing the chosen formats of a sample report to a folder, and noting the
//! export in the sample's custody log. Files are created new (never
//! overwritten), owner-only, and named
//! `antinomie-sample-report-<sha8>-<time>` plus the format's suffix.
use super::{Choices, Format, SampleReport, layout, markdown, misp, stix};
use crate::report::{html, pdf};
use crate::samples::{CustodyEvent, Library};
use std::io::Write;
use std::path::{Path, PathBuf};

/// What an export wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub files: Vec<(String, PathBuf)>,
}

/// The bytes of `format` for `report`; `defang` applies to HTML, PDF and
/// Markdown only.
pub fn render(report: &SampleReport, format: Format, defang: bool) -> Result<Vec<u8>, String> {
    Ok(match format {
        Format::Html => html::render(&layout::document(report, defang)).into_bytes(),
        Format::Pdf => pdf::render(&layout::document(report, defang), report.generated_ms)?,
        Format::Json => report.to_json()?.into_bytes(),
        Format::Misp => misp::render(report)?.into_bytes(),
        Format::Stix => stix::render(report)?.into_bytes(),
        Format::Markdown => markdown::render(&layout::document(report, defang)).into_bytes(),
    })
}

/// `antinomie-sample-report-<sha8>-<yyyymmdd-hhmmss>Z`, the time in UTC.
pub fn base_name(report: &SampleReport) -> String {
    let short: String = report
        .sample
        .sha256
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    let time = crate::report::utc(report.generated_ms)
        .replace(['-', ':'], "")
        .replace(' ', "-");
    format!(
        "antinomie-sample-report-{}-{time}Z",
        if short.is_empty() { "sample" } else { &short }
    )
}

fn create_new(path: &Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn free_base(folder: &Path, base: &str, suffixes: &[&str]) -> String {
    let taken = |name: &str| {
        suffixes
            .iter()
            .any(|s| folder.join(format!("{name}{s}")).exists())
    };
    let mut name = base.to_owned();
    let mut n = 1;
    while taken(&name) {
        n += 1;
        name = format!("{base}-{n}");
    }
    name
}

/// Write the formats of `choices` into `folder`.
pub fn write(report: &SampleReport, choices: &Choices, folder: &Path) -> Result<Written, String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)
        .map_err(|e| format!("{}: {e}", folder.display()))?;
    let suffixes: Vec<&str> = Format::ALL
        .iter()
        .filter(|f| choices.writes(**f))
        .map(|f| f.suffix())
        .collect();
    let base = free_base(folder, &base_name(report), &suffixes);
    let mut written = Written::default();
    for format in Format::ALL.into_iter().filter(|f| choices.writes(*f)) {
        let bytes = render(report, format, choices.defang)?;
        let path = folder.join(format!("{base}{}", format.suffix()));
        let mut file = create_new(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        written.files.push((format.label().to_owned(), path));
    }
    Ok(written)
}

/// Write the files, then add an `Exported` entry to the sample's custody log
/// (the head it names is the one the report holds). The note is made only
/// when at least one file was written.
pub fn write_and_note(
    library: &Library,
    report: &SampleReport,
    choices: &Choices,
    folder: &Path,
) -> Result<Written, String> {
    let written = write(report, choices, folder)?;
    if !written.files.is_empty() {
        library.record_event(
            &report.sample.sha256,
            "analyst",
            CustodyEvent::Exported {
                format: format!(
                    "sample report ({})",
                    written
                        .files
                        .iter()
                        .map(|(label, _)| label.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                signed: "unsigned".into(),
                head: report.custody.head.clone(),
            },
        )?;
    }
    Ok(written)
}
