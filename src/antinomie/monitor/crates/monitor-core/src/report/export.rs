// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Writing the chosen formats and the evidence bundle to a folder. Files are
//! created new (never overwritten), owner-only, and named
//! `antinomie-report-<run>-<time>` plus the format's suffix.
use super::bundle::{self, BundleInput, Bundled};
use super::{Choices, Format, Report, html, layout, misp, pdf, stix};
use std::io::Write;
use std::path::{Path, PathBuf};

/// What an export wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub files: Vec<(String, PathBuf)>,
    pub bundle: Option<Bundled>,
}

/// The text of `format` for `report`; `defang` applies to HTML and PDF only.
pub fn render(report: &Report, format: Format, defang: bool) -> Result<Vec<u8>, String> {
    Ok(match format {
        Format::Html => html::render(&layout::document(report, defang)).into_bytes(),
        Format::Pdf => pdf::render(&layout::document(report, defang), report.generated_ms)?,
        Format::Json => report.to_json()?.into_bytes(),
        Format::Misp => misp::render(report)?.into_bytes(),
        Format::Stix => stix::render(report)?.into_bytes(),
    })
}

/// The base name of a run's files: `antinomie-report-<run8>-<yyyymmdd-hhmmss>`.
pub fn base_name(report: &Report) -> String {
    let run: String = report
        .run
        .run_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    let time = super::utc(report.generated_ms)
        .replace(['-', ':'], "")
        .replace(' ', "-");
    format!(
        "antinomie-report-{}-{time}",
        if run.is_empty() { "run" } else { &run }
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

/// A base name no file in `folder` starts with (a counter is added).
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

fn private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Write the formats of `choices` for `report` into `folder`. The bundle, when
/// one is wanted, is built by `make_bundle` (it needs the run's files); its
/// result is returned next to the formats.
pub fn write(
    report: &Report,
    choices: &Choices,
    folder: &Path,
    bundle_input: Option<BundleInput>,
) -> Result<Written, String> {
    private_dir(folder)?;
    let mut suffixes: Vec<&str> = Format::ALL
        .iter()
        .filter(|f| choices.writes(**f))
        .map(|f| f.suffix())
        .collect();
    if bundle_input.is_some() {
        suffixes.push("-evidence.zip");
    }
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
    if let Some(input) = bundle_input {
        let path = folder.join(format!("{base}-evidence.zip"));
        let temp = folder.join(format!(".{base}-dropped.tmp"));
        written.bundle = Some(bundle::write(&path, &temp, input)?);
        written.files.push(("Evidence bundle".into(), path));
    }
    Ok(written)
}
