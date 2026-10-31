// SPDX-License-Identifier: GPL-3.0-only
//! Embedded content: binwalk's signature scan, without extraction.
use super::tools;
use super::*;
use std::time::Duration;

const SYSTEM: &[&str] = &["/usr/bin/binwalk", "/usr/local/bin/binwalk"];
/// binwalk's own time limit, in seconds.
pub(super) const TIMEOUT_SECONDS: u64 = 180;

pub(super) fn embedded(section: &mut AnalysisSection, specimen_len: u64) {
    let Some(binwalk) = tools::find(SYSTEM) else {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = "binwalk is not installed on this system".into();
        return;
    };
    // binwalk keeps its configuration under $HOME and prints nothing
    // when that directory cannot be created.
    let timeout = Duration::from_secs(super::limits::seconds(TIMEOUT_SECONDS));
    let run = match tools::run_with(
        binwalk,
        &["/input/specimen"],
        &[("HOME", "/tmp")],
        timeout,
        super::limits::tool_output() * 4,
        true,
    ) {
        Ok(run) => run,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("binwalk failed to start: {error}");
            return;
        }
    };
    section.tools = vec![version(binwalk)];
    if !run.success && !run.truncated && !run.timed_out {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = run
            .failure_text("binwalk", timeout)
            .unwrap_or_else(|| "binwalk failed and reported no result".into());
        return;
    }
    let signatures = parse(&run.stdout, specimen_len);
    let found = signatures.len();
    for (offset, description) in signatures.into_iter().take(super::limits::rows()) {
        super::worker::structured_entry(
            section,
            format!("0x{offset:x}"),
            description.clone(),
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: offset,
                file_range: None,
            }),
            AnalysisData::Signature {
                offset,
                description,
            },
        );
    }
    section.summary = format!(
        "{found} {} from binwalk's signature scan; nothing was extracted",
        if found == 1 {
            "signature"
        } else {
            "signatures"
        }
    );
    section.state = AnalysisSectionState::Complete;
    if found > super::limits::rows() {
        section.state = AnalysisSectionState::Partial;
        super::limits::add_for(
            section,
            AnalysisLimitKind::Rows,
            LimitSetting::Rows,
            format!(
                "binwalk found {} signatures; the report lists the first {}.",
                super::detection::group_digits(found as u64),
                super::detection::group_digits(super::limits::rows() as u64)
            ),
        );
    }
    if run.timed_out {
        super::limits::time_out(
            section,
            "binwalk",
            timeout.as_secs(),
            format!(
                "{found} signatures from binwalk's scan were found before it was stopped; nothing was extracted"
            ),
        );
    } else if run.truncated {
        section.state = AnalysisSectionState::Partial;
        super::limits::add_for(
            section,
            AnalysisLimitKind::Size,
            LimitSetting::ToolOutput,
            format!(
                "binwalk printed more than the {} MiB the analysis reads; the rest was ignored.",
                (super::limits::tool_output() * 4) >> 20
            ),
        );
    }
}

/// "Binwalk v2.4.3", the first line binwalk prints for `--help`; it needs
/// a writable home like the scan does.
fn version(binwalk: &str) -> String {
    tools::run(
        binwalk,
        &["--help"],
        &[("HOME", "/tmp")],
        Duration::from_secs(20),
        4096,
    )
    .ok()
    .and_then(|run| {
        run.stdout
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    })
    .unwrap_or_else(|| "binwalk".into())
}

/// `(offset, description)` rows of binwalk's DECIMAL / HEXADECIMAL /
/// DESCRIPTION table; offsets past the specimen are dropped.
fn parse(output: &str, specimen_len: u64) -> Vec<(u64, String)> {
    output
        .lines()
        .filter_map(|line| {
            let (decimal, rest) = line.trim_start().split_once(char::is_whitespace)?;
            let (hex, description) = rest.trim_start().split_once(char::is_whitespace)?;
            let offset = decimal.parse::<u64>().ok()?;
            let hex = u64::from_str_radix(hex.strip_prefix("0x")?, 16).ok()?;
            let description = description.trim();
            (hex == offset && offset <= specimen_len && !description.is_empty())
                .then(|| (offset, description.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_signature_table_parses_and_skips_headers_and_bad_rows() {
        let output = "\nDECIMAL       HEXADECIMAL     DESCRIPTION\n\
            --------------------------------------------------------------------------------\n\
            0             0x0             ELF, 64-bit LSB executable, AMD x86-64\n\
            3000          0xBB8           gzip compressed data, has original file name: \"a b\"\n\
            12            0x99            mismatched offsets\n\
            90000         0x15F90         past the end\n";
        assert_eq!(
            super::parse(output, 5000),
            [
                (0, "ELF, 64-bit LSB executable, AMD x86-64".to_owned()),
                (
                    3000,
                    "gzip compressed data, has original file name: \"a b\"".to_owned()
                ),
            ]
        );
    }
}
