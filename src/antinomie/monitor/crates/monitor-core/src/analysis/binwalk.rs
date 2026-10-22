// SPDX-License-Identifier: GPL-3.0-only
//! Embedded content: binwalk's signature scan, without extraction.
use super::tools;
use super::*;
use std::time::Duration;

const SYSTEM: &[&str] = &["/usr/bin/binwalk", "/usr/local/bin/binwalk"];
/// Signatures kept in the report; binwalk can report thousands on firmware.
const SIGNATURE_MAX_COUNT: usize = 2048;

pub(super) fn embedded(section: &mut AnalysisSection, specimen_len: u64) {
    let Some(binwalk) = tools::find(SYSTEM) else {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = "binwalk is not installed on this system".into();
        return;
    };
    // binwalk keeps its configuration under $HOME and prints nothing
    // when that directory cannot be created.
    let run = match tools::run(
        binwalk,
        &["/input/specimen"],
        &[("HOME", "/tmp")],
        Duration::from_secs(180),
        4 * 1024 * 1024,
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
        section.summary = "binwalk failed; its signature scan reported no result".into();
        return;
    }
    let signatures = parse(&run.stdout, specimen_len);
    let found = signatures.len();
    for (offset, description) in signatures.into_iter().take(SIGNATURE_MAX_COUNT) {
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
    section.state = if run.truncated || run.timed_out || found > SIGNATURE_MAX_COUNT {
        AnalysisSectionState::Partial
    } else {
        AnalysisSectionState::Complete
    };
    section.summary = format!(
        "{found} {} from binwalk's signature scan; nothing was extracted{}",
        if found == 1 {
            "signature"
        } else {
            "signatures"
        },
        if run.timed_out {
            "; binwalk ran out of time (3 minutes)"
        } else {
            ""
        }
    );
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
