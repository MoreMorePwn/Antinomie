// SPDX-License-Identifier: GPL-3.0-only
//! Where the host-side analysis of a library sample lives and how its bytes
//! reach the analysis job (`Command::AnalyzeSample`).
use std::{
    fs::File,
    io::{Seek, Write},
    path::{Path, PathBuf},
};

/// The folder of one analysis of a library sample: `<data>/analyses/<id>`.
/// It belongs to no VM and no recording, so it outlives both and a job runner
/// can address it by the report id. The layers unpacking finds are siblings.
pub fn sample_analysis_directory(data_dir: &Path, report_id: &str) -> PathBuf {
    data_dir.join("analyses").join(report_id)
}

/// The finished static analysis reports kept under `<data>/analyses` for the
/// library sample `sha256` (`Command::AnalyzeSample`'s reports; layers are not
/// included), newest first. A sample that never ran has these and no run.
pub fn static_reports_for(data_dir: &Path, sha256: &str) -> Vec<super::AnalysisReport> {
    let Ok(listed) = std::fs::read_dir(data_dir.join("analyses")) else {
        return Vec::new();
    };
    let needle = sha256.to_ascii_lowercase().into_bytes();
    let mut found: Vec<(std::time::SystemTime, super::AnalysisReport)> = listed
        .filter_map(Result::ok)
        .filter_map(|entry| {
            // Only a report that names the hash is parsed: the folder grows
            // with every analysis ever made (audit AN-16).
            let report = super::jobs::open_report_if(&entry.path(), |text| {
                !needle.is_empty() && text.windows(needle.len()).any(|window| window == needle)
            })
            .ok()??;
            let modified = std::fs::metadata(entry.path().join("report.json"))
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (report.layer.is_none()
                && matches!(
                    report.state,
                    super::AnalysisState::Complete | super::AnalysisState::Partial
                )
                && report
                    .specimen_sha256
                    .as_deref()
                    .is_some_and(|hash| hash.eq_ignore_ascii_case(sha256)))
            .then_some((modified, report))
        })
        .collect();
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    found.into_iter().map(|(_, report)| report).collect()
}

/// The YARA rules a static analysis report matched, as detection hits (no
/// pack and no score: the static scan records the rule's name and credit).
pub fn static_rule_hits(report: &super::AnalysisReport) -> Vec<crate::run_digest::DetectionHit> {
    report
        .sections
        .iter()
        .flat_map(|section| &section.entries)
        .filter_map(|entry| match &entry.record.as_ref()?.data {
            super::AnalysisData::RuleMatch { rule, ruleset, .. } => {
                let (author, license) = ruleset.rsplit_once("; ").unwrap_or((ruleset.as_str(), ""));
                Some(crate::run_digest::DetectionHit {
                    engine: "YARA".into(),
                    rule_id: rule.clone(),
                    title: rule.clone(),
                    author: if author == "unknown author" {
                        String::new()
                    } else {
                        author.into()
                    },
                    license: license.into(),
                    count: 1,
                    ..Default::default()
                })
            }
            _ => None,
        })
        .collect()
}

/// `bytes` in an anonymous in-memory file, read from the start: the
/// decrypted sample reaches the job without a plain copy in a path of its own.
pub fn anonymous_copy(bytes: &[u8]) -> Result<File, String> {
    let fd = rustix::fs::memfd_create("sample", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(|error| format!("anonymous sample copy: {error}"))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.rewind())
        .map_err(|error| format!("anonymous sample copy: {error}"))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{
        AnalysisData, AnalysisEntry, AnalysisKind, AnalysisRecord, AnalysisSectionState,
        AnalysisSelection, AnalysisState, jobs::new_report,
    };
    use crate::storage;
    use std::io::Read;

    /// A finished static report of `sha` whose rules section lists `rules`.
    fn report_with(sha: &str, rules: &[&str]) -> crate::analysis::AnalysisReport {
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Rules],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut report = new_report(&format!("sample:{sha}"), &selection);
        report.state = AnalysisState::Complete;
        report.specimen_sha256 = Some(sha.into());
        report.specimen_len = Some(10);
        report.sections[0].state = AnalysisSectionState::Complete;
        report.sections[0].summary = format!("{} rules matched", rules.len());
        for (at, rule) in rules.iter().enumerate() {
            report.sections[0].entries.push(AnalysisEntry {
                label: (*rule).into(),
                value: "$a".into(),
                offset: None,
                record: Some(AnalysisRecord {
                    revision: 1,
                    id: at as u64 + 1,
                    location: None,
                    data: AnalysisData::RuleMatch {
                        rule: (*rule).into(),
                        namespace: "s171".into(),
                        tags: Vec::new(),
                        ruleset: "Elastic Security; Elastic License v2".into(),
                    },
                }),
            });
        }
        report
    }

    #[test]
    fn a_never_run_sample_finds_its_static_reports_and_their_rules() {
        let root = std::env::temp_dir().join(format!("ant-static-for-{}", storage::unique_id()));
        let sha = "ab".repeat(32);
        for (report, name) in [
            (report_with(&sha, &["Linux_Trojan_Kinsing_3d4c1e0f"]), "one"),
            (
                report_with(&"cd".repeat(32), &["Linux_Trojan_Mirai_b9a9d04b"]),
                "other",
            ),
        ] {
            let directory = root.join("analyses").join(name);
            storage::private_dir(&directory).unwrap();
            std::fs::write(
                directory.join("report.json"),
                serde_json::to_vec(&report).unwrap(),
            )
            .unwrap();
        }
        let found = static_reports_for(&root, &sha);
        assert_eq!(found.len(), 1);
        let hits = static_rule_hits(&found[0]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].engine, "YARA");
        assert_eq!(hits[0].rule_id, "Linux_Trojan_Kinsing_3d4c1e0f");
        assert_eq!(hits[0].author, "Elastic Security");
        let named = crate::family::family_candidates(&hits, crate::family::Bazaar::default());
        assert_eq!(named[0].name, "Kinsing");
        assert!(static_reports_for(&root, &"ef".repeat(32)).is_empty());
        assert!(static_reports_for(&root.join("missing"), &sha).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_copy_reads_back_from_the_start_and_the_folder_is_under_the_data_directory() {
        let mut file = anonymous_copy(b"MZ sample bytes").unwrap();
        let mut back = Vec::new();
        file.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"MZ sample bytes");
        assert_eq!(
            sample_analysis_directory(Path::new("/d"), "abc"),
            Path::new("/d/analyses/abc")
        );
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    /// By hand (ANT-T0618 measurement of AN-16): the lookup of one sample's
    /// reports among many analysis folders, each report parsed as before and
    /// only the ones that name the hash as now.
    #[test]
    #[ignore = "timing"]
    fn time_the_lookup_among_many_reports() {
        let data = std::env::temp_dir().join(format!("ant-lookup-{}", crate::storage::unique_id()));
        let analyses = data.join("analyses");
        std::fs::create_dir_all(&analyses).unwrap();
        let wanted = "ab".repeat(32);
        for n in 0..300u32 {
            let sha = if n % 30 == 0 {
                wanted.clone()
            } else {
                format!("{n:064x}")
            };
            let selection = super::super::AnalysisSelection::default();
            let mut report = super::super::jobs::new_report("sample:x", &selection);
            report.state = super::super::AnalysisState::Complete;
            report.specimen_sha256 = Some(sha);
            for section in &mut report.sections {
                section.state = super::super::AnalysisSectionState::Complete;
                section.summary = "x".repeat(200);
            }
            let folder = analyses.join(&report.id);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("report.json"),
                serde_json::to_vec(&report).unwrap(),
            )
            .unwrap();
        }
        let t = std::time::Instant::now();
        let mut before = 0;
        for entry in std::fs::read_dir(&analyses).unwrap().flatten() {
            if super::super::jobs::open_report(&entry.path())
                .is_ok_and(|r| r.specimen_sha256.as_deref() == Some(wanted.as_str()))
            {
                before += 1;
            }
        }
        eprintln!(
            "TIMING parse every report (300): {:.4} s, {before} found",
            t.elapsed().as_secs_f64()
        );
        let t = std::time::Instant::now();
        let found = static_reports_for(&data, &wanted);
        eprintln!(
            "TIMING prefilter (300): {:.4} s, {} found",
            t.elapsed().as_secs_f64(),
            found.len()
        );
        assert_eq!(before, found.len());
        let _ = std::fs::remove_dir_all(data);
    }
}
