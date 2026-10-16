// SPDX-License-Identifier: MIT
use super::{runner::Staged, *};
use std::{
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

const BLOCK_SIZE: usize = 64 * 1024 * 1024;
const TOTAL_SIZE: u64 = 512 * 1024 * 1024;
const EVIDENCE_LIMIT: usize = 16;

struct Target<'a> {
    path: &'a Path,
    offset: u64,
    address: Option<u64>,
    report_id: Option<&'a str>,
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

fn record(
    scanner: &mut yara_x::Scanner<'_>,
    data: &[u8],
    target: Target<'_>,
    report: &mut Report,
) -> Result<(), String> {
    let results = scanner.scan(data).map_err(|error| error.to_string())?;
    let block = ByteSource {
        offset: target.offset,
        size: data.len() as u64,
        sha256: crate::storage::sha256_hex(data),
    };
    report.scanned_objects += 1;
    for rule in results.matching_rules() {
        let rule_id = format!("{}::{}", rule.namespace(), rule.identifier());
        let position = report
            .findings
            .iter()
            .position(|finding| finding.rule_id == rule_id);
        let index = match position {
            Some(index) => index,
            None if report.findings.len() < MATCH_LIMIT => {
                let metadata: BTreeMap<_, _> = rule
                    .metadata()
                    .filter_map(|(key, value)| match value {
                        yara_x::MetaValue::String(value) => {
                            Some((key.to_owned(), value.to_owned()))
                        }
                        yara_x::MetaValue::Integer(value) => {
                            Some((key.to_owned(), value.to_string()))
                        }
                        _ => None,
                    })
                    .collect();
                let meta = |name: &str| metadata.get(name).cloned().unwrap_or_default();
                let tags = rule
                    .tags()
                    .map(|tag| tag.identifier())
                    .collect::<Vec<_>>()
                    .join(" ");
                let details = format!(
                    "{}; author: {}; tags: {}",
                    meta("description"),
                    meta("author"),
                    tags
                );
                let references = metadata
                    .values()
                    .cloned()
                    .chain([tags])
                    .collect::<Vec<_>>()
                    .join(" ");
                report.findings.push(Finding {
                    rule_id,
                    title: rule.identifier().into(),
                    severity: metadata
                        .get("severity")
                        .cloned()
                        .unwrap_or_else(|| "indicator".into()),
                    source: rule.namespace().into(),
                    license: metadata
                        .get("license")
                        .or_else(|| metadata.get("malpedia_license"))
                        .cloned()
                        .unwrap_or_else(|| {
                            if rule.namespace() == "antinomie" {
                                "MIT".into()
                            } else {
                                "Not declared by rule".into()
                            }
                        }),
                    mitre: mitre_references(&references),
                    count: 0,
                    evidence: vec![],
                    details: details.chars().take(8192).collect(),
                });
                report.findings.len() - 1
            }
            None => {
                report.omitted_evidence += 1;
                report.state = State::Partial;
                continue;
            }
        };
        let finding = &mut report.findings[index];
        // One occurrence is one matched target/block, not one string match.
        finding.count += 1;
        let mut located = false;
        for pattern in rule.patterns() {
            for found in pattern.matches() {
                located = true;
                if finding.evidence.len() >= EVIDENCE_LIMIT {
                    report.omitted_evidence += 1;
                    break;
                }
                let relative = found.range().start as u64;
                finding.evidence.push(Evidence::Bytes {
                    path: target.path.to_path_buf(),
                    offset: target.offset.checked_add(relative),
                    address: target
                        .address
                        .and_then(|address| address.checked_add(relative)),
                    report_id: target.report_id.map(str::to_owned),
                    block: Some(block.clone()),
                });
            }
        }
        if !located {
            if finding.evidence.len() < EVIDENCE_LIMIT {
                finding.evidence.push(Evidence::Bytes {
                    path: target.path.to_path_buf(),
                    offset: None,
                    address: None,
                    report_id: target.report_id.map(str::to_owned),
                    block: Some(block.clone()),
                });
            } else {
                report.omitted_evidence += 1;
            }
        }
    }
    Ok(())
}

fn scan_file(
    scanner: &mut yara_x::Scanner<'_>,
    path: &Path,
    report: &mut Report,
    total: &mut u64,
) -> Result<(), String> {
    let parent = path.parent().ok_or("target has no parent")?;
    let mut file =
        crate::archive_io::open_regular(parent, path).map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if before.len() > BLOCK_SIZE as u64 || total.saturating_add(before.len()) > TOTAL_SIZE {
        return Err("recovered file exceeds the 64 MiB file / 512 MiB total budget".into());
    }
    let mut data = Vec::new();
    (&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 != before.len()
        || !same_file(
            &before,
            &file.metadata().map_err(|error| error.to_string())?,
        )
    {
        return Err("recovered file changed during scan".into());
    }
    *total += data.len() as u64;
    record(
        scanner,
        &data,
        Target {
            path,
            offset: 0,
            address: None,
            report_id: None,
        },
        report,
    )
}

fn scan_core(
    scanner: &mut yara_x::Scanner<'_>,
    path: &Path,
    virtual_addresses: bool,
    report: &mut Report,
    total: &mut u64,
    deadline: Instant,
) -> Result<(), String> {
    let mut file =
        crate::archive_io::open_regular(path.parent().ok_or("core has no parent")?, path)
            .map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    let core = crate::core_dump::CoreDump::open(path).map_err(|error| error.to_string())?;
    let current = crate::archive_io::open_regular(path.parent().ok_or("core has no parent")?, path)
        .map_err(|error| error.to_string())?
        .metadata()
        .map_err(|error| error.to_string())?;
    if !same_file(&before, &current)
        || !same_file(
            &before,
            &file.metadata().map_err(|error| error.to_string())?,
        )
    {
        return Err("Core changed while its mappings were parsed".into());
    }
    report
        .warnings
        .extend(core.warnings.iter().take(16).cloned());
    for mapping in &core.mappings {
        let available = mapping.available_size.min(mapping.captured_size);
        if available < mapping.memory_size {
            report.state = State::Partial;
        }
        let mut consumed = 0;
        while consumed < available {
            if Instant::now() >= deadline || *total >= TOTAL_SIZE {
                return Err("memory scan reached its time / 512 MiB input budget".into());
            }
            let len = (available - consumed)
                .min(BLOCK_SIZE as u64)
                .min(TOTAL_SIZE - *total) as usize;
            let offset = mapping
                .file_offset
                .checked_add(consumed)
                .ok_or("core offset overflow")?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|error| error.to_string())?;
            let mut data = vec![0; len];
            file.read_exact(&mut data)
                .map_err(|error| error.to_string())?;
            if !same_file(
                &before,
                &file.metadata().map_err(|error| error.to_string())?,
            ) {
                return Err("core changed during scan".into());
            }
            record(
                scanner,
                &data,
                Target {
                    path,
                    offset,
                    address: virtual_addresses
                        .then(|| mapping.start.checked_add(consumed))
                        .flatten(),
                    report_id: None,
                },
                report,
            )?;
            *total += len as u64;
            consumed += len as u64;
        }
        if available > BLOCK_SIZE as u64 {
            report.state = State::Partial;
        }
    }
    Ok(())
}

pub(super) fn scan(staged: &Staged, _work: &Path) -> Result<Report, String> {
    let request = &staged.request;
    let mut report = Report::empty(Engine::Yara, request.identity.clone());
    for (name, source) in super::super::rules::bundled_sources() {
        report.sources.push(Source {
            name: name.into(),
            version: "YARA-X 1.21 / bundled 0.6.2".into(),
            license: if name == "Antinomie" {
                "MIT"
            } else {
                "Per-rule licenses; see THIRD-PARTY-NOTICES.md"
            }
            .into(),
            sha256: crate::storage::sha256_hex(source.as_bytes()),
            data: "Verified executable; optional captured ELF core/RAM extents and recovered files"
                .into(),
        });
    }
    let mut extra = Vec::new();
    for source in &staged.yara_sources {
        let data = fs::read_to_string(&source.path).map_err(|error| error.to_string())?;
        report.sources.push(Source {
            name: source.name.clone(),
            version: "Local rule file".into(),
            license: "Per-rule metadata; user-selected source".into(),
            sha256: source.sha256.clone(),
            data: "Byte targets".into(),
        });
        extra.push((source.name.clone(), data));
    }
    let rules = match super::super::rules::compile_extra(&extra) {
        Ok(rules) => rules,
        Err(error) => {
            report.state = State::Unavailable;
            report.warnings.push(error);
            return Ok(report);
        }
    };
    report.scanned_rules = Some(rules.iter().count() as u64);
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(15));
    let deadline = Instant::now() + Duration::from_secs(100);
    let mut total = 0;
    let specimen = (|| {
        let directory = request.directory.join("analysis");
        let saved = super::super::jobs::open_report(&directory)?;
        let (saved, data) = super::super::specimen::read_all(&directory, &saved.id)?;
        report.source_digest = saved.specimen_sha256.clone();
        total += data.len() as u64;
        record(
            &mut scanner,
            &data,
            Target {
                path: &directory.join("specimen"),
                offset: 0,
                address: None,
                report_id: Some(&saved.id),
            },
            &mut report,
        )
    })();
    if let Err(error) = specimen {
        report.warnings.push(format!("Executable: {error}"));
        report.state = State::Partial;
    }
    if request.settings.scan_memory || request.settings.scan_recovered {
        if let Some(artifacts) = super::runner::owned_artifacts(request)? {
            if request.settings.scan_memory {
                if let Some(path) = artifacts.core_dump.as_deref()
                    && let Err(error) =
                        scan_core(&mut scanner, path, true, &mut report, &mut total, deadline)
                {
                    report.warnings.push(format!("Core: {error}"));
                    report.state = State::Partial;
                }
                if let Some(directory) = artifacts.memory_dump.as_deref()
                    && let Err(error) = scan_core(
                        &mut scanner,
                        &directory.join("memory.elf"),
                        false,
                        &mut report,
                        &mut total,
                        deadline,
                    )
                {
                    report.warnings.push(format!("RAM: {error}"));
                    report.state = State::Partial;
                }
                report.warnings.push("Memory rules run on captured contiguous blocks up to 64 MiB. Missing pages are excluded; matches spanning blocks and whole-file conditions are not complete memory coverage.".into());
                report.state = State::Partial;
            }
            if request.settings.scan_recovered {
                let mut pending = artifacts
                    .memory_dump
                    .into_iter()
                    .map(|directory| (directory, false, 0))
                    .collect::<Vec<_>>();
                let mut visited = 0;
                while let Some((path, in_files, depth)) = pending.pop() {
                    visited += 1;
                    if visited > 8192 || depth > 8 || Instant::now() >= deadline {
                        report.state = State::Partial;
                        report.warnings.push(
                            "Recovered-file traversal reached its entry/depth/time budget".into(),
                        );
                        break;
                    }
                    let metadata = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            report.state = State::Partial;
                            if report.warnings.len() < 64 {
                                report.warnings.push(error.to_string());
                            }
                            continue;
                        }
                    };
                    if metadata.is_dir() {
                        for entry in fs::read_dir(&path).map_err(|error| error.to_string())? {
                            let entry = entry.map_err(|error| error.to_string())?;
                            if pending.len() >= 8192 {
                                report.state = State::Partial;
                                break;
                            }
                            let selected = in_files || entry.file_name() == "files";
                            pending.push((entry.path(), selected, depth + 1));
                        }
                    } else if metadata.is_file()
                        && in_files
                        && let Err(error) = scan_file(&mut scanner, &path, &mut report, &mut total)
                    {
                        report.state = State::Partial;
                        if report.warnings.len() < 64 {
                            report.warnings.push(format!("{}: {error}", path.display()));
                        }
                    }
                }
            }
        } else {
            report.state = State::Partial;
            report
                .warnings
                .push("No owned memory/core artifacts recorded".into());
        }
    }
    if report.scanned_objects == 0 {
        report.state = State::Unavailable;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_evidence_keeps_offsets_and_file_level_rules_have_no_fake_offset() {
        let rules = yara_x::compile("rule located { strings: $a = \"needle\" condition: $a } rule file_only { condition: filesize == 9 }").unwrap();
        let mut scanner = yara_x::Scanner::new(&rules);
        let mut report = Report::empty(
            Engine::Yara,
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        );
        record(
            &mut scanner,
            b"xxxneedle",
            Target {
                path: Path::new("/core"),
                offset: 128,
                address: Some(4096),
                report_id: None,
            },
            &mut report,
        )
        .unwrap();
        let located = report
            .findings
            .iter()
            .find(|finding| finding.title == "located")
            .unwrap();
        assert!(matches!(
            located.evidence[0],
            Evidence::Bytes {
                offset: Some(131),
                address: Some(4099),
                ..
            }
        ));
        let file_only = report
            .findings
            .iter()
            .find(|finding| finding.title == "file_only")
            .unwrap();
        assert!(matches!(
            file_only.evidence[0],
            Evidence::Bytes {
                offset: None,
                address: None,
                ..
            }
        ));
    }
}
