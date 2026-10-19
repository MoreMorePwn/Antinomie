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

mod physical;

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
    sources: &[String],
    budget: &mut super::RuleTextBudget,
    report: &mut Report,
) -> Result<String, String> {
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
                let namespace = rule.namespace();
                let body = namespace
                    .strip_prefix('s')
                    .and_then(|index| index.parse::<usize>().ok())
                    .and_then(|index| sources.get(index))
                    .and_then(|text| crate::ruleset::yara_rule_source(text, rule.identifier()));
                report.findings.push(Finding {
                    rule_id,
                    title: rule.identifier().into(),
                    severity: metadata
                        .get("severity")
                        .cloned()
                        .unwrap_or_else(|| "indicator".into()),
                    source: namespace.into(),
                    license: metadata
                        .get("license")
                        .or_else(|| metadata.get("malpedia_license"))
                        .or_else(|| metadata.get(crate::ruleset::REPOSITORY_LICENSE_META))
                        .cloned()
                        .unwrap_or_else(|| {
                            if namespace == "antinomie" {
                                "MIT".into()
                            } else {
                                "Not declared by rule".into()
                            }
                        }),
                    author: meta("author"),
                    mitre: mitre_references(&references),
                    count: 0,
                    evidence: vec![],
                    events: vec![],
                    details: details.chars().take(8192).collect(),
                    rule_text: budget.take(body.as_deref().unwrap_or("")),
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
    Ok(block.sha256)
}

/// Scans one recovered file whole; returns its size and SHA-256.
fn scan_file(
    scanner: &mut yara_x::Scanner<'_>,
    path: &Path,
    sources: &[String],
    budget: &mut super::RuleTextBudget,
    report: &mut Report,
    total: &mut u64,
) -> Result<(u64, String), String> {
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
    let sha256 = record(
        scanner,
        &data,
        Target {
            path,
            offset: 0,
            address: None,
            report_id: None,
        },
        sources,
        budget,
        report,
    )?;
    Ok((data.len() as u64, sha256))
}

fn memory_blocks(path: &Path, virtual_addresses: bool) -> u64 {
    let Ok(mut file) = crate::archive_io::open_regular(path.parent().unwrap_or(path), path) else {
        return 0;
    };
    let Ok(mappings) = memory_mappings(path, &mut file, virtual_addresses) else {
        return 0;
    };
    mappings
        .iter()
        .map(|mapping| {
            let available = mapping.available_size.min(mapping.captured_size);
            if available == 0 {
                0
            } else {
                available.div_ceil(BLOCK_SIZE as u64)
            }
        })
        .sum()
}

fn memory_mappings(
    path: &Path,
    file: &mut fs::File,
    virtual_addresses: bool,
) -> Result<Vec<crate::core_dump::CoreMapping>, String> {
    if virtual_addresses {
        crate::core_dump::CoreDump::open(path)
            .map(|core| core.mappings)
            .map_err(|error| error.to_string())
    } else {
        physical::mappings(file).map_err(|error| error.to_string())
    }
}

/// What the core and RAM passes share: rule sources, input budgets and block progress.
struct MemoryPass<'a> {
    sources: &'a [String],
    budget: &'a mut super::RuleTextBudget,
    total: &'a mut u64,
    deadline: Instant,
    progress: &'a mut super::runner::ProgressWriter,
    block_index: u64,
    block_total: u64,
    /// Mapped ranges of the current dump that were not captured.
    gaps: u64,
}

impl MemoryPass<'_> {
    fn next_block(&mut self) {
        self.block_index += 1;
        let target = ScanTarget::MemoryBlock {
            index: self.block_index,
            total: self.block_total.max(self.block_index),
        };
        if self.block_index == 1 {
            self.progress.stage(target);
        } else {
            self.progress.note(target);
        }
    }
}

fn scan_core(
    scanner: &mut yara_x::Scanner<'_>,
    path: &Path,
    virtual_addresses: bool,
    report: &mut Report,
    pass: &mut MemoryPass<'_>,
) -> Result<(), String> {
    let mut file =
        crate::archive_io::open_regular(path.parent().ok_or("core has no parent")?, path)
            .map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    let (mappings, warnings) = if virtual_addresses {
        let core = crate::core_dump::CoreDump::open(path).map_err(|error| error.to_string())?;
        (core.mappings, core.warnings)
    } else {
        (
            physical::mappings(&mut file).map_err(|error| error.to_string())?,
            vec![],
        )
    };
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
    report.warnings.extend(warnings.into_iter().take(16));
    for mapping in &mappings {
        let available = mapping.available_size.min(mapping.captured_size);
        if available < mapping.memory_size {
            pass.gaps += 1;
        }
        let mut consumed = 0;
        while consumed < available {
            if Instant::now() >= pass.deadline || *pass.total >= TOTAL_SIZE {
                return Err("memory scan reached its time / 512 MiB input budget".into());
            }
            pass.next_block();
            let len = (available - consumed)
                .min(BLOCK_SIZE as u64)
                .min(TOTAL_SIZE - *pass.total) as usize;
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
                pass.sources,
                pass.budget,
                report,
            )?;
            *pass.total += len as u64;
            consumed += len as u64;
        }
    }
    Ok(())
}

pub(super) fn scan(staged: &Staged, work: &Path) -> Result<Report, String> {
    let request = &staged.request;
    let mut report = Report::empty(Engine::Yara, request.identity.clone());
    report.selection = staged.selection.clone();
    if staged.no_rules || staged.yara_sources.is_empty() && staged.warnings.is_empty() {
        report.state = State::NoRules;
        report.warnings.push("No rules enabled".into());
        return Ok(report);
    }
    if staged.yara_sources.is_empty() {
        report.state = State::Unavailable;
        report
            .warnings
            .push("No compatible YARA rules were evaluated.".into());
        return Ok(report);
    }
    let mut extra = Vec::new();
    for source in &staged.yara_sources {
        let data = fs::read_to_string(&source.path).map_err(|error| error.to_string())?;
        report.sources.push(Source {
            name: source.name.clone(),
            version: staged.selection.clone(),
            license: "Per-rule metadata; user-selected source".into(),
            sha256: source.sha256.clone(),
            data: "Verified sample bytes; optional captured core, guest memory and recovered files"
                .into(),
        });
        extra.push((source.name.clone(), data));
    }
    let rules = match super::super::rules::compile_sources(&extra, staged.include_dir.as_deref()) {
        Ok(rules) => rules,
        Err(error) => {
            report.state = State::Unavailable;
            report.warnings.push(error);
            return Ok(report);
        }
    };
    let loaded = rules.iter().count() as u64;
    report.scanned_rules = Some(loaded);
    let sources: Vec<String> = extra.iter().map(|(_, text)| text.clone()).collect();
    let mut budget = super::RuleTextBudget::new();
    let mut progress = super::runner::ProgressWriter::new(work);
    progress.set_rules(loaded);
    progress.stage(ScanTarget::Specimen);
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(15));
    let deadline = Instant::now() + Duration::from_secs(100);
    let mut total = 0;
    let analysis = request.directory.join("analysis");
    let mut executable = ScannedInput::new(InputKind::Executable, &analysis);
    // Whether the engine got as far as scanning: a specimen that could not be
    // read is skipped, one the engine failed on is failed.
    let mut reached_engine = false;
    let specimen = (|| {
        let directory = &analysis;
        let saved = super::super::jobs::open_report(directory)?;
        let (saved, data) = super::super::specimen::read_all(directory, &saved.id)?;
        report.source_digest = saved.specimen_sha256.clone();
        executable.name = Path::new(&saved.source_path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        total += data.len() as u64;
        reached_engine = true;
        let sha256 = record(
            &mut scanner,
            &data,
            Target {
                path: &directory.join("specimen"),
                offset: 0,
                address: None,
                report_id: Some(&saved.id),
            },
            &sources,
            &mut budget,
            &mut report,
        )?;
        Ok::<_, String>((data.len() as u64, saved.specimen_sha256.unwrap_or(sha256)))
    })();
    match specimen {
        Ok((size, sha256)) => report.input(executable.size(size).sha256(sha256)),
        Err(error) => {
            report.warnings.push(format!("Executable: {error}"));
            report.input(if reached_engine {
                executable.failed(format!("YARA failed: {error}"))
            } else {
                executable.skipped(error)
            });
        }
    }
    let scanning = request.settings.scan_memory || request.settings.scan_recovered;
    let artifacts = if scanning {
        match super::runner::owned_artifacts(request) {
            Ok(value) => value,
            Err(error) => {
                progress.flush();
                return Err(error);
            }
        }
    } else {
        super::runner::owned_artifacts(request).ok().flatten()
    };
    if let Some(artifacts) = &artifacts {
        // What this run has but the scan options left out.
        if !request.settings.scan_memory {
            for (kind, path) in [
                (InputKind::CoreDump, artifacts.core_dump.clone()),
                (
                    InputKind::MemoryDump,
                    artifacts
                        .memory_dump
                        .as_ref()
                        .map(|dir| dir.join("memory.elf")),
                ),
            ] {
                if let Some(path) = path {
                    report.input(
                        ScannedInput::new(kind, path)
                            .sized()
                            .skipped("memory scanning is off"),
                    );
                }
            }
        }
        if !request.settings.scan_recovered
            && let Some(directory) = &artifacts.memory_dump
        {
            report.input(
                ScannedInput::new(InputKind::RecoveredFile, directory.join("files"))
                    .skipped("recovered-file scanning is off"),
            );
        }
    }
    if scanning {
        if let Some(artifacts) = artifacts {
            if request.settings.scan_memory {
                let mut block_total = 0u64;
                if let Some(path) = artifacts.core_dump.as_deref() {
                    block_total += memory_blocks(path, true);
                }
                if let Some(directory) = artifacts.memory_dump.as_deref() {
                    block_total += memory_blocks(&directory.join("memory.elf"), false);
                }
                let mut pass = MemoryPass {
                    sources: &sources,
                    budget: &mut budget,
                    total: &mut total,
                    deadline,
                    progress: &mut progress,
                    block_index: 0,
                    block_total,
                    gaps: 0,
                };
                let dumps = [
                    (
                        InputKind::CoreDump,
                        artifacts.core_dump.clone(),
                        true,
                        "Core",
                    ),
                    (
                        InputKind::MemoryDump,
                        artifacts
                            .memory_dump
                            .as_ref()
                            .map(|dir| dir.join("memory.elf")),
                        false,
                        "RAM",
                    ),
                ];
                for (kind, path, virtual_addresses, label) in dumps {
                    let Some(path) = path else { continue };
                    let first = pass.block_index;
                    pass.gaps = 0;
                    let result = scan_core(
                        &mut scanner,
                        &path,
                        virtual_addresses,
                        &mut report,
                        &mut pass,
                    );
                    if let Err(error) = &result {
                        report.warnings.push(format!("{label}: {error}"));
                    }
                    let blocks = pass.block_index - first;
                    report.input(inputs::memory_input(
                        kind, &path, &result, blocks, pass.gaps,
                    ));
                }
                report.warnings.push("Memory rules run on captured contiguous blocks up to 64 MiB. Missing pages are excluded; matches spanning blocks and whole-file conditions are not complete memory coverage.".into());
            }
            if request.settings.scan_recovered {
                let mut pending = artifacts
                    .memory_dump
                    .clone()
                    .into_iter()
                    .map(|directory| (directory, false, 0))
                    .collect::<Vec<_>>();
                let mut visited = 0;
                let mut files = Vec::new();
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
                    } else if metadata.is_file() && in_files {
                        files.push(path);
                    }
                }
                let file_total = files.len() as u64;
                if files.is_empty()
                    && let Some(directory) = &artifacts.memory_dump
                {
                    report.input(
                        ScannedInput::new(InputKind::RecoveredFile, directory.join("files"))
                            .skipped("the memory dump has no recovered files"),
                    );
                }
                for (index, path) in files.iter().enumerate() {
                    let seen = index as u64 + 1;
                    if seen == 1 {
                        progress.stage(ScanTarget::RecoveredFile {
                            index: seen,
                            total: file_total.max(1),
                        });
                    } else {
                        progress.note(ScanTarget::RecoveredFile {
                            index: seen,
                            total: file_total,
                        });
                    }
                    let input = ScannedInput::new(InputKind::RecoveredFile, path);
                    match scan_file(
                        &mut scanner,
                        path,
                        &sources,
                        &mut budget,
                        &mut report,
                        &mut total,
                    ) {
                        Ok((size, sha256)) => report.input(input.size(size).sha256(sha256)),
                        Err(error) => {
                            if report.warnings.len() < 64 {
                                report.warnings.push(format!("{}: {error}", path.display()));
                            }
                            report.input(input.sized().failed(format!("YARA failed: {error}")));
                        }
                    }
                }
            }
        } else {
            report
                .warnings
                .push("No owned memory/core artifacts recorded".into());
            for (on, kind, name) in [
                (
                    request.settings.scan_memory,
                    InputKind::MemoryDump,
                    "memory",
                ),
                (
                    request.settings.scan_recovered,
                    InputKind::RecoveredFile,
                    "files",
                ),
            ] {
                if on {
                    report.input(
                        ScannedInput::new(kind, request.directory.join(name))
                            .skipped("no memory dump or core file for this run"),
                    );
                }
            }
        }
    }
    if report.scanned_objects == 0 {
        report.state = State::Unavailable;
    }
    progress.flush();
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
        let mut budget = super::RuleTextBudget::new();
        record(
            &mut scanner,
            b"xxxneedle",
            Target {
                path: Path::new("/core"),
                offset: 128,
                address: Some(4096),
                report_id: None,
            },
            &[],
            &mut budget,
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

    #[test]
    fn scans_list_each_input_with_its_outcome() {
        let directory =
            std::env::temp_dir().join(format!("ant-yara-inputs-{}", crate::storage::unique_id()));
        let memory = directory.join("memory");
        crate::storage::private_dir(&memory.join("files")).unwrap();
        crate::storage::private_dir(&directory.join("analysis")).unwrap();
        crate::storage::private_dir(&directory.join("work")).unwrap();
        fs::write(memory.join("memory.elf"), b"not scanned").unwrap();
        fs::write(
            memory.join("files/recovered.txt"),
            b"recovered FIXTURE_MARKER",
        )
        .unwrap();
        let specimen = b"xxxFIXTURE_MARKER";
        fs::write(directory.join("analysis/specimen"), specimen).unwrap();
        crate::storage::atomic_json(&directory.join("analysis/report.json"), &serde_json::json!({"id":"fixture-artifact","state":"complete","source_path":"/fixture/sample","specimen_sha256":crate::storage::sha256_hex(specimen),"specimen_len":specimen.len(),"reason":null,"sections":[]})).unwrap();
        crate::storage::atomic_json(&directory.join("artifacts.json"), &serde_json::json!({"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[],"network_state":"complete","memory_dump":memory,"memory_state":"complete","core_dump":null,"core_state":"complete","issues":[]})).unwrap();
        let rules = directory.join("fixture.yar");
        fs::write(
            &rules,
            "rule fixture { strings: $a = \"FIXTURE_MARKER\" condition: $a }",
        )
        .unwrap();
        let staged = Staged {
            request: super::super::runner::Request {
                engine: Engine::Yara,
                identity: Identity {
                    vm_id: "v".into(),
                    boot_id: "b".into(),
                    run_id: "r".into(),
                    root_cookie: 1,
                },
                directory: directory.clone(),
                settings: Settings {
                    scan_recovered: true,
                    ..Settings::default()
                },
                source_digest: None,
                frozen: None,
            },
            sigma_sources: vec![],
            yara_sources: vec![super::super::runner::RuleFile {
                path: rules,
                name: "fixture.yar".into(),
                sha256: "0".repeat(64),
            }],
            ids_sources: vec![],
            captures: vec![],
            journal: None,
            warnings: vec![],
            selection: String::new(),
            no_rules: false,
            include_dir: None,
            skipped_inputs: vec![],
            unstaged: vec![],
        };
        let report = scan(&staged, &directory.join("work")).unwrap();
        let inputs = report.inputs.clone().unwrap();
        let kinds: Vec<_> = inputs
            .iter()
            .map(|input| (input.kind, input.outcome))
            .collect();
        assert_eq!(
            kinds,
            [
                (InputKind::Executable, InputOutcome::Succeeded),
                (InputKind::MemoryDump, InputOutcome::Skipped),
                (InputKind::RecoveredFile, InputOutcome::Succeeded),
            ],
            "{inputs:?}"
        );
        assert_eq!(inputs[0].name, "sample");
        assert_eq!(
            inputs[0].sha256.as_deref(),
            Some(crate::storage::sha256_hex(specimen).as_str())
        );
        assert_eq!(inputs[0].size, Some(specimen.len() as u64));
        assert_eq!(inputs[1].reason, "memory scanning is off");
        assert_eq!(inputs[2].path, memory.join("files/recovered.txt"));
        assert_eq!(inputs[2].size, Some(24));
        assert_eq!(report.findings[0].count, 2);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_match_keeps_the_original_yara_rule() {
        let source = "rule other { condition: false }\nrule located { strings: $a = \"needle\" condition: $a }\n";
        let rules = super::super::super::rules::compile_sources(
            &[("local.yar".into(), source.into())],
            None,
        )
        .unwrap();
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
        let mut budget = super::super::RuleTextBudget::new();
        record(
            &mut scanner,
            b"needle",
            Target {
                path: Path::new("/specimen"),
                offset: 0,
                address: None,
                report_id: None,
            },
            &[source.into()],
            &mut budget,
            &mut report,
        )
        .unwrap();
        let located = report
            .findings
            .iter()
            .find(|finding| finding.title == "located")
            .unwrap();
        assert!(located.rule_text.contains("rule located"));
        assert!(!located.rule_text.contains("rule other"));
        assert!(located.details.contains("author"));
    }
}
