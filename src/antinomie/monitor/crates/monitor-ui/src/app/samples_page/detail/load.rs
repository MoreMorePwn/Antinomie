// SPDX-License-Identifier: GPL-3.0-only
//! Reading a sample, its runs and its string scan on a worker thread (moved out of `detail`).
use super::*;

/// Read the sample and its runs on every VM.
pub(in crate::app::samples_page) fn load(
    options: &BackendOptions,
    vms: &[(String, String)],
    sha256: &str,
) -> Loaded {
    let mut library = Library::open(&options.data_dir)?;
    let record = library
        .get(sha256)?
        .ok_or_else(|| "the sample is no longer in the library".to_owned())?;
    let mut runs: Vec<RunSummary> = Vec::new();
    let mut seen = Vec::new();
    let mut sent = Vec::new();
    for (vm_id, vm_name) in vms {
        let Ok(listed) = antinomie_monitor_core::recording::list_vm_runs(options, vm_id) else {
            continue;
        };
        for run in listed {
            if run
                .request
                .sample
                .as_ref()
                .is_some_and(|sample| sample.sha256 == record.sha256)
            {
                seen.push(SeenRun {
                    sha256: record.sha256.clone(),
                    vm_id: run.vm_id.clone(),
                    vm_name: vm_name.clone(),
                    run_id: run.id.clone(),
                    started_ms: run.started_ms,
                    exit: super::exit_label(&run),
                    directory: run.directory.display().to_string(),
                });
                runs.push(run);
            }
        }
    }
    library.index_runs(&seen)?;
    for other in library.list()? {
        for push in library.pushes(&other.sha256)? {
            sent.push(SentSample {
                vm_id: push.vm_id,
                path: push.path,
                sha256: other.sha256.clone(),
            });
        }
    }
    // Runs deleted through the app stay listed from their records, so the
    // numbers of the other runs do not move.
    let mut retained = std::collections::HashSet::new();
    for run in library.retained_runs(&record.sha256)? {
        if !runs
            .iter()
            .any(|live| live.id == run.id && live.vm_id == run.vm_id)
        {
            retained.insert(run.id.clone());
            runs.push(run);
        }
    }
    runs.sort_by(|a, b| {
        a.started_ms
            .cmp(&b.started_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut report = None;
    let mut entries = Vec::new();
    for (index, run) in runs.into_iter().enumerate() {
        let number = index + 1;
        if let Some(found) = run.analysis.as_ref().filter(|found| finished(found)) {
            // The newest finished report wins: runs are in start order.
            report = Some(ReportRef {
                vm_id: run.vm_id.clone(),
                run_id: run.id.clone(),
                number,
                directory: run.directory.join("analysis"),
                report: {
                    let mut report = found.clone();
                    report.settle_value_limits();
                    report
                },
            });
        }
        let deleted = retained.contains(&run.id);
        let folder = !deleted && run.directory.is_dir();
        let artifacts = if deleted {
            None
        } else {
            RunArtifacts::load(&run.directory).ok().flatten()
        };
        entries.push(RunEntry {
            number,
            run: super::super::history::listed(&run),
            folder,
            artifacts,
            digest: antinomie_monitor_core::run_digest::RunDigest::read(&run.directory),
        });
    }
    let system = system_programs(options, &entries);
    let rollup = antinomie_monitor_core::samples::rollup(
        &entries
            .iter()
            .map(|entry| antinomie_monitor_core::samples::RunInput {
                number: entry.number,
                digest: entry.digest.as_ref(),
            })
            .collect::<Vec<_>>(),
    );
    let iocs = iocs::union_of(&entries);
    entries.reverse();
    let kept = library.artifacts(&record.sha256)?;
    let outputs = output_files::read(&entries, &kept);
    let (known, links) = lineage_links(&library, &record.sha256, &entries)?;
    let archive = library.archive_path(&record.sha256)?;
    Ok(Data {
        tags: library.tags(&record.sha256)?,
        origins: library.origins(&record.sha256)?,
        aliases: library.aliases(&record.sha256)?,
        events: library.events(&record.sha256)?,
        chain: library.custody_check(&record.sha256)?,
        archived: record.removed_ms.is_none() && archive.is_file(),
        archive,
        runs: entries,
        rollup,
        iocs,
        outputs,
        notes: library.notes(&record.sha256)?,
        data_dir: options.data_dir.clone(),
        known,
        links,
        report,
        sent,
        system,
        record,
    })
}

/// The hashes of the base-image programs the runs used: those of the system
/// paths in each VM's first run with lineage that its base image has too.
pub(super) fn system_programs(
    options: &BackendOptions,
    entries: &[RunEntry],
) -> Arc<std::collections::BTreeSet<String>> {
    let mut by_vm: std::collections::BTreeMap<
        &str,
        (&RunEntry, std::collections::BTreeSet<String>),
    > = std::collections::BTreeMap::new();
    for entry in entries.iter().filter(|entry| entry.folder) {
        let Some(lineage) = entry
            .digest
            .as_ref()
            .and_then(|digest| digest.lineage.as_ref())
        else {
            continue;
        };
        let paths = lineage
            .files
            .iter()
            .map(|file| (&file.path, &file.sha256))
            .chain(lineage.execs.iter().map(|exec| (&exec.path, &exec.sha256)))
            .filter(|(path, sha)| {
                !sha.is_empty() && antinomie_monitor_core::samples::system_path(path)
            })
            .map(|(path, _)| path.clone());
        by_vm
            .entry(entry.run.vm_id.as_str())
            .or_insert_with(|| (entry, Default::default()))
            .1
            .extend(paths);
    }
    let mut system = std::collections::BTreeSet::new();
    for (entry, paths) in by_vm.values() {
        let paths: Vec<String> = paths.iter().cloned().collect();
        if let Ok(found) = antinomie_monitor_core::base_manifest::hashes_of(
            &options.data_dir,
            &entry.run.directory,
            &paths,
        ) {
            system.extend(found);
        }
    }
    Arc::new(system)
}

/// A report whose strings can be read: the analysis ended with results.
pub(super) fn finished(report: &AnalysisReport) -> bool {
    use antinomie_monitor_core::AnalysisState;
    matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    )
}

/// Scan the report's strings with the patterns as the rule manager has them.
pub(super) fn scan(data_dir: PathBuf, reference: &ReportRef, cancel: &AtomicBool) -> ScanResult {
    use antinomie_monitor_core::strings_regex::{scan_report, Config, RuleSet};
    let config = Config::load(&data_dir)?;
    let rules = RuleSet::build(&config);
    let scan = scan_report(&reference.directory, &reference.report.id, &rules, cancel)?;
    Ok(Strings {
        longest: antinomie_monitor_core::samples::longest_strings(&scan),
        matches: antinomie_monitor_core::samples::regex_matches(&scan),
        total: scan.total(),
    })
}
