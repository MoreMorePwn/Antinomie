// SPDX-License-Identifier: GPL-3.0-only
//! A headless re-export of recorded runs through the dialog's own worker
//! (`run_job`), for checking the reports against real recordings. Ignored: it
//! needs run folders on disk and is driven by environment variables.
//!
//! `ANTINOMIE_REEXPORT_RUNS` lists run folders separated by `:`,
//! `ANTINOMIE_REEXPORT_OUT` is where the reports go (one folder per run), and
//! `ANTINOMIE_REEXPORT_LIBRARY` optionally names a `library.sqlite` to read
//! the sample library from. The run folders are only read: the scan runs on a
//! scratch copy of each folder (its files, never `objects/` or `analysis/`,
//! which hold the sample's bytes), and the scratch copy is made only with
//! `create_new`, so no copy can ever be written through a link into the
//! original.
use super::*;
use std::collections::BTreeSet;

/// Copy `from` to the new file `to`; it fails if `to` exists (or is a link).
fn copy_new(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut input = std::fs::File::open(from)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    std::io::copy(&mut input, &mut output).map(|_| ())
}

/// A scratch folder that looks like `source` to the scan.
fn mirror(source: &Path, scratch: &Path) -> std::io::Result<PathBuf> {
    let target = scratch.join(source.file_name().unwrap());
    // `remove_dir_all` removes a link, never what it points at.
    let _ = std::fs::remove_dir_all(&target);
    std::fs::create_dir_all(&target)?;
    for entry in std::fs::read_dir(source)?.flatten() {
        let name = entry.file_name();
        let from = entry.path();
        let to = target.join(&name);
        let meta = entry.metadata()?;
        if meta.is_dir() {
            // The detection results are small; the rest of the directories
            // (objects, analysis, report, ioc) are not needed.
            if name == "triage-detection" {
                std::fs::create_dir_all(&to)?;
                for inner in std::fs::read_dir(&from)?.flatten() {
                    if inner.metadata()?.is_file() {
                        copy_new(&inner.path(), &to.join(inner.file_name()))?;
                    }
                }
            }
        } else {
            copy_new(&from, &to)?;
        }
    }
    Ok(target)
}

#[test]
#[ignore = "re-exports recorded runs; set ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT"]
fn reexport_recorded_runs() {
    let (Ok(runs), Ok(out)) = (
        std::env::var("ANTINOMIE_REEXPORT_RUNS"),
        std::env::var("ANTINOMIE_REEXPORT_OUT"),
    ) else {
        panic!("set ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT");
    };
    let out = PathBuf::from(out);
    let scratch = out.join(".scratch");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    // A private data directory holding a copy of the library's database.
    let data_dir = std::env::var("ANTINOMIE_REEXPORT_LIBRARY")
        .ok()
        .map(|library| {
            let dir = scratch.join("data");
            std::fs::create_dir_all(dir.join("samples")).unwrap();
            copy_new(
                Path::new(&library),
                &dir.join("samples").join("library.sqlite"),
            )
            .unwrap();
            dir
        });
    for source in runs.split(':').filter(|s| !s.is_empty()) {
        let source = PathBuf::from(source);
        let archive = mirror(&source, &scratch).unwrap();
        let run: antinomie_monitor_core::RunSummary =
            serde_json::from_slice(&std::fs::read(source.join("run.json")).unwrap()).unwrap();
        let artifacts: serde_json::Value =
            serde_json::from_slice(&std::fs::read(source.join("artifacts.json")).unwrap()).unwrap();
        let pcap = artifacts["network_captures"][0].as_str().map(PathBuf::from);
        // The request the Triage screen holds for this run, as the app sets it.
        let mut view = TriageView::default();
        view.set_launch(Some(&run));
        view.set_kernel_revision(run.environment.as_ref().and_then(|e| e.kernel_revision));
        view.scan_request.root_cookie = run.root_task_cookie;
        view.scan_request.started_ms = run.started_ms;
        view.scan_request.run_finished = true;
        view.scan_request.clock_anchor = run.clock_anchor;
        view.scan_request.data_dir = data_dir.clone();
        view.scan_request.identity = Some((run.vm_id.clone(), run.boot_id.clone(), run.id.clone()));
        let screen = view.scan_request.clone();
        let mut request = whole_run_request(&screen);
        request.run_finished = true;
        let sample = run.analysis.as_ref().and_then(|analysis| {
            Some(report::SampleInfo {
                name: Path::new(&analysis.source_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                sha256: analysis.specimen_sha256.clone()?,
                size: analysis.specimen_len,
                role: String::new(),
            })
        });
        let folder = out.join(run.id.get(..8).unwrap_or(&run.id));
        let job = Job {
            archive,
            pcap,
            request,
            choices: Choices {
                formats: Format::ALL.to_vec(),
                ..Choices::default()
            },
            run: report::RunInfo {
                vm_id: run.vm_id.clone(),
                boot_id: run.boot_id.clone(),
                run_id: run.id.clone(),
                started_ms: run.started_ms,
                finished: true,
                ..Default::default()
            },
            sample,
            clock: run.clock_anchor,
            data_dir: data_dir.clone(),
            now_ms: crate::time_format::now_ms(),
            folder,
        };
        let written = run_job(&job, &Arc::new(AtomicBool::new(false)), &|text| {
            eprintln!("{}: {text}", run.id);
        })
        .unwrap();
        for (label, path) in &written.files {
            eprintln!("{} {label}: {}", run.id, path.display());
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

/// The run facts of a recording that is not scanned (its telemetry is not
/// needed): the state, exit, command and sample as the report states them, as
/// JSON in `ANTINOMIE_REEXPORT_OUT/<run8>-facts.json`. Reads `run.json` only,
/// and the library database from a private copy.
#[test]
#[ignore = "reads recorded runs; set ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT"]
fn reexport_run_facts() {
    let (Ok(runs), Ok(out)) = (
        std::env::var("ANTINOMIE_REEXPORT_RUNS"),
        std::env::var("ANTINOMIE_REEXPORT_OUT"),
    ) else {
        panic!("set ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT");
    };
    let out = PathBuf::from(out);
    let scratch = out.join(".scratch-facts");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("samples")).unwrap();
    if let Ok(library) = std::env::var("ANTINOMIE_REEXPORT_LIBRARY") {
        copy_new(
            Path::new(&library),
            &scratch.join("samples").join("library.sqlite"),
        )
        .unwrap();
    }
    for source in runs.split(':').filter(|s| !s.is_empty()) {
        let bytes = std::fs::read(Path::new(source).join("run.json")).unwrap();
        let run: antinomie_monitor_core::RunSummary = serde_json::from_slice(&bytes).unwrap();
        let sample = run.analysis.as_ref().and_then(|analysis| {
            Some(report::SampleInfo {
                name: Path::new(&analysis.source_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                sha256: analysis.specimen_sha256.clone()?,
                size: analysis.specimen_len,
                role: String::new(),
            })
        });
        let job = Job {
            archive: PathBuf::from(source),
            pcap: None,
            request: ScanRequest::default(),
            choices: Choices::default(),
            run: report::RunInfo {
                vm_id: run.vm_id.clone(),
                boot_id: run.boot_id.clone(),
                run_id: run.id.clone(),
                started_ms: run.started_ms,
                finished: true,
                ..Default::default()
            },
            sample,
            clock: None,
            data_dir: Some(scratch.clone()),
            now_ms: crate::time_format::now_ms(),
            folder: out.clone(),
        };
        let sample = run_facts::sample_for_test(&job, &run);
        let info = run_facts::run_info(&job.run, &run, None, 0, job.now_ms);
        let facts = serde_json::json!({"run": info, "sample": sample, "command": run_facts::command_for_test(&run)});
        std::fs::write(
            out.join(format!("{}-facts.json", run.id.get(..8).unwrap_or(&run.id))),
            serde_json::to_string_pretty(&facts).unwrap(),
        )
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

/// Re-render reports an earlier build exported (their JSON holds every row,
/// with the strings the recording keeps in its object store, which a headless
/// run cannot read) through this build's document, PDF, MISP and STIX writers:
/// the run's record overlays the run facts, the Read files content is dropped
/// as the builder drops it, and the indicators are classified as the builder
/// classifies them. `ANTINOMIE_RERENDER_JSON` lists the JSON files (`:`),
/// `ANTINOMIE_REEXPORT_RUNS` the run folders (only `run.json` is read),
/// `ANTINOMIE_REEXPORT_OUT` the output folder.
#[test]
#[ignore = "re-renders earlier exports; set ANTINOMIE_RERENDER_JSON, ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT"]
fn rerender_exported_reports() {
    use antinomie_monitor_core::report::shared;
    let (Ok(files), Ok(runs), Ok(out)) = (
        std::env::var("ANTINOMIE_RERENDER_JSON"),
        std::env::var("ANTINOMIE_REEXPORT_RUNS"),
        std::env::var("ANTINOMIE_REEXPORT_OUT"),
    ) else {
        panic!("set ANTINOMIE_RERENDER_JSON, ANTINOMIE_REEXPORT_RUNS and ANTINOMIE_REEXPORT_OUT");
    };
    let out = PathBuf::from(out);
    let scratch = out.join(".scratch-rerender");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("samples")).unwrap();
    if let Ok(library) = std::env::var("ANTINOMIE_REEXPORT_LIBRARY") {
        copy_new(
            Path::new(&library),
            &scratch.join("samples").join("library.sqlite"),
        )
        .unwrap();
    }
    for file in files.split(':').filter(|s| !s.is_empty()) {
        let mut report: report::Report =
            serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        let source = runs
            .split(':')
            .map(PathBuf::from)
            .find(|dir| dir.to_string_lossy().contains(&report.run.run_id))
            .expect("a run folder for the report");
        let run: antinomie_monitor_core::RunSummary =
            serde_json::from_slice(&std::fs::read(source.join("run.json")).unwrap()).unwrap();
        let job = Job {
            archive: source.clone(),
            pcap: None,
            request: ScanRequest::default(),
            choices: Choices::default(),
            run: report.run.clone(),
            sample: report.sample.clone(),
            clock: None,
            data_dir: Some(scratch.clone()),
            now_ms: crate::time_format::now_ms(),
            folder: out.clone(),
        };
        report.sample = run_facts::sample_for_test(&job, &run);
        report.run = run_facts::run_info(&report.run, &run, None, 0, job.now_ms);
        if report.sample.as_ref().is_none_or(|s| !s.role.is_empty()) {
            report.run.command = run_facts::command_for_test(&run);
        }
        if let Some(files) = report.files.as_mut() {
            let written: BTreeSet<String> = files
                .tabs
                .iter()
                .find(|tab| tab.name == "Changed files")
                .map(|tab| {
                    tab.table
                        .rows
                        .iter()
                        .filter_map(|r| r.get(1).cloned())
                        .collect()
                })
                .unwrap_or_default();
            for tab in files.tabs.iter_mut().filter(|tab| tab.name == "Read files") {
                build::transferred(&mut tab.table, false, &written);
            }
        }
        for indicator in report.indicators.iter_mut().flatten() {
            let roles: Vec<String> = indicator.count.split(", ").map(str::to_owned).collect();
            indicator.not_shared =
                shared::not_shared_reason(&indicator.kind, &indicator.value, &roles, "");
            if indicator.base_noise.is_empty() {
                if let Some(why) = shared::resolver_noise(&indicator.kind, &indicator.value) {
                    indicator.base_noise = why.into();
                }
            }
        }
        let candidates = crate::triage::family::family_candidates(
            report
                .detections
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|d| antinomie_monitor_core::run_digest::DetectionHit {
                    engine: d.engine.clone(),
                    rule_id: d.rule_id.clone(),
                    title: d.title.clone(),
                    severity: d.severity.clone(),
                    source: d.source.clone(),
                    ..Default::default()
                })
                .collect::<Vec<_>>()
                .as_slice(),
            crate::triage::family::Bazaar::default(),
        );
        if let Some(summary) = report.summary.as_mut() {
            summary.families = candidates.iter().take(3).map(|c| c.name.clone()).collect();
            summary.family_sources = candidates
                .iter()
                .take(3)
                .map(|c| format!("{}: {}", c.name, c.source))
                .collect();
        }
        let folder = out.join(report.run.run_id.get(..8).unwrap_or("run"));
        let choices = Choices {
            formats: Format::ALL.to_vec(),
            ..Choices::default()
        };
        report::export::write(&report, &choices, &folder, None).unwrap();
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

/// What the Export report dialog writes for one saved run, through the
/// dialog's own steps: the run as Run History lists it, the Triage input the
/// app makes for the selected run of a stopped VM, the app's default Triage
/// settings, then `open_report` and `start_report` with every format, and the
/// window until its worker is done. For comparing with `antinomie-cli report`
/// (card P2-4). `ANTINOMIE_DIALOG_DATA` is the data directory,
/// `ANTINOMIE_DIALOG_RUN` the run id and `ANTINOMIE_DIALOG_OUT` the folder.
/// The scan reads the guest's user names from the base disk through the disk
/// reader, a worker role of the running program, which this test binary does
/// not host: `ANTINOMIE_DIALOG_WORKER` names a program that does (the built
/// `antinomie-monitor`), and the names are read with it, as the window would.
#[test]
#[ignore = "exports a saved run; set ANTINOMIE_DIALOG_DATA, ANTINOMIE_DIALOG_RUN and ANTINOMIE_DIALOG_OUT"]
fn export_a_saved_run_as_the_dialog_does() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("set {name}"));
    let data = PathBuf::from(var("ANTINOMIE_DIALOG_DATA"));
    let run_id = var("ANTINOMIE_DIALOG_RUN");
    let out = var("ANTINOMIE_DIALOG_OUT");
    let options = antinomie_monitor_core::BackendOptions {
        data_dir: data.clone(),
        ..Default::default()
    };
    let run = antinomie_monitor_core::recording::read_only_locations(&options)
        .unwrap()
        .into_iter()
        .flat_map(|location| {
            antinomie_monitor_core::recording::list_vm_runs(&options, &location.vm_id)
                .unwrap_or_default()
        })
        .find(|run| run.id == run_id)
        .expect("the run is in the history");
    let pcap = match antinomie_triage::SavedCapture::of(&run) {
        antinomie_triage::SavedCapture::Found { file, .. } => Some(file),
        _ => None,
    };
    let input = TriageInput {
        pcap_open: false,
        run_finished: true,
        current_boot: false,
        ..TriageInput::for_run(&run, pcap.as_deref())
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut view = TriageView::default();
    view.refresh_seconds = 3600;
    view.set_address_lookup(AddressLookup::default());
    view.set_data_dir(&data);
    view.set_write_limits(
        antinomie_monitor_core::settings::EngineSettings::default().write_limits(),
    );
    view.set_page_rows(STORED_ROWS as u32);
    view.set_rebuild_limits(DEFAULT_REBUILD_FILE_MIB, DEFAULT_REBUILD_RUN_MIB);
    view.set_launch(Some(&run));
    view.set_kernel_revision(ScanRequest::kernel_revision_of(&run));
    if let Ok(worker) = std::env::var("ANTINOMIE_DIALOG_WORKER") {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(run.directory.join("manifest.json")).unwrap())
                .unwrap();
        let base = data
            .join("bases")
            .join(manifest["disk_base_identity"].as_str().unwrap());
        let image = antinomie_monitor_core::storage::Bundle::load(&base)
            .unwrap()
            .base_disk;
        let names =
            antinomie_monitor_core::guest_names::read_base(&image, Some(PathBuf::from(worker)))
                .unwrap();
        view.scan_request.guest_names = Some(Arc::new(names));
    }
    let frame = |view: &mut TriageView, input: TriageInput<'_>| {
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            view.tick(root.ctx(), input);
            view.show_report_dialog(root.ctx());
        });
    };
    let deadline = Instant::now() + Duration::from_secs(600);
    while view.scan.is_none() || view.scan_rx.is_some() {
        frame(&mut view, input);
        assert!(Instant::now() < deadline, "the index never arrived");
        std::thread::sleep(Duration::from_millis(50));
    }
    view.set_report_choices(Choices {
        formats: Format::ALL.to_vec(),
        folder: out,
        ..Choices::default()
    });
    view.open_report(&input);
    let _ = ctx.run_ui(egui::RawInput::default(), |root| {
        view.start_report(root.ctx());
    });
    while matches!(view.report.state, State::Running { .. }) {
        frame(&mut view, input);
        assert!(Instant::now() < deadline, "the export never ended");
        std::thread::sleep(Duration::from_millis(50));
    }
    match &view.report.state {
        State::Done(written) => {
            for (label, path) in &written.files {
                eprintln!("{label}: {}", path.display());
            }
        }
        State::Failed(error) => panic!("the export failed: {error}"),
        _ => panic!("the export did not run"),
    }
}
