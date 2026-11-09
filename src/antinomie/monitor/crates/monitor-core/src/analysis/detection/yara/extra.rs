// SPDX-License-Identifier: GPL-3.0-only
//! The inputs a YARA scan reads besides the sample and the memory the run
//! left: the library the run loaded into another program, the executables and
//! libraries the run wrote, and the layers static analysis unpacked. Each is a
//! row in the report's inputs and each match records the input it came from.
//! They share the scan's time and byte budgets; what does not fit is skipped
//! with a note.
use super::*;

/// Libraries scanned for one run.
const MAX_LIBRARIES: usize = 16;

/// What the scan shares with the other inputs.
pub(super) struct Shared<'a> {
    pub sources: &'a [String],
    pub budget: &'a mut super::super::RuleTextBudget,
    pub total: &'a mut u64,
    pub deadline: Instant,
}

fn out_of_time(shared: &Shared<'_>) -> bool {
    Instant::now() >= shared.deadline
}

fn budget_note(report: &mut Report, text: String) {
    report.state = State::Partial;
    if report.warnings.len() < 64 {
        report.warnings.push(text);
    }
}

/// The libraries the run loaded, then the files it wrote, then the layers.
pub(super) fn scan(
    scanner: &mut yara_x::Scanner<'_>,
    staged: &Staged,
    shared: &mut Shared<'_>,
    report: &mut Report,
) {
    let request = &staged.request;
    preloaded(scanner, &staged.libraries, shared, report);
    written(scanner, request, shared, report);
    layers(scanner, request, shared, report);
}

/// The libraries the run loaded into its program, from the copies staging made
/// (the sandbox cannot read the sample library itself).
fn preloaded(
    scanner: &mut yara_x::Scanner<'_>,
    libraries: &[super::super::runner::StagedLibrary],
    shared: &mut Shared<'_>,
    report: &mut Report,
) {
    for (index, staged) in libraries.iter().enumerate() {
        let library = &staged.reference;
        let shown = if library.name.is_empty() {
            library.path.clone()
        } else {
            library.name.clone()
        };
        let mut input = ScannedInput::new(InputKind::PreloadedLibrary, &library.path);
        input.name = shown;
        if index >= MAX_LIBRARIES {
            budget_note(
                report,
                format!("Preloaded libraries: only the first {MAX_LIBRARIES} were scanned"),
            );
            report.input(input.skipped("more preloaded libraries than the scan reads"));
            continue;
        }
        let Some(file) = &staged.file else {
            report.input(input.skipped(staged.reason.clone()));
            continue;
        };
        if out_of_time(shared) {
            budget_note(
                report,
                format!(
                    "Preloaded library {} skipped: YARA time budget reached",
                    library.path
                ),
            );
            report.input(input.skipped("the YARA time budget was reached"));
            continue;
        }
        match scan_file(
            scanner,
            file,
            shared.sources,
            shared.budget,
            report,
            shared.total,
            InputKind::PreloadedLibrary,
        ) {
            Ok((size, sha256)) if sha256 == library.sha256 => report.input(
                input
                    .size(size)
                    .sha256(sha256)
                    .note(format!("loaded through {}", library.via)),
            ),
            Ok(_) => {
                report.input(input.failed("the staged copy does not match the library's hash"))
            }
            Err(error) if error.contains("budget") => {
                budget_note(report, format!("{}: {error}", library.path));
                report.input(input.skipped(error));
            }
            Err(error) => report.input(input.failed(format!("YARA failed: {error}"))),
        }
    }
}

fn written(
    scanner: &mut yara_x::Scanner<'_>,
    request: &Request,
    shared: &mut Shared<'_>,
    report: &mut Report,
) {
    let Some(index) = super::super::written::read(&request.directory) else {
        return;
    };
    let folder = request.directory.join(super::super::written::FOLDER);
    for skip in &index.skipped {
        let mut input = ScannedInput::new(InputKind::WrittenFile, &skip.path);
        input.name = skip.path.clone();
        report.input(input.skipped(skip.reason.clone()));
    }
    for entry in &index.files {
        let path = folder.join(&entry.file);
        let mut input = ScannedInput::new(InputKind::WrittenFile, &path);
        input.name = entry.path.clone();
        if entry.file != entry.sha256 || entry.file.contains(['/', '.']) {
            report.input(input.skipped("the index names a file it cannot trust"));
            continue;
        }
        if out_of_time(shared) {
            budget_note(
                report,
                format!(
                    "Written file {} skipped: YARA time budget reached",
                    entry.path
                ),
            );
            report.input(input.skipped("the YARA time budget was reached"));
            continue;
        }
        scan_kept(
            scanner,
            &folder,
            &path,
            &entry.sha256,
            input,
            shared,
            report,
        );
    }
}

/// One kept file whose hash is known: skipped when it no longer matches.
fn scan_kept(
    scanner: &mut yara_x::Scanner<'_>,
    folder: &Path,
    path: &Path,
    expected: &str,
    input: ScannedInput,
    shared: &mut Shared<'_>,
    report: &mut Report,
) {
    let kind = input.kind;
    match crate::storage::sha256_file_hex(path) {
        Ok(found) if found == expected => {}
        Ok(_) => {
            report.input(input.skipped("the kept file no longer matches its hash"));
            return;
        }
        Err(error) => {
            report.input(input.skipped(format!("the kept file cannot be read ({error})")));
            return;
        }
    }
    let _ = folder;
    match scan_file(
        scanner,
        path,
        shared.sources,
        shared.budget,
        report,
        shared.total,
        kind,
    ) {
        Ok((size, sha256)) => report.input(input.size(size).sha256(sha256)),
        Err(error) => {
            if error.contains("budget") {
                budget_note(report, format!("{}: {error}", input.name));
                report.input(input.skipped(error));
            } else {
                report.input(input.failed(format!("YARA failed: {error}")));
            }
        }
    }
}

fn layers(
    scanner: &mut yara_x::Scanner<'_>,
    request: &Request,
    shared: &mut Shared<'_>,
    report: &mut Report,
) {
    let analysis = request.directory.join("analysis");
    let Ok(saved) = super::super::super::jobs::open_report(&analysis) else {
        return;
    };
    let folder = analysis
        .join("output/artifacts")
        .join(super::super::super::unpack::FOLDER);
    for layer in super::super::super::unpack::unpack_layers(&saved)
        .into_iter()
        .filter(|layer| layer.index > 0)
    {
        let name = layer.file.clone().unwrap_or_default();
        let path = folder.join(&name);
        let mut input = ScannedInput::new(InputKind::UnpackedLayer, &path);
        input.name = format!("layer {} ({})", layer.index, layer.method);
        if name != format!("layer-{}.bin", layer.index) {
            report.input(input.skipped("the report names no file for this layer"));
            continue;
        }
        if !path.is_file() {
            report.input(input.skipped("the layer file is not kept with the analysis"));
            continue;
        }
        if out_of_time(shared) {
            budget_note(
                report,
                format!(
                    "Unpacked layer {} skipped: YARA time budget reached",
                    layer.index
                ),
            );
            report.input(input.skipped("the YARA time budget was reached"));
            continue;
        }
        scan_kept(
            scanner,
            &folder,
            &path,
            &layer.sha256,
            input,
            shared,
            report,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(directory: &Path, data: &Path, rules: PathBuf) -> Staged {
        Staged {
            request: super::super::super::runner::Request {
                engine: Engine::Yara,
                identity: Identity {
                    vm_id: "v".into(),
                    boot_id: "b".into(),
                    run_id: "r".into(),
                    root_cookie: 1,
                },
                directory: directory.to_path_buf(),
                settings: Settings {
                    rules_root: data.display().to_string(),
                    ..Settings::default()
                },
                source_digest: None,
                frozen: None,
            },
            sigma_sources: vec![],
            yara_sources: vec![super::super::super::runner::RuleFile {
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
            libraries: vec![],
            unstaged: vec![],
            network_off: false,
        }
    }

    fn run_folder(name: &str) -> (PathBuf, PathBuf) {
        let directory =
            std::env::temp_dir().join(format!("ant-yara-{name}-{}", crate::storage::unique_id()));
        let data = directory.join("data");
        crate::storage::private_dir(&directory.join("analysis")).unwrap();
        crate::storage::private_dir(&directory.join("work")).unwrap();
        crate::storage::private_dir(&data).unwrap();
        let specimen = b"/bin/sh and nothing else";
        fs::write(directory.join("analysis/specimen"), specimen).unwrap();
        crate::storage::atomic_json(&directory.join("analysis/report.json"), &serde_json::json!({"id":"fixture-artifact","state":"complete","source_path":"/bin/sh","specimen_sha256":crate::storage::sha256_hex(specimen),"specimen_len":specimen.len(),"reason":null,"sections":[]})).unwrap();
        fs::write(
            directory.join("fixture.yar"),
            "rule fixture { strings: $a = \"LIBRARY_MARKER\" condition: $a }",
        )
        .unwrap();
        (directory, data)
    }

    #[test]
    fn the_preloaded_library_and_the_written_file_are_scanned_and_name_their_input() {
        let (directory, data) = run_folder("extra");
        let sha = crate::samples::Library::open(&data)
            .unwrap()
            .add_bytes(
                b"\x7fELF.. LIBRARY_MARKER",
                crate::samples::NewSample::default(),
            )
            .unwrap()
            .sha256;
        crate::storage::atomic_json(
            &directory.join("run.json"),
            &serde_json::json!({"request":{"preloaded":[
                {"sha256":sha,"name":"libhook.so","path":"/tmp/libhook.so","via":"LD_PRELOAD"},
                {"sha256":"","path":"/tmp/other.so","via":"LD_AUDIT","note":"the library did not send this file"}
            ]}}),
        )
        .unwrap();
        let written = b"\x7fELF-dropped LIBRARY_MARKER";
        let blob = crate::storage::sha256_hex(written);
        let folder = directory.join("written");
        crate::storage::private_dir(&folder).unwrap();
        fs::write(folder.join(&blob), written).unwrap();
        crate::storage::atomic_json(
            &folder.join("index.json"),
            &serde_json::json!({
                "files":[{"path":"/lib/libntp/.backup_ld.so","file":blob,"sha256":blob,"size":written.len(),"kind":"library"}],
                "skipped":[{"path":"/tmp/half.so","reason":"not rebuilt whole"}]
            }),
        )
        .unwrap();
        let mut staged = staged(&directory, &data, directory.join("fixture.yar"));
        // As staging does it: the sandboxed scan cannot read the sample library.
        staged.libraries =
            super::super::super::runner::stage_libraries(&staged.request, &directory.join("work"));
        let report = super::super::scan(&staged, &directory.join("work")).unwrap();
        let inputs = report.inputs.clone().unwrap();
        let rows: Vec<_> = inputs
            .iter()
            .map(|input| (input.kind, input.outcome))
            .collect();
        assert_eq!(
            rows,
            [
                (InputKind::Executable, InputOutcome::Succeeded),
                (InputKind::PreloadedLibrary, InputOutcome::Succeeded),
                (InputKind::PreloadedLibrary, InputOutcome::Skipped),
                (InputKind::WrittenFile, InputOutcome::Skipped),
                (InputKind::WrittenFile, InputOutcome::Succeeded),
            ],
            "{inputs:?}"
        );
        assert_eq!(inputs[1].name, "libhook.so");
        assert!(
            inputs[2].reason.contains("not a library sample"),
            "{inputs:?}"
        );
        assert_eq!(inputs[4].name, "/lib/libntp/.backup_ld.so");
        let finding = &report.findings[0];
        assert_eq!(finding.count, 2);
        let kinds: Vec<_> = finding
            .evidence
            .iter()
            .filter_map(|evidence| match evidence {
                Evidence::Bytes { input, .. } => input.as_ref().copied(),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, [InputKind::PreloadedLibrary, InputKind::WrittenFile]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_kept_file_that_no_longer_matches_its_hash_is_skipped_with_a_note() {
        let (directory, data) = run_folder("budget");
        let folder = directory.join("written");
        crate::storage::private_dir(&folder).unwrap();
        let name = "a".repeat(64);
        fs::write(folder.join(&name), b"LIBRARY_MARKER changed").unwrap();
        crate::storage::atomic_json(
            &folder.join("index.json"),
            &serde_json::json!({"files":[{"path":"/tmp/x.so","file":name,"sha256":name,"size":22,"kind":"library"}]}),
        )
        .unwrap();
        let staged = staged(&directory, &data, directory.join("fixture.yar"));
        let report = super::super::scan(&staged, &directory.join("work")).unwrap();
        let inputs = report.inputs.clone().unwrap();
        assert_eq!(inputs[1].kind, InputKind::WrittenFile);
        assert_eq!(inputs[1].outcome, InputOutcome::Skipped);
        assert!(inputs[1].reason.contains("no longer matches"), "{inputs:?}");
        assert!(report.findings.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }
}
