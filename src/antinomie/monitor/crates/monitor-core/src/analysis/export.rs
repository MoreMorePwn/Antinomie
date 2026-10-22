// SPDX-License-Identifier: GPL-3.0-only
//! Export retained evidence on an archive worker, never the rendering thread.
use super::{AnalysisData, AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

/// Native project retention bound, in octets; included in the job reservation.
pub(crate) const PROJECT_MAX_SIZE: u64 = 256 * 1024 * 1024;
const PROJECT_MAX_MEMBERS: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalysisExportFormat {
    Text,
    Json,
    /// A directory containing the actual .gpr and .rep project database.
    GhidraProject,
}

fn checked_report(directory: &Path, report_id: &str) -> Result<AnalysisReport, String> {
    let report = super::open_report(directory)?;
    if report.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    Ok(report)
}

/// Export every retained row, independent of the current preview/search/page.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory`, `report_id` | Retained report location and expected identity. |
/// | `kind` | One category, or all categories when absent. |
/// | `format` | Plain text, complete structured JSON, or native Ghidra bundle. |
/// | `destination` | New output file for text/JSON; new directory for Ghidra. |
///
/// Returns the published path. Existing destinations are never overwritten.
/// Partial reports remain explicitly marked. Run on a background worker.
/// Errors include missing/corrupt listings, unsafe project members, and IO failures.
pub fn export_analysis(
    directory: &Path,
    report_id: &str,
    kind: Option<AnalysisKind>,
    format: AnalysisExportFormat,
    destination: &Path,
) -> Result<PathBuf, String> {
    let report = checked_report(directory, report_id)?;
    if format == AnalysisExportFormat::GhidraProject {
        let project = retained_ghidra_project(directory, report_id)?;
        let source = project.parent().ok_or("Ghidra project has no directory")?;
        copy_project(source, destination)?;
        return Ok(destination.to_owned());
    }
    let sections: Vec<_> = report
        .sections
        .iter()
        .filter(|s| kind.is_none_or(|k| k == s.kind))
        .collect();
    if sections.is_empty() {
        return Err("category not in this report".into());
    }
    // Validate complete listings before publishing any output, using the same
    // category/row/size rules as adoption. Rows are streamed again for writing.
    for section in &sections {
        if let Some(listing) = &section.listing {
            super::listing::validate(
                &directory
                    .join("listings")
                    .join(super::listing::file_name(section.kind)),
                section.kind,
                listing,
                report.specimen_len,
            )?;
        }
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|e| format!("export {}: {e}", destination.display()))?;
    let mut out = BufWriter::new(file);
    let result: Result<(), String> = (|| {
        if format == AnalysisExportFormat::Json {
            // Keep metadata plus preview in `report`, complete evidence in
            // `sections`. Consumers need not guess whether a preview is full.
            out.write_all(b"{\"report\":").map_err(|e| e.to_string())?;
            serde_json::to_writer(&mut out, &report).map_err(|e| e.to_string())?;
            out.write_all(b",\"sections\":[")
                .map_err(|e| e.to_string())?;
        } else {
            writeln!(
                out,
                "Antinomie static analysis\nReport: {}\nSource: {}\nState: {:?}\nSHA-256: {}",
                report.id,
                report.source_path,
                report.state,
                report.specimen_sha256.as_deref().unwrap_or("Unavailable")
            )
            .map_err(|e| e.to_string())?;
            if let Some(reason) = &report.reason {
                writeln!(out, "Reason: {reason}").map_err(|e| e.to_string())?;
            }
        }
        for (index, section) in sections.iter().enumerate() {
            if format == AnalysisExportFormat::Json {
                if index > 0 {
                    out.write_all(b",").map_err(|e| e.to_string())?;
                }
                out.write_all(b"{\"kind\":").map_err(|e| e.to_string())?;
                serde_json::to_writer(&mut out, &section.kind).map_err(|e| e.to_string())?;
                out.write_all(b",\"state\":").map_err(|e| e.to_string())?;
                serde_json::to_writer(&mut out, &section.state).map_err(|e| e.to_string())?;
                out.write_all(b",\"summary\":").map_err(|e| e.to_string())?;
                serde_json::to_writer(&mut out, &section.summary).map_err(|e| e.to_string())?;
                out.write_all(b",\"rows\":[").map_err(|e| e.to_string())?;
            } else {
                writeln!(
                    out,
                    "\n{} ({:?})\n{}",
                    section.kind.label(),
                    section.state,
                    section.summary
                )
                .map_err(|e| e.to_string())?;
                if section.listing.as_ref().is_some_and(|l| l.truncated) {
                    writeln!(out, "[Partial listing: only retained evidence is exported]")
                        .map_err(|e| e.to_string())?;
                }
            }
            let mut first = true;
            visit_rows(directory, section, |entry| {
                if format == AnalysisExportFormat::Json {
                    if !first {
                        out.write_all(b",").map_err(|e| e.to_string())?;
                    }
                    serde_json::to_writer(&mut out, entry).map_err(|e| e.to_string())?;
                } else {
                    text_row(&mut out, entry).map_err(|e| e.to_string())?;
                }
                first = false;
                Ok(())
            })?;
            if format == AnalysisExportFormat::Json {
                out.write_all(b"]}").map_err(|e| e.to_string())?;
            }
        }
        if format == AnalysisExportFormat::Json {
            out.write_all(b"]}\n").map_err(|e| e.to_string())?;
        }
        out.flush()
            .and_then(|()| out.get_ref().sync_all())
            .map_err(|e| format!("export flush: {e}"))
    })();
    drop(out);
    if let Err(error) = result {
        return match fs::remove_file(destination) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; partial export cleanup failed: {cleanup}")),
        };
    }
    Ok(destination.to_owned())
}

fn visit_rows(
    directory: &Path,
    section: &AnalysisSection,
    mut visit: impl FnMut(&AnalysisEntry) -> Result<(), String>,
) -> Result<(), String> {
    if section.listing.is_some() {
        let path = directory
            .join("listings")
            .join(super::listing::file_name(section.kind));
        let file = crate::archive_io::open_regular(directory, &path).map_err(|e| e.to_string())?;
        for line in BufReader::new(file).split(b'\n') {
            let entry = serde_json::from_slice(&line.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            visit(&entry)?;
        }
    } else {
        for entry in &section.entries {
            visit(entry)?;
        }
    }
    Ok(())
}

fn text_row(out: &mut impl Write, entry: &AnalysisEntry) -> std::io::Result<()> {
    match entry.record.as_ref().map(|r| &r.data) {
        Some(AnalysisData::SourceLine { .. }) => writeln!(out, "{}", entry.value),
        Some(AnalysisData::Instruction {
            address,
            bytes,
            mnemonic,
            operands,
            ..
        }) => writeln!(out, "{address:016x}  {bytes:<24}  {mnemonic:<8} {operands}"),
        Some(AnalysisData::Function { name, address, .. }) => {
            writeln!(out, "\n// {name} @ 0x{address:x}")
        }
        _ => match entry.offset {
            Some(offset) => writeln!(out, "0x{offset:x}\t{}\t{}", entry.label, entry.value),
            None => writeln!(out, "{}\t{}", entry.label, entry.value),
        },
    }
}

/// Validate the retained native project. Older/radare2 reports can have text
/// without a Ghidra project and return a useful error instead of fake .gpr data.
pub fn retained_ghidra_project(directory: &Path, report_id: &str) -> Result<PathBuf, String> {
    checked_report(directory, report_id)?;
    let root = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    let project_dir = directory.join("output/artifacts/ghidra");
    let candidate = fs::canonicalize(&project_dir).map_err(|_| "no retained Ghidra project; older reports and radare2 results can still be exported as text".to_string())?;
    if !candidate.starts_with(root) {
        return Err("Ghidra project escapes its report directory".into());
    }
    project_inventory(&project_dir)?;
    Ok(candidate.join("antinomie.gpr"))
}

/// Construct the GUI command with literal arguments and the managed JDK when
/// needed. `tools_directory` is `<data>/tools`, not the sandbox mount path.
/// The caller spawns this command only on explicit user request.
pub fn ghidra_open_command(
    directory: &Path,
    report_id: &str,
    tools_directory: &Path,
) -> Result<Command, String> {
    let project = retained_ghidra_project(directory, report_id)?;
    ghidra_open_exported_project(&project, tools_directory)
}

/// Open a validated exported working copy, preserving the retained evidence.
///
/// | Argument | Meaning |
/// |---|---|
/// | `project` | The exported `antinomie.gpr` with its adjacent `.rep` database. |
/// | `tools_directory` | `<data>/tools`, for the managed GUI and JDK. |
///
/// Returns a literal-argument command; validation/tool errors are returned.
/// The caller spawns it on explicit request, outside the rendering thread.
pub fn ghidra_open_exported_project(
    project: &Path,
    tools_directory: &Path,
) -> Result<Command, String> {
    if project.file_name() != Some(std::ffi::OsStr::new("antinomie.gpr")) {
        return Err("expected the exported native antinomie.gpr project".into());
    }
    project_inventory(project.parent().ok_or("Ghidra project has no directory")?)?;
    let project = fs::canonicalize(project).map_err(|e| e.to_string())?;
    let managed = tools_directory.join("ghidra/ghidra/ghidraRun");
    let system = crate::analysis_tools::GHIDRA_SYSTEM
        .iter()
        .filter_map(|p| Path::new(p).parent()?.parent().map(|p| p.join("ghidraRun")))
        .find(|p| p.is_file());
    let prefer_managed = std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed");
    let launcher = if prefer_managed && managed.is_file() {
        managed.clone()
    } else {
        system
            .or_else(|| managed.is_file().then(|| managed.clone()))
            .ok_or("Ghidra GUI not installed; install Ghidra from Tools > Analysis tools")?
    };
    let mut command = Command::new(&launcher);
    command.arg(project);
    if launcher == managed {
        command.env("JAVA_HOME", tools_directory.join("ghidra/jdk"));
    }
    Ok(command)
}

fn project_inventory(source: &Path) -> Result<Vec<(PathBuf, Option<u64>)>, String> {
    if !source.join("antinomie.gpr").is_file() || !source.join("antinomie.rep").is_dir() {
        return Err("Ghidra native project is incomplete (.gpr or .rep missing)".into());
    }
    let mut files = Vec::new();
    let mut pending = vec![source.to_owned()];
    let mut total = 0u64;
    let mut members = 0usize;
    while let Some(directory) = pending.pop() {
        if fs::symlink_metadata(&directory)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("symlink in Ghidra project".into());
        }
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            members += 1;
            if members > PROJECT_MAX_MEMBERS {
                return Err("Ghidra project member bound exceeded".into());
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if metadata.is_dir() {
                files.push((entry.path(), None));
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or("Ghidra project size overflow")?;
                if total > PROJECT_MAX_SIZE {
                    return Err("Ghidra project exceeds 256 MiB retention bound".into());
                }
                files.push((entry.path(), Some(metadata.len())));
            } else {
                return Err("Ghidra project contains a symlink or special file".into());
            }
        }
    }
    Ok(files)
}

/// Copy only a bounded complete native project, preserving empty directories.
/// Destination must be new; cleanup on failure never touches existing data.
/// Export a validated native Ghidra project without changing its retained source.
///
/// | Item | Purpose |
/// |---|---|
/// | `source` | Directory containing `antinomie.gpr` and its `.rep` database. |
/// | `destination` | New destination directory; existing paths are rejected. |
/// | Return | Success after a bounded copy, or a validation/copy/cleanup error. |
///
/// The copied project's owner is set to this host account so Ghidra can open
/// it, including older projects produced without a sandbox account mapping.
pub fn copy_project(source: &Path, destination: &Path) -> Result<(), String> {
    let files = project_inventory(source)?;
    let source_root = fs::canonicalize(source).map_err(|e| e.to_string())?;
    let destination_parent = fs::canonicalize(
        destination
            .parent()
            .ok_or("project destination has no parent")?,
    )
    .map_err(|e| e.to_string())?;
    if destination_parent.starts_with(&source_root) {
        return Err("project export destination must be outside the retained project".into());
    }
    fs::create_dir(destination).map_err(|e| format!("Ghidra export: {e}"))?;
    let result = (|| {
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        for (path, expected_len) in files {
            let relative = path.strip_prefix(source).map_err(|e| e.to_string())?;
            let target = destination.join(relative);
            let Some(expected_len) = expected_len else {
                fs::create_dir_all(&target).map_err(|e| e.to_string())?;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
                    .map_err(|e| e.to_string())?;
                continue;
            };
            fs::create_dir_all(target.parent().ok_or("project file has no parent")?)
                .map_err(|e| e.to_string())?;
            let mut input =
                crate::archive_io::open_regular(source, &path).map_err(|e| e.to_string())?;
            if input.metadata().map_err(|e| e.to_string())?.len() != expected_len {
                return Err("project changed during export".into());
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(target)
                .map_err(|e| e.to_string())?;
            let copied = std::io::copy(
                &mut std::io::Read::take(&mut input, expected_len + 1),
                &mut output,
            )
            .map_err(|e| e.to_string())?;
            if copied != expected_len {
                return Err("project changed during export".into());
            }
            output.sync_all().map_err(|e| e.to_string())?;
        }
        normalize_copied_project_owner(destination)?;
        project_inventory(destination)?;
        Ok(())
    })();
    if let Err(error) = result {
        return match fs::remove_dir_all(destination) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "{error}; partial project cleanup failed: {cleanup}"
            )),
        };
    }
    Ok(())
}

fn normalize_copied_project_owner(destination: &Path) -> Result<(), String> {
    let property = Path::new("antinomie.rep/project.prp");
    let path = destination.join(property);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let mut bytes = Vec::new();
    crate::archive_io::open_regular(destination, property)
        .and_then(|file| file.take(65537).read_to_end(&mut bytes))
        .map_err(|e| format!("Ghidra project ownership: {e}"))?;
    if bytes.len() > 65536 {
        return Err("Ghidra project ownership metadata exceeds its bound".into());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| "Ghidra project ownership metadata is not UTF-8".to_string())?;
    // Ghidra's FILE_INFO properties serialize OWNER with this fixed STATE
    // shape. Change only its value in the newly owned copy; preserve the
    // retained source and all other project properties/database contents.
    let prefix = "<STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"";
    let Some(start) = text.find(prefix).map(|at| at + prefix.len()) else {
        return Err("Ghidra project ownership metadata has an unsupported format".into());
    };
    if text[start..].contains(prefix) {
        return Err("Ghidra project ownership metadata has duplicate owners".into());
    }
    let Some(end) = text[start..].find("\" />").map(|at| start + at) else {
        return Err("Ghidra project ownership metadata is incomplete".into());
    };
    let owner = super::jobs::host_user_name()?;
    let mut updated = text;
    updated.replace_range(start..end, &owner);
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    output
        .write_all(updated.as_bytes())
        .and_then(|()| output.sync_all())
        .map_err(|e| format!("Ghidra project ownership: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalysisSectionState, AnalysisState, listing::ListingWriter};

    #[test]
    fn project_export_repairs_copy_owner_and_preserves_source_and_other_properties() {
        let root = std::env::temp_dir().join(format!("ant-owner-{}", crate::storage::unique_id()));
        let source = root.join("source");
        fs::create_dir_all(source.join("antinomie.rep")).unwrap();
        fs::write(source.join("antinomie.gpr"), b"project").unwrap();
        fs::write(source.join("antinomie.rep/database"), b"retained database").unwrap();
        let original = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<FILE_INFO><BASIC_INFO>\n<STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"?\" />\n<STATE NAME=\"OTHER\" TYPE=\"string\" VALUE=\"keep\" />\n</BASIC_INFO></FILE_INFO>\n";
        fs::write(source.join("antinomie.rep/project.prp"), original).unwrap();
        let output = root.join("output");
        copy_project(&source, &output).unwrap();
        assert_eq!(
            fs::read_to_string(source.join("antinomie.rep/project.prp")).unwrap(),
            original
        );
        let expected = original.replace(
            "VALUE=\"?\"",
            &format!(
                "VALUE=\"{}\"",
                super::super::jobs::host_user_name().unwrap()
            ),
        );
        assert_eq!(
            fs::read_to_string(output.join("antinomie.rep/project.prp")).unwrap(),
            expected
        );
        assert_eq!(
            fs::read(output.join("antinomie.rep/database")).unwrap(),
            b"retained database"
        );
        assert!(copy_project(&source, &output).is_err());
        fs::write(
            source.join("antinomie.rep/project.prp"),
            original.replace(
                "VALUE=\"?\" />",
                "VALUE=\"?\" />\n<STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"duplicate\" />",
            ),
        )
        .unwrap();
        assert!(copy_project(&source, &root.join("invalid")).is_err());
        assert!(!root.join("invalid").exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ant-export-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        fs::create_dir(root.join("listings")).unwrap();
        let mut writer = ListingWriter::create(
            &root.join("listings"),
            AnalysisKind::Decompilation,
            1024 * 1024,
        )
        .unwrap();
        for line in 1..=1200 {
            assert!(writer.push(
                "function",
                format!("complete source line {line};"),
                None,
                AnalysisData::SourceLine {
                    function: "function".into(),
                    address: None,
                    line
                }
            ));
        }
        let mut section = AnalysisSection::new(AnalysisKind::Decompilation);
        section.state = AnalysisSectionState::Partial;
        section.summary = "synthetic partial analysis".into();
        section.listing = Some(writer.finish(true).unwrap());
        let report = AnalysisReport {
            id: "report".into(),
            source_path: "/fixture".into(),
            state: AnalysisState::Partial,
            specimen_sha256: None,
            specimen_len: None,
            reason: Some("synthetic test".into()),
            sections: vec![section],
        };
        fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn exports_all_listing_rows_beyond_page_bound_and_marks_partial() {
        let root = fixture();
        let text = root.join("export.txt");
        export_analysis(
            &root,
            "report",
            Some(AnalysisKind::Decompilation),
            AnalysisExportFormat::Text,
            &text,
        )
        .unwrap();
        let output = fs::read_to_string(&text).unwrap();
        assert!(output.contains("complete source line 1200;"));
        assert!(output.contains("Partial listing"));
        assert_eq!(output.matches("complete source line").count(), 1200);
        let json = root.join("export.json");
        export_analysis(&root, "report", None, AnalysisExportFormat::Json, &json).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&fs::read(json).unwrap()).unwrap();
        assert_eq!(
            parsed["sections"][0]["rows"].as_array().unwrap().len(),
            1200
        );
        assert_eq!(parsed["report"]["state"], "partial");
        assert!(export_analysis(&root, "report", None, AnalysisExportFormat::Text, &text).is_err());
        assert!(
            fs::read_to_string(text)
                .unwrap()
                .contains("complete source line 1200;")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_wrong_identity_and_corrupt_full_listing_without_creating_export() {
        let root = fixture();
        let out = root.join("export.txt");
        assert!(export_analysis(&root, "wrong", None, AnalysisExportFormat::Text, &out).is_err());
        assert!(!out.exists());
        fs::write(root.join("listings/decompilation.jsonl"), b"malformed\n").unwrap();
        assert!(export_analysis(&root, "report", None, AnalysisExportFormat::Text, &out).is_err());
        assert!(!out.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_project_copy_preserves_database_and_rejects_symlinks_and_size_overflow() {
        let root = fixture();
        let source = root.join("project");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("antinomie.rep")).unwrap();
        fs::create_dir(source.join("antinomie.rep/empty")).unwrap();
        fs::write(source.join("antinomie.gpr"), b"native project descriptor").unwrap();
        fs::write(
            source.join("antinomie.rep/database"),
            b"actual native database",
        )
        .unwrap();
        let target = root.join("export-project");
        copy_project(&source, &target).unwrap();
        assert_eq!(
            fs::read(target.join("antinomie.rep/database")).unwrap(),
            b"actual native database"
        );
        assert!(target.join("antinomie.rep/empty").is_dir());
        assert!(copy_project(&source, &source.join("nested-export")).is_err());
        assert!(copy_project(&source, &target).is_err());
        std::os::unix::fs::symlink(root.join("report.json"), source.join("link")).unwrap();
        assert!(copy_project(&source, &root.join("unsafe-project")).is_err());
        assert!(!root.join("unsafe-project").exists());
        fs::remove_file(source.join("link")).unwrap();
        let oversized = fs::File::create(source.join("antinomie.rep/oversized")).unwrap();
        oversized.set_len(PROJECT_MAX_SIZE + 1).unwrap();
        assert!(copy_project(&source, &root.join("oversized-project")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_native_project_is_not_mislabeled_as_ghidra_output() {
        let root = fixture();
        assert!(
            retained_ghidra_project(&root, "report")
                .unwrap_err()
                .contains("no retained Ghidra project")
        );
        assert!(
            export_analysis(
                &root,
                "report",
                None,
                AnalysisExportFormat::GhidraProject,
                &root.join("native")
            )
            .is_err()
        );
        assert!(!root.join("native").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn gui_command_passes_literal_working_copy_path_and_rejects_text_exports() {
        let root = fixture();
        let source = root.join("project space");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("antinomie.rep")).unwrap();
        fs::write(source.join("antinomie.gpr"), b"native descriptor").unwrap();
        let tools = root.join("tools space");
        fs::create_dir_all(tools.join("ghidra/ghidra")).unwrap();
        fs::write(tools.join("ghidra/ghidra/ghidraRun"), b"mock launcher").unwrap();
        let project = source.join("antinomie.gpr");
        let command = ghidra_open_exported_project(&project, &tools).unwrap();
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![project.as_os_str()]
        );
        fs::write(source.join("decompiled.txt"), b"plain text").unwrap();
        assert!(ghidra_open_exported_project(&source.join("decompiled.txt"), &tools).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legacy_report_exports_retained_entries_without_requiring_a_listing() {
        let root = fixture();
        let mut report = super::super::open_report(&root).unwrap();
        report.sections[0].listing = None;
        report.sections[0].entries = vec![AnalysisEntry {
            label: "Legacy result".into(),
            value: "all retained legacy text".into(),
            offset: None,
            record: None,
        }];
        fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let target = root.join("legacy.txt");
        export_analysis(&root, "report", None, AnalysisExportFormat::Text, &target).unwrap();
        assert!(
            fs::read_to_string(target)
                .unwrap()
                .contains("all retained legacy text")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
