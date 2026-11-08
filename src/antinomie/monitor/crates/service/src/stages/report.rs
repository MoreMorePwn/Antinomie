// SPDX-License-Identifier: GPL-3.0-only
//! `report` (design 4.1, 4.9.3; card P3-5): the report files of a finished
//! job, written into its own directory.
//!
//! The report is the one `antinomie-cli report` and the GUI's Export dialog
//! make (`antinomie_triage::report_export`), for the policy's formats, bundle
//! and defang choice. The writer's own names (`antinomie-report-<run8>-<time>`)
//! are replaced by the design's stable ones: `report-<sha8>.<suffix>` and
//! `report-<sha8>-bundle.zip`, in `jobs/<id>/artifacts/`. Each file is hashed
//! and recorded as an artifact (`job.artifact`). Reports go in the job
//! directory and never into the recording (decided B-H19).
//!
//! Without a Triage scan (it failed, and the policy does not require
//! `analyse`) there is nothing to report: the stage is a warning and the job
//! `partial`. A failure to build or write is `analysis_failed`.
use super::{
    LaneStages, StageStop,
    analyse::Analysed,
    plan::{HostPlan, REPORT_WAIT, format_of},
};
use crate::{
    api::{
        artifact::{Artifact, ArtifactKind, MediaType},
        failure::{Failure, FailureCode},
        ids::Sha256Hex,
        job::{Job, Stage},
    },
    engine::Engine,
    store::NewArtifact,
};
use antinomie_monitor_core::report::{Choices, Format, Part};
use sha2::{Digest, Sha256};
use std::path::Path;

fn kind_of(format: Format) -> (ArtifactKind, MediaType, bool) {
    // The last member: indicators are raw (no defang) in this format.
    match format {
        Format::Html => (ArtifactKind::ReportHtml, MediaType::TextHtml, false),
        Format::Pdf => (ArtifactKind::ReportPdf, MediaType::ApplicationPdf, false),
        Format::Json => (ArtifactKind::ReportJson, MediaType::ApplicationJson, true),
        Format::Misp => (ArtifactKind::ReportMisp, MediaType::ApplicationJson, true),
        Format::Stix => (ArtifactKind::ReportStix, MediaType::ApplicationJson, true),
        Format::Markdown => (ArtifactKind::ReportMd, MediaType::TextMarkdown, false),
    }
}

/// A file the writer made, renamed and hashed.
struct Filed {
    kind: ArtifactKind,
    media_type: MediaType,
    raw_indicators: bool,
    name: String,
    size: u64,
    sha256: String,
}

fn hash_file(path: &Path) -> Result<(u64, String), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

impl<E: Engine> LaneStages<'_, E> {
    /// The `report` stage: the files and their artifacts.
    pub fn report(
        &mut self,
        job: &Job,
        plan: &HostPlan,
        analysed: &Analysed,
    ) -> Result<Vec<Artifact>, StageStop> {
        let fail = |message: &str, detail: &str| {
            StageStop::Failed(Failure::new(
                FailureCode::AnalysisFailed,
                Stage::Report,
                message,
                Some(detail),
            ))
        };
        let Some((saved, scan)) = analysed.scan.as_ref() else {
            return Err(fail(
                "there is no Triage scan to report",
                "the analysis did not produce one",
            ));
        };
        let store = self.env.store;
        let folder = store.job_dir(&job.id).join("artifacts");
        let formats: Vec<Format> = plan.formats.iter().map(|f| format_of(*f)).collect();
        let choices = Choices {
            parts: Part::ALL.to_vec(),
            formats: formats.clone(),
            bundle: plan.bundle,
            defang: plan.defang,
            include_content: false,
            folder: folder.display().to_string(),
        };
        let sha8: String = job
            .sample
            .as_ref()
            .map(|s| s.sha256.as_str().chars().take(8).collect())
            .unwrap_or_else(|| "sample".into());
        let triage: &dyn super::host::HostTriage = self.env.triage;
        let now = super::host::now_ms();
        self.progress(job, Stage::Report, "building and writing the report");
        let worked = self.bounded(REPORT_WAIT, |cancel| {
            let built = triage.build(saved, scan, choices, now)?;
            let written = triage.write(built, cancel)?;
            let mut filed = Vec::new();
            let mut take = |from: &Path, to: String, kind, media_type, raw| -> Result<(), String> {
                let target = from.with_file_name(&to);
                std::fs::rename(from, &target).map_err(|e| format!("{}: {e}", target.display()))?;
                let (size, sha256) = hash_file(&target)?;
                filed.push(Filed {
                    kind,
                    media_type,
                    raw_indicators: raw,
                    name: to,
                    size,
                    sha256,
                });
                Ok(())
            };
            for (label, path) in &written.files {
                let Some(format) = Format::ALL.into_iter().find(|f| f.label() == label) else {
                    continue;
                };
                let (kind, media_type, raw) = kind_of(format);
                take(
                    path,
                    format!("report-{sha8}{}", format.suffix()),
                    kind,
                    media_type,
                    raw || !choices_defang(&formats, format, plan.defang),
                )?;
            }
            if let Some(bundle) = &written.bundle {
                take(
                    &bundle.path,
                    format!("report-{sha8}-bundle.zip"),
                    ArtifactKind::ReportBundle,
                    MediaType::ApplicationZip,
                    true,
                )?;
            }
            Ok::<_, String>(filed)
        });
        let filed = match worked {
            Ok(Ok(filed)) => filed,
            Ok(Err(error)) => return Err(fail("the report could not be written", &error)),
            Err(why) => {
                if let Some(stop) = why.stop() {
                    return Err(stop);
                }
                return Err(fail("the report was not written", &why.words("the report")));
            }
        };
        let mut artifacts = Vec::new();
        for file in filed {
            let sha256 = Sha256Hex::try_from(file.sha256).map_err(|e| {
                self.internal(
                    FailureCode::Internal,
                    Stage::Report,
                    "a report file has no usable hash",
                    Some(&e.to_string()),
                )
            })?;
            let artifact = store
                .add_artifact(
                    &job.id,
                    NewArtifact {
                        kind: file.kind,
                        name: file.name.clone(),
                        size: file.size,
                        sha256,
                        media_type: file.media_type,
                        raw_indicators: file.raw_indicators,
                        location: format!("artifacts/{}", file.name),
                    },
                )
                .map_err(|e| self.store_error(Stage::Report, e))?;
            artifacts.push(artifact);
        }
        Ok(artifacts)
    }
}

/// Whether `format` defangs when it is written with `defang` (HTML, PDF and
/// Markdown only; the other formats keep indicators raw anyway).
fn choices_defang(_: &[Format], format: Format, defang: bool) -> bool {
    defang && matches!(format, Format::Html | Format::Pdf | Format::Markdown)
}
