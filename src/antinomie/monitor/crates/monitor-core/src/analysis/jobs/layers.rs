// SPDX-License-Identifier: GPL-3.0-only
//! Each layer that unpacking recovered gets a static analysis of its own,
//! queued when the analysis of the packed file finishes: the same checks as
//! the packed file's (without unpacking again), in a folder of its own under
//! the packed file's report, with a report that says which layer it is.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Seek, SeekFrom};

/// Room an analysis needs beyond the specimen and its report: a decompiler's
/// project, and the layers an unpacker may leave.
pub(super) fn extra_reserve(report: &AnalysisReport) -> u64 {
    let has = |kind| report.sections.iter().any(|section| section.kind == kind);
    let mut extra = 0;
    if has(AnalysisKind::Decompilation) {
        extra += super::super::export::PROJECT_MAX_SIZE;
    }
    if has(AnalysisKind::Unpacking) {
        extra += super::super::unpack::TOTAL_MAX_SIZE;
    }
    extra
}

/// The report id of the analysis of layer `index` of report `parent`.
fn layer_report_id(parent: &str, index: u32) -> String {
    format!("{parent}-L{index}")
}

impl Jobs {
    /// Queue the analysis of every layer in the finished `job`'s report. The
    /// rows of the report are told the id of each layer's report, or why there
    /// is none. Nothing is queued for a report that is itself a layer.
    pub(super) fn queue_layers(&mut self, job: &mut Job) {
        if !matches!(
            job.report.state,
            AnalysisState::Complete | AnalysisState::Partial
        ) || job.report.layer.is_some()
            // Checks added later queue the layers only for unpacking.
            || job.supplement.as_ref().is_some_and(|supplement| {
                supplement.carried.contains(&AnalysisKind::Unpacking)
            })
        {
            return;
        }
        let layers = super::super::unpack::unpack_layers(&job.report);
        let checks: Vec<_> = job
            .report
            .sections
            .iter()
            .map(|section| section.kind)
            .filter(|kind| *kind != AnalysisKind::Unpacking)
            .collect();
        let folder = job
            .directory
            .join("output/artifacts")
            .join(super::super::unpack::FOLDER);
        let mut results = Vec::new();
        for layer in layers.iter().filter(|layer| layer.index > 0) {
            let queued = if checks.is_empty() {
                Err("no other check was selected".to_owned())
            } else {
                self.queue_layer(job, layer, &folder, &checks)
            };
            results.push((layer.index, queued));
        }
        let Some(section) = job
            .report
            .sections
            .iter_mut()
            .find(|section| section.kind == AnalysisKind::Unpacking)
        else {
            return;
        };
        for entry in &mut section.entries {
            let Some(AnalysisData::Layer {
                index,
                report_id,
                note,
                ..
            }) = entry.record.as_mut().map(|record| &mut record.data)
            else {
                continue;
            };
            // Only the host says which analysis a layer has.
            *report_id = None;
            match results.iter().find(|(number, _)| number == index) {
                Some((_, Ok(id))) => *report_id = Some(id.clone()),
                Some((_, Err(reason))) => {
                    let text = format!("Not analysed on its own: {reason}.");
                    *note = if note.is_empty() {
                        text.clone()
                    } else {
                        format!("{note} {text}")
                    };
                    entry.value.push_str(&format!("; {text}"));
                }
                None => {}
            }
        }
    }

    fn queue_layer(
        &mut self,
        job: &Job,
        layer: &super::super::unpack::UnpackLayer,
        folder: &Path,
        checks: &[AnalysisKind],
    ) -> Result<String, String> {
        let name = layer.file.as_deref().ok_or("it has no file")?;
        if name != format!("layer-{}.bin", layer.index) {
            return Err("its file name is not the expected one".into());
        }
        // Confined to the artifacts folder and never a link, whatever the
        // worker left there.
        let mut file = crate::archive_io::open_regular(folder, &folder.join(name))
            .map_err(|error| format!("its file cannot be opened ({error})"))?;
        let size = file.metadata().map_err(|e| e.to_string())?.len();
        if size != layer.size || size > super::super::unpack::LAYER_MAX_SIZE {
            return Err("its file has another size than the report says".into());
        }
        let mut digest = Sha256::new();
        std::io::copy(&mut file, &mut digest).map_err(|e| e.to_string())?;
        if format!("{:x}", digest.finalize()) != layer.sha256 {
            return Err("its file does not match the hash in the report".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let selection = AnalysisSelection {
            enabled: true,
            checks: checks.to_vec(),
        };
        let mut report = new_report(&job.report.source_path, &selection);
        report.id = layer_report_id(&job.report.id, layer.index);
        report.layer = Some(AnalysisLayer {
            parent_id: job.report.id.clone(),
            index: layer.index,
            method: layer.method.clone(),
            parent_sha256: job
                .report
                .specimen_sha256
                .clone()
                .ok_or("the packed file has no hash")?,
        });
        let directory = job.directory.join("layers").join(layer.index.to_string());
        let queued = self.submit_host_opened(report, directory, file, size, self.available);
        if queued.state == AnalysisState::Unavailable {
            return Err(queued
                .reason
                .unwrap_or_else(|| "the analysis could not be queued".into()));
        }
        Ok(queued.id)
    }
}

#[cfg(test)]
mod tests;
