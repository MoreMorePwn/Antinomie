// SPDX-License-Identifier: GPL-3.0-only
//! Automatic unpacking in phases, on the host and in the analysis sandbox.
//!
//! The file is checked for a packer; a packed file is unpacked into a layer
//! and the layer is checked again, up to a few levels, so a file UPX packed
//! twice comes out whole. Each phase is a row: the file as it came, then each
//! layer with its hash and size and the packer found in it. The host then
//! queues a static analysis of each layer (`jobs::layers`), so a layer is
//! examined on its own, and its report says which phase it is.
//!
//! This never runs the specimen. UPX decompresses data; nothing here starts
//! the file or marks it executable, and the work is confined to the worker's
//! `artifacts/unpack` folder, which is bounded in size and time. Packers that
//! have to run the program to get past (most protectors and packers made for
//! malware) need the guest and are not attempted; unpacking by emulation or
//! from memory is the job of a later version.
use super::tools;
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

#[cfg(test)]
mod tests;
mod upx;

const MANAGED: &str = "/opt/antinomie-tools/upx/upx";
/// Layers recovered from one file; a file packed deeper stays packed.
pub(crate) const LAYER_MAX_COUNT: usize = 3;
/// Largest layer kept, in octets.
pub(crate) const LAYER_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// All layers of one file, in octets.
pub(crate) const TOTAL_MAX_SIZE: u64 = 3 * LAYER_MAX_SIZE;
/// Wall-clock budget of the whole section, and of one run of the unpacker.
pub(super) const BUDGET_SECONDS: u64 = 240;
const RUN_SECONDS: u64 = 60;

/// The folder under a report's artifacts that holds the layers.
pub(crate) const FOLDER: &str = "unpack";

struct Layer {
    index: u32,
    method: String,
    sha256: String,
    size: u64,
    parent: Option<u32>,
    packer: Option<String>,
    file: Option<String>,
    note: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn unpack(section: &mut AnalysisSection, specimen: &[u8], artifacts: &Path) {
    let tool = tools::find_tool(crate::analysis_tools::UPX_SYSTEM, MANAGED);
    unpack_with(section, specimen, artifacts, tool);
}

/// [`unpack`] with the unpacker named, or None when there is none.
fn unpack_with(
    section: &mut AnalysisSection,
    specimen: &[u8],
    artifacts: &Path,
    tool: Option<&str>,
) {
    let started = Instant::now();
    let work = artifacts.join(FOLDER);
    let mut layers = vec![Layer {
        index: 0,
        method: "original".into(),
        sha256: sha256(specimen),
        size: specimen.len() as u64,
        parent: None,
        packer: None,
        file: None,
        note: String::new(),
    }];
    // The octets of the newest layer; the specimen is the first.
    let mut current: Option<Vec<u8>> = None;
    let mut problem: Option<String> = None;
    let mut total = 0u64;
    loop {
        let bytes = current.as_deref().unwrap_or(specimen);
        let at = layers.len() - 1;
        let Some(found) = upx::detect(bytes) else {
            break;
        };
        layers[at].packer = Some(found.label());
        if !found.changes.is_empty() {
            layers[at].note = format!("{}.", found.changes.join("; "));
        }
        if layers.len() > LAYER_MAX_COUNT {
            problem = Some(format!(
                "packed more than {LAYER_MAX_COUNT} levels deep; the layers beyond stay packed"
            ));
            break;
        }
        let Some(tool) = tool else {
            problem = Some(
                "packed with UPX; install UPX from Tools > Analysis tools (or on the system) to unpack it"
                    .into(),
            );
            break;
        };
        let remaining = Duration::from_secs(BUDGET_SECONDS).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            problem = Some("the unpacking time budget ran out".into());
            break;
        }
        if section.tools.is_empty() {
            section.tools.push(tools::version(tool, &["--version"]));
        }
        if let Err(error) = fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&work)
        {
            problem = Some(format!("unpacking folder: {error}"));
            break;
        }
        let room = LAYER_MAX_SIZE.min(TOTAL_MAX_SIZE.saturating_sub(total));
        let unpacked = upx::unpack(
            tool,
            bytes,
            &found,
            &work,
            layers.len(),
            remaining.min(Duration::from_secs(RUN_SECONDS)),
            room,
        );
        let unpacked = match unpacked {
            Ok(unpacked) => unpacked,
            Err(error) => {
                layers[at].note = format!("{}{error}", prefix(&layers[at].note));
                problem = Some(error);
                break;
            }
        };
        let digest = sha256(&unpacked.bytes);
        if layers.iter().any(|layer| layer.sha256 == digest) {
            problem = Some("unpacking gave back a layer already seen".into());
            break;
        }
        let index = layers.len() as u32;
        let name = format!("layer-{index}.bin");
        if let Err(error) = write_layer(&work.join(&name), &unpacked.bytes) {
            problem = Some(error);
            break;
        }
        total += unpacked.bytes.len() as u64;
        let mut method = "UPX".to_owned();
        let mut note = String::new();
        if !unpacked.mended.is_empty() {
            method = "UPX (header repaired)".into();
            note = format!("Repaired before unpacking: {}.", unpacked.mended.join("; "));
        }
        layers.push(Layer {
            index,
            method,
            sha256: digest,
            size: unpacked.bytes.len() as u64,
            parent: Some(index - 1),
            packer: None,
            file: Some(name),
            note,
        });
        current = Some(unpacked.bytes);
    }
    finish(section, &layers, problem, &work);
}

fn prefix(note: &str) -> String {
    if note.is_empty() {
        String::new()
    } else {
        format!("{note} ")
    }
}

/// A new file, owner read and write only: a layer is data, not a program.
fn write_layer(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("layer file: {e}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("layer file: {e}"))
}

fn finish(section: &mut AnalysisSection, layers: &[Layer], problem: Option<String>, work: &Path) {
    for layer in layers {
        let mut value = format!(
            "{}: {} octets, SHA-256 {}",
            layer.method, layer.size, layer.sha256
        );
        if let Some(packer) = &layer.packer {
            value.push_str(&format!("; packed with {packer}"));
        }
        if !layer.note.is_empty() {
            value.push_str(&format!("; {}", layer.note.trim_end()));
        }
        super::worker::structured_entry(
            section,
            format!("Layer {}", layer.index),
            value,
            None,
            AnalysisData::Layer {
                index: layer.index,
                method: layer.method.clone(),
                sha256: layer.sha256.clone(),
                size: layer.size,
                parent: layer.parent,
                packer: layer.packer.clone(),
                file: layer.file.clone(),
                report_id: None,
                note: layer.note.clone(),
            },
        );
    }
    let packed = layers.iter().any(|layer| layer.packer.is_some());
    if packed {
        let manifest = serde_json::json!({
            "schema": 1,
            "specimen_sha256": layers[0].sha256,
            "tool": section.tools.first(),
            "layers": layers.iter().map(|layer| serde_json::json!({
                "index": layer.index,
                "method": layer.method,
                "sha256": layer.sha256,
                "size": layer.size,
                "parent": layer.parent,
                "packer": layer.packer,
                "file": layer.file,
            })).collect::<Vec<_>>(),
        });
        // The manifest is for people and for tools that read the folder; the
        // report holds the same facts.
        let _ = fs::create_dir_all(work).and_then(|()| {
            fs::write(
                work.join("layers.json"),
                serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
            )
        });
    }
    let recovered = layers.len() - 1;
    section.state = if problem.is_some() {
        AnalysisSectionState::Partial
    } else {
        AnalysisSectionState::Complete
    };
    section.summary = match (&problem, packed, recovered) {
        (Some(problem), ..) => format!(
            "Packed with UPX, {recovered} {} recovered: {problem}",
            if recovered == 1 { "layer" } else { "layers" }
        ),
        (None, false, _) => "No UPX packing found; other packers are not unpacked here (Identification names the ones it recognises)".into(),
        (None, true, count) => format!(
            "Packed with UPX: {count} {} recovered, each one analysed on its own",
            if count == 1 { "layer" } else { "layers" }
        ),
    };
}

/// One phase of a report's unpack chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpackLayer {
    pub index: u32,
    pub method: String,
    pub sha256: String,
    pub size: u64,
    pub parent: Option<u32>,
    pub packer: Option<String>,
    pub file: Option<String>,
    /// The report of this layer's own analysis, once it is queued.
    pub report_id: Option<String>,
    pub note: String,
}

/// The unpack chain of a report, original first. Empty when it has no
/// Unpacking section. The hashes are what Indicators of compromise files list.
pub fn unpack_layers(report: &AnalysisReport) -> Vec<UnpackLayer> {
    let Some(section) = report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Unpacking)
    else {
        return Vec::new();
    };
    section
        .entries
        .iter()
        .filter_map(|entry| match &entry.record.as_ref()?.data {
            AnalysisData::Layer {
                index,
                method,
                sha256,
                size,
                parent,
                packer,
                file,
                report_id,
                note,
            } => Some(UnpackLayer {
                index: *index,
                method: method.clone(),
                sha256: sha256.clone(),
                size: *size,
                parent: *parent,
                packer: packer.clone(),
                file: file.clone(),
                report_id: report_id.clone(),
                note: note.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// What unpacking established about the program a report is of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackerVerdict {
    /// "UPX".
    pub packer: String,
    /// The packer's own headers were changed from what the packer writes.
    pub modified: bool,
    /// Layers recovered, beyond the original.
    pub layers: u32,
    /// SHA-256 of the file as it came.
    pub sha256: String,
}

/// The packer found in the file as it came, or None when none was found or
/// unpacking did not run.
pub fn packer_verdict(report: &AnalysisReport) -> Option<PackerVerdict> {
    let layers = unpack_layers(report);
    let original = layers.first()?;
    let packer = original.packer.clone()?;
    Some(PackerVerdict {
        modified: packer.contains("modified")
            || layers.iter().any(|l| l.method.contains("repaired")),
        packer: packer.split(' ').next().unwrap_or("").to_owned(),
        layers: layers.len() as u32 - 1,
        sha256: original.sha256.clone(),
    })
}
