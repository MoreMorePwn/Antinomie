// SPDX-License-Identifier: GPL-3.0-only
//! Saving a dump's image to the host as a sparse raw file or a compressed,
//! self-contained qcow2 file (no backing file).
//!
//! A plain copy is avoided on purpose: it can fill the holes of the image on
//! some filesystems. `qemu-img convert` with the source format given
//! explicitly as `raw` never probes the (guest-controlled) content.
use super::{SPACE_MARGIN, format_size, job::parse_progress, measure};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread,
    time::Duration,
};

/// What the saved file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// The same bytes as the image, holes preserved.
    SparseRaw,
    /// Compressed qcow2, standalone.
    Qcow2,
}

impl ExportFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::SparseRaw => "Sparse raw ext4",
            Self::Qcow2 => "Compressed qcow2",
        }
    }

    /// The `qemu-img convert -O` format name.
    fn target(self) -> &'static str {
        match self {
            Self::SparseRaw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

/// What an export wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    pub path: PathBuf,
    pub size: u64,
    pub allocated: u64,
}

/// Write `source` (a raw image) to `destination` in `format`. The file is
/// written under a temporary name beside the destination and renamed over it
/// once complete, so a failed or cancelled export leaves nothing half-written.
/// `progress` receives the percentage `qemu-img` reports.
pub fn export(
    qemu_img: &Path,
    source: &Path,
    destination: &Path,
    format: ExportFormat,
    cancel: &AtomicBool,
    mut progress: impl FnMut(f32),
) -> Result<Exported, String> {
    if !destination.is_absolute() {
        return Err("choose an absolute destination path".into());
    }
    let name = destination
        .file_name()
        .ok_or("the destination has no file name")?;
    let folder = fs::canonicalize(
        destination
            .parent()
            .ok_or("the destination has no folder")?,
    )
    .map_err(|error| format!("{}: {error}", destination.display()))?;
    let destination = folder.join(name);
    let source_meta =
        fs::metadata(source).map_err(|error| format!("{}: {error}", source.display()))?;
    if !source_meta.is_file() {
        return Err(format!("{} is not a regular file", source.display()));
    }
    if let Ok(existing) = fs::metadata(&destination)
        && existing.dev() == source_meta.dev()
        && existing.ino() == source_meta.ino()
    {
        return Err("the destination is the image itself".into());
    }
    // Space: what the image holds, or its full size without hole support.
    let need = if measure::sparse_supported(&folder) {
        source_meta.blocks().saturating_mul(512)
    } else {
        source_meta.len()
    }
    .saturating_add(SPACE_MARGIN);
    let free = measure::free_space(&folder)?;
    if free < need {
        return Err(format!(
            "{} needs about {} of free space; {} is available",
            folder.display(),
            format_size(need),
            format_size(free)
        ));
    }
    let temporary = folder.join(format!(
        ".{}.part-{}",
        name.to_string_lossy(),
        crate::storage::unique_id()
    ));
    let result =
        convert(qemu_img, source, &temporary, format, cancel, &mut progress).and_then(|()| {
            let file = File::open(&temporary).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            fs::rename(&temporary, &destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            File::open(&folder)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())?;
            let written = fs::metadata(&destination).map_err(|error| error.to_string())?;
            Ok(Exported {
                path: destination.clone(),
                size: written.len(),
                allocated: written.blocks().saturating_mul(512),
            })
        });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn convert(
    qemu_img: &Path,
    source: &Path,
    target: &Path,
    format: ExportFormat,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(f32),
) -> Result<(), String> {
    let mut command = measure::qemu_img_command(qemu_img);
    command.args(["convert", "-p", "-f", "raw", "-O", format.target()]);
    if format == ExportFormat::Qcow2 {
        command.arg("-c");
    }
    let mut child = command
        .arg(source)
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("qemu-img convert: {error}"))?;
    let percent = Arc::new(AtomicU32::new(0));
    let mut stdout = child.stdout.take().ok_or("qemu-img stdout unavailable")?;
    let shared = percent.clone();
    let reader = thread::spawn(move || {
        let mut line = Vec::new();
        let mut buffer = [0u8; 256];
        while let Ok(count) = stdout.read(&mut buffer) {
            if count == 0 {
                break;
            }
            for &byte in &buffer[..count] {
                if byte == b'\r' || byte == b'\n' {
                    if let Some(value) = parse_progress(&String::from_utf8_lossy(&line)) {
                        shared.store(value.to_bits(), Ordering::Relaxed);
                    }
                    line.clear();
                } else if line.len() < 128 {
                    line.push(byte);
                }
            }
        }
    });
    let mut stderr = child.stderr.take().ok_or("qemu-img stderr unavailable")?;
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut text);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        String::from_utf8_lossy(&text).into_owned()
    });
    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            let _ = errors.join();
            return Err("cancelled".into());
        }
        progress(f32::from_bits(percent.load(Ordering::Relaxed)));
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(error.to_string()),
        }
    };
    let _ = reader.join();
    let errors = errors.join().unwrap_or_default();
    if status.success() {
        Ok(())
    } else {
        Err(measure::qemu_failure(&errors))
    }
}

#[cfg(test)]
mod tests;
