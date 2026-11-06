// SPDX-License-Identifier: GPL-3.0-only
//! The VM's UEFI variable store (`efi-vars*.fd`, OVMF on x86 and AAVMF on
//! arm64) as part of a checkpoint: copied in when the checkpoint is taken,
//! hashed into its identity and written back when it is restored.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// One checkpoint's copy of the variable store.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EfiVars {
    /// The store's file name in the VM folder (`efi-vars.fd`,
    /// `efi-vars-secure-boot.fd`, `efi-vars-aarch64.fd`).
    pub name: String,
    /// The copy (`snapshots/<id>.<name>`), relative to the VM folder.
    pub artifact: PathBuf,
    pub sha256: String,
}

/// The variable stores in the VM folder: one per firmware profile the VM
/// has booted (`efi-vars.fd`, `efi-vars-secure-boot.fd`, `efi-vars-aarch64.fd`).
pub(super) fn find(directory: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_name(&name) && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// `efi-vars*.fd` as one plain file name; the manifest is not trusted to name
/// anything else in the VM folder.
pub(super) fn valid_name(name: &str) -> bool {
    name.starts_with("efi-vars")
        && name.ends_with(".fd")
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// Copy `source` to `target` as a new private file, as a reflink where the
/// filesystem supports it, and flush it.
pub(super) fn copy(source: &Path, target: &Path) -> io::Result<()> {
    let input = File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    if rustix::fs::ioctl_ficlone(&output, &input).is_err() {
        io::copy(&mut &input, &mut output)?;
    }
    output.sync_all()
}

/// Save each of the VM's stores as `snapshots/<id>.<name>` and describe the copies.
pub(super) fn save(directory: &Path, id: &str) -> Result<Vec<EfiVars>, String> {
    let mut saved = Vec::new();
    for name in find(directory)? {
        let artifact = PathBuf::from(format!("snapshots/{id}.{name}"));
        let target = directory.join(&artifact);
        copy(&directory.join(&name), &target).map_err(|error| {
            format!("UEFI variable store snapshot {}: {error}", target.display())
        })?;
        let sha256 = crate::storage::sha256_file_hex(&target)?;
        saved.push(EfiVars {
            name,
            artifact,
            sha256,
        });
    }
    Ok(saved)
}

/// The copy's digest still matches the checkpoint.
pub(super) fn verify(directory: &Path, vars: &EfiVars) -> Result<PathBuf, String> {
    if !valid_name(&vars.name) {
        return Err("snapshot UEFI variable store name is invalid".into());
    }
    let path = super::owned(directory, &vars.artifact)?;
    if crate::storage::sha256_file_hex(&path)? != vars.sha256 {
        return Err("saved UEFI variable store checksum differs; current VM retained".into());
    }
    Ok(path)
}

/// Replace the VM's variable store with the checkpoint's copy. The VM's
/// process must have stopped: QEMU keeps the file open while it runs.
pub(super) fn restore(directory: &Path, vars: &EfiVars) -> Result<(), String> {
    let source = verify(directory, vars)?;
    let staging = directory.join(format!(".efi-vars-{}.tmp", crate::storage::unique_id()));
    let target = directory.join(&vars.name);
    copy(&source, &staging)
        .and_then(|()| fs::rename(&staging, &target))
        .map_err(|error| {
            let _ = fs::remove_file(&staging);
            format!("UEFI variable store restore {}: {error}", target.display())
        })?;
    File::open(directory)
        .and_then(|folder| folder.sync_all())
        .map_err(|error| format!("snapshot directory durability: {error}"))
}
