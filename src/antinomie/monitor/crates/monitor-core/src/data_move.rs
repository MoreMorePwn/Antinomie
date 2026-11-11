// SPDX-License-Identifier: GPL-3.0-only
//! A data folder that moved (restored from a backup, mounted at another path,
//! copied to a new disk). Installed bases are found by their own folder, but
//! each VM keeps absolute paths to its base: in its own `bundle.json` and in
//! the backing-file names inside its disk and snapshot layers. When the
//! backend starts, anything of these that no longer exists is pointed at the
//! same file in this data folder. Nothing is changed while every path still
//! exists, and nothing is guessed: a file that cannot be found stays as it is
//! and the VM's own start reports it.
use crate::{
    api::BackendOptions,
    storage::{self, Bundle},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Repair the VM folders after a move. Returns what could not be repaired
/// (one line each); it never fails the start.
pub(crate) fn repair(options: &BackendOptions) -> Vec<String> {
    let mut problems = Vec::new();
    if let Err(error) = crate::locations::heal_registry(options) {
        problems.push(format!("VM registry: {error}"));
    }
    let locations = match crate::locations::all_locations(options) {
        Ok(locations) => locations,
        Err(error) => {
            problems.push(format!("VM folders: {error}"));
            return problems;
        }
    };
    for location in locations {
        let directory = location.disk_directory;
        if !directory.join("bundle.json").is_file() {
            continue;
        }
        if let Err(error) = repair_vm(options, &directory) {
            problems.push(format!("VM {}: {error}", location.vm_id));
        }
    }
    problems
}

/// `path` if it exists, otherwise the file of that name in `folder`, if that
/// exists; `None` when neither does.
fn find_in(path: &Path, folder: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }
    let candidate = folder.join(path.file_name()?);
    candidate.exists().then_some(candidate)
}

fn repair_vm(options: &BackendOptions, directory: &Path) -> Result<(), String> {
    let bundle_path = directory.join("bundle.json");
    let mut bundle: Bundle = storage::read_json(&bundle_path)?;
    let Some(identity) = bundle.base_identity.clone() else {
        return Ok(());
    };
    let base_dir = crate::lanes::bases_dir(&options.data_dir).join(&identity);
    let before = bundle.clone();
    let fix = |path: &mut PathBuf| {
        if let Some(found) = find_in(path, &base_dir) {
            *path = found;
        }
    };
    fix(&mut bundle.kernel);
    fix(&mut bundle.base_disk);
    bundle.initrd.iter_mut().for_each(fix);
    bundle.symbols.iter_mut().for_each(fix);
    bundle.uefi.uefi_root.iter_mut().for_each(fix);
    bundle.uefi.uefi_layout.iter_mut().for_each(fix);
    bundle.uefi.uefi_disk.iter_mut().for_each(fix);
    let value = |bundle: &Bundle| serde_json::to_value(bundle).map_err(|e| e.to_string());
    if value(&bundle)? != value(&before)? {
        storage::atomic_json(&bundle_path, &bundle)?;
    }
    let mut layers = vec![directory.join("disk.qcow2")];
    if let Ok(entries) = fs::read_dir(directory.join("snapshots")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "qcow2") {
                layers.push(path);
            }
        }
    }
    for layer in layers.iter().filter(|layer| layer.is_file()) {
        rebase_layer(options, directory, &base_dir, layer)?;
    }
    Ok(())
}

/// Point a layer whose backing file is missing at that file's place here: a
/// base file in the installed base's folder, a VM layer in this VM's folder.
fn rebase_layer(
    options: &BackendOptions,
    directory: &Path,
    base_dir: &Path,
    layer: &Path,
) -> Result<(), String> {
    let Some(backing) = crate::disk_start::backing_file(layer)? else {
        return Ok(());
    };
    if backing.exists() {
        return Ok(());
    }
    let name = backing.file_name().ok_or("backing file has no name")?;
    let in_snapshots = backing
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|parent| parent == "snapshots");
    let target = if in_snapshots {
        directory.join("snapshots").join(name)
    } else if name == "disk.qcow2" {
        directory.join(name)
    } else {
        base_dir.join(name)
    };
    if !target.exists() {
        return Err(format!(
            "{}: backing file {} is missing and {} does not exist",
            layer.display(),
            backing.display(),
            target.display()
        ));
    }
    let output = Command::new(&options.qemu_img)
        .args(["rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(&target)
        .arg(layer)
        .output()
        .map_err(|e| format!("qemu-img: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{}: rebase onto {}: {}",
            layer.display(),
            target.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
