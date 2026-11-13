// SPDX-License-Identifier: GPL-3.0-only
//! Writable layers nothing refers to any more, and their removal.
//!
//! A restore lays a fresh child on the checkpoint's frozen layer and makes it
//! the active disk ([`super::prepare_restore`]). The child it replaces held
//! the discarded "unsaved changes": no checkpoint, no manifest entry and no
//! pending run layer refers to it. Before 0.9.0 nothing removed it, so a lane
//! that reverts before every job grew `snapshots/` by one file per job.
//!
//! * [`super::commit_restore`] removes the replaced child once the restore is
//!   published, unless something still needs it.
//! * A boot that ended with a restore keeps its run layer "in the chain"
//!   ([`super::run_layer`]); when that record settles, its two files are
//!   removed the same way if no checkpoint's chain reaches them.
//! * [`sweep`] is the startup pass for children an earlier version or a crash
//!   left behind, bounded per pass.
//!
//! "Nothing needs it" is proved, never guessed: the live set is every file on
//! the backing chain of the active disk, of every checkpoint's layer (deleted
//! ones too: their files are kept) and of a pending run layer, read from the
//! qcow2 headers. A header that cannot be read, a backing file that is
//! missing, or an unfinished snapshot operation (its journal) removes nothing.
//! Only `snapshots/<id>.qcow2` files directly in the VM's own `snapshots/`
//! folder are ever candidates: never `disk.qcow2`, a memory state, a UEFI
//! variable copy, a file of another name or anything outside the folder.
use super::*;

/// Layers a startup pass removes from one VM at most.
pub(crate) const SWEEP_LIMIT: usize = 256;
/// Entries of `snapshots/` a startup pass reads at most.
const SCAN_LIMIT: usize = 16_384;

/// What a [`sweep`] pass did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sweep {
    /// No unreferenced layer is left (or none can be proved unreferenced).
    Done { removed: usize },
    /// The pass hit its bound; another pass goes on.
    More { removed: usize },
    /// A run layer finalizer holds the folder; try again later.
    Busy,
}

/// `snapshots/<id>.qcow2`, the only name a removable layer has.
fn layer_name(relative: &Path) -> bool {
    let mut parts = relative.components();
    let (Some(Component::Normal(folder)), Some(Component::Normal(file)), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(stem) = file.to_str().and_then(|file| file.strip_suffix(".qcow2")) else {
        return false;
    };
    folder == "snapshots"
        && !stem.is_empty()
        && stem.len() <= 128
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

/// The canonical path of every file the VM still needs (see the module
/// documentation). Fails when any chain cannot be read to its end.
fn live_set(
    directory: &Path,
    manifest: &Manifest,
    record: Option<&run_layer::Record>,
) -> Result<BTreeSet<PathBuf>, String> {
    let mut roots: Vec<PathBuf> = vec![directory.join(&manifest.active_disk)];
    roots.extend(manifest.nodes.iter().map(|node| directory.join(&node.disk)));
    let mut optional = Vec::new();
    if let Some(record) = record {
        // A finalize cut short may already have removed the top layer.
        optional.push(directory.join(&record.sealed));
        optional.push(directory.join(&record.top));
    }
    for path in optional {
        if path.try_exists().map_err(|e| e.to_string())? {
            roots.push(path);
        }
    }
    let mut live = BTreeSet::new();
    for root in roots {
        let mut current = Some(root);
        let mut depth = 0usize;
        while let Some(path) = current.take() {
            let path = fs::canonicalize(&path)
                .map_err(|e| format!("snapshot layer {}: {e}", path.display()))?;
            if !live.insert(path.clone()) {
                // Walked from here already: the rest of the chain is in.
                break;
            }
            depth += 1;
            if depth > MAX_CHAIN {
                return Err("snapshot chain exceeds supported depth of 64 layers".into());
            }
            current = crate::disk_start::backing_file(&path)?;
        }
    }
    Ok(live)
}

/// Remove those of `candidates` (relative to the VM folder `directory`) that
/// are layers nothing needs; how many were removed. The caller keeps the
/// manifest from changing meanwhile: the worker thread, or a run layer
/// finalizer holding the folder's lock.
pub(super) fn remove_unreferenced(
    directory: &Path,
    vm_id: &str,
    candidates: &[PathBuf],
) -> Result<usize, String> {
    if candidates.is_empty() {
        return Ok(0);
    }
    let Some((manifest, record)) = state(directory, vm_id)? else {
        return Ok(0);
    };
    let roots = roots_of(&manifest, record.as_ref());
    let candidates: Vec<&PathBuf> = candidates
        .iter()
        .filter(|relative| layer_name(relative) && !roots.contains(*relative))
        .collect();
    if candidates.is_empty() {
        return Ok(0);
    }
    let live = live_set(directory, &manifest, record.as_ref())?;
    remove(directory, candidates.into_iter(), &live, usize::MAX)
}

/// `snapshots/<id>.state`, the memory file of a Full checkpoint.
fn state_name(relative: &Path) -> bool {
    let mut parts = relative.components();
    let (Some(Component::Normal(folder)), Some(Component::Normal(file)), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(stem) = file.to_str().and_then(|file| file.strip_suffix(".state")) else {
        return false;
    };
    folder == "snapshots"
        && !stem.is_empty()
        && stem.len() <= 128
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

/// The manifest and pending run layer of a VM folder, or `None` when there is
/// nothing to judge by: no manifest (a VM that never had a snapshot) or an
/// unfinished snapshot operation, whose journal names files the manifest
/// does not list yet.
fn state(
    directory: &Path,
    vm_id: &str,
) -> Result<Option<(Manifest, Option<run_layer::Record>)>, String> {
    if directory
        .join(JOURNAL)
        .try_exists()
        .map_err(|e| e.to_string())?
        || !directory
            .join(MANIFEST)
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        return Ok(None);
    }
    let manifest = load(
        directory,
        &VmConfig {
            id: vm_id.to_owned(),
            ..VmConfig::default()
        },
    )?;
    let record_path = directory.join(run_layer::RECORD);
    let record = run_layer::Record::load(directory);
    if record.is_none() && record_path.try_exists().map_err(|e| e.to_string())? {
        // A record that cannot be read may still name a layer.
        return Ok(None);
    }
    Ok(Some((manifest, record)))
}

/// The manifest-relative names that are needed by name alone.
fn roots_of(manifest: &Manifest, record: Option<&run_layer::Record>) -> BTreeSet<PathBuf> {
    let mut roots: BTreeSet<PathBuf> = manifest
        .nodes
        .iter()
        .map(|node| node.disk.clone())
        .collect();
    roots.insert(manifest.active_disk.clone());
    if let Some(record) = record {
        roots.insert(record.sealed.clone());
        roots.insert(record.top.clone());
    }
    roots
}

/// Remove at most `limit` of `candidates` that are not in `live`, each checked
/// to be a regular file directly in the VM's own `snapshots/` folder.
fn remove<'a>(
    directory: &Path,
    candidates: impl Iterator<Item = &'a PathBuf>,
    live: &BTreeSet<PathBuf>,
    limit: usize,
) -> Result<usize, String> {
    let folder = fs::canonicalize(directory.join("snapshots")).map_err(|e| e.to_string())?;
    let mut removed = 0usize;
    for relative in candidates {
        if removed == limit {
            break;
        }
        // `owned_path` refuses `..`, other folders, a symbolic `snapshots/`
        // and a parent that resolves elsewhere.
        let path = owned_path(directory, relative)?;
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        let canonical = fs::canonicalize(&path).map_err(|e| e.to_string())?;
        if canonical.parent() != Some(folder.as_path()) || live.contains(&canonical) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("unreferenced snapshot layer cleanup: {error}")),
        }
    }
    if removed > 0 {
        sync_directory(&folder)?;
    }
    Ok(removed)
}

/// One startup pass over the VM `vm_id`: remove at most `limit` layers of its
/// `snapshots/` folder that nothing needs. Call it from the worker thread,
/// where every other snapshot change happens; it takes the run layer lock so
/// a background finalizer and the pass never overlap. A running boot needs
/// no exception: the files it uses are the active disk and its run layer.
pub(crate) fn sweep(options: &BackendOptions, vm_id: &str, limit: usize) -> Result<Sweep, String> {
    let directory = vm_dir(options, vm_id)?;
    let folder = directory.join("snapshots");
    match fs::symlink_metadata(&folder) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        // No folder (or not one this code made): nothing to sweep.
        _ => return Ok(Sweep::Done { removed: 0 }),
    }
    let _lock = match run_layer::lock(&directory) {
        Ok(lock) => lock,
        Err(why) if why.contains("still being finished") => return Ok(Sweep::Busy),
        Err(why) => return Err(why),
    };
    let Some((manifest, record)) = state(&directory, vm_id)? else {
        return Ok(Sweep::Done { removed: 0 });
    };
    let roots = roots_of(&manifest, record.as_ref());
    let memories: BTreeSet<&PathBuf> = manifest
        .nodes
        .iter()
        .filter_map(|node| node.memory.as_ref())
        .collect();
    let mut candidates = Vec::new();
    let mut states = Vec::new();
    let mut truncated = false;
    for (index, entry) in fs::read_dir(&folder)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if index == SCAN_LIMIT {
            truncated = true;
            break;
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let relative = Path::new("snapshots").join(entry.file_name());
        if layer_name(&relative) && !roots.contains(&relative) {
            candidates.push(relative);
        } else if state_name(&relative) && !memories.contains(&relative) {
            states.push(relative);
        }
    }
    states.retain(|relative| {
        fs::symlink_metadata(directory.join(relative))
            .is_ok_and(|metadata| metadata.file_type().is_file())
    });
    // Memory files a failed Full take left behind: no checkpoint names them
    // and no snapshot operation is unfinished (`state` checked the journal).
    let removed_states = remove(&directory, states.iter(), &BTreeSet::new(), limit)?;
    if candidates.is_empty() {
        return Ok(
            if removed_states > 0 && (states.len() > removed_states || truncated) {
                Sweep::More {
                    removed: removed_states,
                }
            } else {
                Sweep::Done {
                    removed: removed_states,
                }
            },
        );
    }
    let live = live_set(&directory, &manifest, record.as_ref())?;
    let unreferenced: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|relative| {
            let path = directory.join(relative);
            fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file())
                && fs::canonicalize(&path).is_ok_and(|path| !live.contains(&path))
        })
        .collect();
    let removed = remove(
        &directory,
        unreferenced.iter(),
        &live,
        limit.saturating_sub(removed_states),
    )? + removed_states;
    // A pass that removed nothing ends the sweep, so it always terminates.
    Ok(
        if removed > 0 && (unreferenced.len() + states.len() > removed || truncated) {
            Sweep::More { removed }
        } else {
            Sweep::Done { removed }
        },
    )
}

#[cfg(test)]
mod tests;
