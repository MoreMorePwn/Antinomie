// SPDX-License-Identifier: GPL-3.0-only
//! Bounded archive unpacking and link-free copies.
use super::*;

pub(super) fn unpack_archive(bytes: &[u8], dest: &Path) -> Result<(), String> {
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err("archive exceeds the compressed byte limit".into());
    }
    let free = scratch_free(dest)?;
    if free < 1024 * 1024 {
        return Err(format!(
            "not enough scratch space ({free} bytes free); the previous selection was kept"
        ));
    }
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    let mut members = 0usize;
    let mut expanded = 0u64;
    for entry in archive.entries().map_err(|error| error.to_string())? {
        members += 1;
        if members > MAX_MEMBERS {
            return Err("archive has too many members".into());
        }
        let mut entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.header().entry_type();
        let raw = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let rel = safe_relative(&raw)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        if !matches!(kind, tar::EntryType::Regular | tar::EntryType::Directory) {
            return Err(format!(
                "archive entry {} is not a regular file",
                rel.display()
            ));
        }
        let declared = entry.header().size().map_err(|error| error.to_string())?;
        if declared > MAX_FILE_BYTES {
            return Err(format!("{} exceeds the per-file byte limit", rel.display()));
        }
        expanded = expanded.saturating_add(declared);
        if expanded > MAX_EXPANDED_BYTES {
            return Err("archive exceeds the expanded byte limit".into());
        }
        let target = dest.join(&rel);
        reject_symlink_destination(dest, &target)?;
        if kind == tar::EntryType::Directory {
            crate::storage::private_dir(&target).map_err(|error| error.to_string())?;
            continue;
        }
        if let Some(parent) = target.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        #[cfg(test)]
        if take_fail("unpack-write") {
            return Err(format!(
                "write {}: {}",
                rel.display(),
                std::io::Error::from_raw_os_error(28)
            ));
        }
        let mut file = fs::File::create(&target)
            .map_err(|error| format!("write {}: {error}", rel.display()))?;
        std::io::copy(&mut entry, &mut file)
            .map_err(|error| format!("write {}: {error}", rel.display()))?;
        file.sync_all()
            .map_err(|error| format!("fsync {}: {error}", rel.display()))?;
    }
    Ok(())
}

fn scratch_free(path: &Path) -> Result<u64, String> {
    let stat = rustix::fs::statvfs(path).map_err(|error| error.to_string())?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

fn reject_symlink_destination(root: &Path, target: &Path) -> Result<(), String> {
    let mut cursor = target.to_path_buf();
    loop {
        if cursor
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(format!("{} is a symlink", cursor.display()));
        }
        if cursor == root {
            break;
        }
        if !cursor.pop() {
            break;
        }
    }
    Ok(())
}

fn safe_relative(path: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "archive path {} escapes the pack root",
                    path.display()
                ));
            }
        }
    }
    Ok(out)
}

pub(super) fn copy_import(source: &Path, dest: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("import root is a link".into());
    }
    if meta.is_file() {
        let name = source.file_name().ok_or("import file has no name")?;
        fs::copy(source, dest.join(name)).map_err(|error| error.to_string())?;
        return Ok(());
    }
    if !meta.is_dir() {
        return Err("import source is not a file or directory".into());
    }
    let root = source.canonicalize().map_err(|error| error.to_string())?;
    copy_checked(&root, &root, dest, 0)
}

fn copy_checked(root: &Path, dir: &Path, dest: &Path, depth: u32) -> Result<(), String> {
    if depth > 16 {
        return Err("import directory is too deep".into());
    }
    crate::storage::private_dir(dest).map_err(|error| error.to_string())?;
    let mut count = 0;
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        count += 1;
        if count > 8192 {
            return Err("import directory has too many entries".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a link", path.display()));
        }
        let canon = path.canonicalize().map_err(|error| error.to_string())?;
        if !canon.starts_with(root) {
            return Err(format!("{} escapes the import root", path.display()));
        }
        let name = entry.file_name();
        if meta.is_dir() {
            copy_checked(root, &path, &dest.join(name), depth + 1)?;
        } else if meta.is_file() {
            fs::copy(&path, dest.join(name)).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(super) fn copy_tree_regular(source: &Path, dest: &Path) -> Result<(), String> {
    crate::storage::private_dir(dest).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("snapshot contains a link".into());
        }
        let target = dest.join(entry.file_name());
        if meta.is_dir() {
            copy_tree_regular(&entry.path(), &target)?;
        } else if meta.is_file() {
            fs::copy(entry.path(), target).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(super) fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) -> Result<(), String> {
    if depth > 16 {
        return Err("pack directory is too deep".into());
    }
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a link", path.display()));
        }
        if meta.is_dir() {
            collect_files(&path, out, depth + 1)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
}
