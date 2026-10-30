// SPDX-License-Identifier: GPL-3.0-only
//! What the base image says about the programs a run used.
//!
//! The sample window's lineage graph hides the base image's own programs
//! (curl, crontab, rm ...) so that what the sample did is not buried. A
//! program counts as one of them when its SHA-256 equals that of the file at
//! the same path in the installed base the run's disk came from
//! (`disk_base_identity` in the run's manifest), read on the host by the
//! sandboxed disk reader, as [`crate::guest_names`] reads `/etc/passwd`. A
//! program the base does not have, or whose bytes differ, is not hidden.
use crate::api::BackendOptions;
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Largest program read out of the base to hash it.
const PROGRAM_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// Hashes kept for the bases of this process.
const CACHE_MAX_COUNT: usize = 4096;

type CacheKey = (PathBuf, u64, i64, String);

fn cache() -> &'static Mutex<HashMap<CacheKey, Option<String>>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<CacheKey, Option<String>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// The installed base image file a run's disk came from, when it is still
/// installed and the run says which it was.
fn base_image(data_dir: &Path, run_directory: &Path) -> Result<Option<PathBuf>, String> {
    let manifest: serde_json::Value =
        crate::storage::read_json(&run_directory.join("manifest.json"))
            .map_err(|error| format!("run manifest: {error}"))?;
    let Some(identity) = manifest
        .get("disk_base_identity")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let options = BackendOptions {
        data_dir: data_dir.to_path_buf(),
        ..Default::default()
    };
    let Some(base) = crate::locations::installed_bases(&options)?
        .into_iter()
        .find(|base| base.id == identity)
    else {
        return Ok(None);
    };
    Ok(Some(
        crate::storage::Bundle::load(&base.directory)?.base_disk,
    ))
}

/// The SHA-256 of each of `paths` that the run's base image has, as a set.
/// An empty set when the base is not installed or does not say.
pub fn hashes_of(
    data_dir: &Path,
    run_directory: &Path,
    paths: &[String],
) -> Result<BTreeSet<String>, String> {
    use crate::disks::reader::{DiskAnswer, DiskRequest, Reader};
    let Some(image) = base_image(data_dir, run_directory)? else {
        return Ok(BTreeSet::new());
    };
    let metadata = std::fs::metadata(&image).map_err(|error| error.to_string())?;
    let (size, mtime) = (
        metadata.len(),
        std::os::unix::fs::MetadataExt::mtime(&metadata),
    );
    let mut found = BTreeSet::new();
    let mut unread = Vec::new();
    {
        let cache = cache().lock().map_err(|_| "manifest cache")?;
        for path in paths {
            match cache.get(&(image.clone(), size, mtime, path.clone())) {
                Some(Some(hash)) => {
                    found.insert(hash.clone());
                }
                Some(None) => {}
                None => unread.push(path),
            }
        }
    }
    if unread.is_empty() {
        return Ok(found);
    }
    let scratch = std::env::temp_dir().join(format!(
        "antinomie-base-manifest-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    let result = (|| {
        let mut reader = Reader::open(&image, &scratch)?;
        let mut read = Vec::new();
        for path in unread {
            let answer = reader.request(DiskRequest::Extract {
                path: path.clone(),
                max_len: PROGRAM_MAX_SIZE,
            })?;
            let hash = match answer {
                Ok(DiskAnswer::Extracted(_)) => {
                    let out = scratch.join(reader.last_request_id().to_string());
                    let bytes = std::fs::read(&out).map_err(|error| error.to_string())?;
                    let _ = std::fs::remove_file(&out);
                    Some(crate::storage::sha256_hex(&bytes))
                }
                // Not in the base, or too large to hash: not a base program.
                Err(_) => None,
                Ok(other) => return Err(format!("{path}: unexpected answer {other:?}")),
            };
            read.push((path.clone(), hash));
        }
        Ok(read)
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    let read: Vec<(String, Option<String>)> = result?;
    let mut cache = cache().lock().map_err(|_| "manifest cache")?;
    if cache.len() >= CACHE_MAX_COUNT {
        cache.clear();
    }
    for (path, hash) in read {
        if let Some(hash) = &hash {
            found.insert(hash.clone());
        }
        cache.insert((image.clone(), size, mtime, path), hash);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_without_a_base_identity_has_no_manifest() {
        let dir = std::env::temp_dir().join(format!(
            "antinomie-base-manifest-test-{}",
            crate::storage::unique_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        let hashes = hashes_of(&dir, &dir, &["/usr/bin/curl".into()]).unwrap();
        assert!(hashes.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
