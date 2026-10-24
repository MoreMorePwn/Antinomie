// SPDX-License-Identifier: GPL-3.0-only
//! Hashing the files a run created or changed from a saved disk dump of the
//! machine, so a file the trace hashed only by SHA-256 (or not at all) can be
//! looked up by SHA-256 and MD5. The dump is read by the sandboxed disk
//! reader; nothing on it is run or unpacked.
use super::indicator::Hashes;
use crate::disks::{
    dump::{self, DiskDump},
    reader::{DiskAnswer, DiskRequest, Reader},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

/// Most files hashed from one dump.
pub const FILE_LIMIT: usize = 2_000;
/// Largest file hashed.
pub const SIZE_LIMIT: u64 = 256 * 1024 * 1024;

/// Hashes one file of a disk image.
pub trait FileHasher {
    /// SHA-256 and MD5 of the file at `path` (a guest path), or why not.
    fn hash(&mut self, path: &str, size_limit: u64) -> Result<Hashes, String>;
}

/// The sandboxed disk reader, as a hasher.
pub struct ImageHasher {
    reader: Reader,
}

impl ImageHasher {
    pub fn open(image: &Path, out: &Path) -> Result<Self, String> {
        Ok(Self {
            reader: Reader::open(image, out)?,
        })
    }
}

impl FileHasher for ImageHasher {
    fn hash(&mut self, path: &str, size_limit: u64) -> Result<Hashes, String> {
        let reply = self.reader.request(DiskRequest::Info {
            path: path.to_owned(),
            hash_cap: size_limit,
        })?;
        match reply {
            Ok(DiskAnswer::Info(info)) => match info.sha256 {
                Some(sha256) => Ok(Hashes {
                    sha256,
                    md5: info.md5.unwrap_or_default(),
                    sha1: String::new(),
                }),
                None => Err(info.hash_note.unwrap_or_else(|| "not hashed".into())),
            },
            Ok(_) => Err("the reader answered something else".into()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// What hashing a list of paths gave.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hashed {
    pub hashes: BTreeMap<String, Hashes>,
    /// Paths that were not hashed, with the reason.
    pub skipped: Vec<(String, String)>,
    /// Paths left out because of [`FILE_LIMIT`].
    pub left_out: usize,
}

/// Hash `paths` (at most [`FILE_LIMIT`]) through `hasher`.
pub fn hash_paths(
    hasher: &mut dyn FileHasher,
    paths: &[String],
    cancel: &AtomicBool,
) -> Result<Hashed, String> {
    let mut done = Hashed {
        left_out: paths.len().saturating_sub(FILE_LIMIT),
        ..Hashed::default()
    };
    for path in paths.iter().take(FILE_LIMIT) {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        match hasher.hash(path, SIZE_LIMIT) {
            Ok(hashes) => {
                done.hashes.insert(path.clone(), hashes);
            }
            Err(why) => done.skipped.push((path.clone(), why)),
        }
    }
    Ok(done)
}

/// The newest saved dump in a run's recording folder that can be read.
pub fn newest_dump(recording_dir: &Path) -> Option<DiskDump> {
    dump::list(&[recording_dir.to_path_buf()])
        .into_iter()
        .find(|dump| dump.browsable())
}

/// Where the reader may put files it extracts: a private, empty folder.
pub fn scratch(recording_dir: &Path) -> Result<PathBuf, String> {
    let dir = recording_dir
        .join("ioc")
        .join(format!("reader-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(BTreeMap<&'static str, Result<Hashes, String>>);

    impl FileHasher for Fake {
        fn hash(&mut self, path: &str, _limit: u64) -> Result<Hashes, String> {
            self.0
                .get(path)
                .cloned()
                .unwrap_or_else(|| Err("not found".into()))
        }
    }

    fn hashes(sha: &str) -> Hashes {
        Hashes {
            sha256: sha.repeat(64),
            md5: sha.repeat(32),
            sha1: String::new(),
        }
    }

    #[test]
    fn files_are_hashed_in_order_and_refusals_are_kept_with_their_reason() {
        let mut fake = Fake(BTreeMap::from([
            ("/tmp/a", Ok(hashes("a"))),
            (
                "/tmp/big",
                Err("file is 300 MiB, over the 256 MiB limit".to_owned()),
            ),
        ]));
        let paths: Vec<String> = ["/tmp/a", "/tmp/big", "/tmp/gone"].map(String::from).into();
        let done = hash_paths(&mut fake, &paths, &AtomicBool::new(false)).unwrap();
        assert_eq!(done.hashes.len(), 1);
        assert_eq!(done.hashes["/tmp/a"].md5.len(), 32);
        assert_eq!(done.skipped.len(), 2);
        assert!(done.skipped[0].1.contains("256 MiB"));
        assert_eq!(done.left_out, 0);
    }

    #[test]
    fn at_most_two_thousand_files_are_hashed_and_a_cancel_stops() {
        struct Count(usize);
        impl FileHasher for Count {
            fn hash(&mut self, _path: &str, _limit: u64) -> Result<Hashes, String> {
                self.0 += 1;
                Ok(Hashes::default())
            }
        }
        let paths: Vec<String> = (0..2_005).map(|n| format!("/tmp/f{n}")).collect();
        let mut count = Count(0);
        let done = hash_paths(&mut count, &paths, &AtomicBool::new(false)).unwrap();
        assert_eq!((count.0, done.left_out), (FILE_LIMIT, 5));
        let error = hash_paths(&mut Count(0), &paths, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error, "cancelled");
    }
}
