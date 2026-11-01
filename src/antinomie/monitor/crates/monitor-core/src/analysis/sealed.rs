// SPDX-License-Identifier: GPL-3.0-only
//! The retained specimen at rest. An analysis folder keeps the program it
//! analyzed so previews, checks added later and the detection scan can read
//! it again, but never as a plain file once the work on it is over: it is
//! stored as `specimen.zip`, an AES zip with the library's password and
//! format, and a plain `specimen` exists only while a worker needs one
//! (`materialize`), which `seal` removes again. Folders from before this
//! change are sealed when their run is opened (`seal_tree`).
use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

/// The encrypted specimen next to its report.
pub(crate) const SEALED: &str = "specimen.zip";
/// The plain specimen a worker is given; present only while one needs it.
pub(crate) const PLAIN: &str = "specimen";
const PARTIAL: &str = "specimen.zip.part";
const UNSEALED_PARTIAL: &str = "specimen.partial";
const MATERIALIZING: &str = "specimen.plain.part";
/// Deepest folder nesting `seal_tree` follows (`extra/<id>`, layer folders).
const TREE_DEPTH: usize = 4;

/// Folders a job in this process owns right now: their plain specimen is the
/// job's, so opening a run must leave it alone.
static OWNED: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());

/// A job takes the folder as its own until it is finished.
pub(crate) fn claim(directory: &Path) {
    OWNED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(directory.to_path_buf());
}

/// The job is finished with the folder (sealed or not).
pub(crate) fn release(directory: &Path) {
    let mut owned = OWNED.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(index) = owned.iter().position(|d| d == directory) {
        owned.swap_remove(index);
    }
}

fn owned(directory: &Path) -> bool {
    OWNED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|d| d == directory)
}

fn open_dir(directory: &Path) -> Result<File, String> {
    let root = File::open(directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    if !root.metadata().map_err(|e| e.to_string())?.is_dir() {
        return Err(format!("{} is not a folder", directory.display()));
    }
    Ok(root)
}

/// Open a regular member without following links; `Ok(None)` if absent.
fn open_member(root: &File, name: &str) -> Result<Option<File>, String> {
    match openat(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err(format!("{name} is not a regular file"));
            }
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(format!("{name}: {error}")),
    }
}

fn create_member(root: &File, name: &str) -> Result<File, String> {
    let _ = unlinkat(root, name, AtFlags::empty());
    openat(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|e| format!("{name}: {e}"))
}

fn remove_member(root: &File, name: &str) {
    let _ = unlinkat(root, name, AtFlags::empty());
}

struct Hashing<'a, R> {
    inner: R,
    digest: &'a mut Sha256,
}
impl<R: Read> Read for Hashing<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.digest.update(&buffer[..count]);
        Ok(count)
    }
}

fn hex(digest: Sha256) -> String {
    format!("{:x}", digest.finalize())
}

/// Decrypt the archive `file` into `sink`, returning the plaintext's SHA-256
/// and length. The zip crate checks the AES authentication code and CRC.
fn decrypt_into(file: File, sink: &mut dyn Write, limit: u64) -> Result<(String, u64), String> {
    let mut zip = crate::zip_safe::open(file).map_err(|e| format!("sealed specimen: {e}"))?;
    if zip.len() != 1 {
        return Err("the sealed specimen archive does not hold exactly one file".into());
    }
    let mut entry = zip
        .by_index_decrypt(0, crate::samples::ARCHIVE_PASSWORD.as_bytes())
        .map_err(|e| format!("sealed specimen: {e}"))?;
    if entry.size() > limit {
        return Err(format!("sealed specimen exceeds the {limit} byte bound"));
    }
    let mut digest = Sha256::new();
    let mut reader = Hashing {
        inner: entry.by_ref().take(limit + 1),
        digest: &mut digest,
    };
    let copied = io::copy(&mut reader, sink).map_err(|e| format!("sealed specimen: {e}"))?;
    if copied > limit {
        return Err(format!("sealed specimen exceeds the {limit} byte bound"));
    }
    Ok((hex(digest), copied))
}

fn bound() -> u64 {
    u64::from(crate::control::SPECIMEN_MAX_SIZE)
}

/// The whole specimen, decrypted into memory, with its SHA-256. Bounded by
/// the specimen size limit; for the readers that verify against the report.
pub(crate) fn read_sealed(directory: &Path) -> Result<(Vec<u8>, String), String> {
    let root = open_dir(directory)?;
    let file = open_member(&root, SEALED)?.ok_or("the sealed specimen is missing")?;
    let mut data = Vec::new();
    let (sha256, _) = decrypt_into(file, &mut data, bound())?;
    Ok((data, sha256))
}

/// Metadata of the archive, so a reader can tell it changed under it.
pub(crate) fn sealed_file(directory: &Path) -> Result<File, String> {
    let root = open_dir(directory)?;
    open_member(&root, SEALED)?.ok_or_else(|| "the sealed specimen is missing".into())
}

/// Make the plain `specimen` a worker is bound to exist, from the archive
/// when the folder holds only that. The caller seals again when it is done.
pub(crate) fn materialize(directory: &Path) -> Result<(), String> {
    let root = open_dir(directory)?;
    if open_member(&root, PLAIN)?.is_some() {
        return Ok(());
    }
    let archive = open_member(&root, SEALED)?.ok_or("the retained specimen is missing")?;
    let mut out = create_member(&root, MATERIALIZING)?;
    let result = decrypt_into(archive, &mut out, bound())
        .and_then(|_| out.sync_all().map_err(|e| e.to_string()))
        .and_then(|()| {
            renameat(&root, MATERIALIZING, &root, PLAIN).map_err(|e| format!("{PLAIN}: {e}"))
        });
    if result.is_err() {
        remove_member(&root, MATERIALIZING);
    }
    result
}

/// The specimen as a file to read from the start: the plain one when a worker
/// has it out, otherwise an unnamed file (gone when closed) holding the
/// decrypted bytes. Returns the file and its length.
pub(crate) fn open_plain(directory: &Path) -> Result<(File, u64), String> {
    let root = open_dir(directory)?;
    if let Some(file) = open_member(&root, PLAIN)? {
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        return Ok((file, len));
    }
    let archive = open_member(&root, SEALED)?.ok_or("the retained specimen is missing")?;
    let mut temporary = File::from(
        openat(
            &root,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| format!("unnamed file: {e}"))?,
    );
    let (_, len) = decrypt_into(archive, &mut temporary, bound())?;
    temporary
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;
    Ok((temporary, len))
}

/// Keep the specimen of `directory` only as the encrypted archive: write it
/// (checked by reading it back), then remove the plain file. `Ok(true)` when
/// a plain specimen was removed. A plain file that already has an identical
/// archive is just removed.
pub(crate) fn seal(directory: &Path) -> Result<bool, String> {
    let root = open_dir(directory)?;
    let Some(mut plain) = open_member(&root, PLAIN)? else {
        return Ok(false);
    };
    let mut digest = Sha256::new();
    let len = io::copy(
        &mut Hashing {
            inner: &mut plain,
            digest: &mut digest,
        },
        &mut io::sink(),
    )
    .map_err(|e| format!("{PLAIN}: {e}"))?;
    let sha256 = hex(digest);
    // An archive from before this materialization is already the copy.
    let existing = open_member(&root, SEALED)?
        .and_then(|file| decrypt_into(file, &mut io::sink(), u64::MAX / 2).ok());
    if existing != Some((sha256.clone(), len)) {
        write_archive(&root, &mut plain, &sha256, len)?;
    }
    remove_member(&root, PLAIN);
    Ok(true)
}

fn write_archive(root: &File, plain: &mut File, sha256: &str, len: u64) -> Result<(), String> {
    plain
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("{PLAIN}: {e}"))?;
    let result = (|| {
        let out = create_member(root, PARTIAL)?;
        let mut writer = zip::ZipWriter::new(out);
        writer
            .start_file(
                format!("{sha256}.bin"),
                zip::write::SimpleFileOptions::default()
                    .large_file(len >= u64::from(u32::MAX))
                    .with_aes_encryption(zip::AesMode::Aes256, crate::samples::ARCHIVE_PASSWORD),
            )
            .map_err(|e| format!("sealed specimen: {e}"))?;
        io::copy(plain, &mut writer).map_err(|e| format!("sealed specimen: {e}"))?;
        let out = writer
            .finish()
            .map_err(|e| format!("sealed specimen: {e}"))?;
        out.sync_all().map_err(|e| e.to_string())?;
        // Read back as every reader does: it must open and equal the original.
        let back = open_member(root, PARTIAL)?.ok_or("sealed specimen vanished")?;
        let (check, copied) = decrypt_into(back, &mut io::sink(), u64::MAX / 2)?;
        if check != sha256 || copied != len {
            return Err("the sealed specimen does not match the original".into());
        }
        renameat(root, PARTIAL, root, SEALED).map_err(|e| format!("{SEALED}: {e}"))?;
        root.sync_all().map_err(|e| e.to_string())
    })();
    if result.is_err() {
        remove_member(root, PARTIAL);
    }
    result
}

/// Seal every plain specimen in `directory` and the folders below it, and
/// drop partial guest transfers (never analyzed, so nothing needs them).
/// Only for folders no job owns: a saved run being opened. Returns the
/// problems met; a failed seal leaves that plain file for the next try.
pub(crate) fn seal_tree(directory: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    seal_tree_at(directory, 0, &mut problems);
    problems
}

fn seal_tree_at(directory: &Path, depth: usize, problems: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    if !owned(directory) {
        if let Err(error) = seal(directory) {
            problems.push(format!("{}: {error}", directory.display()));
        }
        let _ = std::fs::remove_file(directory.join(UNSEALED_PARTIAL));
        let _ = std::fs::remove_file(directory.join(MATERIALIZING));
    }
    if depth >= TREE_DEPTH {
        return;
    }
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            seal_tree_at(&entry.path(), depth + 1, problems);
        }
    }
}

#[cfg(test)]
fn is_sealed_only(directory: &Path) -> bool {
    !directory.join(PLAIN).exists() && directory.join(SEALED).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn folder(tag: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("ant-sealed-{tag}-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn sealing_replaces_the_plain_specimen_with_an_encrypted_archive() {
        let dir = folder("seal");
        let bytes: Vec<u8> = (0..70_000u32).map(|n| (n * 7 % 251) as u8).collect();
        std::fs::write(dir.join(PLAIN), &bytes).unwrap();
        assert_eq!(seal(&dir), Ok(true));
        assert!(!dir.join(PLAIN).exists(), "no plain copy may remain");
        let archive = std::fs::read(dir.join(SEALED)).unwrap();
        assert!(
            archive
                .windows(64)
                .all(|w| !bytes.windows(64).any(|b| b == w)),
            "the archive must not hold the plain bytes"
        );
        assert_eq!(
            std::fs::metadata(dir.join(SEALED))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!dir.join(PARTIAL).exists());
        let (back, sha) = read_sealed(&dir).unwrap();
        assert_eq!(back, bytes);
        assert_eq!(sha, format!("{:x}", Sha256::digest(&bytes)));
        // Nothing left to seal.
        assert_eq!(seal(&dir), Ok(false));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn materializing_gives_a_worker_a_plain_file_that_sealing_removes_again() {
        let dir = folder("materialize");
        std::fs::write(dir.join(PLAIN), b"benign bytes").unwrap();
        seal(&dir).unwrap();
        assert!(is_sealed_only(&dir));
        materialize(&dir).unwrap();
        assert_eq!(std::fs::read(dir.join(PLAIN)).unwrap(), b"benign bytes");
        let archive = std::fs::read(dir.join(SEALED)).unwrap();
        // The archive is already the copy: sealing just removes the plain file.
        assert_eq!(seal(&dir), Ok(true));
        assert_eq!(std::fs::read(dir.join(SEALED)).unwrap(), archive);
        assert!(!dir.join(PLAIN).exists());
        let (mut file, len) = open_plain(&dir).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!((text.as_str(), len), ("benign bytes", 12));
        assert!(!dir.join(PLAIN).exists(), "the unnamed file leaves no name");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_tampered_archive_is_refused_and_a_failed_seal_keeps_the_plain_file() {
        let dir = folder("tamper");
        std::fs::write(dir.join(PLAIN), vec![5u8; 4096]).unwrap();
        seal(&dir).unwrap();
        let mut archive = std::fs::read(dir.join(SEALED)).unwrap();
        let middle = archive.len() / 2;
        archive[middle] ^= 0xff;
        std::fs::write(dir.join(SEALED), &archive).unwrap();
        assert!(read_sealed(&dir).is_err());
        assert!(materialize(&dir).is_err());
        assert!(!dir.join(MATERIALIZING).exists());
        // A symlink is not a member.
        std::fs::remove_file(dir.join(SEALED)).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.join(SEALED)).unwrap();
        assert!(read_sealed(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn opening_an_old_run_seals_every_nested_specimen_and_drops_partial_transfers() {
        let dir = folder("tree");
        std::fs::create_dir_all(dir.join("extra/abc")).unwrap();
        std::fs::write(dir.join(PLAIN), b"one").unwrap();
        std::fs::write(dir.join("extra/abc").join(PLAIN), b"two").unwrap();
        std::fs::write(dir.join(UNSEALED_PARTIAL), b"half").unwrap();
        assert!(seal_tree(&dir).is_empty());
        for sub in [dir.clone(), dir.join("extra/abc")] {
            assert!(!sub.join(PLAIN).exists());
            assert!(sub.join(SEALED).is_file());
        }
        assert!(!dir.join(UNSEALED_PARTIAL).exists());
        assert_eq!(read_sealed(&dir.join("extra/abc")).unwrap().0, b"two");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
