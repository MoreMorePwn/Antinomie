// SPDX-License-Identifier: GPL-3.0-only
use crate::api::{BackendOptions, GuestProfile, Health, VmConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn unique_id() -> String {
    let mut random = [0u8; 16];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .is_ok()
    {
        return random.iter().map(|byte| format!("{byte:02x}")).collect();
    }
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}
pub(crate) fn vm_id(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    format!(
        "{}_{}",
        if slug.trim_matches('_').is_empty() {
            "vm"
        } else {
            slug.trim_matches('_')
        },
        unique_id()
    )
}
pub(crate) fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
/// SHA-256 of an in-memory buffer, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// SHA-256 of a file's bytes. Two files of the same length differ when their
/// contents differ.
pub fn sha256_file_hex(path: &Path) -> Result<String, String> {
    Ok(sha256_file(path)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    sha256_uncached(file)
}

/// SHA-256 of a whole file, read once and released from the page cache as
/// it goes: hashing a multi-GiB base must not leave GiBs of cache behind
/// (under WSL the VM keeps that memory from Windows).
pub(crate) fn sha256_uncached(mut file: File) -> Result<[u8; 32], String> {
    use rustix::fs::{Advice, fadvise};
    let _ = fadvise(&file, 0, None, Advice::Sequential);
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut done = 0u64;
    loop {
        let used = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if used == 0 {
            break;
        }
        digest.update(&buffer[..used]);
        done += used as u64;
        if done % (64 << 20) < used as u64 {
            let _ = fadvise(&file, 0, std::num::NonZeroU64::new(done), Advice::DontNeed);
        }
    }
    let _ = fadvise(&file, 0, None, Advice::DontNeed);
    Ok(digest.finalize().into())
}

/// What a verified base file looked like: if it still does, its content
/// checksum from that verification stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    name: String,
    len: u64,
    modified_ns: i128,
    changed_ns: i128,
    inode: u64,
    device: u64,
    sha256: String,
}

impl FileStamp {
    fn of(path: &Path, sha256: String) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        Ok(Self {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            len: meta.len(),
            modified_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            changed_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
            inode: meta.ino(),
            device: meta.dev(),
            sha256,
        })
    }
}

/// Supplies a base file's SHA-256: hashed, or taken from an earlier check.
type ChecksumSource<'a> = dyn FnMut(File, &Path) -> Result<[u8; 32], String> + 'a;

/// The checksum a previous verification recorded for `path`, if the file
/// is unchanged since.
fn stored_checksum(previous: Option<&Verified>, path: &Path) -> Option<([u8; 32], FileStamp)> {
    let now = FileStamp::of(path, String::new()).ok()?;
    let stamp = previous?.files.iter().find(|old| {
        FileStamp {
            sha256: String::new(),
            ..(*old).clone()
        } == now
    })?;
    let mut checksum = [0u8; 32];
    for (index, byte) in checksum.iter_mut().enumerate() {
        *byte = u8::from_str_radix(stamp.sha256.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some((checksum, stamp.clone()))
}

/// `<data>/bases/.<identity>.verified`: the file stamps of the last full
/// verification of an installed base.
#[derive(Debug, Serialize, Deserialize)]
struct Verified {
    identity: String,
    files: Vec<FileStamp>,
}
#[derive(Debug)]
pub(crate) struct PublicationError {
    pub published: bool,
    message: String,
}
impl std::fmt::Display for PublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.published {
            write!(
                f,
                "{}; change is visible, durability is uncertain; data retained",
                self.message
            )
        } else {
            f.write_str(&self.message)
        }
    }
}
impl std::error::Error for PublicationError {}
impl From<String> for PublicationError {
    fn from(message: String) -> Self {
        Self {
            published: false,
            message,
        }
    }
}
impl From<&str> for PublicationError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<PublicationError> for String {
    fn from(error: PublicationError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::RefCell<Option<(PathBuf, usize)>> = const {
        std::cell::RefCell::new(None)
    };
    static FAIL_JSON_RENAME: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}
#[cfg(test)]
pub(crate) fn fail_next_json_rename(path: &Path) {
    FAIL_JSON_RENAME.with(|target| *target.borrow_mut() = Some(path.to_owned()));
}
fn rename_json(temporary: &Path, path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_JSON_RENAME.with(|target| {
        let mut target = target.borrow_mut();
        if target.as_deref() == Some(path) {
            target.take();
            true
        } else {
            false
        }
    }) {
        return Err(io::Error::other("injected JSON rename failure"));
    }
    fs::rename(temporary, path)
}
#[cfg(test)]
pub(crate) fn fail_next_directory_sync(path: &Path) {
    fail_directory_sync_after(path, 0);
}
#[cfg(test)]
pub(crate) fn fail_directory_sync_after(path: &Path, successful_calls: usize) {
    FAIL_DIRECTORY_SYNC
        .with(|target| *target.borrow_mut() = Some((path.to_owned(), successful_calls)));
}
fn sync_json_parent(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|target| {
        let mut target = target.borrow_mut();
        if let Some((wanted, remaining)) = target.as_mut()
            && wanted == path
        {
            if *remaining == 0 {
                target.take();
                return true;
            }
            *remaining -= 1;
        }
        false
    }) {
        return Err(io::Error::other("injected directory sync failure"));
    }
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("missing parent"))?,
    )?
    .sync_all()
}

pub(crate) fn sync_directory_parent(directory: &Path) -> Result<(), String> {
    let parent = directory.parent().ok_or("missing VM directory parent")?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync VM parent {}: {error}", parent.display()))
}

mod json_queue;
#[cfg(test)]
pub(crate) use json_queue::transport_sync_writes;
pub(crate) use json_queue::{
    JsonReceipt, JsonWriteStatus, flush_json, mark_transport_thread, queue_bytes, queue_json,
    queue_json_observed,
};
#[cfg(test)]
pub(crate) use json_queue::{held as slow_disk, settle_json_under};
use json_queue::{note_sync_write, settle_json};

pub(crate) fn atomic_json_checked(
    path: &Path,
    value: &impl Serialize,
) -> Result<(), PublicationError> {
    // A direct write has no size cap; only queued values are bounded.
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| PublicationError {
        published: false,
        message: e.to_string(),
    })?;
    bytes.push(b'\n');
    note_sync_write();
    settle_json(path);
    write_atomic(path, &bytes)
}

/// Writes `bytes` to `path` atomically now, after any queued write to it.
pub(crate) fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    note_sync_write();
    settle_json(path);
    write_atomic(path, bytes).map_err(Into::into)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PublicationError> {
    let temporary = path.with_extension(format!("tmp-{}", unique_id()));
    let mut published = false;
    let result = (|| -> Result<(), String> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        rename_json(&temporary, path).map_err(|e| e.to_string())?;
        published = true;
        sync_json_parent(path).map_err(|e| format!("sync {}: {e}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(|message| PublicationError { published, message })
}
pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    atomic_json_checked(path, value).map_err(Into::into)
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let file = crate::archive_io::open_regular(path.parent().ok_or("missing JSON parent")?, &path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("configuration JSON exceeds 1 MiB limit".into());
    }
    serde_json::from_reader(file).map_err(|error| format!("{}: {error}", path.display()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleBuildProvenance {
    pub parent_identity: Option<String>,
    pub kernel_sha256: String,
    pub base_disk_sha256: String,
    pub initrd_sha256: Option<String>,
    pub kernel_config_sha256: String,
}
impl BundleBuildProvenance {
    fn validate(&self) -> Result<(), String> {
        for value in [
            self.parent_identity.as_ref(),
            Some(&self.kernel_sha256),
            Some(&self.base_disk_sha256),
            self.initrd_sha256.as_ref(),
            Some(&self.kernel_config_sha256),
        ]
        .into_iter()
        .flatten()
        {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("bundle provenance requires lowercase SHA256 values".into());
            }
        }
        Ok(())
    }
}

/// File name of a base's Volatility symbol table.
pub const SYMBOLS_FILE: &str = "symbols.json.xz";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    /// The guest architecture the base is built for: `"arm64"`, or absent
    /// for x86-64 (every base before arm64 existed).
    #[serde(default, skip_serializing_if = "crate::api::GuestArch::is_x86_64")]
    pub arch: crate::api::GuestArch,
    pub kernel: PathBuf,
    pub base_disk: PathBuf,
    pub initrd: Option<PathBuf>,
    #[serde(default)]
    pub kernel_append: String,
    #[serde(default)]
    pub kernel_version: String,
    #[serde(default)]
    pub schema_id: u32,
    #[serde(default)]
    pub base_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestProfile>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fixed_display: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_provenance: Option<BundleBuildProvenance>,
    /// Antinomie patch revision of the kernel (from its embedded source id).
    /// Advisory: not part of the identity; the running kernel is checked at attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub antinomie_revision: Option<u32>,
    /// SHA-256 of the core patch series the kernel was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub antinomie_source: Option<String>,
    /// Antinomie version that built the base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_with: Option<String>,
    /// Oldest Antinomie version that can run the base (its kernel revision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_app_version: Option<String>,
    /// Display name chosen when the base was built; not part of the identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Volatility 3 symbol table (ISF, xz) of the kernel, for memory
    /// analysis; bases before 0.4.0 have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<PathBuf>,
    /// Device profile entries the base boots with besides virtio, SeaBIOS
    /// and 10.0.2.0/24: `uefi`, `sata`, `nvme`, `dhcp` (written by the image
    /// builders). Advisory: an entry a base lacks falls back at launch; not
    /// part of the identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stealth_support: Vec<String>,
    /// A Debian Minimal base's UEFI layout, and in a VM's copy the derived
    /// UEFI disk (`crate::uefi_disk`).
    #[serde(flatten)]
    pub uefi: crate::uefi_disk::UefiFiles,
}
fn is_false(value: &bool) -> bool {
    !value
}
impl Bundle {
    /// The base runs Debian's own signed modules: a Debian image (the only
    /// bases with a guest profile), whose builder accepts only the stock
    /// kernel profile, Debian's configuration. Drivers that are modules there
    /// (NVMe, DRM, USB, libata) are Debian's builds, without Antinomie's hooks.
    pub fn runs_debian_modules(&self) -> bool {
        self.guest.is_some()
    }

    pub fn load(dir: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(dir).map_err(|e| format!("bundle {}: {e}", dir.display()))?;
        let mut b: Self = read_json(&root.join("bundle.json"))?;
        if let Some(guest) = &b.guest {
            guest.validate()?;
        }
        b.validate_revision()?;
        if b.stealth_support.len() > 16
            || b.stealth_support.iter().any(|item| {
                item.is_empty() || item.len() > 32 || !item.bytes().all(|c| c.is_ascii_lowercase())
            })
        {
            return Err("bundle has an invalid stealth_support list".into());
        }
        let resolve = |p: &Path| -> Result<PathBuf, String> {
            let path = fs::canonicalize(root.join(p))
                .map_err(|e| format!("artifact {}: {e}", p.display()))?;
            if !path.starts_with(&root) {
                return Err("bundle artifact escapes bundle directory".into());
            }
            Ok(path)
        };
        b.kernel = resolve(&b.kernel)?;
        b.base_disk = resolve(&b.base_disk)?;
        b.initrd = b.initrd.as_ref().map(|p| resolve(p)).transpose()?;
        b.symbols = b.symbols.as_ref().map(|p| resolve(p)).transpose()?;
        b.uefi.uefi_root = b.uefi.uefi_root.as_ref().map(|p| resolve(p)).transpose()?;
        b.uefi.uefi_layout = b
            .uefi
            .uefi_layout
            .as_ref()
            .map(|p| resolve(p))
            .transpose()?;
        if b.uefi.uefi_root.is_some() != b.uefi.uefi_layout.is_some() {
            return Err("bundle names only one of its UEFI layout files".into());
        }
        // Laid out by the app per installed base, never imported.
        b.uefi.uefi_disk = None;
        Ok(b)
    }
    /// The disk a VM's own disk is an overlay of: the base disk, or for a
    /// VM laid out for UEFI the base's derived UEFI disk.
    pub(crate) fn vm_disk(&self) -> &Path {
        self.uefi.uefi_disk.as_deref().unwrap_or(&self.base_disk)
    }
    fn validate_revision(&self) -> Result<(), String> {
        match (&self.antinomie_revision, &self.antinomie_source) {
            (None, None) => Ok(()),
            (Some(revision), Some(source))
                if crate::api::parse_source_id(&format!("{revision}:{source}")).is_some() =>
            {
                Ok(())
            }
            _ => Err::<(), String>("bundle has an invalid Antinomie revision or source".into()),
        }?;
        for version in [&self.built_with, &self.min_app_version]
            .into_iter()
            .flatten()
        {
            if crate::api::Version::parse(version).is_none() {
                return Err(format!(
                    "bundle has an invalid Antinomie version {version:?}"
                ));
            }
        }
        if let Some(name) = &self.name {
            crate::build::valid_base_name(name)?;
        }
        Ok(())
    }
    fn identity(&self) -> Result<String, String> {
        self.identity_with(&mut |file, _| sha256_uncached(file))
    }
    /// The identity, with file checksums from `checksum(file, path)`.
    fn identity_with(&self, checksum: &mut ChecksumSource) -> Result<String, String> {
        let mut digest = Sha256::new();
        digest.update(
            serde_json::to_vec(&(&self.kernel_append, &self.kernel_version, self.schema_id))
                .map_err(|e| e.to_string())?,
        );
        if let Some(guest) = &self.guest {
            guest.validate()?;
            digest.update(b"antinomie-guest-profile-v1");
            digest.update(serde_json::to_vec(guest).map_err(|e| e.to_string())?);
        }
        if self.fixed_display {
            digest.update(b"antinomie-fixed-display-v1");
        }
        if let Some(provenance) = &self.build_provenance {
            provenance.validate()?;
            if provenance.initrd_sha256.is_some() != self.initrd.is_some() {
                return Err("bundle provenance initrd presence mismatch".into());
            }
            digest.update(b"antinomie-build-provenance-v1");
            digest.update(serde_json::to_vec(provenance).map_err(|e| e.to_string())?);
        }
        let provenance = self.build_provenance.as_ref();
        for (path, expected) in [
            (
                Some(&self.kernel),
                provenance.map(|p| p.kernel_sha256.as_str()),
            ),
            (
                Some(&self.base_disk),
                provenance.map(|p| p.base_disk_sha256.as_str()),
            ),
            (
                self.initrd.as_ref(),
                provenance.and_then(|p| p.initrd_sha256.as_deref()),
            ),
        ] {
            if let Some(path) = path {
                if !fs::symlink_metadata(path)
                    .map_err(|e| e.to_string())?
                    .file_type()
                    .is_file()
                {
                    return Err("bundle artifacts must be regular files".into());
                }
                let file = crate::archive_io::open_regular(
                    path.parent().ok_or("missing artifact parent")?,
                    path,
                )
                .map_err(|e| e.to_string())?;
                let checksum: [u8; 32] = checksum(file, path)?;
                let hex: String = checksum.iter().map(|b| format!("{b:02x}")).collect();
                if expected.is_some_and(|expected| hex != expected) {
                    return Err("bundle artifact differs from build provenance".into());
                }
                digest.update([1]);
                digest.update(checksum);
            } else {
                digest.update([0]);
            }
        }
        // Absent in older bases, whose identity stays as it was.
        if let Some(path) = &self.symbols {
            let file = crate::archive_io::open_regular(
                path.parent().ok_or("missing artifact parent")?,
                path,
            )
            .map_err(|e| e.to_string())?;
            digest.update(b"antinomie-volatility-symbols-v1");
            digest.update(checksum(file, path)?);
        }
        // Absent in bases before 0.8.0, whose identity stays as it was.
        if let (Some(root), Some(layout)) = (&self.uefi.uefi_root, &self.uefi.uefi_layout) {
            digest.update(b"antinomie-uefi-layout-v1");
            for path in [root, layout] {
                let file = crate::archive_io::open_regular(
                    path.parent().ok_or("missing artifact parent")?,
                    path,
                )
                .map_err(|e| e.to_string())?;
                digest.update(checksum(file, path)?);
            }
        }
        Ok(format!("{:x}", digest.finalize()))
    }
    /// Import a content-addressed immutable base outside disposable build trees.
    pub(crate) fn install(self, options: &BackendOptions) -> Result<Self, String> {
        let identity = self.identity()?;
        let root = options.data_dir.join("bases");
        private_dir(&root).map_err(|e| e.to_string())?;
        let target = root.join(&identity);
        if !target.exists() {
            let staging = root.join(format!("import-{}", unique_id()));
            private_dir(&staging).map_err(|e| e.to_string())?;
            let result = (|| -> Result<(), String> {
                for (source, name) in [
                    (Some(&self.kernel), "kernel"),
                    (Some(&self.base_disk), "base.qcow2"),
                    (self.initrd.as_ref(), "initrd"),
                    (self.symbols.as_ref(), SYMBOLS_FILE),
                    (self.uefi.uefi_root.as_ref(), crate::uefi_disk::ROOT_FILE),
                    (
                        self.uefi.uefi_layout.as_ref(),
                        crate::uefi_disk::LAYOUT_FILE,
                    ),
                ] {
                    if let Some(source) = source {
                        let destination = staging.join(name);
                        fs::copy(source, &destination).map_err(|e| e.to_string())?;
                        File::open(&destination)
                            .and_then(|f| f.sync_all())
                            .map_err(|e| e.to_string())?;
                        fs::set_permissions(destination, fs::Permissions::from_mode(0o444))
                            .map_err(|e| e.to_string())?;
                    }
                }
                let copied = Self {
                    arch: self.arch,
                    kernel: staging.join("kernel"),
                    base_disk: staging.join("base.qcow2"),
                    initrd: self.initrd.as_ref().map(|_| staging.join("initrd")),
                    kernel_append: self.kernel_append.clone(),
                    kernel_version: self.kernel_version.clone(),
                    schema_id: self.schema_id,
                    base_identity: Some(identity.clone()),
                    guest: self.guest.clone(),
                    fixed_display: self.fixed_display,
                    build_provenance: self.build_provenance.clone(),
                    antinomie_revision: self.antinomie_revision,
                    antinomie_source: self.antinomie_source.clone(),
                    built_with: self.built_with.clone(),
                    min_app_version: self.min_app_version.clone(),
                    name: self.name.clone(),
                    symbols: self.symbols.as_ref().map(|_| staging.join(SYMBOLS_FILE)),
                    stealth_support: self.stealth_support.clone(),
                    uefi: crate::uefi_disk::UefiFiles {
                        uefi_root: self
                            .uefi
                            .uefi_root
                            .as_ref()
                            .map(|_| staging.join(crate::uefi_disk::ROOT_FILE)),
                        uefi_layout: self
                            .uefi
                            .uefi_layout
                            .as_ref()
                            .map(|_| staging.join(crate::uefi_disk::LAYOUT_FILE)),
                        uefi_disk: None,
                    },
                };
                if copied.identity()? != identity {
                    return Err("bundle changed during import; copies rejected".into());
                }
                match fs::rename(&staging, &target) {
                    Ok(()) => {}
                    Err(e) if target.exists() => {
                        let _ = e;
                    }
                    Err(e) => return Err(e.to_string()),
                }
                File::open(&root)
                    .and_then(|f| f.sync_all())
                    .map_err(|e| e.to_string())?;
                Ok(())
            })();
            if staging.exists() {
                let _ = fs::remove_dir_all(&staging);
            }
            result?;
        }
        let installed = Self {
            arch: self.arch,
            kernel: target.join("kernel"),
            base_disk: target.join("base.qcow2"),
            initrd: self.initrd.as_ref().map(|_| target.join("initrd")),
            kernel_append: self.kernel_append,
            kernel_version: self.kernel_version,
            schema_id: self.schema_id,
            base_identity: Some(identity),
            guest: self.guest,
            fixed_display: self.fixed_display,
            build_provenance: self.build_provenance,
            antinomie_revision: self.antinomie_revision,
            antinomie_source: self.antinomie_source,
            built_with: self.built_with,
            min_app_version: self.min_app_version,
            name: self.name,
            symbols: self.symbols.as_ref().map(|_| target.join(SYMBOLS_FILE)),
            stealth_support: self.stealth_support,
            uefi: crate::uefi_disk::UefiFiles {
                uefi_root: self
                    .uefi
                    .uefi_root
                    .map(|_| target.join(crate::uefi_disk::ROOT_FILE)),
                uefi_layout: self
                    .uefi
                    .uefi_layout
                    .map(|_| target.join(crate::uefi_disk::LAYOUT_FILE)),
                uefi_disk: None,
            },
        };
        installed.verify_installed()?;
        atomic_json(&target.join("bundle.json"), &installed)?;
        Ok(installed)
    }
    /// Check an installed base against its identity. The file checksums of
    /// the last full check are reused while every file is unchanged (same
    /// size, times, inode and device); otherwise the files are hashed again.
    pub(crate) fn verify_installed(&self) -> Result<(), String> {
        let expected = self
            .base_identity
            .as_ref()
            .ok_or("VM has no installed base identity")?;
        let stamp_path = self
            .kernel
            .parent()
            .and_then(|dir| dir.parent())
            .map(|root| root.join(format!(".{expected}.verified")));
        let previous: Option<Verified> = stamp_path
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|verified: &Verified| &verified.identity == expected);
        let mut stamps = Vec::new();
        let identity = self.identity_with(&mut |file, path| {
            if let Some((checksum, stamp)) = stored_checksum(previous.as_ref(), path) {
                stamps.push(stamp);
                return Ok(checksum);
            }
            let checksum = sha256_uncached(file)?;
            let hex = checksum.iter().map(|b| format!("{b:02x}")).collect();
            stamps.push(FileStamp::of(path, hex)?);
            Ok(checksum)
        });
        let identity = identity.inspect_err(|_| {
            if let Some(path) = &stamp_path {
                let _ = fs::remove_file(path);
            }
        })?;
        if &identity != expected {
            if let Some(path) = &stamp_path {
                let _ = fs::remove_file(path);
            }
            return Err("installed base checksum mismatch".into());
        }
        if let Some(path) = &stamp_path {
            let verified = Verified {
                identity,
                files: stamps,
            };
            if previous
                .as_ref()
                .is_none_or(|old| old.files != verified.files)
            {
                let _ = atomic_json(path, &verified);
            }
        }
        Ok(())
    }
}
/// Guest RAM bounds. Sizes QEMU splits around the 4 GiB hole are mapped as two regions.
pub const MIN_RAM_MIB: u32 = 256;
pub const MAX_RAM_MIB: u32 = 8192;
pub(crate) fn validate_vm(vm: &VmConfig) -> Result<(), String> {
    vm.launch.validate()?;
    vm.transport.validate()?;
    if vm.id.is_empty()
        || vm.id.len() > 96
        || !vm
            .id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("invalid VM id".into());
    }
    if vm.name.trim().is_empty() || vm.name.len() > 128 {
        return Err("VM name must be 1..128 bytes".into());
    }
    if !(1..=64).contains(&vm.cpus) {
        return Err("CPU count must be 1..64".into());
    }
    if !(MIN_RAM_MIB..=MAX_RAM_MIB).contains(&vm.ram_mib) {
        return Err(format!("RAM must be {MIN_RAM_MIB}..{MAX_RAM_MIB} MiB"));
    }
    if !(1..=2048).contains(&vm.disk_gib) {
        return Err("disk capacity must be 1..2048 GiB".into());
    }
    Ok(())
}
pub(crate) fn validate_guest_transition(disk: &Bundle, boot: &Bundle) -> Result<(), String> {
    if disk.guest.as_ref().map(|guest| &guest.id) != boot.guest.as_ref().map(|guest| &guest.id) {
        return Err("changing guest OS requires creating a new VM; existing disk retained".into());
    }
    Ok(())
}
pub(crate) fn validate_boot_display(vm: &VmConfig, bundle: &Bundle) -> Result<(), String> {
    if vm.launch.resolution.dimensions().is_some() && !bundle.fixed_display {
        return Err("selected boot bundle does not support fixed display resolutions; install and select a fixed-display-capable Linux 6.12.94 bundle, or choose Auto".into());
    }
    Ok(())
}
pub(crate) fn validate_vm_bundle(
    options: &BackendOptions,
    vm: &VmConfig,
    bundle: &Bundle,
) -> Result<(), String> {
    validate_vm(vm)?;
    vm.launch.validate_for(options)?;
    if let Some(guest) = &bundle.guest {
        guest.validate()?;
        if vm.ram_mib < guest.min_ram_mib || vm.disk_gib < guest.min_disk_gib {
            return Err(format!(
                "guest requires at least {} MiB RAM and {} GiB disk",
                guest.min_ram_mib, guest.min_disk_gib
            ));
        }
    }
    bundle.verify_installed()?;
    let output = Command::new(&options.qemu_img)
        .args(["info", "-f", "qcow2", "--output=json"])
        .arg(&bundle.base_disk)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("cannot inspect installed base disk size".into());
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err("base disk metadata exceeds limit".into());
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let size = metadata
        .get("virtual-size")
        .and_then(|v| v.as_u64())
        .ok_or("base disk virtual size is missing")?;
    if size > u64::from(vm.disk_gib) * 1024 * 1024 * 1024 {
        return Err("VM disk capacity is smaller than installed base disk".into());
    }
    Ok(())
}
pub(crate) fn vm_dir(options: &BackendOptions, id: &str) -> Result<PathBuf, String> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("invalid VM id".into());
    }
    if let Some(directory) = crate::locations::disk_directory(options, id)? {
        return Ok(directory);
    }
    let direct = options.data_dir.join(id);
    if direct.exists()
        && let Ok(vm) = read_json::<VmConfig>(&direct.join("config.json"))
        && vm.id == id
    {
        return Ok(direct);
    }
    if let Ok(entries) = fs::read_dir(&options.data_dir) {
        for entry in entries.flatten() {
            let config = entry.path().join("config.json");
            if let Ok(vm) = read_json::<VmConfig>(&config)
                && vm.id == id
            {
                return Ok(entry.path());
            }
        }
    }
    let legacy = options.data_dir.join("vms").join(id);
    if legacy.exists()
        && let Ok(vm) = read_json::<VmConfig>(&legacy.join("config.json"))
        && vm.id == id
    {
        return Ok(legacy);
    }
    if direct.exists() || legacy.exists() {
        return Err(
            "VM directory collision or invalid configuration; existing files retained".into(),
        );
    }
    Ok(direct)
}
pub(crate) fn load_vms(options: &BackendOptions) -> Result<Vec<VmConfig>, String> {
    let dir = &options.data_dir;
    let mut vms = crate::locations::registered_vms(options)?;
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let path = entry.path().join("config.json");
        if !path.exists() {
            continue;
        }
        let vm: VmConfig = read_json(&path)?;
        validate_vm(&vm)?;
        if !vms.iter().any(|existing| existing.id == vm.id) {
            vms.push(vm);
        }
    }
    vms.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(vms)
}

mod migrate;
pub use migrate::migrate_data;
#[cfg(test)]
use migrate::migrate_data_with_proc;
pub(crate) use migrate::{ensure_data_dir, migrate_default_data};

mod capture;
pub use capture::RawCapture;
mod vm_ops;
pub(crate) use vm_ops::{
    create_overlay, delete_vm, duplicate_vm, reset_vm_disk, save_vm_config, validate_disk_chain,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn guest_fixture() -> (PathBuf, BackendOptions, Bundle, VmConfig) {
        let root = std::env::temp_dir().join(format!("ant-guest-storage-{}", unique_id()));
        let source = root.join("source");
        private_dir(&source).unwrap();
        fs::write(source.join("kernel"), b"kernel fixture").unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(source.join("base.qcow2"))
                .arg("1G")
                .output()
                .unwrap()
                .status
                .success()
        );
        let options = BackendOptions {
            data_dir: root.join("data"),
            ..BackendOptions::default()
        };
        let bundle = Bundle {
            arch: Default::default(),
            kernel: source.join("kernel"),
            base_disk: source.join("base.qcow2"),
            initrd: None,
            kernel_append: String::new(),
            kernel_version: "6.12.94".into(),
            schema_id: 1,
            base_identity: None,
            guest: Some(GuestProfile {
                id: "debian-xfce".into(),
                label: "Debian 13 (Xfce)".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                requires_credentials: true,
                graphical: true,
            }),
            fixed_display: false,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
            symbols: None,
            stealth_support: Vec::new(),
            uefi: Default::default(),
        }
        .install(&options)
        .unwrap();
        let vm = VmConfig {
            id: "guest".into(),
            base_identity: bundle.base_identity.clone(),
            ..VmConfig::default()
        };
        (root, options, bundle, vm)
    }
    #[test]
    fn queued_json_keeps_the_newest_value_and_never_overwrites_a_later_sync_write() {
        let _disk = slow_disk::SlowDisk::install();
        let root = std::env::temp_dir().join(format!("ant-json-queue-{}", unique_id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("run.json");
        for value in 0..50 {
            queue_json(&path, &value).unwrap();
        }
        flush_json().unwrap();
        assert_eq!(read_json::<u32>(&path).unwrap(), 49);
        for value in 100..150 {
            queue_json(&path, &value).unwrap();
            atomic_json(&path, &(value + 1000)).unwrap();
        }
        flush_json().unwrap();
        assert_eq!(read_json::<u32>(&path).unwrap(), 1149);
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            1,
            "temporary files left behind"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn observed_json_reports_durability_failure_and_same_path_supersession() {
        let _disk = slow_disk::SlowDisk::install();
        let root = std::env::temp_dir().join(format!("ant-json-receipt-{}", unique_id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("artifacts.json");
        let first = queue_json_observed(&path, &1).unwrap();
        flush_json().unwrap();
        assert!(matches!(first.status(), JsonWriteStatus::Complete));
        queue_json(&path, &2).unwrap();
        assert!(matches!(first.status(), JsonWriteStatus::Superseded));
        flush_json().unwrap();
        let final_value = queue_json_observed(&path, &3).unwrap();
        flush_json().unwrap();
        assert!(matches!(final_value.status(), JsonWriteStatus::Complete));
        assert_eq!(read_json::<u32>(&path).unwrap(), 3);
        atomic_json(&path, &4).unwrap();
        assert!(matches!(final_value.status(), JsonWriteStatus::Superseded));
        let blocked = root.join("blocked");
        fs::write(&blocked, b"file").unwrap();
        let failure = queue_json_observed(&blocked.join("artifacts.json"), &5).unwrap();
        assert!(flush_json().is_err());
        assert!(matches!(failure.status(), JsonWriteStatus::Failed(_)));
        assert!(
            matches!(failure.status(), JsonWriteStatus::Failed(_)),
            "observing a failure must not consume it"
        );
        drop(first);
        drop(final_value);
        drop(failure);
        settle_json(&blocked.join("artifacts.json"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_folder_with_only_window_state_is_not_legacy_data_in_either_order() {
        let root = std::env::temp_dir().join(format!("ant-legacy-order-{}", unique_id()));
        let proc_root = root.join("proc");
        fs::create_dir_all(&proc_root).unwrap();
        // The tool resolver first, then the GUI saved its window state.
        let old = root.join("old-a");
        let new = root.join("new-a");
        fs::create_dir_all(new.join("tools")).unwrap();
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("app.ron"), b"()").unwrap();
        migrate_data_with_proc(&old, &new, &proc_root).unwrap();
        assert!(!new.join("migration.json").exists());
        // The GUI first, then the tool resolver.
        let old = root.join("old-b");
        let new = root.join("new-b");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("app.ron"), b"()").unwrap();
        migrate_data_with_proc(&old, &new, &proc_root).unwrap();
        fs::create_dir_all(new.join("tools")).unwrap();
        migrate_data_with_proc(&old, &new, &proc_root).unwrap();
        // Real old data next to a destination the resolver filled first says what to do.
        let old = root.join("old-c");
        let new = root.join("new-c");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("vms.json"), b"[]").unwrap();
        fs::create_dir_all(new.join("tools")).unwrap();
        let message = migrate_data_with_proc(&old, &new, &proc_root).unwrap_err();
        assert!(
            message.contains("not empty") && message.contains("move or delete"),
            "{message}"
        );
        // Old data and a fresh destination still migrate.
        fs::remove_dir_all(&new).unwrap();
        migrate_data_with_proc(&old, &new, &proc_root).unwrap();
        assert!(new.join("migration.json").exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// The vector `tests/monitor/test-publish-base-sources.py` also checks, so
    /// `scripts/publish-base-sources.py` and this module cannot drift apart.
    #[test]
    fn the_identity_matches_the_shared_uefi_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../tests/monitor/fixtures/base-identity-uefi.json"
        ))
        .unwrap();
        let root = std::env::temp_dir().join(format!("ant-identity-vector-{}", unique_id()));
        private_dir(&root).unwrap();
        for (name, text) in vector["files"].as_object().unwrap() {
            fs::write(root.join(name), text.as_str().unwrap()).unwrap();
        }
        let write = |bundle: &serde_json::Value| {
            fs::write(root.join("bundle.json"), bundle.to_string()).unwrap()
        };
        let mut bundle = vector["bundle"].clone();
        write(&bundle);
        assert_eq!(
            Bundle::load(&root).unwrap().identity().unwrap(),
            vector["identity"].as_str().unwrap()
        );
        let object = bundle.as_object_mut().unwrap();
        object.remove("uefi_root");
        object.remove("uefi_layout");
        write(&bundle);
        assert_eq!(
            Bundle::load(&root).unwrap().identity().unwrap(),
            vector["identity_without_uefi"].as_str().unwrap()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn revision_metadata_is_validated_preserved_and_outside_the_identity() {
        let (root, options, mut bundle, _) = guest_fixture();
        let identity = bundle.identity().unwrap();
        bundle.antinomie_revision = Some(9);
        bundle.antinomie_source = Some("d".repeat(64));
        assert_eq!(bundle.identity().unwrap(), identity);
        let source = bundle.kernel.parent().unwrap().to_path_buf();
        let write = |bundle: &Bundle| {
            let mut manifest = serde_json::to_value(bundle).unwrap();
            manifest["kernel"] = "kernel".into();
            manifest["base_disk"] = "base.qcow2".into();
            fs::write(
                source.join("bundle.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        };
        write(&bundle);
        bundle.built_with = Some("0.1.0".into());
        bundle.min_app_version = Some("0.1.0".into());
        assert_eq!(bundle.identity().unwrap(), identity);
        write(&bundle);
        let installed = Bundle::load(&source).unwrap().install(&options).unwrap();
        assert_eq!(installed.antinomie_revision, Some(9));
        assert_eq!(installed.min_app_version.as_deref(), Some("0.1.0"));
        let reloaded = Bundle::load(installed.kernel.parent().unwrap()).unwrap();
        assert_eq!(reloaded.antinomie_source, bundle.antinomie_source);
        for (revision, source_id) in [
            (Some(9), None),
            (None, Some("d".repeat(64))),
            (Some(0), Some("d".repeat(64))),
            (Some(9), Some("D".repeat(64))),
        ] {
            bundle.antinomie_revision = revision;
            bundle.antinomie_source = source_id;
            write(&bundle);
            assert!(Bundle::load(&source).is_err());
        }
        bundle.antinomie_revision = Some(9);
        bundle.antinomie_source = Some("d".repeat(64));
        bundle.min_app_version = Some("0.1.0".into());
        bundle.name = Some("Lab base".into());
        write(&bundle);
        assert_eq!(
            Bundle::load(&source).unwrap().name.as_deref(),
            Some("Lab base")
        );
        bundle.name = Some("bad\nname".into());
        write(&bundle);
        assert!(Bundle::load(&source).is_err());
        bundle.name = None;
        for version in ["0.1", "v0.1.0", "01.0.0"] {
            bundle.min_app_version = Some(version.into());
            write(&bundle);
            assert!(Bundle::load(&source).is_err(), "{version}");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn legacy_identity_is_exact_and_guest_metadata_changes_identity() {
        let (root, _, mut bundle, _) = guest_fixture();
        let guest_identity = bundle.identity().unwrap();
        let serialized = serde_json::to_value(&bundle).unwrap();
        assert!(serialized.get("fixed_display").is_none());
        assert!(serialized.get("build_provenance").is_none());
        let decoded: Bundle = serde_json::from_value(serialized).unwrap();
        assert!(!decoded.fixed_display);
        assert!(decoded.build_provenance.is_none());
        bundle.fixed_display = true;
        assert_ne!(bundle.identity().unwrap(), guest_identity);
        bundle.fixed_display = false;
        bundle.guest = None;
        let mut expected = Sha256::new();
        expected.update(
            serde_json::to_vec(&(
                &bundle.kernel_append,
                &bundle.kernel_version,
                bundle.schema_id,
            ))
            .unwrap(),
        );
        for path in [
            Some(&bundle.kernel),
            Some(&bundle.base_disk),
            bundle.initrd.as_ref(),
        ] {
            if let Some(path) = path {
                expected.update([1]);
                expected.update(sha256_file(path).unwrap());
            } else {
                expected.update([0]);
            }
        }
        assert_eq!(
            bundle.identity().unwrap(),
            format!("{:x}", expected.finalize())
        );
        assert_ne!(guest_identity, bundle.identity().unwrap());
        let legacy: Bundle =
            serde_json::from_str(r#"{"kernel":"kernel","base_disk":"base","initrd":null}"#)
                .unwrap();
        assert!(legacy.guest.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn guest_resource_size_and_os_transition_guards() {
        let (root, options, bundle, mut vm) = guest_fixture();
        assert!(validate_vm_bundle(&options, &vm, &bundle).is_ok());
        vm.ram_mib = 1024;
        assert!(
            validate_vm_bundle(&options, &vm, &bundle)
                .unwrap_err()
                .contains("2048")
        );
        vm.ram_mib = 2048;
        vm.disk_gib = 4;
        assert!(validate_vm_bundle(&options, &vm, &bundle).is_err());
        let mut legacy = bundle.clone();
        legacy.guest = None;
        assert!(validate_guest_transition(&bundle, &legacy).is_err());
        assert!(validate_guest_transition(&bundle, &bundle).is_ok());
        let mut larger = bundle.clone();
        larger.guest.as_mut().unwrap().min_disk_gib = 1;
        larger.base_identity = None;
        // Re-import after changing metadata and grow the source disk above VM capacity.
        fs::set_permissions(&larger.base_disk, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            Command::new("qemu-img")
                .arg("resize")
                .arg(&larger.base_disk)
                .arg("2G")
                .output()
                .unwrap()
                .status
                .success()
        );
        let larger = larger.install(&options).unwrap();
        vm.disk_gib = 1;
        assert!(
            validate_vm_bundle(&options, &vm, &larger)
                .unwrap_err()
                .contains("smaller")
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reset_failure_preserves_disk_and_duplicate_delete_preserve_account_contract() {
        let (root, options, bundle, mut vm) = guest_fixture();
        let location = crate::locations::prepare(&options, &mut vm).unwrap();
        private_dir(&location.disk_directory).unwrap();
        create_overlay(&options, &location.disk_directory, vm.disk_gib, &bundle).unwrap();
        atomic_json(&location.disk_directory.join("config.json"), &vm).unwrap();
        let account = crate::guest_account::fixture("analyst");
        account.save(&location.disk_directory).unwrap();
        crate::locations::publish(&options, &location).unwrap();
        let old = fs::read(location.disk_directory.join("disk.qcow2")).unwrap();
        let record = fs::read(location.disk_directory.join("guest-account.json")).unwrap();
        fs::write(location.disk_directory.join("user-file"), b"retain").unwrap();
        let account_path = location.disk_directory.join("guest-account.json");
        let retained_account_path = location.disk_directory.join("retained-account.json");
        fs::rename(&account_path, &retained_account_path).unwrap();
        assert!(
            reset_vm_disk(&options, &location.disk_directory, &vm, &bundle)
                .unwrap_err()
                .contains("unavailable")
        );
        assert_eq!(
            old,
            fs::read(location.disk_directory.join("disk.qcow2")).unwrap()
        );
        fs::rename(&retained_account_path, &account_path).unwrap();
        crate::guest_account::fail_next_provision();
        assert!(reset_vm_disk(&options, &location.disk_directory, &vm, &bundle).is_err());
        assert_eq!(
            old,
            fs::read(location.disk_directory.join("disk.qcow2")).unwrap()
        );
        assert_eq!(
            record,
            fs::read(location.disk_directory.join("guest-account.json")).unwrap()
        );
        assert!(!fs::read_dir(&location.disk_directory).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("reset-")
        }));
        let duplicate = duplicate_vm(&options, &vm, "Copy".into()).unwrap();
        let duplicate_dir = vm_dir(&options, &duplicate.id).unwrap();
        assert_eq!(
            record,
            fs::read(duplicate_dir.join("guest-account.json")).unwrap()
        );
        assert_eq!(
            fs::metadata(duplicate_dir.join("guest-account.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        delete_vm(&options, &vm.id).unwrap();
        assert!(!location.disk_directory.join("guest-account.json").exists());
        assert_eq!(
            fs::read(location.disk_directory.join("user-file")).unwrap(),
            b"retain"
        );
        assert!(duplicate_dir.join("guest-account.json").is_file());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn migration_preserves_disk_bytes_relocates_fields_and_parent_mode() {
        let parent = std::env::temp_dir().join(format!("ant-migration-{}", unique_id()));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        let source = parent.join("legacy");
        let destination = parent.join("new");
        private_dir(&source).unwrap();
        let base = source.join("bases/original");
        private_dir(&base).unwrap();
        fs::write(base.join("kernel"), b"kernel").unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(base.join("base.qcow2"))
                .arg("1M")
                .output()
                .unwrap()
                .status
                .success()
        );
        let mut bundle = Bundle {
            arch: Default::default(),
            kernel: base.join("kernel"),
            base_disk: base.join("base.qcow2"),
            initrd: None,
            kernel_append: String::new(),
            kernel_version: "6.12.94".into(),
            schema_id: 1,
            base_identity: None,
            guest: None,
            fixed_display: false,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
            symbols: None,
            stealth_support: Vec::new(),
            uefi: Default::default(),
        };
        bundle.base_identity = Some(bundle.identity().unwrap());
        let vm = source.join("vms/old-id");
        private_dir(&vm).unwrap();
        atomic_json(
            &vm.join("config.json"),
            &VmConfig {
                id: "old-id".into(),
                name: "Old VM".into(),
                ..VmConfig::default()
            },
        )
        .unwrap();
        atomic_json(&vm.join("bundle.json"), &bundle).unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                .arg(&bundle.base_disk)
                .arg(vm.join("disk.qcow2"))
                .output()
                .unwrap()
                .status
                .success()
        );
        let capture = source.join("captures/old-capture");
        private_dir(&capture.join("objects")).unwrap();
        fs::write(capture.join("objects/field.raw"), b"saved").unwrap();
        atomic_json(
            &capture.join("events.json"),
            &Vec::<crate::api::EventSummary>::new(),
        )
        .unwrap();
        atomic_json(
            &capture.join("manifest.json"),
            &serde_json::json!({"bundle":bundle,"raw_path":capture.join("objects/field.raw")}),
        )
        .unwrap();
        // Use a controlled process table: an unrelated running app must not
        // make this fixture depend on the developer's desktop or other tests.
        let proc_root = parent.join("proc");
        let monitor = proc_root.join("1");
        fs::create_dir_all(&monitor).unwrap();
        fs::write(monitor.join("cmdline"), b"/bin/antinomie-monitor\0").unwrap();
        assert!(
            migrate_data_with_proc(&source, &destination, &proc_root)
                .unwrap_err()
                .contains("deferred")
        );
        fs::remove_dir_all(monitor).unwrap();
        let unrelated = proc_root.join("2");
        fs::create_dir_all(&unrelated).unwrap();
        fs::write(unrelated.join("cmdline"), b"qemu-system-x86_64\0other-vm\0").unwrap();
        let vm_process = proc_root.join("3");
        fs::create_dir_all(&vm_process).unwrap();
        let mut command = b"qemu-system-x86_64\0-drive\0".to_vec();
        command.extend_from_slice(source.join("disk.qcow2").as_os_str().as_bytes());
        command.push(0);
        fs::write(vm_process.join("cmdline"), command).unwrap();
        assert!(
            migrate_data_with_proc(&source, &destination, &proc_root)
                .unwrap_err()
                .contains("deferred")
        );
        fs::remove_dir_all(vm_process).unwrap();
        migrate_data_with_proc(&source, &destination, &proc_root).unwrap();
        assert_eq!(
            fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o750
        );
        let options = BackendOptions {
            data_dir: destination.clone(),
            ..BackendOptions::default()
        };
        let migrated_vm = vm_dir(&options, "old-id").unwrap();
        let migrated: Bundle =
            serde_json::from_reader(File::open(migrated_vm.join("bundle.json")).unwrap()).unwrap();
        migrated.verify_installed().unwrap();
        assert!(migrated.base_disk.starts_with(&destination));
        assert!(
            Command::new("qemu-img")
                .arg("compare")
                .arg(vm.join("disk.qcow2"))
                .arg(migrated_vm.join("disk.qcow2"))
                .output()
                .unwrap()
                .status
                .success()
        );
        let hidden = parent.join("legacy-hidden");
        fs::rename(&source, &hidden).unwrap();
        migrated.verify_installed().unwrap();
        let field = crate::api::FieldSummary {
            arg: None,
            object_id: 1,
            key: String::new(),
            layout: String::new(),
            logical_len: Some(5),
            captured_len: 5,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: vec![],
            raw_path: Some(source.join("captures/old-capture/objects/field.raw")),
            ranges: vec![(0, 5)],
            recapture: None,
            encoding: None,
        };
        assert_eq!(
            crate::recording::read_captured_range(
                &destination.join("captures/old-capture"),
                &field,
                0,
                5
            )
            .unwrap(),
            b"saved"
        );
        assert!(hidden.exists());
        assert!(
            migrate_data_with_proc(&hidden, &hidden.join("nested"), &proc_root)
                .unwrap_err()
                .contains("overlap")
        );
        let conflict = parent.join("conflict");
        private_dir(&conflict).unwrap();
        fs::write(conflict.join("keep"), b"untouched").unwrap();
        assert!(
            migrate_data_with_proc(&hidden, &conflict, &proc_root)
                .unwrap_err()
                .contains("not empty")
        );
        assert_eq!(fs::read(conflict.join("keep")).unwrap(), b"untouched");
        let bad = parent.join("bad-source");
        private_dir(&bad).unwrap();
        fs::write(bad.join("manifest.json"), b"{broken").unwrap();
        assert!(migrate_data_with_proc(&bad, &parent.join("bad-target"), &proc_root).is_err());
        assert!(bad.join("manifest.json").exists());
        assert!(!parent.join("bad-target").exists());
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn validates_paths_and_memory_boundaries() {
        let mut vm = VmConfig {
            id: "ok".into(),
            ..VmConfig::default()
        };
        assert!(validate_vm(&vm).is_ok());
        vm.id = "../../escape".into();
        assert!(validate_vm(&vm).is_err());
        vm.id = "ok".into();
        vm.ram_mib = 4096;
        assert!(validate_vm(&vm).is_ok());
        vm.ram_mib = MAX_RAM_MIB + 1;
        assert!(validate_vm(&vm).is_err());
        vm.ram_mib = MIN_RAM_MIB - 1;
        assert!(validate_vm(&vm).is_err());
    }
    #[test]
    fn raw_packets_reach_the_file_on_flush_and_drop() {
        let path = std::env::temp_dir().join(format!("ant-capture-{}", unique_id()));
        let mut c = RawCapture::new(path.clone(), 1 << 20).unwrap();
        assert!(c.append(b"one"));
        assert!(c.append(b"two"));
        assert_eq!(fs::metadata(path.join("telemetry.raw")).unwrap().len(), 0);
        assert!(c.flush());
        crate::writer::barrier();
        assert_eq!(fs::metadata(path.join("telemetry.raw")).unwrap().len(), 14);
        assert!(c.append(b"three"));
        drop(c);
        crate::writer::barrier();
        assert_eq!(
            fs::read(path.join("telemetry.raw")).unwrap()[14..],
            [5, 0, 0, 0, b't', b'h', b'r', b'e', b'e']
        );
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn quota_preserves_prior_packets() {
        let path = std::env::temp_dir().join(format!("ant-capture-{}", unique_id()));
        let mut c = RawCapture::new(path.clone(), 8).unwrap();
        assert!(c.append(b"test"));
        assert!(!c.append(b"lost"));
        assert!(c.error.is_some());
        assert!(c.flush());
        crate::writer::barrier();
        assert_eq!(
            fs::read(path.join("telemetry.raw")).unwrap(),
            [4, 0, 0, 0, b't', b'e', b's', b't']
        );
        drop(c);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn quota_accounts_for_assembled_objects() {
        let path = std::env::temp_dir().join(format!("ant-shared-quota-{}", unique_id()));
        let mut c = RawCapture::new(path.clone(), 16).unwrap();
        assert!(c.append_with_reserved(b"data", 8));
        assert!(!c.append_with_reserved(b"x", 8));
        assert_eq!(c.bytes, 8);
        drop(c);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn installed_base_survives_removal_of_source_bundle() {
        let directory = std::env::temp_dir().join(format!("ant-base-{}", unique_id()));
        let source = directory.join("source");
        private_dir(&source).unwrap();
        fs::write(source.join("kernel"), b"kernel").unwrap();
        fs::write(source.join("base.qcow2"), b"disk").unwrap();
        let provenance = BundleBuildProvenance {
            parent_identity: Some("a".repeat(64)),
            kernel_sha256: format!("{:x}", Sha256::digest(b"kernel")),
            base_disk_sha256: format!("{:x}", Sha256::digest(b"disk")),
            initrd_sha256: None,
            kernel_config_sha256: "b".repeat(64),
        };
        let bundle = Bundle {
            arch: Default::default(),
            kernel: source.join("kernel"),
            base_disk: source.join("base.qcow2"),
            initrd: None,
            kernel_append: "root=/dev/vda".into(),
            kernel_version: "test".into(),
            schema_id: 1,
            base_identity: None,
            guest: None,
            fixed_display: false,
            build_provenance: Some(provenance),
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
            symbols: None,
            stealth_support: Vec::new(),
            uefi: Default::default(),
        };
        let options = BackendOptions {
            data_dir: directory.join("data"),
            ..BackendOptions::default()
        };
        let installed = bundle.install(&options).unwrap();
        fs::remove_dir_all(source).unwrap();
        installed.verify_installed().unwrap();
        // The first check leaves a stamp; later checks reuse its checksums
        // while the files are unchanged, and a changed file is hashed again.
        let identity = installed.base_identity.clone().unwrap();
        let stamp = options
            .data_dir
            .join("bases")
            .join(format!(".{identity}.verified"));
        let verified: Verified = serde_json::from_slice(&fs::read(&stamp).unwrap()).unwrap();
        assert_eq!(verified.identity, identity);
        assert_eq!(verified.files.len(), 2);
        installed.verify_installed().unwrap();
        let disk = installed.base_disk.clone();
        fs::set_permissions(&disk, fs::Permissions::from_mode(0o644)).unwrap();
        let mut bytes = fs::read(&disk).unwrap();
        bytes[0] ^= 1;
        fs::write(&disk, &bytes).unwrap();
        assert!(installed.verify_installed().is_err());
        assert!(!stamp.exists());
        bytes[0] ^= 1;
        fs::write(&disk, &bytes).unwrap();
        installed.verify_installed().unwrap();
        let loaded = Bundle::load(installed.kernel.parent().unwrap()).unwrap();
        assert_eq!(
            loaded.build_provenance.unwrap().kernel_config_sha256,
            "b".repeat(64)
        );
        let mut corrupted = installed.clone();
        corrupted.build_provenance.as_mut().unwrap().kernel_sha256 = "c".repeat(64);
        assert!(
            corrupted
                .identity()
                .unwrap_err()
                .contains("differs from build provenance")
        );
        corrupted.build_provenance.as_mut().unwrap().kernel_sha256 = "invalid".into();
        assert!(
            corrupted
                .identity()
                .unwrap_err()
                .contains("lowercase SHA256")
        );
        assert_eq!(fs::read(installed.base_disk).unwrap(), b"disk");
        fs::remove_dir_all(directory).unwrap();
    }
}
