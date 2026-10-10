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

/// Atomic JSON writes that must not stall the transport worker on a slow
/// `fsync`. One background thread writes them; a newer value for a path
/// replaces one still pending, and a synchronous write to the same path first
/// waits for the background copy so it can never be overwritten by older data.
#[derive(Default)]
struct JsonQueue {
    pending: std::collections::BTreeMap<PathBuf, Vec<u8>>,
    writing: Option<PathBuf>,
    errors: std::collections::BTreeMap<PathBuf, String>,
}
static JSON_QUEUE: std::sync::OnceLock<(std::sync::Mutex<JsonQueue>, std::sync::Condvar)> =
    std::sync::OnceLock::new();

fn json_queue() -> &'static (std::sync::Mutex<JsonQueue>, std::sync::Condvar) {
    JSON_QUEUE.get_or_init(|| {
        let spawned = std::thread::Builder::new()
            .name("antinomie-json".into())
            .spawn(json_writer);
        if let Err(error) = spawned {
            panic!("JSON writer thread: {error}");
        }
        Default::default()
    })
}

fn json_writer() {
    let (lock, ready) = json_queue();
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let Some((path, bytes)) = queue.pending.pop_first() else {
            queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
            continue;
        };
        queue.writing = Some(path.clone());
        drop(queue);
        let result = write_atomic(&path, &bytes);
        queue = lock.lock().unwrap_or_else(|e| e.into_inner());
        queue.writing = None;
        match result {
            Ok(()) => queue.errors.remove(&path),
            Err(error) => queue.errors.insert(path, error.message),
        };
        ready.notify_all();
    }
}

/// Queues an atomic JSON write and returns at once. Reports the failure of an
/// earlier background write to the same path, if any.
pub(crate) fn queue_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    queue_bytes(path, bytes)
}

/// Queues an atomic write of `bytes` to `path`, like `queue_json`.
pub(crate) fn queue_bytes(path: &Path, bytes: Vec<u8>) -> Result<(), String> {
    let (lock, ready) = json_queue();
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    let earlier = queue.errors.remove(path);
    queue.pending.insert(path.to_path_buf(), bytes);
    ready.notify_all();
    earlier.map_or(Ok(()), Err)
}

/// Drops a pending background write to `path` and waits for one in progress.
fn settle_json(path: &Path) {
    let Some((lock, ready)) = JSON_QUEUE.get() else {
        return;
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    queue.pending.remove(path);
    while queue.writing.as_deref() == Some(path) {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
    queue.errors.remove(path);
}

/// Before a test removes `directory`: drops background writes queued below it
/// and waits for one in progress there, so none recreates a file meanwhile.
#[cfg(test)]
pub(crate) fn settle_json_under(directory: &Path) {
    let Some((lock, ready)) = JSON_QUEUE.get() else {
        return;
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    queue.pending.retain(|path, _| !path.starts_with(directory));
    while queue
        .writing
        .as_deref()
        .is_some_and(|path| path.starts_with(directory))
    {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
    queue.errors.retain(|path, _| !path.starts_with(directory));
}

/// Waits until every queued JSON write has reached the disk.
pub(crate) fn flush_json() {
    let Some((lock, ready)) = JSON_QUEUE.get() else {
        return;
    };
    let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !queue.pending.is_empty() || queue.writing.is_some() {
        queue = ready.wait(queue).unwrap_or_else(|e| e.into_inner());
    }
}

pub(crate) fn atomic_json_checked(
    path: &Path,
    value: &impl Serialize,
) -> Result<(), PublicationError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| PublicationError {
        published: false,
        message: e.to_string(),
    })?;
    bytes.push(b'\n');
    settle_json(path);
    write_atomic(path, &bytes)
}

/// Writes `bytes` to `path` atomically now, after any queued write to it.
pub(crate) fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
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
}
fn is_false(value: &bool) -> bool {
    !value
}
impl Bundle {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(dir).map_err(|e| format!("bundle {}: {e}", dir.display()))?;
        let mut b: Self = read_json(&root.join("bundle.json"))?;
        if let Some(guest) = &b.guest {
            guest.validate()?;
        }
        b.validate_revision()?;
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
        Ok(b)
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

/// Copy, validate, and atomically publish legacy data. The source is retained.
pub(crate) fn migrate_default_data(options: &BackendOptions) -> Result<(), String> {
    if options.data_dir != BackendOptions::default().data_dir {
        return Ok(());
    }
    let source = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("antinomie");
    migrate_data(&source, &options.data_dir)
}
pub fn migrate_data(source: &Path, destination: &Path) -> Result<(), String> {
    migrate_data_with_proc(source, destination, Path::new("/proc"))
}

fn migrate_data_with_proc(
    source: &Path,
    destination: &Path,
    proc_root: &Path,
) -> Result<(), String> {
    if !destination.is_absolute() {
        return Err("migration destination must be absolute".into());
    }
    if !source.exists() || destination.join("migration.json").exists() {
        return Ok(());
    }
    let source = fs::canonicalize(source).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(proc_root)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        if let Ok(command) = fs::read(entry.path().join("cmdline")) {
            let arguments: Vec<_> = command
                .split(|byte| *byte == 0)
                .filter(|arg| !arg.is_empty())
                .collect();
            let executable = arguments
                .first()
                .map(|arg| {
                    Path::new(std::ffi::OsStr::from_bytes(arg))
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default();
            let references_source = arguments.iter().any(|arg| {
                String::from_utf8_lossy(arg).contains(source.to_string_lossy().as_ref())
            });
            if executable == "antinomie-monitor"
                || (executable.starts_with("qemu-system-") && references_source)
            {
                return Err("legacy data migration deferred: close the existing Antinomie app and its QEMU VM before starting the new app".into());
            }
        }
    }
    if destination.exists()
        && fs::read_dir(destination)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("legacy migration destination is not empty; source retained, migration needs an explicit destination".into());
    }
    let parent = destination
        .parent()
        .ok_or("migration destination has no parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let parent_canonical = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    let destination_canonical = parent_canonical.join(
        destination
            .file_name()
            .ok_or("migration destination has no name")?,
    );
    if parent_canonical.starts_with(&source) || source.starts_with(&destination_canonical) {
        return Err("migration source and destination overlap; source retained".into());
    }
    let staging = parent.join(format!(".antinomie-migrate-{}", unique_id()));
    private_dir(&staging).map_err(|e| e.to_string())?;
    fn copy_verified(source: &Path, destination: &Path) -> Result<(), String> {
        for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let target = destination.join(entry.file_name());
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                private_dir(&target).map_err(|e| e.to_string())?;
                copy_verified(&entry.path(), &target)?;
            } else if kind.is_file() {
                fs::copy(entry.path(), &target).map_err(|e| e.to_string())?;
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(
                        fs::metadata(entry.path())
                            .map_err(|e| e.to_string())?
                            .permissions()
                            .mode()
                            & 0o777,
                    ),
                )
                .map_err(|e| e.to_string())?;
                if sha256_file(&entry.path())? != sha256_file(&target)? {
                    return Err("migration copy validation failed".into());
                }
                File::open(&target)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| e.to_string())?;
            } else {
                return Err(format!(
                    "migration source contains unsupported live/special file {}; source retained",
                    entry.path().display()
                ));
            }
        }
        Ok(())
    }
    let result = (|| {
        copy_verified(&source, &staging)?;
        let vms = staging.join("vms");
        if vms.exists() {
            for entry in fs::read_dir(&vms).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let config = entry.path().join("config.json");
                if config.is_file() {
                    let vm: VmConfig =
                        serde_json::from_reader(File::open(config).map_err(|e| e.to_string())?)
                            .map_err(|e| e.to_string())?;
                    validate_vm(&vm)?;
                    let slug = vm_id(&vm.name)
                        .split('_')
                        .next()
                        .unwrap_or("vm")
                        .to_string();
                    fs::rename(entry.path(), staging.join(format!("{slug}_{}", vm.id)))
                        .map_err(|e| e.to_string())?;
                }
            }
            fs::remove_dir(&vms).map_err(|e| e.to_string())?;
        }
        fn rewrite_json_paths(value: &mut serde_json::Value, source: &Path, destination: &Path) {
            match value {
                serde_json::Value::Object(object) => {
                    for (key, value) in object {
                        if [
                            "kernel",
                            "base_disk",
                            "initrd",
                            "raw_path",
                            "directory",
                            "capture_dir",
                            "serial_log",
                        ]
                        .contains(&key.as_str())
                        {
                            if let Some(text) = value.as_str()
                                && let Ok(relative) = Path::new(text).strip_prefix(source)
                            {
                                *value = serde_json::Value::String(
                                    destination.join(relative).to_string_lossy().into_owned(),
                                );
                            }
                        } else {
                            rewrite_json_paths(value, source, destination);
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        rewrite_json_paths(value, source, destination);
                    }
                }
                _ => {}
            }
        }
        fn rewrite_tree(root: &Path, source: &Path, destination: &Path) -> Result<(), String> {
            for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                    rewrite_tree(&path, source, destination)?;
                } else if path.extension().is_some_and(|ext| ext == "json")
                    && ["bundle.json", "manifest.json", "events.json", "run.json"]
                        .contains(&entry.file_name().to_string_lossy().as_ref())
                {
                    if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 64 * 1024 * 1024 {
                        return Err(
                            "migration JSON exceeds bounded 64 MiB reader; source retained".into(),
                        );
                    }
                    let mut value: serde_json::Value =
                        serde_json::from_reader(File::open(&path).map_err(|e| e.to_string())?)
                            .map_err(|e| format!("migration JSON {}: {e}", path.display()))?;
                    rewrite_json_paths(&mut value, source, destination);
                    atomic_json(&path, &value)?;
                }
            }
            Ok(())
        }
        rewrite_tree(&staging, &source, destination)?;
        for entry in fs::read_dir(&staging).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let disk = entry.path().join("disk.qcow2");
            let bundle = entry.path().join("bundle.json");
            if disk.is_file() && bundle.is_file() {
                let bundle: Bundle =
                    serde_json::from_reader(File::open(bundle).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                let relative = bundle
                    .base_disk
                    .strip_prefix(destination)
                    .map_err(|_| "migration overlay backing is outside verified data root")?;
                let verified_base = staging.join(relative);
                if !verified_base.is_file() {
                    return Err("migration verified backing base is missing".into());
                }
                let result = Command::new("qemu-img")
                    .args(["rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b"])
                    .arg(&bundle.base_disk)
                    .arg(&disk)
                    .output()
                    .map_err(|e| e.to_string())?;
                if !result.status.success() {
                    return Err(format!(
                        "migration overlay rebase: {}",
                        String::from_utf8_lossy(&result.stderr)
                    ));
                }
                File::open(&disk)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| e.to_string())?;
            }
        }
        atomic_json(
            &staging.join("migration.json"),
            &serde_json::json!({"source":source,"validated":true,"source_retained":true}),
        )?;
        if destination.exists() {
            fs::remove_dir(destination).map_err(|e| e.to_string())?;
        }
        fs::rename(&staging, destination).map_err(|e| e.to_string())?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(staging);
    }
    result
}
pub(crate) fn create_overlay(
    options: &BackendOptions,
    dir: &Path,
    disk_gib: u32,
    bundle: &Bundle,
) -> Result<(), String> {
    bundle.verify_installed()?;
    validate_disk_chain(options, &bundle.base_disk, None)?;
    let disk = dir.join("disk.qcow2");
    if disk.exists() {
        return Err("VM disk already exists".into());
    }
    let result = Command::new(&options.qemu_img)
        .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(&bundle.base_disk)
        .arg(&disk)
        .arg(format!("{disk_gib}G"))
        .output()
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "qemu-img: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    atomic_json(&dir.join("bundle.json"), bundle)
}

pub(crate) fn reset_vm_disk(
    options: &BackendOptions,
    directory: &Path,
    vm: &VmConfig,
    bundle: &Bundle,
) -> Result<(), String> {
    validate_vm_bundle(options, vm, bundle)?;
    validate_disk_chain(
        options,
        &directory.join("disk.qcow2"),
        Some(&bundle.base_disk),
    )?;
    let account = if bundle
        .guest
        .as_ref()
        .is_some_and(|guest| guest.requires_credentials)
    {
        Some(crate::guest_account::GuestAccount::load(directory)?)
    } else {
        None
    };
    let staging = directory.join(format!("reset-{}", unique_id()));
    private_dir(&staging).map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        create_overlay(options, &staging, vm.disk_gib, bundle)?;
        let disk = staging.join("disk.qcow2");
        if let Some(account) = account {
            account.provision(&disk)?;
        }
        File::open(&disk)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&disk, directory.join("disk.qcow2")).map_err(|e| e.to_string())?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|e| format!("reset disk is published; directory durability is uncertain: {e}"))
    })();
    let cleanup = fs::remove_dir_all(&staging).map_err(|e| e.to_string());
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}; reset staging cleanup failed: {cleanup}"))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

pub(crate) fn duplicate_vm(
    options: &BackendOptions,
    source: &VmConfig,
    name: String,
) -> Result<VmConfig, String> {
    validate_vm(source)?;
    source.launch.validate_for(options)?;
    if source.launch.resolution.dimensions().is_some() {
        let boot = crate::locations::boot_bundle(options, source.base_identity.as_deref())?;
        validate_boot_display(source, &boot)?;
    }
    let source_dir = vm_dir(options, &source.id)?;
    let source_disk = source_dir.join("disk.qcow2");
    if !fs::symlink_metadata(&source_disk)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_file()
    {
        return Err("source disk must be a regular file".into());
    }
    let bundle: Bundle = read_json(&source_dir.join("bundle.json"))?;
    bundle.verify_installed()?;
    let account = if bundle
        .guest
        .as_ref()
        .is_some_and(|guest| guest.requires_credentials)
    {
        Some(crate::guest_account::GuestAccount::load(&source_dir)?)
    } else {
        None
    };
    validate_disk_chain(options, &source_disk, Some(&bundle.base_disk))?;
    let mut vm = source.clone();
    vm.id = vm_id(&name);
    vm.name = name;
    validate_vm(&vm)?;
    let location = crate::locations::prepare(options, &mut vm)?;
    fs::create_dir(&location.disk_directory).map_err(|e| e.to_string())?;
    fs::set_permissions(&location.disk_directory, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), PublicationError> {
        let disk = location.disk_directory.join("disk.qcow2");
        let result = Command::new(&options.qemu_img)
            .args(["convert", "-f", "qcow2", "-O", "qcow2"])
            .arg(&source_disk)
            .arg(&disk)
            .output()
            .map_err(|e| e.to_string())?;
        if !result.status.success() {
            return Err(format!(
                "disk duplication: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        File::open(&disk)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::set_permissions(&disk, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        atomic_json(&location.disk_directory.join("bundle.json"), &bundle)?;
        if let Some(account) = &account {
            account.save(&location.disk_directory)?;
        }
        atomic_json(&location.disk_directory.join("config.json"), &vm)?;
        sync_directory_parent(&location.disk_directory)?;
        crate::locations::publish(options, &location)?;
        Ok(())
    })();
    if let Err(error) = result {
        if error.published {
            return Err(error.into());
        }
        let cleanup = fs::remove_dir_all(&location.disk_directory).map_err(|e| e.to_string());
        return Err(format!("{error}; duplicate rollback {:?}", cleanup.err()));
    }
    Ok(vm)
}

pub(crate) fn validate_disk_chain(
    options: &BackendOptions,
    disk: &Path,
    expected_base: Option<&Path>,
) -> Result<(), String> {
    let output = Command::new(&options.qemu_img)
        .args(["info", "-f", "qcow2", "--backing-chain", "--output=json"])
        .arg(disk)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "disk backing validation: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err("disk backing metadata exceeds limit".into());
    }
    let chain: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if chain.is_empty() || chain.len() > 2 {
        return Err("unsupported disk backing chain".into());
    }
    if chain
        .iter()
        .any(|image| image.get("format").and_then(|value| value.as_str()) != Some("qcow2"))
    {
        return Err("disk chain must use qcow2 images".into());
    }
    if chain.len() == 2 {
        let expected = expected_base.ok_or("installed base must be self contained")?;
        let actual = chain[1]
            .get("filename")
            .and_then(|value| value.as_str())
            .ok_or("missing disk backing path")?;
        if fs::canonicalize(actual).map_err(|e| e.to_string())?
            != fs::canonicalize(expected).map_err(|e| e.to_string())?
        {
            return Err("disk backing differs from pinned installed base".into());
        }
    }
    Ok(())
}

pub(crate) fn delete_vm(options: &BackendOptions, id: &str) -> Result<(), String> {
    let dir = vm_dir(options, id)?;
    let config: VmConfig = read_json(&dir.join("config.json"))?;
    if config.id != id {
        return Err("VM configuration identity mismatch".into());
    }
    let bundle: Bundle = read_json(&dir.join("bundle.json"))?;
    bundle.verify_installed()?;
    validate_disk_chain(options, &dir.join("disk.qcow2"), Some(&bundle.base_disk))?;
    crate::locations::publish(options, &crate::locations::locations(options, id)?)?;
    let mut paths = Vec::new();
    for name in ["disk.qcow2", "config.json", "bundle.json"] {
        let path = dir.join(name);
        if !fs::symlink_metadata(&path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_file()
        {
            return Err("VM deletion requires owned regular disk/configuration files".into());
        }
        paths.push(path);
    }
    let account = dir.join("guest-account.json");
    if account.exists() || fs::symlink_metadata(&account).is_ok() {
        crate::guest_account::GuestAccount::load(&dir)?;
        paths.push(account);
    } else if bundle
        .guest
        .as_ref()
        .is_some_and(|guest| guest.requires_credentials)
    {
        return Err(
            "guest account provisioning record is unavailable; existing files retained".into(),
        );
    }
    let staging = dir.join(format!("delete-{}", unique_id()));
    fs::create_dir(&staging).map_err(|e| e.to_string())?;
    let mut staged = Vec::new();
    let result = (|| -> Result<(), PublicationError> {
        for path in &paths {
            let target = staging.join(path.file_name().ok_or("missing file name")?);
            fs::rename(path, &target).map_err(|e| e.to_string())?;
            staged.push((path.clone(), target));
        }
        crate::locations::mark_deleted(options, id)
    })();
    if let Err(error) = result {
        if error.published {
            return Err(format!(
                "{error}; deleted VM files retained in {}",
                staging.display()
            ));
        }
        let mut rollback_errors = Vec::new();
        for (path, target) in staged.into_iter().rev() {
            if let Err(rollback) = fs::rename(target, path) {
                rollback_errors.push(rollback.to_string());
            }
        }
        let _ = fs::remove_dir(&staging);
        return Err(format!(
            "{error}; deletion rollback errors {rollback_errors:?}"
        ));
    }
    for (_, target) in staged {
        fs::remove_file(target).map_err(|e| e.to_string())?;
    }
    fs::remove_dir(staging).map_err(|e| e.to_string())?;
    File::open(&dir)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}

pub(crate) fn save_vm_config(
    options: &BackendOptions,
    directory: &Path,
    previous: &VmConfig,
    next: &VmConfig,
    location: &crate::api::VmLocations,
) -> Result<(), PublicationError> {
    validate_vm(next)?;
    next.launch.validate_for(options)?;
    let path = directory.join("config.json");
    let config_warning = match atomic_json_checked(&path, next) {
        Ok(()) => None,
        Err(error) if error.published => Some(error),
        Err(error) => return Err(error),
    };
    match crate::locations::publish(options, location) {
        Ok(()) => config_warning.map_or(Ok(()), Err),
        Err(error) if error.published => Err(error),
        Err(error) => {
            atomic_json_checked(&path, previous).map_err(|rollback| PublicationError {
                // A successful rollback rename restored the previous config,
                // even when syncing that restoration subsequently failed.
                published: !rollback.published,
                message: format!("{error}; settings rollback failed: {rollback}"),
            })?;
            Err(error)
        }
    }
}

#[derive(Serialize)]
struct CaptureManifest<'a> {
    format: &'static str,
    vm: &'a VmConfig,
    bundle: &'a Bundle,
    disk_bundle: &'a Bundle,
    packets: u64,
    bytes: u64,
    persistence_error: &'a Option<String>,
    final_state: &'a str,
    health: &'a Option<Health>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_kernel: &'a Option<crate::api::GuestKernel>,
}
/// Packets are buffered in memory and handed to the recording writer thread
/// in large blocks: the transport thread calls [`RawCapture::flush`] after
/// every drain pass, and `sync`, `manifest` and drop flush too. `sync` and
/// `manifest` also wait until the writer has written everything.
pub struct RawCapture {
    pub directory: PathBuf,
    file: std::sync::Arc<File>,
    buffer: Vec<u8>,
    /// File length and packet count handed to the writer thread.
    written: (u64, u64),
    /// The writer thread's first error for this file, reported once.
    write_error: crate::writer::ErrorSlot,
    write_error_seen: bool,
    quota: u64,
    pub packets: u64,
    pub bytes: u64,
    pub error: Option<String>,
    pub final_health: Option<Health>,
    /// The guest kernel's INFO answer, recorded in the manifest.
    pub guest_kernel: Option<crate::api::GuestKernel>,
}
/// Buffered raw packet bytes that trigger a write before the next flush.
const RAW_BUFFER: usize = 1024 * 1024;
impl Drop for RawCapture {
    fn drop(&mut self) {
        self.flush();
    }
}
impl RawCapture {
    pub(crate) fn sync(&mut self) -> Result<(), String> {
        self.flush();
        crate::writer::barrier();
        self.flush();
        if let Some(error) = &self.error
            && error.starts_with("capture write failed")
        {
            return Err(error.clone());
        }
        self.file.sync_all().map_err(|error| {
            let message = format!("raw capture sync failed: {error}");
            self.error.get_or_insert(message.clone());
            message
        })
    }
    pub(crate) fn quota(&self) -> u64 {
        self.quota
    }
    pub fn new(directory: PathBuf, quota: u64) -> Result<Self, String> {
        private_dir(&directory).map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("telemetry.raw"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            directory,
            file: std::sync::Arc::new(file),
            buffer: Vec::new(),
            written: (0, 0),
            write_error: crate::writer::error_slot(),
            write_error_seen: false,
            quota,
            packets: 0,
            bytes: 0,
            error: None,
            final_health: None,
            guest_kernel: None,
        })
    }
    pub fn append(&mut self, packet: &[u8]) -> bool {
        self.append_with_reserved(packet, 0)
    }
    pub fn append_with_reserved(&mut self, packet: &[u8], reserved_len: u64) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(total) = self
            .bytes
            .checked_add(4)
            .and_then(|n| n.checked_add(packet.len() as u64))
        else {
            self.error = Some("capture size overflow".into());
            return false;
        };
        if total.saturating_add(reserved_len) > self.quota {
            self.error = Some(
                "capture quota exhausted; collection continues without saving new packets".into(),
            );
            return false;
        }
        let length = match u32::try_from(packet.len()) {
            Ok(n) => n,
            Err(_) => {
                self.error = Some("packet length overflow".into());
                return false;
            }
        };
        self.buffer.extend_from_slice(&length.to_le_bytes());
        self.buffer.extend_from_slice(packet);
        self.bytes = total;
        self.packets += 1;
        self.buffer.len() < RAW_BUFFER || self.flush()
    }
    /// Hand buffered packets to the writer thread. False once, when an
    /// earlier write of this file has failed: the writer then cut the file
    /// back to the last complete block, so it stays whole packets, and
    /// nothing more is written.
    pub fn flush(&mut self) -> bool {
        if !self.write_error_seen
            && let Some(error) = crate::writer::error_of(&self.write_error)
        {
            self.write_error_seen = true;
            self.error.get_or_insert(error);
            self.buffer.clear();
            if let Ok(metadata) = self.file.metadata() {
                self.bytes = metadata.len();
            }
            return false;
        }
        if !self.buffer.is_empty() && !self.write_error_seen {
            crate::writer::submit(crate::writer::Op::Append {
                file: self.file.clone(),
                data: std::mem::take(&mut self.buffer),
                rollback: self.written.0,
                error: self.write_error.clone(),
            });
            self.written = (self.bytes, self.packets);
        }
        true
    }
    pub(crate) fn manifest(
        &mut self,
        vm: &VmConfig,
        bundle: &Bundle,
        disk_bundle: &Bundle,
        state: &str,
    ) -> Result<(), String> {
        self.flush();
        crate::writer::barrier();
        if self.flush()
            && let Err(e) = self.file.sync_all()
        {
            self.error
                .get_or_insert_with(|| format!("capture sync failed: {e}"));
        }
        if let Some(health) = &mut self.final_health {
            health.persistence_error = self
                .error
                .clone()
                .or_else(|| health.persistence_error.clone());
        }
        atomic_json(
            &self.directory.join("manifest.json"),
            &CaptureManifest {
                format: "ANTT1 length-prefixed raw LE32",
                vm,
                bundle,
                disk_bundle,
                packets: self.packets,
                bytes: self.bytes,
                persistence_error: &self.error,
                final_state: state,
                health: &self.final_health,
                guest_kernel: &self.guest_kernel,
            },
        )
    }
}

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
        let root = std::env::temp_dir().join(format!("ant-json-queue-{}", unique_id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("run.json");
        for value in 0..50 {
            queue_json(&path, &value).unwrap();
        }
        flush_json();
        assert_eq!(read_json::<u32>(&path).unwrap(), 49);
        for value in 100..150 {
            queue_json(&path, &value).unwrap();
            atomic_json(&path, &(value + 1000)).unwrap();
        }
        flush_json();
        assert_eq!(read_json::<u32>(&path).unwrap(), 1149);
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            1,
            "temporary files left behind"
        );
        fs::remove_dir_all(root).unwrap();
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
        let account = crate::guest_account::GuestAccount::from_credentials(
            crate::api::GuestCredentials::new("analyst".into(), "fixturepassword".into()).unwrap(),
        )
        .unwrap();
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
