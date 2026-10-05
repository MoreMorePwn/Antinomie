use crate::api::{BackendOptions, Health, VmConfig};
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
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let used = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if used == 0 {
            break;
        }
        digest.update(&buffer[..used]);
    }
    Ok(digest.finalize().into())
}
pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", unique_id()));
    let result = (|| -> Result<(), String> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(&mut f, value).map_err(|e| e.to_string())?;
        f.write_all(b"\n").map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        File::open(path.parent().ok_or("missing parent")?)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
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
}
impl Bundle {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(dir).map_err(|e| format!("bundle {}: {e}", dir.display()))?;
        let mut b: Self = serde_json::from_reader(
            File::open(root.join("bundle.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
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
    fn identity(&self) -> Result<String, String> {
        let mut digest = Sha256::new();
        digest.update(
            serde_json::to_vec(&(&self.kernel_append, &self.kernel_version, self.schema_id))
                .map_err(|e| e.to_string())?,
        );
        for path in [
            Some(&self.kernel),
            Some(&self.base_disk),
            self.initrd.as_ref(),
        ] {
            if let Some(path) = path {
                let mut file = File::open(path).map_err(|e| e.to_string())?;
                let mut content = Sha256::new();
                let mut chunk = [0; 65536];
                loop {
                    let len = file.read(&mut chunk).map_err(|e| e.to_string())?;
                    if len == 0 {
                        break;
                    }
                    content.update(&chunk[..len]);
                }
                digest.update([1]);
                digest.update(content.finalize());
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
        };
        installed.verify_installed()?;
        atomic_json(&target.join("bundle.json"), &installed)?;
        Ok(installed)
    }
    pub(crate) fn verify_installed(&self) -> Result<(), String> {
        let expected = self
            .base_identity
            .as_ref()
            .ok_or("VM has no installed base identity")?;
        if &self.identity()? != expected {
            return Err("installed base checksum mismatch".into());
        }
        Ok(())
    }
}
pub(crate) fn validate_vm(vm: &VmConfig) -> Result<(), String> {
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
    if !(256..=3072).contains(&vm.ram_mib) {
        return Err("initial release requires 256..3072 MiB RAM, entirely below 4 GiB".into());
    }
    if !(1..=2048).contains(&vm.disk_gib) {
        return Err("disk capacity must be 1..2048 GiB".into());
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
    let direct = options.data_dir.join(id);
    if direct.exists() {
        return Ok(direct);
    }
    if let Ok(entries) = fs::read_dir(&options.data_dir) {
        for entry in entries.flatten() {
            let config = entry.path().join("config.json");
            if let Ok(file) = File::open(config)
                && let Ok(vm) = serde_json::from_reader::<_, VmConfig>(file)
                && vm.id == id
            {
                return Ok(entry.path());
            }
        }
    }
    let legacy = options.data_dir.join("vms").join(id);
    if legacy.exists() {
        return Ok(legacy);
    }
    Ok(direct)
}
pub(crate) fn load_vms(options: &BackendOptions) -> Result<Vec<VmConfig>, String> {
    let dir = &options.data_dir;
    let mut vms = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let path = entry.path().join("config.json");
        if !path.exists() {
            continue;
        }
        let vm: VmConfig = serde_json::from_reader(File::open(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        validate_vm(&vm)?;
        vms.push(vm);
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
    if !destination.is_absolute() {
        return Err("migration destination must be absolute".into());
    }
    if !source.exists() || destination.join("migration.json").exists() {
        return Ok(());
    }
    let source = fs::canonicalize(source).map_err(|e| e.to_string())?;
    for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
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
}
pub struct RawCapture {
    pub directory: PathBuf,
    file: File,
    quota: u64,
    pub packets: u64,
    pub bytes: u64,
    pub error: Option<String>,
    pub final_health: Option<Health>,
}
impl RawCapture {
    pub(crate) fn sync(&mut self) -> Result<(), String> {
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
            file,
            quota,
            packets: 0,
            bytes: 0,
            error: None,
            final_health: None,
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
        let prior = self.bytes;
        if let Err(e) = self
            .file
            .write_all(&length.to_le_bytes())
            .and_then(|_| self.file.write_all(packet))
        {
            self.error = Some(format!("capture write failed: {e}"));
            let _ = self.file.set_len(prior);
            return false;
        }
        self.bytes = total;
        self.packets += 1;
        true
    }
    pub(crate) fn manifest(
        &mut self,
        vm: &VmConfig,
        bundle: &Bundle,
        disk_bundle: &Bundle,
        state: &str,
    ) -> Result<(), String> {
        if let Err(e) = self.file.sync_all() {
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
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let monitor = parent.join("antinomie-monitor");
        std::os::unix::fs::symlink("/bin/sleep", &monitor).unwrap();
        let mut child = Command::new(&monitor).arg("60").spawn().unwrap();
        assert!(
            migrate_data(&source, &destination)
                .unwrap_err()
                .contains("deferred")
        );
        child.kill().unwrap();
        child.wait().unwrap();
        migrate_data(&source, &destination).unwrap();
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
            migrate_data(&hidden, &hidden.join("nested"))
                .unwrap_err()
                .contains("overlap")
        );
        let conflict = parent.join("conflict");
        private_dir(&conflict).unwrap();
        fs::write(conflict.join("keep"), b"untouched").unwrap();
        assert!(
            migrate_data(&hidden, &conflict)
                .unwrap_err()
                .contains("not empty")
        );
        assert_eq!(fs::read(conflict.join("keep")).unwrap(), b"untouched");
        let bad = parent.join("bad-source");
        private_dir(&bad).unwrap();
        fs::write(bad.join("manifest.json"), b"{broken").unwrap();
        assert!(migrate_data(&bad, &parent.join("bad-target")).is_err());
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
        assert!(validate_vm(&vm).is_err());
    }
    #[test]
    fn quota_preserves_prior_packets() {
        let path = std::env::temp_dir().join(format!("ant-capture-{}", unique_id()));
        let mut c = RawCapture::new(path.clone(), 8).unwrap();
        assert!(c.append(b"test"));
        assert!(!c.append(b"lost"));
        assert!(c.error.is_some());
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
        let bundle = Bundle {
            kernel: source.join("kernel"),
            base_disk: source.join("base.qcow2"),
            initrd: None,
            kernel_append: "root=/dev/vda".into(),
            kernel_version: "test".into(),
            schema_id: 1,
            base_identity: None,
        };
        let options = BackendOptions {
            data_dir: directory.join("data"),
            ..BackendOptions::default()
        };
        let installed = bundle.install(&options).unwrap();
        fs::remove_dir_all(source).unwrap();
        installed.verify_installed().unwrap();
        assert_eq!(fs::read(installed.base_disk).unwrap(), b"disk");
        fs::remove_dir_all(directory).unwrap();
    }
}
