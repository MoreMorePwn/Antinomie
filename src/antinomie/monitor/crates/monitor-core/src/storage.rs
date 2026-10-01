use crate::api::{BackendOptions, Health, VmConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn unique_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}
pub(crate) fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
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
    Ok(options.data_dir.join("vms").join(id))
}
pub(crate) fn load_vms(options: &BackendOptions) -> Result<Vec<VmConfig>, String> {
    let dir = options.data_dir.join("vms");
    private_dir(&dir).map_err(|e| e.to_string())?;
    let mut vms = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
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
        state: &str,
    ) -> Result<(), String> {
        if let Err(e) = self.file.sync_all() {
            self.error
                .get_or_insert_with(|| format!("capture sync failed: {e}"));
        }
        if let Some(health) = &mut self.final_health {
            health.persistence_error = self.error.clone();
        }
        atomic_json(
            &self.directory.join("manifest.json"),
            &CaptureManifest {
                format: "ANTT1 length-prefixed raw LE32",
                vm,
                bundle,
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
