// SPDX-License-Identifier: MIT
//! Importing a qcow2 image made elsewhere.
//!
//! The qcow2 metadata of an imported file (headers, L1/L2 tables, backing
//! file name, compression) is attacker-controlled, unlike the chains QEMU
//! wrote for the VMs here. `qemu-img` therefore only ever touches it inside
//! the analysis sandbox: no network, the host hidden, the file at `/input`
//! read-only and one writable folder at `/out`, under `prlimit`.
//!
//! The file is inspected first and refused when it depends on anything
//! outside itself (a backing file, an external data file), is encrypted, or
//! claims an absurd size. It is then converted to a raw image; a disk with a
//! partition table is carved down to its root (or largest ext4) partition in
//! a second sandboxed conversion, so the dump is, like every other, one ext4
//! filesystem.
use super::*;
use crate::disks::{
    DiskLayerRef, DiskSourceKind,
    partition::{self, PartitionFs},
    sandbox::{self, Account},
};
use serde_json::Value;
use std::ffi::OsString;

/// The largest virtual disk an import accepts.
pub const VIRTUAL_SIZE_LIMIT: u64 = 2 * 1024 * 1024 * 1024 * 1024;
/// File names inside the output folder.
const WHOLE_FILE: &str = "disk.raw.tmp";

/// Everything an import needs.
#[derive(Clone, Debug)]
pub struct ImportSpec {
    pub qemu_img: PathBuf,
    /// The VM whose recordings get the dump.
    pub vm_id: String,
    pub vm_name: String,
    /// The qcow2 file, anywhere on the host.
    pub source: PathBuf,
    /// `<recording dir>/disks`.
    pub disks_dir: PathBuf,
    /// SHA-256 of the converted image.
    pub hash: bool,
}

/// What `qemu-img info` says about an imported qcow2, after the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qcow2Facts {
    pub virtual_size: u64,
    pub actual_size: u64,
}

/// Judge the `qemu-img info --output=json` of an imported file. Refuses a
/// file that is not qcow2, depends on a backing file or an external data
/// file, is encrypted, or has an absurd size.
pub fn check_info(info: &Value) -> Result<Qcow2Facts, String> {
    if info.get("format").and_then(Value::as_str) != Some("qcow2") {
        return Err("this is not a qcow2 image".into());
    }
    if let Some(backing) = info.get("backing-filename").and_then(Value::as_str) {
        let shown: String = backing
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        return Err(format!(
            "the qcow2 image depends on a backing file ({shown}); an import must be \
             self-contained. Flatten it first with `qemu-img convert -O qcow2 <file> \
             <flat.qcow2>`"
        ));
    }
    let specific = info.pointer("/format-specific/data");
    if specific
        .and_then(|data| data.get("data-file"))
        .is_some_and(|file| !file.is_null())
    {
        return Err("the qcow2 image keeps its data in an external data file; an import must be self-contained".into());
    }
    if info.get("encrypted").and_then(Value::as_bool) == Some(true)
        || specific
            .and_then(|data| data.get("encrypt"))
            .is_some_and(|encrypt| !encrypt.is_null())
    {
        return Err("the qcow2 image is encrypted".into());
    }
    let virtual_size = info
        .get("virtual-size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or("qemu-img did not report the image's size")?;
    if virtual_size > VIRTUAL_SIZE_LIMIT {
        return Err(format!(
            "the qcow2 image claims {} of disk; imports are limited to {}",
            crate::disks::format_size(virtual_size),
            crate::disks::format_size(VIRTUAL_SIZE_LIMIT)
        ));
    }
    Ok(Qcow2Facts {
        virtual_size,
        actual_size: info
            .get("actual-size")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    })
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

impl Run {
    /// Convert `spec.source` into a new dump of the VM's recordings.
    pub(super) fn import_qcow2(&self, spec: &ImportSpec) -> Result<DiskDump, String> {
        crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "util-linux")?;
        let started_ms = unix_ms();
        let qemu_img = sandbox::sandboxed_qemu_img(&spec.qemu_img)?;
        let source = fs::canonicalize(&spec.source)
            .map_err(|error| format!("{}: {error}", spec.source.display()))?;
        let metadata =
            fs::metadata(&source).map_err(|error| format!("{}: {error}", source.display()))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", source.display()));
        }
        let mut head = [0u8; 4];
        File::open(&source)
            .and_then(|mut file| file.read_exact(&mut head))
            .map_err(|error| format!("{}: {error}", source.display()))?;
        if &head != b"QFI\xfb" {
            return Err("this is not a qcow2 image".into());
        }
        crate::storage::private_dir(&spec.disks_dir)
            .map_err(|error| format!("{}: {error}", spec.disks_dir.display()))?;
        let account = Account::new()?;
        sweep_partial(&spec.disks_dir);
        let id = crate::storage::unique_id();
        let folder = spec.disks_dir.join(&id);
        crate::storage::private_dir(&folder)
            .map_err(|error| format!("{}: {error}", folder.display()))?;
        let result =
            self.convert_import(spec, &qemu_img, &source, &account, &folder, &id, started_ms);
        if result.is_err() {
            let _ = fs::remove_dir_all(&folder);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn convert_import(
        &self,
        spec: &ImportSpec,
        qemu_img: &Path,
        source: &Path,
        account: &Account,
        folder: &Path,
        id: &str,
        started_ms: u64,
    ) -> Result<DiskDump, String> {
        self.set_stage(DiskJobStage::Measuring);
        // 1. What the file claims, read in the sandbox.
        let command = sandbox::qemu_img_in_sandbox(
            qemu_img,
            account.passwd(),
            Some(source),
            folder,
            &args(&["info", "-f", "qcow2", "--output=json", "/input"]),
        );
        let (output, _) = measure::run_capped(command, 1024 * 1024)?
            .ok_or("the qcow2 description is unexpectedly large")?;
        let info: Value = serde_json::from_slice(&output)
            .map_err(|error| format!("qemu-img info output: {error}"))?;
        let facts = check_info(&info)?;
        self.cancelled()?;
        // 2. Room for it. The output is sparse; a hostile image can still
        // expand (compressed clusters), so the conversion is watched.
        let free = measure::free_space(folder)?;
        let limit = free.saturating_sub(crate::disks::SPACE_MARGIN);
        if limit < facts.actual_size.min(facts.virtual_size) {
            return Err(format!(
                "the image needs about {} of free space under {}; {} is available",
                crate::disks::format_size(facts.actual_size.min(facts.virtual_size)),
                spec.disks_dir.display(),
                crate::disks::format_size(free)
            ));
        }
        self.estimate
            .store(facts.actual_size.min(facts.virtual_size), Ordering::Relaxed);
        // 3. The whole disk as raw, written in the sandbox.
        let whole = folder.join(WHOLE_FILE);
        self.sandboxed_convert(
            qemu_img,
            account,
            Some(source),
            folder,
            &[
                "convert",
                "-p",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "/input",
                "/out/disk.raw.tmp",
            ],
            &whole,
            limit,
        )?;
        let length = fs::metadata(&whole)
            .map_err(|error| error.to_string())?
            .len();
        if length != facts.virtual_size {
            return Err(format!(
                "the converted image is {length} bytes; the qcow2 image declares {}",
                facts.virtual_size
            ));
        }
        // 4. A partitioned disk is carved down to its ext4 partition.
        let part = folder.join(PART_FILE);
        let mut record = DiskSourceRecord {
            kind: DiskSourceKind::Imported,
            ..DiskSourceRecord::default()
        };
        let table = raw_partitions(&whole, length)?;
        let image_size = if let Some(table) = table {
            let index = table.default_partition().ok_or(
                "unsupported filesystem: the disk has a partition table but no ext2/3/4 partition",
            )?;
            let chosen = table.get(index).cloned().ok_or("partition vanished")?;
            self.sandboxed_convert(
                qemu_img,
                account,
                None,
                folder,
                &[
                    "convert",
                    "-p",
                    "--image-opts",
                    "-O",
                    "raw",
                    &format!(
                        "driver=raw,offset={},size={},file.driver=file,file.filename=/out/{WHOLE_FILE}",
                        chosen.start, chosen.length
                    ),
                    "/out/root.ext4.part",
                ],
                &part,
                limit,
            )?;
            let size = chosen.length;
            record.partition = Some(chosen);
            let _ = fs::remove_file(&whole);
            size
        } else {
            fs::rename(&whole, &part).map_err(|error| error.to_string())?;
            length
        };
        // 5. Check, name, hash, record.
        self.set_stage(DiskJobStage::Finalizing);
        let flat = self
            .finish_image(&part, image_size, folder)
            .map_err(|error| {
                if error.contains("ext2/3/4") {
                    format!("unsupported filesystem: {error}")
                } else {
                    error
                }
            })?;
        let sha256 = spec.hash.then(|| self.hash(&flat.image)).transpose()?;
        self.cancelled()?;
        record.layers = vec![DiskLayerRef {
            filename: source.display().to_string(),
            size: facts.actual_size,
            modified_ms: fs::metadata(source)
                .map(|metadata| (metadata.mtime().max(0) as u64) * 1000)
                .unwrap_or_default(),
            sha256: None,
        }];
        let dump = DiskDump {
            id: id.into(),
            vm_id: spec.vm_id.clone(),
            vm_name: spec.vm_name.clone(),
            imported: false,
            file: IMAGE_FILE.into(),
            format: DiskImageFormat::RawExt4,
            fs_state: flat.fs_state,
            started_ms,
            finished_ms: Some(unix_ms()),
            logical_size: image_size,
            allocated_size: Some(flat.allocated),
            sha256,
            source: record,
            system: "Imported qcow2 image, converted in the sandbox".into(),
            error: None,
            dir: folder.to_path_buf(),
        };
        dump.save()?;
        Ok(dump)
    }

    /// Run one sandboxed `qemu-img convert` that writes `output` (a path on
    /// the host that `/out/...` names), watching its allocation.
    #[allow(clippy::too_many_arguments)]
    fn sandboxed_convert(
        &self,
        qemu_img: &Path,
        account: &Account,
        input: Option<&Path>,
        out: &Path,
        arguments: &[&str],
        output: &Path,
        limit: u64,
    ) -> Result<(), String> {
        self.set_stage(DiskJobStage::Converting { percent: 0.0 });
        let mut command =
            sandbox::qemu_img_in_sandbox(qemu_img, account.passwd(), input, out, &args(arguments));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::process_tree::own_group(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("mandatory bubblewrap isolation unavailable: {error}"))?;
        self.wait_watching(&mut child, Some((output, limit)))
    }
}

/// The partition table of a raw disk file, with the filesystem of each
/// partition looked at. `None` for a whole-disk filesystem.
fn raw_partitions(disk: &Path, size: u64) -> Result<Option<partition::PartitionTable>, String> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(disk).map_err(|error| error.to_string())?;
    let mut head = vec![0u8; partition::HEAD_SECTORS * 512];
    let count = file.read(&mut head).map_err(|error| error.to_string())?;
    head.truncate(count);
    let Some(mut table) = partition::parse(&head, size)? else {
        return Ok(None);
    };
    for entry in table.partitions.iter_mut().take(partition::FS_PROBE_LIMIT) {
        if entry.fs == PartitionFs::Other {
            continue;
        }
        let mut sector = [0u8; 512];
        entry.fs = match file
            .seek(SeekFrom::Start(entry.start + 1024))
            .and_then(|_| file.read_exact(&mut sector))
        {
            Ok(()) if partition::is_ext4_superblock(&sector) => PartitionFs::Ext4,
            Ok(()) => PartitionFs::Other,
            Err(_) => PartitionFs::Unknown,
        };
    }
    Ok(Some(table))
}
