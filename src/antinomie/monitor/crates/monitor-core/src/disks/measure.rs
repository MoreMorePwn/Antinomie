// SPDX-License-Identifier: MIT
//! Measuring a disk chain before it is flattened: its logical size, how much
//! of it is allocated, and whether the destination can hold the image.
use super::{DiskLayerRef, DiskMeasure, DiskSourceRecord, unix_ms};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Output of `qemu-img map` read at most; a larger one falls back to the
/// layers' allocated sizes.
const MAP_OUTPUT_LIMIT: u64 = 64 * 1024 * 1024;
/// Output of `qemu-img info --backing-chain` read at most.
const INFO_OUTPUT_LIMIT: u64 = 1024 * 1024;
/// Layers of a chain read at most (the snapshot module's own depth limit).
const CHAIN_LIMIT: usize = 64;

/// A `qemu-img` command that dies with the app: through util-linux `setpriv`
/// when installed, so an app crash cannot leave a converter reading (and
/// locking) the chain, like the QEMU launch does.
pub(crate) fn qemu_img_command(qemu_img: &Path) -> Command {
    match crate::dependencies::executable(Path::new("setpriv")) {
        Some(setpriv) => {
            let mut command = Command::new(setpriv);
            command.args(["--pdeathsig", "KILL", "--"]).arg(qemu_img);
            command
        }
        None => Command::new(qemu_img),
    }
}

/// What `qemu-img info --backing-chain` says about a chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainInfo {
    pub virtual_size: u64,
    /// Top first, base last.
    pub layers: Vec<DiskLayerRef>,
    /// Sum of the layers' allocated file sizes.
    pub actual_size: u64,
}

/// Run `command`, reading at most `limit` bytes of stdout. `None` when the
/// output was larger (the process is stopped).
fn run_capped(mut command: Command, limit: u64) -> Result<Option<(Vec<u8>, String)>, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{}: {error}", command.get_program().to_string_lossy()))?;
    let mut stderr = child.stderr.take().ok_or("qemu-img stderr unavailable")?;
    let errors = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut text);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        String::from_utf8_lossy(&text).into_owned()
    });
    let mut output = Vec::new();
    let stdout = child.stdout.take().ok_or("qemu-img stdout unavailable")?;
    let read = stdout.take(limit + 1).read_to_end(&mut output);
    let exceeded = output.len() as u64 > limit;
    if exceeded {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    let errors = errors.join().unwrap_or_default();
    read.map_err(|error| error.to_string())?;
    if exceeded {
        return Ok(None);
    }
    if !status.success() {
        return Err(qemu_failure(&errors));
    }
    Ok(Some((output, errors)))
}

/// A `qemu-img` failure as a sentence. A write lock held by QEMU is the one
/// the user can act on: the VM (or another program) has the disk open.
pub(crate) fn qemu_failure(stderr: &str) -> String {
    let text = stderr.trim();
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("qemu-img failed");
    if text.contains("lock") {
        format!("the VM appears to be running or another program holds its disk: {line}")
    } else {
        format!("qemu-img: {line}")
    }
}

/// Logical size and layers of the chain whose top is `top`. `vm_dir` shortens
/// layer names to the VM-relative form the snapshot manifest uses.
pub fn chain_info(qemu_img: &Path, vm_dir: &Path, top: &Path) -> Result<ChainInfo, String> {
    let mut command = qemu_img_command(qemu_img);
    command
        .args(["info", "-f", "qcow2", "--backing-chain", "--output=json"])
        .arg(top);
    let (output, _) = run_capped(command, INFO_OUTPUT_LIMIT)?
        .ok_or("the disk chain description is unexpectedly large")?;
    let layers: Vec<Value> = serde_json::from_slice(&output)
        .map_err(|error| format!("qemu-img info output: {error}"))?;
    let Some(first) = layers.first() else {
        return Err("qemu-img describes no disk layers".into());
    };
    if layers.len() > CHAIN_LIMIT {
        return Err("the disk chain is deeper than the supported 64 layers".into());
    }
    let virtual_size = first
        .get("virtual-size")
        .and_then(Value::as_u64)
        .ok_or("qemu-img did not report the disk's size")?;
    let mut info = ChainInfo {
        virtual_size,
        ..ChainInfo::default()
    };
    for layer in &layers {
        let path = PathBuf::from(
            layer
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        let metadata = fs::metadata(&path).ok();
        let name = path
            .strip_prefix(vm_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        info.layers.push(DiskLayerRef {
            filename: name,
            size: metadata.as_ref().map_or(0, |metadata| metadata.len()),
            modified_ms: metadata
                .as_ref()
                .map_or(0, |metadata| (metadata.mtime().max(0) as u64) * 1000),
            sha256: None,
        });
        info.actual_size = info.actual_size.saturating_add(
            layer
                .get("actual-size")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        );
    }
    Ok(info)
}

/// The data a flattened image will hold: the sum of the extents `qemu-img map`
/// reports as data and not zero. An upper bound of the sparse output's
/// allocation (conversion drops more zero runs). Falls back to the layers'
/// allocated sizes when the map is unexpectedly large.
pub fn allocated_estimate(qemu_img: &Path, top: &Path, chain: &ChainInfo) -> Result<u64, String> {
    let mut command = qemu_img_command(qemu_img);
    command
        .args(["map", "-f", "qcow2", "--output=json"])
        .arg(top);
    let Some((output, _)) = run_capped(command, MAP_OUTPUT_LIMIT)? else {
        return Ok(chain.actual_size.min(chain.virtual_size));
    };
    let extents: Vec<Value> =
        serde_json::from_slice(&output).map_err(|error| format!("qemu-img map output: {error}"))?;
    Ok(map_data_size(&extents))
}

/// The sum of the data extents of a `qemu-img map --output=json` listing.
pub(crate) fn map_data_size(extents: &[Value]) -> u64 {
    extents
        .iter()
        .filter(|extent| {
            extent.get("data").and_then(Value::as_bool) == Some(true)
                && extent.get("zero").and_then(Value::as_bool) != Some(true)
        })
        .filter_map(|extent| extent.get("length").and_then(Value::as_u64))
        .fold(0u64, u64::saturating_add)
}

/// Bytes available to an unprivileged writer of the folder's filesystem.
pub fn free_space(directory: &Path) -> Result<u64, String> {
    let space = rustix::fs::statvfs(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    Ok(space.f_bavail.saturating_mul(space.f_frsize))
}

/// Whether the folder's filesystem keeps holes: a file extended with
/// `set_len` must allocate no blocks.
pub fn sparse_supported(directory: &Path) -> bool {
    let probe = directory.join(format!(".sparse-probe-{}", crate::storage::unique_id()));
    let result = (|| -> std::io::Result<bool> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        file.set_len(1024 * 1024)?;
        file.sync_all()?;
        Ok(file.metadata()?.blocks() == 0)
    })();
    let _ = fs::remove_file(&probe);
    result.unwrap_or(false)
}

/// Measure the chain with top `top`, for a view written under `disks_dir`
/// (created). A failure is recorded in the result, not returned, so the UI
/// can show it on the card.
pub fn measure(
    qemu_img: &Path,
    vm_id: &str,
    vm_dir: &Path,
    top: &Path,
    mut source: DiskSourceRecord,
    disks_dir: &Path,
) -> DiskMeasure {
    let mut measure = DiskMeasure {
        vm_id: vm_id.into(),
        directory: disks_dir.to_path_buf(),
        measured_ms: unix_ms(),
        ..DiskMeasure::default()
    };
    let result = (|| -> Result<(), String> {
        crate::storage::private_dir(disks_dir)
            .map_err(|error| format!("{}: {error}", disks_dir.display()))?;
        let chain = chain_info(qemu_img, vm_dir, top)?;
        measure.logical_size = chain.virtual_size;
        measure.allocated_estimate = allocated_estimate(qemu_img, top, &chain)?;
        source.layers = chain.layers;
        measure.free_space = free_space(disks_dir)?;
        measure.sparse_supported = sparse_supported(disks_dir);
        Ok(())
    })();
    measure.source = source;
    measure.error = result.err().or_else(|| measure.space_error());
    measure
}
