// SPDX-License-Identifier: MIT
//! UEFI firmware (OVMF) for the stealth profile, found as QEMU and libvirt
//! find it: through the firmware descriptors QEMU's packages install
//! (QEMU's `docs/interop/firmware.json`).
use std::{
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// The OVMF images of one descriptor: the read-only code and the variable
/// store template every VM copies once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ovmf {
    pub code: PathBuf,
    pub vars_template: PathBuf,
    /// The descriptor the images came from.
    pub descriptor: PathBuf,
}

/// Descriptor folders, most specific first: the user's, the host's, then
/// the data folder of the QEMU in use and the distribution's.
fn descriptor_dirs(qemu: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
    {
        dirs.push(config.join("qemu/firmware"));
    }
    dirs.push(PathBuf::from("/etc/qemu/firmware"));
    if let Some(prefix) = crate::dependencies::executable(qemu)
        .and_then(|binary| fs::canonicalize(binary).ok())
        .and_then(|binary| Some(binary.parent()?.parent()?.to_owned()))
    {
        dirs.push(prefix.join("share/qemu/firmware"));
    }
    dirs.push(PathBuf::from("/usr/share/qemu/firmware"));
    dirs.dedup();
    dirs
}

/// Descriptors by file name: a name in a more specific folder hides the same
/// name further down (an empty file disables one), and they are tried in
/// file name order.
fn descriptors(qemu: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for dir in descriptor_dirs(qemu) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") && !found.iter().any(|(known, _)| *known == name) {
                found.push((name, entry.path()));
            }
        }
    }
    found.sort();
    found.into_iter().map(|(_, path)| path).collect()
}

fn read_descriptor(path: &Path) -> Option<serde_json::Value> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    serde_json::from_str(&text).ok()
}

/// The images of `descriptor` when it is UEFI for x86_64 q35 in two flash
/// devices with a raw variable store, and Secure Boot with Microsoft's keys
/// enrolled exactly when `secure_boot`.
pub(super) fn matches(
    descriptor: &serde_json::Value,
    secure_boot: bool,
) -> Option<(PathBuf, PathBuf)> {
    let has = |list: &str, value: &str| {
        descriptor[list]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
    };
    let q35 = descriptor["targets"].as_array()?.iter().any(|target| {
        target["architecture"].as_str() == Some("x86_64")
            && target["machines"].as_array().is_some_and(|machines| {
                machines
                    .iter()
                    .filter_map(|machine| machine.as_str())
                    .any(|machine| machine.starts_with("pc-q35"))
            })
    });
    let mapping = &descriptor["mapping"];
    let raw = |image: &serde_json::Value| {
        image["format"].as_str().unwrap_or("raw") == "raw"
            && image["filename"]
                .as_str()
                .is_some_and(|name| !name.is_empty())
    };
    let wanted = if secure_boot {
        has("features", "secure-boot") && has("features", "enrolled-keys")
    } else {
        !has("features", "secure-boot")
    };
    // Confidential-computing builds need launch support this VM does not have.
    let plain = !["amd-sev-es", "amd-sev-snp", "intel-tdx"]
        .iter()
        .any(|feature| has("features", feature));
    if !(has("interface-types", "uefi")
        && q35
        && wanted
        && plain
        && mapping["device"].as_str() == Some("flash")
        && mapping["mode"].as_str().unwrap_or("split") == "split"
        && raw(&mapping["executable"])
        && raw(&mapping["nvram-template"]))
    {
        return None;
    }
    let code = PathBuf::from(mapping["executable"]["filename"].as_str()?);
    let vars = PathBuf::from(mapping["nvram-template"]["filename"].as_str()?);
    (code.is_file() && vars.is_file()).then_some((code, vars))
}

/// OVMF for `qemu`, with Secure Boot keys enrolled when `secure_boot`.
pub fn find_ovmf(qemu: &Path, secure_boot: bool) -> Result<Ovmf, String> {
    descriptors(qemu)
        .into_iter()
        .find_map(|path| {
            let (code, vars_template) = matches(&read_descriptor(&path)?, secure_boot)?;
            Some(Ovmf {
                code,
                vars_template,
                descriptor: path,
            })
        })
        .ok_or_else(|| {
            if secure_boot {
                "no OVMF with enrolled Secure Boot keys among QEMU's firmware descriptors; \
                 on Debian/Ubuntu: sudo apt install ovmf"
            } else {
                "no OVMF among QEMU's firmware descriptors; on Debian/Ubuntu: sudo apt install ovmf"
            }
            .to_owned()
        })
}

/// The VM's own variable store (boot entries, Secure Boot keys), copied from
/// the template on its first UEFI boot and kept with the VM after that.
pub(super) fn vm_vars(ovmf: &Ovmf, vm_dir: &Path, secure_boot: bool) -> Result<PathBuf, String> {
    let path = vm_dir.join(if secure_boot {
        "efi-vars-secure-boot.fd"
    } else {
        "efi-vars.fd"
    });
    if path.exists() {
        return Ok(path);
    }
    let staging = vm_dir.join(format!(".efi-vars-{}.tmp", crate::storage::unique_id()));
    let copy = || -> std::io::Result<()> {
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        std::io::copy(&mut fs::File::open(&ovmf.vars_template)?, &mut target)?;
        target.sync_all()?;
        fs::rename(&staging, &path)
    };
    copy().map_err(|error| {
        let _ = fs::remove_file(&staging);
        format!("UEFI variable store {}: {error}", path.display())
    })?;
    Ok(path)
}
