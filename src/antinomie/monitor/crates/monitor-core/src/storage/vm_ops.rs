// SPDX-License-Identifier: GPL-3.0-only
//! VM directory operations: overlay, reset, duplicate, delete, config save (moved out of `storage`).
use super::*;

pub(crate) fn create_overlay(
    options: &BackendOptions,
    dir: &Path,
    disk_gib: u32,
    bundle: &Bundle,
) -> Result<(), String> {
    crate::dependencies::require_tool(&options.qemu_img, "qemu-utils")?;
    bundle.verify_installed()?;
    validate_disk_chain(options, bundle.vm_disk(), None)?;
    if bundle.uefi.uefi_disk.is_some() && crate::uefi_disk::existing(bundle)?.is_none() {
        return Err("the base's UEFI disk is missing".into());
    }
    let disk = dir.join("disk.qcow2");
    if disk.exists() {
        return Err("VM disk already exists".into());
    }
    let result = Command::new(&options.qemu_img)
        .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(bundle.vm_disk())
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
    if crate::snapshots::managed(directory) {
        return Err("reset is unavailable while snapshot dependencies exist; duplicate to an independent VM first".into());
    }
    validate_vm_bundle(options, vm, bundle)?;
    validate_disk_chain(
        options,
        &directory.join("disk.qcow2"),
        Some(bundle.vm_disk()),
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
    let boot = crate::guest_account::ProvisionBoot::for_bundle(options, bundle)?;
    let staging = directory.join(format!("reset-{}", unique_id()));
    private_dir(&staging).map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        create_overlay(options, &staging, vm.disk_gib, bundle)?;
        let disk = staging.join("disk.qcow2");
        let interface = crate::guest_account::provisioned_interface(
            &bundle.stealth_support,
            &vm.stealth,
            bundle.arch,
        );
        let account = account
            .map(|mut account| {
                account
                    .provision(
                        &disk,
                        vm.ram_mib,
                        interface,
                        crate::guest_account::boot_disk(&vm.stealth),
                        boot.as_ref(),
                    )
                    .map(|()| account)
            })
            .transpose()?;
        File::open(&disk)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&disk, directory.join("disk.qcow2")).map_err(|e| e.to_string())?;
        // The new disk's filesystem UUID, for the kernel command line.
        account.map_or(Ok(()), |account| account.save(directory))?;
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
    let source_disk = crate::snapshots::active_disk(options, source)?;
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
    crate::snapshots::validate_active(options, source, bundle.vm_disk())?;
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
    crate::dependencies::require_tool(&options.qemu_img, "qemu-utils")?;
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
    crate::snapshots::run_layer::ensure_idle(options, id)?;
    let bundle: Bundle = read_json(&dir.join("bundle.json"))?;
    bundle.verify_installed()?;
    crate::snapshots::validate_active(options, &config, bundle.vm_disk())?;
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
    paths.extend(crate::snapshots::deletion_paths(
        options,
        &config,
        bundle.vm_disk(),
    )?);
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
        // Persist both ends of the rename before the discovery tombstone.
        // Otherwise a crash could retain a deleted registry entry while the
        // VM's disk/manifest moves were never made durable.
        sync_json_parent(&staging.join("config.json"))
            .map_err(|error| format!("VM deletion staging durability: {error}"))?;
        sync_json_parent(&dir.join("config.json"))
            .map_err(|error| format!("VM deletion source directory durability: {error}"))?;
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
        if let Err(error) = fs::remove_dir(&staging) {
            rollback_errors.push(format!("deletion staging cleanup: {error}"));
        }
        if let Err(error) = sync_json_parent(&dir.join("config.json")) {
            rollback_errors.push(format!("deletion rollback directory durability: {error}"));
        }
        if staging.exists()
            && let Err(error) = sync_json_parent(&staging.join("config.json"))
        {
            rollback_errors.push(format!("retained deletion staging durability: {error}"));
        }
        return Err(format!(
            "{error}; deletion rollback errors {rollback_errors:?}"
        ));
    }
    for (_, target) in staged {
        if fs::symlink_metadata(&target)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_dir()
        {
            fs::remove_dir_all(target).map_err(|e| e.to_string())?;
        } else {
            fs::remove_file(target).map_err(|e| e.to_string())?;
        }
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
