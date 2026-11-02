// SPDX-License-Identifier: GPL-3.0-only
//! Moving the old data folder into the default one at first start.
use super::*;

/// Copy, validate, and atomically publish legacy data. The source is retained.
pub(crate) fn migrate_default_data(options: &BackendOptions) -> Result<(), String> {
    migrate_default_data_dir(&options.data_dir)
}

/// Whatever creates the default data directory first (the backend, a tool
/// install) calls this first, so the legacy folder is migrated into it rather
/// than found next to a half-filled destination.
pub(crate) fn ensure_data_dir(data_dir: &Path) -> Result<(), String> {
    migrate_default_data_dir(data_dir)?;
    private_dir(data_dir).map_err(|e| e.to_string())
}

fn migrate_default_data_dir(data_dir: &Path) -> Result<(), String> {
    if data_dir != BackendOptions::default().data_dir {
        return Ok(());
    }
    let source = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("antinomie");
    migrate_data(&source, data_dir)
}
/// The old data folder holds nothing of Antinomie's: it is empty or has only
/// the window state eframe saves there (`app.ron`), which every GUI run
/// recreates because the application id is "antinomie".
fn holds_only_window_state(folder: &Path) -> bool {
    let Ok(entries) = fs::read_dir(folder) else {
        return false;
    };
    entries
        .flatten()
        .all(|entry| entry.file_name() == "app.ron")
}

pub fn migrate_data(source: &Path, destination: &Path) -> Result<(), String> {
    migrate_data_with_proc(source, destination, Path::new("/proc"))
}

pub(super) fn migrate_data_with_proc(
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
    if holds_only_window_state(source) {
        return Ok(());
    }
    let source = fs::canonicalize(source).map_err(|e| e.to_string())?;
    // The legacy relocation rebases a single disk.qcow2 directly onto its base.
    // Applying that transformation to a snapshot tree would sever dependencies.
    for entry in fs::read_dir(&source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir()
            && crate::snapshots::managed(&entry.path())
        {
            return Err(
                "data migration with snapshot trees is unsupported; source retained".into(),
            );
        }
    }
    let legacy_vms = source.join("vms");
    if legacy_vms.is_dir() {
        for entry in fs::read_dir(&legacy_vms).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if crate::snapshots::managed(&entry.path()) {
                return Err(
                    "data migration with snapshot trees is unsupported; source retained".into(),
                );
            }
        }
    }
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
        return Err("the old data folder has data, but the new data folder is not empty and has no migration record; the old folder was kept. Close Antinomie, move or delete the new data folder if it holds nothing you need, and start again, or copy the old one over by hand".into());
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
                    .vm_disk()
                    .strip_prefix(destination)
                    .map_err(|_| "migration overlay backing is outside verified data root")?;
                let verified_base = staging.join(relative);
                if !verified_base.is_file() {
                    return Err("migration verified backing base is missing".into());
                }
                let result = Command::new("qemu-img")
                    .args(["rebase", "-u", "-f", "qcow2", "-F", "qcow2", "-b"])
                    .arg(bundle.vm_disk())
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
