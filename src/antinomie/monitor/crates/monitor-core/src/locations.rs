// SPDX-License-Identifier: MIT
//! Durable VM discovery and retained recording locations.
use crate::{
    api::*,
    storage::{self, Bundle, PublicationError},
};
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::OpenOptionsExt, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    id: String,
    disk_directory: PathBuf,
    recording_directory: PathBuf,
    recording_directories: Vec<PathBuf>,
    #[serde(default)]
    deleted: bool,
}

fn registry(options: &BackendOptions) -> Result<Vec<Entry>, String> {
    let path = options.data_dir.join("vm-locations.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let entries: Vec<Entry> = storage::read_json(&path)?;
    if entries.len() > 1024 {
        return Err("VM registry exceeds 1024 entries".into());
    }
    for entry in &entries {
        storage::validate_vm(&VmConfig {
            id: entry.id.clone(),
            ..VmConfig::default()
        })?;
        if !entry.disk_directory.is_absolute()
            || !entry.recording_directory.is_absolute()
            || entry.recording_directories.len() > 128
            || entry
                .recording_directories
                .iter()
                .any(|path| !path.is_absolute())
        {
            return Err("invalid VM registry location".into());
        }
    }
    Ok(entries)
}

fn store(options: &BackendOptions, entries: &[Entry]) -> Result<(), PublicationError> {
    if entries.len() > 1024 {
        return Err("VM registry exceeds 1024 entries".into());
    }
    if serde_json::to_vec_pretty(entries)
        .map_err(|e| e.to_string())?
        .len()
        >= 1024 * 1024
    {
        return Err("VM registry exceeds 1 MiB limit".into());
    }
    storage::atomic_json_checked(&options.data_dir.join("vm-locations.json"), &entries)
}

pub(crate) fn disk_directory(
    options: &BackendOptions,
    id: &str,
) -> Result<Option<PathBuf>, String> {
    Ok(registry(options)?
        .into_iter()
        .find(|entry| entry.id == id && !entry.deleted)
        .map(|entry| entry.disk_directory))
}

pub(crate) fn registered_vms(options: &BackendOptions) -> Result<Vec<VmConfig>, String> {
    registry(options)?
        .into_iter()
        .filter(|entry| !entry.deleted)
        .map(|entry| {
            let path = entry.disk_directory.join("config.json");
            let vm: VmConfig = storage::read_json(&path)?;
            storage::validate_vm(&vm)?;
            if vm.id != entry.id {
                return Err("VM registry/config identity mismatch".into());
            }
            Ok(vm)
        })
        .collect()
}

fn parent(options: &BackendOptions, chosen: &Option<PathBuf>) -> Result<PathBuf, String> {
    let path = chosen.as_deref().unwrap_or(&options.data_dir);
    let canonical =
        fs::canonicalize(path).map_err(|e| format!("storage parent {}: {e}", path.display()))?;
    if !canonical.is_dir() {
        return Err("storage parent must be a directory".into());
    }
    if canonical.starts_with(options.data_dir.join("bases")) {
        return Err("storage parent overlaps installed immutable bases".into());
    }
    for vm in storage::load_vms(options)? {
        let location = locations(options, &vm.id)?;
        if canonical.starts_with(&location.disk_directory)
            || location
                .recording_directories
                .iter()
                .any(|directory| canonical.starts_with(directory))
        {
            return Err("storage parent overlaps an existing VM directory".into());
        }
    }
    for entry in registry(options)?.into_iter().filter(|entry| entry.deleted) {
        if canonical.starts_with(entry.disk_directory)
            || entry
                .recording_directories
                .iter()
                .any(|directory| canonical.starts_with(directory))
        {
            return Err("storage parent overlaps retained deleted-VM recordings".into());
        }
    }
    let probe = canonical.join(format!(".antinomie-write-check-{}", storage::unique_id()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)
        .map_err(|error| {
            format!(
                "storage parent {} is not writable: {error}",
                canonical.display()
            )
        })?;
    let synced = file.sync_all().map_err(|error| error.to_string());
    drop(file);
    fs::remove_file(&probe)
        .map_err(|error| format!("storage write-check cleanup {}: {error}", probe.display()))?;
    synced?;
    Ok(canonical)
}

pub(crate) fn prepare(options: &BackendOptions, vm: &mut VmConfig) -> Result<VmLocations, String> {
    if registry(options)?.iter().any(|entry| entry.id == vm.id) {
        return Err("VM identity already registered".into());
    }
    let disk_parent = parent(options, &vm.disk_root)?;
    let recording_parent = vm
        .recording_root
        .as_ref()
        .map(|_| parent(options, &vm.recording_root))
        .transpose()?;
    if vm.disk_root.is_some() {
        vm.disk_root = Some(disk_parent.clone());
    }
    if let Some(path) = &recording_parent {
        vm.recording_root = Some(path.clone());
    }
    let disk_directory = disk_parent.join(&vm.id);
    let recording_directory =
        recording_parent.map_or_else(|| disk_directory.clone(), |path| path.join(&vm.id));
    if disk_directory.exists()
        || (recording_directory != disk_directory && recording_directory.exists())
    {
        return Err("VM storage directory already exists".into());
    }
    Ok(VmLocations {
        vm_id: vm.id.clone(),
        disk_directory,
        recording_directories: vec![recording_directory.clone()],
        recording_directory,
    })
}

pub(crate) fn locations(options: &BackendOptions, id: &str) -> Result<VmLocations, String> {
    if let Some(entry) = registry(options)?.into_iter().find(|entry| entry.id == id) {
        return Ok(VmLocations {
            vm_id: entry.id,
            disk_directory: entry.disk_directory,
            recording_directory: entry.recording_directory,
            recording_directories: entry.recording_directories,
        });
    }
    let directory = storage::vm_dir(options, id)?;
    Ok(VmLocations {
        vm_id: id.into(),
        disk_directory: directory.clone(),
        recording_directory: directory.clone(),
        recording_directories: vec![directory],
    })
}

pub(crate) fn publish(
    options: &BackendOptions,
    location: &VmLocations,
) -> Result<(), PublicationError> {
    let mut entries = registry(options)?;
    if let Some(entry) = entries.iter_mut().find(|entry| entry.id == location.vm_id) {
        if entry.deleted {
            return Err("VM identity belongs to retained deleted recordings".into());
        }
        entry.recording_directory = location.recording_directory.clone();
        entry.recording_directories = location.recording_directories.clone();
    } else {
        entries.push(Entry {
            id: location.vm_id.clone(),
            disk_directory: location.disk_directory.clone(),
            recording_directory: location.recording_directory.clone(),
            recording_directories: location.recording_directories.clone(),
            deleted: false,
        });
    }
    store(options, &entries)
}

pub(crate) fn future_recordings(
    options: &BackendOptions,
    current: &VmConfig,
    next: &mut VmConfig,
) -> Result<VmLocations, String> {
    if current.disk_root != next.disk_root {
        return Err(
            "disk relocation is not implemented; disk folder is fixed after creation".into(),
        );
    }
    let mut location = locations(options, &current.id)?;
    if current.recording_root != next.recording_root {
        let directory = match &next.recording_root {
            Some(_) => {
                let root = parent(options, &next.recording_root)?;
                next.recording_root = Some(root.clone());
                root.join(&current.id)
            }
            None => location.disk_directory.clone(),
        };
        if directory.exists() && !location.recording_directories.contains(&directory) {
            return Err("recording directory already exists and is not owned by this VM".into());
        }
        if !location.recording_directories.contains(&directory) {
            if location.recording_directories.len() >= 128 {
                return Err("VM recording location limit reached".into());
            }
            location.recording_directories.push(directory.clone());
        }
        location.recording_directory = directory;
    }
    Ok(location)
}

pub(crate) fn mark_deleted(options: &BackendOptions, id: &str) -> Result<(), PublicationError> {
    let mut entries = registry(options)?;
    let entry = entries
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or("unknown VM")?;
    entry.deleted = true;
    store(options, &entries)
}

pub(crate) fn installed_bases(options: &BackendOptions) -> Result<Vec<BaseSummary>, String> {
    let root = options.data_dir.join("bases");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut bases = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir()
            || !entry.path().join("bundle.json").is_file()
        {
            continue;
        }
        let bundle = Bundle::load(&entry.path())?;
        bundle.verify_installed()?;
        if !bundle.kernel_version.starts_with("6.12.94") {
            continue;
        }
        let id = bundle
            .base_identity
            .ok_or("installed bundle missing identity")?;
        if entry.file_name() != std::ffi::OsStr::new(&id) {
            return Err("installed base directory identity mismatch".into());
        }
        bases.push(BaseSummary {
            id,
            label: bundle.name.clone().unwrap_or_else(|| {
                bundle
                    .guest
                    .as_ref()
                    .map_or_else(|| "Linux 6.12.94".into(), |guest| guest.label.clone())
            }),
            directory: entry.path(),
            min_ram_mib: bundle.guest.as_ref().map_or(256, |guest| guest.min_ram_mib),
            min_disk_gib: bundle.guest.as_ref().map_or(1, |guest| guest.min_disk_gib),
            guest: bundle.guest,
            fixed_display: bundle.fixed_display,
            size_bytes: fs::metadata(&bundle.base_disk).map_or(0, |meta| meta.len()),
            revision: bundle.antinomie_revision,
            min_app_version: bundle.min_app_version.clone(),
            built_with: bundle.built_with.clone(),
        });
        if bases.len() > 128 {
            return Err("installed base catalog exceeds limit".into());
        }
    }
    bases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(bases)
}

pub(crate) fn boot_bundle(
    options: &BackendOptions,
    identity: Option<&str>,
) -> Result<Bundle, String> {
    let bases = installed_bases(options)?;
    let selected = match identity {
        Some(id) => Some(
            bases
                .iter()
                .find(|base| base.id == id)
                .ok_or("selected installed base is unavailable")?,
        ),
        None => bases
            .iter()
            .find(|base| base.guest.is_none())
            .or_else(|| bases.first()),
    };
    if let Some(base) = selected {
        return Bundle::load(&base.directory);
    }
    let bundle = Bundle::load(&options.bundle_dir)?;
    if !bundle.kernel_version.starts_with("6.12.94") {
        return Err("boot bundle must use Linux 6.12.94".into());
    }
    bundle.install(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    struct Fixture {
        root: PathBuf,
        options: BackendOptions,
        bundle: Bundle,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("ant-locations-{}", storage::unique_id()));
            let options = BackendOptions {
                data_dir: root.join("data"),
                bundle_dir: root.join("missing-build"),
                ..BackendOptions::default()
            };
            storage::private_dir(&options.data_dir).unwrap();
            let source = root.join("source");
            storage::private_dir(&source).unwrap();
            fs::write(source.join("kernel"), b"kernel fixture").unwrap();
            assert!(
                Command::new("qemu-img")
                    .args(["create", "-f", "qcow2"])
                    .arg(source.join("base.qcow2"))
                    .arg("1M")
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let bundle = Bundle {
                kernel: source.join("kernel"),
                base_disk: source.join("base.qcow2"),
                initrd: None,
                kernel_append: String::new(),
                kernel_version: "6.12.94".into(),
                schema_id: 1,
                base_identity: None,
                guest: None,
                fixed_display: true,
                build_provenance: None,
                antinomie_revision: None,
                antinomie_source: None,
                built_with: None,
                min_app_version: None,
                name: None,
            }
            .install(&options)
            .unwrap();
            fs::remove_dir_all(source).unwrap();
            Self {
                root,
                options,
                bundle,
            }
        }
        fn create(&self, mut vm: VmConfig) -> (VmConfig, VmLocations) {
            let location = prepare(&self.options, &mut vm).unwrap();
            storage::private_dir(&location.disk_directory).unwrap();
            storage::create_overlay(
                &self.options,
                &location.disk_directory,
                vm.disk_gib,
                &self.bundle,
            )
            .unwrap();
            vm.base_identity = self.bundle.base_identity.clone();
            storage::atomic_json(&location.disk_directory.join("config.json"), &vm).unwrap();
            publish(&self.options, &location).unwrap();
            (vm, location)
        }
        fn save_run(&self, vm: &VmConfig, directory: &std::path::Path, id: &str, boot: &str) {
            let directory = directory.join("runs").join(id);
            storage::private_dir(&directory).unwrap();
            let run = RunSummary {
                id: id.into(),
                vm_id: vm.id.clone(),
                boot_id: boot.into(),
                session_id: 1,
                root_task_cookie: 1,
                pid: 2,
                request: ExecRequest::default(),
                directory: directory.clone(),
                terminal_eof: true,
                state: RunState::Finalized,
                recording_error: None,
                execution: None,
            };
            storage::atomic_json(&directory.join("run.json"), &run).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn launch_settings_survive_create_save_backend_restart_and_duplicate() {
        use crate::{DisplayResolution, Notification, VmAcceleration, VmCpuModel, VmLaunchOptions};

        fn command(backend: &crate::Backend, command: crate::Command) {
            let id = backend.send(command).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if let Some(Notification::CommandResult {
                    id: result,
                    success,
                    message,
                }) = backend.try_recv()
                    && result == id
                {
                    assert!(success, "{message}");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            panic!("VM command timed out");
        }

        let fixture = Fixture::new();
        let mut backend = crate::Backend::new(fixture.options.clone()).unwrap();
        let mut vm = VmConfig {
            id: "launch-source".into(),
            launch: VmLaunchOptions {
                resolution: DisplayResolution::R1280x720,
                fullscreen: true,
                fit_to_window: true,
                acceleration: VmAcceleration::Tcg,
                cpu_model: VmCpuModel::Max,
            },
            ..VmConfig::default()
        };
        command(&backend, crate::Command::Create(vm.clone()));
        vm = storage::load_vms(&fixture.options).unwrap().remove(0);
        assert_eq!(vm.launch.resolution, DisplayResolution::R1280x720);
        assert!(vm.launch.fullscreen && vm.launch.fit_to_window);
        vm.launch.resolution = DisplayResolution::R1920x1080;
        vm.launch.cpu_model = VmCpuModel::Qemu64;
        command(&backend, crate::Command::Save(vm.clone()));
        backend.shutdown().unwrap();

        let mut restarted = crate::Backend::new(fixture.options.clone()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut loaded = false;
        while std::time::Instant::now() < deadline {
            if let Some(Notification::Snapshot(snapshot)) = restarted.try_recv() {
                assert_eq!(snapshot.vms[0].launch, vm.launch);
                loaded = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(loaded, "restart snapshot timed out");
        command(
            &restarted,
            crate::Command::Duplicate {
                vm_id: vm.id.clone(),
                name: "Launch copy".into(),
            },
        );
        let copies = storage::load_vms(&fixture.options).unwrap();
        assert_eq!(copies.len(), 2);
        assert!(copies.iter().all(|copy| copy.launch == vm.launch));
        restarted.shutdown().unwrap();
    }

    #[test]
    fn registry_post_rename_failure_retains_duplicate_and_coherent_settings() {
        let fixture = Fixture::new();
        let (vm, location) = fixture.create(VmConfig {
            id: "sync-failure-source".into(),
            ..VmConfig::default()
        });
        let registry_path = fixture.options.data_dir.join("vm-locations.json");
        storage::fail_next_directory_sync(&registry_path);
        let error =
            storage::duplicate_vm(&fixture.options, &vm, "Sync duplicate".into()).unwrap_err();
        assert!(error.contains("data retained"));
        let loaded = storage::load_vms(&fixture.options).unwrap();
        assert_eq!(loaded.len(), 2);
        for saved in &loaded {
            assert!(
                storage::vm_dir(&fixture.options, &saved.id)
                    .unwrap()
                    .join("disk.qcow2")
                    .is_file()
            );
        }
        let parent = fixture.root.join("new recordings");
        fs::create_dir(&parent).unwrap();
        let mut next = vm.clone();
        next.recording_root = Some(parent);
        let future = future_recordings(&fixture.options, &vm, &mut next).unwrap();
        storage::fail_next_directory_sync(&registry_path);
        let error = storage::save_vm_config(
            &fixture.options,
            &location.disk_directory,
            &vm,
            &next,
            &future,
        )
        .unwrap_err();
        assert!(error.published);
        assert_eq!(
            locations(&fixture.options, &vm.id)
                .unwrap()
                .recording_directory,
            future.recording_directory
        );
        let saved: VmConfig =
            storage::read_json(&location.disk_directory.join("config.json")).unwrap();
        assert_eq!(saved.recording_root, next.recording_root);
    }

    #[test]
    fn rollback_rename_restoration_does_not_report_new_settings_as_published() {
        let fixture = Fixture::new();
        let (previous, location) = fixture.create(VmConfig {
            id: "rollback-sync-failure".into(),
            ..VmConfig::default()
        });
        let root = fixture.root.join("future recordings");
        fs::create_dir(&root).unwrap();
        let mut next = previous.clone();
        next.recording_root = Some(root);
        let future = future_recordings(&fixture.options, &previous, &mut next).unwrap();
        storage::fail_next_json_rename(&fixture.options.data_dir.join("vm-locations.json"));
        let config = location.disk_directory.join("config.json");
        storage::fail_directory_sync_after(&config, 1);
        let error = storage::save_vm_config(
            &fixture.options,
            &location.disk_directory,
            &previous,
            &next,
            &future,
        )
        .unwrap_err();
        assert!(!error.published);
        assert!(error.to_string().contains("rollback failed"));
        assert_eq!(
            storage::read_json::<VmConfig>(&config)
                .unwrap()
                .recording_root,
            previous.recording_root
        );
        assert_eq!(
            locations(&fixture.options, &previous.id)
                .unwrap()
                .recording_directory,
            location.recording_directory
        );
    }

    #[test]
    fn post_rename_error_distinguishes_visible_changes_from_prepublication_failure() {
        let fixture = Fixture::new();
        let path = fixture.options.data_dir.join("example.json");
        storage::fail_next_directory_sync(&path);
        let error = storage::atomic_json_checked(&path, &vec![1, 2]).unwrap_err();
        assert!(error.published);
        assert_eq!(storage::read_json::<Vec<u8>>(&path).unwrap(), vec![1, 2]);
        let error = storage::atomic_json_checked(&fixture.root.join("missing/file.json"), &vec![3])
            .unwrap_err();
        assert!(!error.published);
    }

    #[test]
    fn published_delete_retains_recovery_files_and_recordings_without_dangling_vm() {
        let fixture = Fixture::new();
        let (vm, location) = fixture.create(VmConfig {
            id: "delete-sync-failure".into(),
            ..VmConfig::default()
        });
        fixture.save_run(&vm, &location.recording_directory, "retained", "prior-boot");
        storage::fail_directory_sync_after(&fixture.options.data_dir.join("vm-locations.json"), 1);
        let error = storage::delete_vm(&fixture.options, &vm.id).unwrap_err();
        assert!(error.contains("deleted VM files retained"));
        assert!(storage::load_vms(&fixture.options).unwrap().is_empty());
        let staging = fs::read_dir(&location.disk_directory)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().starts_with("delete-"))
            .unwrap()
            .path();
        assert!(staging.join("disk.qcow2").is_file());
        assert!(staging.join("config.json").is_file());
        assert_eq!(
            crate::recording::list_vm_runs(&fixture.options, &vm.id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn custom_parents_reopen_preserve_modes_and_all_prior_boots() {
        let fixture = Fixture::new();
        let disk_parent = fixture.root.join("disks ' unusual, name");
        let first_parent = fixture.root.join("recordings $ unusual");
        let next_parent = fixture.root.join("future recordings");
        for path in [&disk_parent, &first_parent, &next_parent] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o750)).unwrap();
        }
        let (vm, location) = fixture.create(VmConfig {
            id: "custom-id".into(),
            disk_root: Some(disk_parent.clone()),
            recording_root: Some(first_parent.clone()),
            ..VmConfig::default()
        });
        assert_eq!(
            storage::vm_dir(&fixture.options, &vm.id).unwrap(),
            disk_parent.join(&vm.id)
        );
        assert_eq!(storage::load_vms(&fixture.options).unwrap()[0].id, vm.id);
        fixture.save_run(&vm, &location.recording_directory, "run-before", "boot-one");
        let mut next = vm.clone();
        next.recording_root = Some(next_parent.clone());
        let next_location = future_recordings(&fixture.options, &vm, &mut next).unwrap();
        publish(&fixture.options, &next_location).unwrap();
        storage::atomic_json(&location.disk_directory.join("config.json"), &next).unwrap();
        fixture.save_run(
            &vm,
            &next_location.recording_directory,
            "run-after",
            "boot-two",
        );
        let history = crate::recording::list_vm_runs(&fixture.options, &vm.id).unwrap();
        assert_eq!(history.len(), 2);
        assert_ne!(history[0].boot_id, history[1].boot_id);
        assert!(
            location
                .recording_directory
                .join("runs/run-before/run.json")
                .exists()
        );
        next.disk_root = Some(next_parent.clone());
        assert!(
            future_recordings(&fixture.options, &vm, &mut next)
                .unwrap_err()
                .contains("relocation")
        );
        for path in [&disk_parent, &first_parent, &next_parent] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }
    }

    #[test]
    fn defaults_rename_duplicate_and_delete_preserve_identity_and_recordings() {
        let fixture = Fixture::new();
        let (mut vm, location) = fixture.create(VmConfig {
            id: "default-id".into(),
            ..VmConfig::default()
        });
        assert_eq!(
            location.disk_directory,
            fixture.options.data_dir.join(&vm.id)
        );
        assert_eq!(location.disk_directory, location.recording_directory);
        fixture.save_run(&vm, &location.recording_directory, "old-run", "old-boot");
        vm.name = "Renamed VM".into();
        storage::atomic_json(&location.disk_directory.join("config.json"), &vm).unwrap();
        assert_eq!(
            storage::load_vms(&fixture.options).unwrap()[0].id,
            "default-id"
        );
        let source = location.disk_directory.join("disk.qcow2");
        assert!(
            Command::new("qemu-io")
                .args(["-f", "qcow2", "-c", "write -P 0x41 0 4096"])
                .arg(&source)
                .output()
                .unwrap()
                .status
                .success()
        );
        let duplicate =
            storage::duplicate_vm(&fixture.options, &vm, "Duplicate VM".into()).unwrap();
        assert_ne!(duplicate.id, vm.id);
        let duplicate_dir = storage::vm_dir(&fixture.options, &duplicate.id).unwrap();
        let copied = duplicate_dir.join("disk.qcow2");
        assert!(
            Command::new("qemu-img")
                .arg("compare")
                .arg(&source)
                .arg(&copied)
                .output()
                .unwrap()
                .status
                .success()
        );
        let info = Command::new("qemu-img")
            .args(["info", "--output=json"])
            .arg(&copied)
            .output()
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
        assert!(info.get("backing-filename").is_none());
        assert!(
            crate::recording::list_vm_runs(&fixture.options, &duplicate.id)
                .unwrap()
                .is_empty()
        );
        assert!(
            Command::new("qemu-io")
                .args(["-f", "qcow2", "-c", "write -P 0x42 0 4096"])
                .arg(&source)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            !Command::new("qemu-img")
                .arg("compare")
                .arg(&source)
                .arg(&copied)
                .output()
                .unwrap()
                .status
                .success()
        );
        fs::write(location.disk_directory.join("keep-user-file"), b"keep").unwrap();
        storage::delete_vm(&fixture.options, &vm.id).unwrap();
        assert!(location.disk_directory.join("keep-user-file").exists());
        assert!(!source.exists());
        assert_eq!(
            crate::recording::list_vm_runs(&fixture.options, &vm.id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(storage::load_vms(&fixture.options).unwrap().len(), 1);
    }

    #[test]
    fn installed_catalog_and_creation_do_not_need_build_inputs_and_failed_copy_rolls_back() {
        let fixture = Fixture::new();
        assert!(!fixture.options.bundle_dir.exists());
        let bases = installed_bases(&fixture.options).unwrap();
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].label, "Linux 6.12.94");
        boot_bundle(&fixture.options, Some(&bases[0].id))
            .unwrap()
            .verify_installed()
            .unwrap();
        assert!(boot_bundle(&fixture.options, Some("missing-id")).is_err());
        let (vm, _) = fixture.create(VmConfig {
            id: "copy-source".into(),
            ..VmConfig::default()
        });
        let failing_img = fixture.root.join("qemu-img-failing-convert");
        fs::write(
            &failing_img,
            b"#!/bin/sh\nif [ \"$1\" = info ]; then exec qemu-img \"$@\"; fi\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&failing_img, fs::Permissions::from_mode(0o700)).unwrap();
        let options = BackendOptions {
            qemu_img: failing_img,
            ..fixture.options.clone()
        };
        assert!(storage::duplicate_vm(&options, &vm, "Failed duplicate".into()).is_err());
        assert_eq!(storage::load_vms(&fixture.options).unwrap().len(), 1);
        assert_eq!(fs::read_dir(&fixture.options.data_dir).unwrap().count(), 3);
        let mut backend = crate::Backend::new(fixture.options.clone()).unwrap();
        let id = backend
            .send(crate::Command::Create(VmConfig::default()))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut success = false;
        while std::time::Instant::now() < deadline {
            if let Some(crate::Notification::CommandResult {
                id: result,
                success: ok,
                message,
            }) = backend.try_recv()
                && result == id
            {
                assert!(ok, "{message}");
                success = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(success, "creation did not complete from installed base");
        backend.shutdown().unwrap();
    }

    #[test]
    fn invalid_parent_overlap_and_existing_paths_are_rejected() {
        let fixture = Fixture::new();
        let (vm, location) = fixture.create(VmConfig {
            id: "owned-vm".into(),
            ..VmConfig::default()
        });
        let mut next = VmConfig {
            id: "new-vm".into(),
            disk_root: Some(location.disk_directory.clone()),
            ..VmConfig::default()
        };
        assert!(
            prepare(&fixture.options, &mut next)
                .unwrap_err()
                .contains("overlaps")
        );
        next.disk_root = Some(fixture.options.data_dir.join("bases"));
        assert!(
            prepare(&fixture.options, &mut next)
                .unwrap_err()
                .contains("overlaps")
        );
        next.disk_root = Some(fixture.root.join("missing"));
        assert!(prepare(&fixture.options, &mut next).is_err());
        let unwritable = fixture.root.join("readonly-parent");
        fs::create_dir(&unwritable).unwrap();
        fs::set_permissions(&unwritable, fs::Permissions::from_mode(0o500)).unwrap();
        next.disk_root = Some(unwritable.clone());
        assert!(
            prepare(&fixture.options, &mut next)
                .unwrap_err()
                .contains("not writable")
        );
        fs::set_permissions(&unwritable, fs::Permissions::from_mode(0o700)).unwrap();
        next.disk_root = None;
        next.id = vm.id;
        assert!(prepare(&fixture.options, &mut next).is_err());
    }
}
