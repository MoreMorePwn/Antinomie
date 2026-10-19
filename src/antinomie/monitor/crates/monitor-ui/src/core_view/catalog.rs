// SPDX-License-Identifier: MIT
//! The catalog of process cores on disk and its background refresh.
use super::*;

impl CoreView {
    pub(super) fn start_catalog(&mut self) {
        if self.catalog_job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let generation = self.catalog_generation;
        let roots = self.roots.clone();
        let vm_id = self.vm_id.clone();
        let selected = self.selected.as_ref().map(|record| SelectedCoreProbe {
            directory: record.dir.clone(),
            source: record.core.source.clone(),
            source_size: record.core.source_size,
            stamp: self.selected_stamp,
        });
        self.catalog_checked = Some(Instant::now());
        if std::thread::Builder::new()
            .name("core-catalog".into())
            .spawn(move || {
                let catalog = catalog(&roots, vm_id.as_deref());
                let stamp = catalog.as_ref().ok().and_then(catalog_stamp);
                let selected = selected.map(selected_core_refresh);
                let _ = sender.send(CatalogReply {
                    generation,
                    roots,
                    vm_id,
                    catalog,
                    stamp,
                    selected,
                });
            })
            .is_err()
        {
            self.fail("Could not refresh the core list".into());
            return;
        }
        self.catalog_job = Some(receiver);
    }

    pub(super) fn poll_catalog(&mut self) {
        let Some(receiver) = self.catalog_job.as_ref() else {
            return;
        };
        let reply = match receiver.try_recv() {
            Ok(reply) => reply,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.catalog_job = None;
                return;
            }
        };
        self.catalog_job = None;
        if reply.generation != self.catalog_generation
            || reply.roots != self.roots
            || reply.vm_id != self.vm_id
        {
            return;
        }
        self.catalog_checked = Some(Instant::now());
        match reply.catalog {
            Ok(catalog) => {
                if reply.stamp.is_none()
                    || self.catalog_stamp != reply.stamp
                    || self.catalog_issues != catalog.issues
                {
                    self.apply_catalog(catalog);
                    self.catalog_stamp = reply.stamp;
                }
            }
            Err(error) => self.fail(error),
        }
        if let Some(refresh) = reply.selected {
            self.apply_selected_refresh(refresh);
        }
    }

    fn apply_selected_refresh(&mut self, refresh: SelectedCoreRefresh) {
        let Some(record) = self.selected.as_mut() else {
            return;
        };
        if record.dir != refresh.directory
            || record.core.source != refresh.source
            || self.selected_stamp != refresh.previous_stamp
        {
            return;
        }
        match refresh.core {
            Ok(Some(core)) => {
                let tid = record
                    .core
                    .threads
                    .get(self.thread_index)
                    .map(|thread| thread.tid);
                let mapping = record.core.mappings.get(self.mapping_index).map(|mapping| {
                    (
                        mapping.start,
                        mapping.file_offset,
                        mapping.memory_size,
                        mapping.flags,
                    )
                });
                self.thread_index = tid
                    .and_then(|tid| core.threads.iter().position(|thread| thread.tid == tid))
                    .unwrap_or(0);
                self.mapping_index = mapping
                    .and_then(|identity| {
                        core.mappings.iter().position(|mapping| {
                            (
                                mapping.start,
                                mapping.file_offset,
                                mapping.memory_size,
                                mapping.flags,
                            ) == identity
                        })
                    })
                    .unwrap_or(0);
                if let Some(mapping) = core.mappings.get(self.mapping_index) {
                    self.window_offset = self
                        .window_offset
                        .min(mapping.memory_size.saturating_sub(1) / 16 * 16);
                }
                record.core = core;
                self.selected_stamp = refresh.stamp;
                self.page = None;
            }
            Ok(None) => self.selected_stamp = refresh.stamp,
            Err(error) => self.fail(format!("Core metadata refresh: {error}")),
        }
    }

    /// A deleted core leaves the list, the viewer and Details at once; the
    /// next catalog read confirms it.
    pub(crate) fn forget_core(&mut self, directory: &Path) {
        self.manual.retain(|core| core.directory != directory);
        self.acquired.retain(|core| core.directory != directory);
        self.records.retain(|record| record.dir != directory);
        if self.selected_directory.as_deref() == Some(directory)
            || self
                .selected
                .as_ref()
                .is_some_and(|record| record.dir == directory)
        {
            self.selected = None;
            self.selected_directory = None;
            self.selected_stamp = None;
            self.page = None;
        }
        self.invalidate_catalog();
    }

    pub(super) fn invalidate_catalog(&mut self) {
        self.catalog_generation = self.catalog_generation.wrapping_add(1);
        self.catalog_checked = None;
    }

    pub(super) fn set_catalog_scope(&mut self, roots: &[PathBuf], vm_id: Option<&str>) {
        if self.roots == roots && self.vm_id.as_deref() == vm_id {
            return;
        }
        let changed_vm = self.scope_initialized && self.vm_id.as_deref() != vm_id;
        if self.scope_initialized {
            self.scope_generation = self.scope_generation.wrapping_add(1);
        }
        self.scope_initialized = true;
        self.invalidate_catalog();
        self.catalog_stamp = None;
        self.acquired.clear();
        self.manual.clear();
        self.records.clear();
        self.catalog_issues.clear();
        self.import_open = false;
        if changed_vm
            || self
                .selected_directory
                .as_ref()
                .is_some_and(|directory| !roots.iter().any(|root| directory.starts_with(root)))
        {
            self.selected = None;
            self.selected_directory = None;
            self.selected_stamp = None;
        }
        self.roots = roots.to_vec();
        self.vm_id = vm_id.map(str::to_owned);
        if self.destination >= self.roots.len() {
            self.destination = 0;
        }
    }

    pub(super) fn catalog_interval(&self, active: bool) -> Option<Duration> {
        let unfinished = self
            .manual
            .iter()
            .any(|capture| capture.phase != ProcessCorePhase::Finished)
            || self.acquired.iter().any(|capture| {
                matches!(
                    capture.state,
                    antinomie_monitor_core::RunArtifactState::Queued
                        | antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                        | antinomie_monitor_core::RunArtifactState::InProgress
                )
            });
        if unfinished {
            Some(Duration::from_secs(1))
        } else if active {
            Some(Duration::from_secs(5))
        } else {
            None
        }
    }

    pub(super) fn refresh_catalog_if_due(
        &mut self,
        active: bool,
        now: Instant,
    ) -> Option<Duration> {
        let interval = self.catalog_interval(active);
        let due = self.catalog_checked.is_none()
            || interval.is_some_and(|interval| {
                self.catalog_checked
                    .is_some_and(|checked| now.saturating_duration_since(checked) >= interval)
            });
        if due && self.catalog_job.is_none() {
            self.start_catalog();
        }
        if self.catalog_job.is_some() {
            return Some(Duration::from_millis(200));
        }
        interval.map(|interval| {
            interval.saturating_sub(self.catalog_checked.map_or(Duration::ZERO, |checked| {
                now.saturating_duration_since(checked)
            }))
        })
    }

    /// Disk catalog is authoritative inside the recording roots it scanned.
    /// An unfinished capture with no file yet, and any record outside those
    /// roots, stays until a later scan actually covers it.
    fn apply_catalog(&mut self, catalog: CoreCatalog) {
        let covered = |directory: &Path| self.roots.iter().any(|root| directory.starts_with(root));
        let pending_acquired: Vec<_> = self
            .acquired
            .iter()
            .filter(|core| {
                !covered(&core.directory)
                    || (core.file.is_none()
                        && !catalog
                            .acquired
                            .iter()
                            .any(|found| found.directory == core.directory))
            })
            .cloned()
            .collect();
        let pending_manual: Vec<_> = self
            .manual
            .iter()
            .filter(|core| {
                !covered(&core.directory)
                    || (core.file.is_none()
                        && !catalog
                            .manual
                            .iter()
                            .any(|found| found.directory == core.directory))
            })
            .cloned()
            .collect();
        let kept_records: Vec<_> = self
            .records
            .iter()
            .filter(|record| !covered(&record.dir))
            .cloned()
            .collect();
        self.records = catalog.imported;
        self.records.extend(kept_records);
        self.acquired = catalog.acquired;
        self.acquired.extend(pending_acquired);
        self.manual = catalog.manual;
        self.manual.extend(pending_manual);
        self.catalog_issues = catalog.issues;
        self.catalog_checked = Some(Instant::now());
    }
}

/// Called only by inspection/catalog workers, never by the rendering path.
pub(super) fn core_file_stamp(path: &Path) -> Option<CoreFileStamp> {
    let metadata = fs::metadata(path).ok()?;
    metadata.is_file().then(|| CoreFileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

pub(super) fn opened_reply(record: CoreRecord, code: String) -> Reply {
    let stamp = core_file_stamp(&record.core.source)
        .filter(|stamp| stamp.file_size == record.core.source_size);
    Reply::Open(Box::new(record), code, stamp)
}

pub(super) fn catalog_stamp(catalog: &CoreCatalog) -> Option<CatalogStamp> {
    // Hash the bounded decoded metadata, not a later filesystem timestamp:
    // a sidecar can be sealed while a catalog worker is reading its old value.
    struct MetadataHash(std::collections::hash_map::DefaultHasher);
    impl Write for MetadataHash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hash = MetadataHash(std::collections::hash_map::DefaultHasher::new());
    serde_json::to_writer(&mut hash, catalog).ok()?;
    Some(hash.0.finish())
}

pub(super) fn selected_core_refresh(probe: SelectedCoreProbe) -> SelectedCoreRefresh {
    let stamp = core_file_stamp(&probe.source);
    let core = if stamp == probe.stamp
        && stamp.is_some_and(|stamp| stamp.file_size == probe.source_size)
    {
        Ok(None)
    } else if probe.stamp.is_none()
        && stamp.is_some_and(|stamp| stamp.file_size == probe.source_size)
    {
        // A restored view may have no stamp yet. Establish its baseline without
        // inspecting unchanged bytes; ordinary opens carry their worker stamp.
        Ok(None)
    } else {
        CoreDump::open(&probe.source)
            .map(Some)
            .map_err(|error| error.to_string())
    };
    SelectedCoreRefresh {
        directory: probe.directory,
        source: probe.source,
        previous_stamp: probe.stamp,
        stamp: stamp.filter(|stamp| {
            core.as_ref()
                .ok()
                .and_then(|core| core.as_ref())
                .is_none_or(|core| core.source_size == stamp.file_size)
        }),
        core,
    }
}

pub(super) fn manual_status(core: &ProcessCoreCapture) -> String {
    match core.phase {
        ProcessCorePhase::Admission => "Requesting capture".into(),
        ProcessCorePhase::UnknownAdmission => "Admission outcome unknown; checking status".into(),
        ProcessCorePhase::GuestCapture => {
            "Capturing process; waiting for resume confirmation".into()
        }
        ProcessCorePhase::Transfer => core.guest_size.map_or_else(
            || format!("Saving {} octets", core.stored_size),
            |size| format!("Saving {} / {size} octets", core.stored_size),
        ),
        ProcessCorePhase::Seal => "Finalizing retained core".into(),
        ProcessCorePhase::Finished => crate::app::core_capture_status(core.state).into(),
    }
}

/// Read bounded sidecars on the inspection worker; ELF data is read only on open.
pub(super) fn catalog(roots: &[PathBuf], vm_id: Option<&str>) -> Result<CoreCatalog, String> {
    let mut result = CoreCatalog::default();
    match core_dump::list_records(roots) {
        Ok(records) => result.imported = records,
        Err(error) => result.issues.push(error.to_string()),
    }
    let Some(vm_id) = vm_id else {
        return Ok(result);
    };
    match antinomie_monitor_core::core_capture::list_with_issues(roots, Some(vm_id)) {
        Ok(catalog) => {
            result.manual = catalog.records;
            result.issues.extend(catalog.issues);
        }
        Err(error) => result.issues.push(format!("Manual core catalog: {error}")),
    }
    let mut entries_count = 0usize;
    let mut metadata_size = 0u64;
    for root in roots {
        let entries = match fs::read_dir(root.join("runs")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Core run catalog: {error}")),
        };
        for entry in entries {
            entries_count += 1;
            if entries_count > 4096 {
                return Err(
                    "Core run catalog exceeds 4096 entries; select fewer recording folders".into(),
                );
            }
            let entry = entry.map_err(|error| error.to_string())?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                continue;
            }
            let path = entry.path();
            let sidecar = path.join("artifacts.json");
            let size = match fs::symlink_metadata(&sidecar) {
                Ok(metadata) if metadata.is_file() => metadata.len(),
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            metadata_size = metadata_size.saturating_add(size);
            if metadata_size > 32 * 1024 * 1024 {
                return Err("Core run metadata exceeds 32 MiB".into());
            }
            let artifacts = match antinomie_monitor_core::RunArtifacts::load(&path) {
                Ok(Some(artifacts)) => artifacts,
                Ok(None) => continue,
                Err(error) => {
                    if result.issues.len() < 16 {
                        result.issues.push(format!("{}: {error}", path.display()));
                    }
                    continue;
                }
            };
            if artifacts.vm_id != vm_id
                || matches!(
                    artifacts.core_state,
                    antinomie_monitor_core::RunArtifactState::Disabled
                        | antinomie_monitor_core::RunArtifactState::Deleted
                )
            {
                continue;
            }
            for issue in &artifacts.issues {
                if result.issues.len() >= 16 {
                    break;
                }
                let mut issue_text: String = issue.chars().take(2048).collect();
                if issue.chars().count() > 2048 {
                    issue_text.push('…');
                }
                result
                    .issues
                    .push(format!("Run {}: {issue_text}", artifacts.run_id));
            }
            if result
                .acquired
                .iter()
                .any(|core| core.run_id == artifacts.run_id)
            {
                continue;
            }
            result.acquired.push(AcquiredCore {
                vm_id: artifacts.vm_id,
                boot_id: artifacts.boot_id,
                run_id: artifacts.run_id,
                directory: path.join("core"),
                file: artifacts.core_dump,
                state: artifacts.core_state,
            });
            if result.acquired.len() > 1024 {
                return Err("Core catalog exceeds 1024 runs".into());
            }
        }
    }
    result
        .acquired
        .sort_by(|left, right| right.run_id.cmp(&left.run_id));
    Ok(result)
}

pub(super) fn acquired_record(source: &Path) -> Result<CoreRecord, String> {
    let core = CoreDump::open(source).map_err(|error| error.to_string())?;
    let directory = core
        .source
        .parent()
        .ok_or("Core file has no result directory")?
        .to_owned();
    const METADATA_LIMIT: u64 = 16 * 1024 * 1024;
    let record = match fs::File::open(directory.join("metadata.json")) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() || metadata.len() > METADATA_LIMIT {
                return Err("Core metadata must be a regular file of at most 16 MiB".into());
            }
            let mut saved: CoreRecord = serde_json::from_reader(file.take(METADATA_LIMIT + 1))
                .map_err(|error| format!("Core metadata: {error}"))?;
            if saved.core.source != core.source {
                return Err("Core metadata source identity does not match this run core".into());
            }
            saved.dir = directory;
            saved.core = core;
            saved
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CoreRecord {
            label: source
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            tags: String::new(),
            dir: directory,
            core,
        },
        Err(error) => return Err(format!("Core metadata: {error}")),
    };
    record.save().map_err(|error| error.to_string())?;
    Ok(record)
}
