// SPDX-License-Identifier: GPL-3.0-only
//! Commands from the frontend that do not need a running guest.
use super::*;

impl Worker {
    fn ensure_stopped(&self, id: &str) -> Result<(), String> {
        if self.snapshot.active_vm.as_deref() == Some(id) {
            Err("stop the VM before modifying its disk or configuration".into())
        } else {
            Ok(())
        }
    }
    pub(super) fn command_at_epoch(
        &mut self,
        epoch: u64,
        command: Command,
    ) -> Result<String, String> {
        if guest_scoped_command(&command) && epoch != self.guest_epoch.load(Ordering::Acquire) {
            return Err("command cancelled at snapshot/reconnect boundary; submit it explicitly in the current timeline".into());
        }
        self.command(command)
    }
    pub(super) fn begin_guest_transition(&self) -> Result<GuestTransition, String> {
        self.guest_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(2).map(|_| value + 1)
            })
            .map_err(|_| "guest command epoch exhausted")?;
        Ok(GuestTransition(self.guest_epoch.clone()))
    }
    /// Run one command behind the disk-job lease: refused while a disk job
    /// reads the VM's chain, and a view of a chain the command changed is
    /// closed once it succeeded.
    pub(super) fn command(&mut self, command: Command) -> Result<String, String> {
        self.disk_lease_gate(&command)?;
        let after = super::worker_disks::effect(&command)
            .is_some()
            .then(|| command.clone());
        let result = self.run_command(command);
        if result.is_ok()
            && let Some(command) = after
        {
            self.close_disk_view_after(&command);
        }
        result
    }
    fn run_command(&mut self, command: Command) -> Result<String, String> {
        if matches!(
            command,
            Command::Stop
                | Command::DumpMemory
                | Command::CreateVmSnapshot { .. }
                | Command::RestoreVmSnapshot { .. }
                | Command::ReconnectTransport
        ) && let Some(job) = self.keyboard.take()
        {
            let result = job.cancel_and_join();
            self.emit(Notification::CommandResult {
                id: 0,
                success: result.is_ok(),
                message: result.unwrap_or_else(|error| error),
            });
        }
        // QEMU keeps the guest paused while it writes a memory dump: a guest
        // command would only time out.
        if self.snapshot.memory_dump.is_some() && command.needs_running_guest() {
            return Err(
                "the VM is paused while its memory is written; try again in a moment".into(),
            );
        }
        match command {
            Command::TypeClipboard {
                vm_id,
                boot_id,
                text,
            } => {
                if self.keyboard.is_some() {
                    return Err("Clipboard typing is already active".into());
                }
                if self.snapshot.state != VmState::Running
                    || self.snapshot.active_vm.as_ref() != Some(&vm_id)
                    || self.snapshot.boot_id.as_ref() != Some(&boot_id)
                {
                    return Err("Clipboard target VM or boot changed; request it again".into());
                }
                let text = crate::clipboard::Text::prepare(&text)?;
                if text.skipped_count != 0 {
                    return Err("Clipboard contains unsupported keyboard characters".into());
                }
                let session = self.session.as_ref().ok_or("no running VM")?;
                self.keyboard = Some(crate::vm::keyboard::Job::start(
                    session.process.qmp_path.clone(),
                    boot_id,
                    text,
                    self.guest_epoch.clone(),
                    self.stopping.clone(),
                )?);
                Ok("Clipboard typing started (US layout)".into())
            }
            Command::RefreshVmSnapshots { vm_id } => {
                self.refresh_vm_snapshots(&vm_id)?;
                Ok("Snapshots refreshed".into())
            }
            Command::CreateVmSnapshot { vm_id, request } => {
                self.create_vm_snapshot(&vm_id, request)
            }
            Command::RestoreVmSnapshot {
                vm_id,
                snapshot_id,
                boot_from_disk,
                save_current,
                confirmed,
            } => {
                if !confirmed {
                    return Err("restore requires confirmation".into());
                }
                self.restore_vm_snapshot(&vm_id, &snapshot_id, boot_from_disk, save_current)
            }
            Command::RenameVmSnapshot {
                vm_id,
                snapshot_id,
                name,
            } => {
                let vm = self.snapshot_vm(&vm_id)?;
                crate::snapshots::rename(&self.options, &vm, &snapshot_id, &name)?;
                self.refresh_vm_snapshots(&vm_id)?;
                Ok("Snapshot renamed".into())
            }
            Command::DeleteVmSnapshot {
                vm_id,
                snapshot_id,
                confirmed,
            } => {
                if !confirmed {
                    return Err("snapshot deletion requires confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                let vm = self.snapshot_vm(&vm_id)?;
                crate::snapshots::logical_delete(&self.options, &vm, &snapshot_id)?;
                self.refresh_vm_snapshots(&vm_id)?;
                Ok("Snapshot hidden; dependent disk layers retained".into())
            }
            Command::ReconnectTransport => self.reconnect_transport(),
            Command::Create(vm) => self.create(vm, None),
            Command::CreateWithCredentials { vm, credentials } => {
                self.create(vm, Some(credentials))
            }
            Command::ImportBase { directory } => {
                if self.session.is_some() || self.snapshot.active_vm.is_some() {
                    return Err("stop VM before importing a base".into());
                }
                let bundle = Bundle::load(&directory)?;
                if !bundle.kernel_version.starts_with("6.12.94") {
                    return Err("boot bundle must use Linux 6.12.94".into());
                }
                require_supported(bundle.antinomie_revision, bundle.min_app_version.as_deref())?;
                storage::validate_disk_chain(&self.options, &bundle.base_disk, None)?;
                bundle.install(&self.options)?;
                self.refresh_locations()?;
                Ok("base imported".into())
            }
            Command::RefreshRemoteBases => {
                if self.refresh.is_some() {
                    return Err("base catalog refresh already in progress".into());
                }
                distribution::curl_version(&self.options.curl)?;
                let curl = self.options.curl.clone();
                let remote = self.options.remote_base.clone();
                let (sender, receiver) = mpsc::channel();
                thread::Builder::new()
                    .name("antinomie-catalog".into())
                    .spawn(move || {
                        let _ = sender.send(distribution::fetch_catalog(&curl, &remote));
                    })
                    .map_err(|e| e.to_string())?;
                self.refresh = Some(receiver);
                self.snapshot.remote_refreshing = true;
                self.snapshot.remote_error = None;
                Ok("refreshing base catalog".into())
            }
            Command::DownloadBase { identity } => {
                if self.download.is_some() {
                    return Err("a base download is already in progress".into());
                }
                distribution::curl_version(&self.options.curl)?;
                let base = self
                    .catalog
                    .bases
                    .iter()
                    .find(|base| base.identity == identity)
                    .cloned()
                    .ok_or("unknown base; refresh the catalog first")?;
                require_supported(base.antinomie_revision, base.min_app_version.as_deref())?;
                if self
                    .snapshot
                    .bases
                    .iter()
                    .any(|installed| installed.id == identity)
                {
                    return Err("base is already installed".into());
                }
                let staging = self.options.data_dir.join("downloads").join(&base.identity);
                fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
                let options = self.options.clone();
                let curl = self.options.curl.clone();
                let remote = self.options.remote_base.clone();
                let total: u64 = base.files.iter().map(|file| file.size).sum();
                let label = match base_app_version(
                    base.antinomie_revision,
                    base.min_app_version.as_deref(),
                ) {
                    Some(version) => format!("{} · Antinomie {version}", base.label),
                    None => base.label.clone(),
                };
                let progress = Arc::new(Mutex::new((0u64, false)));
                let worker_progress = progress.clone();
                let (sender, receiver) = mpsc::channel();
                let requested = base.clone();
                let staging_thread = staging.clone();
                let cancel = Arc::new(AtomicBool::new(false));
                let worker_cancel = cancel.clone();
                let thread = thread::Builder::new()
                    .name("antinomie-download".into())
                    .spawn(move || {
                        let cancel = worker_cancel;
                        let result = distribution::download_base(
                            &curl,
                            &remote,
                            &requested,
                            &staging_thread,
                            &cancel,
                            |received, _| {
                                if let Ok(mut guard) = worker_progress.lock() {
                                    guard.0 = received;
                                }
                            },
                        )
                        .and_then(|bundle| {
                            if cancel.load(Ordering::Relaxed) {
                                return Err("download cancelled".into());
                            }
                            require_supported(
                                bundle.antinomie_revision,
                                bundle.min_app_version.as_deref(),
                            )?;
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            begin_base_install(&worker_progress, &cancel)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let ok = result.is_ok();
                        let _ = sender.send(result);
                        if ok {
                            let _ = fs::remove_dir_all(&staging_thread);
                        }
                    })
                    .map_err(|e| e.to_string())?;
                self.download = Some(DownloadJob {
                    identity: base.identity.clone(),
                    label: label.clone(),
                    total,
                    progress,
                    cancel,
                    done: receiver,
                    thread,
                });
                self.snapshot.download = Some(DownloadStatus {
                    identity: base.identity,
                    label,
                    received: 0,
                    total,
                    installing: false,
                    finished: false,
                    error: None,
                });
                Ok("base download started".into())
            }
            Command::CancelDownload => {
                let job = self
                    .download
                    .as_ref()
                    .ok_or("no base download is running")?;
                let progress = job
                    .progress
                    .lock()
                    .map_err(|_| "download progress lock poisoned")?;
                if progress.1 {
                    return Err("base download finished; installation is in progress".into());
                }
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling the base download".into())
            }
            Command::BuildBase { request } => {
                if self.build.is_some() {
                    return Err("a base build is already in progress".into());
                }
                let spec = build::profile(&request.profile).ok_or("unknown build profile")?;
                request.options.validate(spec.kind)?;
                let mode = build::resolve_mode(spec.kind, request.mode)?;
                let label = match request.options.name.trim() {
                    "" => build::automatic_base_name(spec.kind, &request.options.desktop),
                    name => name.to_string(),
                };
                let id = crate::storage::unique_id();
                let builds = self.options.data_dir.join("builds");
                storage::private_dir(&builds).map_err(|e| e.to_string())?;
                let output = builds.join(format!("{}-{id}", spec.id));
                let log_path = builds.join(format!("{}-{id}.log", spec.id));
                let stage = Arc::new(Mutex::new("prepare".to_string()));
                let log = Arc::new(Mutex::new(VecDeque::<String>::new()));
                let cancel = Arc::new(AtomicBool::new(false));
                let (sender, receiver) = mpsc::channel();
                let job = BuildRun {
                    kind: spec.kind,
                    profile: spec.id,
                    mode,
                    options: request.options,
                    data_dir: self.options.data_dir.clone(),
                    curl: self.options.curl.clone(),
                    output,
                    log_path: log_path.clone(),
                    stage: stage.clone(),
                    log: log.clone(),
                    cancel: cancel.clone(),
                };
                let options = self.options.clone();
                thread::Builder::new()
                    .name("antinomie-build".into())
                    .spawn(move || {
                        let output = job.output.clone();
                        let result = job.run().and_then(|()| {
                            let bundle = Bundle::load(&output)?;
                            require_supported(
                                bundle.antinomie_revision,
                                bundle.min_app_version.as_deref(),
                            )?;
                            storage::validate_disk_chain(&options, &bundle.base_disk, None)?;
                            bundle.install(&options)?;
                            Ok(())
                        });
                        let _ = fs::remove_dir_all(&output);
                        let _ = sender.send(result);
                    })
                    .map_err(|e| e.to_string())?;
                self.build = Some(BuildJob {
                    label: label.clone(),
                    stage,
                    log,
                    cancel,
                    done: receiver,
                });
                self.snapshot.build = Some(BuildStatus {
                    profile: spec.id.to_string(),
                    label: label.clone(),
                    mode,
                    stage: "prepare".into(),
                    log: Vec::new(),
                    log_path: Some(log_path),
                    finished: false,
                    error: None,
                });
                Ok(match mode {
                    build::BuildMode::Qemu => "base build started in the QEMU builder VM".into(),
                    _ => "base build started on this host".into(),
                })
            }
            Command::InstallTool { id } => {
                if self.tool.is_some() {
                    return Err("a tool installation is already in progress".into());
                }
                let package = crate::analysis_tools::package(&id).ok_or("unknown analysis tool")?;
                distribution::curl_version(&self.options.curl)?;
                let progress = Arc::new(Mutex::new(("download".to_string(), 0, package.size())));
                let cancel = Arc::new(AtomicBool::new(false));
                let (sender, receiver) = mpsc::channel();
                let (curl, data_dir) = (self.options.curl.clone(), self.options.data_dir.clone());
                let (worker_progress, worker_cancel) = (progress.clone(), cancel.clone());
                thread::Builder::new()
                    .name("antinomie-tool-install".into())
                    .spawn(move || {
                        let result = crate::analysis_tools::install(
                            &curl,
                            &data_dir,
                            package.id,
                            &worker_cancel,
                            |stage, received, total| {
                                if let Ok(mut guard) = worker_progress.lock() {
                                    *guard = (stage.to_string(), received, total);
                                }
                            },
                        );
                        let _ = sender.send(result);
                    })
                    .map_err(|e| e.to_string())?;
                self.tool = Some(ToolJob {
                    progress,
                    cancel,
                    done: receiver,
                });
                self.snapshot.tool_install = Some(crate::analysis_tools::ToolInstall {
                    id: package.id.into(),
                    name: package.name.into(),
                    stage: "download".into(),
                    received: 0,
                    total: package.size(),
                    finished: false,
                    error: None,
                });
                Ok(format!("installing {}", package.name))
            }
            Command::CancelToolInstall => {
                let job = self
                    .tool
                    .as_ref()
                    .ok_or("no tool installation is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling tool installation".into())
            }
            Command::RemoveTool { id } => {
                if self.tool.as_ref().is_some()
                    && self
                        .snapshot
                        .tool_install
                        .as_ref()
                        .is_some_and(|t| t.id == id)
                {
                    return Err("the tool is being installed".into());
                }
                crate::analysis_tools::remove(&self.options.data_dir, &id)?;
                self.snapshot.analysis_tools =
                    crate::analysis_tools::statuses(&self.options.data_dir);
                Ok("analysis tool removed".into())
            }
            Command::CancelBuild => {
                let job = self.build.as_ref().ok_or("no base build is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling the base build".into())
            }
            Command::DeleteBase {
                identity,
                confirmed,
            } => {
                if !confirmed {
                    return Err("base deletion requires confirmation".into());
                }
                if self.session.is_some() || self.snapshot.active_vm.is_some() {
                    return Err("stop the VM before deleting a base".into());
                }
                if identity.len() != 64
                    || !identity
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid base identity".into());
                }
                let dependents: Vec<&str> = self
                    .snapshot
                    .vms
                    .iter()
                    .filter(|vm| vm.base_identity.as_deref() == Some(identity.as_str()))
                    .map(|vm| vm.name.as_str())
                    .collect();
                if !dependents.is_empty() {
                    return Err(format!(
                        "base is used by {} VM(s): {}",
                        dependents.len(),
                        dependents.join(", ")
                    ));
                }
                let directory = self.options.data_dir.join("bases").join(&identity);
                if !directory.is_dir() {
                    return Err("unknown base".into());
                }
                fs::remove_dir_all(&directory).map_err(|e| e.to_string())?;
                self.refresh_locations()?;
                Ok("base deleted".into())
            }
            // Dispatched by the worker loop, which answers it when the
            // deletion thread is done (see `start_evidence_delete`).
            Command::DeleteEvidence { .. } => {
                Err("evidence deletion is handled by the worker loop".into())
            }
            Command::Save(mut vm) => {
                storage::validate_vm(&vm)?;
                vm.launch.validate_for(&self.options)?;
                self.ensure_stopped(&vm.id)?;
                let current = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                let boot_bundle =
                    crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
                storage::validate_boot_display(&vm, &boot_bundle)?;
                let location =
                    crate::locations::future_recordings(&self.options, current, &mut vm)?;
                let dir = storage::vm_dir(&self.options, &vm.id)?;
                let disk_bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
                storage::validate_guest_transition(&disk_bundle, &boot_bundle)?;
                storage::validate_vm_bundle(&self.options, &vm, &disk_bundle)?;
                storage::validate_vm_bundle(&self.options, &vm, &boot_bundle)?;
                if vm.disk_gib < current.disk_gib {
                    return Err("persistent VM disks cannot be shrunk".into());
                }
                if vm.disk_gib != current.disk_gib {
                    if !crate::snapshots::list(&self.options, current)?
                        .nodes
                        .is_empty()
                    {
                        return Err(
                            "disk resizing is blocked while snapshots retain disk geometry".into(),
                        );
                    }
                    let disk = crate::snapshots::active_disk(&self.options, current)?;
                    let output = std::process::Command::new(&self.options.qemu_img)
                        .arg("resize")
                        .arg(&disk)
                        .arg(format!("{}G", vm.disk_gib))
                        .output()
                        .map_err(|e| e.to_string())?;
                    if !output.status.success() {
                        return Err(format!(
                            "disk resize: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ));
                    }
                    // A provisioned (partitioned) root grows with its disk.
                    if disk_bundle
                        .guest
                        .as_ref()
                        .is_some_and(|guest| guest.requires_credentials)
                    {
                        crate::guest_account::grow_disk(&disk)?;
                    }
                }
                let previous = current.clone();
                let publication =
                    storage::save_vm_config(&self.options, &dir, &previous, &vm, &location);
                if let Err(error) = &publication
                    && !error.published
                {
                    return Err(error.to_string());
                }
                let slot = self
                    .snapshot
                    .vms
                    .iter_mut()
                    .find(|v| v.id == vm.id)
                    .ok_or("unknown VM")?;
                *slot = vm;
                self.refresh_locations()?;
                publication?;
                Ok("VM saved".into())
            }
            Command::Rename { vm_id, name } => {
                let mut vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| vm.id == vm_id)
                    .ok_or("unknown VM")?
                    .clone();
                vm.name = name;
                storage::validate_vm(&vm)?;
                let dir = storage::vm_dir(&self.options, &vm_id)?;
                storage::atomic_json(&dir.join("config.json"), &vm)?;
                if let Some(slot) = self.snapshot.vms.iter_mut().find(|vm| vm.id == vm_id) {
                    *slot = vm;
                }
                Ok("VM renamed; identity, disk and recordings retained".into())
            }
            Command::Duplicate { vm_id, name } => {
                self.ensure_stopped(&vm_id)?;
                let source = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| vm.id == vm_id)
                    .ok_or("unknown VM")?
                    .clone();
                source.launch.validate_for(&self.options)?;
                if source.launch.resolution.dimensions().is_some() {
                    let boot = crate::locations::boot_bundle(
                        &self.options,
                        source.base_identity.as_deref(),
                    )?;
                    storage::validate_boot_display(&source, &boot)?;
                }
                let result = storage::duplicate_vm(&self.options, &source, name);
                if result.is_err() {
                    self.snapshot.vms = storage::load_vms(&self.options)?;
                    self.refresh_locations()?;
                }
                let vm = result?;
                self.snapshot.vms.push(vm);
                self.refresh_locations()?;
                Ok("VM duplicated with an independent disk; no history copied".into())
            }
            Command::Delete { vm_id, confirmed } => {
                if !confirmed {
                    return Err("disk deletion requires explicit confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                if !self.snapshot.vms.iter().any(|v| v.id == vm_id) {
                    return Err("unknown VM".into());
                }
                let result = storage::delete_vm(&self.options, &vm_id);
                if result.is_err() {
                    self.snapshot.vms = storage::load_vms(&self.options)?;
                    self.refresh_locations()?;
                    result?;
                }
                self.snapshot.vms.retain(|v| v.id != vm_id);
                self.refresh_locations()?;
                Ok("VM disk and configuration deleted; recordings retained".into())
            }
            Command::Reset { vm_id, confirmed } => {
                if !confirmed {
                    return Err("disk reset requires explicit confirmation".into());
                }
                self.ensure_stopped(&vm_id)?;
                let vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|v| v.id == vm_id)
                    .ok_or("unknown VM")?;
                let dir = storage::vm_dir(&self.options, &vm_id)?;
                let bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
                storage::reset_vm_disk(&self.options, &dir, vm, &bundle)?;
                Ok("VM reset to base".into())
            }
            Command::UpdateOptions {
                bundle_dir,
                capture_quota_size,
                shutdown_timeout_secs,
            } => {
                if self.session.is_some() {
                    return Err("stop VM before changing settings".into());
                }
                if capture_quota_size < 1024 || !(1..=120).contains(&shutdown_timeout_secs) {
                    return Err(
                        "capture quota must be at least 1024 and shutdown timeout 1..120 seconds"
                            .into(),
                    );
                }
                self.options.bundle_dir = bundle_dir;
                self.options.capture_quota_size = capture_quota_size;
                self.options.shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);
                Ok("settings updated".into())
            }
            Command::OpenRecording { directory } => Err(format!(
                "open {} with the independent recording reader",
                directory.display()
            )),
            Command::Start { vm_id } => self.start(&vm_id),
            Command::StartNetworkCapture => self.start_network_capture(),
            Command::StopNetworkCapture => self.stop_network_capture(),
            Command::DumpMemory => self.start_memory_dump(),
            Command::MeasureDisk {
                vm_id,
                source,
                partition,
            } => self.measure_disk(&vm_id, &source, partition),
            Command::OpenCurrentDisk {
                vm_id,
                source,
                partition,
            } => self.open_current_disk(&vm_id, &source, partition),
            Command::CloseCurrentDisk { vm_id } => self.close_current_disk(&vm_id),
            Command::OpenDiskReference { vm_id, source } => {
                self.open_disk_reference(&vm_id, &source)
            }
            Command::CloseDiskReference { vm_id } => self.close_disk_reference_for(&vm_id),
            Command::DumpDisk {
                vm_id,
                source,
                partition,
                hash,
                layer_digests,
            } => self.dump_disk(&vm_id, &source, partition, hash, layer_digests),
            Command::SaveDiskPartition {
                vm_id,
                source,
                partition,
                path,
            } => self.save_disk_partition(&vm_id, &source, partition, &path),
            Command::ImportQcow2Disk { vm_id, path, hash } => {
                self.import_qcow2_disk(&vm_id, &path, hash)
            }
            Command::KeepCurrentDiskAsDump {
                vm_id,
                hash,
                layer_digests,
            } => self.keep_current_disk(&vm_id, hash, layer_digests),
            Command::CancelDiskJob { vm_id } => self.cancel_disk_job(&vm_id),
            Command::AnalyzeHostFile {
                vm_id,
                path,
                analysis,
            } => self.analyze_host_file(&vm_id, &path, analysis),
            Command::AnalyzeMore {
                directory,
                run_id,
                checks,
            } => self.analyze_more(&directory, run_id, &checks),
            Command::CancelAnalysis { analysis_id }
                if self.host_analysis.cancel(&analysis_id).is_ok() =>
            {
                self.host_analysis_tick();
                Ok("analysis cancelled".into())
            }
            Command::Stop => {
                self.stop()?;
                Ok("VM stopped; recordings are being saved in the background".into())
            }
            Command::Close => {
                self.closing.store(true, Ordering::Relaxed);
                self.stop()?;
                Ok("backend closed".into())
            }
            other => self.guest_command(other),
        }
    }
    pub(super) fn create(
        &mut self,
        mut vm: VmConfig,
        credentials: Option<GuestCredentials>,
    ) -> Result<String, String> {
        if self.session.is_some() || self.snapshot.active_vm.is_some() {
            return Err("stop VM before creating another VM".into());
        }
        if vm.id.is_empty() {
            vm.id = storage::vm_id(&vm.name);
        }
        storage::validate_vm(&vm)?;
        vm.launch.validate_for(&self.options)?;
        if self.snapshot.vms.iter().any(|current| current.id == vm.id) {
            return Err("VM identity already exists".into());
        }
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        storage::validate_boot_display(&vm, &bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &bundle)?;
        let requires_credentials = bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials);
        if requires_credentials != credentials.is_some() {
            return Err(if requires_credentials {
                "guest credentials are required"
            } else {
                "this base does not accept guest credentials"
            }
            .into());
        }
        vm.base_identity = bundle.base_identity.clone();
        let location = crate::locations::prepare(&self.options, &mut vm)?;
        let dir = &location.disk_directory;
        fs::create_dir(dir).map_err(|e| e.to_string())?;
        let result = (|| -> Result<(), String> {
            storage::private_dir(dir).map_err(|e| e.to_string())?;
            storage::create_overlay(&self.options, dir, vm.disk_gib, &bundle)?;
            if let Some(credentials) = credentials {
                let mut account =
                    crate::guest_account::GuestAccount::from_credentials(credentials)?;
                account.provision(&dir.join("disk.qcow2"), vm.ram_mib)?;
                account.save(dir)?;
            }
            storage::atomic_json(&dir.join("config.json"), &vm)?;
            storage::sync_directory_parent(dir)
        })();
        if let Err(error) = result {
            let cleanup = fs::remove_dir_all(dir);
            return Err(format!("{error}; creation rollback {:?}", cleanup.err()));
        }
        let publication = crate::locations::publish(&self.options, &location);
        if let Err(error) = &publication
            && !error.published
        {
            let cleanup = fs::remove_dir_all(dir);
            return Err(format!("{error}; creation rollback {:?}", cleanup.err()));
        }
        self.snapshot.vms.push(vm);
        self.refresh_locations()?;
        publication?;
        Ok("VM created".into())
    }
}
