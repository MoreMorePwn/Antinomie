// SPDX-License-Identifier: GPL-3.0-only
//! Commands that start or end base installs, tool installs and clipboard typing.
use super::*;

impl Worker {
    /// Install a boot bundle from a directory.
    pub(super) fn import_base(&mut self, directory: PathBuf) -> Result<String, String> {
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

    /// Start fetching the remote base catalog.
    pub(super) fn refresh_remote_bases(&mut self) -> Result<String, String> {
        if self.refresh.is_some() {
            return Err("base catalog refresh already in progress".into());
        }
        distribution::curl_version(&self.options.curl)?;
        let curl = self.options.curl.clone();
        let remote = self.options.remote_base.clone();
        let (sender, receiver) = mpsc::channel();
        let cancel = crate::cancel::CancelToken::new();
        let worker_cancel = cancel.clone();
        thread::Builder::new()
            .name("antinomie-catalog".into())
            .spawn(move || {
                let _ = sender.send(distribution::fetch_catalog(&curl, &remote, &worker_cancel));
            })
            .map_err(|e| e.to_string())?;
        self.refresh = Some(RefreshJob {
            cancel,
            done: receiver,
        });
        self.snapshot.remote_refreshing = true;
        self.snapshot.remote_error = None;
        Ok("refreshing base catalog".into())
    }

    /// Start downloading one base of the catalog.
    pub(super) fn download_base(&mut self, identity: String) -> Result<String, String> {
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
        let label = match base_app_version(base.antinomie_revision, base.min_app_version.as_deref())
        {
            Some(version) => {
                format!("{} · Antinomie {version}", base_label_plain(&base.label))
            }
            None => base_label_plain(&base.label).to_owned(),
        };
        let progress = Arc::new(Mutex::new((0u64, false)));
        let worker_progress = progress.clone();
        let notes = Arc::new(Mutex::new(String::new()));
        let worker_notes = notes.clone();
        let (sender, receiver) = mpsc::channel();
        let requested = base.clone();
        let staging_thread = staging.clone();
        let cancel = crate::cancel::CancelToken::new();
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
                    &mut |line| {
                        if let Ok(mut guard) = worker_notes.lock() {
                            *guard = line.to_owned();
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
            notes,
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
            note: String::new(),
            kept: 0,
        });
        Ok("base download started".into())
    }

    /// Start building a base.
    pub(super) fn build_base(&mut self, request: build::BuildRequest) -> Result<String, String> {
        if self.build.is_some() {
            return Err("a base build is already in progress".into());
        }
        let spec = build::profile(&request.profile).ok_or("unknown build profile")?;
        request.options.validate(spec.kind)?;
        let mode = build::resolve_mode(spec.kind, request.mode)?;
        // Automatic may fall through from a container to QEMU later,
        // when the image cannot be had.
        let fallback = request.mode == build::BuildMode::Automatic
            && mode.engine().is_some()
            && build::mode_obstacle(spec.kind, build::BuildMode::Qemu).is_none();
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
        let cancel = crate::cancel::CancelToken::new();
        let (sender, receiver) = mpsc::channel();
        let job = BuildRun {
            kind: spec.kind,
            profile: spec.id,
            mode,
            fallback,
            options: request.options,
            data_dir: self.options.data_dir.clone(),
            curl: self.options.curl.clone(),
            tcg_multiplier: self.options.start.tcg_multiplier,
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
                let log_path = job.log_path.clone();
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
                // A cancelled build leaves nothing: not even its log. It
                // is not resumed (a build step is not a download); only
                // a download it had under way keeps its partial file.
                let result = result.map_err(|error| {
                    if !crate::cancel::is_cancelled(&error) {
                        return error;
                    }
                    let _ = fs::remove_file(&log_path);
                    crate::resume::cancelled_build_text(&options.data_dir)
                });
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
            build::BuildMode::Podman | build::BuildMode::Docker => {
                format!("base build started in a {} container", mode.label())
            }
            _ => "base build started on this host".into(),
        })
    }

    /// Start installing an analysis tool.
    pub(super) fn install_tool(&mut self, id: String) -> Result<String, String> {
        if self.tool.is_some() {
            return Err("a tool installation is already in progress".into());
        }
        let package = crate::analysis_tools::package(&id).ok_or("unknown analysis tool")?;
        distribution::curl_version(&self.options.curl)?;
        let progress = Arc::new(Mutex::new(("download".to_string(), 0, package.size())));
        let cancel = crate::cancel::CancelToken::new();
        let (sender, receiver) = mpsc::channel();
        let (curl, data_dir) = (self.options.curl.clone(), self.options.data_dir.clone());
        let (worker_progress, worker_cancel) = (progress.clone(), cancel.clone());
        let notes = Arc::new(Mutex::new(String::new()));
        let worker_notes = notes.clone();
        thread::Builder::new()
            .name("antinomie-tool-install".into())
            .spawn(move || {
                let result = crate::analysis_tools::install(
                    &curl,
                    &data_dir,
                    package.id,
                    &worker_cancel,
                    |stage, received, total| {
                        if let Some(text) = stage.strip_prefix("note:") {
                            if let Ok(mut guard) = worker_notes.lock() {
                                *guard = text.to_owned();
                            }
                        } else if let Ok(mut guard) = worker_progress.lock() {
                            *guard = (stage.to_string(), received, total);
                        }
                    },
                );
                let _ = sender.send(result);
            })
            .map_err(|e| e.to_string())?;
        self.tool = Some(ToolJob {
            notes,
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
            note: String::new(),
        });
        Ok(format!("installing {}", package.name))
    }

    /// Delete an installed base nothing depends on.
    pub(super) fn delete_base(
        &mut self,
        identity: String,
        confirmed: bool,
    ) -> Result<String, String> {
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
        // A partial download of the same base goes with it.
        if self
            .download
            .as_ref()
            .is_none_or(|job| job.identity != identity)
        {
            let _ = fs::remove_dir_all(self.options.data_dir.join("downloads").join(&identity));
        }
        self.refresh_locations()?;
        Ok("base deleted".into())
    }

    /// Start typing the clipboard into the guest.
    pub(super) fn type_clipboard(
        &mut self,
        vm_id: String,
        boot_id: String,
        text: String,
    ) -> Result<String, String> {
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

    /// Remove an installed analysis tool.
    pub(super) fn remove_tool(&mut self, id: String) -> Result<String, String> {
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
        self.snapshot.analysis_tools = crate::analysis_tools::statuses(&self.options.data_dir);
        Ok("analysis tool removed".into())
    }

    /// Cancel the base download unless it is already installing.
    pub(super) fn cancel_download(&mut self) -> Result<String, String> {
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
}
