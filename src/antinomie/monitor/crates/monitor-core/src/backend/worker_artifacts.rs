// SPDX-License-Identifier: GPL-3.0-only
//! Network captures, memory dumps and run artifacts owned by the worker.
use super::*;

impl Worker {
    /// Attach a filter-dump to the VM's network interface: QEMU writes every
    /// frame to a new pcap in the boot recording, outside the guest.
    pub(super) fn start_network_capture(&mut self) -> Result<String, String> {
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        if self.snapshot.network_capture.is_some() {
            return Err("a network capture is already running".into());
        }
        let capture = prepare_network_capture(&self.options, session)?;
        if let Err(error) = crate::network::filter_dump_add(&capture)
            .and_then(|command| session.process.qmp(&command))
        {
            let cleanup = remove_network_filter(&session.process, &capture);
            if cleanup.is_ok() {
                let saved = finish_network_summary(capture);
                return Err(format!(
                    "network capture start: {error}; stopped summary: {saved:?}"
                ));
            }
            // Keep ownership visible so Stop capture can retry an uncertain add.
            self.snapshot.network_capture = Some(capture);
            return Err(format!(
                "network capture start: {error}; cleanup: {cleanup:?}"
            ));
        }
        self.snapshot.network_capture = Some(capture);
        // Publish the changed toggle before acknowledging the command, so
        // the UI cannot briefly re-enable the old action after completion.
        self.publish();
        Ok("network capture started".into())
    }
    pub(super) fn stop_network_capture(&mut self) -> Result<String, String> {
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        let capture = self
            .snapshot
            .network_capture
            .as_ref()
            .ok_or("no network capture is running")?;
        remove_network_filter(&session.process, capture)?;
        let finished = end_network_capture(&mut self.snapshot);
        if let (Ok(bytes), Some(session)) = (&finished, self.session.as_mut()) {
            session.network_bytes_done = session.network_bytes_done.saturating_add(*bytes);
            session.network_bytes = session.network_bytes.max(session.network_bytes_done);
        }
        self.publish();
        let bytes = finished?;
        Ok(format!(
            "network capture stopped ({})",
            crate::byte_size::file_size(bytes)
        ))
    }
    /// Start writing the running VM's RAM to a new memory dump; QEMU writes
    /// it in the background and pauses the guest until it is done.
    pub(super) fn start_memory_dump(&mut self) -> Result<String, String> {
        self.start_memory_dump_for(None)
    }
    fn start_memory_dump_for(&mut self, owner_cookie: Option<u64>) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        if self.snapshot.memory_dump.is_some() {
            return Err("a memory dump is already being written".into());
        }
        let recording =
            crate::locations::locations(&self.options, &session.vm.id)?.recording_directory;
        let bundle = &session.bundle;
        let system = match &bundle.name {
            Some(name) => format!("Linux {} · {name}", bundle.kernel_version),
            None => format!("Linux {}", bundle.kernel_version),
        };
        let dump = crate::memory::new_vm_dump(
            &recording,
            &session.vm,
            &session.boot_id,
            system,
            bundle.symbols.as_deref(),
        )?;
        if let Some(cookie) = owner_cookie {
            let owner = session
                .run_artifacts
                .get_mut(&cookie)
                .ok_or("missing RAM dump owner")?;
            owner.summary.memory_dump = Some(dump.dir.clone());
            owner.summary.memory_state = RunArtifactState::InProgress;
            if let Err(error) = owner.save() {
                let cleanup = crate::memory::delete(&dump);
                return Err(format!("{error}; dump cleanup: {cleanup:?}"));
            }
        }
        // QEMU stops the guest while it writes: a silent guest is expected.
        if let Err(error) = session.transport.set_guest_paused(true) {
            let cleanup = crate::memory::delete(&dump);
            return Err(format!(
                "memory dump pause: {error}; dump cleanup: {cleanup:?}"
            ));
        }
        let command = match crate::memory::dump_command(&dump) {
            Ok(command) => command,
            Err(error) => {
                let resumed = session.transport.set_guest_paused(false);
                let cleanup = crate::memory::delete(&dump);
                return Err(format!(
                    "memory dump command: {error}; transport resume: {resumed:?}; dump cleanup: {cleanup:?}"
                ));
            }
        };
        let mut warning = None;
        if let Err(error) = session.process.qmp(&command) {
            if !qmp_outcome_unknown(&error) {
                let resumed = session.transport.set_guest_paused(false);
                let cleanup = crate::memory::delete(&dump);
                return Err(format!(
                    "memory dump: {error}; transport resume: {resumed:?}; dump cleanup: {cleanup:?}"
                ));
            }
            let status = session
                .process
                .qmp(&serde_json::json!({"execute":"query-dump"}))
                .and_then(|reply| memory_query_status(&reply));
            let message = format!(
                "memory dump acknowledgement unresolved: {error}; reconciliation: {status:?}; artifacts retained"
            );
            if matches!(
                status,
                Ok(crate::memory::DumpStatus::Failed | crate::memory::DumpStatus::None)
            ) {
                let resumed = session.transport.set_guest_paused(false);
                let mut failed = dump;
                failed.error = Some(message.clone());
                let saved = failed.save();
                return Err(format!(
                    "{message}; transport resume: {resumed:?}; failed dump summary: {saved:?}"
                ));
            }
            // Active/completed or still unknown: preserve both paused-guest
            // accounting and the dump owner until a later query proves an end.
            warning = Some(message);
        }
        session.last_memory_check = Instant::now();
        let total = u64::from(session.vm.ram_mib) << 20;
        self.snapshot.memory_dump = Some(crate::memory::DumpProgress {
            dump,
            completed: 0,
            total,
        });
        if let Some(message) = warning {
            if let Some(cookie) = owner_cookie
                && let Some(owner) = session.run_artifacts.get_mut(&cookie)
            {
                owner.issue(message.clone());
                if let Err(error) = owner.save() {
                    self.snapshot.last_error = Some(error);
                }
            }
            self.snapshot.last_error = Some(message.clone());
            self.emit(Notification::CommandResult {
                id: 0,
                success: false,
                message: message.clone(),
            });
            self.publish();
            return Ok(message);
        }
        self.publish();
        Ok("memory dump started: the VM is paused while its RAM is written".into())
    }
    /// Follow the memory dump QEMU writes, and record it when it is done.
    pub(super) fn check_memory_dump(&mut self) {
        let (Some(session), Some(progress)) =
            (self.session.as_mut(), self.snapshot.memory_dump.as_mut())
        else {
            return;
        };
        if session.last_memory_check.elapsed() < Duration::from_millis(200) {
            return;
        }
        session.last_memory_check = Instant::now();
        let status = session
            .process
            .qmp(&serde_json::from_str(crate::memory::QUERY_DUMP).unwrap_or_default())
            .and_then(|reply| memory_query_status(&reply));
        let mut dump = progress.dump.clone();
        let message = match status {
            Ok(crate::memory::DumpStatus::Active { completed, total }) => {
                progress.completed = completed;
                progress.total = total.max(1);
                return;
            }
            Ok(crate::memory::DumpStatus::Completed) => {
                dump.finished_ms = Some(unix_ms());
                match completed_memory_dump_size(&dump) {
                    Ok(size) => dump.bytes = Some(size),
                    Err(error) => dump.error = Some(format!("completed memory dump file: {error}")),
                }
                if let Some(error) = dump.error.as_ref() {
                    format!("memory dump failed: {error}")
                } else {
                    format!(
                        "memory dump written ({})",
                        crate::byte_size::file_size(dump.bytes.unwrap_or(0))
                    )
                }
            }
            Ok(_) => {
                dump.error = Some("QEMU could not write the memory dump".into());
                "memory dump failed".into()
            }
            Err(error) => {
                // QMP loss is not proof that a background operation stopped.
                // Keep the owned file/progress and retry; no guest commands
                // run against a VM whose paused state remains unresolved.
                let message = format!(
                    "memory dump status unresolved: {error}; artifacts retained; retrying QMP"
                );
                self.snapshot.last_error = Some(message.clone());
                for owner in session.run_artifacts.values_mut() {
                    if owner.summary.memory_dump.as_ref() == Some(&dump.dir) {
                        owner.issue(message.clone());
                        if let Err(error) = owner.save() {
                            self.snapshot.last_error = Some(error);
                        }
                    }
                }
                return;
            }
        };
        if let Err(error) = session.transport.set_guest_paused(false) {
            self.snapshot.last_error = Some(format!("after the memory dump: {error}"));
        }
        if let Err(error) = dump.save() {
            dump.error
                .get_or_insert_with(|| format!("memory dump summary: {error}"));
            self.snapshot.last_error = Some(format!("memory dump summary: {error}"));
        } else if dump.error.is_some() {
            self.snapshot.last_error = Some(message);
        }
        for owner in session.run_artifacts.values_mut() {
            if owner.summary.memory_dump.as_ref() == Some(&dump.dir)
                && owner.summary.memory_state == RunArtifactState::InProgress
            {
                owner.summary.memory_state = if dump.error.is_some() {
                    RunArtifactState::Failed
                } else {
                    RunArtifactState::Complete
                };
                if let Some(error) = dump.error.as_ref() {
                    owner.issue(error.clone());
                }
                if let Err(error) = owner.save() {
                    self.snapshot.last_error = Some(error);
                }
            }
        }
        self.snapshot.memory_dump = None;
        self.publish();
    }
    /// React once to fresh guest tree-completion status. Neither root exit nor
    /// terminal EOF can authorize these actions while descendants still live.
    pub(super) fn check_run_artifacts(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let cookies: Vec<_> = session.run_artifacts.keys().copied().collect();
        let mut issues = Vec::new();
        for cookie in cookies {
            let Some(mut owner) = session.run_artifacts.remove(&cookie) else {
                continue;
            };
            let changed = owner.observe(
                session
                    .runs
                    .get(&cookie)
                    .and_then(|run| run.summary.execution.as_ref()),
            );
            if owner.tree_complete
                && owner.network.is_some()
                && owner
                    .last_network_stop
                    .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
                && let Err(error) = session.stop_run_network(&mut owner)
            {
                let new_issue = !owner.summary.issues.contains(&error);
                owner.issue(error.clone());
                if new_issue {
                    issues.push(error);
                }
                if let Err(error) = owner.save() {
                    issues.push(error);
                }
            }
            if changed && let Err(error) = owner.save() {
                issues.push(error);
            }
            if cookie != 0 || owner.network.is_some() {
                session.run_artifacts.insert(cookie, owner);
            }
        }
        let queued = session.run_artifacts.iter().find_map(|(cookie, owner)| {
            (owner.summary.memory_state == RunArtifactState::Queued).then_some(*cookie)
        });
        if self.snapshot.memory_dump.is_none()
            && self.snapshot.vm_snapshot_progress.is_none()
            && self.snapshot.state == VmState::Running
            && let Some(cookie) = queued
            && let Err(error) = self.start_memory_dump_for(Some(cookie))
        {
            if let Some(owner) = self
                .session
                .as_mut()
                .and_then(|session| session.run_artifacts.get_mut(&cookie))
            {
                owner.summary.memory_state = RunArtifactState::Failed;
                owner.issue(format!("post-exit RAM dump: {error}"));
                if let Err(error) = owner.save() {
                    issues.push(error);
                }
            }
            issues.push(format!("post-exit RAM dump: {error}"));
        }
        for message in issues {
            self.snapshot.last_error = Some(message.clone());
            self.emit(Notification::CommandResult {
                id: 0,
                success: false,
                message,
            });
        }
    }
    /// About once a second: measure the running network capture and stop it
    /// when the recordings of this boot have used up the quota.
    pub(super) fn check_network_capture(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if self.snapshot.network_capture.is_none()
            && session
                .run_artifacts
                .values()
                .all(|owner| owner.network.is_none())
        {
            return;
        }
        if session.last_network_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        session.last_network_check = Instant::now();
        let live = self
            .snapshot
            .network_capture
            .iter()
            .chain(
                session
                    .run_artifacts
                    .values()
                    .filter_map(|owner| owner.network.as_ref()),
            )
            .map(|capture| fs::metadata(&capture.file).map_or(0, |metadata| metadata.len()))
            .fold(0u64, u64::saturating_add);
        session.network_bytes = session.network_bytes_done.saturating_add(live);
        if session.available() > 0 {
            return;
        }
        let cookies: Vec<_> = session.run_artifacts.keys().copied().collect();
        for cookie in cookies {
            let Some(mut owner) = session.run_artifacts.remove(&cookie) else {
                continue;
            };
            if owner.network.is_some() {
                let result = session.stop_run_network(&mut owner);
                owner.summary.network_state = RunArtifactState::Failed;
                owner.issue("network capture reached the recording quota before tree exit".into());
                if let Err(error) = result {
                    owner.issue(error);
                }
                if let Err(error) = owner.save() {
                    self.snapshot.last_error = Some(error);
                }
            }
            session.run_artifacts.insert(cookie, owner);
        }
        let result = if self.snapshot.network_capture.is_some() {
            self.stop_network_capture()
        } else {
            Ok(String::new())
        };
        self.snapshot.last_error = Some(match result {
            Ok(_) => "network captures stopped: the recording quota is full".into(),
            Err(error) => format!("network capture reached the recording quota; {error}"),
        });
        self.publish();
    }
}

pub(super) fn memory_query_status(
    reply: &serde_json::Value,
) -> Result<crate::memory::DumpStatus, String> {
    match reply["status"].as_str() {
        Some("active")
            if reply["completed"].as_u64().is_some() && reply["total"].as_u64().is_some() =>
        {
            Ok(crate::memory::dump_status(reply))
        }
        Some("completed" | "failed" | "none") => Ok(crate::memory::dump_status(reply)),
        _ => Err("invalid memory dump status reply; operation outcome remains unknown".into()),
    }
}

pub(super) fn completed_memory_dump_size(dump: &crate::memory::MemoryDump) -> Result<u64, String> {
    let mut file = crate::archive_io::open_regular(&dump.dir, &dump.path())
        .map_err(|error| error.to_string())?;
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    let mut header = [0; 64];
    file.read_exact(&mut header)
        .map_err(|error| format!("ELF header: {error}"))?;
    // This launcher produces x86-64 QEMU ELF cores. Check the actual regular
    // artifact, rather than trusting a QMP completion flag or a guessed size.
    if size <= header.len() as u64
        || &header[..4] != b"\x7fELF"
        || header[4..7] != [2, 1, 1]
        || u16::from_le_bytes([header[16], header[17]]) != 4
        || u16::from_le_bytes([header[18], header[19]]) != 62
    {
        return Err("expected a nonempty x86-64 ELF core dump".into());
    }
    // QEMU's physical ELF can report e_ehsize=8. Its actual ELF64 header and
    // program table still follow the standard layout, so validate the table
    // and file-backed extents instead of rejecting that producer field.
    let table_offset = u64_at(&header, 32).map_err(|error| error.to_string())?;
    let entry_size = u16::from_le_bytes([header[54], header[55]]);
    let entry_count = u16::from_le_bytes([header[56], header[57]]);
    let table_end = table_offset.checked_add(u64::from(entry_size) * u64::from(entry_count));
    if entry_size != 56
        || entry_count == 0
        || table_offset < 64
        || table_end.is_none_or(|end| end > size)
    {
        return Err("ELF program table is missing or exceeds the completed file".into());
    }
    let mut reader = BufReader::new(file);
    reader
        .seek(SeekFrom::Start(table_offset))
        .map_err(|error| error.to_string())?;
    let mut load = false;
    for _ in 0..entry_count {
        let mut entry = [0; 56];
        reader
            .read_exact(&mut entry)
            .map_err(|error| format!("ELF program entry: {error}"))?;
        let read64 = |offset| u64_at(&entry, offset).map_err(|error| error.to_string());
        let offset = read64(8)?;
        let file_size = read64(32)?;
        let memory_size = read64(40)?;
        if file_size > 0 && offset.checked_add(file_size).is_none_or(|end| end > size) {
            return Err("ELF segment exceeds the completed file; RAM artifact is truncated".into());
        }
        if u32_at(&entry, 0).map_err(|error| error.to_string())? == 1 {
            if file_size > memory_size {
                return Err("ELF load extent exceeds its memory extent".into());
            }
            load |= file_size > 0 && memory_size > 0;
        }
    }
    if !load {
        return Err("ELF core contains no file-backed memory load segment".into());
    }
    Ok(size)
}

/// The VM stopped while QEMU was writing a memory dump: record it as failed.
pub(super) fn abandon_memory_dump(snapshot: &mut Snapshot) {
    if let Some(progress) = snapshot.memory_dump.take() {
        let mut dump = progress.dump;
        dump.error = Some("the VM stopped before the memory dump was written".into());
        let _ = dump.save();
    }
}
