// SPDX-License-Identifier: MIT
//! Per-run network capture on the session: start, stop, suspend and resume.
use super::*;

impl Session {
    pub(super) fn failed_run_launch(
        &mut self,
        run: &mut ProgramRun,
        mut owner: RunArtifactOwner,
        error: String,
    ) -> String {
        let mut issues = vec![error];
        owner.tree_complete = true;
        if owner.network.is_some() {
            if let Err(error) = self.stop_run_network(&mut owner) {
                issues.push(error);
            }
            owner.summary.network_state = RunArtifactState::Failed;
        }
        if owner.summary.memory_state != RunArtifactState::Disabled {
            owner.summary.memory_state = RunArtifactState::Failed;
        }
        if owner.summary.core_state != RunArtifactState::Disabled {
            owner.summary.core_state = RunArtifactState::Failed;
        }
        for error in &issues {
            owner.issue(error.clone());
        }
        if let Err(error) = owner.save() {
            issues.push(error);
        }
        run.storage_error(issues.join("; "));
        if let Err(error) = run.persist_summary() {
            issues.push(error);
        }
        if owner.network.is_some() {
            // Cookie zero is never a valid execution identity. Retain cleanup
            // ownership across timeout and prohibit another ambiguous launch.
            self.run_artifacts.insert(0, owner);
        }
        issues.join("; ")
    }
    pub(super) fn start_run_network(
        &mut self,
        options: &BackendOptions,
        owner: &mut RunArtifactOwner,
    ) -> Result<(), String> {
        if owner.summary.network_captures.len() >= 256 {
            return Err("this run reached the 256 network-segment limit".into());
        }
        let capture = prepare_network_capture(options, self)?;
        owner.summary.network_captures.push(capture.file.clone());
        owner.summary.network_state = RunArtifactState::Recording;
        owner.network = Some(capture);
        if let Err(error) = owner.save() {
            let cleanup = owner.network.take().map(finish_network_summary);
            return Err(format!("{error}; capture cleanup: {cleanup:?}"));
        }
        let capture = owner.network.as_ref().ok_or("missing run capture owner")?;
        if let Err(error) =
            crate::network::filter_dump_add(capture).and_then(|command| self.process.qmp(&command))
        {
            let cleanup = self.stop_run_network(owner);
            owner.summary.network_state = RunArtifactState::Failed;
            owner.issue(format!(
                "network capture start: {error}; cleanup: {cleanup:?}"
            ));
            return Err(format!(
                "network capture start: {error}; cleanup: {cleanup:?}"
            ));
        }
        Ok(())
    }
    pub(super) fn stop_run_network(&mut self, owner: &mut RunArtifactOwner) -> Result<(), String> {
        let Some(capture) = owner.network.as_ref() else {
            return Ok(());
        };
        owner.last_network_stop = Some(Instant::now());
        // Only this owner's QOM object is removed. Manual and other runs' objects remain.
        remove_network_filter(&self.process, capture)?;
        // Retain ownership until final metadata is durable; cleanup can retry
        // after a transient write failure even though QEMU closed the filter.
        let bytes = finish_network_summary(capture.clone())?;
        owner.network = None;
        self.network_bytes_done = self.network_bytes_done.saturating_add(bytes);
        self.network_bytes = self.network_bytes.max(self.network_bytes_done);
        if owner.summary.network_state != RunArtifactState::Failed {
            owner.summary.network_state = RunArtifactState::Complete;
        }
        owner.save()
    }
    pub(super) fn suspend_run_network(&mut self, reason: &str) -> Result<(), String> {
        let cookies: Vec<_> = self.run_artifacts.keys().copied().collect();
        for cookie in cookies {
            let Some(mut owner) = self.run_artifacts.remove(&cookie) else {
                continue;
            };
            let result = if owner.network.is_some() {
                self.stop_run_network(&mut owner).and_then(|()| {
                    owner.summary.network_state = RunArtifactState::Interrupted;
                    owner.issue(reason.into());
                    owner.save()
                })
            } else {
                Ok(())
            };
            self.run_artifacts.insert(cookie, owner);
            result?;
        }
        Ok(())
    }
    pub(super) fn resume_run_network(&mut self, options: &BackendOptions) -> Result<(), String> {
        let cookies: Vec<_> = self.run_artifacts.keys().copied().collect();
        let mut issues = Vec::new();
        for cookie in cookies {
            let Some(mut owner) = self.run_artifacts.remove(&cookie) else {
                continue;
            };
            if !owner.tree_complete
                && owner.summary.network_state == RunArtifactState::Interrupted
                && let Err(error) = self.start_run_network(options, &mut owner)
            {
                owner.summary.network_state = RunArtifactState::Failed;
                owner.issue(error.clone());
                issues.push(error);
                if let Err(error) = owner.save() {
                    issues.push(error);
                }
            }
            self.run_artifacts.insert(cookie, owner);
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues.join("; "))
        }
    }
}

/// Record the end of the running network capture (stopped over QMP, or its
/// VM gone) with its size, and count its packets on a background thread so
/// a large capture does not pause the transport. Returns the bytes.
pub(super) fn end_network_capture(snapshot: &mut Snapshot) -> Result<u64, String> {
    let Some(capture) = snapshot.network_capture.take() else {
        return Ok(0);
    };
    finish_network_summary(capture)
}

pub(super) fn prepare_network_capture(
    options: &BackendOptions,
    session: &Session,
) -> Result<crate::network::NetworkCapture, String> {
    if !session.vm.nat && !session.vm.isolated_network {
        return Err("this VM has no network: select NAT or isolated network and restart it".into());
    }
    if session.available() == 0 {
        return Err("the recording quota of this boot is full".into());
    }
    let boot_dir = crate::locations::locations(options, &session.vm.id)?
        .recording_directory
        .join("boots")
        .join(&session.boot_id);
    let capture = crate::network::NetworkCapture::new(
        &boot_dir,
        &session.boot_id,
        &storage::unique_id(),
        unix_ms(),
    );
    let dir = capture.file.parent().ok_or("network capture folder")?;
    storage::private_dir(dir).map_err(|error| format!("network capture folder: {error}"))?;
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&capture.file)
        .map_err(|error| format!("network capture file: {error}"))?;
    if let Err(error) = crate::network::save_summary(&capture) {
        let cleanup = fs::remove_file(&capture.file);
        return Err(format!(
            "network capture summary: {error}; empty file cleanup: {cleanup:?}"
        ));
    }
    Ok(capture)
}

pub(super) fn remove_network_filter(
    process: &VmProcess,
    capture: &crate::network::NetworkCapture,
) -> Result<(), String> {
    if let Err(error) = process.qmp(&crate::network::filter_dump_del(capture)) {
        // A timed-out object-add/delete may have succeeded. Confirm absence
        // instead of abandoning ownership or confusing another run's object.
        let objects = process
            .qmp(&serde_json::json!({
                "execute":"qom-list", "arguments":{"path":"/objects"}
            }))
            .map_err(|query| format!("network capture stop: {error}; ownership query: {query}"))?;
        if network_filter_present(&objects, &capture.object_id())? {
            return Err(format!(
                "network capture stop: {error}; filter is still active"
            ));
        }
    }
    Ok(())
}

pub(super) fn network_filter_present(
    objects: &serde_json::Value,
    object_id: &str,
) -> Result<bool, String> {
    // VmProcess::qmp already unwraps the QMP return envelope.
    let entries = objects
        .as_array()
        .ok_or("invalid network capture ownership reply")?;
    let mut present = false;
    for entry in entries {
        let name = entry["name"]
            .as_str()
            .ok_or("network capture ownership entry has no name")?;
        present |= name == object_id;
    }
    Ok(present)
}

pub(super) fn finish_network_summary(
    mut capture: crate::network::NetworkCapture,
) -> Result<u64, String> {
    capture.stopped_ms = Some(unix_ms());
    let bytes = fs::metadata(&capture.file)
        .map_err(|error| format!("network capture final size: {error}"))?
        .len();
    capture.bytes = Some(bytes);
    crate::network::save_summary(&capture)
        .map_err(|error| format!("network capture summary: {error}"))?;
    let _ = thread::Builder::new()
        .name("antinomie-pcap-count".into())
        .spawn(move || {
            if let Ok((packets, bytes)) = crate::network::count_packets(&capture.file) {
                capture.packets = Some(packets);
                capture.bytes = Some(bytes);
                let _ = crate::network::save_summary(&capture);
            }
        });
    Ok(bytes)
}
