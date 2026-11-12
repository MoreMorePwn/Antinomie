// SPDX-License-Identifier: GPL-3.0-only
//! Commands executed inside the running guest.
use super::*;

/// How long the guest has to answer one command at KVM speed.
pub(super) const GUEST_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

impl Session {
    /// [`GUEST_REPLY_TIMEOUT`] for this boot: stretched under TCG by the
    /// factor the boot wait uses (`accel::Waits::guest_command`), unchanged
    /// under KVM.
    pub(super) fn reply_timeout(&self) -> Duration {
        self.process.waits.guest_command(GUEST_REPLY_TIMEOUT)
    }
}

impl Worker {
    /// [`Session::reply_timeout`] of the running VM.
    pub(super) fn reply_timeout(&self) -> Duration {
        self.session
            .as_ref()
            .map_or(GUEST_REPLY_TIMEOUT, Session::reply_timeout)
    }

    pub(super) fn guest_command(&mut self, command: Command) -> Result<String, String> {
        let launch = matches!(&command, Command::Execute(_));
        let result = self.guest_command_once(command);
        // Whatever became of a launch, the telemetry still waiting for an
        // acknowledgement ages again from here.
        if launch && let Some(session) = self.session.as_mut() {
            session.pre_ack.launch_answered();
        }
        result
    }

    fn guest_command_once(&mut self, command: Command) -> Result<String, String> {
        if matches!(&command, Command::Execute(request) if request.debug_on_start) {
            self.debug_reap_ended();
        }
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        if matches!(
            &command,
            Command::ListProcesses { .. }
                | Command::AttachProcess { .. }
                | Command::CaptureAll
                | Command::StopCapture { .. }
        ) {
            observer_ready(self.snapshot.guest_kernel.as_ref())?;
        }
        match command {
            Command::DebugAttach { identity } => {
                let message = self.debug_attach(identity)?;
                Ok(message)
            }
            Command::DebugDetach { kill } => self.debug_detach(kill),
            Command::DebugUi(request) => self.debug_panel_request(request),
            Command::DumpProcessCore { request } => {
                if !self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|kernel| kernel.revision)
                    .is_some_and(|revision| revision >= 16)
                {
                    return Err("manual process cores require a revision-16 guest".into());
                }
                let message = session.start_manual_core(request)?;
                self.publish();
                Ok(message)
            }
            Command::CancelCoreCapture { capture_id } => {
                let message = session.cancel_manual_core(&capture_id)?;
                self.publish();
                Ok(message)
            }
            Command::ListProcesses { after_pid } => {
                let page = Some(session.list_processes(
                    after_pid,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?);
                let count = page.as_ref().map_or(0, |p| p.processes.len());
                self.snapshot.process_page = page;
                Ok(format!("{count} guest processes listed"))
            }
            Command::AttachProcess { identity } => {
                let message = session.start_capture(
                    &self.options,
                    CaptureScope::Process { root: identity },
                    &mut self.snapshot,
                    &self.sender,
                )?;
                // The picker's list names the attached process and its ancestors.
                if let (Some(page), Some(capture)) = (
                    &self.snapshot.process_page,
                    session
                        .captures
                        .values_mut()
                        .find(|capture| capture.summary.state == CaptureState::Active),
                ) {
                    capture.processes.seed(&page.processes);
                }
                Ok(message)
            }
            Command::CaptureAll => self.capture_all(),
            Command::StopCapture { capture_id } => self.stop_capture(capture_id),
            Command::Execute(request) => self.execute(request),
            Command::CancelProcessCore { run_id } => {
                session.cancel_core(&run_id, &mut self.snapshot, &self.sender)
            }
            Command::AnalyzeOnly {
                path,
                uid,
                gid,
                analysis,
            } => self.analyze_only(path, uid, gid, analysis),
            Command::CancelAnalysis { analysis_id } => {
                session.analysis.cancel(&analysis_id)?;
                session.analysis_updates(&mut self.snapshot, &self.sender);
                Ok("analysis cancelled; program continues".into())
            }
            Command::Upload {
                source,
                destination,
                overwrite,
                executable,
            } => self.upload_file(source, destination, overwrite, executable),
            Command::UploadSample {
                sha256,
                destination,
                executable,
            } => self.upload_sample(sha256, destination, executable),
            Command::TerminalInput { run_id, data } => self.terminal_input(run_id, data),
            Command::TerminalRead { run_id } => {
                session.read_terminal(
                    &run_id,
                    &mut self.snapshot,
                    &self.sender,
                    Duration::from_millis(500),
                )?;
                Ok(String::new())
            }
            Command::TerminalResize { run_id, rows, cols } => {
                self.terminal_resize(run_id, rows, cols)
            }
            Command::TerminalSnapshot { run_id } => {
                let cookie = session.run_cookie(&run_id)?;
                let notification = session
                    .runs
                    .get(&cookie)
                    .ok_or("unknown run")?
                    .screen_notification();
                self.emit(notification);
                Ok(String::new())
            }
            Command::Signal { run_id, signal } => self.signal_run(run_id, signal),
            Command::ForgetRun { run_id } => {
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                run.summary.forgettable()?;
                session.runs.remove(&cookie);
                Ok(format!("run {run_id} removed from this list"))
            }
            Command::StopRun { run_id } => self.stop_run(run_id),
            Command::RecorderStats => self.recorder_stats(),
            _ => Err("not a guest command".into()),
        }
    }

    /// Start capturing every user-space process and name those already running.
    fn capture_all(&mut self) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        let message = session.start_capture(
            &self.options,
            CaptureScope::AllUserspace,
            &mut self.snapshot,
            &self.sender,
        )?;
        // start_capture answers with a status message; the capture
        // just started is the active one.
        let id = session
            .captures
            .iter()
            .find(|(_, capture)| capture.summary.state == CaptureState::Active)
            .map(|(id, _)| id.clone())
            .unwrap_or_default();
        // Name the processes already running; the capture's fork and
        // exec records name the rest. A failed list only leaves
        // early processes unnamed.
        match session.list_processes(0, &mut self.snapshot, &self.sender, timeout) {
            Ok(page) => {
                if let Some(capture) = session.captures.get_mut(&id) {
                    capture.processes.seed(&page.processes);
                }
            }
            Err(error) => {
                self.snapshot.last_error = Some(format!("Capture All process names: {error}"));
            }
        }
        Ok(message)
    }

    /// Stop the admission of observations for one capture.
    fn stop_capture(&mut self, capture_id: String) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        let capture = session
            .captures
            .get(&capture_id)
            .ok_or("unknown capture in this VM boot")?;
        let mut cookie = capture.summary.capture_cookie;
        if cookie == 0 {
            let reply = session.request(
                control::CAPTURE_STATUS,
                &control::with_session(0),
                &mut self.snapshot,
                &self.sender,
                timeout,
            )?;
            let status = control::capture_status(&reply, 0)?;
            if status.cookie == 0 {
                return Err(
                    "capture identity is unknown; admission outcome unresolved until VM restart"
                        .into(),
                );
            }
            session.apply_capture_status(&capture_id, status)?;
            session.update_captures(&mut self.snapshot);
            cookie = session
                .captures
                .get(&capture_id)
                .ok_or("unknown capture")?
                .summary
                .capture_cookie;
        }
        let reply = session.request(
            control::CAPTURE_STOP,
            &control::with_session(cookie),
            &mut self.snapshot,
            &self.sender,
            timeout,
        )?;
        let status = control::capture_status(&reply, cookie)?;
        if status.active {
            return Err("capture stop reply still admits observations".into());
        }
        session.apply_capture_status(&capture_id, status)?;
        session.update_captures(&mut self.snapshot);
        Ok("capture admission stopped; programs continue running and late observation tails remain recordable".into())
    }

    /// Record a standalone static analysis of a file in the guest.
    fn analyze_only(
        &mut self,
        path: String,
        uid: u32,
        gid: u32,
        analysis: crate::analysis::AnalysisSelection,
    ) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        analysis.validate()?;
        control::string(&path, true)?;
        if !analysis.enabled {
            return Err("Analyze Only requires static analysis enabled".into());
        }
        if self.snapshot.analysis_reports.len() >= 8 {
            return Err("this VM boot reached the eight standalone analysis limit".into());
        }
        let report = crate::analysis::jobs::new_report(&path, &analysis);
        let directory = crate::locations::locations(&self.options, &session.vm.id)?
            .recording_directory
            .join("analyses")
            .join(&report.id);
        // The specimen size this guest's contract takes (none before 10).
        let specimen = control::specimen_request(
            self.snapshot.guest_kernel.as_ref().and_then(|k| k.revision),
            session.vm.ram_mib,
        );
        let supported = specimen.is_some();
        let acquisition = if supported {
            session
                .request(
                    control::ACQUIRE,
                    &control::acquire(
                        &path,
                        uid,
                        gid,
                        specimen.unwrap_or(control::LEGACY_SPECIMEN_MAX_SIZE),
                    )?,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )
                .and_then(|reply| {
                    control::specimen_acquisition(
                        &reply,
                        specimen.unwrap_or(control::LEGACY_SPECIMEN_MAX_SIZE),
                    )
                })
        } else {
            Err("this base does not support static analysis; use a base for Antinomie 0.2.0 or newer".into())
        };
        let available = session.available();
        session
            .analysis
            .submit(None, report, directory, acquisition, available);
        session.analysis_updates(&mut self.snapshot, &self.sender);
        Ok("standalone analysis request recorded".into())
    }

    /// Send a host file into the guest, archiving it in the library first.
    fn upload_file(
        &mut self,
        source: PathBuf,
        destination: String,
        overwrite: bool,
        executable: bool,
    ) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        let mut file =
            File::open(&source).map_err(|e| format!("upload {}: {e}", source.display()))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() {
            return Err("upload source must be a regular file".into());
        }
        let total = metadata.len();
        check_program_size(total, executable, session.vm.ram_mib)?;
        if total > crate::samples::MAX_SAMPLE {
            // Too large for the library, which keeps what is sent.
            return upload_stream(
                session,
                &mut self.snapshot,
                &self.sender,
                &self.stopping,
                timeout,
                &mut file,
                total,
                (&destination, overwrite, executable),
            );
        }
        // Everything the app sends into a guest is archived first,
        // hashed on the host and never run or unpacked there: what is
        // streamed is exactly what the library holds.
        let mut bytes = Vec::with_capacity(total as usize);
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut file, crate::samples::MAX_SAMPLE + 1),
            &mut bytes,
        )
        .map_err(|e| format!("upload {}: {e}", source.display()))?;
        let note = arch_note(&self.snapshot, &bytes, executable);
        let actor = self.custody_actor.get();
        let mut library =
            crate::samples::Library::open(&self.options.data_dir)?.with_actor(&actor)?;
        let sha256 = library
            .add_bytes(
                &bytes,
                crate::samples::NewSample {
                    origin: crate::samples::NewOrigin {
                        kind: crate::samples::OriginKind::Uploaded,
                        source: "Upload".into(),
                        path: source.display().to_string(),
                        vm_id: session.vm.id.clone(),
                        vm_name: session.vm.name.clone(),
                        ..crate::samples::NewOrigin::default()
                    },
                    ..crate::samples::NewSample::default()
                },
            )?
            .sha256;
        let message = upload_stream(
            session,
            &mut self.snapshot,
            &self.sender,
            &self.stopping,
            timeout,
            &mut bytes.as_slice(),
            bytes.len() as u64,
            (&destination, overwrite, executable),
        )? + &note;
        drop(bytes);
        drop(library);
        // Written by the custody thread: a commit here held the
        // transport thread for seconds on a busy disk (ANT-T0203).
        crate::samples::record_push_later(
            &self.options.data_dir,
            &sha256,
            crate::samples::Push {
                vm_id: session.vm.id.clone(),
                vm_name: session.vm.name.clone(),
                path: destination.clone(),
                at_ms: 0,
            },
            &self.custody_actor.get(),
        );
        Ok(message)
    }

    /// Send a library sample into the guest.
    fn upload_sample(
        &mut self,
        sha256: String,
        destination: String,
        executable: bool,
    ) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = session.reply_timeout();
        // Decrypted in memory only; the host keeps the archive. The
        // library reads it back and compares its SHA-256 first: a
        // sample that does not verify is never sent.
        let library = crate::samples::Library::open(&self.options.data_dir)?;
        let bytes = library.open_bytes(&sha256)?;
        drop(library);
        check_program_size(bytes.len() as u64, executable, session.vm.ram_mib)?;
        let note = arch_note(&self.snapshot, &bytes, executable);
        let message = upload_stream(
            session,
            &mut self.snapshot,
            &self.sender,
            &self.stopping,
            timeout,
            &mut bytes.as_slice(),
            bytes.len() as u64,
            // The path names the sample's hash: what is there is the
            // same sample (sent before), so it is replaced.
            (&destination, true, executable),
        )? + &note;
        drop(bytes);
        crate::samples::record_push_later(
            &self.options.data_dir,
            &sha256,
            crate::samples::Push {
                vm_id: session.vm.id.clone(),
                vm_name: session.vm.name.clone(),
                path: destination.clone(),
                at_ms: 0,
            },
            &self.custody_actor.get(),
        );
        Ok(message)
    }
}

/// Process attachment and Capture All need a revision-11 guest; until the
/// running kernel has identified itself (right after boot) it is too early to
/// tell, which is not the same as an old base.
fn observer_ready(kernel: Option<&GuestKernel>) -> Result<(), String> {
    match kernel.map(|kernel| kernel.revision) {
        None => Err("the guest kernel has not identified itself yet; retry in a moment".into()),
        Some(Some(revision)) if revision >= 11 => Ok(()),
        Some(_) => Err("process attachment and Capture All are unavailable; running guest requires a base for Antinomie 0.2.0 or newer".into()),
    }
}

#[cfg(test)]
mod observer_ready_tests {
    use super::*;

    #[test]
    fn a_guest_that_has_not_identified_itself_is_not_called_old() {
        let error = observer_ready(None).unwrap_err();
        assert!(error.contains("not identified itself yet"), "{error}");
        let kernel = |revision| GuestKernel {
            revision,
            ..GuestKernel::default()
        };
        assert!(
            observer_ready(Some(&kernel(None)))
                .unwrap_err()
                .contains("0.2.0 or newer")
        );
        assert!(
            observer_ready(Some(&kernel(Some(10))))
                .unwrap_err()
                .contains("0.2.0 or newer")
        );
        assert_eq!(observer_ready(Some(&kernel(Some(20)))), Ok(()));
    }
}
