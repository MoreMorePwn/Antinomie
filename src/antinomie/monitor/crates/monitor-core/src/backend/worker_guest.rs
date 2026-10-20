// SPDX-License-Identifier: MIT
//! Commands executed inside the running guest.
use super::*;
use crate::debug::KernelDebugBackend;

impl Worker {
    pub(super) fn guest_command(&mut self, command: Command) -> Result<String, String> {
        if matches!(&command, Command::Execute(request) if request.debug_on_start) {
            self.debug_reap_ended();
        }
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = Duration::from_secs(10);
        if matches!(
            &command,
            Command::ListProcesses { .. }
                | Command::AttachProcess { .. }
                | Command::CaptureAll
                | Command::StopCapture { .. }
        ) && !self
            .snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision)
            .is_some_and(|revision| revision >= 11)
        {
            return Err("process attachment and Capture All are unavailable; running guest requires a base for Antinomie 0.2.0 or newer".into());
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
            Command::CaptureAll => {
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
                        self.snapshot.last_error =
                            Some(format!("Capture All process names: {error}"));
                    }
                }
                Ok(message)
            }
            Command::StopCapture { capture_id } => {
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
                        return Err("capture identity is unknown; admission outcome unresolved until VM restart".into());
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
            Command::Execute(request) => {
                if request.core_dump_on_exit
                    && !self
                        .snapshot
                        .guest_kernel
                        .as_ref()
                        .and_then(|kernel| kernel.revision)
                        .is_some_and(|revision| revision >= 15)
                {
                    return Err(
                        "process Core Dump on Exit requires a revision-15 base for Antinomie 0.6.0"
                            .into(),
                    );
                }
                if request.core_dump_on_exit {
                    crate::core_limits::CoreLimits::check_known(
                        self.snapshot.guest_core_limits,
                        u64::from(request.core_max_size.unwrap_or(64 << 20)),
                        request.core_timeout_ms.unwrap_or(5000),
                    )?;
                }
                if request.core_dump_on_exit && request.run_in.guest_desktop() {
                    return Err("process Core Dump on Exit currently requires App Terminal; desktop wrappers do not identify the selected executable as the root group".into());
                }
                if request.debug_on_start {
                    if request.run_in.guest_desktop() {
                        return Err("Debug on start needs Run in: App terminal; a desktop launcher runs a shell wrapper, which is what would stop".into());
                    }
                    if self.debug.is_active() {
                        return Err("a debugger is already attached; detach it before debugging another program from its start".into());
                    }
                    let caps = KernelDebugBackend::probe(&mut debug_service::WorkerLink {
                        session,
                        snapshot: &mut self.snapshot,
                        sender: &self.sender,
                    })
                    .map_err(|error| error.to_string())?;
                    if !caps.debug_on_start {
                        return Err("this base's debugger cannot stop a program at its start; rebuild the base for Antinomie 0.7.0 (Debug on start is a Phase 2 feature)".into());
                    }
                }
                let boot_id = session.boot_id.clone();
                if session.run_artifacts.contains_key(&0) {
                    return Err("a failed launch still owns an unresolved network capture; wait for cleanup or restart the VM".into());
                }
                if (request.capture_network || request.memory_dump_on_exit)
                    && !self
                        .snapshot
                        .guest_kernel
                        .as_ref()
                        .and_then(|kernel| kernel.revision)
                        .is_some_and(|revision| revision >= 14)
                {
                    return Err("run-to-exit capture and post-exit RAM dump require a revision-14 base for Antinomie 0.5.0".into());
                }
                if session.runs.len() >= 64 {
                    return Err("this VM boot reached the 64-run limit; restart the VM before another launch".into());
                }
                let supported = self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|k| k.revision)
                    .is_some_and(|r| r >= 10);
                let desktop = request.run_in.guest_desktop();
                if desktop
                    && !session
                        .disk_bundle
                        .guest
                        .as_ref()
                        .is_some_and(|guest| guest.graphical)
                {
                    return Err(format!(
                        "{} needs a VM with a graphical base",
                        request.run_in.label()
                    ));
                }
                // A desktop run executes `/bin/sh`, so its program is acquired
                // by path after the launch instead of by the kernel's exec.
                let wire = crate::guest_desktop::wire_request(&request)?;
                let args = control::execute_analysis(&wire, supported)?;
                let selected = request.analysis.enabled;
                let inline_acquisition = selected && supported && !desktop;
                let run_id = storage::unique_id();
                let directory = crate::locations::locations(&self.options, &session.vm.id)?
                    .recording_directory
                    .join("runs")
                    .join(&run_id);
                let summary = RunSummary {
                    started_ms: None,
                    clock_anchor: None,
                    id: run_id,
                    vm_id: session.vm.id.clone(),
                    boot_id: session.boot_id.clone(),
                    session_id: 0,
                    root_task_cookie: 0,
                    pid: 0,
                    request: request.clone(),
                    directory,
                    terminal_eof: false,
                    state: RunState::Unknown,
                    recording_error: Some("execution has not been acknowledged".into()),
                    notes: Vec::new(),
                    execution: None,
                    analysis: selected.then(|| {
                        crate::analysis::jobs::new_report(&request.path, &request.analysis)
                    }),
                };
                let mut run = ProgramRun::new(summary, session.capture.quota())?;
                run.assembler
                    .set_event_table(session.vm.transport.event_table as usize);
                run.summary.recording_error = None;
                run.boot_bundle_identity = session.bundle.base_identity.clone();
                run.disk_base_identity = session.disk_bundle.base_identity.clone();
                let mut artifacts = RunArtifactOwner::new(&run.summary);
                let prepared = if request.capture_network {
                    session.start_run_network(&self.options, &mut artifacts)
                } else {
                    artifacts.save()
                };
                if let Err(error) = prepared {
                    return Err(session.failed_run_launch(&mut run, artifacts, error));
                }
                // Every error text below is final: a guest rejection says the launch
                // did not happen, only an unanswered or malformed one leaves it unknown.
                let acknowledged = (|| -> Result<(Vec<u8>, u64, u64, u32), String> {
                    let reply = session
                        .request_typed(
                            control::EXEC,
                            &args,
                            &mut self.snapshot,
                            &self.sender,
                            timeout,
                        )
                        .map_err(|error| launch_failure(error, &request.path, &request.cwd))?;
                    (|| {
                        if reply.len()
                            != 24
                                + usize::from(inline_acquisition) * 24
                                + usize::from(request.core_dump_on_exit) * 24
                                + usize::from(request.debug_on_start) * 16
                            || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0
                        {
                            return Err("invalid execution reply".to_string());
                        }
                        let id = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                        let cookie = u64_at(&reply, 8).map_err(|e| e.to_string())?;
                        let pid = u32_at(&reply, 16).map_err(|e| e.to_string())?;
                        if cookie == 0 || session.runs.contains_key(&cookie) {
                            return Err("invalid or reused execution root identity".to_string());
                        }
                        Ok((id, cookie, pid))
                    })()
                    .map(|(id, cookie, pid)| (reply, id, cookie, pid))
                    .map_err(|error| launch_unknown(&error))
                })();
                let (reply, id, cookie, pid) = match acknowledged {
                    Ok(acknowledged) => acknowledged,
                    Err(error) => return Err(session.failed_run_launch(&mut run, artifacts, error)),
                };
                run.summary.session_id = id;
                run.summary.root_task_cookie = cookie;
                run.summary.pid = pid;
                run.summary.state = RunState::Running;
                if request.core_dump_on_exit {
                    let core_offset = 24 + usize::from(inline_acquisition) * 24;
                    match process_core::Transfer::armed(&reply[core_offset..], &run.summary) {
                        Ok(core) => artifacts.core = Some(core),
                        Err(error) => {
                            artifacts.summary.core_state = RunArtifactState::Failed;
                            artifacts.issue(error.clone());
                            artifacts.core = Some(process_core::Transfer::failed(
                                &reply[core_offset..],
                                &run.summary,
                                error,
                            ));
                        }
                    }
                    if let Err(error) = storage::queue_json(
                        &artifacts.directory.join("artifacts.json"),
                        &artifacts.summary,
                    ) {
                        artifacts.issue(error);
                    }
                }
                session.run_artifacts.insert(cookie, artifacts);
                if let Some(report) = run.summary.analysis.take() {
                    let acquisition = if inline_acquisition {
                        control::acquisition(&reply[24..48])
                    } else if supported {
                        control::acquire(&request.path, request.uid, request.gid)
                            .and_then(|args| {
                                session.request(
                                    control::ACQUIRE,
                                    &args,
                                    &mut self.snapshot,
                                    &self.sender,
                                    timeout,
                                )
                            })
                            .and_then(|reply| control::acquisition(&reply))
                    } else {
                        Err(
                            "this base does not support static analysis (it needs a base for Antinomie 0.2.0 or newer); the program ran without it"
                                .into(),
                        )
                    };
                    let available = session.available().saturating_sub(run.stored_len());
                    run.summary.analysis = Some(session.analysis.submit(
                        Some(run.summary.id.clone()),
                        report,
                        run.summary.directory.join("analysis"),
                        acquisition,
                        available,
                    ));
                    if let Err(error) = run.refresh_analysis_metadata() {
                        run.storage_error(format!("analysis metadata accounting: {error}"));
                    }
                }
                if let Some(error) = session.capture.error.clone() {
                    run.capture.error = Some(error.clone());
                    run.storage_error(error);
                }
                // Telemetry that arrived before this launch was acknowledged.
                let claim = session.pre_ack.claim(cookie, Instant::now());
                for packet in claim.packets {
                    if let Ok((header, _)) = crate::parser::parse_packet(&packet) {
                        run.observe_clock(header.timestamp_ns);
                    }
                    let reserved = session.stored_len() + run.stored_len() - run.capture.bytes;
                    if !run.capture.append_with_reserved(&packet, reserved) {
                        let error = run
                            .capture
                            .error
                            .clone()
                            .unwrap_or_else(|| "pending raw saving failed".into());
                        run.storage_error(error.clone());
                        session.saving_refused(cookie, error);
                    }
                    run.assembler.set_storage_limit(
                        run.assembler
                            .stored_len()
                            .saturating_add(session.available().saturating_sub(run.stored_len())),
                    );
                    if let Err(error) = run.assembler.ingest(&packet) {
                        self.snapshot.last_error = Some(error.to_string());
                    }
                    if let Some(error) = run.assembler.saving_error().map(str::to_owned) {
                        run.capture.error.get_or_insert(error.clone());
                        run.storage_error(error.clone());
                        session.saving_refused(cookie, error);
                    }
                }
                // A note, not a saving failure: the run keeps recording and the
                // lost packets are still in the boot's raw archives.
                if let Some(note) = claim.lost.note() {
                    run.add_note(note);
                }
                if let Err(error) = run.persist_summary() {
                    run.storage_error(format!("run metadata persistence failed: {error}"));
                }
                let summary = run.summary.clone();
                session.runs.insert(cookie, run);
                session.update_runs(&mut self.snapshot);
                self.emit(Notification::RunStarted(summary));
                let launched = format!("launched pid {pid}, terminal session {id}");
                if !request.debug_on_start {
                    return Ok(launched);
                }
                // The guest parked the new program before its first instruction;
                // the debugger takes over that session.
                let start_offset = 24
                    + usize::from(inline_acquisition) * 24
                    + usize::from(request.core_dump_on_exit) * 24;
                let identity = crate::observation::GuestProcessIdentity {
                    boot_id: boot_id.clone(),
                    task_cookie: cookie,
                    tgid: pid,
                    start_boot_ns: u64_at(&reply, start_offset).map_err(|e| e.to_string())?,
                };
                match self.debug_attach(identity) {
                    Ok(attached) => Ok(format!(
                        "{launched}; stopped before its first instruction; {attached}"
                    )),
                    Err(error) => {
                        // A parked program nobody can debug must not wait for ever.
                        if let Some(session) = self.session.as_mut() {
                            let mut args = control::header(0);
                            args.extend(cookie.to_le_bytes());
                            let _ = session.request(
                                0x1015,
                                &args,
                                &mut self.snapshot,
                                &self.sender,
                                timeout,
                            );
                        }
                        let message = format!(
                            "{launched}, but the debugger could not attach ({error}); the program was stopped"
                        );
                        self.snapshot.last_error = Some(message.clone());
                        Ok(message)
                    }
                }
            }
            Command::CancelProcessCore { run_id } => {
                session.cancel_core(&run_id, &mut self.snapshot, &self.sender)
            }
            Command::AnalyzeOnly {
                path,
                uid,
                gid,
                analysis,
            } => {
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
                let supported = self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|k| k.revision)
                    .is_some_and(|r| r >= 10);
                let acquisition = if supported {
                    session
                        .request(
                            control::ACQUIRE,
                            &control::acquire(&path, uid, gid)?,
                            &mut self.snapshot,
                            &self.sender,
                            timeout,
                        )
                        .and_then(|reply| control::acquisition(&reply))
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
            } => {
                let mut file =
                    File::open(&source).map_err(|e| format!("upload {}: {e}", source.display()))?;
                let metadata = file.metadata().map_err(|e| e.to_string())?;
                if !metadata.is_file() {
                    return Err("upload source must be a regular file".into());
                }
                let total = metadata.len();
                upload_stream(
                    session,
                    &mut self.snapshot,
                    &self.sender,
                    &self.stopping,
                    timeout,
                    &mut file,
                    total,
                    (&destination, overwrite, executable),
                )
            }
            Command::UploadSample {
                sha256,
                destination,
                executable,
            } => {
                // Decrypted in memory only; the host keeps the archive.
                let archive = crate::samples::archive_path(&self.options.data_dir, &sha256)?;
                let bytes = crate::samples::open_sample(&archive, &sha256)?;
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
                )?;
                drop(bytes);
                crate::samples::record_push(
                    &self.options.data_dir,
                    &sha256,
                    crate::samples::Push {
                        vm_id: session.vm.id.clone(),
                        vm_name: session.vm.name.clone(),
                        path: destination.clone(),
                        at_ms: 0,
                    },
                )?;
                Ok(message)
            }
            Command::TerminalInput { run_id, data } => {
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                if run.summary.terminal_eof {
                    return Err("terminal is closed".into());
                }
                let terminal = run.summary.session_id;
                let chunk_size = session.transport.command_limit.saturating_sub(16);
                if chunk_size == 0 {
                    return Err("no terminal payload capacity".into());
                }
                let mut written = 0;
                for chunk in data.chunks(chunk_size) {
                    let mut args = control::with_session(terminal);
                    args.extend(chunk);
                    let reply = session.request(
                        control::INPUT,
                        &args,
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    )?;
                    if reply.len() != 8 {
                        return Err("invalid terminal input reply".into());
                    }
                    let count = u64_at(&reply, 0).map_err(|e| e.to_string())?;
                    if count > chunk.len() as u64 {
                        return Err("invalid terminal input count".into());
                    }
                    written += count;
                    if count != chunk.len() as u64 {
                        return Err(format!("terminal accepted only {written} input bytes"));
                    }
                }
                Ok(format!("terminal input accepted {written} bytes"))
            }
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
                if rows == 0 || cols == 0 || rows > 256 || cols > 256 {
                    return Err("terminal dimensions must be 1..256".into());
                }
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                if run.summary.terminal_eof {
                    // Nothing to size: a program that detached (a daemon)
                    // closed it, as its window opened. Not an error.
                    return Ok(String::new());
                }
                let mut args = control::with_session(run.summary.session_id);
                args.extend(rows.to_le_bytes());
                args.extend(cols.to_le_bytes());
                args.extend([0; 4]);
                session.request(
                    control::RESIZE,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                let available = session.available();
                let run = session.runs.get_mut(&cookie).ok_or("unknown run")?;
                run.resize(rows, cols, available)?;
                let notification = run.screen_notification();
                self.emit(notification);
                Ok("terminal resized".into())
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
            Command::Signal { run_id, signal } => {
                if !(1..=64).contains(&signal) {
                    return Err("signal must be 1..64".into());
                }
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                let (id, current_pid) = (run.summary.session_id, run.summary.pid);
                let mut args = control::with_session(id);
                args.extend(signal.to_le_bytes());
                args.extend(0u32.to_le_bytes());
                session.request(
                    control::SIGNAL,
                    &args,
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                Ok(format!(
                    "signal {signal} sent to process group {current_pid}"
                ))
            }
            Command::StopRun { run_id } => {
                let cookie = session.run_cookie(&run_id)?;
                let run = session.runs.get(&cookie).ok_or("unknown run")?;
                if !matches!(
                    run.summary.state,
                    RunState::Running | RunState::TerminalClosed
                ) {
                    return Err("run is no longer available for termination".into());
                }
                let mut args = control::header(0);
                args.extend(cookie.to_le_bytes());
                // A revision-17 guest sends SIGKILL to the whole run when SIGTERM
                // was not enough, after 4 s unless the options name another grace.
                let escalates = self
                    .snapshot
                    .guest_kernel
                    .as_ref()
                    .and_then(|kernel| kernel.revision)
                    .is_some_and(|revision| revision >= 17);
                let mut grace = 4000;
                if let Some(wanted) = self.options.stop_grace {
                    if !escalates {
                        return Err("a Stop grace period needs a revision-17 guest".into());
                    }
                    grace = u32::try_from(wanted.as_millis())
                        .ok()
                        .filter(|millis| (100..=30_000).contains(millis))
                        .ok_or("the Stop grace period must be 100 ms to 30 s")?;
                    args.extend(grace.to_le_bytes());
                    args.extend(0u32.to_le_bytes());
                }
                let reply =
                    session.request(0x1015, &args, &mut self.snapshot, &self.sender, timeout)?;
                if !reply.is_empty() {
                    return Err("invalid stop-run acknowledgement".into());
                }
                let run = session.runs.get_mut(&cookie).ok_or("unknown run")?;
                run.summary.state = RunState::StopRequested;
                run.persist_summary()?;
                Ok(if escalates {
                    format!(
                        "SIGTERM issued to the run; the guest sends SIGKILL to anything still alive after {:.1} s, and the run status then says which signal ended it",
                        f64::from(grace) / 1000.0
                    )
                } else {
                    "SIGTERM issued to the run; this guest never escalates, so a task that ignores it keeps running (descendant completion is not yet proven)".into()
                })
            }
            Command::RecorderStats => {
                let stats_requested = Instant::now();
                let reply = session.request(
                    control::STATS,
                    &control::header(0),
                    &mut self.snapshot,
                    &self.sender,
                    timeout,
                )?;
                if reply.len() != 80 {
                    return Err("invalid recorder stats reply".into());
                }
                let counters = decode_stats(&reply)?;
                session
                    .recorder_poll
                    .observe(stats_requested, counters, &mut self.snapshot.health);
                Ok(format!(
                    "recorder stream {} calls {} packets {} failed {} copy faults {} schema gaps {} context failures {}",
                    counters[0],
                    counters[3],
                    counters[5],
                    counters[6],
                    counters[7],
                    counters[8],
                    counters[9]
                ))
            }
            _ => Err("not a guest command".into()),
        }
    }
}
