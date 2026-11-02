// SPDX-License-Identifier: GPL-3.0-only
//! Starting a program in the guest: the checks, the launch request and the run it creates.
use super::worker_guest::GUEST_REPLY_TIMEOUT;
use super::*;
use crate::debug::KernelDebugBackend;
use session_transport::launch_image_hash;

/// A launch the guest confirmed: the reply, session id, root task cookie and pid.
type Acknowledged = (Vec<u8>, u64, u64, u32);

/// What the guest offers and what the launch asks of it, once known.
#[derive(Clone, Copy)]
struct LaunchShape {
    specimen: Option<u32>,
    supported: bool,
    tracer_hashing: u32,
    inline_acquisition: bool,
}

/// Everything decided before the launch request goes to the guest.
struct LaunchPlan {
    shape: LaunchShape,
    args: Vec<u8>,
    summary: RunSummary,
    route_claim: Option<crate::route::RouteClaim>,
}

/// A launch the guest acknowledged: its reply and identity.
struct Launched {
    reply: Vec<u8>,
    id: u64,
    cookie: u64,
    pid: u32,
    shape: LaunchShape,
}

/// A launch whose run and artifacts exist but are not yet registered.
struct SentLaunch {
    run: ProgramRun,
    artifacts: RunArtifactOwner,
    ack: Launched,
}

/// Arms the core transfer of a run that dumps its process core on exit.
fn arm_process_core(
    run: &ProgramRun,
    artifacts: &mut RunArtifactOwner,
    reply: &[u8],
    inline_acquisition: bool,
) {
    // The core's 24-byte arm reply sits before the debugger's
    // 16-byte start record, which is not part of it.
    let core_offset = 24 + usize::from(inline_acquisition) * 24;
    let core_reply = &reply[core_offset..core_offset + 24];
    match process_core::Transfer::armed(core_reply, &run.summary) {
        Ok(core) => artifacts.core = Some(core),
        Err(error) => {
            artifacts.summary.core_state = RunArtifactState::Failed;
            artifacts.issue(error.clone());
            artifacts.core = Some(process_core::Transfer::failed(
                core_reply,
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

impl Worker {
    /// Start a program in the guest and record the run.
    pub(super) fn execute(&mut self, mut request: ExecRequest) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let boot_id = session.boot_id.clone();
        self.launch_checks(&mut request)?;
        let plan = self.plan_launch(&request)?;
        let sent = self.send_launch(&request, plan)?;
        let ack = self.register_run(&request, sent)?;
        self.report_launch(&request, ack, boot_id)
    }
    /// Refuse a launch this guest or this boot cannot take, and name the library sample.
    fn launch_checks(&mut self, request: &mut ExecRequest) -> Result<(), String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        // A program the library sent into this VM is the library's
        // sample; the run record names it.
        if request.sample.is_none() {
            request.sample = crate::samples::Library::open(&self.options.data_dir)
                .and_then(|library| {
                    library.identify_run(&session.vm.id, &request.path, &request.args)
                })
                .unwrap_or(None);
        }
        if request.core_dump_on_exit
            && !self
                .snapshot
                .guest_kernel
                .as_ref()
                .and_then(|kernel| kernel.revision)
                .is_some_and(|revision| revision >= 15)
        {
            return Err(
                "process Core Dump on Exit requires a revision-15 base for Antinomie 0.6.0".into(),
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
            return Err(
                "this VM boot reached the 64-run limit; restart the VM before another launch"
                    .into(),
            );
        }
        Ok(())
    }

    /// Work out the launch request and the run summary from what the guest offers.
    fn plan_launch(&mut self, request: &ExecRequest) -> Result<LaunchPlan, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        // The specimen size this guest's contract takes (none before 10).
        let specimen = control::specimen_request(
            self.snapshot.guest_kernel.as_ref().and_then(|k| k.revision),
            session.vm.ram_mib,
        );
        let supported = specimen.is_some();
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
        // Whatever hashing and launch shape the guest offers is asked
        // for; an older guest offers none and sees no new flag.
        // The offer comes from a probe after boot. A launch that beat it
        // would silently drop the shell-job shape and the hashing, so it
        // waits instead, like the core limits do.
        if let Some(kernel) = self.snapshot.guest_kernel.as_ref()
            && !kernel.arch.supported()
        {
            return Err(super::session_transport::unsupported_arch(kernel.arch));
        }
        let offered = control::tracer_offer(self.snapshot.guest_tracer)?;
        let tracer_hashing = offered & (control::EXEC_HASH_ROOT | control::EXEC_HASH_WRITES);
        let args = control::with_tracer_flags(control::execute_analysis(&wire, specimen)?, offered);
        // Refused before the run exists, so Run History lists nothing for it.
        if request.capture_network && !session.vm.has_network() {
            return Err(format!(
                "Capture network cannot be used: {}",
                super::run_network::NO_NETWORK_CARD
            ));
        }
        let selected = request.analysis.enabled;
        let inline_acquisition = selected && supported && !desktop;
        let run_id = storage::unique_id();
        let directory = crate::locations::locations(&self.options, &session.vm.id)?
            .recording_directory
            .join("runs")
            .join(&run_id);
        // The route comes up before anything of the run exists, and a
        // route that cannot start is the run's error (no fallback).
        let (route, route_claim) =
            session.claim_run_route(&self.options, &run_id, request.route)?;
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
            // The identity the guest shows, for reading the result against it.
            machine: Some(crate::stealth::MachineRecord::of(
                &session.vm.stealth,
                &crate::stealth::HostCpu::detect(),
                session.vm.ram_mib,
            )),
            route: Some(route),
            environment: Some(crate::run_environment::RunEnvironment::capture(
                &crate::run_environment::Inputs {
                    vm: &session.vm,
                    base_name: session.disk_bundle.name.as_deref().or(session
                        .disk_bundle
                        .guest
                        .as_ref()
                        .map(|guest| guest.label.as_str())),
                    base_identity: session.disk_bundle.base_identity.as_deref(),
                    base_revision: session.disk_bundle.antinomie_revision,
                    kernel: self.snapshot.guest_kernel.as_ref(),
                    accelerator: Some(session.process.accel.record().as_str()),
                    data_dir: &self.options.data_dir,
                },
            )),
            reduced: None,
            execution: None,
            analysis: selected
                .then(|| crate::analysis::jobs::new_report(&request.path, &request.analysis)),
        };
        Ok(LaunchPlan {
            shape: LaunchShape {
                specimen,
                supported,
                tracer_hashing,
                inline_acquisition,
            },
            args,
            summary,
            route_claim,
        })
    }

    /// Create the run, send the launch and read the guest's acknowledgement.
    fn send_launch(
        &mut self,
        request: &ExecRequest,
        plan: LaunchPlan,
    ) -> Result<SentLaunch, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
        let LaunchPlan {
            shape,
            args,
            summary,
            route_claim,
        } = plan;
        let LaunchShape {
            inline_acquisition,
            tracer_hashing,
            ..
        } = shape;
        let run_id = summary.id.clone();
        let mut run = match ProgramRun::new(summary, session.capture.quota()) {
            Ok(run) => run,
            Err(error) => {
                session.release_unowned_route(&run_id, route_claim);
                return Err(error);
            }
        };
        run.assembler
            .set_event_table(session.vm.transport.event_table as usize);
        run.summary.recording_error = None;
        // What the VM started without, so a run that evaded on a
        // setting that was never applied says so in its notes.
        run.add_stealth_fallbacks(&session.process.stealth_fallbacks);
        run.boot_bundle_identity = session.bundle.base_identity.clone();
        run.disk_base_identity = session.disk_bundle.base_identity.clone();
        run.tracer_hashing = tracer_hashing;
        let mut artifacts = RunArtifactOwner::new(&run.summary);
        artifacts.route_claim = route_claim;
        let prepared = if request.capture_network {
            session.start_run_network(&self.options, &mut artifacts)
        } else {
            artifacts.save()
        };
        if let Err(error) = prepared {
            // Nothing was sent to the guest: the program never started.
            return Err(session.failed_run_launch(
                &mut run,
                artifacts,
                (RunState::FailedToStart, error),
            ));
        }
        // Every error text below is final: a guest rejection says the launch
        // did not happen, only an unanswered or malformed one leaves it unknown.
        // Telemetry of the new program can arrive before this reply,
        // and the claim below can be late (the disk can hold this
        // thread up): until then none of it ages out.
        session.pre_ack.launch_sent(Instant::now());
        let acknowledged = (|| -> Result<Acknowledged, (RunState, String)> {
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
            .map_err(|error| (RunState::LaunchUnconfirmed, launch_unknown(&error)))
        })();
        let (reply, id, cookie, pid) = match acknowledged {
            Ok(acknowledged) => acknowledged,
            Err(error) => return Err(session.failed_run_launch(&mut run, artifacts, error)),
        };
        Ok(SentLaunch {
            run,
            artifacts,
            ack: Launched {
                reply,
                id,
                cookie,
                pid,
                shape,
            },
        })
    }

    /// Record the acknowledged launch: custody, artifacts, analysis, replayed telemetry and the run list.
    fn register_run(
        &mut self,
        request: &ExecRequest,
        sent: SentLaunch,
    ) -> Result<Launched, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let SentLaunch {
            mut run,
            mut artifacts,
            ack,
        } = sent;
        let Launched {
            id, cookie, pid, ..
        } = ack;
        let reply = &ack.reply;
        let inline_acquisition = ack.shape.inline_acquisition;
        run.summary.session_id = id;
        run.summary.root_task_cookie = cookie;
        run.summary.pid = pid;
        run.summary.state = RunState::Running;
        if let Some(sample) = request.sample.as_ref() {
            session.custody_start(&self.options.data_dir, sample, &mut run);
        }
        if request.core_dump_on_exit {
            arm_process_core(&run, &mut artifacts, reply, inline_acquisition);
        }
        session.run_artifacts.insert(cookie, artifacts);
        self.submit_run_analysis(request, &mut run, reply, ack.shape);
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        if let Some(error) = session.capture.error.clone() {
            run.capture.error = Some(error.clone());
            run.storage_error(error);
        }
        self.replay_pre_ack(&mut run, cookie);
        if let Err(error) = run.persist_summary() {
            run.storage_error(format!("run metadata persistence failed: {error}"));
        }
        let summary = run.summary.clone();
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        session.runs.insert(cookie, run);
        session.update_runs(&mut self.snapshot);
        self.emit(Notification::RunStarted(summary));
        Ok(ack)
    }

    /// Hand the specimen of a run with static analysis selected to the analysis queue.
    fn submit_run_analysis(
        &mut self,
        request: &ExecRequest,
        run: &mut ProgramRun,
        reply: &[u8],
        shape: LaunchShape,
    ) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let timeout = GUEST_REPLY_TIMEOUT;
        let LaunchShape {
            specimen,
            supported,
            tracer_hashing,
            inline_acquisition,
        } = shape;
        if let Some(report) = run.summary.analysis.take() {
            let acquisition = if inline_acquisition {
                control::specimen_acquisition(
                    &reply[24..48],
                    specimen.unwrap_or(control::LEGACY_SPECIMEN_MAX_SIZE),
                )
            } else if supported {
                control::acquire(
                    &request.path,
                    request.uid,
                    request.gid,
                    specimen.unwrap_or(control::LEGACY_SPECIMEN_MAX_SIZE),
                )
                .and_then(|args| {
                    session.request(
                        control::ACQUIRE,
                        &args,
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    )
                })
                .and_then(|reply| {
                    control::specimen_acquisition(
                        &reply,
                        specimen.unwrap_or(control::LEGACY_SPECIMEN_MAX_SIZE),
                    )
                })
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
            // Only a guest that hashes the executed file can vouch for
            // the host's copy; any other falls back to the transfer.
            if let (Some(source), Some(report)) = (&request.host_copy, &run.summary.analysis)
                && tracer_hashing & control::EXEC_HASH_ROOT != 0
            {
                // A refusal leaves the guest transfer as it was.
                let _ = session.analysis.offer_host_copy(&report.id, source);
            }
            if let Err(error) = run.refresh_analysis_metadata() {
                run.storage_error(format!("analysis metadata accounting: {error}"));
            }
        }
    }

    /// Feed the run the telemetry that arrived before its launch was acknowledged.
    fn replay_pre_ack(&mut self, run: &mut ProgramRun, cookie: u64) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        // Telemetry that arrived before this launch was acknowledged.
        let claim = session.pre_ack.claim(cookie, Instant::now());
        for packet in claim.packets {
            if let Ok((header, _)) = crate::parser::parse_packet(&packet) {
                run.observe_clock(header.timestamp_ns);
                run.telemetry_loss
                    .packet(header.task_cookie, header.packet_seq);
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
            match run.assembler.ingest(&packet) {
                Ok(event) => {
                    if let Some(hash) = event.as_ref().and_then(launch_image_hash) {
                        session
                            .analysis
                            .guest_hash(&run.summary.id, hash.sha256_hex().as_deref());
                    }
                }
                Err(error) => self.snapshot.last_error = Some(error.to_string()),
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
    }

    /// Answer the launch; with Debug on start, attach the debugger to the parked program.
    fn report_launch(
        &mut self,
        request: &ExecRequest,
        ack: Launched,
        boot_id: String,
    ) -> Result<String, String> {
        let timeout = GUEST_REPLY_TIMEOUT;
        let Launched {
            reply,
            id,
            cookie,
            pid,
            shape,
        } = ack;
        let inline_acquisition = shape.inline_acquisition;
        let launched = format!("launched pid {pid}, terminal session {id}");
        if !request.debug_on_start {
            return Ok(launched);
        }
        // The guest parked the new program before its first instruction;
        // the debugger takes over that session.
        let start_offset =
            24 + usize::from(inline_acquisition) * 24 + usize::from(request.core_dump_on_exit) * 24;
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
                    let _ =
                        session.request(0x1015, &args, &mut self.snapshot, &self.sender, timeout);
                }
                let message = format!(
                    "{launched}, but the debugger could not attach ({error}); the program was stopped"
                );
                self.snapshot.last_error = Some(message.clone());
                Ok(message)
            }
        }
    }
}
