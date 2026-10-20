// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Guest resource producers on the single backend transport owner: the kernel's
//! RESOURCES command (revision 17 and later) or, for older bases, the temporary
//! guest collector controls.
use super::*;

impl Session {
    pub(super) fn start_guest_resources(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        stopping: &AtomicBool,
    ) -> Result<(), String> {
        let path = format!("/tmp/.antinomie-resource-{}", self.guest_resources.token);
        if !self.guest_resources.uploaded {
            // INFO can arrive before init mounts the real root and creates /tmp.
            // Retry only a definite Begin rejection: no file/transfer was admitted.
            let reply = match self.request_typed(
                control::UPLOAD_BEGIN,
                &control::upload_begin(
                    &path,
                    crate::guest_resources::EXECUTABLE.len() as u64,
                    false,
                    true,
                )?,
                snapshot,
                sender,
                Duration::from_secs(2),
            ) {
                Ok(reply) => reply,
                Err(error) => {
                    if matches!(error, RequestError::Rejected { status: -2, .. }) {
                        self.guest_resources.defer_boot_readiness(Instant::now());
                    }
                    return Err(format!(
                        "{}; collector upload path {path}",
                        error.into_message()
                    ));
                }
            };
            if reply.len() != 8 {
                return Err("invalid collector upload begin reply; outcome unknown".into());
            }
            let upload = u64_at(&reply, 0).map_err(|error| error.to_string())?;
            let mut executable = crate::guest_resources::EXECUTABLE;
            upload_contents(
                self,
                snapshot,
                sender,
                stopping,
                Duration::from_secs(2),
                &mut executable,
                crate::guest_resources::EXECUTABLE.len() as u64,
                &path,
                upload,
            )
            .map_err(|error| format!("{error}; collector upload path {path}"))?;
            self.guest_resources.uploaded = true;
        }
        let request = ExecRequest {
            path,
            args: vec![self.guest_resources.token.clone()],
            cwd: "/".into(),
            env: Vec::new(),
            uid: 0,
            gid: 0,
            analysis: Default::default(),
            run_in: Default::default(),
            capture_network: false,
            memory_dump_on_exit: false,
            core_dump_on_exit: false,
            debug_on_start: false,
        };
        let reply = match self.request_typed(
            control::EXEC,
            &control::execute(&request)?,
            snapshot,
            sender,
            Duration::from_secs(2),
        ) {
            Ok(reply) => reply,
            Err(error) => {
                // UMH_WAIT_EXEC rejection proves the collector did not exec.
                // /dev/ptmx can appear after /tmp; retain the committed file and
                // retry only this known rejection, never a timeout/unknown launch.
                if matches!(error, RequestError::Rejected { status: -2, .. }) {
                    self.guest_resources.defer_boot_readiness(Instant::now());
                }
                self.guest_resources.launch_uncertain =
                    !matches!(error, RequestError::Rejected { .. });
                return Err(format!(
                    "{}; uploaded collector path {}",
                    error.into_message(),
                    request.path
                ));
            }
        };
        if reply.len() != 24 || u32_at(&reply, 20).map_err(|e| e.to_string())? != 0 {
            self.guest_resources.launch_uncertain = true;
            return Err("invalid resource collector launch reply; outcome unknown".into());
        }
        let terminal = u64_at(&reply, 0).map_err(|e| e.to_string())?;
        let cookie = u64_at(&reply, 8).map_err(|e| e.to_string())?;
        let pid = u32_at(&reply, 16).map_err(|e| e.to_string())?;
        if terminal == 0 || cookie == 0 || pid == 0 {
            self.guest_resources.launch_uncertain = true;
            return Err("resource collector has invalid process/terminal identity".into());
        }
        self.guest_resources.pid = pid;
        self.guest_resources.cookie = cookie;
        // Packets of the collector that arrived before its reply will never be claimed.
        self.pre_ack.discard(cookie);
        self.guest_resources.started(terminal);
        Ok(())
    }
    /// Confirm terminal EOF before serializing a snapshot; never snapshot a helper
    /// whose future host owner is absent from the checkpoint.
    pub(super) fn stop_guest_resources(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        self.kernel_resources.reset_timeline();
        if let Some(terminal) = self.guest_resources.terminal {
            self.guest_resources
                .fail("guest resource collector stopping at timeline boundary".into());
            // After an external snapshot restore a numeric terminal/PID can be
            // reused. Check the collector's cookie and opaque comm token before
            // sending a signal; never signal/read an unrelated restored terminal.
            let pid = self.guest_resources.pid;
            let reply = self.request(
                control::PROCESS_LIST,
                &control::process_list(pid.saturating_sub(1)),
                snapshot,
                sender,
                Duration::from_secs(2),
            )?;
            let page = control::process_page(&reply, &self.boot_id, pid.saturating_sub(1))?;
            let matches = page
                .processes
                .first()
                .map(|process| self.guest_resources.owns_process(process))
                .transpose()?
                .unwrap_or(false);
            if !matches {
                self.guest_resources = crate::guest_resources::Collector::default();
                snapshot.vm_resources = None;
                return Ok(());
            }
            let mut args = control::with_session(terminal);
            args.extend(9u32.to_le_bytes());
            args.extend(0u32.to_le_bytes());
            match self.request_typed(
                control::SIGNAL,
                &args,
                snapshot,
                sender,
                Duration::from_secs(2),
            ) {
                Ok(_) | Err(RequestError::Rejected { status: -3, .. }) => {}
                Err(error) => {
                    return Err(format!(
                        "resource collector cleanup: {}",
                        error.into_message()
                    ));
                }
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("resource collector cleanup: EOF deadline exhausted".into());
                }
                let mut args = control::with_session(terminal);
                args.extend(4096u32.to_le_bytes());
                args.extend(0u32.to_le_bytes());
                match self.request_typed(control::READ, &args, snapshot, sender, remaining) {
                    Ok(reply) if crate::guest_resources::terminal_data(&reply)?.1 => break,
                    Ok(_) => {
                        self.transport.poll(10)?;
                    }
                    Err(RequestError::Rejected { status: -2, .. }) => break,
                    Err(error) => {
                        return Err(format!("resource collector EOF: {}", error.into_message()));
                    }
                }
            }
        } else if self.guest_resources.launch_uncertain {
            // An unacknowledged EXEC could own a process. Refuse snapshots until
            // a reconnect/VM restart resolves that uncertainty; no effect replay.
            return Err("resource collector launch was not acknowledged; restart the VM before snapshotting".into());
        }
        self.guest_resources = crate::guest_resources::Collector::default();
        snapshot.vm_resources = None;
        Ok(())
    }
}

impl Worker {
    pub(super) fn check_guest_resources(&mut self) {
        if self.reconnect.1.is_some()
            || self.snapshot.memory_dump.is_some()
            || self.snapshot.state != VmState::Running
        {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        // INFO establishes control support, but does not certify userspace readiness.
        let Some(kernel) = self.snapshot.guest_kernel.as_ref() else {
            return;
        };
        if crate::kernel_resources::kernel_produces(Some(kernel)) {
            self.poll_kernel_resources();
            return;
        }
        if !kernel.revision.is_some_and(|revision| revision >= 11) {
            session.guest_resources.attempted = true;
            session.guest_resources.fail(
                "guest resource monitoring requires revision-11 process identity controls or newer"
                    .into(),
            );
            return;
        }
        if session.guest_resources.ready_to_start(Instant::now()) {
            session.guest_resources.begin_attempt();
            if let Err(error) =
                session.start_guest_resources(&mut self.snapshot, &self.sender, &self.stopping)
            {
                session
                    .guest_resources
                    .fail(format!("guest resource collector: {error}"));
            }
        }
        if let Err(error) = session.drain_replies(&mut self.snapshot, &self.sender) {
            session
                .guest_resources
                .fail(format!("guest resource transport: {error}"));
            return;
        }
        let now = Instant::now();
        if let Some((opcode, args)) = session.guest_resources.command(now) {
            match session.transport.send(opcode, &args) {
                Ok(id) => session
                    .guest_resources
                    .submitted(id, opcode, args.len(), now),
                Err(error) => session
                    .guest_resources
                    .fail(format!("guest resource submit: {error}")),
            }
        }
    }
}

impl Worker {
    /// Kernel-native path: no guest process, upload or terminal is involved.
    fn poll_kernel_resources(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if let Err(error) = session.drain_replies(&mut self.snapshot, &self.sender) {
            session
                .kernel_resources
                .submit_failed(format!("guest resource transport: {error}"), Instant::now());
            return;
        }
        let now = Instant::now();
        if let Some((opcode, args)) = session.kernel_resources.command(now) {
            match session.transport.send(opcode, &args) {
                Ok(id) => session.kernel_resources.submitted(id, now),
                Err(error) => session
                    .kernel_resources
                    .submit_failed(format!("guest resource submit: {error}"), now),
            }
        }
    }
}
