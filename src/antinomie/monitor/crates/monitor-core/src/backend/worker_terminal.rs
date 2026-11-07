// SPDX-License-Identifier: GPL-3.0-only
//! Commands on a running guest's terminals and runs: input, size, signals, stop and counters.
use super::worker_guest::GUEST_REPLY_TIMEOUT;
use super::*;

impl Worker {
    /// Write typed bytes to a run's terminal.
    pub(super) fn terminal_input(
        &mut self,
        run_id: String,
        data: Vec<u8>,
    ) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
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
        if let Some(log) = session
            .runs
            .get_mut(&cookie)
            .and_then(|run| run.custody.as_mut())
        {
            log.typed(&data);
        }
        Ok(format!("terminal input accepted {written} bytes"))
    }

    /// Size a run's terminal.
    pub(super) fn terminal_resize(
        &mut self,
        run_id: String,
        rows: u16,
        cols: u16,
    ) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
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

    /// Send a signal to a run's process group.
    pub(super) fn signal_run(&mut self, run_id: String, signal: u32) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
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
        if let Some(log) = session
            .runs
            .get_mut(&cookie)
            .and_then(|run| run.custody.as_mut())
        {
            log.action(
                crate::samples::ActionKind::Kill,
                &format!("signal {signal} sent to process group {current_pid}"),
            );
        }
        Ok(format!(
            "signal {signal} sent to process group {current_pid}"
        ))
    }

    /// Ask the guest to end a run: SIGTERM, then SIGKILL on a guest that escalates.
    pub(super) fn stop_run(&mut self, run_id: String) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
        let cookie = session.run_cookie(&run_id)?;
        let run = session.runs.get(&cookie).ok_or("unknown run")?;
        if !run.summary.state.can_stop() {
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
        let reply = session.request(0x1015, &args, &mut self.snapshot, &self.sender, timeout)?;
        if !reply.is_empty() {
            return Err("invalid stop-run acknowledgement".into());
        }
        let run = session.runs.get_mut(&cookie).ok_or("unknown run")?;
        run.summary.state = RunState::StopRequested;
        run.summary.stopped_by_user = true;
        if let Some(log) = run.custody.as_mut() {
            log.action(
                crate::samples::ActionKind::Kill,
                "Stop: SIGTERM issued to the run",
            );
        }
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

    /// Read the guest recorder counters.
    pub(super) fn recorder_stats(&mut self) -> Result<String, String> {
        let session = self.session.as_mut().ok_or("VM is stopped")?;
        let timeout = GUEST_REPLY_TIMEOUT;
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
}
