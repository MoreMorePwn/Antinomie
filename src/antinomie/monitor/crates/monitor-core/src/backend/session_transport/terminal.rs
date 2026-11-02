// SPDX-License-Identifier: GPL-3.0-only
//! Reading the guest terminal and applying its replies (moved out of `session_transport`).
use super::*;

impl Session {
    /// Read what the run's terminal has, until it has no more, a pass bound is
    /// reached ([`TERMINAL_PASS_SIZE`] bytes, [`TERMINAL_PASS_SLICE`] of time)
    /// or the guest is late. One 4 KiB read per pass capped a chatty program
    /// at the pass rate (about 200 KB/s); a full read means more is waiting,
    /// so the next one follows at once. The bound keeps other runs, commands
    /// and the telemetry drain from waiting for one noisy terminal.
    pub(in crate::backend) fn read_terminal(
        &mut self,
        run_id: &str,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<(), String> {
        self.terminal_backlog.flush(sender);
        drain_pass(timeout, |left| {
            self.read_terminal_once(run_id, snapshot, sender, left)
        })
    }
    pub(super) fn read_terminal_once(
        &mut self,
        run_id: &str,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        timeout: Duration,
    ) -> Result<TerminalRead, String> {
        let cookie = self.run_cookie(run_id)?;
        let run = self.runs.get(&cookie).ok_or("unknown run")?;
        if run.summary.terminal_eof {
            return Ok(TerminalRead::default());
        }
        // Debug builds can force short deadlines to exercise late replies.
        #[cfg(debug_assertions)]
        let timeout = std::env::var("ANTINOMIE_TEST_TERMINAL_READ_TIMEOUT_US")
            .ok()
            .and_then(|value| value.parse().ok())
            .map_or(timeout, Duration::from_micros);
        if timeout.is_zero() {
            return Err("guest command deadline exhausted before submission".into());
        }
        let session_id = run.summary.session_id;
        // At most one READ per run is outstanding. While an earlier reply is late,
        // spend this budget waiting for it instead of queueing more reads.
        let deadline = Instant::now() + timeout;
        while self.late_reads.values().any(|&pending| pending == cookie) {
            self.drain_replies(snapshot, sender)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !self.late_reads.values().any(|&pending| pending == cookie) {
                break;
            }
            if remaining.is_zero() {
                return Ok(TerminalRead::default());
            }
            self.transport.poll(remaining.as_millis().min(10) as i32)?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let run = self.runs.get(&cookie).ok_or("unknown run")?;
        if run.summary.terminal_eof || remaining.is_zero() {
            return Ok(TerminalRead::default());
        }
        let mut args = control::with_session(session_id);
        args.extend((TERMINAL_READ_SIZE as u32).to_le_bytes());
        args.extend(0u32.to_le_bytes());
        let id = self.transport.send(control::READ, &args)?;
        // A late reply is applied when it comes (`late_reads`): no grace here.
        match self.wait_reply_in(id, control::READ, snapshot, sender, remaining, false) {
            Ok(reply) => self.apply_terminal_reply(cookie, 0, &reply, snapshot, sender),
            Err(RequestError::TimedOut(_)) => {
                // The guest may already have consumed output for this reply; keep
                // the id so the reply is applied when it arrives.
                self.late_reads.insert(id, cookie);
                Ok(TerminalRead::default())
            }
            Err(RequestError::Failed(error) | RequestError::Rejected { message: error, .. }) => {
                Err(error)
            }
        }
    }
    pub(super) fn apply_terminal_reply(
        &mut self,
        cookie: u64,
        status: i32,
        reply: &[u8],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<TerminalRead, String> {
        if status != 0 {
            return Err(format!("terminal read returned status {status}"));
        }
        let flags = u32_at(reply, 0).map_err(|e| e.to_string())?;
        let count = u32_at(reply, 4).map_err(|e| e.to_string())? as usize;
        if reply.len() != 8 + count || count > TERMINAL_READ_SIZE || flags & !1 != 0 {
            return Err("invalid terminal read reply".into());
        }
        let available = self.available();
        let run = self.runs.get_mut(&cookie).ok_or("unknown run")?;
        let mut persistence_error = None;
        if count > 0
            && let Err(error) = run.output(&reply[8..], available)
        {
            persistence_error = Some(error);
        }
        let available = available.saturating_sub(if count > 0 { count as u64 * 2 + 5 } else { 0 });
        let eof = flags & 1 != 0;
        if eof && count == 0 {
            run.sequence = run.sequence.saturating_add(1);
        }
        if eof
            && let Err(error) = run
                .eof(available)
                .and_then(|_| run.save_screen(available.saturating_sub(5)))
        {
            persistence_error = Some(error);
        }
        let failure = persistence_error.map(|error| terminal_failure(run, error));
        let sequence = run.sequence;
        let run_id = run.summary.id.clone();
        match failure {
            // A terminal write that fails stops saving for this run only; the boot
            // keeps recording everything else. The first cause stays the one
            // reported.
            Some(TerminalFailure::RunOnly(cause)) => {
                snapshot.health.persistence_error.get_or_insert(cause);
            }
            // Only the quota, which every recording shares, stops the boot.
            Some(TerminalFailure::Quota(cause)) => {
                self.quota_reached(cookie);
                snapshot.health.persistence_error.get_or_insert(cause);
            }
            None => {}
        }
        if count > 0 || eof {
            let dropped = self.terminal_backlog.send(
                sender,
                Notification::Terminal {
                    run_id,
                    sequence,
                    data: reply[8..].to_vec(),
                    eof,
                },
                count,
            );
            snapshot.health.ui_dropped = snapshot.health.ui_dropped.saturating_add(dropped);
        }
        Ok(TerminalRead {
            len: count,
            full: count == TERMINAL_READ_SIZE && !eof,
        })
    }
}
