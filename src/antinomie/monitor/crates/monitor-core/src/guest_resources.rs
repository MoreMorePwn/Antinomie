// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Temporary guest producer ownership and bounded, authenticated-by-session framing.
//! Guest measurements are observations, not trusted against a compromised guest.
use crate::{api::GuestResources, control, storage};
use std::time::{Duration, Instant};

pub(crate) const EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guest-resources"));
const INTERVAL: Duration = Duration::from_secs(2);
const DEADLINE: Duration = Duration::from_secs(4);
const STALE: Duration = Duration::from_secs(6);
const OUTPUT_LIMIT: usize = 1024;

#[derive(Clone, Copy)]
enum ReplyKind {
    Input(usize),
    Read,
}
struct Pending {
    id: u64,
    kind: ReplyKind,
    submitted: Instant,
}

pub(crate) struct Collector {
    pub(crate) attempted: bool,
    pub(crate) terminal: Option<u64>,
    pub(crate) pid: u32,
    pub(crate) cookie: u64,
    pub(crate) token: String,
    pub(crate) launch_uncertain: bool,
    pending: Option<Pending>,
    restart_after: Option<Instant>,
    ready: bool,
    sequence: u64,
    sampling: Option<Instant>,
    next: Instant,
    output: Vec<u8>,
    last: Option<(GuestResources, Instant)>,
    pub(crate) error: Option<String>,
}
impl Default for Collector {
    fn default() -> Self {
        Self {
            attempted: false,
            terminal: None,
            pid: 0,
            cookie: 0,
            token: storage::unique_id(),
            launch_uncertain: false,
            pending: None,
            restart_after: None,
            ready: false,
            sequence: 0,
            sampling: None,
            next: Instant::now(),
            output: Vec::new(),
            last: None,
            error: None,
        }
    }
}
impl Collector {
    /// Numeric ids may be reused across an external snapshot restore. Verify the
    /// per-launch comm nonce before any destructive terminal control.
    pub(crate) fn owns_process(
        &self,
        process: &crate::observation::GuestProcess,
    ) -> Result<bool, String> {
        if process.identity.tgid != self.pid || process.identity.task_cookie != self.cookie {
            return Ok(false);
        }
        if process.command != self.token[..15] {
            return Err("guest resource process identity changed or collector is not ready; old terminal was not signalled".into());
        }
        Ok(true)
    }
    pub(crate) fn ready_to_start(&self, now: Instant) -> bool {
        !self.attempted || self.restart_after.is_some_and(|when| now >= when)
    }
    pub(crate) fn started(&mut self, terminal: u64) {
        self.terminal = Some(terminal);
        self.sampling = Some(Instant::now());
        self.next = Instant::now();
    }
    pub(crate) fn fail(&mut self, error: String) {
        self.error = Some(error);
        // Retain pending identity: a late read consumed guest output and must not
        // be routed to a program terminal or trigger another consuming request.
    }
    pub(crate) fn sample(&self, boot_id: &str, unavailable: bool) -> GuestResources {
        let (mut sample, age) = match &self.last {
            Some((sample, seen)) => (sample.clone(), Some(seen.elapsed())),
            None => (GuestResources::default(), None),
        };
        sample.boot_id = boot_id.into();
        sample.age_ms = age.map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX));
        sample.stale = unavailable || self.error.is_some() || age.is_none_or(|age| age > STALE);
        if let Some(error) = &self.error {
            sample.error = Some(error.clone());
        }
        sample
    }
    /// Return at most one new request; the owner assigns its transport id.
    pub(crate) fn command(&mut self, now: Instant) -> Option<(u32, Vec<u8>)> {
        if let Some(pending) = &self.pending {
            if now.duration_since(pending.submitted) > DEADLINE && self.error.is_none() {
                self.fail(
                    "guest resource request timed out; no consuming request was replayed".into(),
                );
            }
            return None;
        }
        if self.error.is_some() || now < self.next {
            return None;
        }
        let terminal = self.terminal?;
        if let Some(started) = self.sampling {
            if now.duration_since(started) > DEADLINE {
                self.fail("guest resource output timed out".into());
                return None;
            }
            let mut args = control::with_session(terminal);
            args.extend(4096u32.to_le_bytes());
            args.extend(0u32.to_le_bytes());
            Some((control::READ, args))
        } else {
            self.sequence = match self.sequence.checked_add(1) {
                Some(sequence) => sequence,
                None => {
                    self.fail("guest resource sequence exhausted".into());
                    return None;
                }
            };
            self.output.clear();
            self.sampling = Some(now);
            let mut args = control::with_session(terminal);
            args.extend(format!("{}\n", self.sequence).as_bytes());
            Some((control::INPUT, args))
        }
    }
    pub(crate) fn submitted(&mut self, id: u64, opcode: u32, size: usize, now: Instant) {
        self.pending = Some(Pending {
            id,
            kind: if opcode == control::INPUT {
                ReplyKind::Input(size - 16)
            } else {
                ReplyKind::Read
            },
            submitted: now,
        });
    }
    /// Consume only this producer's reply id, including late failed replies.
    pub(crate) fn reply(
        &mut self,
        id: u64,
        status: i32,
        payload: &[u8],
        boot_id: &str,
        now: Instant,
    ) -> bool {
        if self.pending.as_ref().is_none_or(|pending| pending.id != id) {
            return false;
        }
        let pending = self
            .pending
            .take()
            .expect("matched pending producer request");
        if self.error.is_some() {
            return true;
        }
        let result = (|| -> Result<(), String> {
            if status != 0 {
                return Err(format!("guest resource command rejected: {status}"));
            }
            match pending.kind {
                ReplyKind::Input(size) => {
                    if payload.len() != 8
                        || u64::from_le_bytes(
                            payload
                                .try_into()
                                .map_err(|_| "invalid resource input reply")?,
                        ) != size as u64
                    {
                        return Err("partial or invalid resource input reply".into());
                    }
                    self.next = now + Duration::from_millis(100);
                }
                ReplyKind::Read => {
                    let (data, eof) = terminal_data(payload)?;
                    if eof {
                        // EOF is authoritative cleanup; only then may an automatic
                        // restart follow (e.g. a long paused memory dump).
                        self.terminal = None;
                        self.restart_after = Some(now + Duration::from_secs(10));
                        return Err(
                            "guest resource collector exited; retrying after 10 seconds".into()
                        );
                    }
                    if self.output.len().saturating_add(data.len()) > OUTPUT_LIMIT {
                        return Err("guest resource output exceeds size limit".into());
                    }
                    self.output.extend(data);
                    if self.output.contains(&b'\n') {
                        if !self.ready {
                            let expected = format!("ANTREADY1 {}\n", self.token);
                            if self.output != expected.as_bytes() {
                                return Err("invalid guest resource ready handshake".into());
                            }
                            self.ready = true;
                            self.next = now;
                        } else {
                            let sample = parse(&self.output, &self.token, self.sequence, boot_id)?;
                            self.last = Some((sample, now));
                            self.next = now + INTERVAL;
                        }
                        self.sampling = None;
                        self.output.clear();
                    } else {
                        self.next = now + Duration::from_millis(100);
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.fail(error);
        }
        true
    }
}

pub(crate) fn terminal_data(payload: &[u8]) -> Result<(&[u8], bool), String> {
    let flags = payload
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("truncated resource terminal flags")?;
    let count = payload
        .get(4..8)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("truncated resource terminal length")? as usize;
    if flags & !1 != 0 || count > 4096 || payload.len() != 8 + count {
        return Err("invalid resource terminal reply".into());
    }
    Ok((&payload[8..], flags == 1))
}
fn parse(data: &[u8], token: &str, sequence: u64, boot_id: &str) -> Result<GuestResources, String> {
    if data.len() > OUTPUT_LIMIT
        || !data.ends_with(b"\n")
        || data[..data.len() - 1].contains(&b'\n')
    {
        return Err("invalid guest resource frame".into());
    }
    let text = std::str::from_utf8(data).map_err(|_| "invalid guest resource encoding")?;
    let fields: Vec<_> = text.split_ascii_whitespace().collect();
    if fields.len() != 11 || fields[0] != "ANTRES1" || fields[1] != token {
        return Err("guest resource version, session or field count mismatch".into());
    }
    let number = |index: usize| -> Result<u64, String> {
        if !fields[index].bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid guest resource number".into());
        }
        fields[index]
            .parse()
            .map_err(|_| "guest resource number overflow".into())
    };
    if number(2)? != sequence {
        return Err("guest resource sequence mismatch".into());
    }
    let mut result = GuestResources {
        boot_id: boot_id.into(),
        sample_sequence: sequence,
        ..GuestResources::default()
    };
    let mut issues = Vec::new();
    let mem_error = number(3)?;
    let (total, available) = (number(4)?, number(5)?);
    if mem_error != 0 {
        issues.push(format!(
            "guest /proc/meminfo unavailable (errno {mem_error})"
        ));
    } else if total == 0 || available > total {
        return Err("invalid guest memory capacities".into());
    } else {
        result.memory_total_size = Some(total);
        result.memory_available_size = Some(available);
        result.memory_used_size = Some(total - available);
    }
    let disk_error = number(6)?;
    let (blocks, free, available, fragment) = (number(7)?, number(8)?, number(9)?, number(10)?);
    if disk_error != 0 {
        issues.push(format!(
            "guest root statvfs unavailable (errno {disk_error})"
        ));
    } else if fragment == 0 || free > blocks || available > free {
        return Err("invalid guest filesystem capacities".into());
    } else {
        let size = |count: u64| {
            count
                .checked_mul(fragment)
                .ok_or("guest filesystem size overflow")
        };
        result.root_total_size = Some(size(blocks)?);
        result.root_free_size = Some(size(free)?);
        result.root_available_size = Some(size(available)?);
        result.root_used_size = Some(size(blocks - free)?);
    }
    if !issues.is_empty() {
        result.error = Some(issues.join("; "));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    fn frame() -> Vec<u8> {
        format!("ANTRES1 {TOKEN} 1 0 10240 4096 0 100 40 30 4096\n").into_bytes()
    }
    fn read(data: &[u8]) -> Vec<u8> {
        [
            0u32.to_le_bytes().as_slice(),
            (data.len() as u32).to_le_bytes().as_slice(),
            data,
        ]
        .concat()
    }
    #[test]
    fn reports_guest_memory_and_reserved_free_space_separately() {
        let value = parse(&frame(), TOKEN, 1, "boot").unwrap();
        assert_eq!(value.memory_used_size, Some(6144));
        assert_eq!(value.root_used_size, Some(60 * 4096));
        assert_eq!(value.root_available_size, Some(30 * 4096));
        assert_eq!(value.root_free_size, Some(40 * 4096));
        assert_eq!(value.boot_id, "boot");
    }
    #[test]
    fn rejects_foreign_sequence_malformed_bounds_and_overflow() {
        assert!(parse(&frame(), "other", 1, "boot").is_err());
        assert!(parse(&frame(), TOKEN, 2, "boot").is_err());
        for replacement in [
            "0 100 101 30 4096",
            "0 100 40 41 4096",
            "0 100 40 30 0",
            "0 18446744073709551615 40 30 4096",
        ] {
            let invalid = String::from_utf8(frame())
                .unwrap()
                .replace("0 100 40 30 4096", replacement);
            assert!(parse(invalid.as_bytes(), TOKEN, 1, "boot").is_err());
        }
        assert!(parse(&frame()[..20], TOKEN, 1, "boot").is_err());
        assert!(parse(&[frame(), frame()].concat(), TOKEN, 1, "boot").is_err());
    }
    #[test]
    fn errors_leave_independent_measurement_available() {
        let data = String::from_utf8(frame())
            .unwrap()
            .replace("1 0 10240 4096", "1 13 0 0");
        let value = parse(data.as_bytes(), TOKEN, 1, "boot").unwrap();
        assert!(value.memory_used_size.is_none());
        assert!(value.root_used_size.is_some());
        assert!(value.error.unwrap().contains("errno 13"));
    }
    #[test]
    fn fragments_are_bounded_and_only_matching_reply_can_advance() {
        let now = Instant::now();
        let mut collector = Collector {
            token: TOKEN.into(),
            ready: true,
            next: now,
            terminal: Some(7),
            ..Collector::default()
        };
        let (opcode, args) = collector.command(now).unwrap();
        collector.submitted(4, opcode, args.len(), now);
        assert!(collector.command(now + Duration::from_secs(1)).is_none());
        assert!(!collector.reply(99, 0, &2u64.to_le_bytes(), "boot", now));
        assert!(collector.reply(4, 0, &2u64.to_le_bytes(), "boot", now));
        for (id, data) in [(5, &frame()[..12]), (6, &frame()[12..])] {
            let (opcode, args) = collector.command(now + Duration::from_secs(1)).unwrap();
            collector.submitted(id, opcode, args.len(), now);
            assert!(collector.reply(id, 0, &read(data), "boot", now));
        }
        assert!(collector.error.is_none());
        assert_eq!(collector.sample("boot", false).memory_used_size, Some(6144));
        assert!(collector.sample("boot", true).stale);
    }
    #[test]
    fn timeout_never_replays_consuming_read_and_late_reply_is_owned() {
        let now = Instant::now();
        let mut collector = Collector {
            terminal: Some(7),
            sampling: Some(now),
            next: now,
            ..Collector::default()
        };
        let (opcode, args) = collector.command(now).unwrap();
        collector.submitted(4, opcode, args.len(), now);
        assert!(collector.command(now + Duration::from_secs(5)).is_none());
        assert!(collector.error.is_some());
        assert!(collector.reply(4, 0, &read(&frame()), "boot", now));
        assert!(collector.command(now + Duration::from_secs(6)).is_none());
        assert!(collector.sample("boot", false).memory_used_size.is_none());
    }
    #[test]
    fn ready_handshake_precedes_any_input_and_fences_foreign_output() {
        let mut collector = Collector {
            token: TOKEN.into(),
            ..Collector::default()
        };
        collector.started(7);
        let now = Instant::now();
        let (opcode, args) = collector.command(now).unwrap();
        assert_eq!(opcode, control::READ);
        collector.submitted(1, opcode, args.len(), now);
        let ready = format!("ANTREADY1 {TOKEN}\n");
        assert!(collector.reply(1, 0, &read(ready.as_bytes()), "boot", now));
        assert_eq!(collector.command(now).unwrap().0, control::INPUT);
        let mut foreign = Collector::default();
        foreign.started(8);
        let now = Instant::now();
        let (opcode, args) = foreign.command(now).unwrap();
        foreign.submitted(2, opcode, args.len(), now);
        assert!(foreign.reply(2, 0, &read(ready.as_bytes()), "boot", now));
        assert!(foreign.error.is_some());
        assert!(foreign.command(now).is_none());
    }
    #[test]
    fn only_acknowledged_eof_allows_delayed_restart() {
        let now = Instant::now();
        let mut collector = Collector {
            attempted: true,
            terminal: Some(7),
            next: now,
            sampling: Some(now),
            ..Collector::default()
        };
        let (opcode, args) = collector.command(now).unwrap();
        collector.submitted(1, opcode, args.len(), now);
        assert!(collector.reply(1, 0, &[1, 0, 0, 0, 0, 0, 0, 0], "boot", now));
        assert!(collector.terminal.is_none());
        assert!(!collector.ready_to_start(now + Duration::from_secs(9)));
        assert!(collector.ready_to_start(now + Duration::from_secs(10)));
        assert!(
            !Collector {
                attempted: true,
                error: Some("timeout".into()),
                ..Collector::default()
            }
            .ready_to_start(now)
        );
    }
    #[test]
    fn cleanup_never_authorizes_a_reused_or_foreign_process() {
        use crate::observation::{GuestProcess, GuestProcessIdentity};
        let collector = Collector {
            token: TOKEN.into(),
            pid: 12,
            cookie: 45,
            ..Collector::default()
        };
        let mut process = GuestProcess {
            identity: GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 45,
                tgid: 12,
                start_boot_ns: 1,
            },
            parent_tgid: 1,
            uid: 0,
            gid: 0,
            thread_count: 1,
            command: TOKEN[..15].into(),
        };
        assert!(collector.owns_process(&process).unwrap());
        process.identity.task_cookie = 46;
        assert!(!collector.owns_process(&process).unwrap());
        process.identity.task_cookie = 45;
        process.command = "other-program".into();
        assert!(collector.owns_process(&process).is_err());
        process.identity.tgid = 13;
        assert!(!collector.owns_process(&process).unwrap());
    }
    #[test]
    fn terminal_length_and_flags_are_validated() {
        assert!(terminal_data(&[0; 7]).is_err());
        assert!(terminal_data(&[2, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(terminal_data(&[0, 0, 0, 0, 1, 0, 0, 0]).is_err());
    }
}
