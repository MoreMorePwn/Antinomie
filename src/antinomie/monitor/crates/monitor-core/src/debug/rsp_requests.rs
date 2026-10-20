// SPDX-License-Identifier: MIT
//! The request handlers of an RSP client session that read and change the
//! target: stop status, thread selection, registers, memory, breakpoints and
//! the queries (`qSupported`, target description, thread list). The session
//! loop, stop replies and resuming are in `rsp_client.rs`.
use super::{
    debugger::Happening,
    inferior::{RunState, hardware_pieces},
    rsp_client::{
        ALL_PROCESSES, PACKET_BUFFER, Reply, Sel, Session, TidSel, Wire, errno, ok, parse_sel,
        report, text, unsupported,
    },
    rsp_packet::{from_hex, parse_hex, to_hex},
    target::{DebugError, StopKind, ThreadInfo},
    view::{BreakpointKind, WatchAccess},
};

impl<W: Wire> Session<'_, W> {
    // ---- ? and thread selection -----------------------------------------------------

    pub(super) fn status(&mut self) -> Result<Reply, DebugError> {
        if self.client.nonstop {
            // The stopped threads are reported through the notification queue: the
            // first one answers, vStopped brings the rest, OK says there is no more.
            self.queue_initial_stops()?;
            let first = self.client.queue.pop_front();
            self.client.deferred.extend(self.client.queue.drain(..));
            return Ok(match first {
                Some(first) => {
                    self.client.held = Some(first.clone());
                    Reply::Packet(first)
                }
                None => ok(),
            });
        }
        let Some(pid) = self.target_pid() else {
            return Ok(text("W00"));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(text("W00"));
        };
        // A fork, exec or vfork that cut the stop at connect cannot happen again:
        // it is what the client must be told about, not a bare stop.
        if let (RunState::Stopped(event), true) = (inferior.run, inferior.unreported)
            && matches!(
                event.kind,
                StopKind::Fork { .. }
                    | StopKind::Vfork { .. }
                    | StopKind::VforkDone { .. }
                    | StopKind::Exec
            )
        {
            inferior.unreported = false;
            let payload = self.stop_reply(&Happening::Stopped { pid, event });
            return Ok(Reply::Packet(payload));
        }
        let tid = inferior.current_tid;
        let thread = self.thread_text(pid, tid);
        Ok(text(format!("T05thread:{thread};")))
    }

    /// One report per thread that sits stopped, once, when a non-stop client asks.
    pub(super) fn queue_initial_stops(&mut self) -> Result<(), DebugError> {
        if self.client.held.is_some() || !self.client.queue.is_empty() {
            return Ok(());
        }
        for pid in self.debugger.pids() {
            let threads = match self.debugger.get(pid) {
                Some(inferior) if inferior.is_live() => inferior.threads()?,
                _ => continue,
            };
            for thread in threads.iter().filter(|thread| thread.stopped) {
                // Stopped, not by a trap: signal 0, which gdb reads as "stopped".
                let reply = format!("T00thread:{};", self.thread_text(pid, thread.tid));
                self.client.queue.push_back(reply.into_bytes());
            }
        }
        Ok(())
    }

    /// The client has started up: the stops held back may be announced.
    pub(super) fn release_deferred(&mut self) {
        let waiting = std::mem::take(&mut self.client.deferred);
        self.client.queue.extend(waiting);
    }

    pub(super) fn next_notification(&mut self) -> Reply {
        self.client.held = None;
        match self.client.queue.pop_front() {
            Some(next) => {
                self.client.held = Some(next.clone());
                Reply::Packet(next)
            }
            None => ok(),
        }
    }

    pub(super) fn select_thread(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let (Some(&op), Some(sel)) = (rest.first(), parse_sel(&rest[1..])) else {
            return Ok(errno(22));
        };
        match op {
            b'g' => {
                self.client.general = sel;
                if let Some(pid) = sel.pid.filter(|pid| *pid != ALL_PROCESSES)
                    && self.debugger.inferiors.contains_key(&pid)
                {
                    self.debugger.current = pid;
                }
                Ok(ok())
            }
            b'c' => Ok(ok()),
            _ => Ok(errno(22)),
        }
    }

    pub(super) fn thread_alive(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let Some(Sel {
            pid,
            tid: TidSel::One(tid),
        }) = parse_sel(rest)
        else {
            return Ok(errno(1));
        };
        let owner = match pid {
            Some(pid) if pid != ALL_PROCESSES => Some(pid),
            _ => self.debugger.owner_of(tid),
        };
        let Some(inferior) = owner.and_then(|pid| self.debugger.get(pid)) else {
            return Ok(errno(1));
        };
        match inferior.threads() {
            Ok(threads) if threads.iter().any(|thread| thread.tid == tid) => Ok(ok()),
            Ok(_) => Ok(errno(1)),
            Err(error) => report(error),
        }
    }

    // ---- registers and memory -----------------------------------------------------------

    pub(super) fn read_registers(&mut self) -> Result<Reply, DebugError> {
        let Some(pid) = self.target_pid() else {
            return Ok(errno(3));
        };
        let Some(tid) = self.target_tid(pid) else {
            return Ok(errno(3));
        };
        match self
            .debugger
            .get(pid)
            .map(|inferior| inferior.register_image(tid))
        {
            Some(Ok(image)) => Ok(text(to_hex(&image))),
            Some(Err(error)) => report(error),
            None => Ok(errno(3)),
        }
    }

    pub(super) fn write_registers(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let Some(image) = from_hex(rest) else {
            return Ok(errno(22));
        };
        let Some(pid) = self.target_pid() else {
            return Ok(errno(3));
        };
        let Some(tid) = self.target_tid(pid) else {
            return Ok(errno(3));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(errno(3));
        };
        if image.len() != inferior.description().image_len() {
            // A protocol violation: nothing is half applied, the session ends.
            return Err(DebugError::Invalid(
                "register image of the wrong size".into(),
            ));
        }
        match inferior.write_register_image(tid, &image) {
            Ok(()) => Ok(ok()),
            Err(error) => report(error),
        }
    }

    pub(super) fn read_register(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let Some(index) = parse_hex(rest).and_then(|n| usize::try_from(n).ok()) else {
            return Ok(errno(22));
        };
        let Some(pid) = self.target_pid() else {
            return Ok(errno(3));
        };
        let Some(tid) = self.target_tid(pid) else {
            return Ok(errno(3));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(errno(3));
        };
        let description = inferior.description();
        let Some(register) = description.regs.get(index) else {
            return Ok(errno(22));
        };
        let offset: usize = description.regs[..index].iter().map(|r| r.bytes()).sum();
        match inferior.register_image(tid) {
            Ok(image) => Ok(text(to_hex(&image[offset..offset + register.bytes()]))),
            Err(error) => report(error),
        }
    }

    pub(super) fn write_register(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let Some(equals) = rest.iter().position(|byte| *byte == b'=') else {
            return Ok(errno(22));
        };
        let (Some(index), Some(bytes)) = (
            parse_hex(&rest[..equals]).and_then(|n| usize::try_from(n).ok()),
            from_hex(&rest[equals + 1..]),
        ) else {
            return Ok(errno(22));
        };
        let Some(pid) = self.target_pid() else {
            return Ok(errno(3));
        };
        let Some(tid) = self.target_tid(pid) else {
            return Ok(errno(3));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(errno(3));
        };
        let description = inferior.description();
        let Some(register) = description.regs.get(index) else {
            return Ok(errno(22));
        };
        if bytes.len() != register.bytes() {
            return Ok(errno(22));
        }
        let offset: usize = description.regs[..index].iter().map(|r| r.bytes()).sum();
        let mut image = match inferior.register_image(tid) {
            Ok(image) => image,
            Err(error) => return report(error),
        };
        image[offset..offset + bytes.len()].copy_from_slice(&bytes);
        match inferior.write_register_image(tid, &image) {
            Ok(()) => Ok(ok()),
            Err(error) => report(error),
        }
    }

    /// `addr,len` as two hexadecimal numbers.
    pub(super) fn parse_range(text: &[u8]) -> Option<(u64, usize)> {
        let comma = text.iter().position(|byte| *byte == b',')?;
        Some((
            parse_hex(&text[..comma])?,
            usize::try_from(parse_hex(&text[comma + 1..])?).ok()?,
        ))
    }

    pub(super) fn read_memory(&mut self, rest: &[u8]) -> Result<Reply, DebugError> {
        let Some((addr, len)) = Self::parse_range(rest) else {
            return Ok(errno(22));
        };
        // A reply is hex in a packet: never ask for more than one can carry.
        let len = len.min(PACKET_BUFFER / 2 - 8);
        if len == 0 {
            return Ok(text(""));
        }
        match self.with_inferior(|inferior| inferior.backend.read_memory(addr, len))? {
            Ok(bytes) => Ok(text(to_hex(&bytes))),
            Err(error) => report(error),
        }
    }

    pub(super) fn write_memory(&mut self, rest: &[u8], binary: bool) -> Result<Reply, DebugError> {
        let Some(colon) = rest.iter().position(|byte| *byte == b':') else {
            return Ok(errno(22));
        };
        let Some((addr, len)) = Self::parse_range(&rest[..colon]) else {
            return Ok(errno(22));
        };
        let data = if binary {
            rest[colon + 1..].to_vec()
        } else if let Some(bytes) = from_hex(&rest[colon + 1..]) {
            bytes
        } else {
            return Ok(errno(22));
        };
        if data.len() != len {
            return Ok(errno(22));
        }
        if data.is_empty() {
            return Ok(ok());
        }
        let result = self.with_inferior(|inferior| {
            let result = inferior.backend.write_memory(addr, &data);
            inferior.invalidate();
            result
        })?;
        match result {
            Ok(()) => Ok(ok()),
            Err(error) => report(error),
        }
    }

    // ---- breakpoints -------------------------------------------------------------------

    pub(super) fn breakpoint(&mut self, rest: &[u8], set: bool) -> Result<Reply, DebugError> {
        let mut fields = rest.splitn(3, |byte| *byte == b',');
        let (Some(kind), Some(addr), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            return Ok(errno(22));
        };
        // Conditions and commands after the length are the client's business.
        let size = size.split(|byte| *byte == b';').next().unwrap_or(size);
        let (Some(addr), Some(size)) = (parse_hex(addr), parse_hex(size)) else {
            return Ok(errno(22));
        };
        let kind = match kind {
            b"0" => BreakpointKind::Software,
            b"1" => BreakpointKind::Hardware,
            b"2" => BreakpointKind::Watch(WatchAccess::Write),
            b"4" => BreakpointKind::Watch(WatchAccess::Access),
            // Read watchpoints: the debug registers cannot do them.
            _ => return Ok(unsupported()),
        };
        let Some(pid) = self.target_pid() else {
            return Ok(errno(3));
        };
        let Some(inferior) = self.debugger.get(pid) else {
            return Ok(errno(3));
        };
        let caps = inferior.backend.caps();
        match kind {
            BreakpointKind::Software if !caps.software_breakpoints => return Ok(unsupported()),
            BreakpointKind::Hardware if caps.hardware_breakpoints == 0 => return Ok(unsupported()),
            BreakpointKind::Watch(_) if caps.hardware_watchpoints == 0 => return Ok(unsupported()),
            _ => {}
        }
        if matches!(kind, BreakpointKind::Watch(_)) && (size == 0 || size > 4096) {
            return Ok(errno(22));
        }
        let pieces: Vec<(u64, u32)> = match kind {
            BreakpointKind::Software => vec![(addr, u32::try_from(size).unwrap_or(1))],
            other => hardware_pieces(other, addr, size),
        };
        let outcome = inferior.with_registry(|registry, backend| -> Result<bool, DebugError> {
            let mut done = 0;
            let mut found = false;
            for (start, len) in &pieces {
                let step = match (kind, set) {
                    (BreakpointKind::Software, true) => {
                        registry.client_add_sw(backend, *start, *len).map(|()| true)
                    }
                    (BreakpointKind::Software, false) => {
                        registry.client_remove_sw(backend, *start, *len)
                    }
                    (other, true) => registry
                        .client_add_hw(backend, other, *start, *len)
                        .map(|()| true),
                    (other, false) => registry.client_remove_hw(backend, other, *start, *len),
                };
                match step {
                    Ok(was) => {
                        found |= was;
                        done += 1;
                    }
                    Err(error) => {
                        // Nothing is left half set.
                        if set {
                            for (start, len) in &pieces[..done] {
                                let _ = match kind {
                                    BreakpointKind::Software => {
                                        registry.client_remove_sw(backend, *start, *len)
                                    }
                                    other => {
                                        registry.client_remove_hw(backend, other, *start, *len)
                                    }
                                };
                            }
                        }
                        return Err(error);
                    }
                }
            }
            Ok(found)
        });
        match outcome {
            Ok(true) => Ok(ok()),
            Ok(false) => Ok(errno(22)),
            Err(error) => report(error),
        }
    }

    // ---- queries -------------------------------------------------------------------------------

    pub(super) fn query(&mut self, packet: &[u8]) -> Result<Reply, DebugError> {
        if let Some(features) = packet.strip_prefix(b"qSupported") {
            return self.supported(features);
        }
        if packet == b"qC" {
            let Some(pid) = self.target_pid() else {
                return Ok(unsupported());
            };
            let tid = self.debugger.get(pid).map_or(pid, |i| i.current_tid);
            return Ok(text(format!("QC{}", self.thread_text(pid, tid))));
        }
        if packet.starts_with(b"qAttached") {
            return Ok(text("1"));
        }
        if packet == b"qfThreadInfo" {
            return self.thread_list();
        }
        if packet == b"qsThreadInfo" {
            return Ok(text("l"));
        }
        if let Some(arg) = packet.strip_prefix(b"qThreadExtraInfo,") {
            return Ok(self.thread_extra_info(arg));
        }
        if packet.starts_with(b"qSymbol") {
            self.release_deferred();
            return Ok(ok());
        }
        if let Some(rest) = packet.strip_prefix(b"qXfer:features:read:target.xml:") {
            let xml = match self.target_pid().and_then(|pid| self.debugger.get(pid)) {
                Some(inferior) => inferior.description().xml(),
                None => return Ok(errno(3)),
            };
            return Ok(Self::xfer(xml.trim().as_bytes(), rest));
        }
        if let Some(rest) = packet.strip_prefix(b"qXfer:auxv:read::") {
            let auxv = self
                .target_pid()
                .and_then(|pid| self.debugger.get(pid))
                .and_then(|inferior| inferior.auxv.clone());
            return Ok(match auxv {
                Some(data) => Self::xfer(&data, rest),
                None => text("l"),
            });
        }
        Ok(unsupported())
    }

    pub(super) fn xfer(data: &[u8], range: &[u8]) -> Reply {
        let Some((offset, length)) = Self::parse_range(range) else {
            return errno(22);
        };
        let start = offset.min(data.len() as u64) as usize;
        let length = length.min(PACKET_BUFFER - 16);
        let end = start.saturating_add(length).min(data.len());
        let mut reply = Vec::with_capacity(end - start + 1);
        reply.push(if end < data.len() { b'm' } else { b'l' });
        reply.extend_from_slice(&data[start..end]);
        Reply::Packet(reply)
    }

    pub(super) fn supported(&mut self, features: &[u8]) -> Result<Reply, DebugError> {
        let features = features.strip_prefix(b":").unwrap_or(features);
        for feature in features.split(|byte| *byte == b';') {
            match feature {
                b"multiprocess+" => self.client.multiprocess = true,
                b"swbreak+" => self.client.swbreak = true,
                b"hwbreak+" => self.client.hwbreak = true,
                b"fork-events+" => self.client.fork_events = true,
                b"vfork-events+" => self.client.vfork_events = true,
                b"exec-events+" => self.client.exec_events = true,
                _ => {}
            }
        }
        let Some(inferior) = self.debugger.current_mut() else {
            return Ok(errno(3));
        };
        let caps = inferior.backend.caps().clone();
        let mut reply = format!("PacketSize={PACKET_BUFFER:x};QStartNoAckMode+;multiprocess+");
        if caps.software_breakpoints {
            reply.push_str(";swbreak+");
        }
        if caps.hardware_breakpoints > 0 {
            reply.push_str(";hwbreak+");
        }
        reply.push_str(";vContSupported+;qXfer:features:read+");
        if caps.auxv {
            reply.push_str(";qXfer:auxv:read+");
        }
        let follows =
            self.client.fork_events && self.client.vfork_events && self.client.exec_events;
        if caps.follow && follows {
            reply.push_str(";fork-events+;vfork-events+;exec-events+");
        }
        if caps.nonstop && caps.follow {
            reply.push_str(";QNonStop+");
        }
        // Following forks is decided now: the client says it can take the events.
        self.debugger.follow_forks(caps.follow && follows);
        Ok(text(reply))
    }

    pub(super) fn set(&mut self, packet: &[u8]) -> Result<Reply, DebugError> {
        if packet == b"QStartNoAckMode" {
            self.client.switch_to_no_ack = true;
            return Ok(ok());
        }
        if let Some(mode) = packet.strip_prefix(b"QNonStop:") {
            return self.set_nonstop(mode == b"1");
        }
        Ok(unsupported())
    }

    pub(super) fn set_nonstop(&mut self, on: bool) -> Result<Reply, DebugError> {
        if on == self.client.nonstop {
            return Ok(ok());
        }
        if self.debugger.any_running() {
            return Ok(errno(16));
        }
        match self.debugger.set_nonstop(on) {
            Ok(()) => {
                self.client.nonstop = on;
                self.client.waiting = false;
                Ok(ok())
            }
            Err(DebugError::Unsupported(_)) => Ok(unsupported()),
            Err(error) => report(error),
        }
    }

    pub(super) fn thread_list(&mut self) -> Result<Reply, DebugError> {
        let mut ids = Vec::new();
        for pid in self.debugger.pids() {
            let Some(inferior) = self.debugger.get(pid) else {
                continue;
            };
            if !inferior.is_live() {
                continue;
            }
            let threads: Vec<ThreadInfo> = match inferior.threads() {
                Ok(threads) => threads,
                Err(error) => return report(error),
            };
            for thread in threads {
                ids.push(self.thread_text(pid, thread.tid));
            }
        }
        if ids.is_empty() {
            return Ok(text("l"));
        }
        Ok(text(format!("m{}", ids.join(","))))
    }

    pub(super) fn thread_extra_info(&mut self, arg: &[u8]) -> Reply {
        let Some(Sel {
            tid: TidSel::One(tid),
            pid,
        }) = parse_sel(arg)
        else {
            return errno(22);
        };
        let owner = match pid {
            Some(pid) if pid != ALL_PROCESSES => Some(pid),
            _ => self.debugger.owner_of(tid),
        };
        let state = owner
            .and_then(|pid| self.debugger.get(pid))
            .and_then(|inferior| inferior.threads().ok())
            .and_then(|threads| threads.into_iter().find(|thread| thread.tid == tid))
            .map(|thread| if thread.stopped { "stopped" } else { "running" });
        match state {
            Some(state) => Reply::Packet(to_hex(state.as_bytes()).into_bytes()),
            None => errno(1),
        }
    }
}
