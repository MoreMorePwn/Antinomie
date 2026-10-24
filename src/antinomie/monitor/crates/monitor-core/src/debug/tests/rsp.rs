// SPDX-License-Identifier: GPL-3.0-only
//! The RSP server against a mock backend, over its real Unix socket and TCP
//! port. Packets are written by hand so these tests pin the exact replies a
//! debugger sees, independent of the server's own packet code.
use crate::debug::{
    ArchTag, BreakpointKind, DebugBackend, DebugCaps, DebugError, DebugServer, DetachMode,
    RegsetBlob, RegsetInfo, ResumeAction, StopEvent, StopKind, TargetState, ThreadInfo,
    WatchAccess,
    amd64::{FXSAVE_SIZE, NT_PRFPREG, NT_PRSTATUS, USER_REGS_SIZE},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const BASE: u64 = 0x1000;
const TID: u32 = 1234;

struct Mock {
    state: TargetState,
    sequence: u32,
    prstatus: Vec<u8>,
    fp: Vec<u8>,
    memory: Vec<u8>,
    breakpoints: Vec<u64>,
    /// Debug-register requests held, and how many the mock has room for.
    hardware: Vec<(BreakpointKind, u64, u32)>,
    hardware_slots: usize,
    log: Vec<String>,
    /// Polls of a running target before its next event, and that event.
    next: Option<(u32, TargetState)>,
}
impl Mock {
    fn new() -> Arc<Mutex<Self>> {
        let mut prstatus = vec![0u8; USER_REGS_SIZE];
        prstatus[80..88].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // rax
        prstatus[128..136].copy_from_slice(&0x4018c0u64.to_le_bytes()); // rip
        Arc::new(Mutex::new(Self {
            state: TargetState::Running,
            sequence: 0,
            prstatus,
            fp: vec![0u8; FXSAVE_SIZE],
            memory: (0..0x100u32).map(|index| index as u8).collect(),
            breakpoints: Vec::new(),
            hardware: Vec::new(),
            hardware_slots: 4,
            log: Vec::new(),
            next: None,
        }))
    }
    fn stopped(&mut self, kind: StopKind, pc: u64) {
        self.sequence += 1;
        self.state = TargetState::Stopped(StopEvent {
            sequence: self.sequence,
            kind,
            tid: TID,
            pc,
        });
    }
}

struct Backend(Arc<Mutex<Mock>>, DebugCaps);
fn caps() -> DebugCaps {
    DebugCaps {
        abi: 1,
        arch: ArchTag::X86_64,
        software_breakpoints: true,
        hardware_single_step: true,
        shadow_reads: true,
        multi_thread: true,
        signals: true,
        batch_regs: false,
        debug_on_start: false,
        auxv: false,
        follow: false,
        nonstop: false,
        adopt: false,
        thread_hw: false,
        hardware_breakpoints: 0,
        hardware_watchpoints: 0,
        breakpoint_len_mask: 1,
        watch_len_mask: 0,
        max_threads: 256,
        max_transfer: 16000,
        regsets: vec![
            RegsetInfo {
                nt_type: NT_PRSTATUS,
                max_size: 216,
                writable: true,
            },
            RegsetInfo {
                nt_type: NT_PRFPREG,
                max_size: 512,
                writable: true,
            },
        ],
    }
}
impl DebugBackend for Backend {
    fn caps(&self) -> &DebugCaps {
        &self.1
    }
    fn state(&mut self) -> Result<TargetState, DebugError> {
        let mut mock = self.0.lock().unwrap();
        if mock.state == TargetState::Running
            && let Some((polls, event)) = mock.next.take()
        {
            if polls == 0 {
                mock.sequence += 1;
                mock.state = match event {
                    TargetState::Stopped(mut stop) => {
                        stop.sequence = mock.sequence;
                        TargetState::Stopped(stop)
                    }
                    other => other,
                };
            } else {
                mock.next = Some((polls - 1, event));
            }
        }
        Ok(mock.state)
    }
    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        Ok(vec![
            ThreadInfo {
                tid: TID,
                stopped: true,
                pc: 0x4018c0,
                signal: 0,
                vfork_wait: false,
            },
            ThreadInfo {
                tid: TID + 1,
                stopped: true,
                pc: 0x4018c0,
                signal: 0,
                vfork_wait: false,
            },
        ])
    }
    fn interrupt(&mut self) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        mock.log.push("interrupt".into());
        if mock.state == TargetState::Running {
            mock.next = None;
            mock.stopped(StopKind::Interrupt, 0x4018c0);
        }
        Ok(())
    }
    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        mock.log.push(format!("{action:?}"));
        mock.state = TargetState::Running;
        Ok(())
    }
    fn read_regset(&mut self, _tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError> {
        let mock = self.0.lock().unwrap();
        let data = match nt_type {
            NT_PRSTATUS => mock.prstatus.clone(),
            NT_PRFPREG => mock.fp.clone(),
            _ => return Err(DebugError::Unsupported("set".into())),
        };
        Ok(RegsetBlob { nt_type, data })
    }
    fn write_regset(&mut self, _tid: u32, blob: &RegsetBlob) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        mock.log.push(format!("write_regset {}", blob.nt_type));
        match blob.nt_type {
            NT_PRSTATUS => mock.prstatus = blob.data.clone(),
            _ => mock.fp = blob.data.clone(),
        }
        Ok(())
    }
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, DebugError> {
        let mock = self.0.lock().unwrap();
        let start = addr.checked_sub(BASE).ok_or(DebugError::Fault)? as usize;
        if start >= mock.memory.len() {
            return Err(DebugError::Fault);
        }
        Ok(mock.memory[start..(start + len).min(mock.memory.len())].to_vec())
    }
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        let start = addr.checked_sub(BASE).ok_or(DebugError::Fault)? as usize;
        if start + data.len() > mock.memory.len() {
            return Err(DebugError::Fault);
        }
        mock.memory[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn set_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        if addr == 0xdead {
            return Err(DebugError::Fault);
        }
        mock.log.push(format!("set {addr:#x}"));
        mock.breakpoints.push(addr);
        Ok(())
    }
    fn clear_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        let mut mock = self.0.lock().unwrap();
        mock.log.push(format!("clear {addr:#x}"));
        mock.breakpoints.retain(|existing| *existing != addr);
        Ok(())
    }
    fn insert_breakpoint(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if kind == BreakpointKind::Software {
            return self.set_breakpoint(addr, len);
        }
        let mut mock = self.0.lock().unwrap();
        if mock.hardware.len() >= mock.hardware_slots {
            return Err(DebugError::NoSlots);
        }
        mock.log.push(format!("hw+ {kind:?} {addr:#x} {len}"));
        mock.hardware.push((kind, addr, len));
        Ok(())
    }
    fn remove_breakpoint(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if kind == BreakpointKind::Software {
            return self.clear_breakpoint(addr, len);
        }
        let mut mock = self.0.lock().unwrap();
        mock.log.push(format!("hw- {kind:?} {addr:#x} {len}"));
        mock.hardware.retain(|held| *held != (kind, addr, len));
        Ok(())
    }
    fn detach(&mut self, mode: DetachMode) -> Result<(), DebugError> {
        self.0.lock().unwrap().log.push(format!("detach {mode:?}"));
        Ok(())
    }
}

struct Fixture {
    mock: Arc<Mutex<Mock>>,
    server: DebugServer,
    directory: PathBuf,
}
impl Fixture {
    fn start(state: TargetState) -> Self {
        Self::start_with(state, caps())
    }
    /// The debug registers on offer, four slots.
    fn start_hardware(state: TargetState) -> Self {
        Self::start_with(
            state,
            DebugCaps {
                hardware_breakpoints: 4,
                hardware_watchpoints: 4,
                watch_len_mask: 0x8b,
                ..caps()
            },
        )
    }
    fn start_with(state: TargetState, caps: DebugCaps) -> Self {
        let mock = Mock::new();
        {
            let mut inner = mock.lock().unwrap();
            match state {
                TargetState::Stopped(_) => inner.stopped(StopKind::Interrupt, 0x4018c0),
                other => inner.state = other,
            }
        }
        let directory =
            std::env::temp_dir().join(format!("ant-rsp-test-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let server = DebugServer::start(Box::new(Backend(mock.clone(), caps)), &directory).unwrap();
        Self {
            mock,
            server,
            directory,
        }
    }
    fn unix(&self) -> Client {
        Client::new(Stream::Unix(
            UnixStream::connect(&self.server.endpoints().unix_socket).unwrap(),
        ))
    }
    fn tcp(&self) -> Client {
        Client::new(Stream::Tcp(
            TcpStream::connect(("127.0.0.1", self.server.endpoints().tcp_port)).unwrap(),
        ))
    }
    fn log(&self) -> Vec<String> {
        self.mock.lock().unwrap().log.clone()
    }
    fn wait_log(&self, entry: &str) {
        self.wait_count(entry, 1);
    }
    fn wait_count(&self, entry: &str, count: usize) {
        let until = Instant::now() + Duration::from_secs(60);
        while self.log().iter().filter(|line| *line == entry).count() < count {
            assert!(
                Instant::now() < until,
                "{entry:?} x{count} never logged: {:?}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .server
            .shutdown(DetachMode::Resume, Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}
struct Client {
    stream: Stream,
    pending: Vec<u8>,
    acks: bool,
    /// The server was started with debug registers: the handshake expects them.
    hardware: bool,
}
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}
impl Client {
    fn new(stream: Stream) -> Self {
        let timeout = Some(Duration::from_secs(10));
        match &stream {
            Stream::Unix(socket) => socket.set_read_timeout(timeout).unwrap(),
            Stream::Tcp(socket) => socket.set_read_timeout(timeout).unwrap(),
        }
        Self {
            stream,
            pending: Vec::new(),
            acks: true,
            hardware: false,
        }
    }
    fn write(&mut self, bytes: &[u8]) {
        let socket: &mut dyn Write = match &mut self.stream {
            Stream::Unix(socket) => socket,
            Stream::Tcp(socket) => socket,
        };
        // A peer that already closed is observed through the missing reply.
        let _ = socket.write_all(bytes);
    }
    fn fill(&mut self) -> bool {
        let mut buffer = [0u8; 4096];
        let socket: &mut dyn Read = match &mut self.stream {
            Stream::Unix(socket) => socket,
            Stream::Tcp(socket) => socket,
        };
        match socket.read(&mut buffer) {
            Ok(0) | Err(_) => false,
            Ok(count) => {
                self.pending.extend(&buffer[..count]);
                true
            }
        }
    }
    /// The next reply packet's payload, or None when the peer closed.
    fn packet(&mut self) -> Option<String> {
        loop {
            if let Some(start) = self.pending.iter().position(|byte| *byte == b'$')
                && let Some(hash) = self.pending[start..].iter().position(|byte| *byte == b'#')
                && self.pending.len() >= start + hash + 3
            {
                let payload = self.pending[start + 1..start + hash].to_vec();
                let sum = u8::from_str_radix(
                    std::str::from_utf8(&self.pending[start + hash + 1..start + hash + 3]).unwrap(),
                    16,
                )
                .unwrap();
                assert_eq!(sum, checksum(&payload), "reply checksum");
                self.pending.drain(..start + hash + 3);
                if self.acks {
                    self.write(b"+");
                }
                return Some(unrle(&payload));
            }
            if !self.fill() {
                return None;
            }
        }
    }
    fn send(&mut self, payload: &str) -> String {
        self.write(format!("${payload}#{:02x}", checksum(payload.as_bytes())).as_bytes());
        self.packet()
            .unwrap_or_else(|| panic!("no reply to {payload:?}"))
    }
    fn send_no_wait(&mut self, payload: &str) {
        self.write(format!("${payload}#{:02x}", checksum(payload.as_bytes())).as_bytes());
    }
    fn closed(&mut self) -> bool {
        self.pending.clear();
        let until = Instant::now() + Duration::from_secs(60);
        while Instant::now() < until {
            if !self.fill() {
                return true;
            }
        }
        false
    }
    fn handshake(&mut self) {
        let reply = self.send("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+");
        assert!(reply.contains("swbreak+"), "{reply}");
        assert!(reply.contains("qXfer:features:read+"), "{reply}");
        assert!(reply.contains("PacketSize=4000"), "{reply}");
        if !self.hardware {
            assert!(
                !reply.contains("hwbreak+"),
                "hardware breakpoints are not offered: {reply}"
            );
        } else {
            assert!(reply.contains("hwbreak+"), "{reply}");
        }
        assert!(
            !reply.contains("QNonStop"),
            "non-stop is not implemented: {reply}"
        );
        assert_eq!(self.send("QStartNoAckMode"), "OK");
        self.acks = false;
    }
}
/// Undo run-length encoding: `X*N` repeats X by N - 29 more times.
fn unrle(payload: &[u8]) -> String {
    let mut out = Vec::new();
    let mut index = 0;
    while index < payload.len() {
        if payload[index] == b'*' && index + 1 < payload.len() && !out.is_empty() {
            let extra = usize::from(payload[index + 1]) - 29;
            let last = *out.last().unwrap();
            out.extend(std::iter::repeat_n(last, extra));
            index += 2;
        } else {
            out.push(payload[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
fn thread_id() -> String {
    format!("p01.{TID:04x}")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_stopped_target_answers_the_basic_queries() {
    let fixture = Fixture::start(TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Interrupt,
        tid: TID,
        pc: 0,
    }));
    let mut client = fixture.unix();
    client.handshake();
    assert_eq!(client.send("?"), format!("T05thread:{};", thread_id()));
    assert_eq!(client.send("qAttached"), "1");
    let threads = client.send("qfThreadInfo");
    assert!(
        threads.starts_with('m') && threads.contains(&format!("{TID:x}")),
        "{threads}"
    );
    assert_eq!(client.send("qsThreadInfo"), "l");
    assert_eq!(client.send(&format!("Hg{TID:x}")), "OK");
    // g: the whole register image, rax and rip where the description puts them.
    let image = client.send("g");
    assert_eq!(image.len(), 560 * 2);
    assert_eq!(
        &image[..16],
        "8877665544332211",
        "rax is the first register"
    );
    let rip_at = 16 * 16;
    assert_eq!(&image[rip_at..rip_at + 16], "c018400000000000", "rip");
    // The target description, chunked as the client asks.
    let mut xml = String::new();
    loop {
        let chunk = client.send(&format!(
            "qXfer:features:read:target.xml:{:x},3ff",
            xml.len()
        ));
        xml.push_str(&chunk[1..]);
        if chunk.starts_with('l') {
            break;
        }
        assert!(chunk.starts_with('m'), "{chunk}");
    }
    assert!(xml.starts_with("<?xml"), "{xml}");
    // The stub serves the description trimmed of surrounding whitespace.
    assert_eq!(xml, crate::debug::amd64::description().xml().trim());
    // m reads (a short read ends at the region), M writes, X is not claimed.
    assert_eq!(client.send("m1000,4"), "00010203");
    assert_eq!(
        client.send("m10fe,8"),
        "feff",
        "a short read ends at the region"
    );
    assert_eq!(client.send("m5000,4"), "E0e");
    assert_eq!(client.send("M1000,2:aabb"), "OK");
    assert_eq!(client.send("m1000,4"), "aabb0203");
    assert!(client.send("M5000,2:aabb").starts_with('E'));
    assert_eq!(client.send("D"), "OK");
}

#[test]
fn registers_are_written_back_only_where_they_changed() {
    let fixture = Fixture::start(TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Interrupt,
        tid: TID,
        pc: 0,
    }));
    let mut client = fixture.tcp();
    client.handshake();
    client.send(&format!("Hg{TID:x}"));
    let image = client.send("g");
    let mut changed = image.clone().into_bytes();
    changed[..16].copy_from_slice(b"0100000000000000");
    assert_eq!(
        client.send(&format!("G{}", String::from_utf8(changed).unwrap())),
        "OK"
    );
    let log = fixture.log();
    assert!(
        log.contains(&format!("write_regset {NT_PRSTATUS}")),
        "{log:?}"
    );
    assert!(
        !log.contains(&format!("write_regset {NT_PRFPREG}")),
        "{log:?}"
    );
    assert_eq!(
        &fixture.mock.lock().unwrap().prstatus[80..88],
        &1u64.to_le_bytes()
    );
    // A short image is a protocol violation: the session ends, nothing is half applied.
    client.send_no_wait(&format!("G{}", &image[..100]));
    assert!(client.closed());
    assert_eq!(
        fixture
            .log()
            .iter()
            .filter(|line| line.starts_with("write_regset"))
            .count(),
        1
    );
}

#[test]
fn breakpoints_are_counted_and_hit_with_swbreak() {
    let fixture = Fixture::start(TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Interrupt,
        tid: TID,
        pc: 0,
    }));
    let mut client = fixture.unix();
    client.handshake();
    assert_eq!(client.send("Z0,4018c0,1"), "OK");
    assert_eq!(client.send("Z0,4018c0,1"), "OK");
    assert_eq!(client.send("z0,4018c0,1"), "OK");
    assert_eq!(
        fixture.mock.lock().unwrap().breakpoints,
        vec![0x4018c0],
        "still set once"
    );
    assert_eq!(client.send("z0,4018c0,1"), "OK");
    assert!(fixture.mock.lock().unwrap().breakpoints.is_empty());
    assert!(
        client.send("z0,4018c0,1").starts_with('E'),
        "removing an unknown breakpoint is refused"
    );
    assert!(
        client.send("Z0,dead,1").starts_with('E'),
        "a refused breakpoint is an error reply"
    );
    assert_eq!(
        client.send("Z1,4018c0,1"),
        "",
        "hardware breakpoints are not offered"
    );
    assert_eq!(
        client.send("Z2,4018c0,1"),
        "",
        "watchpoints are not offered"
    );
    assert_eq!(client.send("Z0,4018c0,1"), "OK");
    // Continue; the mock hits the breakpoint after two polls.
    fixture.mock.lock().unwrap().next = Some((
        2,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::Breakpoint { addr: 0x4018c0 },
            tid: TID,
            pc: 0x4018c0,
        }),
    ));
    client.send_no_wait("vCont;c");
    let stop = client.packet().unwrap();
    assert_eq!(stop, format!("T05thread:{};swbreak:;", thread_id()));
    assert!(fixture.log().contains(&"Continue".to_string()));
    // Detach removes what the client left set and lets the process go.
    assert_eq!(client.send("D"), "OK");
    assert!(client.closed());
    fixture.wait_count("clear 0x4018c0", 2);
    fixture.wait_count("Continue", 2);
    let log = fixture.log();
    let cleared = log
        .iter()
        .rposition(|line| line == "clear 0x4018c0")
        .unwrap();
    assert_eq!(
        log.iter().rposition(|line| line == "Continue").unwrap(),
        cleared + 1,
        "{log:?}"
    );
    assert!(fixture.mock.lock().unwrap().breakpoints.is_empty());
}

fn hit(addr: u64) -> TargetState {
    TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Breakpoint { addr },
        tid: TID,
        pc: addr,
    })
}
fn stopped_fixture() -> Fixture {
    Fixture::start(TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Interrupt,
        tid: TID,
        pc: 0,
    }))
}

#[test]
fn single_step_and_interrupt() {
    let fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    assert!(
        client.send("vCont?").contains(";s"),
        "single-step is offered"
    );
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::Step,
            tid: TID,
            pc: 0x4018c3,
        }),
    ));
    client.send_no_wait(&format!("vCont;s:{};c", thread_id()));
    assert_eq!(
        client.packet().unwrap(),
        format!("T05thread:{};", thread_id())
    );
    assert!(
        fixture.log().contains(&format!("Step {{ tid: {TID} }}")),
        "{:?}",
        fixture.log()
    );
    // Continue, then interrupt with the 0x03 byte.
    client.send_no_wait("vCont;c");
    fixture.wait_log("Continue");
    client.write(&[3]);
    assert_eq!(
        client.packet().unwrap(),
        format!("T02thread:{};", thread_id())
    );
    assert!(fixture.log().contains(&"interrupt".to_string()));
    assert_eq!(client.send("D"), "OK");
}

#[test]
fn the_process_ending_is_reported_and_ends_the_session() {
    let fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Exited {
            wait_status: 0x0300,
        },
    ));
    client.send_no_wait("vCont;c");
    assert_eq!(client.packet().unwrap(), "W03");
    assert!(client.closed());
    let until = Instant::now() + Duration::from_secs(60);
    while !fixture.server.is_finished() {
        assert!(Instant::now() < until, "server should end with its target");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.server.status().ended.unwrap().contains("status 3"));
    // Killed by a signal is X, not W.
    let fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    fixture.mock.lock().unwrap().next = Some((0, TargetState::Exited { wait_status: 9 }));
    client.send_no_wait("vCont;c");
    assert_eq!(client.packet().unwrap(), "X09");
}

#[test]
fn a_client_that_vanishes_leaves_the_process_running_and_the_server_usable() {
    let fixture = stopped_fixture();
    {
        let mut client = fixture.unix();
        client.handshake();
        assert_eq!(client.send("Z0,4018c0,1"), "OK");
        // Dropped without D.
    }
    fixture.wait_log("clear 0x4018c0");
    fixture.wait_log("Continue");
    assert!(!fixture.server.is_finished());
    // The process was released while running: a new client interrupts it first.
    let mut again = fixture.tcp();
    again.handshake();
    assert!(fixture.log().contains(&"interrupt".to_string()));
    assert!(again.send("?").starts_with("T05thread:"));
    assert_eq!(again.send("D"), "OK");
    assert_eq!(fixture.server.status().clients_served, 2);
}

#[test]
fn a_client_that_waited_and_sent_its_first_packet_again_gets_one_reply() {
    let fixture = stopped_fixture();
    let mut first = fixture.unix();
    first.handshake();
    // The second client is queued behind the first: gdb, with no `+` within
    // its remote timeout, sends its first packet again.
    let mut second = fixture.tcp();
    second.send_no_wait("qSupported:multiprocess+;swbreak+");
    second.send_no_wait("qSupported:multiprocess+;swbreak+");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(first.send("D"), "OK");
    let reply = second.packet().unwrap();
    assert!(reply.contains("PacketSize=4000"), "{reply}");
    // Every later reply answers its own request, not the copy.
    assert_eq!(second.send("vMustReplyEmpty"), "");
    assert!(second.send("?").starts_with("T05thread:"));
    // A request repeated after its reply was acknowledged is answered again.
    assert_eq!(second.send("qAttached"), "1");
    assert_eq!(second.send("qAttached"), "1");
    assert_eq!(second.send("D"), "OK");
}

#[test]
fn kill_ends_the_process_and_the_session() {
    let fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    client.send_no_wait("k");
    assert!(client.closed());
    fixture.wait_log("detach Kill");
}

#[test]
fn shutdown_resumes_and_detaches() {
    let mut fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    assert_eq!(client.send("Z0,4018c0,1"), "OK");
    fixture
        .server
        .shutdown(DetachMode::Resume, Duration::from_secs(5))
        .unwrap();
    let log = fixture.log();
    assert_eq!(log.last().unwrap(), "detach Resume", "{log:?}");
    assert!(log.contains(&"clear 0x4018c0".to_string()), "{log:?}");
    assert!(
        !fixture.server.endpoints().unix_socket.exists(),
        "the socket is removed"
    );
}

#[test]
fn bad_input_never_hangs_or_panics_the_server() {
    let fixture = stopped_fixture();
    // A packet with a wrong checksum ends that session, not the server.
    let mut client = fixture.unix();
    client.write(b"$?#00");
    assert!(client.closed());
    drop(client);
    assert!(!fixture.server.is_finished());
    // Garbage and random payloads: the session may end, the server must not.
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..40 {
        let mut client = fixture.unix();
        client.write(b"+");
        let length = 1 + (next() % 60) as usize;
        let payload: String = (0..length)
            .map(|_| (0x20 + (next() % 0x5f) as u8) as char)
            .filter(|c| *c != '#' && *c != '$' && *c != '}' && *c != '*')
            .collect();
        client.write(format!("${payload}#{:02x}", checksum(payload.as_bytes())).as_bytes());
        let _ = client.packet();
        drop(client);
        assert!(!fixture.server.is_finished(), "round {round}: {payload:?}");
    }
    let mut client = fixture.unix();
    client.handshake();
    assert!(client.send("?").starts_with("T05thread:"));
    assert_eq!(client.send("D"), "OK");
}

#[test]
fn endpoints_are_loopback_only() {
    let fixture = stopped_fixture();
    let endpoints = fixture.server.endpoints();
    assert!(endpoints.tcp_port != 0);
    assert!(endpoints.gdb_command().contains("127.0.0.1"));
    assert!(
        endpoints
            .gdb_command()
            .starts_with("gdb -ex 'target remote ")
    );
    assert!(!endpoints.gdb_command().contains("0.0.0.0"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&endpoints.unix_socket)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the socket is private to the user");
    let _ = hex(&[]);
    let _ = hit;
}

#[test]
fn only_this_users_tcp_connections_are_served() {
    use std::net::{SocketAddr, TcpListener};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = listener.local_addr().unwrap();
    let client = TcpStream::connect(local).unwrap();
    let (server_side, peer) = listener.accept().unwrap();
    assert_eq!(client.local_addr().unwrap(), peer);
    assert!(crate::debug::rsp_server::tcp_peer_is_this_user(
        &peer,
        &server_side.local_addr().unwrap()
    ));
    // A connection the kernel does not list as ours is refused.
    let stranger: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(!crate::debug::rsp_server::tcp_peer_is_this_user(
        &stranger, &local
    ));
    let v6: SocketAddr = "[::1]:9".parse().unwrap();
    assert!(!crate::debug::rsp_server::tcp_peer_is_this_user(&v6, &v6));
}

#[test]
fn debug_registers_are_offered_only_when_the_guest_has_them_and_run_out_cleanly() {
    let fixture = Fixture::start_hardware(TargetState::Stopped(StopEvent {
        sequence: 0,
        kind: StopKind::Interrupt,
        tid: TID,
        pc: 0,
    }));
    let mut client = fixture.unix();
    client.hardware = true;
    client.handshake();
    assert_eq!(client.send("Z1,4018c0,1"), "OK");
    assert_eq!(client.send("Z1,4018c0,1"), "OK", "asked twice, held once");
    assert_eq!(client.send("Z2,1000,8"), "OK");
    // Five bytes at 0x1001 are three aligned pieces: 1, 2 and 2 bytes. That is
    // five slots in all with the two above: one too many, and nothing is left
    // half set.
    assert_eq!(client.send("Z2,1001,5"), "E1c");
    assert_eq!(fixture.mock.lock().unwrap().hardware.len(), 2);
    // Room for the three pieces once the others are gone.
    assert_eq!(client.send("z1,4018c0,1"), "OK");
    assert_eq!(client.send("z1,4018c0,1"), "OK");
    assert_eq!(client.send("Z4,1001,5"), "OK");
    let held = fixture.mock.lock().unwrap().hardware.clone();
    assert_eq!(
        held,
        vec![
            (BreakpointKind::Watch(WatchAccess::Write), 0x1000, 8),
            (BreakpointKind::Watch(WatchAccess::Access), 0x1001, 1),
            (BreakpointKind::Watch(WatchAccess::Access), 0x1002, 2),
            (BreakpointKind::Watch(WatchAccess::Access), 0x1004, 2),
        ]
    );
    // A read watchpoint cannot be done with the debug registers.
    assert_ne!(client.send("Z3,2000,4"), "OK");
    assert_eq!(client.send("z4,1001,5"), "OK");
    assert_eq!(fixture.mock.lock().unwrap().hardware.len(), 1);
    assert_eq!(client.send("Z1,4018c0,1"), "OK");
    // The reports a debugger reads.
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::HardwareBreakpoint { addr: 0x4018c0 },
            tid: TID,
            pc: 0x4018c0,
        }),
    ));
    client.send_no_wait("vCont;c");
    assert_eq!(
        client.packet().unwrap(),
        format!("T05thread:{};hwbreak:;", thread_id())
    );
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::Watchpoint {
                addr: 0x1000,
                access: WatchAccess::Write,
            },
            tid: TID,
            pc: 0x4018c7,
        }),
    ));
    client.send_no_wait("vCont;c");
    assert_eq!(
        client.packet().unwrap(),
        format!("T05thread:{};watch:1000;", thread_id())
    );
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::Watchpoint {
                addr: 0x1002,
                access: WatchAccess::Access,
            },
            tid: TID,
            pc: 0x4018c7,
        }),
    ));
    client.send_no_wait("vCont;c");
    assert_eq!(
        client.packet().unwrap(),
        format!("T05thread:{};awatch:1002;", thread_id())
    );
    // Detach clears every hardware request the client left.
    assert_eq!(client.send("D"), "OK");
    assert!(client.closed());
    fixture.wait_log("hw- Watch(Write) 0x1000 8");
    fixture.wait_count("hw- Hardware 0x4018c0 1", 2);
    assert!(fixture.mock.lock().unwrap().hardware.is_empty());
}

#[test]
fn signal_stops_use_gdbs_numbers_and_a_resume_names_the_signal_to_pass() {
    let fixture = stopped_fixture();
    let mut client = fixture.unix();
    client.handshake();
    // Linux SIGUSR1 (10) is GDB's 30 (0x1e); SIGSEGV is 11 in both.
    for (linux, gdb) in [(10u32, "1e"), (11, "0b"), (7, "0a"), (17, "14")] {
        fixture.mock.lock().unwrap().next = Some((
            1,
            TargetState::Stopped(StopEvent {
                sequence: 0,
                kind: StopKind::Signal { signal: linux },
                tid: TID,
                pc: 0x4018c0,
            }),
        ));
        client.send_no_wait("vCont;c");
        assert_eq!(
            client.packet().unwrap(),
            format!("T{gdb}thread:{};", thread_id())
        );
        // Pass it (C<sig>), step into its handler (S<sig>).
        fixture.mock.lock().unwrap().next = Some((
            1,
            TargetState::Stopped(StopEvent {
                sequence: 0,
                kind: StopKind::Step,
                tid: TID,
                pc: 0x401000,
            }),
        ));
        client.send_no_wait(&format!("vCont;S{gdb}:{}", thread_id()));
        assert_eq!(
            client.packet().unwrap(),
            format!("T05thread:{};", thread_id())
        );
        let log = fixture.log();
        assert!(
            log.contains(&format!("StepSignal {{ tid: {TID}, signal: {linux} }}")),
            "{log:?}"
        );
    }
    fixture.mock.lock().unwrap().next = Some((
        1,
        TargetState::Stopped(StopEvent {
            sequence: 0,
            kind: StopKind::Signal { signal: 10 },
            tid: TID,
            pc: 0x4018c0,
        }),
    ));
    client.send_no_wait("vCont;c");
    client.packet().unwrap();
    client.send_no_wait(&format!("vCont;C1e:{}", thread_id()));
    fixture.wait_log(&format!("ContinueSignal {{ tid: {TID}, signal: 10 }}"));
    // A plain continue drops the signal.
    client.write(&[3]);
    client.packet().unwrap();
    client.send_no_wait("vCont;c");
    fixture.wait_count("Continue", 1);
}
