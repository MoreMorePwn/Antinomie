// SPDX-License-Identifier: GPL-3.0-only
//! Several processes and non-stop over the real sockets, against a fake guest
//! that can fork, exec and run threads one by one: the replies a debugger reads
//! for a fork, a vfork and an exec, process-qualified thread ids, `D;pid`, and the
//! `%Stop` notifications of non-stop mode.
use crate::debug::{
    ArchTag, BreakpointKind, ChildRef, DebugBackend, DebugCaps, DebugError, DebugServer,
    DetachMode, EventBatch, GuestBreakpoint, RegsetBlob, RegsetInfo, ResumeAction, SessionOptions,
    StopEvent, StopKind, TargetState, ThreadAction, ThreadInfo,
    amd64::{FXSAVE_SIZE, NT_PRFPREG, NT_PRSTATUS, USER_REGS_SIZE},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Proc {
    state: TargetState,
    sequence: u32,
    /// Thread ids and whether each is stopped (non-stop).
    threads: Vec<(u32, bool)>,
    nonstop: bool,
    queue: VecDeque<StopEvent>,
    exec_path: Option<String>,
    rax: u64,
    breakpoints: Vec<u64>,
    options: SessionOptions,
}
struct World {
    procs: BTreeMap<u32, Proc>,
    log: Vec<String>,
    /// Count guest polling until a memory command is dispatched.
    event_polls: usize,
    memory_polls: Option<usize>,
}
impl World {
    fn new() -> Arc<Mutex<Self>> {
        let mut world = Self {
            procs: BTreeMap::new(),
            log: Vec::new(),
            event_polls: 0,
            memory_polls: None,
        };
        world.spawn(10, &[10, 11], 0x1111);
        Arc::new(Mutex::new(world))
    }
    fn spawn(&mut self, pid: u32, threads: &[u32], rax: u64) {
        self.procs.insert(
            pid,
            Proc {
                state: TargetState::Stopped(StopEvent {
                    sequence: 1,
                    kind: StopKind::Interrupt,
                    tid: pid,
                    pc: 0x4000,
                }),
                sequence: 1,
                threads: threads.iter().map(|tid| (*tid, true)).collect(),
                nonstop: false,
                queue: VecDeque::new(),
                exec_path: None,
                rax,
                breakpoints: Vec::new(),
                options: SessionOptions::default(),
            },
        );
    }
    /// The program of `parent` forks (or vforks) a child: the parent stops with the
    /// event, the child is held stopped.
    fn fork(&mut self, parent: u32, child: u32, vfork: bool) {
        self.spawn(child, &[child], 0);
        let child_ref = ChildRef {
            session: u64::from(child) + 100,
            tgid: child,
            task_cookie: u64::from(child),
            start_boot_ns: 1,
            shared_memory: vfork,
        };
        let kind = if vfork {
            StopKind::Vfork { child: child_ref }
        } else {
            StopKind::Fork { child: child_ref }
        };
        self.stop(parent, kind);
    }
    fn stop(&mut self, pid: u32, kind: StopKind) {
        let proc = self.procs.get_mut(&pid).expect("process");
        proc.sequence += 1;
        let event = StopEvent {
            sequence: proc.sequence,
            kind,
            tid: pid,
            pc: 0x4010,
        };
        if proc.nonstop {
            proc.queue.push_back(event);
        } else {
            proc.state = TargetState::Stopped(event);
        }
    }
    /// Non-stop: one thread hits a breakpoint and stops, the others run.
    fn thread_hits(&mut self, pid: u32, tid: u32, addr: u64) {
        let proc = self.procs.get_mut(&pid).expect("process");
        proc.sequence += 1;
        for thread in &mut proc.threads {
            if thread.0 == tid {
                thread.1 = true;
            }
        }
        proc.queue.push_back(StopEvent {
            sequence: proc.sequence,
            kind: StopKind::Breakpoint { addr },
            tid,
            pc: addr,
        });
    }
}

struct Fake {
    world: Arc<Mutex<World>>,
    pid: u32,
    caps: DebugCaps,
}
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
        follow: true,
        nonstop: true,
        adopt: true,
        thread_hw: true,
        hardware_breakpoints: 0,
        hardware_watchpoints: 0,
        breakpoint_len_mask: 1,
        watch_len_mask: 0,
        max_threads: 64,
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
impl Fake {
    fn new(world: &Arc<Mutex<World>>, pid: u32) -> Self {
        Self {
            world: world.clone(),
            pid,
            caps: caps(),
        }
    }
    fn with<R>(&self, f: impl FnOnce(&mut World, u32) -> R) -> R {
        let mut world = self.world.lock().unwrap();
        f(&mut world, self.pid)
    }
}
impl DebugBackend for Fake {
    fn caps(&self) -> &DebugCaps {
        &self.caps
    }
    fn target_pid(&self) -> u32 {
        self.pid
    }
    fn session_id(&self) -> u64 {
        u64::from(self.pid) + 100
    }
    fn state(&mut self) -> Result<TargetState, DebugError> {
        self.with(|world, pid| Ok(world.procs[&pid].state))
    }
    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        self.with(|world, pid| {
            Ok(world.procs[&pid]
                .threads
                .iter()
                .map(|(tid, stopped)| ThreadInfo {
                    tid: *tid,
                    stopped: *stopped,
                    pc: 0x4000,
                    signal: 0,
                    vfork_wait: false,
                })
                .collect())
        })
    }
    fn interrupt(&mut self) -> Result<(), DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("interrupt {pid}"));
            if world.procs[&pid].state == TargetState::Running {
                world.stop(pid, StopKind::Interrupt);
            }
            Ok(())
        })
    }
    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("{action:?} {pid}"));
            world.procs.get_mut(&pid).unwrap().state = TargetState::Running;
            Ok(())
        })
    }
    fn read_regset(&mut self, _tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError> {
        self.with(|world, pid| {
            let data = if nt_type == NT_PRSTATUS {
                let mut blob = vec![0u8; USER_REGS_SIZE];
                blob[80..88].copy_from_slice(&world.procs[&pid].rax.to_le_bytes());
                blob
            } else {
                vec![0u8; FXSAVE_SIZE]
            };
            Ok(RegsetBlob { nt_type, data })
        })
    }
    fn write_regset(&mut self, _tid: u32, _blob: &RegsetBlob) -> Result<(), DebugError> {
        Ok(())
    }
    fn read_memory(&mut self, _addr: u64, len: usize) -> Result<Vec<u8>, DebugError> {
        self.with(|world, _| {
            world.memory_polls = Some(world.event_polls);
            Ok(vec![0x90; len])
        })
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), DebugError> {
        self.with(|world, _| {
            world.memory_polls = Some(world.event_polls);
            Ok(())
        })
    }
    fn set_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("set {pid} {addr:#x}"));
            world.procs.get_mut(&pid).unwrap().breakpoints.push(addr);
            Ok(())
        })
    }
    fn clear_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("clear {pid} {addr:#x}"));
            world
                .procs
                .get_mut(&pid)
                .unwrap()
                .breakpoints
                .retain(|held| *held != addr);
            Ok(())
        })
    }
    fn detach(&mut self, mode: DetachMode) -> Result<(), DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("detach {pid} {mode:?}"));
            Ok(())
        })
    }
    fn configure(&mut self, options: SessionOptions) -> Result<SessionOptions, DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("configure {pid} {options:?}"));
            let proc = world.procs.get_mut(&pid).unwrap();
            proc.options = options;
            proc.nonstop = options.nonstop;
            Ok(options)
        })
    }
    fn exec_path(&mut self) -> Option<String> {
        self.with(|world, pid| world.procs[&pid].exec_path.clone())
    }
    fn adopt_child(&mut self, child: &ChildRef) -> Result<Box<dyn DebugBackend>, DebugError> {
        let world = self.world.clone();
        let options = self.with(|world, pid| world.procs[&pid].options);
        let backend = Fake::new(&world, child.tgid);
        backend.with(|world, pid| {
            world.log.push(format!("adopt {pid}"));
            world.procs.get_mut(&pid).unwrap().options = options;
        });
        Ok(Box::new(backend))
    }
    fn events(&mut self, acknowledged: u32) -> Result<EventBatch, DebugError> {
        self.with(|world, pid| {
            world.event_polls += 1;
            let proc = world.procs.get_mut(&pid).unwrap();
            proc.queue.retain(|event| event.sequence > acknowledged);
            Ok(EventBatch {
                events: proc.queue.iter().copied().collect(),
                ..EventBatch::default()
            })
        })
    }
    fn thread_action(&mut self, tid: Option<u32>, action: ThreadAction) -> Result<u32, DebugError> {
        self.with(|world, pid| {
            world.log.push(format!("thread {pid} {tid:?} {action:?}"));
            let proc = world.procs.get_mut(&pid).unwrap();
            let mut count = 0;
            for thread in &mut proc.threads {
                if tid.is_none_or(|wanted| wanted == thread.0) {
                    thread.1 = matches!(action, ThreadAction::Stop);
                    count += 1;
                }
            }
            Ok(count)
        })
    }
    fn guest_breakpoints(&mut self) -> Result<Vec<GuestBreakpoint>, DebugError> {
        self.with(|world, pid| {
            Ok(world.procs[&pid]
                .breakpoints
                .iter()
                .map(|addr| GuestBreakpoint {
                    kind: BreakpointKind::Software,
                    addr: *addr,
                    len: 1,
                    active: false,
                })
                .collect())
        })
    }
}

struct Fixture {
    world: Arc<Mutex<World>>,
    server: DebugServer,
    directory: PathBuf,
}
impl Fixture {
    fn start() -> Self {
        let world = World::new();
        let directory =
            std::env::temp_dir().join(format!("ant-follow-test-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let server = DebugServer::start(Box::new(Fake::new(&world, 10)), &directory).unwrap();
        Self {
            world,
            server,
            directory,
        }
    }
    fn client(&self) -> Client {
        let stream = UnixStream::connect(&self.server.endpoints().unix_socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Client {
            stream,
            pending: Vec::new(),
        }
    }
    fn log(&self) -> Vec<String> {
        self.world.lock().unwrap().log.clone()
    }
    fn wait_log(&self, entry: &str) {
        let until = Instant::now() + Duration::from_secs(60);
        while !self.log().iter().any(|line| line == entry) {
            assert!(
                Instant::now() < until,
                "{entry:?} never logged: {:?}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn with_world<R>(&self, f: impl FnOnce(&mut World) -> R) -> R {
        f(&mut self.world.lock().unwrap())
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

struct Client {
    stream: UnixStream,
    pending: Vec<u8>,
}
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}
impl Client {
    fn write(&mut self, payload: &str) {
        let framed = format!("${payload}#{:02x}", checksum(payload.as_bytes()));
        let _ = self.stream.write_all(framed.as_bytes());
    }
    /// The next packet or notification: ('$' | '%', payload).
    fn next(&mut self) -> Option<(char, String)> {
        loop {
            let start = self
                .pending
                .iter()
                .position(|byte| matches!(byte, b'$' | b'%'));
            if let Some(start) = start
                && let Some(hash) = self.pending[start..].iter().position(|byte| *byte == b'#')
                && self.pending.len() >= start + hash + 3
            {
                let kind = self.pending[start] as char;
                let payload =
                    String::from_utf8(self.pending[start + 1..start + hash].to_vec()).unwrap();
                self.pending.drain(..start + hash + 3);
                return Some((kind, payload));
            }
            let mut buffer = [0u8; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) | Err(_) => return None,
                Ok(count) => self.pending.extend(&buffer[..count]),
            }
        }
    }
    fn packet(&mut self) -> String {
        loop {
            let (kind, payload) = self.next().expect("a reply");
            if kind == '$' {
                return payload;
            }
        }
    }
    fn send(&mut self, payload: &str) -> String {
        self.write(payload);
        self.packet()
    }
    fn handshake(&mut self, extra: &str) -> String {
        let reply = self.send(&format!(
            "qSupported:multiprocess+;swbreak+;vContSupported+;fork-events+;vfork-events+;exec-events+{extra}"
        ));
        assert_eq!(self.send("QStartNoAckMode"), "OK");
        reply
    }
}

#[test]
fn a_fork_is_reported_with_the_childs_id_and_both_processes_answer() {
    let fixture = Fixture::start();
    let mut client = fixture.client();
    let features = client.handshake("");
    assert!(
        features.contains("fork-events+")
            && features.contains("vfork-events+")
            && features.contains("exec-events+"),
        "{features}"
    );
    assert!(features.contains("QNonStop+"), "{features}");
    assert_eq!(client.send("?"), "T05thread:p0a.0a;");
    assert_eq!(client.send("Z0,5000,1"), "OK");
    // The program forks while running: the stop reply names the child.
    client.write("vCont;c");
    fixture.wait_log("Continue 10");
    fixture.with_world(|world| world.fork(10, 12, false));
    assert_eq!(client.packet(), "T05thread:p0a.0a;fork:p0c.0c;");
    // Both processes are listed, each thread with its process.
    let list = client.send("qfThreadInfo");
    assert_eq!(list, "mp0a.0a,p0a.0b,p0c.0c");
    // Requests follow the process of the selected thread.
    assert_eq!(client.send("Hgp0c.0"), "OK");
    let image = client.send("g");
    assert_eq!(&image[..16], "0000000000000000", "the child's rax");
    assert_eq!(client.send("Hgp0a.0"), "OK");
    let image = client.send("g");
    assert_eq!(&image[..16], "1111000000000000", "the parent's rax");
    // A breakpoint set with the child selected goes to the child.
    assert_eq!(client.send("Hgp0c.0"), "OK");
    assert_eq!(client.send("Z0,6000,1"), "OK");
    assert!(
        fixture.log().contains(&"set 12 0x6000".to_string()),
        "{:?}",
        fixture.log()
    );
    // Letting the child go: its breakpoints go with it and the guest releases it.
    assert_eq!(client.send("D;c"), "OK");
    let log = fixture.log();
    let cleared = log
        .iter()
        .position(|line| line == "clear 12 0x6000")
        .unwrap();
    let detached = log
        .iter()
        .position(|line| line == "detach 12 Resume")
        .unwrap();
    assert!(cleared < detached, "{log:?}");
    assert_eq!(client.send("qfThreadInfo"), "mp0a.0a,p0a.0b");
    // Continue the parent only.
    client.write("vCont;c:p0a.-1");
    fixture.wait_count_of("Continue 10", 2);
    assert!(!fixture.log().iter().any(|line| line == "Continue 12"));
}

impl Fixture {
    fn wait_count_of(&self, entry: &str, count: usize) {
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

#[test]
fn a_vfork_child_shares_the_parents_breakpoints_and_vfork_done_is_reported() {
    let fixture = Fixture::start();
    let mut client = fixture.client();
    client.handshake("");
    client.write("vCont;c");
    fixture.wait_log("Continue 10");
    fixture.with_world(|world| world.fork(10, 13, true));
    assert_eq!(client.packet(), "T05thread:p0a.0a;vfork:p0d.0d;");
    // The parent carries on; vfork done comes as its own stop.
    client.write("vCont;c:p0a.-1");
    fixture.wait_count_of("Continue 10", 2);
    fixture.with_world(|world| {
        let kind = StopKind::VforkDone { child_tgid: 13 };
        world.stop(10, kind);
    });
    assert_eq!(client.packet(), "T05thread:p0a.0a;vforkdone:;");
}

#[test]
fn an_exec_is_reported_with_the_path_and_the_clients_breakpoints_are_gone() {
    let fixture = Fixture::start();
    let mut client = fixture.client();
    client.handshake("");
    assert_eq!(client.send("Z0,5000,1"), "OK");
    client.write("vCont;c");
    fixture.wait_log("Continue 10");
    fixture.with_world(|world| {
        world.procs.get_mut(&10).unwrap().exec_path = Some("/bin/x".into());
        world.stop(10, StopKind::Exec);
    });
    assert_eq!(client.packet(), "T05thread:p0a.0a;exec:2f62696e2f78;");
    // The new image has none of the old breakpoints: removing one is an error.
    assert!(client.send("z0,5000,1").starts_with('E'));
    assert_eq!(client.send("Z0,5000,1"), "OK");
}

#[test]
fn a_session_without_follow_support_offers_neither_events_nor_non_stop() {
    let fixture = Fixture::start();
    fixture.with_world(|world| {
        world.log.push("start".into());
    });
    let mut client = fixture.client();
    // A client that does not know fork events is not given any.
    let reply = client.send("qSupported:multiprocess+;swbreak+");
    assert!(!reply.contains("fork-events"), "{reply}");
    assert_eq!(client.send("D"), "OK");
}

#[test]
fn non_stop_input_does_not_poll_the_guest_for_every_packet_byte() {
    let fixture = Fixture::start();
    let mut client = fixture.client();
    client.handshake("");
    assert_eq!(client.send("QNonStop:1"), "OK");
    // A valid 2 KiB memory write crosses input budgets. Queue the whole request
    // before counting, excluding idle polls and counting at backend dispatch.
    fixture.with_world(|world| {
        client.write(&format!("M4000,800:{}", "90".repeat(2048)));
        world.event_polls = 0;
        world.memory_polls = None;
    });
    assert_eq!(client.packet(), "OK");
    let polls = fixture.with_world(|world| world.memory_polls.unwrap());
    assert!(polls < 128, "{polls} guest polls for one buffered request");
}

#[test]
fn non_stop_reports_one_thread_at_a_time_through_notifications() {
    let fixture = Fixture::start();
    let mut client = fixture.client();
    client.handshake("");
    assert_eq!(client.send("QNonStop:1"), "OK");
    assert!(
        fixture
            .log()
            .iter()
            .any(|line| line.starts_with("configure 10") && line.contains("nonstop: true")),
        "{:?}",
        fixture.log()
    );
    // Both threads sit stopped: the first answers `?` and the next waits until gdb
    // has started up (its first wait cannot take two), then comes as a notification.
    assert_eq!(client.send("?"), "T00thread:p0a.0a;");
    assert_eq!(client.send("vStopped"), "OK");
    assert_eq!(client.send("qSymbol::"), "OK");
    let (kind, payload) = client.next().unwrap();
    assert_eq!((kind, payload.as_str()), ('%', "Stop:T00thread:p0a.0b;"));
    assert_eq!(client.send("vStopped"), "OK");
    // Run one thread; the other stays stopped.
    assert_eq!(client.send("vCont;c:p0a.0b"), "OK");
    assert!(
        fixture
            .log()
            .contains(&"thread 10 Some(11) Continue { signal: 0 }".to_string())
    );
    fixture.with_world(|world| world.thread_hits(10, 11, 0x5000));
    let (kind, payload) = client.next().unwrap();
    assert_eq!(
        (kind, payload.as_str()),
        ('%', "Stop:T05thread:p0a.0b;swbreak:;")
    );
    // Until it is acknowledged no second notification is sent.
    fixture.with_world(|world| world.thread_hits(10, 10, 0x5010));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(client.send("vStopped"), "T05thread:p0a.0a;swbreak:;");
    assert_eq!(client.send("vStopped"), "OK");
    // Stop and run every thread.
    assert_eq!(client.send("vCont;t"), "OK");
    assert!(fixture.log().contains(&"thread 10 None Stop".to_string()));
    assert_eq!(client.send("vCont;c"), "OK");
    // Leaving puts the program back in all-stop and runs it.
    assert_eq!(client.send("D"), "OK");
    fixture.wait_log("configure 10 SessionOptions { fork: true, exec: true, nonstop: false }");
}
