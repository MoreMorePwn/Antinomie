// SPDX-License-Identifier: GPL-3.0-only
//! AArch32 tasks of an arm64 guest (guest contract revision 21): the host tells
//! them by the 72-byte `NT_PRSTATUS`, serves gdb the `arm` target description
//! and breakpoint kinds, plants 2-byte (Thumb) and 4-byte (ARM) traps by the
//! CPSR T bit, and says clearly when the guest cannot debug the program
//! (ANT-T0293). Recorded exchanges: the RSP packets gdb sends, and the guest
//! requests the backend makes.
use crate::debug::{
    ArchTag, BreakpointKind, DebugBackend, DebugCaps, DebugError, DebugServer, DetachMode,
    GuestLink, KernelDebugBackend, LinkError, RegsetBlob, RegsetInfo, ResumeAction, StopEvent,
    StopKind, TargetState, ThreadInfo,
    arm::{self, CPSR_THUMB},
    debugger::Debugger,
    kernel_backend::{NO_AARCH32_DEBUGGER, PROGRAM_NOT_DEBUGGABLE},
    ui_control::{PanelControl, PanelHandle, Pump},
    view::{DebugAction, DebugRequest, DebugView, WindowKind},
    wire,
};
use crate::observation::GuestProcessIdentity;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TID: u32 = 4242;
const CODE: u64 = 0x1_0000;
const PC: u64 = CODE + 0x20;
const ARM_STATE: u32 = 0x10;
const THUMB_STATE: u32 = 0x10 | CPSR_THUMB;

/// What the fake AArch32 guest holds: r0-r15, cpsr, orig_r0.
struct Task {
    state: TargetState,
    sequence: u32,
    regs: [u32; 18],
    log: Vec<String>,
    /// The guest's regset reads, by `nt_type`.
    native: bool,
}
impl Task {
    fn new(cpsr: u32, native: bool) -> Arc<Mutex<Self>> {
        let mut regs = [0u32; 18];
        for (index, reg) in regs.iter_mut().enumerate().take(13) {
            *reg = 0x1111_0000 + index as u32;
        }
        regs[13] = 0x7efff000; // sp
        regs[14] = 0x10075; // lr
        regs[15] = PC as u32;
        regs[16] = cpsr;
        Arc::new(Mutex::new(Self {
            state: TargetState::Running,
            sequence: 0,
            regs,
            log: Vec::new(),
            native,
        }))
    }
    fn stop(&mut self, kind: StopKind) {
        self.sequence += 1;
        self.state = TargetState::Stopped(StopEvent {
            sequence: self.sequence,
            kind,
            tid: TID,
            pc: u64::from(self.regs[15]),
        });
    }
}

struct Guest(Arc<Mutex<Task>>, DebugCaps);
fn caps(aarch32: bool) -> DebugCaps {
    DebugCaps {
        abi: 1,
        arch: ArchTag::Aarch64,
        software_breakpoints: true,
        hardware_single_step: true,
        shadow_reads: true,
        multi_thread: true,
        signals: true,
        batch_regs: false,
        debug_on_start: true,
        auxv: false,
        read_watch: true,
        aarch32,
        follow: false,
        nonstop: false,
        adopt: false,
        thread_hw: false,
        hardware_breakpoints: 6,
        hardware_watchpoints: 4,
        // The guest's CAPS stay the native 4-byte table (contract).
        breakpoint_len_mask: 8,
        watch_len_mask: 0x8b,
        max_threads: 16,
        max_transfer: 16000,
        regsets: vec![
            RegsetInfo {
                nt_type: 1,
                max_size: 272,
                writable: true,
            },
            RegsetInfo {
                nt_type: 2,
                max_size: 528,
                writable: true,
            },
            RegsetInfo {
                nt_type: 0x401,
                max_size: 8,
                writable: true,
            },
        ],
    }
}
impl DebugBackend for Guest {
    fn caps(&self) -> &DebugCaps {
        &self.1
    }
    fn state(&mut self) -> Result<TargetState, DebugError> {
        Ok(self.0.lock().unwrap().state)
    }
    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        let task = self.0.lock().unwrap();
        Ok(vec![ThreadInfo {
            tid: TID,
            stopped: true,
            pc: u64::from(task.regs[15]),
            signal: 0,
            vfork_wait: false,
        }])
    }
    fn interrupt(&mut self) -> Result<(), DebugError> {
        let mut task = self.0.lock().unwrap();
        if task.state == TargetState::Running {
            task.stop(StopKind::Interrupt);
        }
        Ok(())
    }
    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        let mut task = self.0.lock().unwrap();
        task.log.push(format!("{action:?}"));
        match action {
            ResumeAction::Step { .. } => {
                let width = if task.regs[16] & CPSR_THUMB != 0 {
                    2
                } else {
                    4
                };
                task.regs[15] += width;
                task.stop(StopKind::Step);
            }
            _ => task.state = TargetState::Running,
        }
        Ok(())
    }
    fn read_regset(&mut self, tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError> {
        let mut task = self.0.lock().unwrap();
        task.log.push(format!("regs {tid} {nt_type:#x}"));
        let data = match nt_type {
            1 if task.native => vec![0u8; 272],
            1 => task
                .regs
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect(),
            0x400 => {
                let mut vfp = vec![0u8; arm::VFP_SIZE];
                vfp[..8].copy_from_slice(&1.5f64.to_le_bytes());
                vfp[256..260].copy_from_slice(&0x0300_0000u32.to_le_bytes());
                vfp
            }
            0x401 => 0x76f0_1000u32.to_le_bytes().to_vec(),
            _ => return Err(DebugError::Unsupported("register set".into())),
        };
        Ok(RegsetBlob { nt_type, data })
    }
    fn write_regset(&mut self, _tid: u32, blob: &RegsetBlob) -> Result<(), DebugError> {
        let mut task = self.0.lock().unwrap();
        task.log.push(format!("write_regset {:#x}", blob.nt_type));
        if blob.nt_type == 1 {
            for (word, bytes) in task.regs.iter_mut().zip(blob.data.chunks(4)) {
                *word = u32::from_le_bytes(bytes.try_into().unwrap());
            }
        }
        Ok(())
    }
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, DebugError> {
        // Thumb code at CODE: nop (0xbf00) repeated; 4 bytes per two halfwords.
        if !(CODE..CODE + 0x400).contains(&addr) {
            return Err(DebugError::Fault);
        }
        Ok((0..len)
            .map(|index| {
                if (addr as usize + index).is_multiple_of(2) {
                    0x00
                } else {
                    0xbf
                }
            })
            .collect())
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), DebugError> {
        Ok(())
    }
    fn set_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError> {
        self.0
            .lock()
            .unwrap()
            .log
            .push(format!("set {addr:#x} {len}"));
        Ok(())
    }
    fn clear_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError> {
        self.0
            .lock()
            .unwrap()
            .log
            .push(format!("clear {addr:#x} {len}"));
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
        self.0
            .lock()
            .unwrap()
            .log
            .push(format!("hw+ {kind:?} {addr:#x} {len}"));
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
        self.0
            .lock()
            .unwrap()
            .log
            .push(format!("hw- {kind:?} {addr:#x} {len}"));
        Ok(())
    }
    fn set_task_arch(&mut self, arch: ArchTag) {
        self.0
            .lock()
            .unwrap()
            .log
            .push(format!("task_arch {arch:?}"));
    }
    fn detach(&mut self, _mode: DetachMode) -> Result<(), DebugError> {
        Ok(())
    }
}

// ---- gdb over the Unix socket --------------------------------------------------------

struct Gdb(UnixStream, Vec<u8>);
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}
impl Gdb {
    fn send(&mut self, payload: &str) -> String {
        let packet = format!("${payload}#{:02x}", checksum(payload.as_bytes()));
        self.0.write_all(packet.as_bytes()).unwrap();
        loop {
            if let Some(start) = self.1.iter().position(|byte| *byte == b'$')
                && let Some(hash) = self.1[start..].iter().position(|byte| *byte == b'#')
                && self.1.len() >= start + hash + 3
            {
                let reply = String::from_utf8(self.1[start + 1..start + hash].to_vec()).unwrap();
                self.1.drain(..start + hash + 3);
                self.0.write_all(b"+").unwrap();
                return reply;
            }
            let mut buffer = [0u8; 8192];
            let count = self.0.read(&mut buffer).unwrap();
            assert!(count > 0, "no reply to {payload:?}");
            self.1.extend(&buffer[..count]);
        }
    }
}

struct Rig {
    task: Arc<Mutex<Task>>,
    server: DebugServer,
    directory: std::path::PathBuf,
}
impl Rig {
    fn start(cpsr: u32, caps: DebugCaps, native: bool) -> (Self, Gdb) {
        let task = Task::new(cpsr, native);
        task.lock().unwrap().stop(StopKind::Interrupt);
        let directory =
            std::env::temp_dir().join(format!("ant-arm-test-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let server = DebugServer::start(Box::new(Guest(task.clone(), caps)), &directory).unwrap();
        let stream = UnixStream::connect(&server.endpoints().unix_socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut gdb = Gdb(stream, Vec::new());
        let reply = gdb.send("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+");
        assert!(reply.contains("qXfer:features:read+"), "{reply}");
        assert_eq!(gdb.send("QStartNoAckMode"), "OK");
        (
            Self {
                task,
                server,
                directory,
            },
            gdb,
        )
    }
    fn log(&self) -> Vec<String> {
        self.task.lock().unwrap().log.clone()
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self
            .server
            .shutdown(DetachMode::Resume, Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn target_xml(gdb: &mut Gdb) -> String {
    let mut xml = String::new();
    loop {
        let reply = gdb.send(&format!(
            "qXfer:features:read:target.xml:{:x},fff",
            xml.len()
        ));
        xml.push_str(&reply[1..]);
        if reply.starts_with('l') {
            return xml;
        }
    }
}
fn hex_u32(value: u32) -> String {
    value
        .to_le_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn gdb_gets_the_arm_target_description_and_the_compat_register_image() {
    let (rig, mut gdb) = Rig::start(ARM_STATE, caps(true), false);
    let xml = target_xml(&mut gdb);
    assert!(xml.contains("<architecture>arm</architecture>"), "{xml}");
    assert!(xml.contains("<osabi>GNU/Linux</osabi>"));
    assert!(xml.contains("<feature name=\"org.gnu.gdb.arm.core\">"));
    assert!(xml.contains("<feature name=\"org.gnu.gdb.arm.vfp\">"));
    let names: Vec<&str> = xml
        .lines()
        .filter_map(|line| line.split("<reg name=\"").nth(1)?.split('"').next())
        .collect();
    let expected: Vec<String> = (0..13)
        .map(|n| format!("r{n}"))
        .chain(["sp", "lr", "pc", "cpsr"].map(String::from))
        .chain((0..32).map(|n| format!("d{n}")))
        .chain(["fpscr", "tpidruro"].map(String::from))
        .collect();
    assert_eq!(names, expected);
    assert!(xml.contains("<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\""));
    assert!(xml.contains("<field name=\"T\" start=\"5\" end=\"5\"/>"));
    // g: r0-r12, sp, lr, pc, cpsr (17 words), d0-d31, fpscr, tpidruro.
    let image = gdb.send("g");
    assert_eq!(image.len() / 8, 17 + 64 + 1 + 1, "{image}");
    assert_eq!(&image[..8], hex_u32(0x1111_0000));
    assert_eq!(&image[15 * 8..16 * 8], hex_u32(PC as u32), "pc");
    assert_eq!(&image[16 * 8..17 * 8], hex_u32(ARM_STATE), "cpsr");
    assert_eq!(&image[17 * 8..17 * 8 + 16], "000000000000f83f", "d0 = 1.5");
    assert_eq!(
        &image[image.len() - 16..image.len() - 8],
        hex_u32(0x0300_0000)
    );
    assert_eq!(&image[image.len() - 8..], hex_u32(0x76f0_1000), "tpidruro");
    // p of pc (index 15) and P of r0 write the PRSTATUS set back.
    assert_eq!(gdb.send("pf"), hex_u32(PC as u32));
    assert_eq!(gdb.send(&format!("P0={}", hex_u32(7))), "OK");
    assert_eq!(rig.task.lock().unwrap().regs[0], 7);
    assert!(
        rig.log().contains(&"task_arch Arm".to_string()),
        "{:?}",
        rig.log()
    );
}

#[test]
fn a_native_aarch64_session_keeps_the_aarch64_description() {
    let (rig, mut gdb) = Rig::start(ARM_STATE, caps(true), true);
    let xml = target_xml(&mut gdb);
    assert!(
        xml.contains("<architecture>aarch64</architecture>"),
        "{xml}"
    );
    assert_eq!(gdb.send("Z0,2000,4"), "OK");
    assert!(rig.log().contains(&"set 0x2000 4".to_string()));
    assert!(
        !rig.log()
            .iter()
            .any(|line| line.starts_with("task_arch Arm"))
    );
}

#[test]
fn z0_kinds_select_arm_and_thumb_traps_and_removal_uses_the_planted_length() {
    let (rig, mut gdb) = Rig::start(THUMB_STATE, caps(true), false);
    // 4 is ARM, 2 Thumb, 3 a 32-bit Thumb-2 instruction (its trap is 2 bytes).
    assert_eq!(gdb.send("Z0,10100,4"), "OK");
    assert_eq!(gdb.send("Z0,10202,2"), "OK");
    assert_eq!(gdb.send("Z0,10304,3"), "OK");
    // A Thumb address with its marker bit set is the same halfword.
    assert_eq!(gdb.send("Z0,10409,2"), "OK");
    assert_eq!(
        rig.log()
            .iter()
            .filter(|line| line.starts_with("set "))
            .collect::<Vec<_>>(),
        [
            "set 0x10100 4",
            "set 0x10202 2",
            "set 0x10304 2",
            "set 0x10408 2"
        ]
    );
    // Not a kind, or a misaligned ARM trap: E22. Debug registers execute-break on ARM code only.
    assert_eq!(gdb.send("Z0,10500,1"), "E16");
    assert_eq!(gdb.send("Z0,10502,4"), "E16");
    assert_eq!(gdb.send("Z1,10600,2"), "");
    assert_eq!(gdb.send("Z1,10600,3"), "");
    assert_eq!(gdb.send("Z1,10600,4"), "OK");
    // The debug-register request asks for the architecture's own length (1).
    assert!(
        rig.log().contains(&"hw+ Hardware 0x10600 1".to_string()),
        "{:?}",
        rig.log()
    );
    // Removal sends the kind's length again; a Thumb-2 breakpoint removes as 2.
    assert_eq!(gdb.send("z0,10304,3"), "OK");
    assert_eq!(gdb.send("z0,10100,4"), "OK");
    assert_eq!(gdb.send("z0,10202,2"), "OK");
    let log = rig.log();
    for line in ["clear 0x10304 2", "clear 0x10100 4", "clear 0x10202 2"] {
        assert!(log.contains(&line.to_string()), "{line} in {log:?}");
    }
}

#[test]
fn a_step_in_thumb_moves_two_bytes_and_the_stop_reply_carries_the_thread() {
    let (rig, mut gdb) = Rig::start(THUMB_STATE, caps(true), false);
    assert!(!gdb.send("g").is_empty());
    let reply = gdb.send("vCont;s");
    assert!(reply.starts_with("T05"), "{reply}");
    assert!(rig.log().iter().any(|line| line.starts_with("Step")));
    assert_eq!(rig.task.lock().unwrap().regs[15], (PC + 2) as u32);
    assert_eq!(gdb.send("pf"), hex_u32((PC + 2) as u32));
}

// ---- the in-app panel ------------------------------------------------------------------

struct Panel {
    task: Arc<Mutex<Task>>,
    target: Debugger,
    control: PanelControl,
    handle: PanelHandle,
    next: u64,
}
impl Panel {
    fn new(cpsr: u32) -> Self {
        let task = Task::new(cpsr, false);
        let guest = Guest(task.clone(), caps(true));
        let (mut control, handle) = PanelControl::new(guest.caps());
        control.timing(Duration::ZERO, Duration::ZERO, Duration::from_secs(5));
        Self {
            task,
            target: Debugger::new(Box::new(guest)),
            control,
            handle,
            next: 1,
        }
    }
    fn view(&self) -> Arc<DebugView> {
        self.handle.view()
    }
    fn send(&mut self, action: DebugAction) {
        let sequence = self.view().run.stopped_sequence().unwrap_or(0);
        self.handle
            .submit(DebugRequest {
                id: self.next,
                sequence,
                action,
            })
            .unwrap();
        self.next += 1;
    }
    fn settle(&mut self, done: impl Fn(&DebugView) -> bool) {
        let until = Instant::now() + Duration::from_secs(60);
        while !done(&self.view()) {
            assert!(Instant::now() < until, "never settled: {:?}", self.view());
            assert_eq!(self.control.pump(&mut self.target), Pump::Idle);
        }
    }
    fn stopped(&mut self) {
        self.control.pump(&mut self.target);
        self.send(DebugAction::Stop);
        self.settle(|view| view.run.stopped_sequence().is_some() && !view.loading);
    }
}

#[test]
fn the_panel_shows_arm_registers_and_plants_traps_by_the_instruction_set() {
    let mut panel = Panel::new(THUMB_STATE);
    // Before the first stop the guest's own tag is all the view knows.
    assert_eq!(panel.view().caps.arch, ArchTag::Aarch64);
    panel.stopped();
    let view = panel.view();
    assert_eq!(view.caps.arch, ArchTag::Arm);
    assert!(view.thumb());
    let registers = view.registers.as_ref().unwrap();
    assert_eq!(registers.pc(), Some(PC));
    assert_eq!(registers.get("lr"), Some(0x10075));
    assert_eq!(registers.get("cpsr"), Some(u64::from(THUMB_STATE)));
    assert_eq!(registers.get("r0"), Some(0x1111_0000));
    assert_eq!(registers.get("x0"), None);
    // The code window is read around pc and decodes in Thumb (nop is 0xbf00).
    assert!(
        view.window(WindowKind::Code)
            .is_some_and(|w| w.error.is_none())
    );

    panel.send(DebugAction::AddBreakpoint {
        addr: PC + 4,
        kind: BreakpointKind::Software,
    });
    panel.settle(|view| view.breakpoints.len() == 1);
    assert!(
        panel
            .task
            .lock()
            .unwrap()
            .log
            .contains(&format!("set {:#x} 2", PC + 4)),
        "{:?}",
        panel.task.lock().unwrap().log
    );
    panel.send(DebugAction::RemoveBreakpoint { addr: PC + 4 });
    panel.settle(|view| view.breakpoints.is_empty());
    assert!(
        panel
            .task
            .lock()
            .unwrap()
            .log
            .contains(&format!("clear {:#x} 2", PC + 4))
    );
}

#[test]
fn the_panel_plants_four_byte_traps_in_arm_state() {
    let mut panel = Panel::new(ARM_STATE);
    panel.stopped();
    assert!(!panel.view().thumb());
    assert_eq!(panel.view().caps.arch, ArchTag::Arm);
    panel.send(DebugAction::AddBreakpoint {
        addr: PC + 8,
        kind: BreakpointKind::Software,
    });
    panel.settle(|view| view.breakpoints.len() == 1);
    assert!(
        panel
            .task
            .lock()
            .unwrap()
            .log
            .contains(&format!("set {:#x} 4", PC + 8))
    );
}

// ---- the backend's guest requests, scripted --------------------------------------------

/// The requests a scripted link was asked.
type Asked = Arc<Mutex<Vec<(u32, Vec<u8>)>>>;

/// A guest link that answers from a script and records what was asked.
struct Script {
    asked: Asked,
    replies: Vec<Result<Vec<u8>, LinkError>>,
}
impl GuestLink for Script {
    fn request(&mut self, opcode: u32, args: &[u8]) -> Result<Vec<u8>, LinkError> {
        self.asked.lock().unwrap().push((opcode, args.to_vec()));
        assert!(!self.replies.is_empty(), "unexpected request {opcode:#x}");
        self.replies.remove(0)
    }
}
fn refused() -> LinkError {
    LinkError {
        errno: Some(95),
        message: "Operation not supported".into(),
        outcome_unknown: false,
    }
}
fn identity() -> GuestProcessIdentity {
    GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 0x1234,
        tgid: 55,
        start_boot_ns: 99,
    }
}
fn scripted(
    replies: Vec<Result<Vec<u8>, LinkError>>,
    aarch32: bool,
) -> (KernelDebugBackend, Asked) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let link = Script {
        asked: asked.clone(),
        replies,
    };
    let attached = crate::debug::AttachedSession {
        caps: caps(aarch32),
        session: 9,
        generation: 3,
        tgid: 55,
    };
    (KernelDebugBackend::new(Box::new(link), attached), asked)
}
/// A `REGS_READ` reply for one set.
fn regs_reply(nt_type: u32, data: &[u8]) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.extend(nt_type.to_le_bytes());
    reply.extend((data.len() as u32).to_le_bytes());
    reply.extend([0u8; 8]);
    reply.extend(data);
    reply
}

#[test]
fn a_compat_task_reads_its_three_regsets_in_one_request_and_plants_two_lengths() {
    let status = vec![0u8; arm::PRSTATUS_SIZE];
    let vfp = vec![0u8; arm::VFP_SIZE];
    let tls = [0u8; 4];
    let mut many = Vec::new();
    many.extend(3u32.to_le_bytes());
    many.extend([0u8; 12]);
    for (nt, data) in [(1u32, &status[..]), (0x400, &vfp[..]), (0x401, &tls[..])] {
        many.extend(regs_reply(nt, data));
    }
    let mut batch = caps(true);
    batch.batch_regs = true;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let link = Script {
        asked: asked.clone(),
        replies: vec![
            Ok(regs_reply(1, &status)),
            Ok(many),
            Ok(vec![]),
            Ok(vec![]),
            Ok(vec![]),
        ],
    };
    let attached = crate::debug::AttachedSession {
        caps: batch,
        session: 9,
        generation: 3,
        tgid: 55,
    };
    let mut backend = KernelDebugBackend::new(Box::new(link), attached);
    // The first read of a session: the guest's own table, PRSTATUS alone. A
    // compat task's is 72 bytes, a native one's 272.
    let blob = backend.read_regset(TID, 1).unwrap();
    assert!(arm::is_compat_prstatus(&blob.data));
    assert_eq!(arm::thumb_state(&blob.data), Some(false));
    backend.set_task_arch(ArchTag::Arm);
    // Compat: the table is PRSTATUS, VFP, TLS (bits 0-2), not the CAPS table.
    assert!(
        backend.read_regset(TID, 2).is_err(),
        "NT_PRFPREG is no compat set"
    );
    asked.lock().unwrap().clear();
    let blobs = backend.read_regsets(TID, &[1, 0x400, 0x401]).unwrap();
    assert_eq!(
        blobs
            .iter()
            .map(|b| (b.nt_type, b.data.len()))
            .collect::<Vec<_>>(),
        [(1, 72), (0x400, 260), (0x401, 4)]
    );
    assert_eq!(
        asked.lock().unwrap()[0],
        (
            wire::REGS_READ,
            wire::regs_read_many_request(9, TID, 0b111, 3)
        )
    );
    // 4 (A32) and 2 (T16) are taken, 1 asks for the ARM trap, 3 is no length.
    backend.set_breakpoint(0x1000, 4).unwrap();
    backend.set_breakpoint(0x2002, 2).unwrap();
    backend.set_breakpoint(0x3000, 1).unwrap();
    assert!(matches!(
        backend.set_breakpoint(0x4000, 3),
        Err(DebugError::Unsupported(_))
    ));
    let sent: Vec<_> = asked.lock().unwrap().iter().skip(1).cloned().collect();
    assert_eq!(
        sent,
        [
            (wire::BP_SET, wire::breakpoint_request(9, 0x1000, 4, 3)),
            (wire::BP_SET, wire::breakpoint_request(9, 0x2002, 2, 3)),
            (wire::BP_SET, wire::breakpoint_request(9, 0x3000, 4, 3)),
        ]
    );
}

#[test]
fn guests_without_the_aarch32_engine_refuse_clearly() {
    // ATTACH refused with EOPNOTSUPP: an arm64 base older than revision 21 says
    // so; a guest that does debug AArch32 (or x86-64) names ia32/x32 instead.
    for (aarch32, arch, text) in [
        (false, ArchTag::Aarch64, NO_AARCH32_DEBUGGER),
        (true, ArchTag::Aarch64, PROGRAM_NOT_DEBUGGABLE),
        (false, ArchTag::X86_64, PROGRAM_NOT_DEBUGGABLE),
    ] {
        let mut link = Script {
            asked: Arc::default(),
            replies: vec![Err(refused())],
        };
        let mut guest_caps = caps(aarch32);
        guest_caps.arch = arch;
        let error = KernelDebugBackend::adopt_session(&mut link, guest_caps, &identity(), [1, 2])
            .err()
            .expect("the attach is refused");
        assert_eq!(
            error,
            DebugError::Unsupported(text.into()),
            "{arch:?} {aarch32}"
        );
    }
    assert!(
        NO_AARCH32_DEBUGGER.contains("32-bit ARM") && NO_AARCH32_DEBUGGER.contains("revision 21")
    );
    assert!(PROGRAM_NOT_DEBUGGABLE.contains("ia32 or x32"));
    // A debug-on-start session adopted before the exec: the first register read
    // is the refusal, and says the same.
    let (mut backend, _) = scripted(vec![Err(refused())], false);
    assert_eq!(
        backend.read_regset(TID, 1).unwrap_err(),
        DebugError::Unsupported(NO_AARCH32_DEBUGGER.into())
    );
    // An AArch32 breakpoint cannot be planted on a guest without the engine.
    let (mut backend, _) = scripted(vec![], false);
    backend.set_task_arch(ArchTag::Arm);
    assert!(matches!(
        backend.set_breakpoint(0x1000, 2),
        Err(DebugError::Unsupported(_))
    ));
}

#[test]
fn caps_with_the_aarch32_bit_parse_and_the_bit_means_nothing_on_x86() {
    let reply = |arch: u32, flags: u32| {
        let mut reply = vec![0u8; wire::CAPS_SIZE + 16];
        reply[0..4].copy_from_slice(&wire::ABI.to_le_bytes());
        reply[4..8].copy_from_slice(&arch.to_le_bytes());
        reply[8..12].copy_from_slice(&flags.to_le_bytes());
        reply[12..16].copy_from_slice(&8u32.to_le_bytes());
        reply[32..36].copy_from_slice(&4096u32.to_le_bytes());
        reply[36..40].copy_from_slice(&1u32.to_le_bytes());
        reply[wire::CAPS_SIZE..wire::CAPS_SIZE + 4].copy_from_slice(&1u32.to_le_bytes());
        reply
    };
    let base = wire::CAP_SW_BREAKPOINT | wire::CAP_MULTI_THREAD;
    let caps = wire::parse_caps(&reply(183, base | wire::CAP_AARCH32), false).unwrap();
    assert!(caps.aarch32 && caps.arch == ArchTag::Aarch64);
    assert!(!wire::parse_caps(&reply(183, base), false).unwrap().aarch32);
    assert!(
        !wire::parse_caps(&reply(62, base | wire::CAP_AARCH32), false)
            .unwrap()
            .aarch32
    );
}
